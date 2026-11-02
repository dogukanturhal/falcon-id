// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/pkg/config"
)

// ---------------------------------------------------------------------------
// Fakes
// ---------------------------------------------------------------------------

type fakeAPIKeyRepo struct {
	keys        map[uuid.UUID]*models.APIKey
	activeCount *int  // overrides the computed active count when set
	activeSeq   []int // successive counts to return first (cap-race simulation)
}

func newFakeAPIKeyRepo() *fakeAPIKeyRepo {
	return &fakeAPIKeyRepo{keys: map[uuid.UUID]*models.APIKey{}}
}

func (f *fakeAPIKeyRepo) CreateTenantKey(_ context.Context, key *models.APIKey) error {
	key.ID = uuid.New()
	key.CreatedAt = time.Now()
	key.IsActive = true
	key.Kind = models.APIKeyKindTenant
	cp := *key
	f.keys[key.ID] = &cp
	return nil
}

func (f *fakeAPIKeyRepo) GetTenantKey(_ context.Context, tenantID, id uuid.UUID) (*models.APIKey, error) {
	k, ok := f.keys[id]
	if !ok || k.TenantID != tenantID {
		return nil, nil
	}
	cp := *k
	return &cp, nil
}

func (f *fakeAPIKeyRepo) GetByKeyID(_ context.Context, keyID string) (*models.APIKey, error) {
	for _, k := range f.keys {
		if k.KeyID != nil && *k.KeyID == keyID {
			cp := *k
			return &cp, nil
		}
	}
	return nil, nil
}

func (f *fakeAPIKeyRepo) ListTenantKeys(_ context.Context, tenantID uuid.UUID) ([]*models.APIKey, error) {
	var out []*models.APIKey
	for _, k := range f.keys {
		if k.TenantID == tenantID {
			cp := *k
			out = append(out, &cp)
		}
	}
	return out, nil
}

func (f *fakeAPIKeyRepo) ActiveCountByTenant(_ context.Context, tenantID uuid.UUID) (int, error) {
	if f.activeCount != nil {
		return *f.activeCount, nil
	}
	if len(f.activeSeq) > 0 {
		n := f.activeSeq[0]
		f.activeSeq = f.activeSeq[1:]
		return n, nil
	}
	n := 0
	for _, k := range f.keys {
		if k.TenantID == tenantID && k.IsActive && k.RevokedAt == nil {
			n++
		}
	}
	return n, nil
}

func (f *fakeAPIKeyRepo) RotateSecret(_ context.Context, id uuid.UUID, newHash, hashAlg string, until time.Time) error {
	k := f.keys[id]
	if until.IsZero() {
		k.PrevHash, k.PrevValidUntil = nil, nil
	} else {
		prev := k.KeyHash
		k.PrevHash, k.PrevValidUntil = &prev, &until
	}
	k.KeyHash, k.HashAlg = newHash, hashAlg
	return nil
}

func (f *fakeAPIKeyRepo) RevokeTenantKey(_ context.Context, id uuid.UUID) error {
	k := f.keys[id]
	now := time.Now()
	k.IsActive, k.RevokedAt, k.PrevHash, k.PrevValidUntil = false, &now, nil, nil
	if len(k.CompanyIDs) > 0 { // mirrors the repository's atomic pending_remove
		k.CompanySyncState, k.CompanySyncAttempt, k.CompanySyncNextAt = models.APIKeyCompanySyncPendingRemove, 0, &now
	}
	return nil
}

func (f *fakeAPIKeyRepo) DeleteTenantKey(_ context.Context, _, id uuid.UUID) error {
	k := f.keys[id]
	if k == nil || k.RevokedAt == nil || k.CompanySyncState != models.APIKeyCompanySyncSynced {
		return errors.New("API key not found")
	}
	delete(f.keys, id)
	return nil
}

func (f *fakeAPIKeyRepo) HardDeleteTenantKey(_ context.Context, _, id uuid.UUID) error {
	delete(f.keys, id)
	return nil
}

func (f *fakeAPIKeyRepo) SetCompanySync(_ context.Context, id uuid.UUID, expected, state string, attempts int, next *time.Time) (bool, error) {
	k := f.keys[id]
	if k == nil || k.CompanySyncState != expected {
		return false, nil
	}
	k.CompanySyncState, k.CompanySyncAttempt, k.CompanySyncNextAt = state, attempts, next
	return true, nil
}

func (f *fakeAPIKeyRepo) ListPendingCompanySync(_ context.Context, _ int) ([]*models.APIKey, error) {
	var out []*models.APIKey
	for _, k := range f.keys {
		if k.CompanySyncState != "" && k.CompanySyncState != models.APIKeyCompanySyncSynced && k.CompanySyncState != models.APIKeyCompanySyncFailed {
			cp := *k
			out = append(out, &cp)
		}
	}
	return out, nil
}

func (f *fakeAPIKeyRepo) UpdateLastUsed(context.Context, uuid.UUID, string) error { return nil }

type apiKeyFakeRoleRepo struct {
	roles map[uuid.UUID]*models.Role
	perms map[uuid.UUID][]string
}

func (f *apiKeyFakeRoleRepo) GetByIDAndTenant(_ context.Context, id, tenantID uuid.UUID) (*models.Role, error) {
	r, ok := f.roles[id]
	if !ok || r.TenantID != tenantID {
		return nil, nil
	}
	return r, nil
}

func (f *apiKeyFakeRoleRepo) GetRolePermissions(_ context.Context, id uuid.UUID) ([]models.Permission, error) {
	var out []models.Permission
	for _, n := range f.perms[id] {
		out = append(out, models.Permission{Name: n})
	}
	return out, nil
}

type fakeUserRoles struct{ held []models.Role }

func (f *fakeUserRoles) GetUserRoles(context.Context, uuid.UUID) ([]models.Role, error) {
	return f.held, nil
}

type spiceEdge struct{ tenant, user, role uuid.UUID }

type apiKeyFakeSpiceDB struct {
	denyCompanies map[string]bool // company id -> creator cannot view
	failWrite     bool
	checked       []string
	written       []spiceEdge
	expiry        []time.Time
	deleted       []spiceEdge
}

func (f *apiKeyFakeSpiceDB) WriteUserRoleUntil(_ context.Context, t, u, r uuid.UUID, exp time.Time) (string, error) {
	if f.failWrite {
		return "", errors.New("spicedb down")
	}
	f.written = append(f.written, spiceEdge{t, u, r})
	f.expiry = append(f.expiry, exp)
	return "", nil
}

func (f *apiKeyFakeSpiceDB) CheckPermission(_ context.Context, _, _ uuid.UUID, objectType, objectID, permission string) (bool, error) {
	if objectType != "company" || permission != "view" {
		return false, fmt.Errorf("unexpected check %s#%s", objectType, permission)
	}
	f.checked = append(f.checked, objectID)
	return !f.denyCompanies[objectID], nil
}

func (f *apiKeyFakeSpiceDB) DeleteUserRole(_ context.Context, t, u, r uuid.UUID) (string, error) {
	f.deleted = append(f.deleted, spiceEdge{t, u, r})
	return "", nil
}

type fakeCompanyClient struct {
	fail    bool
	err     error // returned instead of the generic outage when set
	added   [][]uuid.UUID
	removed [][]uuid.UUID
	onAdd   func() // runs inside AddCompanies, to simulate a concurrent actor
}

func (f *fakeCompanyClient) AddCompanies(_ context.Context, _, _ uuid.UUID, ids []uuid.UUID) error {
	if f.err != nil {
		return f.err
	}
	if f.fail {
		return errors.New("business unavailable")
	}
	f.added = append(f.added, ids)
	if f.onAdd != nil {
		f.onAdd()
	}
	return nil
}

func (f *fakeCompanyClient) RemoveCompanies(_ context.Context, _, _ uuid.UUID, ids []uuid.UUID) error {
	if f.err != nil {
		return f.err
	}
	if f.fail {
		return errors.New("business unavailable")
	}
	f.removed = append(f.removed, ids)
	return nil
}

type auditRecord struct {
	action  string
	success bool
	details map[string]interface{}
}

type fakeAuditor struct{ events []auditRecord }

func (f *fakeAuditor) LogTenantAPIKeyEvent(_ context.Context, _ uuid.UUID, _ *uuid.UUID, _ uuid.UUID, action string, success bool, details map[string]interface{}) {
	f.events = append(f.events, auditRecord{action, success, details})
}

type apiKeyFakeEntitlements struct{ limits map[string]int64 }

func (f *apiKeyFakeEntitlements) GetFlags(_ context.Context, tenantID uuid.UUID) (*models.TenantEntitlementFlags, error) {
	if f.limits == nil {
		return nil, nil
	}
	return &models.TenantEntitlementFlags{TenantID: tenantID, Limits: f.limits}, nil
}

type fakeMinter struct{ params []APIKeyTokenParams }

func (f *fakeMinter) MintAPIKeyToken(p APIKeyTokenParams) (string, error) {
	f.params = append(f.params, p)
	return "signed.jwt.token", nil
}

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

type apiKeyHarness struct {
	svc       *TenantAPIKeyService
	repo      *fakeAPIKeyRepo
	roles     *apiKeyFakeRoleRepo
	userRoles *fakeUserRoles
	spice     *apiKeyFakeSpiceDB
	companies *fakeCompanyClient
	audit     *fakeAuditor
	minter    *fakeMinter
	tenantID  uuid.UUID
	creatorID uuid.UUID
	roleID    uuid.UUID
	now       time.Time
}

func newAPIKeyHarness(t *testing.T) *apiKeyHarness {
	t.Helper()
	h := &apiKeyHarness{
		repo:      newFakeAPIKeyRepo(),
		spice:     &apiKeyFakeSpiceDB{},
		companies: &fakeCompanyClient{},
		audit:     &fakeAuditor{},
		minter:    &fakeMinter{},
		tenantID:  uuid.New(),
		creatorID: uuid.New(),
		roleID:    uuid.New(),
		now:       time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC),
	}
	role := &models.Role{ID: h.roleID, TenantID: h.tenantID, Name: "sales_manager"}
	h.roles = &apiKeyFakeRoleRepo{
		roles: map[uuid.UUID]*models.Role{h.roleID: role},
		perms: map[uuid.UUID][]string{h.roleID: {"crm:deals:read", "crm:deals:update"}},
	}
	h.userRoles = &fakeUserRoles{held: []models.Role{*role}}
	cfg := &config.Config{
		DeveloperKeysEnabled:  true,
		DeveloperKeysPepper:   "test-pepper-not-a-secret",
		DeveloperKeysAudience: "https://api.example.test",
		DeveloperKeysTokenTTL: 600 * time.Second,
	}
	h.svc = NewTenantAPIKeyService(cfg, TenantAPIKeyDeps{
		Repo: h.repo, Roles: h.roles, UserRoles: h.userRoles, SpiceDB: h.spice,
		Companies: h.companies, Audit: h.audit,
		Entitlements: &apiKeyFakeEntitlements{limits: map[string]int64{"api_requests_monthly": 100000}},
		Minter:       h.minter,
	})
	h.svc.now = func() time.Time { return h.now }
	return h
}

func (h *apiKeyHarness) createReq() *models.CreateTenantAPIKeyRequest {
	return &models.CreateTenantAPIKeyRequest{
		Name:       "ERP sync",
		Access:     models.APIKeyAccessRead,
		RoleIDs:    []uuid.UUID{h.roleID},
		CompanyIDs: []uuid.UUID{uuid.New()},
	}
}

func splitKey(t *testing.T, full string) (clientID, secret string) {
	t.Helper()
	keyID, secret, ok := ParseTenantAPIKey(full)
	require.True(t, ok, "created key must parse")
	return models.TenantAPIKeyPrefix + keyID, secret
}

// ---------------------------------------------------------------------------
// Key material
// ---------------------------------------------------------------------------

func TestGenerateAndParseTenantAPIKey(t *testing.T) {
	keyID, secret, full, err := GenerateTenantAPIKey()
	require.NoError(t, err)
	assert.Len(t, keyID, 16)
	assert.Len(t, secret, 43)
	assert.True(t, strings.HasPrefix(full, "lgk_live_"))

	gotID, gotSecret, ok := ParseTenantAPIKey(full)
	require.True(t, ok)
	assert.Equal(t, keyID, gotID)
	assert.Equal(t, secret, gotSecret)

	for _, bad := range []string{"", "hxk_abc", "lgk_live_", full + "x", "lgk_live_" + keyID + "-" + secret, strings.ToUpper(full)} {
		_, _, ok := ParseTenantAPIKey(bad)
		assert.False(t, ok, bad)
	}
}

func TestHashTenantAPISecretBindsKeyIDAndPepper(t *testing.T) {
	a := HashTenantAPISecret([]byte("p1"), "keyidkeyidkeyid2", "secret")
	assert.Equal(t, a, HashTenantAPISecret([]byte("p1"), "keyidkeyidkeyid2", "secret"))
	assert.NotEqual(t, a, HashTenantAPISecret([]byte("p2"), "keyidkeyidkeyid2", "secret"))
	assert.NotEqual(t, a, HashTenantAPISecret([]byte("p1"), "otherkeyidother22", "secret"))
	assert.Len(t, a, 64)
}

// ---------------------------------------------------------------------------
// Create
// ---------------------------------------------------------------------------

func TestTenantAPIKeyCreate_Success(t *testing.T) {
	h := newAPIKeyHarness(t)
	resp, err := h.svc.Create(context.Background(), h.tenantID, h.creatorID, h.createReq())
	require.NoError(t, err)

	assert.True(t, strings.HasPrefix(resp.Key, "lgk_live_"))
	assert.Equal(t, "active", resp.Status)
	assert.Equal(t, models.APIKeyCompanySyncSynced, resp.CompanySyncState)
	require.NotNil(t, resp.ExpiresAt)
	assert.Equal(t, h.now.Add(defaultTenantAPIKeyLifetime), *resp.ExpiresAt)

	stored := h.repo.keys[resp.ID]
	require.NotNil(t, stored)
	assert.Equal(t, models.APIKeyHashAlgHMAC("v1"), stored.HashAlg)
	assert.NotContains(t, stored.KeyHash, resp.Key, "full key must never be stored")
	_, secret := splitKey(t, resp.Key)
	assert.Equal(t, HashTenantAPISecret(h.svc.currentPepper(), *stored.KeyID, secret), stored.KeyHash)

	// Role edge: subject is the key row id, expiry is the key expiry.
	require.Len(t, h.spice.written, 1)
	assert.Equal(t, spiceEdge{h.tenantID, resp.ID, h.roleID}, h.spice.written[0])
	assert.Equal(t, *resp.ExpiresAt, h.spice.expiry[0])
	// Company edge call went out once.
	assert.Len(t, h.companies.added, 1)
	require.Len(t, h.audit.events, 1)
	assert.Equal(t, AuditActionAPIKeyCreated, h.audit.events[0].action)
}

func TestTenantAPIKeyCreate_EscalationDenied(t *testing.T) {
	h := newAPIKeyHarness(t)
	// The creator holds no roles: choosing a role they do not hold is an escalation.
	h.userRoles.held = nil

	_, err := h.svc.Create(context.Background(), h.tenantID, h.creatorID, h.createReq())
	require.ErrorIs(t, err, ErrAPIKeyRoleNotHeld)
	assert.Empty(t, h.repo.keys, "no key row may be created")
	assert.Empty(t, h.spice.written, "no SpiceDB edge may be written")
	assert.Empty(t, h.companies.added)
}

func TestTenantAPIKeyCreate_AdminCreatorMayGrantUnheldRole(t *testing.T) {
	h := newAPIKeyHarness(t)
	h.userRoles.held = []models.Role{{ID: uuid.New(), TenantID: h.tenantID, Name: "owner"}}
	resp, err := h.svc.Create(context.Background(), h.tenantID, h.creatorID, h.createReq())
	require.NoError(t, err)
	require.Len(t, h.spice.written, 1)
	assert.Equal(t, spiceEdge{h.tenantID, resp.ID, h.roleID}, h.spice.written[0])
}

func TestTenantAPIKeyCreate_AdminRoleInAnotherTenantDoesNotExempt(t *testing.T) {
	h := newAPIKeyHarness(t)
	h.userRoles.held = []models.Role{{ID: uuid.New(), TenantID: uuid.New(), Name: "owner"}}
	_, err := h.svc.Create(context.Background(), h.tenantID, h.creatorID, h.createReq())
	require.ErrorIs(t, err, ErrAPIKeyRoleNotHeld)
}

func TestTenantAPIKeyCreate_RoleHeldInAnotherTenantDoesNotCount(t *testing.T) {
	h := newAPIKeyHarness(t)
	h.userRoles.held = []models.Role{{ID: h.roleID, TenantID: uuid.New(), Name: "sales_manager"}}
	_, err := h.svc.Create(context.Background(), h.tenantID, h.creatorID, h.createReq())
	require.ErrorIs(t, err, ErrAPIKeyRoleNotHeld)
}

func TestTenantAPIKeyCreate_ExcludedRoles(t *testing.T) {
	cases := []struct {
		name  string
		role  string
		perms []string
	}{
		{"org_admin", "org_admin", nil},
		{"owner", "Owner", nil},
		{"iam permission", "hr_lead", []string{"hr:people:read", "iam:users:read"}},
		{"developer permission itself", "dev", []string{"iam:api_keys:manage"}},
		{"billing", "finance", []string{"billing:invoices:read"}},
		{"approval admin", "approver", []string{"core:approvals:admin"}},
		{"wildcard", "root", []string{"crm:*:*"}},
		{"platform", "ops", []string{"platform:tenants:read"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newAPIKeyHarness(t)
			role := &models.Role{ID: uuid.New(), TenantID: h.tenantID, Name: tc.role}
			h.roles.roles[role.ID] = role
			h.roles.perms[role.ID] = tc.perms
			h.userRoles.held = append(h.userRoles.held, *role) // even a role the creator holds
			req := h.createReq()
			req.RoleIDs = []uuid.UUID{role.ID}

			_, err := h.svc.Create(context.Background(), h.tenantID, h.creatorID, req)
			require.ErrorIs(t, err, ErrAPIKeyRoleExcluded)
			assert.Empty(t, h.repo.keys)
			assert.Empty(t, h.spice.written)
		})
	}
}

func TestPermissionForbiddenForAPIKey(t *testing.T) {
	for _, name := range []string{"iam:users:read", "iam:webhooks:manage", "platform:x:y", "billing:plans:read", "core:billing:manage", "core:approvals:admin", "x:y:*", "*"} {
		assert.True(t, PermissionForbiddenForAPIKey(name), name)
	}
	for _, name := range []string{"crm:deals:read", "cmms:work_orders:update", "core:approvals:read", "core:legal_entities:read"} {
		assert.False(t, PermissionForbiddenForAPIKey(name), name)
	}
}

func TestTenantAPIKeyCreate_CapReached(t *testing.T) {
	h := newAPIKeyHarness(t)
	n := MaxActiveTenantAPIKeys
	h.repo.activeCount = &n
	_, err := h.svc.Create(context.Background(), h.tenantID, h.creatorID, h.createReq())
	require.ErrorIs(t, err, ErrAPIKeyCapReached)
	assert.Empty(t, h.repo.keys)
}

func TestTenantAPIKeyCreate_Validation(t *testing.T) {
	mutate := map[string]func(r *models.CreateTenantAPIKeyRequest){
		"empty name":   func(r *models.CreateTenantAPIKeyRequest) { r.Name = "  " },
		"bad access":   func(r *models.CreateTenantAPIKeyRequest) { r.Access = "admin" },
		"no roles":     func(r *models.CreateTenantAPIKeyRequest) { r.RoleIDs = nil },
		"no companies": func(r *models.CreateTenantAPIKeyRequest) { r.CompanyIDs = nil },
		"bad ip":       func(r *models.CreateTenantAPIKeyRequest) { r.IPAllowlist = []string{"not-an-ip"} },
		"expiry too far": func(r *models.CreateTenantAPIKeyRequest) {
			e := time.Date(2029, 1, 1, 0, 0, 0, 0, time.UTC)
			r.ExpiresAt = &e
		},
		"expiry past": func(r *models.CreateTenantAPIKeyRequest) {
			e := time.Date(2026, 10, 18, 12, 5, 0, 0, time.UTC)
			r.ExpiresAt = &e
		},
	}
	for name, fn := range mutate {
		t.Run(name, func(t *testing.T) {
			h := newAPIKeyHarness(t)
			req := h.createReq()
			fn(req)
			_, err := h.svc.Create(context.Background(), h.tenantID, h.creatorID, req)
			var verr *APIKeyValidationError
			require.ErrorAs(t, err, &verr)
			assert.Empty(t, h.repo.keys)
		})
	}
}

func TestTenantAPIKeyCreate_GatesAndPlan(t *testing.T) {
	t.Run("flag off", func(t *testing.T) {
		h := newAPIKeyHarness(t)
		h.svc.enabled = false
		_, err := h.svc.Create(context.Background(), h.tenantID, h.creatorID, h.createReq())
		require.ErrorIs(t, err, ErrDeveloperKeysDisabled)
	})
	t.Run("tenant not in allowlist", func(t *testing.T) {
		h := newAPIKeyHarness(t)
		h.svc.allowlist = map[uuid.UUID]struct{}{uuid.New(): {}}
		_, err := h.svc.Create(context.Background(), h.tenantID, h.creatorID, h.createReq())
		require.ErrorIs(t, err, ErrDeveloperKeysDisabled)
	})
	t.Run("tenant in allowlist", func(t *testing.T) {
		h := newAPIKeyHarness(t)
		h.svc.allowlist = map[uuid.UUID]struct{}{h.tenantID: {}}
		_, err := h.svc.Create(context.Background(), h.tenantID, h.creatorID, h.createReq())
		require.NoError(t, err)
	})
	t.Run("pepper missing fails closed", func(t *testing.T) {
		h := newAPIKeyHarness(t)
		h.svc.peppers = nil
		_, err := h.svc.Create(context.Background(), h.tenantID, h.creatorID, h.createReq())
		require.ErrorIs(t, err, ErrAPIKeyPepperMissing)
	})
	t.Run("plan limit zero", func(t *testing.T) {
		h := newAPIKeyHarness(t)
		h.svc.entitlements = &apiKeyFakeEntitlements{limits: map[string]int64{"api_requests_monthly": 0}}
		_, err := h.svc.Create(context.Background(), h.tenantID, h.creatorID, h.createReq())
		require.ErrorIs(t, err, ErrAPIKeyPlanLimit)
	})
	t.Run("plan limit unlimited", func(t *testing.T) {
		h := newAPIKeyHarness(t)
		h.svc.entitlements = &apiKeyFakeEntitlements{limits: map[string]int64{"api_requests_monthly": -1}}
		_, err := h.svc.Create(context.Background(), h.tenantID, h.creatorID, h.createReq())
		require.NoError(t, err)
	})
}

func TestTenantAPIKeyCreate_CompanySyncFailureStaysPendingThenRetries(t *testing.T) {
	h := newAPIKeyHarness(t)
	h.companies.fail = true
	resp, err := h.svc.Create(context.Background(), h.tenantID, h.creatorID, h.createReq())
	require.NoError(t, err, "a business outage must not fail key creation")
	assert.Equal(t, models.APIKeyCompanySyncPendingAdd, resp.CompanySyncState)
	assert.Equal(t, models.APIKeyCompanySyncPendingAdd, h.repo.keys[resp.ID].CompanySyncState)
	assert.Equal(t, 1, h.repo.keys[resp.ID].CompanySyncAttempt)

	h.companies.fail = false
	done, err := h.svc.ProcessPendingCompanySync(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 1, done)
	assert.Equal(t, models.APIKeyCompanySyncSynced, h.repo.keys[resp.ID].CompanySyncState)
}

func TestTenantAPIKeyCompanySync_TerminalRejectionMarksFailedAndAudits(t *testing.T) {
	h := newAPIKeyHarness(t)
	bad := uuid.New()
	h.companies.err = &BusinessCompanyEdgeError{Method: "POST", StatusCode: 422, Code: "company_not_in_tenant", CompanyIDs: []uuid.UUID{bad}}
	resp, err := h.svc.Create(context.Background(), h.tenantID, h.creatorID, h.createReq())
	require.NoError(t, err)
	assert.Equal(t, models.APIKeyCompanySyncFailed, resp.CompanySyncState)
	assert.Equal(t, models.APIKeyCompanySyncFailed, h.repo.keys[resp.ID].CompanySyncState)
	require.Len(t, h.audit.events, 2)
	assert.Equal(t, AuditActionAPIKeyCompanySyncFailed, h.audit.events[0].action)
	assert.False(t, h.audit.events[0].success)
}

func TestCompanySyncBackoff(t *testing.T) {
	assert.Equal(t, 30*time.Second, companySyncBackoff(1))
	assert.Equal(t, time.Minute, companySyncBackoff(2))
	assert.Equal(t, companySyncBackoffMax, companySyncBackoff(50))
}

// ---------------------------------------------------------------------------
// Exchange, rotation, revoke
// ---------------------------------------------------------------------------

func TestTenantAPIKeyExchange_Success(t *testing.T) {
	h := newAPIKeyHarness(t)
	created, err := h.svc.Create(context.Background(), h.tenantID, h.creatorID, h.createReq())
	require.NoError(t, err)
	clientID, secret := splitKey(t, created.Key)

	res, err := h.svc.Exchange(context.Background(), clientID, secret, "203.0.113.9")
	require.NoError(t, err)
	assert.Equal(t, "Bearer", res.Response.TokenType)
	assert.Equal(t, 600, res.Response.ExpiresIn)
	assert.Equal(t, "erp.read", res.Response.Scope)
	require.Len(t, h.minter.params, 1)
	assert.Equal(t, APIKeyTokenParams{
		TenantID: h.tenantID, KeyID: created.ID, Access: "read",
		Audience: "https://api.example.test", TTL: 600 * time.Second,
	}, h.minter.params[0])

	// The whole key as client_id works too.
	_, err = h.svc.Exchange(context.Background(), created.Key, "", "203.0.113.9")
	require.NoError(t, err)
}

func TestTenantAPIKeyExchange_Failures(t *testing.T) {
	h := newAPIKeyHarness(t)
	created, err := h.svc.Create(context.Background(), h.tenantID, h.creatorID, h.createReq())
	require.NoError(t, err)
	clientID, secret := splitKey(t, created.Key)
	ctx := context.Background()

	wrong := strings.Repeat("a", 43)
	for name, args := range map[string][2]string{
		"wrong secret": {clientID, wrong},
		"unknown id":   {"lgk_live_aaaaaaaaaaaaaaaa", secret},
		"malformed":    {"nonsense", secret},
		"short secret": {clientID, "short"},
	} {
		_, err := h.svc.Exchange(ctx, args[0], args[1], "203.0.113.9")
		require.ErrorIs(t, err, ErrAPIKeyInvalidClient, name)
	}

	t.Run("expired", func(t *testing.T) {
		h.now = h.now.Add(defaultTenantAPIKeyLifetime + time.Hour)
		_, err := h.svc.Exchange(ctx, clientID, secret, "203.0.113.9")
		require.ErrorIs(t, err, ErrAPIKeyInvalidClient)
		h.now = h.now.Add(-defaultTenantAPIKeyLifetime - time.Hour)
	})
	t.Run("plan limit dropped to zero", func(t *testing.T) {
		h.svc.entitlements = &apiKeyFakeEntitlements{limits: map[string]int64{"api_requests_monthly": 0}}
		_, err := h.svc.Exchange(ctx, clientID, secret, "203.0.113.9")
		require.ErrorIs(t, err, ErrAPIKeyPlanLimit)
		h.svc.entitlements = &apiKeyFakeEntitlements{limits: map[string]int64{"api_requests_monthly": 10}}
	})
	t.Run("flag off", func(t *testing.T) {
		h.svc.enabled = false
		_, err := h.svc.Exchange(ctx, clientID, secret, "203.0.113.9")
		require.ErrorIs(t, err, ErrAPIKeyInvalidClient)
		h.svc.enabled = true
	})
	t.Run("suspended tenant", func(t *testing.T) {
		h.svc.suspension = suspendedChecker{}
		_, err := h.svc.Exchange(ctx, clientID, secret, "203.0.113.9")
		require.ErrorIs(t, err, ErrAPIKeyTenantSuspended)
		h.svc.suspension = nil
	})
}

type suspendedChecker struct{}

func (suspendedChecker) IsSuspended(context.Context, uuid.UUID) bool { return true }

func TestTenantAPIKeyExchange_IPAllowlist(t *testing.T) {
	h := newAPIKeyHarness(t)
	req := h.createReq()
	req.IPAllowlist = []string{"198.51.100.0/24", "203.0.113.7"}
	created, err := h.svc.Create(context.Background(), h.tenantID, h.creatorID, req)
	require.NoError(t, err)
	clientID, secret := splitKey(t, created.Key)

	for _, ip := range []string{"198.51.100.20", "203.0.113.7"} {
		_, err := h.svc.Exchange(context.Background(), clientID, secret, ip)
		require.NoError(t, err, ip)
	}
	for _, ip := range []string{"203.0.113.8", "garbage", ""} {
		_, err := h.svc.Exchange(context.Background(), clientID, secret, ip)
		require.ErrorIs(t, err, ErrAPIKeyIPNotAllowed, ip)
	}
}

func TestTenantAPIKeyRotate_GraceWindow(t *testing.T) {
	h := newAPIKeyHarness(t)
	created, err := h.svc.Create(context.Background(), h.tenantID, h.creatorID, h.createReq())
	require.NoError(t, err)
	clientID, oldSecret := splitKey(t, created.Key)
	ctx := context.Background()

	rotated, err := h.svc.Rotate(ctx, h.tenantID, h.creatorID, created.ID, nil)
	require.NoError(t, err)
	newClientID, newSecret := splitKey(t, rotated.Key)
	assert.Equal(t, clientID, newClientID, "rotation keeps the key id")
	assert.NotEqual(t, oldSecret, newSecret)
	require.NotNil(t, rotated.GraceValidUntil)
	assert.Equal(t, h.now.Add(24*time.Hour), *rotated.GraceValidUntil)

	_, err = h.svc.Exchange(ctx, clientID, newSecret, "203.0.113.9")
	require.NoError(t, err, "new secret works")
	_, err = h.svc.Exchange(ctx, clientID, oldSecret, "203.0.113.9")
	require.NoError(t, err, "old secret works inside the grace window")

	h.now = h.now.Add(25 * time.Hour)
	_, err = h.svc.Exchange(ctx, clientID, oldSecret, "203.0.113.9")
	require.ErrorIs(t, err, ErrAPIKeyInvalidClient, "old secret dies after the grace window")
	_, err = h.svc.Exchange(ctx, clientID, newSecret, "203.0.113.9")
	require.NoError(t, err)
}

func TestTenantAPIKeyRotate_ZeroGraceCutsOldSecretImmediately(t *testing.T) {
	h := newAPIKeyHarness(t)
	created, err := h.svc.Create(context.Background(), h.tenantID, h.creatorID, h.createReq())
	require.NoError(t, err)
	clientID, oldSecret := splitKey(t, created.Key)

	zero := time.Duration(0)
	_, err = h.svc.Rotate(context.Background(), h.tenantID, h.creatorID, created.ID, &zero)
	require.NoError(t, err)
	_, err = h.svc.Exchange(context.Background(), clientID, oldSecret, "203.0.113.9")
	require.ErrorIs(t, err, ErrAPIKeyInvalidClient)

	tooLong := 8 * 24 * time.Hour
	_, err = h.svc.Rotate(context.Background(), h.tenantID, h.creatorID, created.ID, &tooLong)
	var verr *APIKeyValidationError
	require.ErrorAs(t, err, &verr)
}

func TestTenantAPIKeyRevoke(t *testing.T) {
	h := newAPIKeyHarness(t)
	created, err := h.svc.Create(context.Background(), h.tenantID, h.creatorID, h.createReq())
	require.NoError(t, err)
	clientID, secret := splitKey(t, created.Key)
	ctx := context.Background()

	h.companies.fail = true // business is down at revoke time
	require.NoError(t, h.svc.Revoke(ctx, h.tenantID, h.creatorID, created.ID))

	_, err = h.svc.Exchange(ctx, clientID, secret, "203.0.113.9")
	require.ErrorIs(t, err, ErrAPIKeyInvalidClient, "revoked key cannot mint tokens")
	assert.Contains(t, h.spice.deleted, spiceEdge{h.tenantID, created.ID, h.roleID}, "role edge removed")
	assert.Equal(t, models.APIKeyCompanySyncPendingRemove, h.repo.keys[created.ID].CompanySyncState)

	// Delete is refused until the company edges are gone.
	require.ErrorIs(t, h.svc.Delete(ctx, h.tenantID, h.creatorID, created.ID), ErrAPIKeyCompanySyncPending)

	h.companies.fail = false
	_, err = h.svc.ProcessPendingCompanySync(ctx)
	require.NoError(t, err)
	require.Len(t, h.companies.removed, 1)
	require.NoError(t, h.svc.Delete(ctx, h.tenantID, h.creatorID, created.ID))
	assert.NotContains(t, h.repo.keys, created.ID)

	// Revoke is idempotent and tenant-scoped.
	require.ErrorIs(t, h.svc.Revoke(ctx, uuid.New(), h.creatorID, created.ID), ErrAPIKeyNotFound)
}

func TestTenantAPIKeyDelete_RequiresRevoked(t *testing.T) {
	h := newAPIKeyHarness(t)
	created, err := h.svc.Create(context.Background(), h.tenantID, h.creatorID, h.createReq())
	require.NoError(t, err)
	err = h.svc.Delete(context.Background(), h.tenantID, h.creatorID, created.ID)
	var verr *APIKeyValidationError
	require.ErrorAs(t, err, &verr)
}

func TestTenantAPIKeyList_NeverLeaksSecrets(t *testing.T) {
	h := newAPIKeyHarness(t)
	created, err := h.svc.Create(context.Background(), h.tenantID, h.creatorID, h.createReq())
	require.NoError(t, err)
	list, err := h.svc.List(context.Background(), h.tenantID)
	require.NoError(t, err)
	require.Len(t, list, 1)
	assert.Equal(t, "lgk_live_"+*h.repo.keys[created.ID].KeyID, list[0].ClientID)
	assert.Equal(t, "active", list[0].Status)
}

// ---------------------------------------------------------------------------
// Claims
// ---------------------------------------------------------------------------

func TestBuildAPIKeyClaims_Golden(t *testing.T) {
	tenantID := uuid.MustParse("11111111-1111-1111-1111-111111111111")
	keyID := uuid.MustParse("22222222-2222-2222-2222-222222222222")
	now := time.Unix(1790000000, 0)

	read := BuildAPIKeyClaims("https://id.example.test", now, "jti-1", APIKeyTokenParams{
		TenantID: tenantID, KeyID: keyID, Access: "read", Audience: "https://api.example.test", TTL: 600 * time.Second,
	})
	assert.Equal(t, jwt.MapClaims{
		"iss":        "https://id.example.test",
		"aud":        jwt.ClaimStrings{"https://api.example.test"},
		"iat":        int64(1790000000),
		"nbf":        int64(1790000000),
		"exp":        int64(1790000600),
		"jti":        "jti-1",
		"sub":        "22222222-2222-2222-2222-222222222222",
		"tenant_id":  "11111111-1111-1111-1111-111111111111",
		"type":       "api_key",
		"api_key_id": "22222222-2222-2222-2222-222222222222",
		"scope":      "erp.read",
	}, read)

	write := BuildAPIKeyClaims("https://id.example.test", now, "jti-2", APIKeyTokenParams{
		TenantID: tenantID, KeyID: keyID, Access: "write", Audience: "https://api.example.test", TTL: 600 * time.Second,
	})
	assert.Equal(t, "erp.read erp.write", write["scope"])

	for _, claims := range []jwt.MapClaims{read, write} {
		assert.NotContains(t, claims, "roles", "a key token must not carry a roles claim")
		assert.NotContains(t, claims, "permissions")
		assert.NotContains(t, claims["aud"], "hexxlock-services")
	}
}

func TestMintAPIKeyToken_SignsRS256WithProviderKey(t *testing.T) {
	svc := newTestOAuthProviderService(t, nil, nil)
	tenantID, keyID := uuid.New(), uuid.New()

	signed, err := svc.MintAPIKeyToken(APIKeyTokenParams{
		TenantID: tenantID, KeyID: keyID, Access: "write", Audience: "https://api.example.test", TTL: 600 * time.Second,
	})
	require.NoError(t, err)

	parsed, err := jwt.Parse(signed, func(tok *jwt.Token) (interface{}, error) {
		assert.Equal(t, "RS256", tok.Method.Alg())
		kid, pub := svc.SigningKeyInfo()
		assert.Equal(t, kid, tok.Header["kid"])
		return pub, nil
	}, jwt.WithAudience("https://api.example.test"), jwt.WithValidMethods([]string{"RS256"}))
	require.NoError(t, err)
	claims := parsed.Claims.(jwt.MapClaims)
	assert.Equal(t, "api_key", claims["type"])
	assert.Equal(t, keyID.String(), claims["sub"])
	assert.Equal(t, tenantID.String(), claims["tenant_id"])
	assert.NotContains(t, claims, "roles")

	_, err = svc.MintAPIKeyToken(APIKeyTokenParams{TenantID: tenantID, KeyID: keyID, Access: "read", TTL: time.Minute})
	require.Error(t, err, "audience is mandatory")
}

func TestTenantAPIKeyExchange_WrongSecretIsAuditedWithoutSecret(t *testing.T) {
	h := newAPIKeyHarness(t)
	created, err := h.svc.Create(context.Background(), h.tenantID, h.creatorID, h.createReq())
	require.NoError(t, err)
	clientID, _ := splitKey(t, created.Key)
	wrong := strings.Repeat("b", 43)
	h.audit.events = nil

	_, err = h.svc.Exchange(context.Background(), clientID, wrong, "203.0.113.9")
	require.ErrorIs(t, err, ErrAPIKeyInvalidClient)

	require.Len(t, h.audit.events, 1)
	ev := h.audit.events[0]
	assert.Equal(t, AuditActionAPIKeyAuthDenied, ev.action)
	assert.False(t, ev.success)
	assert.Equal(t, "invalid_secret", ev.details["reason"])
	for _, v := range ev.details {
		assert.NotContains(t, fmt.Sprint(v), wrong)
	}

	// Unknown key ids are not audited (nothing to attribute them to).
	h.audit.events = nil
	_, _ = h.svc.Exchange(context.Background(), "lgk_live_aaaaaaaaaaaaaaaa", wrong, "203.0.113.9")
	assert.Empty(t, h.audit.events)
}

func TestTenantAPIKeyCreate_NonAdminCreatorLimitedToOwnCompanies(t *testing.T) {
	h := newAPIKeyHarness(t)
	mine, theirs := uuid.New(), uuid.New()
	h.spice.denyCompanies = map[string]bool{theirs.String(): true}

	req := h.createReq()
	req.CompanyIDs = []uuid.UUID{mine}
	_, err := h.svc.Create(context.Background(), h.tenantID, h.creatorID, req)
	require.NoError(t, err)

	req = h.createReq()
	req.CompanyIDs = []uuid.UUID{mine, theirs}
	before := len(h.repo.keys)
	_, err = h.svc.Create(context.Background(), h.tenantID, h.creatorID, req)
	require.ErrorIs(t, err, ErrAPIKeyCompanyNotHeld)
	assert.Len(t, h.repo.keys, before, "no key row may be created")
}

func TestTenantAPIKeyCreate_AdminCreatorUnrestrictedByCompany(t *testing.T) {
	h := newAPIKeyHarness(t)
	h.userRoles.held = []models.Role{{ID: uuid.New(), TenantID: h.tenantID, Name: "owner"}}
	other := uuid.New()
	h.spice.denyCompanies = map[string]bool{other.String(): true}

	req := h.createReq()
	req.CompanyIDs = []uuid.UUID{other}
	_, err := h.svc.Create(context.Background(), h.tenantID, h.creatorID, req)
	require.NoError(t, err)
	assert.Empty(t, h.spice.checked, "admins skip the company membership check")
}

// --- B7: pepper versioning ---

func TestTenantAPIKey_HashAlgIsPepperVersioned(t *testing.T) {
	h := newAPIKeyHarness(t)
	created, err := h.svc.Create(context.Background(), h.tenantID, h.creatorID, h.createReq())
	require.NoError(t, err)
	assert.Equal(t, "hmac-sha256:v1", h.repo.keys[created.ID].HashAlg)
}

func TestTenantAPIKeyExchange_PepperRotationKeepsOldKeysValid(t *testing.T) {
	h := newAPIKeyHarness(t)
	ctx := context.Background()
	created, err := h.svc.Create(ctx, h.tenantID, h.creatorID, h.createReq())
	require.NoError(t, err)
	clientID, secret := splitKey(t, created.Key)

	// Operator adds pepper v2 and makes it current; the v1 key still verifies.
	h.svc.peppers["v2"] = []byte("second-pepper-not-a-secret")
	h.svc.pepperVersion = "v2"
	_, err = h.svc.Exchange(ctx, clientID, secret, "203.0.113.9")
	require.NoError(t, err)

	// Rotation re-hashes with v2 and the old (v1) secret survives the grace.
	rotated, err := h.svc.Rotate(ctx, h.tenantID, h.creatorID, created.ID, nil)
	require.NoError(t, err)
	assert.Equal(t, "hmac-sha256:v2", h.repo.keys[created.ID].HashAlg)
	_, newSecret := splitKey(t, rotated.Key)
	_, err = h.svc.Exchange(ctx, clientID, newSecret, "203.0.113.9")
	require.NoError(t, err)
	_, err = h.svc.Exchange(ctx, clientID, secret, "203.0.113.9")
	require.NoError(t, err, "previous secret (v1 pepper) valid during grace")

	// Dropping the v1 pepper stops v1 hashes from verifying (fail closed).
	delete(h.svc.peppers, "v1")
	_, err = h.svc.Exchange(ctx, clientID, secret, "203.0.113.9")
	require.ErrorIs(t, err, ErrAPIKeyInvalidClient)
}

func TestTenantAPIKeyExchange_UnversionedHashAlgNeverAuthenticates(t *testing.T) {
	h := newAPIKeyHarness(t)
	ctx := context.Background()
	created, err := h.svc.Create(ctx, h.tenantID, h.creatorID, h.createReq())
	require.NoError(t, err)
	clientID, secret := splitKey(t, created.Key)
	h.repo.keys[created.ID].HashAlg = "hmac-sha256"
	_, err = h.svc.Exchange(ctx, clientID, secret, "203.0.113.9")
	require.ErrorIs(t, err, ErrAPIKeyInvalidClient)
}

// --- B6: company sync ---

func TestTenantAPIKeyCreate_RoleEdgeFailureRevokesAndQueuesRemoval(t *testing.T) {
	h := newAPIKeyHarness(t)
	h.spice.failWrite = true
	_, err := h.svc.Create(context.Background(), h.tenantID, h.creatorID, h.createReq())
	require.Error(t, err)
	require.Len(t, h.repo.keys, 1)
	for _, k := range h.repo.keys {
		assert.NotNil(t, k.RevokedAt)
		assert.Equal(t, models.APIKeyCompanySyncPendingRemove, k.CompanySyncState,
			"a revoked key must never be left pending_add")
	}
}

func TestTenantAPIKeyCompanySync_RevokedPendingAddBecomesRemove(t *testing.T) {
	h := newAPIKeyHarness(t)
	ctx := context.Background()
	created, err := h.svc.Create(ctx, h.tenantID, h.creatorID, h.createReq())
	require.NoError(t, err)
	k := h.repo.keys[created.ID]
	now := time.Now()
	k.IsActive, k.RevokedAt = false, &now
	k.CompanySyncState, k.CompanySyncNextAt = models.APIKeyCompanySyncPendingAdd, nil
	h.companies.added, h.companies.removed = nil, nil

	_, err = h.svc.ProcessPendingCompanySync(ctx)
	require.NoError(t, err)
	assert.Empty(t, h.companies.added, "revoked key must not gain company edges")
	assert.Len(t, h.companies.removed, 1)
	assert.Equal(t, models.APIKeyCompanySyncSynced, h.repo.keys[created.ID].CompanySyncState)
}

func TestTenantAPIKeyCompanySync_CompareAndSetLosesToConcurrentRevoke(t *testing.T) {
	h := newAPIKeyHarness(t)
	ctx := context.Background()
	h.companies.fail = true
	created, err := h.svc.Create(ctx, h.tenantID, h.creatorID, h.createReq())
	require.NoError(t, err)
	stale := *h.repo.keys[created.ID] // worker's view: pending_add
	require.Equal(t, models.APIKeyCompanySyncPendingAdd, stale.CompanySyncState)

	// A revoke lands before the worker records its outcome.
	require.NoError(t, h.svc.Revoke(ctx, h.tenantID, h.creatorID, created.ID))
	stored := h.repo.keys[created.ID].CompanySyncState

	h.companies.fail = false
	h.svc.syncCompanies(ctx, &stale) // would have written synced/pending_add
	assert.Equal(t, stored, h.repo.keys[created.ID].CompanySyncState, "stale writer must not overwrite")
}

func TestTenantAPIKeyDelete_OnlyWhenRevokedAndSynced(t *testing.T) {
	h := newAPIKeyHarness(t)
	ctx := context.Background()
	created, err := h.svc.Create(ctx, h.tenantID, h.creatorID, h.createReq())
	require.NoError(t, err)
	// Active key: refused.
	require.Error(t, h.svc.Delete(ctx, h.tenantID, h.creatorID, created.ID))
	// Inactive but not revoked (e.g. is_active=false only) is also refused.
	h.repo.keys[created.ID].IsActive = false
	require.Error(t, h.svc.Delete(ctx, h.tenantID, h.creatorID, created.ID))
	assert.Contains(t, h.repo.keys, created.ID)
}

func TestTenantAPIKeyRevoke_ReturnsRoleEdgeFreeRowEvenWhenInlineSyncFails(t *testing.T) {
	h := newAPIKeyHarness(t)
	ctx := context.Background()
	created, err := h.svc.Create(ctx, h.tenantID, h.creatorID, h.createReq())
	require.NoError(t, err)
	h.companies.fail = true
	require.NoError(t, h.svc.Revoke(ctx, h.tenantID, h.creatorID, created.ID))
	assert.Equal(t, models.APIKeyCompanySyncPendingRemove, h.repo.keys[created.ID].CompanySyncState)
}

func TestTenantAPIKeyExchange_DeniesRoleGainingForbiddenPermission(t *testing.T) {
	h := newAPIKeyHarness(t)
	created, err := h.svc.Create(context.Background(), h.tenantID, h.creatorID, h.createReq())
	require.NoError(t, err)
	clientID, secret := splitKey(t, created.Key)

	// A system provisioner adds a forbidden permission after key creation.
	h.roles.perms[h.roleID] = append(h.roles.perms[h.roleID], "iam:users:read")
	h.audit.events = nil

	_, err = h.svc.Exchange(context.Background(), clientID, secret, "203.0.113.9")
	require.ErrorIs(t, err, ErrAPIKeyInvalidClient)
	assert.Empty(t, h.minter.params)
	require.Len(t, h.audit.events, 1)
	assert.Equal(t, AuditActionAPIKeyAuthDenied, h.audit.events[0].action)
	assert.Equal(t, "forbidden_permission", h.audit.events[0].details["reason"])
}

func TestTenantAPIKeySync_LostCASOnRevokedKeyQueuesRemoval(t *testing.T) {
	h := newAPIKeyHarness(t)
	h.companies.onAdd = func() {
		for _, k := range h.repo.keys {
			now := time.Now()
			k.RevokedAt, k.IsActive = &now, false
			k.CompanySyncState = models.APIKeyCompanySyncSynced // another actor moved it
		}
	}
	created, err := h.svc.Create(context.Background(), h.tenantID, h.creatorID, h.createReq())
	require.NoError(t, err)
	require.NotNil(t, created)
	require.Len(t, h.repo.keys, 1)
	for _, k := range h.repo.keys {
		assert.Equal(t, models.APIKeyCompanySyncPendingRemove, k.CompanySyncState)
	}
}

type fakeAuditDedupe struct {
	seen map[string]bool
	err  error
}

func (f *fakeAuditDedupe) SetNX(_ context.Context, key string, _ interface{}, _ time.Duration) (bool, error) {
	if f.err != nil {
		return false, f.err
	}
	if f.seen[key] {
		return false, nil
	}
	f.seen[key] = true
	return true, nil
}

func TestTenantAPIKeyExchange_WrongSecretAuditDedupedPerKeyPerMinute(t *testing.T) {
	h := newAPIKeyHarness(t)
	dedupe := &fakeAuditDedupe{seen: map[string]bool{}}
	h.svc.auditDedupe = dedupe
	created, err := h.svc.Create(context.Background(), h.tenantID, h.creatorID, h.createReq())
	require.NoError(t, err)
	clientID, _ := splitKey(t, created.Key)
	wrong := strings.Repeat("b", 43)
	h.audit.events = nil

	for i := 0; i < 3; i++ {
		_, _ = h.svc.Exchange(context.Background(), clientID, wrong, "203.0.113.9")
	}
	assert.Len(t, h.audit.events, 1)

	// Redis failure fails open: every attempt is audited.
	dedupe.err = errors.New("redis down")
	h.audit.events = nil
	for i := 0; i < 2; i++ {
		_, _ = h.svc.Exchange(context.Background(), clientID, wrong, "203.0.113.9")
	}
	assert.Len(t, h.audit.events, 2)
}

func TestTenantAPIKeyCreate_CapRaceBackOutHardDeletes(t *testing.T) {
	h := newAPIKeyHarness(t)
	h.repo.activeSeq = []int{MaxActiveTenantAPIKeys - 1, MaxActiveTenantAPIKeys + 1}
	_, err := h.svc.Create(context.Background(), h.tenantID, h.creatorID, h.createReq())
	require.ErrorIs(t, err, ErrAPIKeyCapReached)
	assert.Empty(t, h.repo.keys)
}
