// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/authorization"
	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/pkg/config"
	"github.com/dogukanturhal/falcon-id/pkg/logger"
)

// Tenant API key limits and defaults (WO#20).
const (
	// MaxActiveTenantAPIKeys caps active keys per tenant.
	MaxActiveTenantAPIKeys = 10
	// MaxTenantAPIKeyCompanies / Roles bound the per-key edge fan-out.
	MaxTenantAPIKeyCompanies = 50
	MaxTenantAPIKeyRoles     = 20
	maxTenantAPIKeyIPs       = 20
	maxTenantAPIKeyNameLen   = 100

	defaultTenantAPIKeyLifetime = 365 * 24 * time.Hour
	maxTenantAPIKeyLifetime     = 2 * 365 * 24 * time.Hour
	minTenantAPIKeyLifetime     = time.Hour

	defaultRotationGrace = 24 * time.Hour
	maxRotationGrace     = 7 * 24 * time.Hour

	// apiRequestsMonthlyLimit is the plan limit key that must be non-zero for
	// a tenant to hold or use API keys (-1 = unlimited).
	apiRequestsMonthlyLimit = "api_requests_monthly"

	tenantAPIKeyKeyIDLen  = 16 // base32 chars of 10 random bytes
	tenantAPIKeySecretLen = 43 // base64url chars of 32 random bytes

	companySyncBackoffBase = 30 * time.Second
	companySyncBackoffMax  = time.Hour
	companySyncBatch       = 50
)

// Errors returned by TenantAPIKeyService. Handlers map them to HTTP statuses.
var (
	ErrDeveloperKeysDisabled     = errors.New("developer API keys are not enabled for this tenant")
	ErrAPIKeyPepperMissing       = errors.New("developer API key pepper is not configured")
	ErrAPIKeyCapReached          = errors.New("active API key limit reached")
	ErrAPIKeyPlanLimit           = errors.New("plan does not include API access")
	ErrAPIKeyNotFound            = errors.New("API key not found")
	ErrAPIKeyRoleNotHeld         = errors.New("you can only grant roles you hold yourself")
	ErrAPIKeyRoleExcluded        = errors.New("role cannot be granted to an API key")
	ErrAPIKeyCompanyNotHeld      = errors.New("you can only grant companies you can access yourself")
	ErrAPIKeyNotActive           = errors.New("API key is not active")
	ErrAPIKeyCompanySyncPending  = errors.New("company access removal is still pending")
	ErrAPIKeyInvalidClient       = errors.New("invalid_client")
	ErrAPIKeyIPNotAllowed        = errors.New("ip_not_allowed")
	ErrAPIKeyTenantSuspended     = errors.New("tenant suspended")
	errAPIKeyCompanyClientAbsent = errors.New("business company client not configured")
)

// APIKeyValidationError is a client-correctable request error.
type APIKeyValidationError struct{ Msg string }

func (e *APIKeyValidationError) Error() string { return e.Msg }

func invalidAPIKeyRequest(format string, args ...interface{}) error {
	return &APIKeyValidationError{Msg: fmt.Sprintf(format, args...)}
}

// tenantAPIKeyRepo is the repository slice TenantAPIKeyService needs.
type tenantAPIKeyRepo interface {
	CreateTenantKey(ctx context.Context, key *models.APIKey) error
	GetTenantKey(ctx context.Context, tenantID, id uuid.UUID) (*models.APIKey, error)
	GetByKeyID(ctx context.Context, keyID string) (*models.APIKey, error)
	ListTenantKeys(ctx context.Context, tenantID uuid.UUID) ([]*models.APIKey, error)
	ActiveCountByTenant(ctx context.Context, tenantID uuid.UUID) (int, error)
	RotateSecret(ctx context.Context, id uuid.UUID, newHash, hashAlg string, prevValidUntil time.Time) error
	RevokeTenantKey(ctx context.Context, id uuid.UUID) error
	DeleteTenantKey(ctx context.Context, tenantID, id uuid.UUID) error
	// HardDeleteTenantKey deletes the row whatever its revoke or sync state. Only
	// for Create's cap-race back-out, where no edges were ever written.
	HardDeleteTenantKey(ctx context.Context, tenantID, id uuid.UUID) error
	// SetCompanySync is a compare-and-set on company_sync_state: it reports
	// false when the row no longer has expectedState.
	SetCompanySync(ctx context.Context, id uuid.UUID, expectedState, state string, attempts int, nextAt *time.Time) (bool, error)
	ListPendingCompanySync(ctx context.Context, limit int) ([]*models.APIKey, error)
	UpdateLastUsed(ctx context.Context, id uuid.UUID, ip string) error
}

// tenantAPIKeyRoleRepo resolves a role and the permissions it grants.
type tenantAPIKeyRoleRepo interface {
	GetByIDAndTenant(ctx context.Context, id, tenantID uuid.UUID) (*models.Role, error)
	GetRolePermissions(ctx context.Context, roleID uuid.UUID) ([]models.Permission, error)
}

// tenantAPIKeyUserRoles lists the roles the creating user holds.
type tenantAPIKeyUserRoles interface {
	GetUserRoles(ctx context.Context, userID uuid.UUID) ([]models.Role, error)
}

// tenantAPIKeySpiceDB writes and removes the key's role edges. The key's row
// id is the SpiceDB user subject.
type tenantAPIKeySpiceDB interface {
	WriteUserRoleUntil(ctx context.Context, tenantID, userID, roleID uuid.UUID, expiresAt time.Time) (string, error)
	DeleteUserRole(ctx context.Context, tenantID, userID, roleID uuid.UUID) (string, error)
	CheckPermission(ctx context.Context, tenantID, userID uuid.UUID, objectType, objectID, permission string) (bool, error)
}

// TenantAPIKeyCompanyClient manages the business-side company edges of a key
// principal (POST/DELETE .../api-key-principals/{keyId}/companies).
type TenantAPIKeyCompanyClient interface {
	AddCompanies(ctx context.Context, tenantID, keyID uuid.UUID, companyIDs []uuid.UUID) error
	RemoveCompanies(ctx context.Context, tenantID, keyID uuid.UUID, companyIDs []uuid.UUID) error
}

// tenantAPIKeyAuditor records audit events.
type tenantAPIKeyAuditor interface {
	LogTenantAPIKeyEvent(ctx context.Context, tenantID uuid.UUID, actorID *uuid.UUID, keyID uuid.UUID, action string, success bool, details map[string]interface{})
}

// tenantAPIKeyEntitlements reads plan limits.
type tenantAPIKeyEntitlements interface {
	GetFlags(ctx context.Context, tenantID uuid.UUID) (*models.TenantEntitlementFlags, error)
}

// tenantAPIKeyAuditDedupe is the Redis SETNX used to dedupe wrong-secret audits.
type tenantAPIKeyAuditDedupe interface {
	SetNX(ctx context.Context, key string, value interface{}, expiration time.Duration) (bool, error)
}

// wrongSecretAuditWindow is the per-key_id dedupe window for wrong-secret audits.
const wrongSecretAuditWindow = 60 * time.Second

// tenantAPIKeyMinter signs the exchanged access token.
type tenantAPIKeyMinter interface {
	MintAPIKeyToken(p APIKeyTokenParams) (string, error)
}

// TenantAPIKeyService issues, rotates, revokes and authenticates tenant API
// keys (lgk_live_<key_id>_<secret>).
type TenantAPIKeyService struct {
	repo         tenantAPIKeyRepo
	roles        tenantAPIKeyRoleRepo
	userRoles    tenantAPIKeyUserRoles
	spicedb      tenantAPIKeySpiceDB
	companies    TenantAPIKeyCompanyClient
	audit        tenantAPIKeyAuditor
	entitlements tenantAPIKeyEntitlements
	minter       tenantAPIKeyMinter
	suspension   TenantSuspensionChecker
	auditDedupe  tenantAPIKeyAuditDedupe

	enabled   bool
	allowlist map[uuid.UUID]struct{}
	// peppers maps a pepper version ("v1") to its secret; pepperVersion is
	// the one new hashes use. hash_alg stores "hmac-sha256:<version>".
	peppers       map[string][]byte
	pepperVersion string
	audience      string
	tokenTTL      time.Duration
	now           func() time.Time

	syncMu sync.Mutex
}

// TenantAPIKeyDeps groups the collaborators of NewTenantAPIKeyService.
type TenantAPIKeyDeps struct {
	Repo         tenantAPIKeyRepo
	Roles        tenantAPIKeyRoleRepo
	UserRoles    tenantAPIKeyUserRoles
	SpiceDB      tenantAPIKeySpiceDB
	Companies    TenantAPIKeyCompanyClient
	Audit        tenantAPIKeyAuditor
	Entitlements tenantAPIKeyEntitlements
	Minter       tenantAPIKeyMinter
	Suspension   TenantSuspensionChecker
	// AuditDedupe is optional (nil audits every wrong-secret attempt).
	AuditDedupe tenantAPIKeyAuditDedupe
}

// NewTenantAPIKeyService builds the service. Flags, pepper, audience and TTL
// come from cfg; with the flag off every operation returns
// ErrDeveloperKeysDisabled.
func NewTenantAPIKeyService(cfg *config.Config, deps TenantAPIKeyDeps) *TenantAPIKeyService {
	allow := make(map[uuid.UUID]struct{}, len(cfg.DeveloperKeysTenantAllowlist))
	for _, raw := range cfg.DeveloperKeysTenantAllowlist {
		if id, err := uuid.Parse(strings.TrimSpace(raw)); err == nil {
			allow[id] = struct{}{}
		}
	}
	peppers := map[string][]byte{}
	rawPeppers, pepperVersion := cfg.DeveloperKeyPeppers()
	for version, secret := range rawPeppers {
		peppers[version] = []byte(secret)
	}
	ttl := cfg.DeveloperKeysTokenTTL
	if ttl <= 0 {
		ttl = 600 * time.Second
	}
	return &TenantAPIKeyService{
		repo:          deps.Repo,
		roles:         deps.Roles,
		userRoles:     deps.UserRoles,
		spicedb:       deps.SpiceDB,
		companies:     deps.Companies,
		audit:         deps.Audit,
		entitlements:  deps.Entitlements,
		minter:        deps.Minter,
		suspension:    deps.Suspension,
		auditDedupe:   deps.AuditDedupe,
		enabled:       cfg.DeveloperKeysEnabled,
		allowlist:     allow,
		peppers:       peppers,
		pepperVersion: pepperVersion,
		audience:      cfg.DeveloperKeysAudience,
		tokenTTL:      ttl,
		now:           time.Now,
	}
}

func (s *TenantAPIKeyService) auditEvent(ctx context.Context, tenantID uuid.UUID, actorID *uuid.UUID, keyID uuid.UUID, action string, success bool, details map[string]interface{}) {
	if s.audit != nil {
		s.audit.LogTenantAPIKeyEvent(ctx, tenantID, actorID, keyID, action, success, details)
	}
}

// Enabled reports whether developer keys are on for tenantID: the global flag
// is on and the tenant is in the allowlist (an empty allowlist means every
// tenant).
func (s *TenantAPIKeyService) Enabled(tenantID uuid.UUID) bool {
	if s == nil || !s.enabled {
		return false
	}
	if len(s.allowlist) == 0 {
		return true
	}
	_, ok := s.allowlist[tenantID]
	return ok
}

// ---------------------------------------------------------------------------
// Key material
// ---------------------------------------------------------------------------

var keyIDEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)

// GenerateTenantAPIKey returns a fresh key id, secret and the full key.
func GenerateTenantAPIKey() (keyID, secret, full string, err error) {
	idBytes := make([]byte, 10)
	secretBytes := make([]byte, 32)
	if _, err = rand.Read(idBytes); err != nil {
		return "", "", "", fmt.Errorf("generate key id: %w", err)
	}
	if _, err = rand.Read(secretBytes); err != nil {
		return "", "", "", fmt.Errorf("generate key secret: %w", err)
	}
	keyID = strings.ToLower(keyIDEncoding.EncodeToString(idBytes))
	secret = base64.RawURLEncoding.EncodeToString(secretBytes)
	return keyID, secret, models.TenantAPIKeyPrefix + keyID + "_" + secret, nil
}

// ParseTenantAPIKey splits lgk_live_<key_id>_<secret>.
func ParseTenantAPIKey(raw string) (keyID, secret string, ok bool) {
	rest, found := strings.CutPrefix(raw, models.TenantAPIKeyPrefix)
	if !found || len(rest) != tenantAPIKeyKeyIDLen+1+tenantAPIKeySecretLen || rest[tenantAPIKeyKeyIDLen] != '_' {
		return "", "", false
	}
	keyID, secret = rest[:tenantAPIKeyKeyIDLen], rest[tenantAPIKeyKeyIDLen+1:]
	if !validKeyID(keyID) {
		return "", "", false
	}
	return keyID, secret, true
}

func validKeyID(id string) bool {
	if len(id) != tenantAPIKeyKeyIDLen {
		return false
	}
	for _, c := range id {
		if (c < 'a' || c > 'z') && (c < '2' || c > '7') {
			return false
		}
	}
	return true
}

// HashTenantAPISecret returns hex(HMAC-SHA256(pepper, key_id "." secret)).
// Binding the key id stops a hash from being replayed onto another key row.
func HashTenantAPISecret(pepper []byte, keyID, secret string) string {
	mac := hmac.New(sha256.New, pepper)
	mac.Write([]byte(keyID))
	mac.Write([]byte{'.'})
	mac.Write([]byte(secret))
	return hex.EncodeToString(mac.Sum(nil))
}

// currentPepper is the pepper new hashes are made with (nil when unset).
func (s *TenantAPIKeyService) currentPepper() []byte {
	return s.peppers[s.pepperVersion]
}

// currentHashAlg is the hash_alg tag stored with newly made hashes.
func (s *TenantAPIKeyService) currentHashAlg() string {
	return models.APIKeyHashAlgHMAC(s.pepperVersion)
}

func secretMatchesPepper(pepper []byte, hash, keyID, secret string) bool {
	want := HashTenantAPISecret(pepper, keyID, secret)
	return subtle.ConstantTimeCompare([]byte(want), []byte(hash)) == 1
}

// secretMatchesAlg verifies hash with the pepper version named by hashAlg.
func (s *TenantAPIKeyService) secretMatchesAlg(hashAlg, hash, keyID, secret string) bool {
	version, ok := models.APIKeyPepperVersion(hashAlg)
	if !ok {
		return false
	}
	pepper := s.peppers[version]
	if len(pepper) == 0 {
		return false
	}
	return secretMatchesPepper(pepper, hash, keyID, secret)
}

// secretMatchesAnyPepper verifies hash against every configured pepper. It is
// used for the rotation-grace hash, whose pepper version is not recorded
// separately from the current hash's.
func (s *TenantAPIKeyService) secretMatchesAnyPepper(hash, keyID, secret string) bool {
	matched := false
	for _, pepper := range s.peppers {
		if secretMatchesPepper(pepper, hash, keyID, secret) {
			matched = true
		}
	}
	return matched
}

// ---------------------------------------------------------------------------
// Role rules
// ---------------------------------------------------------------------------

// RoleForbiddenForAPIKey reports why a role may never be granted to an API
// key: tenant-admin roles (owner, org_admin, ...) and any role carrying a
// forbidden permission.
func RoleForbiddenForAPIKey(role *models.Role, perms []models.Permission) (bool, string) {
	if authorization.IsTenantAdministratorRole(role.Name) {
		return true, "administrator roles cannot be granted to API keys"
	}
	for _, p := range perms {
		if PermissionForbiddenForAPIKey(p.Name) {
			return true, fmt.Sprintf("role grants %s, which API keys cannot hold", p.Name)
		}
	}
	return false, ""
}

// PermissionForbiddenForAPIKey is true for iam:* (identity and access
// management, including the developer permissions themselves), platform:*,
// billing, approval administration, and wildcards.
func PermissionForbiddenForAPIKey(name string) bool {
	n := strings.ToLower(name)
	switch {
	case n == "*" || strings.Contains(n, "*"):
		return true
	case strings.HasPrefix(n, "iam:"), strings.HasPrefix(n, "platform:"):
		return true
	case strings.Contains(n, "billing"):
		return true
	}
	parts := strings.Split(n, ":")
	if len(parts) == 3 && strings.Contains(parts[1], "approval") {
		switch parts[2] {
		case "admin", "manage", "configure", "delegate", "override":
			return true
		}
	}
	return false
}

// validateRoles enforces the role-subset rule: every chosen role belongs to
// the tenant, is held by the creator, and is not an excluded role.
func (s *TenantAPIKeyService) validateRoles(ctx context.Context, tenantID, creatorID uuid.UUID, roleIDs []uuid.UUID) (creatorIsAdmin bool, err error) {
	held, err := s.userRoles.GetUserRoles(ctx, creatorID)
	if err != nil {
		return false, fmt.Errorf("load creator roles: %w", err)
	}
	heldSet := make(map[uuid.UUID]struct{}, len(held))
	for _, r := range held {
		if r.TenantID == tenantID {
			heldSet[r.ID] = struct{}{}
			if authorization.IsTenantAdministratorRole(r.Name) {
				creatorIsAdmin = true
			}
		}
	}
	for _, roleID := range roleIDs {
		role, err := s.roles.GetByIDAndTenant(ctx, roleID, tenantID)
		if err != nil {
			return false, fmt.Errorf("load role %s: %w", roleID, err)
		}
		if role == nil {
			return false, invalidAPIKeyRequest("unknown role %s", roleID)
		}
		perms, err := s.roles.GetRolePermissions(ctx, roleID)
		if err != nil {
			return false, fmt.Errorf("load role permissions %s: %w", roleID, err)
		}
		if forbidden, why := RoleForbiddenForAPIKey(role, perms); forbidden {
			return false, fmt.Errorf("%w: %s (%s)", ErrAPIKeyRoleExcluded, role.Name, why)
		}
		if _, ok := heldSet[roleID]; !ok && !creatorIsAdmin {
			return false, fmt.Errorf("%w: %s", ErrAPIKeyRoleNotHeld, role.Name)
		}
	}
	return creatorIsAdmin, nil
}

// validateCompanyAccess keeps a non-admin creator from granting a key
// companies they cannot reach themselves: every company must be viewable by the
// creator in SpiceDB (company#view: members reach every company through the
// tenant, guests only the companies they were granted). Owners and org_admins
// skip this check.
func (s *TenantAPIKeyService) validateCompanyAccess(ctx context.Context, tenantID, creatorID uuid.UUID, companyIDs []uuid.UUID) error {
	for _, companyID := range companyIDs {
		ok, err := s.spicedb.CheckPermission(ctx, tenantID, creatorID, "company", companyID.String(), "view")
		if err != nil {
			return fmt.Errorf("check creator access to company %s: %w", companyID, err)
		}
		if !ok {
			return fmt.Errorf("%w: %s", ErrAPIKeyCompanyNotHeld, companyID)
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Create / list / get
// ---------------------------------------------------------------------------

func (s *TenantAPIKeyService) requireReady(tenantID uuid.UUID) error {
	if !s.Enabled(tenantID) {
		return ErrDeveloperKeysDisabled
	}
	if len(s.currentPepper()) == 0 {
		return ErrAPIKeyPepperMissing
	}
	return nil
}

// planAllowsAPI is true when the tenant's api_requests_monthly limit is
// positive or unlimited (-1). A missing limit is treated as no API access.
func (s *TenantAPIKeyService) planAllowsAPI(ctx context.Context, tenantID uuid.UUID) (bool, error) {
	if s.entitlements == nil {
		return false, nil
	}
	flags, err := s.entitlements.GetFlags(ctx, tenantID)
	if err != nil {
		return false, fmt.Errorf("load entitlement limits: %w", err)
	}
	if flags == nil {
		return false, nil
	}
	limit, ok := flags.Limits[apiRequestsMonthlyLimit]
	return ok && (limit > 0 || limit == models.EntitlementLimitUnlimited), nil
}

func normaliseIPAllowlist(in []string) ([]string, error) {
	if len(in) > maxTenantAPIKeyIPs {
		return nil, invalidAPIKeyRequest("at most %d IP allowlist entries", maxTenantAPIKeyIPs)
	}
	out := make([]string, 0, len(in))
	for _, raw := range in {
		entry := strings.TrimSpace(raw)
		if entry == "" {
			continue
		}
		if _, _, err := net.ParseCIDR(entry); err != nil && net.ParseIP(entry) == nil {
			return nil, invalidAPIKeyRequest("invalid IP allowlist entry %q", entry)
		}
		out = append(out, entry)
	}
	return out, nil
}

func uniqueUUIDs(in []uuid.UUID) []uuid.UUID {
	seen := make(map[uuid.UUID]struct{}, len(in))
	out := make([]uuid.UUID, 0, len(in))
	for _, id := range in {
		if _, dup := seen[id]; dup {
			continue
		}
		seen[id] = struct{}{}
		out = append(out, id)
	}
	return out
}

func (s *TenantAPIKeyService) validateCreate(req *models.CreateTenantAPIKeyRequest) (expires time.Time, ips []string, err error) {
	name := strings.TrimSpace(req.Name)
	if name == "" || len(name) > maxTenantAPIKeyNameLen {
		return time.Time{}, nil, invalidAPIKeyRequest("name must be 1-%d characters", maxTenantAPIKeyNameLen)
	}
	req.Name = name
	if req.Access != models.APIKeyAccessRead && req.Access != models.APIKeyAccessWrite {
		return time.Time{}, nil, invalidAPIKeyRequest("access must be read or write")
	}
	req.RoleIDs = uniqueUUIDs(req.RoleIDs)
	req.CompanyIDs = uniqueUUIDs(req.CompanyIDs)
	if len(req.RoleIDs) == 0 || len(req.RoleIDs) > MaxTenantAPIKeyRoles {
		return time.Time{}, nil, invalidAPIKeyRequest("role_ids must contain 1-%d roles", MaxTenantAPIKeyRoles)
	}
	if len(req.CompanyIDs) == 0 || len(req.CompanyIDs) > MaxTenantAPIKeyCompanies {
		return time.Time{}, nil, invalidAPIKeyRequest("company_ids must contain 1-%d companies", MaxTenantAPIKeyCompanies)
	}
	now := s.now()
	expires = now.Add(defaultTenantAPIKeyLifetime)
	if req.ExpiresAt != nil {
		expires = req.ExpiresAt.UTC()
		if expires.Before(now.Add(minTenantAPIKeyLifetime)) {
			return time.Time{}, nil, invalidAPIKeyRequest("expires_at must be at least one hour away")
		}
		if expires.After(now.Add(maxTenantAPIKeyLifetime)) {
			return time.Time{}, nil, invalidAPIKeyRequest("expires_at may be at most two years away")
		}
	}
	ips, err = normaliseIPAllowlist(req.IPAllowlist)
	return expires, ips, err
}

// Create issues a new key. The full key is in the response and never again.
func (s *TenantAPIKeyService) Create(ctx context.Context, tenantID, creatorID uuid.UUID, req *models.CreateTenantAPIKeyRequest) (*models.TenantAPIKeyCreatedResponse, error) {
	if err := s.requireReady(tenantID); err != nil {
		return nil, err
	}
	expires, ips, err := s.validateCreate(req)
	if err != nil {
		return nil, err
	}
	if ok, planErr := s.planAllowsAPI(ctx, tenantID); planErr != nil {
		return nil, planErr
	} else if !ok {
		return nil, ErrAPIKeyPlanLimit
	}
	active, err := s.repo.ActiveCountByTenant(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	if active >= MaxActiveTenantAPIKeys {
		return nil, ErrAPIKeyCapReached
	}
	creatorIsAdmin, err := s.validateRoles(ctx, tenantID, creatorID, req.RoleIDs)
	if err != nil {
		return nil, err
	}
	if !creatorIsAdmin {
		if err := s.validateCompanyAccess(ctx, tenantID, creatorID, req.CompanyIDs); err != nil {
			return nil, err
		}
	}

	keyID, secret, full, err := GenerateTenantAPIKey()
	if err != nil {
		return nil, err
	}
	access := req.Access
	now := s.now()
	key := &models.APIKey{
		TenantID:          tenantID,
		UserID:            creatorID,
		CreatedBy:         &creatorID,
		Name:              req.Name,
		Description:       req.Description,
		KeyPrefix:         keyID,
		KeyID:             &keyID,
		KeyHash:           HashTenantAPISecret(s.currentPepper(), keyID, secret),
		HashAlg:           s.currentHashAlg(),
		Access:            &access,
		Scopes:            APIKeyScopes(access),
		IPWhitelist:       ips,
		RoleIDs:           req.RoleIDs,
		CompanyIDs:        req.CompanyIDs,
		ExpiresAt:         &expires,
		CompanySyncState:  models.APIKeyCompanySyncPendingAdd,
		CompanySyncNextAt: &now,
	}
	if err := s.repo.CreateTenantKey(ctx, key); err != nil {
		return nil, err
	}

	// Cap re-check after insert: two concurrent creates can both pass the
	// pre-check, so the loser backs out.
	if n, countErr := s.repo.ActiveCountByTenant(ctx, tenantID); countErr == nil && n > MaxActiveTenantAPIKeys {
		_ = s.repo.HardDeleteTenantKey(ctx, tenantID, key.ID)
		return nil, ErrAPIKeyCapReached
	}

	if err := s.writeRoleEdges(ctx, key); err != nil {
		s.removeRoleEdges(ctx, key)
		// RevokeTenantKey also queues the company-edge removal
		// (pending_remove, never pending_add) in the same statement.
		_ = s.repo.RevokeTenantKey(ctx, key.ID)
		return nil, fmt.Errorf("grant key roles: %w", err)
	}

	s.syncCompanies(ctx, key)
	s.auditEvent(ctx, tenantID, &creatorID, key.ID, AuditActionAPIKeyCreated, true, map[string]interface{}{
		"name": key.Name, "access": access, "role_ids": uuidStrings(key.RoleIDs),
		"company_ids": uuidStrings(key.CompanyIDs), "expires_at": expires.Format(time.RFC3339),
	})
	logger.Info("Tenant API key created",
		zap.String("tenant_id", tenantID.String()), zap.String("api_key_id", key.ID.String()))

	return &models.TenantAPIKeyCreatedResponse{TenantAPIKeyResponse: s.toResponse(key, now), Key: full}, nil
}

// List returns the tenant's keys.
func (s *TenantAPIKeyService) List(ctx context.Context, tenantID uuid.UUID) ([]models.TenantAPIKeyResponse, error) {
	if !s.Enabled(tenantID) {
		return nil, ErrDeveloperKeysDisabled
	}
	keys, err := s.repo.ListTenantKeys(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	now := s.now()
	out := make([]models.TenantAPIKeyResponse, 0, len(keys))
	for _, k := range keys {
		out = append(out, s.toResponse(k, now))
	}
	return out, nil
}

// Get returns one key.
func (s *TenantAPIKeyService) Get(ctx context.Context, tenantID, id uuid.UUID) (*models.TenantAPIKeyResponse, error) {
	if !s.Enabled(tenantID) {
		return nil, ErrDeveloperKeysDisabled
	}
	key, err := s.repo.GetTenantKey(ctx, tenantID, id)
	if err != nil {
		return nil, err
	}
	if key == nil {
		return nil, ErrAPIKeyNotFound
	}
	resp := s.toResponse(key, s.now())
	return &resp, nil
}

func (s *TenantAPIKeyService) toResponse(k *models.APIKey, now time.Time) models.TenantAPIKeyResponse {
	status := "active"
	switch {
	case k.RevokedAt != nil || !k.IsActive:
		status = "revoked"
	case k.ExpiresAt != nil && !k.ExpiresAt.After(now):
		status = "expired"
	}
	clientID, access := "", ""
	if k.KeyID != nil {
		clientID = models.TenantAPIKeyPrefix + *k.KeyID
	}
	if k.Access != nil {
		access = *k.Access
	}
	ips := k.IPWhitelist
	if ips == nil {
		ips = []string{}
	}
	var grace *time.Time
	if k.PrevHash != nil && k.PrevValidUntil != nil && k.PrevValidUntil.After(now) {
		grace = k.PrevValidUntil
	}
	return models.TenantAPIKeyResponse{
		ID: k.ID, ClientID: clientID, Name: k.Name, Description: k.Description, Access: access,
		RoleIDs: nonNilIDs(k.RoleIDs), CompanyIDs: nonNilIDs(k.CompanyIDs), IPAllowlist: ips,
		Status: status, CreatedAt: k.CreatedAt, CreatedBy: k.CreatedBy, ExpiresAt: k.ExpiresAt,
		LastUsedAt: k.LastUsedAt, LastUsedIP: k.LastUsedIP, RotatedAt: k.RotatedAt,
		GraceValidUntil: grace, RevokedAt: k.RevokedAt, CompanySyncState: k.CompanySyncState,
	}
}

func nonNilIDs(in []uuid.UUID) []uuid.UUID {
	if in == nil {
		return []uuid.UUID{}
	}
	return in
}

func uuidStrings(in []uuid.UUID) []string {
	out := make([]string, 0, len(in))
	for _, id := range in {
		out = append(out, id.String())
	}
	return out
}

// ---------------------------------------------------------------------------
// Rotate / revoke / delete
// ---------------------------------------------------------------------------

// Rotate replaces the key's secret. The previous secret stays valid for
// grace (default 24h, 0 to 7d; zero cuts it off immediately).
func (s *TenantAPIKeyService) Rotate(ctx context.Context, tenantID, actorID, id uuid.UUID, grace *time.Duration) (*models.TenantAPIKeyCreatedResponse, error) {
	if err := s.requireReady(tenantID); err != nil {
		return nil, err
	}
	g := defaultRotationGrace
	if grace != nil {
		g = *grace
	}
	if g < 0 || g > maxRotationGrace {
		return nil, invalidAPIKeyRequest("grace must be between 0 and %d hours", int(maxRotationGrace.Hours()))
	}
	key, err := s.repo.GetTenantKey(ctx, tenantID, id)
	if err != nil {
		return nil, err
	}
	if key == nil {
		return nil, ErrAPIKeyNotFound
	}
	now := s.now()
	if key.RevokedAt != nil || !key.IsActive || (key.ExpiresAt != nil && !key.ExpiresAt.After(now)) {
		return nil, ErrAPIKeyNotActive
	}
	keyID := stringOrEmpty(key.KeyID)
	_, secret, _, err := GenerateTenantAPIKey()
	if err != nil {
		return nil, err
	}
	newHash := HashTenantAPISecret(s.currentPepper(), keyID, secret)
	var until time.Time
	if g > 0 {
		until = now.Add(g)
	}
	if err := s.repo.RotateSecret(ctx, key.ID, newHash, s.currentHashAlg(), until); err != nil {
		return nil, err
	}
	rotated := now
	key.RotatedAt = &rotated
	if g > 0 {
		prev := key.KeyHash
		key.PrevHash, key.PrevValidUntil = &prev, &until
	} else {
		key.PrevHash, key.PrevValidUntil = nil, nil
	}
	key.KeyHash, key.HashAlg = newHash, s.currentHashAlg()
	s.auditEvent(ctx, tenantID, &actorID, key.ID, AuditActionAPIKeyRotated, true, map[string]interface{}{
		"grace_hours": g.Hours(),
	})
	return &models.TenantAPIKeyCreatedResponse{
		TenantAPIKeyResponse: s.toResponse(key, now),
		Key:                  models.TenantAPIKeyPrefix + keyID + "_" + secret,
	}, nil
}

func stringOrEmpty(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

// Revoke disables a key at once: the row is marked revoked first (so the
// exchange stops minting tokens), then its role edges are deleted and its
// company edges are queued for removal. Tokens already minted live out their
// short TTL at most.
func (s *TenantAPIKeyService) Revoke(ctx context.Context, tenantID, actorID, id uuid.UUID) error {
	if !s.Enabled(tenantID) {
		return ErrDeveloperKeysDisabled
	}
	key, err := s.repo.GetTenantKey(ctx, tenantID, id)
	if err != nil {
		return err
	}
	if key == nil {
		return ErrAPIKeyNotFound
	}
	if key.RevokedAt != nil {
		return nil // idempotent
	}
	if err := s.repo.RevokeTenantKey(ctx, key.ID); err != nil {
		return err
	}
	now := s.now()
	key.IsActive, key.RevokedAt = false, &now
	s.removeRoleEdges(ctx, key)
	if len(key.CompanyIDs) > 0 {
		// RevokeTenantKey already moved the row to pending_remove atomically
		// (so a failure here cannot lose the removal); mirror it locally and
		// try the removal once now. The CAS in syncCompanies keeps a racing
		// worker from overwriting it.
		key.CompanySyncState, key.CompanySyncAttempt, key.CompanySyncNextAt = models.APIKeyCompanySyncPendingRemove, 0, &now
		s.syncCompanies(ctx, key)
	}
	s.auditEvent(ctx, tenantID, &actorID, key.ID, AuditActionAPIKeyRevoked, true, nil)
	logger.Info("Tenant API key revoked",
		zap.String("tenant_id", tenantID.String()), zap.String("api_key_id", key.ID.String()))
	return nil
}

// Delete removes a revoked key's row once its company edges are gone.
func (s *TenantAPIKeyService) Delete(ctx context.Context, tenantID, actorID, id uuid.UUID) error {
	if !s.Enabled(tenantID) {
		return ErrDeveloperKeysDisabled
	}
	key, err := s.repo.GetTenantKey(ctx, tenantID, id)
	if err != nil {
		return err
	}
	if key == nil {
		return ErrAPIKeyNotFound
	}
	if key.RevokedAt == nil {
		return invalidAPIKeyRequest("revoke the key before deleting it")
	}
	if key.CompanySyncState != models.APIKeyCompanySyncSynced {
		return ErrAPIKeyCompanySyncPending
	}
	if err := s.repo.DeleteTenantKey(ctx, tenantID, key.ID); err != nil {
		return err
	}
	s.auditEvent(ctx, tenantID, &actorID, key.ID, AuditActionAPIKeyDeleted, true, map[string]interface{}{"name": key.Name})
	return nil
}

// ---------------------------------------------------------------------------
// SpiceDB role edges
// ---------------------------------------------------------------------------

func (s *TenantAPIKeyService) writeRoleEdges(ctx context.Context, key *models.APIKey) error {
	if key.ExpiresAt == nil {
		return errors.New("tenant API key has no expiry")
	}
	for _, roleID := range key.RoleIDs {
		if _, err := s.spicedb.WriteUserRoleUntil(ctx, key.TenantID, key.ID, roleID, *key.ExpiresAt); err != nil {
			return fmt.Errorf("role %s: %w", roleID, err)
		}
	}
	return nil
}

// removeRoleEdges deletes the key's role edges, best effort: a failure is
// logged and left to the SpiceDB reconciler (reconcileAPIKeyRoles).
func (s *TenantAPIKeyService) removeRoleEdges(ctx context.Context, key *models.APIKey) {
	for _, roleID := range key.RoleIDs {
		if _, err := s.spicedb.DeleteUserRole(ctx, key.TenantID, key.ID, roleID); err != nil {
			logger.Warn("Failed to delete API key role edge; reconciler will retry",
				zap.String("api_key_id", key.ID.String()), zap.String("role_id", roleID.String()), zap.Error(err))
		}
	}
}

// ---------------------------------------------------------------------------
// Company edges (business) through the key-row outbox
// ---------------------------------------------------------------------------

// casCompanySync moves the key's company-sync row from the state this process
// last saw to state, as a compare-and-set. It reports false (and leaves key
// untouched) when the write failed or another actor, such as a revoke or a
// second replica, changed the state first.
func (s *TenantAPIKeyService) casCompanySync(ctx context.Context, key *models.APIKey, state string, attempts int, next *time.Time) bool {
	ok, err := s.repo.SetCompanySync(ctx, key.ID, key.CompanySyncState, state, attempts, next)
	if err != nil {
		logger.Warn("Failed to update API key company sync state",
			zap.String("api_key_id", key.ID.String()), zap.String("state", state), zap.Error(err))
		return false
	}
	if !ok {
		logger.Info("API key company sync state changed concurrently; leaving it to the new owner",
			zap.String("api_key_id", key.ID.String()), zap.String("expected_state", key.CompanySyncState))
		return false
	}
	key.CompanySyncState, key.CompanySyncAttempt, key.CompanySyncNextAt = state, attempts, next
	return true
}

// syncCompanies attempts the pending company-edge call once. Success marks the
// key synced; failure records the attempt and backs off, and the background
// worker (ProcessPendingCompanySync) retries. Every state write is a
// compare-and-set, so a revoke that lands while the call is in flight wins.
func (s *TenantAPIKeyService) syncCompanies(ctx context.Context, key *models.APIKey) {
	if key.RevokedAt != nil && key.CompanySyncState == models.APIKeyCompanySyncPendingAdd {
		// A revoked key must never gain company edges: turn the add into a
		// removal (covers a revoke that raced creation).
		now := s.now()
		if !s.casCompanySync(ctx, key, models.APIKeyCompanySyncPendingRemove, 0, &now) {
			return
		}
	}
	if key.CompanySyncState == models.APIKeyCompanySyncSynced {
		return
	}
	err := s.applyCompanyState(ctx, key)
	if err == nil {
		if !s.casCompanySync(ctx, key, models.APIKeyCompanySyncSynced, 0, nil) {
			s.requeueRevokedAfterAdd(ctx, key)
		}
		return
	}
	if be, terminal := companySyncTerminal(err); terminal {
		s.failCompanySync(ctx, key, be)
		return
	}
	attempts := key.CompanySyncAttempt + 1
	next := s.now().Add(companySyncBackoff(attempts))
	state := key.CompanySyncState
	s.casCompanySync(ctx, key, state, attempts, &next)
	logger.Warn("API key company sync failed; will retry",
		zap.String("api_key_id", key.ID.String()), zap.String("state", state),
		zap.Int("attempts", attempts), zap.Error(err))
}

// requeueRevokedAfterAdd handles a lost compare-and-set after a successful
// AddCompanies: the add may have landed after a revoke, so re-read the row and,
// if the key is revoked and no removal is queued, queue pending_remove.
func (s *TenantAPIKeyService) requeueRevokedAfterAdd(ctx context.Context, key *models.APIKey) {
	fresh, err := s.repo.GetTenantKey(ctx, key.TenantID, key.ID)
	if err != nil || fresh == nil || fresh.RevokedAt == nil {
		return
	}
	switch fresh.CompanySyncState {
	case models.APIKeyCompanySyncPendingRemove, models.APIKeyCompanySyncFailed:
		return
	}
	now := s.now()
	if ok, err := s.repo.SetCompanySync(ctx, fresh.ID, fresh.CompanySyncState, models.APIKeyCompanySyncPendingRemove, 0, &now); err != nil || !ok {
		logger.Warn("Failed to queue company edge removal for key revoked during add",
			zap.String("api_key_id", key.ID.String()), zap.Error(err))
	}
}

// failCompanySync parks the key in the terminal failed state and audits it:
// business rejected the call (400/422), so retrying forever cannot help.
func (s *TenantAPIKeyService) failCompanySync(ctx context.Context, key *models.APIKey, be *BusinessCompanyEdgeError) {
	op := key.CompanySyncState
	if !s.casCompanySync(ctx, key, models.APIKeyCompanySyncFailed, key.CompanySyncAttempt, nil) {
		return
	}
	s.auditEvent(ctx, key.TenantID, nil, key.ID, AuditActionAPIKeyCompanySyncFailed, false, map[string]interface{}{
		"operation": op, "status": be.StatusCode, "code": be.Code, "company_ids": uuidStrings(be.CompanyIDs),
	})
	logger.Error("API key company sync rejected by business; marked failed",
		zap.String("api_key_id", key.ID.String()), zap.String("operation", op),
		zap.Int("status", be.StatusCode), zap.String("code", be.Code))
}

func (s *TenantAPIKeyService) applyCompanyState(ctx context.Context, key *models.APIKey) error {
	if s.companies == nil {
		return errAPIKeyCompanyClientAbsent
	}
	switch key.CompanySyncState {
	case models.APIKeyCompanySyncPendingAdd:
		return s.companies.AddCompanies(ctx, key.TenantID, key.ID, key.CompanyIDs)
	case models.APIKeyCompanySyncPendingRemove:
		return s.companies.RemoveCompanies(ctx, key.TenantID, key.ID, key.CompanyIDs)
	}
	return nil
}

func companySyncBackoff(attempt int) time.Duration {
	if attempt < 1 {
		attempt = 1
	}
	if attempt > 7 {
		return companySyncBackoffMax
	}
	d := companySyncBackoffBase << uint(attempt-1)
	if d > companySyncBackoffMax {
		return companySyncBackoffMax
	}
	return d
}

// ProcessPendingCompanySync retries due company-edge calls. Safe to call from
// several pods: the business endpoint is idempotent.
func (s *TenantAPIKeyService) ProcessPendingCompanySync(ctx context.Context) (int, error) {
	if s == nil || !s.enabled {
		return 0, nil
	}
	s.syncMu.Lock()
	defer s.syncMu.Unlock()
	keys, err := s.repo.ListPendingCompanySync(ctx, companySyncBatch)
	if err != nil {
		return 0, err
	}
	done := 0
	for _, key := range keys {
		s.syncCompanies(ctx, key)
		if key.CompanySyncState == models.APIKeyCompanySyncSynced {
			done++
		}
	}
	return done, nil
}

// StartCompanySyncWorker runs ProcessPendingCompanySync every interval until
// ctx is cancelled.
func (s *TenantAPIKeyService) StartCompanySyncWorker(ctx context.Context, interval time.Duration) {
	if s == nil || !s.enabled {
		return
	}
	if interval <= 0 {
		interval = 30 * time.Second
	}
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if _, err := s.ProcessPendingCompanySync(ctx); err != nil {
					logger.Warn("API key company sync pass failed", zap.Error(err))
				}
			}
		}
	}()
}

// ---------------------------------------------------------------------------
// Token exchange
// ---------------------------------------------------------------------------

// APIKeyExchangeResult is a minted token plus its metadata.
type APIKeyExchangeResult struct {
	Response *models.APIKeyTokenResponse
	TenantID uuid.UUID
	KeyID    uuid.UUID
}

// Exchange authenticates an API key and mints a short-lived access token.
// Every authentication failure collapses to ErrAPIKeyInvalidClient (except
// the IP allowlist, which only a holder of the real secret can reach), so the
// endpoint is not an oracle for key ids or key state.
func (s *TenantAPIKeyService) Exchange(ctx context.Context, clientID, clientSecret, clientIP string) (*APIKeyExchangeResult, error) {
	if s == nil || !s.enabled || len(s.currentPepper()) == 0 || s.minter == nil {
		return nil, ErrAPIKeyInvalidClient
	}
	keyID, secret, ok := parseExchangeCredentials(clientID, clientSecret)
	if !ok {
		return nil, ErrAPIKeyInvalidClient
	}
	key, err := s.repo.GetByKeyID(ctx, keyID)
	if err != nil {
		return nil, fmt.Errorf("lookup API key: %w", err)
	}
	if key == nil {
		// Burn the same HMAC work as a real lookup so timing does not
		// distinguish unknown ids.
		_ = HashTenantAPISecret(s.currentPepper(), keyID, secret)
		return nil, ErrAPIKeyInvalidClient
	}
	if !s.credentialValid(key, keyID, secret) {
		// Wrong secret against a real key id: audit the attempt (no secret in
		// the record). The exchange rate limiter bounds how often this fires.
		if s.wrongSecretAuditDue(ctx, keyID) {
			s.auditEvent(ctx, key.TenantID, nil, key.ID, AuditActionAPIKeyAuthDenied, false, map[string]interface{}{
				"reason": "invalid_secret", "client_ip": clientIP,
			})
		}
		return nil, ErrAPIKeyInvalidClient
	}

	// Past the secret check: the caller holds the real key, so state failures
	// are safe to audit as replay signals.
	now := s.now()
	deny := func(reason string, ret error) (*APIKeyExchangeResult, error) {
		s.auditEvent(ctx, key.TenantID, nil, key.ID, AuditActionAPIKeyAuthDenied, false, map[string]interface{}{
			"reason": reason, "client_ip": clientIP,
		})
		return nil, ret
	}
	switch {
	case key.RevokedAt != nil || !key.IsActive:
		return deny("revoked", ErrAPIKeyInvalidClient)
	case key.ExpiresAt != nil && !key.ExpiresAt.After(now):
		return deny("expired", ErrAPIKeyInvalidClient)
	case !s.Enabled(key.TenantID):
		return deny("tenant_not_enabled", ErrAPIKeyInvalidClient)
	}
	if len(key.IPWhitelist) > 0 && !ipAllowed(clientIP, key.IPWhitelist) {
		return deny("ip_not_allowed", ErrAPIKeyIPNotAllowed)
	}
	if s.suspension != nil && s.suspension.IsSuspended(ctx, key.TenantID) {
		return deny("tenant_suspended", ErrAPIKeyTenantSuspended)
	}
	if allowed, planErr := s.planAllowsAPI(ctx, key.TenantID); planErr != nil {
		return nil, planErr
	} else if !allowed {
		return deny("plan_limit", ErrAPIKeyPlanLimit)
	}

	// Roles can gain forbidden permissions after key creation through system
	// provisioners that bypass the grant guard, so re-check at token time.
	for _, roleID := range key.RoleIDs {
		perms, err := s.roles.GetRolePermissions(ctx, roleID)
		if err != nil {
			return nil, fmt.Errorf("load role permissions %s: %w", roleID, err)
		}
		for _, p := range perms {
			if PermissionForbiddenForAPIKey(p.Name) {
				return deny("forbidden_permission", ErrAPIKeyInvalidClient)
			}
		}
	}

	access := stringOrEmpty(key.Access)
	token, err := s.minter.MintAPIKeyToken(APIKeyTokenParams{
		TenantID: key.TenantID, KeyID: key.ID, Access: access, Audience: s.audience, TTL: s.tokenTTL,
	})
	if err != nil {
		return nil, err
	}

	go func(id uuid.UUID) {
		bg, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
		defer cancel()
		if err := s.repo.UpdateLastUsed(bg, id, clientIP); err != nil {
			logger.Warn("Failed to update API key last used", zap.String("api_key_id", id.String()), zap.Error(err))
		}
	}(key.ID)

	return &APIKeyExchangeResult{
		TenantID: key.TenantID,
		KeyID:    key.ID,
		Response: &models.APIKeyTokenResponse{
			AccessToken: token,
			TokenType:   "Bearer",
			ExpiresIn:   int(s.tokenTTL.Seconds()),
			Scope:       strings.Join(APIKeyScopes(access), " "),
		},
	}, nil
}

// wrongSecretAuditDue limits the wrong-secret audit to one entry per key_id per
// minute. A Redis failure fails open: the audit is still written.
func (s *TenantAPIKeyService) wrongSecretAuditDue(ctx context.Context, keyID string) bool {
	if s.auditDedupe == nil {
		return true
	}
	first, err := s.auditDedupe.SetNX(ctx, "apikey_audit:wrong_secret:"+keyID, 1, wrongSecretAuditWindow)
	if err != nil {
		logger.Warn("API key audit dedupe unavailable; auditing anyway", zap.Error(err))
		return true
	}
	return first
}

// credentialValid checks the secret against the current hash (pepper chosen by
// the version in hash_alg), or against the previous hash while its rotation
// grace window is open (tried against every configured pepper). Legacy argon2
// rows never authenticate here: tenant keys are always hmac-sha256:<version>.
func (s *TenantAPIKeyService) credentialValid(key *models.APIKey, keyID, secret string) bool {
	if _, ok := models.APIKeyPepperVersion(key.HashAlg); !ok {
		return false
	}
	if s.secretMatchesAlg(key.HashAlg, key.KeyHash, keyID, secret) {
		return true
	}
	if key.PrevHash != nil && key.PrevValidUntil != nil && key.PrevValidUntil.After(s.now()) {
		return s.secretMatchesAnyPepper(*key.PrevHash, keyID, secret)
	}
	return false
}

// ParseAPIKeyExchangeCredentials exposes the exchange credential parsing so the
// rate limiter keys on the same parsed key_id the service looks up.
func ParseAPIKeyExchangeCredentials(clientID, clientSecret string) (keyID, secret string, ok bool) {
	return parseExchangeCredentials(clientID, clientSecret)
}

func parseExchangeCredentials(clientID, clientSecret string) (keyID, secret string, ok bool) {
	if clientSecret == "" {
		return ParseTenantAPIKey(clientID)
	}
	rest, found := strings.CutPrefix(clientID, models.TenantAPIKeyPrefix)
	if !found || !validKeyID(rest) || len(clientSecret) != tenantAPIKeySecretLen {
		return "", "", false
	}
	return rest, clientSecret, true
}

func ipAllowed(clientIP string, allowlist []string) bool {
	ip := net.ParseIP(clientIP)
	if ip == nil {
		return false
	}
	for _, entry := range allowlist {
		if _, network, err := net.ParseCIDR(entry); err == nil {
			if network.Contains(ip) {
				return true
			}
			continue
		}
		if p := net.ParseIP(entry); p != nil && p.Equal(ip) {
			return true
		}
	}
	return false
}
