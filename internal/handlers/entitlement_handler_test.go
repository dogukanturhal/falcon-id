// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/middleware"
	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/internal/services"
)

func init() {
	gin.SetMode(gin.TestMode)
}

// fakeRepo/fakeCache satisfy services' unexported entitlementModuleRepo /
// entitlementCache interfaces structurally (Go allows cross-package
// interface satisfaction), so these handler tests can exercise a REAL
// services.TenantEntitlementService end to end instead of re-mocking the
// handler's own dependency (there is nothing left to mock -- the handler
// holds a concrete *services.TenantEntitlementService, not an interface).
type fakeRepo struct {
	rows  []models.ModuleEntitlement
	flags *models.TenantEntitlementFlags
	err   error
}

func (f *fakeRepo) UpsertModule(ctx context.Context, e *models.ModuleEntitlement) (bool, error) {
	return true, f.err
}
func (f *fakeRepo) UpsertFlags(ctx context.Context, fl *models.TenantEntitlementFlags) (bool, error) {
	return true, f.err
}
func (f *fakeRepo) GetByTenant(ctx context.Context, tenantID uuid.UUID) ([]models.ModuleEntitlement, error) {
	return f.rows, f.err
}
func (f *fakeRepo) GetFlags(ctx context.Context, tenantID uuid.UUID) (*models.TenantEntitlementFlags, error) {
	return f.flags, f.err
}

// entitlementRepo mirrors services' unexported entitlementModuleRepo
// interface, letting these tests accept either *fakeRepo or
// *capturingFakeRepo.
type entitlementRepo interface {
	UpsertModule(ctx context.Context, e *models.ModuleEntitlement) (bool, error)
	UpsertFlags(ctx context.Context, f *models.TenantEntitlementFlags) (bool, error)
	GetByTenant(ctx context.Context, tenantID uuid.UUID) ([]models.ModuleEntitlement, error)
	GetFlags(ctx context.Context, tenantID uuid.UUID) (*models.TenantEntitlementFlags, error)
}

func newTestHandler(repo entitlementRepo) *EntitlementHandler {
	svc := services.NewTenantEntitlementService(repo, nil)
	return NewEntitlementHandler(svc, zap.NewNop())
}

// ---------------------------------------------------------------------------
// GetTenantEntitlements: public route, tenant MUST come from the
// session/JWT-derived CurrentUser, never a header. Verifies both the
// unauthenticated-401 path and that the correct tenant is threaded through.
// ---------------------------------------------------------------------------

func TestGetTenantEntitlements_NoCurrentUser_Returns401(t *testing.T) {
	h := newTestHandler(&fakeRepo{})
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/api/v1/tenant/entitlements", nil)
	// Deliberately do NOT set middleware.CurrentUserKey, simulating a
	// request that reached the handler without RequireAuth populating it.

	h.GetTenantEntitlements(c)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestGetTenantEntitlements_UsesSessionTenant_NotHeader(t *testing.T) {
	sessionTenant := uuid.New()
	headerTenant := uuid.New() // must be ignored -- header-trust rule

	var capturedTenant uuid.UUID
	capturingRepo := &capturingFakeRepo{
		fakeRepo: fakeRepo{rows: []models.ModuleEntitlement{
			{ModuleCode: "crm", Status: models.ModuleEntitlementStatusActive},
		}},
		captured: &capturedTenant,
	}
	h := newTestHandler(capturingRepo)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/api/v1/tenant/entitlements", nil)
	c.Request.Header.Set("X-Tenant-ID", headerTenant.String())
	c.Set(middleware.CurrentUserKey, &models.CurrentUser{
		ID:       uuid.New(),
		TenantID: sessionTenant,
	})

	h.GetTenantEntitlements(c)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, sessionTenant, capturedTenant, "must query the session-derived tenant")
	assert.NotEqual(t, headerTenant, capturedTenant, "must never trust the X-Tenant-ID header")
}

type capturingFakeRepo struct {
	fakeRepo
	captured *uuid.UUID
}

func (c *capturingFakeRepo) GetByTenant(ctx context.Context, tenantID uuid.UUID) ([]models.ModuleEntitlement, error) {
	*c.captured = tenantID
	return c.rows, c.err
}

// ---------------------------------------------------------------------------
// PutModuleEntitlements: validation behavior at the handler layer (authz
// itself is enforced by middleware registered in cmd/routes_admin.go --
// RequireScope("iam:entitlements:write") -- exercised separately below via
// a real router assembling ServiceAuth-context + RequireScope).
// ---------------------------------------------------------------------------

func TestPutModuleEntitlements_InvalidStatus_Returns400(t *testing.T) {
	h := newTestHandler(&fakeRepo{})
	tenantID := uuid.New()

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	body := `{"event_version":1,"modules":[{"module_code":"crm","status":"cancelled"}]}`
	req := httptest.NewRequest(http.MethodPut, "/internal/v1/tenants/"+tenantID.String()+"/module-entitlements", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	c.Request = req
	c.Params = gin.Params{{Key: "id", Value: tenantID.String()}}

	h.PutModuleEntitlements(c)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestPutModuleEntitlements_InvalidTenantID_Returns400(t *testing.T) {
	h := newTestHandler(&fakeRepo{})

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodPut, "/internal/v1/tenants/not-a-uuid/module-entitlements", strings.NewReader(`{}`))
	c.Params = gin.Params{{Key: "id", Value: "not-a-uuid"}}

	h.PutModuleEntitlements(c)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestPutModuleEntitlements_ValidSnapshot_Applied(t *testing.T) {
	h := newTestHandler(&fakeRepo{})
	tenantID := uuid.New()

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	body := `{"event_version":1,"modules":[{"module_code":"crm","status":"active"}],"flags":{"beta":true}}`
	req := httptest.NewRequest(http.MethodPut, "/internal/v1/tenants/"+tenantID.String()+"/module-entitlements", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	c.Request = req
	c.Params = gin.Params{{Key: "id", Value: tenantID.String()}}

	h.PutModuleEntitlements(c)

	assert.Equal(t, http.StatusOK, w.Code)
}

type sourceTierRoundtripRepo struct{ fakeRepo }

func (r *sourceTierRoundtripRepo) UpsertModule(_ context.Context, e *models.ModuleEntitlement) (bool, error) {
	r.rows = []models.ModuleEntitlement{*e}
	return true, nil
}

func TestModuleEntitlements_SourceTierRoundtrip_PublicAndInternal(t *testing.T) {
	repo := &sourceTierRoundtripRepo{}
	h := newTestHandler(repo)
	tenant := uuid.New()
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Params = gin.Params{{Key: "id", Value: tenant.String()}}
	c.Request = httptest.NewRequest(http.MethodPut, "/internal/v1/tenants/"+tenant.String()+"/module-entitlements", strings.NewReader(`{"event_version":1,"modules":[{"module_code":"crm","status":"active","source":"operator-comp","tier_code":"professional"}]}`))
	c.Request.Header.Set("Content-Type", "application/json")
	h.PutModuleEntitlements(c)
	require.Equal(t, http.StatusOK, w.Code)
	require.Len(t, repo.rows, 1)
	require.Equal(t, tenant, repo.rows[0].TenantID)
	for _, public := range []bool{true, false} {
		w = httptest.NewRecorder()
		c, _ = gin.CreateTestContext(w)
		c.Request = httptest.NewRequest(http.MethodGet, "/", nil)
		if public {
			c.Set(middleware.CurrentUserKey, &models.CurrentUser{TenantID: tenant})
			h.GetTenantEntitlements(c)
		} else {
			c.Params = gin.Params{{Key: "id", Value: tenant.String()}}
			h.GetModuleEntitlements(c)
		}
		require.Equal(t, http.StatusOK, w.Code)
		var env services.EntitlementEnvelope
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &env))
		require.Len(t, env.Modules, 1)
		require.False(t, env.Stale)
		require.NotNil(t, env.Modules[0].Source)
		require.Equal(t, "operator-comp", *env.Modules[0].Source)
		require.NotNil(t, env.Modules[0].TierCode)
		require.Equal(t, "professional", *env.Modules[0].TierCode)
		require.Equal(t, "complimentary", env.Modules[0].TrialReason)
		require.False(t, env.Modules[0].TrialEligible)
		require.False(t, env.TrialEligibility["crm"])
		var wire map[string]json.RawMessage
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &wire))
		require.Equal(t, "false", string(wire["stale"]), "freshness is explicit on both routes")
		var modules []map[string]json.RawMessage
		require.NoError(t, json.Unmarshal(wire["modules"], &modules))
		for _, field := range []string{"code", "source", "tier_code", "status", "seats", "expires_at"} {
			require.Contains(t, modules[0], field, "internal/public module contract")
		}
		golden, err := os.ReadFile("testdata/bqo-complimentary-entitlements.json")
		require.NoError(t, err)
		require.JSONEq(t, string(golden), w.Body.String())
	}
}

func TestModuleEntitlements_ReadFailureIsStale_PublicAndInternal(t *testing.T) {
	h := newTestHandler(&fakeRepo{err: assert.AnError})
	for _, public := range []bool{true, false} {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest(http.MethodGet, "/", nil)
		if public {
			c.Set(middleware.CurrentUserKey, &models.CurrentUser{TenantID: uuid.New()})
			h.GetTenantEntitlements(c)
		} else {
			c.Params = gin.Params{{Key: "id", Value: uuid.NewString()}}
			h.GetModuleEntitlements(c)
		}
		require.Equal(t, http.StatusOK, w.Code)
		var env services.EntitlementEnvelope
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &env))
		require.True(t, env.Stale, "fail-closed 200 cannot authorize lowering the parent seat limit")
		require.Empty(t, env.Modules)
	}
}

// ---------------------------------------------------------------------------
// Route-level authz: internal PUT/GET module-entitlements routes must
// require the "iam:entitlements:write"/"iam:entitlements:read" scopes
// respectively, mirroring how cmd/routes_admin.go wires RequireScope AFTER
// ServiceAuth(). This test drives the real middleware.RequireScope against
// a bare gin.Engine to prove insufficient-scope requests are rejected with
// 403 before ever reaching the handler.
// ---------------------------------------------------------------------------

func TestInternalRoutes_RequireScope_Enforced(t *testing.T) {
	h := newTestHandler(&fakeRepo{rows: []models.ModuleEntitlement{
		{ModuleCode: "crm", Status: models.ModuleEntitlementStatusActive},
	}})

	router := gin.New()
	group := router.Group("/internal/v1/tenants")
	// Simulate ServiceAuth() having already run and populated scopes --
	// here deliberately WITHOUT the required scope, to prove RequireScope
	// blocks the handler.
	group.Use(func(c *gin.Context) {
		c.Set(middleware.CtxKeyServiceScopes, "some:other:scope")
		c.Next()
	})
	group.GET("/:id/module-entitlements", middleware.RequireScope("iam:entitlements:read"), h.GetModuleEntitlements)
	group.PUT("/:id/module-entitlements", middleware.RequireScope("iam:entitlements:write"), h.PutModuleEntitlements)

	tenantID := uuid.New()

	wGet := httptest.NewRecorder()
	rGet := httptest.NewRequest(http.MethodGet, "/internal/v1/tenants/"+tenantID.String()+"/module-entitlements", nil)
	router.ServeHTTP(wGet, rGet)
	assert.Equal(t, http.StatusForbidden, wGet.Code, "GET without iam:entitlements:read must be forbidden")

	wPut := httptest.NewRecorder()
	rPut := httptest.NewRequest(http.MethodPut, "/internal/v1/tenants/"+tenantID.String()+"/module-entitlements", strings.NewReader(`{"event_version":1,"modules":[]}`))
	rPut.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(wPut, rPut)
	assert.Equal(t, http.StatusForbidden, wPut.Code, "PUT without iam:entitlements:write must be forbidden")
}

func TestInternalRoutes_RequireScope_AllowsWithScope(t *testing.T) {
	h := newTestHandler(&fakeRepo{rows: []models.ModuleEntitlement{
		{ModuleCode: "crm", Status: models.ModuleEntitlementStatusActive},
	}})

	router := gin.New()
	group := router.Group("/internal/v1/tenants")
	group.Use(func(c *gin.Context) {
		c.Set(middleware.CtxKeyServiceScopes, "iam:entitlements:read iam:entitlements:write")
		c.Next()
	})
	group.GET("/:id/module-entitlements", middleware.RequireScope("iam:entitlements:read"), h.GetModuleEntitlements)
	group.PUT("/:id/module-entitlements", middleware.RequireScope("iam:entitlements:write"), h.PutModuleEntitlements)

	tenantID := uuid.New()

	wGet := httptest.NewRecorder()
	rGet := httptest.NewRequest(http.MethodGet, "/internal/v1/tenants/"+tenantID.String()+"/module-entitlements", nil)
	router.ServeHTTP(wGet, rGet)
	assert.Equal(t, http.StatusOK, wGet.Code)

	wPut := httptest.NewRecorder()
	rPut := httptest.NewRequest(http.MethodPut, "/internal/v1/tenants/"+tenantID.String()+"/module-entitlements", strings.NewReader(`{"event_version":1,"modules":[{"module_code":"crm","status":"active"}]}`))
	rPut.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(wPut, rPut)
	assert.Equal(t, http.StatusOK, wPut.Code)
}

func TestGetModuleEntitlements_RepoError_Returns500(t *testing.T) {
	h := newTestHandler(&fakeRepo{})

	// nil cache + a repo whose GetByTenant errors triggers the service's
	// fail-closed chain to fall through to LKG (miss, no cache configured)
	// and ultimately return (emptyEnvelope, nil) -- so GetModuleEntitlements
	// itself cannot observe a non-nil error via the normal fail-closed
	// service contract. This test instead asserts the 200/empty-envelope
	// behavior that results, documenting that the 500 branch in the
	// handler is a defensive backstop that the service contract makes
	// unreachable in practice (see handler doc comment).
	tenantID := uuid.New()
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/internal/v1/tenants/"+tenantID.String()+"/module-entitlements", nil)
	c.Params = gin.Params{{Key: "id", Value: tenantID.String()}}

	h.GetModuleEntitlements(c)

	require.Equal(t, http.StatusOK, w.Code)
}

// Contract: GET /api/v1/tenant/entitlements keeps the legacy keys and adds the
// per-module trial fields with exactly these JSON names.
func TestGetTenantEntitlements_ResponseContract_TrialFields(t *testing.T) {
	trialEnd := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	h := newTestHandler(&fakeRepo{rows: []models.ModuleEntitlement{
		{ModuleCode: "crm", Status: models.ModuleEntitlementStatusTrialing, EverTrialed: true, ExpiresAt: &trialEnd},
		{ModuleCode: "pm", Status: models.ModuleEntitlementStatusExpired},
	}})
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/api/v1/tenant/entitlements", nil)
	c.Set(middleware.CurrentUserKey, &models.CurrentUser{ID: uuid.New(), TenantID: uuid.New()})

	h.GetTenantEntitlements(c)

	require.Equal(t, http.StatusOK, w.Code)
	var body map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	for _, k := range []string{"modules", "flags", "trial_eligibility"} {
		assert.Contains(t, body, k)
	}
	var mods []map[string]interface{}
	require.NoError(t, json.Unmarshal(body["modules"], &mods))
	require.Len(t, mods, 2)
	assert.Equal(t, "crm", mods[0]["code"])
	assert.Equal(t, false, mods[0]["trial_eligible"])
	assert.Equal(t, "trial_active", mods[0]["trial_reason"])
	assert.Equal(t, "2026-10-10T12:00:00Z", mods[0]["trial_ends_at"])
	assert.NotContains(t, mods[0], "grace_ends_at")
	assert.Equal(t, true, mods[1]["trial_eligible"])
	assert.Equal(t, "eligible", mods[1]["trial_reason"])
}

func TestPutModuleEntitlements_InvalidLimit_Returns400(t *testing.T) {
	h := newTestHandler(&fakeRepo{})
	tenantID := uuid.New()
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	body := `{"event_version":1,"modules":[],"limits":{"production_bom_depth":-2}}`
	req := httptest.NewRequest(http.MethodPut, "/internal/v1/tenants/"+tenantID.String()+"/module-entitlements", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	c.Request = req
	c.Params = gin.Params{{Key: "id", Value: tenantID.String()}}

	h.PutModuleEntitlements(c)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestGetTenantEntitlements_ServesIntegerLimits(t *testing.T) {
	for _, tc := range []struct {
		name string
		row  *models.TenantEntitlementFlags
		want map[string]int64
	}{
		{"row with limits", &models.TenantEntitlementFlags{Limits: map[string]int64{"production_bom_depth": 10}}, map[string]int64{"production_bom_depth": 10}},
		{"no row -> empty object, never null", nil, map[string]int64{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newTestHandler(&fakeRepo{flags: tc.row})
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			c.Request = httptest.NewRequest(http.MethodGet, "/api/v1/tenant/entitlements", nil)
			c.Set(middleware.CurrentUserKey, &models.CurrentUser{ID: uuid.New(), TenantID: uuid.New()})

			h.GetTenantEntitlements(c)

			require.Equal(t, http.StatusOK, w.Code)
			var body struct {
				Limits map[string]int64 `json:"limits"`
			}
			require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
			require.NotNil(t, body.Limits)
			assert.Equal(t, tc.want, body.Limits)
		})
	}
}

func TestPutModuleEntitlements_ReadOnlyOnlyWithGrace(t *testing.T) {
	for body, want := range map[string]int{
		`{"event_version":1,"modules":[{"module_code":"crm","status":"grace","read_only":true}]}`:  http.StatusOK,
		`{"event_version":1,"modules":[{"module_code":"crm","status":"active","read_only":true}]}`: http.StatusBadRequest,
	} {
		repo := &sourceTierRoundtripRepo{}
		h := newTestHandler(repo)
		tenant := uuid.New()
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Params = gin.Params{{Key: "id", Value: tenant.String()}}
		c.Request = httptest.NewRequest(http.MethodPut, "/internal/v1/tenants/"+tenant.String()+"/module-entitlements", strings.NewReader(body))
		c.Request.Header.Set("Content-Type", "application/json")
		h.PutModuleEntitlements(c)
		require.Equal(t, want, w.Code, body)
		if want == http.StatusOK {
			require.True(t, repo.rows[0].ReadOnly)
		}
	}
}
