// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"context"
	"net/http"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/dogukanturhal/falcon-id/internal/middleware"
	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/internal/services"
	"github.com/dogukanturhal/falcon-id/pkg/config"
)

// ---------------------------------------------------------------------------
// Mocks satisfying the narrow interfaces services.SoDService depends on
// (sodRuleRepo / sodViolationRepo / sodPermissionRepo, all unexported to
// the services package) so this file can build a real *services.SoDService
// without reaching into that package's internals.
// ---------------------------------------------------------------------------

type mockSoDHandlerRuleRepo struct{ mock.Mock }

func (m *mockSoDHandlerRuleRepo) ListActiveRulesForTenant(ctx context.Context, tenantID uuid.UUID) ([]models.SoDRule, error) {
	args := m.Called(ctx, tenantID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]models.SoDRule), args.Error(1)
}

func (m *mockSoDHandlerRuleRepo) ListRulesForTenant(ctx context.Context, tenantID uuid.UUID) ([]models.SoDRule, error) {
	args := m.Called(ctx, tenantID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]models.SoDRule), args.Error(1)
}

func (m *mockSoDHandlerRuleRepo) GetRuleByIDAndTenant(ctx context.Context, id, tenantID uuid.UUID) (*models.SoDRule, error) {
	args := m.Called(ctx, id, tenantID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.SoDRule), args.Error(1)
}

func (m *mockSoDHandlerRuleRepo) CreateRule(ctx context.Context, rule *models.SoDRule) error {
	args := m.Called(ctx, rule)
	if rule.ID == uuid.Nil {
		rule.ID = uuid.New()
	}
	return args.Error(0)
}

func (m *mockSoDHandlerRuleRepo) UpdateRule(ctx context.Context, id, tenantID uuid.UUID, req *models.UpdateSoDRuleRequest) (*models.SoDRule, error) {
	args := m.Called(ctx, id, tenantID, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.SoDRule), args.Error(1)
}

type mockSoDHandlerViolationRepo struct{ mock.Mock }

func (m *mockSoDHandlerViolationRepo) UpsertViolation(ctx context.Context, v *models.SoDViolation) error {
	args := m.Called(ctx, v)
	return args.Error(0)
}

func (m *mockSoDHandlerViolationRepo) ListViolationsForTenant(ctx context.Context, tenantID uuid.UUID, openOnly bool) ([]models.SoDViolation, error) {
	args := m.Called(ctx, tenantID, openOnly)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]models.SoDViolation), args.Error(1)
}

type mockSoDHandlerPermissionRepo struct{ mock.Mock }

func (m *mockSoDHandlerPermissionRepo) GetUserPermissionNames(ctx context.Context, userID, tenantID uuid.UUID) ([]string, error) {
	args := m.Called(ctx, userID, tenantID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]string), args.Error(1)
}

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

// setupSoDInternalRouter mounts the internal ServiceAuth-gated evaluate
// endpoint, matching cmd/routes_admin.go wiring.
func setupSoDInternalRouter(h *SoDHandler) *gin.Engine {
	router := gin.New()
	router.POST("/internal/v1/sod/evaluate", h.Evaluate)
	return router
}

// setupSoDBFFRouter mounts the tenant-admin gated BFF SoD surface exactly
// like cmd/routes.go's `account` group: an auth-injecting stand-in for
// RequireAuth (a real RequireAuth needs a signed JWT, which is orthogonal
// to what these tests check) followed by the real
// AuthMiddleware.RequirePermission(permAccountSoDManage).
func setupSoDBFFRouter(h *SoDHandler, authzEngine services.AuthorizationEngine, user *models.CurrentUser) *gin.Engine {
	router := gin.New()
	authMW := middleware.NewAuthMiddleware(nil, &config.Config{})
	if authzEngine != nil {
		authMW.SetAuthorizationEngine(authzEngine)
	}

	injectAuth := func(c *gin.Context) {
		if user != nil {
			c.Set(middleware.CurrentUserKey, user)
			c.Set(middleware.TenantIDKey, user.TenantID)
		}
		c.Next()
	}

	account := router.Group("/api/v1/account")
	account.Use(injectAuth)
	{
		account.GET("/sod-rules", authMW.RequirePermission("account:sod:manage"), h.ListRules)
		account.POST("/sod-rules", authMW.RequirePermission("account:sod:manage"), h.CreateRule)
		account.PATCH("/sod-rules/:id", authMW.RequirePermission("account:sod:manage"), h.UpdateRule)
		account.GET("/sod-violations", authMW.RequirePermission("account:sod:manage"), h.ListViolations)
	}
	return router
}

// sodTestAuthzEngine is a minimal services.AuthorizationEngine test double
// that grants (or denies) a fixed set of permissions, mirroring the
// grantPermsEngine pattern used in internal/middleware/auth_test.go. Named
// distinctly from the package's pre-existing mockAuthzEngine (defined in
// spicedb_debug_handler_test.go), which is result/error-driven rather than
// permission-name-driven.
type sodTestAuthzEngine struct {
	granted map[string]bool
}

func (e *sodTestAuthzEngine) CheckPermission(_ context.Context, req services.PermissionRequest) (*services.PermissionResult, error) {
	return &services.PermissionResult{Allowed: e.granted[req.Permission]}, nil
}

func (e *sodTestAuthzEngine) CheckResourcePermission(_ context.Context, _ services.ResourcePermissionRequest) (*services.PermissionResult, error) {
	return &services.PermissionResult{Allowed: false}, nil
}

func (e *sodTestAuthzEngine) CheckContextualPermission(_ context.Context, _ services.ContextualPermissionRequest) (*services.PermissionResult, error) {
	return &services.PermissionResult{Allowed: false}, nil
}

func (e *sodTestAuthzEngine) BatchCheckPermissions(_ context.Context, _, _ uuid.UUID, permissions []string) (map[string]bool, error) {
	out := map[string]bool{}
	for _, p := range permissions {
		out[p] = e.granted[p]
	}
	return out, nil
}

func (e *sodTestAuthzEngine) CheckProductAccess(_ context.Context, _ services.ProductAccessRequest) (*services.PermissionResult, error) {
	return &services.PermissionResult{Allowed: true}, nil
}

// ---------------------------------------------------------------------------
// POST /internal/v1/sod/evaluate
// ---------------------------------------------------------------------------

func TestSoDHandler_Evaluate_DetectsConflict_ReturnsViolationsNeverBlocks(t *testing.T) {
	tenantID := uuid.New()
	userID := uuid.New()
	permA, permB := "accounting:journal_entries:create", "accounting:journal_entries:approve"

	ruleRepo := new(mockSoDHandlerRuleRepo)
	violationRepo := new(mockSoDHandlerViolationRepo)
	permRepo := new(mockSoDHandlerPermissionRepo)

	rule := models.SoDRule{ID: uuid.New(), PermissionA: permA, PermissionB: permB, Mode: models.SoDModeWarn}
	ruleRepo.On("ListActiveRulesForTenant", mock.Anything, tenantID).Return([]models.SoDRule{rule}, nil)
	permRepo.On("GetUserPermissionNames", mock.Anything, userID, tenantID).Return([]string{permA, permB}, nil)
	violationRepo.On("UpsertViolation", mock.Anything, mock.Anything).Return(nil)

	sodSvc := services.NewSoDService(ruleRepo, violationRepo, permRepo)
	h := NewSoDHandler(sodSvc)
	router := setupSoDInternalRouter(h)

	body := `{"tenant_id":"` + tenantID.String() + `","user_id":"` + userID.String() + `"}`
	w := doRequest(router, http.MethodPost, "/internal/v1/sod/evaluate", body)

	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	assert.Contains(t, w.Body.String(), permA)
	assert.Contains(t, w.Body.String(), permB)
	violationRepo.AssertCalled(t, "UpsertViolation", mock.Anything, mock.Anything)
}

func TestSoDHandler_Evaluate_NoConflict_ReturnsEmptyViolations(t *testing.T) {
	tenantID := uuid.New()
	userID := uuid.New()

	ruleRepo := new(mockSoDHandlerRuleRepo)
	violationRepo := new(mockSoDHandlerViolationRepo)
	permRepo := new(mockSoDHandlerPermissionRepo)

	rule := models.SoDRule{ID: uuid.New(), PermissionA: "accounting:journal_entries:create", PermissionB: "accounting:journal_entries:approve", Mode: models.SoDModeWarn}
	ruleRepo.On("ListActiveRulesForTenant", mock.Anything, tenantID).Return([]models.SoDRule{rule}, nil)
	permRepo.On("GetUserPermissionNames", mock.Anything, userID, tenantID).Return([]string{"accounting:journal_entries:create"}, nil)

	sodSvc := services.NewSoDService(ruleRepo, violationRepo, permRepo)
	h := NewSoDHandler(sodSvc)
	router := setupSoDInternalRouter(h)

	body := `{"tenant_id":"` + tenantID.String() + `","user_id":"` + userID.String() + `"}`
	w := doRequest(router, http.MethodPost, "/internal/v1/sod/evaluate", body)

	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	assert.Contains(t, w.Body.String(), `"violations":[]`)
	violationRepo.AssertNotCalled(t, "UpsertViolation", mock.Anything, mock.Anything)
}

func TestSoDHandler_Evaluate_InvalidBody_Returns400(t *testing.T) {
	ruleRepo := new(mockSoDHandlerRuleRepo)
	violationRepo := new(mockSoDHandlerViolationRepo)
	permRepo := new(mockSoDHandlerPermissionRepo)
	sodSvc := services.NewSoDService(ruleRepo, violationRepo, permRepo)
	h := NewSoDHandler(sodSvc)
	router := setupSoDInternalRouter(h)

	w := doRequest(router, http.MethodPost, "/internal/v1/sod/evaluate", `{"tenant_id":"not-a-uuid"}`)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ---------------------------------------------------------------------------
// BFF surface: /api/v1/account/sod-rules, /api/v1/account/sod-violations
// ---------------------------------------------------------------------------

func TestSoDHandler_ListRules_NonAdminCaller_Returns403(t *testing.T) {
	tenantID := uuid.New()
	ruleRepo := new(mockSoDHandlerRuleRepo)
	violationRepo := new(mockSoDHandlerViolationRepo)
	permRepo := new(mockSoDHandlerPermissionRepo)
	sodSvc := services.NewSoDService(ruleRepo, violationRepo, permRepo)
	h := NewSoDHandler(sodSvc)

	// Caller is authenticated but lacks account:sod:manage.
	engine := &sodTestAuthzEngine{granted: map[string]bool{"users:read": true}}
	nonAdmin := &models.CurrentUser{ID: uuid.New(), TenantID: tenantID, Roles: []string{"member"}}
	router := setupSoDBFFRouter(h, engine, nonAdmin)

	w := doRequest(router, http.MethodGet, "/api/v1/account/sod-rules", "")

	assert.Equal(t, http.StatusForbidden, w.Code)
	ruleRepo.AssertNotCalled(t, "ListRulesForTenant", mock.Anything, mock.Anything)
}

func TestSoDHandler_ListRules_AdminCaller_Returns200(t *testing.T) {
	tenantID := uuid.New()
	ruleRepo := new(mockSoDHandlerRuleRepo)
	violationRepo := new(mockSoDHandlerViolationRepo)
	permRepo := new(mockSoDHandlerPermissionRepo)
	ruleRepo.On("ListRulesForTenant", mock.Anything, tenantID).Return([]models.SoDRule{}, nil)
	ruleRepo.On("ListActiveRulesForTenant", mock.Anything, tenantID).Return([]models.SoDRule{}, nil)
	sodSvc := services.NewSoDService(ruleRepo, violationRepo, permRepo)
	h := NewSoDHandler(sodSvc)

	engine := &sodTestAuthzEngine{granted: map[string]bool{"account:sod:manage": true}}
	admin := &models.CurrentUser{ID: uuid.New(), TenantID: tenantID, Roles: []string{"tenant_admin"}}
	router := setupSoDBFFRouter(h, engine, admin)

	w := doRequest(router, http.MethodGet, "/api/v1/account/sod-rules", "")

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestSoDHandler_ListRules_NoTenantContext_Returns400(t *testing.T) {
	ruleRepo := new(mockSoDHandlerRuleRepo)
	violationRepo := new(mockSoDHandlerViolationRepo)
	permRepo := new(mockSoDHandlerPermissionRepo)
	sodSvc := services.NewSoDService(ruleRepo, violationRepo, permRepo)
	h := NewSoDHandler(sodSvc)

	router := gin.New()
	router.GET("/api/v1/account/sod-rules", h.ListRules) // no tenant middleware at all

	w := doRequest(router, http.MethodGet, "/api/v1/account/sod-rules", "")

	assert.Equal(t, http.StatusBadRequest, w.Code)
	ruleRepo.AssertNotCalled(t, "ListRulesForTenant", mock.Anything, mock.Anything)
}

// TestSoDHandler_ListRules_CrossTenant_ScopedToCallersTenant is the
// cross-tenant-blocked acceptance check: tenant A's admin session must only
// ever see tenant A's rules, even though the repo holds rows for both
// tenants — the handler never accepts a tenant ID from anywhere but the
// authenticated session (middleware.GetTenantID, sourced from the JWT).
func TestSoDHandler_ListRules_CrossTenant_ScopedToCallersTenant(t *testing.T) {
	tenantA := uuid.New()
	tenantB := uuid.New()

	ruleRepo := new(mockSoDHandlerRuleRepo)
	violationRepo := new(mockSoDHandlerViolationRepo)
	permRepo := new(mockSoDHandlerPermissionRepo)

	ruleA := models.SoDRule{ID: uuid.New(), TenantID: &tenantA, PermissionA: "a:x", PermissionB: "a:y"}
	ruleB := models.SoDRule{ID: uuid.New(), TenantID: &tenantB, PermissionA: "b:x", PermissionB: "b:y"}
	ruleRepo.On("ListRulesForTenant", mock.Anything, tenantA).Return([]models.SoDRule{ruleA}, nil)
	ruleRepo.On("ListActiveRulesForTenant", mock.Anything, tenantA).Return([]models.SoDRule{}, nil)
	ruleRepo.On("ListRulesForTenant", mock.Anything, tenantB).Return([]models.SoDRule{ruleB}, nil)
	ruleRepo.On("ListActiveRulesForTenant", mock.Anything, tenantB).Return([]models.SoDRule{}, nil)

	sodSvc := services.NewSoDService(ruleRepo, violationRepo, permRepo)
	h := NewSoDHandler(sodSvc)

	engine := &sodTestAuthzEngine{granted: map[string]bool{"account:sod:manage": true}}
	adminA := &models.CurrentUser{ID: uuid.New(), TenantID: tenantA, Roles: []string{"tenant_admin"}}
	routerA := setupSoDBFFRouter(h, engine, adminA)

	w := doRequest(routerA, http.MethodGet, "/api/v1/account/sod-rules", "")

	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	assert.Contains(t, w.Body.String(), "a:x")
	assert.NotContains(t, w.Body.String(), "b:x")
	ruleRepo.AssertCalled(t, "ListRulesForTenant", mock.Anything, tenantA)
	ruleRepo.AssertNotCalled(t, "ListRulesForTenant", mock.Anything, tenantB)
}

func TestSoDHandler_ListViolations_NonAdminCaller_Returns403(t *testing.T) {
	tenantID := uuid.New()
	ruleRepo := new(mockSoDHandlerRuleRepo)
	violationRepo := new(mockSoDHandlerViolationRepo)
	permRepo := new(mockSoDHandlerPermissionRepo)
	sodSvc := services.NewSoDService(ruleRepo, violationRepo, permRepo)
	h := NewSoDHandler(sodSvc)

	engine := &sodTestAuthzEngine{granted: map[string]bool{}}
	nonAdmin := &models.CurrentUser{ID: uuid.New(), TenantID: tenantID, Roles: []string{"member"}}
	router := setupSoDBFFRouter(h, engine, nonAdmin)

	w := doRequest(router, http.MethodGet, "/api/v1/account/sod-violations", "")

	assert.Equal(t, http.StatusForbidden, w.Code)
	violationRepo.AssertNotCalled(t, "ListViolationsForTenant", mock.Anything, mock.Anything, mock.Anything)
}

func TestSoDHandler_ListViolations_CrossTenant_ScopedToCallersTenant(t *testing.T) {
	tenantA := uuid.New()
	tenantB := uuid.New()

	ruleRepo := new(mockSoDHandlerRuleRepo)
	violationRepo := new(mockSoDHandlerViolationRepo)
	permRepo := new(mockSoDHandlerPermissionRepo)

	vA := models.SoDViolation{ID: uuid.New(), TenantID: tenantA, PermissionA: "a:x", PermissionB: "a:y"}
	vB := models.SoDViolation{ID: uuid.New(), TenantID: tenantB, PermissionA: "b:x", PermissionB: "b:y"}
	violationRepo.On("ListViolationsForTenant", mock.Anything, tenantA, true).Return([]models.SoDViolation{vA}, nil)
	violationRepo.On("ListViolationsForTenant", mock.Anything, tenantB, true).Return([]models.SoDViolation{vB}, nil)

	sodSvc := services.NewSoDService(ruleRepo, violationRepo, permRepo)
	h := NewSoDHandler(sodSvc)

	engine := &sodTestAuthzEngine{granted: map[string]bool{"account:sod:manage": true}}
	adminA := &models.CurrentUser{ID: uuid.New(), TenantID: tenantA, Roles: []string{"tenant_admin"}}
	routerA := setupSoDBFFRouter(h, engine, adminA)

	w := doRequest(routerA, http.MethodGet, "/api/v1/account/sod-violations", "")

	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	assert.Contains(t, w.Body.String(), "a:x")
	assert.NotContains(t, w.Body.String(), "b:x")
}

func TestSoDHandler_CreateRule_NoTenantContext_Returns400(t *testing.T) {
	ruleRepo := new(mockSoDHandlerRuleRepo)
	violationRepo := new(mockSoDHandlerViolationRepo)
	permRepo := new(mockSoDHandlerPermissionRepo)
	sodSvc := services.NewSoDService(ruleRepo, violationRepo, permRepo)
	h := NewSoDHandler(sodSvc)

	router := gin.New()
	router.POST("/api/v1/account/sod-rules", h.CreateRule)

	w := doRequest(router, http.MethodPost, "/api/v1/account/sod-rules", `{"module":"accounting","permission_a":"a:x","permission_b":"a:y"}`)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	ruleRepo.AssertNotCalled(t, "CreateRule", mock.Anything, mock.Anything)
}
