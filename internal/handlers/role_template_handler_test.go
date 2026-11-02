// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dogukanturhal/falcon-id/internal/middleware"
	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/internal/services"
	"github.com/dogukanturhal/falcon-id/pkg/config"
)

// ---------------------------------------------------------------------------
// Fakes: enough of RoleTemplateRepository / TemplateRoleProvisioner's deps to
// build a real *services.RoleTemplateService without a DB. Mirrors the
// approach in internal/services/template_role_provisioner_test.go, but kept
// local to this package (those fakes are unexported to the services
// package's test files and not reusable across package boundaries).
// ---------------------------------------------------------------------------

type fakeHandlerRoleTemplateRepo struct {
	latest map[string]*models.RoleTemplate
}

func (f *fakeHandlerRoleTemplateRepo) GetLatestByKey(_ context.Context, key string) (*models.RoleTemplate, error) {
	return f.latest[key], nil
}
func (f *fakeHandlerRoleTemplateRepo) ListLatestActiveByModules(_ context.Context, modules []string) ([]models.RoleTemplate, error) {
	want := map[string]bool{}
	for _, m := range modules {
		want[m] = true
	}
	var out []models.RoleTemplate
	for _, t := range f.latest {
		if t.IsActive && want[t.Module] {
			out = append(out, *t)
		}
	}
	return out, nil
}

type fakeHandlerRoleRepo struct {
	rolesByID       map[uuid.UUID]*models.Role
	rolesByTemplate map[string]map[uuid.UUID]*models.Role
}

func newFakeHandlerRoleRepo() *fakeHandlerRoleRepo {
	return &fakeHandlerRoleRepo{
		rolesByID:       map[uuid.UUID]*models.Role{},
		rolesByTemplate: map[string]map[uuid.UUID]*models.Role{},
	}
}
func (f *fakeHandlerRoleRepo) CreateFromTemplate(_ context.Context, role *models.Role) error {
	if role.ID == uuid.Nil {
		role.ID = uuid.New()
	}
	f.rolesByID[role.ID] = role
	if role.TemplateKey != nil {
		byTenant, ok := f.rolesByTemplate[*role.TemplateKey]
		if !ok {
			byTenant = map[uuid.UUID]*models.Role{}
			f.rolesByTemplate[*role.TemplateKey] = byTenant
		}
		byTenant[role.TenantID] = role
	}
	return nil
}
func (f *fakeHandlerRoleRepo) GetByTemplateKeyForTenant(_ context.Context, tenantID uuid.UUID, templateKey string) (*models.Role, error) {
	byTenant, ok := f.rolesByTemplate[templateKey]
	if !ok {
		return nil, nil
	}
	return byTenant[tenantID], nil
}
func (f *fakeHandlerRoleRepo) ListRolesByTemplateKey(_ context.Context, templateKey string) ([]models.Role, error) {
	var out []models.Role
	for _, r := range f.rolesByTemplate[templateKey] {
		out = append(out, *r)
	}
	return out, nil
}
func (f *fakeHandlerRoleRepo) ListTemplateDerivedRolesByModule(_ context.Context, tenantID uuid.UUID, module string) ([]models.Role, error) {
	var out []models.Role
	for _, r := range f.rolesByID {
		if r.TenantID == tenantID && r.Module != nil && *r.Module == module && r.TemplateKey != nil {
			out = append(out, *r)
		}
	}
	return out, nil
}
func (f *fakeHandlerRoleRepo) SetTemplateVersion(_ context.Context, roleID uuid.UUID, version int) error {
	if r, ok := f.rolesByID[roleID]; ok {
		r.TemplateVersion = &version
	}
	return nil
}
func (f *fakeHandlerRoleRepo) AssignPermissions(_ context.Context, _ uuid.UUID, _ []uuid.UUID, _ *uuid.UUID) error {
	return nil
}
func (f *fakeHandlerRoleRepo) GrantPermissionsByName(_ context.Context, _ uuid.UUID, _ []string) error {
	return nil
}
func (f *fakeHandlerRoleRepo) GetRolePermissions(_ context.Context, _ uuid.UUID) ([]models.Permission, error) {
	return nil, nil
}
func (f *fakeHandlerRoleRepo) ListActiveHolderIDs(_ context.Context, _ uuid.UUID) ([]uuid.UUID, error) {
	return nil, nil
}

type fakeHandlerPermissionRepo struct{}

func (f *fakeHandlerPermissionRepo) List(_ context.Context) ([]models.Permission, error) {
	return nil, nil
}
func (f *fakeHandlerPermissionRepo) ListByModules(_ context.Context, _ []string) ([]models.Permission, error) {
	return nil, nil
}
func (f *fakeHandlerPermissionRepo) GetModules(_ context.Context) ([]string, error) { return nil, nil }
func (f *fakeHandlerPermissionRepo) GetUserPermissionIDs(_ context.Context, _, _ uuid.UUID) ([]uuid.UUID, error) {
	return nil, nil
}
func (f *fakeHandlerPermissionRepo) GetUserPermissionNames(_ context.Context, _, _ uuid.UUID) ([]string, error) {
	return nil, nil
}
func (f *fakeHandlerPermissionRepo) GetPermissionNamesByIDs(_ context.Context, _ []uuid.UUID) (map[uuid.UUID]string, error) {
	return nil, nil
}

// fakeHandlerEntitledModules always returns modules unrestricted (nil = "no
// entitlement filtering configured"), matching most test-fixture tenants;
// tests that need to prove entitlement-scoping override this via
// entitledOverride.
type fakeHandlerEntitledModules struct {
	entitledOverride map[uuid.UUID][]string // tenantID -> modules; absent = unrestricted (nil)
	allModules       []string
}

func (f *fakeHandlerEntitledModules) ListModulesForTenant(_ context.Context, tenantID uuid.UUID) ([]string, error) {
	if mods, ok := f.entitledOverride[tenantID]; ok {
		return mods, nil
	}
	return nil, nil
}
func (f *fakeHandlerEntitledModules) ListModules(_ context.Context) ([]string, error) {
	return f.allModules, nil
}

// fakeAuthzEngine lets tests control whether RequirePermission's SpiceDB
// check allows or denies, without a real SpiceDB connection.
type fakeAuthzEngine struct {
	allow map[string]bool // permission -> allowed
}

func (f *fakeAuthzEngine) CheckPermission(_ context.Context, req services.PermissionRequest) (*services.PermissionResult, error) {
	return &services.PermissionResult{Allowed: f.allow[req.Permission]}, nil
}
func (f *fakeAuthzEngine) CheckResourcePermission(_ context.Context, _ services.ResourcePermissionRequest) (*services.PermissionResult, error) {
	return &services.PermissionResult{Allowed: false}, nil
}
func (f *fakeAuthzEngine) CheckContextualPermission(_ context.Context, _ services.ContextualPermissionRequest) (*services.PermissionResult, error) {
	return &services.PermissionResult{Allowed: false}, nil
}
func (f *fakeAuthzEngine) BatchCheckPermissions(_ context.Context, _, _ uuid.UUID, _ []string) (map[string]bool, error) {
	return nil, nil
}
func (f *fakeAuthzEngine) CheckProductAccess(_ context.Context, _ services.ProductAccessRequest) (*services.PermissionResult, error) {
	return &services.PermissionResult{Allowed: false}, nil
}

// setupRoleTemplateRouter mirrors registerRoleTemplateRoutes in
// cmd/routes.go: RequireAuth is bypassed (as every other handler test in
// this package does — see role_handler_test.go's setupRoleHandlerRouter),
// but RequirePermission is the REAL middleware, backed by a fake SpiceDB
// engine, so authz tests exercise the actual 403 path rather than a stub.
func setupRoleTemplateRouter(t *testing.T, h *RoleTemplateHandler, tenantID uuid.UUID, cu *models.CurrentUser, allow map[string]bool) *gin.Engine {
	t.Helper()
	gin.SetMode(gin.TestMode)
	router := gin.New()

	authMW := middleware.NewAuthMiddleware(nil, &config.Config{})
	authMW.SetAuthorizationEngine(&fakeAuthzEngine{allow: allow})

	inject := func(c *gin.Context) {
		c.Set("tenant_id", tenantID)
		c.Set(middleware.CurrentUserKey, cu)
		if cu != nil {
			c.Set("user_id", cu.ID)
		}
		c.Next()
	}

	g := router.Group("/api/v1/role-templates", inject)
	g.GET("", authMW.RequirePermission("core:roles:read"), h.List)
	g.POST("/:key/instantiate", authMW.RequirePermission("core:roles:create"), h.Instantiate)
	return router
}

func doTemplateRequest(router *gin.Engine, method, path, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	return w
}

func newTestRoleTemplateHandler(roleRepo *fakeHandlerRoleRepo, templateRepo *fakeHandlerRoleTemplateRepo, entitled *fakeHandlerEntitledModules) *RoleTemplateHandler {
	provisioner := services.NewTemplateRoleProvisioner(roleRepo, templateRepo, &fakeHandlerPermissionRepo{}, nil)
	svc := services.NewRoleTemplateService(templateRepo, entitled, provisioner)
	return NewRoleTemplateHandler(svc)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

func TestRoleTemplateHandler_Instantiate_403ForNonAdmin(t *testing.T) {
	tenantID := uuid.New()
	templateRepo := &fakeHandlerRoleTemplateRepo{latest: map[string]*models.RoleTemplate{
		"marketing:campaign_manager": {
			Key: "marketing:campaign_manager", Version: 1, Module: "marketing",
			Name: "Campaign Manager", IsActive: true, Permissions: []string{"marketing:campaigns:send"},
		},
	}}
	h := newTestRoleTemplateHandler(newFakeHandlerRoleRepo(), templateRepo, &fakeHandlerEntitledModules{allModules: []string{"marketing"}})

	nonAdmin := &models.CurrentUser{ID: uuid.New(), TenantID: tenantID, Roles: []string{"member"}}
	// fakeAuthzEngine denies "core:roles:create" for this caller (empty allow map).
	router := setupRoleTemplateRouter(t, h, tenantID, nonAdmin, map[string]bool{})

	w := doTemplateRequest(router, http.MethodPost, "/api/v1/role-templates/marketing:campaign_manager/instantiate", "{}")
	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestRoleTemplateHandler_Instantiate_SucceedsForAdmin(t *testing.T) {
	tenantID := uuid.New()
	templateRepo := &fakeHandlerRoleTemplateRepo{latest: map[string]*models.RoleTemplate{
		"marketing:campaign_manager": {
			Key: "marketing:campaign_manager", Version: 1, Module: "marketing",
			Name: "Campaign Manager", IsActive: true, Permissions: []string{"marketing:campaigns:send"},
		},
	}}
	h := newTestRoleTemplateHandler(newFakeHandlerRoleRepo(), templateRepo, &fakeHandlerEntitledModules{allModules: []string{"marketing"}})

	admin := &models.CurrentUser{ID: uuid.New(), TenantID: tenantID, Roles: []string{"admin"}}
	router := setupRoleTemplateRouter(t, h, tenantID, admin, map[string]bool{"core:roles:create": true})

	w := doTemplateRequest(router, http.MethodPost, "/api/v1/role-templates/marketing:campaign_manager/instantiate", "{}")
	assert.Equal(t, http.StatusCreated, w.Code)
}

// TestRoleTemplateHandler_Instantiate_CrossTenantBlocked proves tenant A's
// admin cannot cause tenant B to get a role instantiated, and cannot read
// back tenant B's previously-instantiated role: the handler derives tenant
// solely from middleware.GetTenantID(c) (the validated JWT's tenant claim,
// injected here exactly as auth middleware would set it) — there is no
// tenant_id field anywhere in InstantiateRoleTemplateRequest for a caller to
// override, so "cross-tenant" input has nothing to attach to.
func TestRoleTemplateHandler_Instantiate_CrossTenantBlocked(t *testing.T) {
	tenantA := uuid.New()
	tenantB := uuid.New()
	templateRepo := &fakeHandlerRoleTemplateRepo{latest: map[string]*models.RoleTemplate{
		"marketing:campaign_manager": {
			Key: "marketing:campaign_manager", Version: 1, Module: "marketing",
			Name: "Campaign Manager", IsActive: true, Permissions: []string{"marketing:campaigns:send"},
		},
	}}
	roleRepo := newFakeHandlerRoleRepo()
	h := newTestRoleTemplateHandler(roleRepo, templateRepo, &fakeHandlerEntitledModules{allModules: []string{"marketing"}})

	adminA := &models.CurrentUser{ID: uuid.New(), TenantID: tenantA, Roles: []string{"admin"}}
	routerA := setupRoleTemplateRouter(t, h, tenantA, adminA, map[string]bool{"core:roles:create": true})

	w := doTemplateRequest(routerA, http.MethodPost, "/api/v1/role-templates/marketing:campaign_manager/instantiate", "{}")
	require.Equal(t, http.StatusCreated, w.Code)

	// Tenant A now has exactly one instantiated role for this template; tenant B has none.
	roleA, err := roleRepo.GetByTemplateKeyForTenant(context.Background(), tenantA, "marketing:campaign_manager")
	require.NoError(t, err)
	require.NotNil(t, roleA)
	assert.Equal(t, tenantA, roleA.TenantID)

	roleB, err := roleRepo.GetByTemplateKeyForTenant(context.Background(), tenantB, "marketing:campaign_manager")
	require.NoError(t, err)
	assert.Nil(t, roleB, "tenant B must not have received a role from tenant A's request")

	// Now instantiate as tenant B's own admin — must create tenant B's OWN
	// role, distinct from tenant A's.
	adminB := &models.CurrentUser{ID: uuid.New(), TenantID: tenantB, Roles: []string{"admin"}}
	routerB := setupRoleTemplateRouter(t, h, tenantB, adminB, map[string]bool{"core:roles:create": true})
	w = doTemplateRequest(routerB, http.MethodPost, "/api/v1/role-templates/marketing:campaign_manager/instantiate", "{}")
	require.Equal(t, http.StatusCreated, w.Code)

	roleB, err = roleRepo.GetByTemplateKeyForTenant(context.Background(), tenantB, "marketing:campaign_manager")
	require.NoError(t, err)
	require.NotNil(t, roleB)
	assert.NotEqual(t, roleA.ID, roleB.ID)
}

func TestRoleTemplateHandler_List_ScopedToEntitledModulesOnly(t *testing.T) {
	tenantID := uuid.New()
	templateRepo := &fakeHandlerRoleTemplateRepo{latest: map[string]*models.RoleTemplate{
		"marketing:campaign_manager": {
			Key: "marketing:campaign_manager", Version: 1, Module: "marketing",
			Name: "Campaign Manager", IsActive: true, Permissions: []string{"marketing:campaigns:send"},
		},
		"billing:invoice_admin": {
			Key: "billing:invoice_admin", Version: 1, Module: "billing",
			Name: "Invoice Admin", IsActive: true, Permissions: []string{"billing:invoices:read"},
		},
	}}
	entitled := &fakeHandlerEntitledModules{
		entitledOverride: map[uuid.UUID][]string{tenantID: {"marketing"}},
		allModules:       []string{"marketing", "billing"},
	}
	h := newTestRoleTemplateHandler(newFakeHandlerRoleRepo(), templateRepo, entitled)

	admin := &models.CurrentUser{ID: uuid.New(), TenantID: tenantID, Roles: []string{"admin"}}
	router := setupRoleTemplateRouter(t, h, tenantID, admin, map[string]bool{"core:roles:read": true})

	w := doTemplateRequest(router, http.MethodGet, "/api/v1/role-templates", "")
	require.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "marketing:campaign_manager")
	assert.NotContains(t, w.Body.String(), "billing:invoice_admin")
}

func (f *fakeHandlerPermissionRepo) GetByID(_ context.Context, _ uuid.UUID) (*models.Permission, error) {
	return nil, nil
}
