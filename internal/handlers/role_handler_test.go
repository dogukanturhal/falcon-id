// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/internal/repositories"
	"github.com/dogukanturhal/falcon-id/internal/services"
)

// ---------------------------------------------------------------------------
// Mock: roleServiceRoleRepo (unexported interface in services package)
// ---------------------------------------------------------------------------

type mockRoleHandlerRoleRepo struct {
	mock.Mock
}

func (m *mockRoleHandlerRoleRepo) GetByName(ctx context.Context, tenantID uuid.UUID, name string) (*models.Role, error) {
	args := m.Called(ctx, tenantID, name)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.Role), args.Error(1)
}

func (m *mockRoleHandlerRoleRepo) Create(ctx context.Context, role *models.Role) error {
	args := m.Called(ctx, role)
	if role.ID == uuid.Nil {
		role.ID = uuid.New()
	}
	role.CreatedAt = time.Now()
	role.UpdatedAt = time.Now()
	return args.Error(0)
}

func (m *mockRoleHandlerRoleRepo) AssignPermissions(ctx context.Context, roleID uuid.UUID, permIDs []uuid.UUID, assignedBy *uuid.UUID) error {
	args := m.Called(ctx, roleID, permIDs, assignedBy)
	return args.Error(0)
}

// GrantPermissionsByName is a no-op stub: no test in this file exercises the
// AcmeApp reconcile path.
func (m *mockRoleHandlerRoleRepo) GrantPermissionsByName(ctx context.Context, roleID uuid.UUID, permissionNames []string) error {
	return nil
}

func (m *mockRoleHandlerRoleRepo) GetRolePermissions(ctx context.Context, roleID uuid.UUID) ([]models.Permission, error) {
	args := m.Called(ctx, roleID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]models.Permission), args.Error(1)
}

func (m *mockRoleHandlerRoleRepo) GetByID(ctx context.Context, id uuid.UUID) (*models.Role, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.Role), args.Error(1)
}

func (m *mockRoleHandlerRoleRepo) Update(ctx context.Context, role *models.Role) error {
	args := m.Called(ctx, role)
	return args.Error(0)
}

func (m *mockRoleHandlerRoleRepo) Delete(ctx context.Context, id uuid.UUID) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *mockRoleHandlerRoleRepo) List(ctx context.Context, tenantID uuid.UUID, page, pageSize int, search string) ([]models.Role, int64, error) {
	args := m.Called(ctx, tenantID, page, pageSize, search)
	if args.Get(0) == nil {
		return nil, args.Get(1).(int64), args.Error(2)
	}
	return args.Get(0).([]models.Role), args.Get(1).(int64), args.Error(2)
}

func (m *mockRoleHandlerRoleRepo) ListForModules(ctx context.Context, tenantID uuid.UUID, page, pageSize int, search string, modules []string) ([]models.Role, int64, error) {
	args := m.Called(ctx, tenantID, page, pageSize, search, modules)
	if args.Get(0) == nil {
		return nil, args.Get(1).(int64), args.Error(2)
	}
	return args.Get(0).([]models.Role), args.Get(1).(int64), args.Error(2)
}

func (m *mockRoleHandlerRoleRepo) CreateSystemRoles(ctx context.Context, tenantID uuid.UUID) error {
	args := m.Called(ctx, tenantID)
	return args.Error(0)
}

func (m *mockRoleHandlerRoleRepo) GetByIDAndTenant(ctx context.Context, id, tenantID uuid.UUID) (*models.Role, error) {
	args := m.Called(ctx, id, tenantID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.Role), args.Error(1)
}

func (m *mockRoleHandlerRoleRepo) GetMaxPriorityForUser(ctx context.Context, userID, tenantID uuid.UUID) (int, error) {
	args := m.Called(ctx, userID, tenantID)
	return args.Int(0), args.Error(1)
}

func (m *mockRoleHandlerRoleRepo) GetRoleMembers(ctx context.Context, tenantID uuid.UUID, roleIdentifier string, page, pageSize int) ([]repositories.RoleMemberResult, int, error) {
	args := m.Called(ctx, tenantID, roleIdentifier, page, pageSize)
	if args.Get(0) == nil {
		return nil, 0, args.Error(2)
	}
	return args.Get(0).([]repositories.RoleMemberResult), args.Int(1), args.Error(2)
}

// ---------------------------------------------------------------------------
// Mock: roleServicePermissionRepo
// ---------------------------------------------------------------------------

type mockRoleHandlerPermRepo struct {
	mock.Mock
}

func (m *mockRoleHandlerPermRepo) List(ctx context.Context) ([]models.Permission, error) {
	args := m.Called(ctx)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]models.Permission), args.Error(1)
}

func (m *mockRoleHandlerPermRepo) GetModules(ctx context.Context) ([]string, error) {
	args := m.Called(ctx)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]string), args.Error(1)
}

func (m *mockRoleHandlerPermRepo) ListByModules(ctx context.Context, modules []string) ([]models.Permission, error) {
	args := m.Called(ctx, modules)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]models.Permission), args.Error(1)
}

func (m *mockRoleHandlerPermRepo) GetUserPermissionNames(ctx context.Context, userID, tenantID uuid.UUID) ([]string, error) {
	args := m.Called(ctx, userID, tenantID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]string), args.Error(1)
}

func (m *mockRoleHandlerPermRepo) GetByID(ctx context.Context, id uuid.UUID) (*models.Permission, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.Permission), args.Error(1)
}

func (m *mockRoleHandlerPermRepo) GetPermissionNamesByIDs(ctx context.Context, ids []uuid.UUID) (map[uuid.UUID]string, error) {
	args := m.Called(ctx, ids)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(map[uuid.UUID]string), args.Error(1)
}

func (m *mockRoleHandlerPermRepo) GetUserPermissionIDs(ctx context.Context, userID, tenantID uuid.UUID) ([]uuid.UUID, error) {
	args := m.Called(ctx, userID, tenantID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]uuid.UUID), args.Error(1)
}

// ---------------------------------------------------------------------------
// Mock: auditServiceTokenRepo (used by AuditService inside RoleService)
// ---------------------------------------------------------------------------

type mockRoleAuditTokenRepo struct {
	mock.Mock
}

func (m *mockRoleAuditTokenRepo) CreateAuditLog(ctx context.Context, log *models.AuditLog) error {
	args := m.Called(ctx, log)
	return args.Error(0)
}

func (m *mockRoleAuditTokenRepo) GetAuditLogByID(ctx context.Context, id, tenantID uuid.UUID) (*models.AuditLog, error) {
	args := m.Called(ctx, id, tenantID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.AuditLog), args.Error(1)
}

func (m *mockRoleAuditTokenRepo) ListAuditLogs(ctx context.Context, tenantID uuid.UUID, page, pageSize int, filters map[string]interface{}) ([]models.AuditLog, int64, error) {
	args := m.Called(ctx, tenantID, page, pageSize, filters)
	if args.Get(0) == nil {
		return nil, args.Get(1).(int64), args.Error(2)
	}
	return args.Get(0).([]models.AuditLog), args.Get(1).(int64), args.Error(2)
}

// ---------------------------------------------------------------------------
// Test setup helpers
// ---------------------------------------------------------------------------

func newTestRoleSvc(t *testing.T, roleRepo *mockRoleHandlerRoleRepo, permRepo *mockRoleHandlerPermRepo) *services.RoleService {
	t.Helper()
	auditRepo := new(mockRoleAuditTokenRepo)
	auditRepo.On("CreateAuditLog", mock.Anything, mock.AnythingOfType("*models.AuditLog")).Return(nil)
	auditSvc := services.NewAuditService(auditRepo, nil)
	return services.NewRoleService(roleRepo, permRepo, auditSvc)
}

func makeTestRole(tenantID uuid.UUID, isSystem bool) *models.Role {
	return &models.Role{
		ID:          uuid.New(),
		TenantID:    tenantID,
		Name:        "editor",
		DisplayName: "Editor",
		IsSystem:    isSystem,
		IsDefault:   false,
		Priority:    10,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}
}

func setupRoleHandlerRouter(h *RoleHandler, tenantID uuid.UUID, cu *models.CurrentUser) *gin.Engine {
	router := gin.New()
	inject := func(c *gin.Context) {
		c.Set("tenant_id", tenantID)
		c.Set("current_user", cu)
		if cu != nil {
			c.Set("user_id", cu.ID)
		}
		c.Next()
	}
	g := router.Group("/api/roles", inject)
	g.GET("", h.List)
	g.POST("", h.Create)
	g.GET("/:id", h.GetByID)
	g.PUT("/:id", h.Update)
	g.DELETE("/:id", h.Delete)
	g.GET("/:id/permissions", h.GetPermissions)
	g.PUT("/:id/permissions", h.AssignPermissions)

	// ListPermissions + ListPermissionsByModule were removed 2026-05-21
	// (duplicated PermissionHandler.List / ListGroupedByModule which are
	// the canonical permission-listing surfaces). The corresponding
	// TestRoleHandler_ListPermissions* tests were removed in the same
	// commit; the router setup function is kept as the role-mutation
	// test fixture.

	return router
}

// ---------------------------------------------------------------------------
// Tests: GET /api/roles (List)
// ---------------------------------------------------------------------------

func TestRoleHandler_List_ReturnsPaginatedRoles(t *testing.T) {
	tenantID := uuid.New()
	r := makeTestRole(tenantID, false)

	roleRepo := new(mockRoleHandlerRoleRepo)
	permRepo := new(mockRoleHandlerPermRepo)
	roleRepo.On("GetMaxPriorityForUser", mock.Anything, mock.AnythingOfType("uuid.UUID"), tenantID).Return(100, nil)
	roleRepo.On("ListForModules", mock.Anything, tenantID, 1, 100, "", []string{"core", "iam"}).Return([]models.Role{*r}, int64(1), nil)
	roleRepo.On("GetRolePermissions", mock.Anything, r.ID).Return([]models.Permission{}, nil)

	svc := newTestRoleSvc(t, roleRepo, permRepo)
	h := NewRoleHandler(svc)
	router := setupRoleHandlerRouter(h, tenantID, makeAdminCtx(tenantID))

	w := doRequest(router, http.MethodGet, "/api/roles", "")

	assert.Equal(t, http.StatusOK, w.Code)
	var resp map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Contains(t, resp, "roles")
	total := resp["total"].(float64)
	assert.Equal(t, float64(1), total)
}

// TestRoleHandler_List_SucceedsWithNilPermissions_V2Token is a control for
// the 2026-09-18 fix: v2 (SpiceDB) tokens always carry CurrentUser.Permissions
// == nil (see token_service.go/GenerateAccessTokenV2 and
// token_service_validation.go/extractSpiceDBClaims — "Permissions: nil, //
// Resolved via SpiceDB"). Route-level authorization for GET /api/v1/roles is
// authMiddleware.RequirePermission(permCoreRolesRead) in cmd/routes.go, which
// is SpiceDB-backed and already ran by the time this handler executes; the
// handler itself must not re-deny based on the (always-nil-for-v2) static
// Permissions claim.
//
// Before the fix this test fails with 403 {"error":"forbidden"} because
// RoleHandler.List called currentUser.HasPermission("core:roles:read"),
// which iterates a nil slice and always returns false — denying every
// v2-token caller regardless of their real SpiceDB grants or platform-admin
// status.
func TestRoleHandler_List_SucceedsWithNilPermissions_V2Token(t *testing.T) {
	tenantID := uuid.New()
	r := makeTestRole(tenantID, false)
	roleRepo := new(mockRoleHandlerRoleRepo)
	permRepo := new(mockRoleHandlerPermRepo)
	roleRepo.On("GetMaxPriorityForUser", mock.Anything, mock.AnythingOfType("uuid.UUID"), tenantID).Return(100, nil)
	roleRepo.On("ListForModules", mock.Anything, tenantID, 1, 100, "", []string{"core", "iam"}).Return([]models.Role{*r}, int64(1), nil)
	roleRepo.On("GetRolePermissions", mock.Anything, r.ID).Return([]models.Permission{}, nil)
	svc := newTestRoleSvc(t, roleRepo, permRepo)
	h := NewRoleHandler(svc)

	// Shape of a v2-token CurrentUser: Permissions is nil. IsPlatformAdmin is
	// false here on purpose — this is a regular tenant user whose access was
	// already decided by the SpiceDB-backed middleware, not a platform-admin
	// bypass case, to prove the handler itself isn't the thing deciding.
	v2User := &models.CurrentUser{
		ID:              uuid.New(),
		TenantID:        tenantID,
		Username:        "v2-user",
		Roles:           []string{"member"},
		Permissions:     nil,
		IsPlatformAdmin: false,
	}

	router := setupRoleHandlerRouter(h, tenantID, v2User)
	w := doRequest(router, http.MethodGet, "/api/roles", "")
	assert.Equal(t, http.StatusOK, w.Code, "handler must not re-deny core:roles:read locally; that decision belongs to the SpiceDB-backed RequirePermission middleware which already ran")
}

func TestRoleHandler_List_EmptyResult(t *testing.T) {
	tenantID := uuid.New()

	roleRepo := new(mockRoleHandlerRoleRepo)
	permRepo := new(mockRoleHandlerPermRepo)
	roleRepo.On("GetMaxPriorityForUser", mock.Anything, mock.AnythingOfType("uuid.UUID"), tenantID).Return(100, nil)
	roleRepo.On("ListForModules", mock.Anything, tenantID, 1, 100, "", []string{"core", "iam"}).Return([]models.Role{}, int64(0), nil)

	svc := newTestRoleSvc(t, roleRepo, permRepo)
	h := NewRoleHandler(svc)
	router := setupRoleHandlerRouter(h, tenantID, makeAdminCtx(tenantID))

	w := doRequest(router, http.MethodGet, "/api/roles", "")

	assert.Equal(t, http.StatusOK, w.Code)
	var resp map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	roles, _ := resp["roles"].([]interface{})
	assert.Len(t, roles, 0)
}

func TestRoleHandler_List_ServiceError_Returns500(t *testing.T) {
	tenantID := uuid.New()

	roleRepo := new(mockRoleHandlerRoleRepo)
	permRepo := new(mockRoleHandlerPermRepo)
	roleRepo.On("GetMaxPriorityForUser", mock.Anything, mock.AnythingOfType("uuid.UUID"), tenantID).Return(100, nil)
	roleRepo.On("ListForModules", mock.Anything, tenantID, 1, 100, "", []string{"core", "iam"}).Return(nil, int64(0), fmt.Errorf("db error"))

	svc := newTestRoleSvc(t, roleRepo, permRepo)
	h := NewRoleHandler(svc)
	router := setupRoleHandlerRouter(h, tenantID, makeAdminCtx(tenantID))

	w := doRequest(router, http.MethodGet, "/api/roles", "")

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestRoleHandler_List_IgnoresCallerTenantHeader(t *testing.T) {
	tenantID := uuid.New()
	roleRepo := new(mockRoleHandlerRoleRepo)
	permRepo := new(mockRoleHandlerPermRepo)
	roleRepo.On("GetMaxPriorityForUser", mock.Anything, mock.AnythingOfType("uuid.UUID"), tenantID).Return(100, nil)
	roleRepo.On("ListForModules", mock.Anything, tenantID, 1, 100, "", []string{"core", "iam"}).Return([]models.Role{}, int64(0), nil)

	h := NewRoleHandler(newTestRoleSvc(t, roleRepo, permRepo))
	router := setupRoleHandlerRouter(h, tenantID, makeAdminCtx(tenantID))
	req := httptest.NewRequest(http.MethodGet, "/api/roles", nil)
	req.Header.Set("X-Tenant-ID", uuid.NewString())
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	roleRepo.AssertExpectations(t)
}

// ---------------------------------------------------------------------------
// Tests: POST /api/roles (Create)
// ---------------------------------------------------------------------------

func TestRoleHandler_Create_ValidRequest_Returns201(t *testing.T) {
	tenantID := uuid.New()

	roleRepo := new(mockRoleHandlerRoleRepo)
	permRepo := new(mockRoleHandlerPermRepo)
	// RoleService.Create: GetByName returns (nil, nil) means name is available (no existing role found)
	// The service checks: if err != nil => fail; if existing != nil => duplicate
	// Returning (nil, nil): no error AND no existing role => name is free to use
	roleRepo.On("GetByName", mock.Anything, tenantID, "analyst").Return(nil, nil)
	roleRepo.On("GetMaxPriorityForUser", mock.Anything, mock.AnythingOfType("uuid.UUID"), tenantID).Return(100, nil)
	roleRepo.On("Create", mock.Anything, mock.AnythingOfType("*models.Role")).Return(nil)
	roleRepo.On("GetRolePermissions", mock.Anything, mock.AnythingOfType("uuid.UUID")).Return([]models.Permission{}, nil)

	svc := newTestRoleSvc(t, roleRepo, permRepo)
	h := NewRoleHandler(svc)
	router := setupRoleHandlerRouter(h, tenantID, makeAdminCtx(tenantID))

	body := `{"name":"analyst","display_name":"Analyst"}`
	w := doRequest(router, http.MethodPost, "/api/roles", body)

	assert.Equal(t, http.StatusCreated, w.Code)
}

func TestRoleHandler_Create_InvalidJSON_Returns400(t *testing.T) {
	tenantID := uuid.New()
	roleRepo := new(mockRoleHandlerRoleRepo)
	permRepo := new(mockRoleHandlerPermRepo)

	svc := newTestRoleSvc(t, roleRepo, permRepo)
	h := NewRoleHandler(svc)
	router := setupRoleHandlerRouter(h, tenantID, makeAdminCtx(tenantID))

	w := doRequest(router, http.MethodPost, "/api/roles", `{invalid}`)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestRoleHandler_Create_MissingName_Returns400(t *testing.T) {
	tenantID := uuid.New()
	roleRepo := new(mockRoleHandlerRoleRepo)
	permRepo := new(mockRoleHandlerPermRepo)

	svc := newTestRoleSvc(t, roleRepo, permRepo)
	h := NewRoleHandler(svc)
	router := setupRoleHandlerRouter(h, tenantID, makeAdminCtx(tenantID))

	// name is required (min=2)
	body := `{"display_name":"Missing Name"}`
	w := doRequest(router, http.MethodPost, "/api/roles", body)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestRoleHandler_Create_DuplicateName_Returns400(t *testing.T) {
	tenantID := uuid.New()
	existing := makeTestRole(tenantID, false)
	existing.Name = "editor"

	roleRepo := new(mockRoleHandlerRoleRepo)
	permRepo := new(mockRoleHandlerPermRepo)
	roleRepo.On("GetByName", mock.Anything, tenantID, "editor").Return(existing, nil)

	svc := newTestRoleSvc(t, roleRepo, permRepo)
	h := NewRoleHandler(svc)
	router := setupRoleHandlerRouter(h, tenantID, makeAdminCtx(tenantID))

	body := `{"name":"editor","display_name":"Editor"}`
	w := doRequest(router, http.MethodPost, "/api/roles", body)

	requireJSONErrorContains(t, w, http.StatusBadRequest, "already exists")
}

// ---------------------------------------------------------------------------
// Tests: GET /api/roles/:id (GetByID)
// ---------------------------------------------------------------------------

func TestRoleHandler_GetByID_Found(t *testing.T) {
	tenantID := uuid.New()
	r := makeTestRole(tenantID, false)

	roleRepo := new(mockRoleHandlerRoleRepo)
	permRepo := new(mockRoleHandlerPermRepo)
	roleRepo.On("GetByID", mock.Anything, r.ID).Return(r, nil)
	roleRepo.On("GetRolePermissions", mock.Anything, r.ID).Return([]models.Permission{}, nil)

	svc := newTestRoleSvc(t, roleRepo, permRepo)
	h := NewRoleHandler(svc)
	router := setupRoleHandlerRouter(h, tenantID, makeAdminCtx(tenantID))

	w := doRequest(router, http.MethodGet, "/api/roles/"+r.ID.String(), "")

	assert.Equal(t, http.StatusOK, w.Code)
	var resp map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, r.ID.String(), resp["id"])
}

func TestRoleHandler_GetByID_NotFound(t *testing.T) {
	tenantID := uuid.New()
	targetID := uuid.New()

	roleRepo := new(mockRoleHandlerRoleRepo)
	permRepo := new(mockRoleHandlerPermRepo)
	roleRepo.On("GetByID", mock.Anything, targetID).Return(nil, fmt.Errorf("not found"))

	svc := newTestRoleSvc(t, roleRepo, permRepo)
	h := NewRoleHandler(svc)
	router := setupRoleHandlerRouter(h, tenantID, makeAdminCtx(tenantID))

	w := doRequest(router, http.MethodGet, "/api/roles/"+targetID.String(), "")

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestRoleHandler_GetByID_DifferentTenant_Returns404(t *testing.T) {
	myTenant := uuid.New()
	otherTenant := uuid.New()
	r := makeTestRole(otherTenant, false) // belongs to another tenant

	roleRepo := new(mockRoleHandlerRoleRepo)
	permRepo := new(mockRoleHandlerPermRepo)
	roleRepo.On("GetByID", mock.Anything, r.ID).Return(r, nil)
	roleRepo.On("GetRolePermissions", mock.Anything, r.ID).Return([]models.Permission{}, nil)

	svc := newTestRoleSvc(t, roleRepo, permRepo)
	h := NewRoleHandler(svc)
	// inject myTenant into context
	router := setupRoleHandlerRouter(h, myTenant, makeAdminCtx(myTenant))

	w := doRequest(router, http.MethodGet, "/api/roles/"+r.ID.String(), "")

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestRoleHandler_GetByID_InvalidUUID(t *testing.T) {
	tenantID := uuid.New()
	roleRepo := new(mockRoleHandlerRoleRepo)
	permRepo := new(mockRoleHandlerPermRepo)

	svc := newTestRoleSvc(t, roleRepo, permRepo)
	h := NewRoleHandler(svc)
	router := setupRoleHandlerRouter(h, tenantID, makeAdminCtx(tenantID))

	w := doRequest(router, http.MethodGet, "/api/roles/not-a-uuid", "")

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ---------------------------------------------------------------------------
// Tests: PUT /api/roles/:id (Update)
// ---------------------------------------------------------------------------

func TestRoleHandler_Update_ValidRequest_Returns200(t *testing.T) {
	tenantID := uuid.New()
	r := makeTestRole(tenantID, false)

	roleRepo := new(mockRoleHandlerRoleRepo)
	permRepo := new(mockRoleHandlerPermRepo)
	// GetByID called for tenant validation and inside service Update
	roleRepo.On("GetByID", mock.Anything, r.ID).Return(r, nil)
	roleRepo.On("Update", mock.Anything, mock.AnythingOfType("*models.Role")).Return(nil)
	roleRepo.On("GetRolePermissions", mock.Anything, r.ID).Return([]models.Permission{}, nil)

	svc := newTestRoleSvc(t, roleRepo, permRepo)
	h := NewRoleHandler(svc)
	router := setupRoleHandlerRouter(h, tenantID, makeAdminCtx(tenantID))

	newDisplay := "Senior Editor"
	body, _ := json.Marshal(models.UpdateRoleRequest{DisplayName: &newDisplay})
	w := doRequest(router, http.MethodPut, "/api/roles/"+r.ID.String(), string(body))

	assert.Equal(t, http.StatusOK, w.Code)
	var resp map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "Senior Editor", resp["display_name"])
}

func TestRoleHandler_Update_NotFound_Returns404(t *testing.T) {
	tenantID := uuid.New()
	targetID := uuid.New()

	roleRepo := new(mockRoleHandlerRoleRepo)
	permRepo := new(mockRoleHandlerPermRepo)
	roleRepo.On("GetByID", mock.Anything, targetID).Return(nil, fmt.Errorf("not found"))

	svc := newTestRoleSvc(t, roleRepo, permRepo)
	h := NewRoleHandler(svc)
	router := setupRoleHandlerRouter(h, tenantID, makeAdminCtx(tenantID))

	body, _ := json.Marshal(models.UpdateRoleRequest{})
	w := doRequest(router, http.MethodPut, "/api/roles/"+targetID.String(), string(body))

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestRoleHandler_Update_SystemRole_CannotModifyProperties_Returns400(t *testing.T) {
	tenantID := uuid.New()
	// IsSystem = true => cannot update DisplayName
	sysRole := makeTestRole(tenantID, true)
	sysRole.Name = "admin"
	sysRole.DisplayName = "Administrator"

	roleRepo := new(mockRoleHandlerRoleRepo)
	permRepo := new(mockRoleHandlerPermRepo)
	// handler calls service.GetByID for tenant check (which calls GetByID + GetRolePermissions)
	// service Update then calls GetByID again (detects IsSystem, returns error - no GetRolePermissions call after that)
	roleRepo.On("GetByID", mock.Anything, sysRole.ID).Return(sysRole, nil)
	roleRepo.On("GetRolePermissions", mock.Anything, sysRole.ID).Return([]models.Permission{}, nil)

	svc := newTestRoleSvc(t, roleRepo, permRepo)
	h := NewRoleHandler(svc)
	router := setupRoleHandlerRouter(h, tenantID, makeAdminCtx(tenantID))

	// Attempting to change display name on system role
	newDisplay := "Hacked Admin"
	body, _ := json.Marshal(models.UpdateRoleRequest{DisplayName: &newDisplay})
	w := doRequest(router, http.MethodPut, "/api/roles/"+sysRole.ID.String(), string(body))

	// Service enforces: cannot modify system role properties
	assert.Equal(t, http.StatusBadRequest, w.Code)
	requireJSONErrorContains(t, w, http.StatusBadRequest, "system role")
}

// ---------------------------------------------------------------------------
// Tests: DELETE /api/roles/:id (Delete)
// ---------------------------------------------------------------------------

func TestRoleHandler_Delete_Returns200(t *testing.T) {
	tenantID := uuid.New()
	r := makeTestRole(tenantID, false)

	roleRepo := new(mockRoleHandlerRoleRepo)
	permRepo := new(mockRoleHandlerPermRepo)
	// handler calls service.GetByID for tenant validation (GetByID + GetRolePermissions)
	// service.Delete then calls GetByID again (no GetRolePermissions) and GetMaxPriorityForUser
	roleRepo.On("GetByID", mock.Anything, r.ID).Return(r, nil)
	roleRepo.On("GetRolePermissions", mock.Anything, r.ID).Return([]models.Permission{}, nil)
	roleRepo.On("GetMaxPriorityForUser", mock.Anything, mock.AnythingOfType("uuid.UUID"), tenantID).Return(100, nil)
	roleRepo.On("Delete", mock.Anything, r.ID).Return(nil)

	svc := newTestRoleSvc(t, roleRepo, permRepo)
	h := NewRoleHandler(svc)
	router := setupRoleHandlerRouter(h, tenantID, makeAdminCtx(tenantID))

	w := doRequest(router, http.MethodDelete, "/api/roles/"+r.ID.String(), "")

	assert.Equal(t, http.StatusOK, w.Code)
	var resp map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Contains(t, strings.ToLower(fmt.Sprint(resp["message"])), "deleted")
}

func TestRoleHandler_Delete_SystemRole_CannotDelete_Returns400(t *testing.T) {
	tenantID := uuid.New()
	sysRole := makeTestRole(tenantID, true)

	roleRepo := new(mockRoleHandlerRoleRepo)
	permRepo := new(mockRoleHandlerPermRepo)
	// handler calls service.GetByID for tenant validation (GetByID + GetRolePermissions)
	// service.Delete then calls GetByID again and detects IsSystem
	roleRepo.On("GetByID", mock.Anything, sysRole.ID).Return(sysRole, nil)
	roleRepo.On("GetRolePermissions", mock.Anything, sysRole.ID).Return([]models.Permission{}, nil)

	svc := newTestRoleSvc(t, roleRepo, permRepo)
	h := NewRoleHandler(svc)
	router := setupRoleHandlerRouter(h, tenantID, makeAdminCtx(tenantID))

	w := doRequest(router, http.MethodDelete, "/api/roles/"+sysRole.ID.String(), "")

	requireJSONErrorContains(t, w, http.StatusBadRequest, "system role")
}

func TestRoleHandler_Delete_NotFound_Returns404(t *testing.T) {
	tenantID := uuid.New()
	targetID := uuid.New()

	roleRepo := new(mockRoleHandlerRoleRepo)
	permRepo := new(mockRoleHandlerPermRepo)
	roleRepo.On("GetByID", mock.Anything, targetID).Return(nil, fmt.Errorf("not found"))

	svc := newTestRoleSvc(t, roleRepo, permRepo)
	h := NewRoleHandler(svc)
	router := setupRoleHandlerRouter(h, tenantID, makeAdminCtx(tenantID))

	w := doRequest(router, http.MethodDelete, "/api/roles/"+targetID.String(), "")

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestRoleHandler_Delete_DifferentTenant_Returns404(t *testing.T) {
	myTenant := uuid.New()
	otherTenant := uuid.New()
	r := makeTestRole(otherTenant, false)

	roleRepo := new(mockRoleHandlerRoleRepo)
	permRepo := new(mockRoleHandlerPermRepo)
	// handler calls service.GetByID for tenant validation (GetByID + GetRolePermissions)
	// then detects tenant mismatch and returns 404 before service.Delete is called
	roleRepo.On("GetByID", mock.Anything, r.ID).Return(r, nil)
	roleRepo.On("GetRolePermissions", mock.Anything, r.ID).Return([]models.Permission{}, nil)

	svc := newTestRoleSvc(t, roleRepo, permRepo)
	h := NewRoleHandler(svc)
	router := setupRoleHandlerRouter(h, myTenant, makeAdminCtx(myTenant))

	w := doRequest(router, http.MethodDelete, "/api/roles/"+r.ID.String(), "")

	assert.Equal(t, http.StatusNotFound, w.Code)
}

// ---------------------------------------------------------------------------
// Tests: GET /api/roles/:id/permissions (GetPermissions)
// ---------------------------------------------------------------------------

func TestRoleHandler_GetPermissions_Returns200(t *testing.T) {
	tenantID := uuid.New()
	r := makeTestRole(tenantID, false)
	perm := models.Permission{
		ID:          uuid.New(),
		Module:      "core",
		Resource:    "users",
		Action:      "read",
		Name:        "core:users:read",
		DisplayName: "Read Users",
	}

	roleRepo := new(mockRoleHandlerRoleRepo)
	permRepo := new(mockRoleHandlerPermRepo)
	roleRepo.On("GetByID", mock.Anything, r.ID).Return(r, nil)
	roleRepo.On("GetRolePermissions", mock.Anything, r.ID).Return([]models.Permission{perm}, nil)

	svc := newTestRoleSvc(t, roleRepo, permRepo)
	h := NewRoleHandler(svc)
	router := setupRoleHandlerRouter(h, tenantID, makeAdminCtx(tenantID))

	w := doRequest(router, http.MethodGet, "/api/roles/"+r.ID.String()+"/permissions", "")

	assert.Equal(t, http.StatusOK, w.Code)
	var resp map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	perms, ok := resp["permissions"].([]interface{})
	require.True(t, ok)
	assert.Len(t, perms, 1)
}

func TestRoleHandler_GetPermissions_NotFound_Returns404(t *testing.T) {
	tenantID := uuid.New()
	targetID := uuid.New()

	roleRepo := new(mockRoleHandlerRoleRepo)
	permRepo := new(mockRoleHandlerPermRepo)
	roleRepo.On("GetByID", mock.Anything, targetID).Return(nil, fmt.Errorf("not found"))

	svc := newTestRoleSvc(t, roleRepo, permRepo)
	h := NewRoleHandler(svc)
	router := setupRoleHandlerRouter(h, tenantID, makeAdminCtx(tenantID))

	w := doRequest(router, http.MethodGet, "/api/roles/"+targetID.String()+"/permissions", "")

	assert.Equal(t, http.StatusNotFound, w.Code)
}

// ---------------------------------------------------------------------------
// Tests: PUT /api/roles/:id/permissions (AssignPermissions)
// ---------------------------------------------------------------------------

func TestRoleHandler_AssignPermissions_Returns200(t *testing.T) {
	tenantID := uuid.New()
	r := makeTestRole(tenantID, false)
	permID := uuid.New()

	roleRepo := new(mockRoleHandlerRoleRepo)
	permRepo := new(mockRoleHandlerPermRepo)
	roleRepo.On("GetByID", mock.Anything, r.ID).Return(r, nil)
	roleRepo.On("AssignPermissions", mock.Anything, r.ID, mock.Anything, mock.Anything).Return(nil)
	roleRepo.On("GetRolePermissions", mock.Anything, r.ID).Return([]models.Permission{}, nil)
	// checkCallerCoversPermissions: caller has module-level wildcard covering all permissions
	permRepo.On("GetUserPermissionNames", mock.Anything, mock.AnythingOfType("uuid.UUID"), tenantID).
		Return([]string{"crm:*:*"}, nil)
	permRepo.On("GetPermissionNamesByIDs", mock.Anything, mock.Anything).
		Return(map[uuid.UUID]string{permID: "crm:contacts:read"}, nil)
	// ADR-A10 boundary check (checkGrantBoundaryForIDs): no
	// entitlementChecker is wired in this test, so EntitledModules fails
	// closed to UniversalModules (core, iam) — use a core permission so
	// the boundary passes.
	permRepo.On("GetByID", mock.Anything, permID).
		Return(&models.Permission{ID: permID, Name: "core:contacts:read", Module: "core"}, nil)

	svc := newTestRoleSvc(t, roleRepo, permRepo)
	h := NewRoleHandler(svc)
	router := setupRoleHandlerRouter(h, tenantID, makeAdminCtx(tenantID))

	body := fmt.Sprintf(`{"permission_ids":[%q]}`, permID.String())
	w := doRequest(router, http.MethodPut, "/api/roles/"+r.ID.String()+"/permissions", body)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Contains(t, strings.ToLower(fmt.Sprint(resp["message"])), "assigned")
}

func TestRoleHandler_AssignPermissions_NotFound_Returns404(t *testing.T) {
	tenantID := uuid.New()
	targetID := uuid.New()

	roleRepo := new(mockRoleHandlerRoleRepo)
	permRepo := new(mockRoleHandlerPermRepo)
	roleRepo.On("GetByID", mock.Anything, targetID).Return(nil, fmt.Errorf("not found"))

	svc := newTestRoleSvc(t, roleRepo, permRepo)
	h := NewRoleHandler(svc)
	router := setupRoleHandlerRouter(h, tenantID, makeAdminCtx(tenantID))

	body := `{"permission_ids":[]}`
	w := doRequest(router, http.MethodPut, "/api/roles/"+targetID.String()+"/permissions", body)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

type fakeRoleAPIKeyUsage struct{ n int }

func (f fakeRoleAPIKeyUsage) CountActiveTenantKeysByRole(context.Context, uuid.UUID, uuid.UUID) (int, error) {
	return f.n, nil
}

func TestRoleHandler_AssignPermissions_ForbiddenForAPIKeyRole_Returns409(t *testing.T) {
	tenantID := uuid.New()
	r := makeTestRole(tenantID, false)
	permID := uuid.New()

	roleRepo := new(mockRoleHandlerRoleRepo)
	permRepo := new(mockRoleHandlerPermRepo)
	roleRepo.On("GetByID", mock.Anything, r.ID).Return(r, nil)
	roleRepo.On("GetRolePermissions", mock.Anything, r.ID).Return([]models.Permission{}, nil)
	permRepo.On("GetPermissionNamesByIDs", mock.Anything, mock.Anything).
		Return(map[uuid.UUID]string{permID: "iam:users:manage"}, nil)

	svc := newTestRoleSvc(t, roleRepo, permRepo)
	svc.SetAPIKeyRoleUsage(fakeRoleAPIKeyUsage{n: 2})
	h := NewRoleHandler(svc)
	router := setupRoleHandlerRouter(h, tenantID, makeAdminCtx(tenantID))

	body := fmt.Sprintf(`{"permission_ids":[%q]}`, permID.String())
	w := doRequest(router, http.MethodPut, "/api/roles/"+r.ID.String()+"/permissions", body)

	assert.Equal(t, http.StatusConflict, w.Code)
	var resp map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.EqualValues(t, 2, resp["key_count"])
}
