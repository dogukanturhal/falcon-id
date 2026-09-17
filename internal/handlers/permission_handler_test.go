// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/internal/services"
)

// ---------------------------------------------------------------------------
// Mock: permissionServicePermissionRepo
// ---------------------------------------------------------------------------

type mockPermHandlerPermRepo struct {
	mock.Mock
}

func (m *mockPermHandlerPermRepo) RegisterPermissionsBatch(ctx context.Context, permissions []*models.Permission) (int, int, error) {
	args := m.Called(ctx, permissions)
	return args.Int(0), args.Int(1), args.Error(2)
}

func (m *mockPermHandlerPermRepo) DeprecateUnlistedInModule(ctx context.Context, module string, activePermissionNames []string, sunsetWindow time.Duration) (int, error) {
	args := m.Called(ctx, module, activePermissionNames, sunsetWindow)
	return args.Int(0), args.Error(1)
}

func (m *mockPermHandlerPermRepo) List(ctx context.Context) ([]models.Permission, error) {
	args := m.Called(ctx)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]models.Permission), args.Error(1)
}

func (m *mockPermHandlerPermRepo) ListByModule(ctx context.Context, module string) ([]models.Permission, error) {
	args := m.Called(ctx, module)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]models.Permission), args.Error(1)
}

func (m *mockPermHandlerPermRepo) GetModules(ctx context.Context) ([]string, error) {
	args := m.Called(ctx)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]string), args.Error(1)
}

func (m *mockPermHandlerPermRepo) GetByID(ctx context.Context, id uuid.UUID) (*models.Permission, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.Permission), args.Error(1)
}

func (m *mockPermHandlerPermRepo) GetByName(ctx context.Context, name string) (*models.Permission, error) {
	args := m.Called(ctx, name)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.Permission), args.Error(1)
}

func (m *mockPermHandlerPermRepo) Create(ctx context.Context, perm *models.Permission) error {
	args := m.Called(ctx, perm)
	if args.Error(0) == nil {
		perm.ID = uuid.New()
	}
	return args.Error(0)
}

func (m *mockPermHandlerPermRepo) Update(ctx context.Context, id uuid.UUID, displayName *string, description *string) error {
	args := m.Called(ctx, id, displayName, description)
	return args.Error(0)
}

func (m *mockPermHandlerPermRepo) DeleteIfNotInUse(ctx context.Context, id uuid.UUID) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *mockPermHandlerPermRepo) ListByModules(ctx context.Context, modules []string) ([]models.Permission, error) {
	args := m.Called(ctx, modules)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]models.Permission), args.Error(1)
}

// ---------------------------------------------------------------------------
// Mock: audit token repo (reuse shape for PermissionService)
// ---------------------------------------------------------------------------

type mockPermAuditTokenRepo struct {
	mock.Mock
}

func (m *mockPermAuditTokenRepo) CreateAuditLog(ctx context.Context, log *models.AuditLog) error {
	args := m.Called(ctx, log)
	return args.Error(0)
}

func (m *mockPermAuditTokenRepo) GetAuditLogByID(ctx context.Context, id, tenantID uuid.UUID) (*models.AuditLog, error) {
	args := m.Called(ctx, id, tenantID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.AuditLog), args.Error(1)
}

func (m *mockPermAuditTokenRepo) ListAuditLogs(ctx context.Context, tenantID uuid.UUID, page, pageSize int, filters map[string]interface{}) ([]models.AuditLog, int64, error) {
	args := m.Called(ctx, tenantID, page, pageSize, filters)
	if args.Get(0) == nil {
		return nil, args.Get(1).(int64), args.Error(2)
	}
	return args.Get(0).([]models.AuditLog), args.Get(1).(int64), args.Error(2)
}

// ---------------------------------------------------------------------------
// Test setup
// ---------------------------------------------------------------------------

func newTestPermSvc(t *testing.T, repo *mockPermHandlerPermRepo) *services.PermissionService {
	t.Helper()
	auditRepo := new(mockPermAuditTokenRepo)
	auditRepo.On("CreateAuditLog", mock.Anything, mock.AnythingOfType("*models.AuditLog")).Return(nil)
	auditSvc := services.NewAuditService(auditRepo, nil)
	return services.NewPermissionService(repo, auditSvc)
}

func setupPermHandlerRouter(h *PermissionHandler, tenantID uuid.UUID, cu *models.CurrentUser) *gin.Engine {
	router := gin.New()
	inject := func(c *gin.Context) {
		c.Set("tenant_id", tenantID)
		c.Set("current_user", cu)
		if cu != nil {
			c.Set("user_id", cu.ID)
		}
		c.Next()
	}
	g := router.Group("/api/permissions", inject)
	g.POST("/register", h.RegisterModule)
	g.GET("", h.List)
	g.GET("/module/:module", h.ListByModule)
	g.GET("/modules", h.ListModules)
	g.GET("/grouped", h.ListGroupedByModule)
	return router
}

func samplePermissions() []models.Permission {
	return []models.Permission{
		{ID: uuid.New(), Module: "core", Resource: "users", Action: "read", Name: "core:users:read", DisplayName: "Read Users", IsSystem: true},
		{ID: uuid.New(), Module: "core", Resource: "users", Action: "write", Name: "core:users:write", DisplayName: "Write Users", IsSystem: true},
		{ID: uuid.New(), Module: "billing", Resource: "invoices", Action: "read", Name: "billing:invoices:read", DisplayName: "Read Invoices"},
	}
}

// ---------------------------------------------------------------------------
// Tests: POST /api/permissions/register (RegisterModule)
// ---------------------------------------------------------------------------

func TestPermissionHandler_RegisterModule_Returns200(t *testing.T) {
	tenantID := uuid.New()
	repo := new(mockPermHandlerPermRepo)
	// RegisterPermissionsBatch returns (registered=2, updated=0, err=nil)
	repo.On("RegisterPermissionsBatch", mock.Anything, mock.Anything).Return(2, 0, nil)

	svc := newTestPermSvc(t, repo)
	h := NewPermissionHandler(svc)
	router := setupPermHandlerRouter(h, tenantID, makeAdminCtx(tenantID))

	body := `{
		"module": "crm",
		"permissions": [
			{"resource": "contacts", "actions": ["read", "write"]}
		]
	}`
	w := doRequest(router, http.MethodPost, "/api/permissions/register", body)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "crm", resp["module"])
	assert.Equal(t, float64(2), resp["registered"])
}

func TestPermissionHandler_RegisterModule_InvalidJSON_Returns400(t *testing.T) {
	tenantID := uuid.New()
	repo := new(mockPermHandlerPermRepo)

	svc := newTestPermSvc(t, repo)
	h := NewPermissionHandler(svc)
	router := setupPermHandlerRouter(h, tenantID, makeAdminCtx(tenantID))

	w := doRequest(router, http.MethodPost, "/api/permissions/register", `{invalid}`)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestPermissionHandler_RegisterModule_MissingModule_Returns400(t *testing.T) {
	tenantID := uuid.New()
	repo := new(mockPermHandlerPermRepo)

	svc := newTestPermSvc(t, repo)
	h := NewPermissionHandler(svc)
	router := setupPermHandlerRouter(h, tenantID, makeAdminCtx(tenantID))

	// module field is required
	body := `{"permissions":[{"resource":"contacts","actions":["read"]}]}`
	w := doRequest(router, http.MethodPost, "/api/permissions/register", body)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestPermissionHandler_RegisterModule_EmptyPermissions_Returns400(t *testing.T) {
	tenantID := uuid.New()
	repo := new(mockPermHandlerPermRepo)

	svc := newTestPermSvc(t, repo)
	h := NewPermissionHandler(svc)
	router := setupPermHandlerRouter(h, tenantID, makeAdminCtx(tenantID))

	// permissions array is required (min=1)
	body := `{"module":"crm","permissions":[]}`
	w := doRequest(router, http.MethodPost, "/api/permissions/register", body)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestPermissionHandler_RegisterModule_MissingResource_Returns400(t *testing.T) {
	tenantID := uuid.New()
	repo := new(mockPermHandlerPermRepo)

	svc := newTestPermSvc(t, repo)
	h := NewPermissionHandler(svc)
	router := setupPermHandlerRouter(h, tenantID, makeAdminCtx(tenantID))

	// resource is required in each permission definition
	body := `{"module":"crm","permissions":[{"actions":["read"]}]}`
	w := doRequest(router, http.MethodPost, "/api/permissions/register", body)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestPermissionHandler_RegisterModule_ServiceError_Returns400(t *testing.T) {
	tenantID := uuid.New()
	repo := new(mockPermHandlerPermRepo)
	repo.On("RegisterPermissionsBatch", mock.Anything, mock.Anything).Return(0, 0, fmt.Errorf("db error"))

	svc := newTestPermSvc(t, repo)
	h := NewPermissionHandler(svc)
	router := setupPermHandlerRouter(h, tenantID, makeAdminCtx(tenantID))

	body := `{"module":"crm","permissions":[{"resource":"contacts","actions":["read"]}]}`
	w := doRequest(router, http.MethodPost, "/api/permissions/register", body)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ---------------------------------------------------------------------------
// Tests: GET /api/permissions (List)
// ---------------------------------------------------------------------------

func TestPermissionHandler_List_Returns200(t *testing.T) {
	tenantID := uuid.New()
	repo := new(mockPermHandlerPermRepo)
	perms := samplePermissions()
	repo.On("List", mock.Anything).Return(perms, nil)

	svc := newTestPermSvc(t, repo)
	h := NewPermissionHandler(svc)
	router := setupPermHandlerRouter(h, tenantID, makeAdminCtx(tenantID))

	w := doRequest(router, http.MethodGet, "/api/permissions", "")

	assert.Equal(t, http.StatusOK, w.Code)
	var resp map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	permList, ok := resp["permissions"].([]interface{})
	require.True(t, ok)
	assert.Len(t, permList, 3)
	assert.Equal(t, float64(3), resp["total"])
}

func TestPermissionHandler_List_Empty_Returns200(t *testing.T) {
	tenantID := uuid.New()
	repo := new(mockPermHandlerPermRepo)
	repo.On("List", mock.Anything).Return([]models.Permission{}, nil)

	svc := newTestPermSvc(t, repo)
	h := NewPermissionHandler(svc)
	router := setupPermHandlerRouter(h, tenantID, makeAdminCtx(tenantID))

	w := doRequest(router, http.MethodGet, "/api/permissions", "")

	assert.Equal(t, http.StatusOK, w.Code)
	var resp map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, float64(0), resp["total"])
}

func TestPermissionHandler_List_ServiceError_Returns500(t *testing.T) {
	tenantID := uuid.New()
	repo := new(mockPermHandlerPermRepo)
	repo.On("List", mock.Anything).Return(nil, fmt.Errorf("db error"))

	svc := newTestPermSvc(t, repo)
	h := NewPermissionHandler(svc)
	router := setupPermHandlerRouter(h, tenantID, makeAdminCtx(tenantID))

	w := doRequest(router, http.MethodGet, "/api/permissions", "")

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// ---------------------------------------------------------------------------
// Tests: GET /api/permissions/module/:module (ListByModule)
// ---------------------------------------------------------------------------

func TestPermissionHandler_ListByModule_FilteredByModule(t *testing.T) {
	tenantID := uuid.New()
	repo := new(mockPermHandlerPermRepo)
	corePerms := []models.Permission{
		{ID: uuid.New(), Module: "core", Resource: "users", Action: "read", Name: "core:users:read", DisplayName: "Read Users"},
		{ID: uuid.New(), Module: "core", Resource: "users", Action: "write", Name: "core:users:write", DisplayName: "Write Users"},
	}
	repo.On("ListByModule", mock.Anything, "core").Return(corePerms, nil)

	svc := newTestPermSvc(t, repo)
	h := NewPermissionHandler(svc)
	router := setupPermHandlerRouter(h, tenantID, makeAdminCtx(tenantID))

	w := doRequest(router, http.MethodGet, "/api/permissions/module/core", "")

	assert.Equal(t, http.StatusOK, w.Code)
	var resp map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	permList, ok := resp["permissions"].([]interface{})
	require.True(t, ok)
	assert.Len(t, permList, 2)
	assert.Equal(t, float64(2), resp["total"])
}

func TestPermissionHandler_ListByModule_ServiceError_Returns500(t *testing.T) {
	tenantID := uuid.New()
	repo := new(mockPermHandlerPermRepo)
	repo.On("ListByModule", mock.Anything, "core").Return(nil, fmt.Errorf("db error"))

	svc := newTestPermSvc(t, repo)
	h := NewPermissionHandler(svc)
	router := setupPermHandlerRouter(h, tenantID, makeAdminCtx(tenantID))

	w := doRequest(router, http.MethodGet, "/api/permissions/module/core", "")

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// ---------------------------------------------------------------------------
// Tests: GET /api/permissions/modules (ListModules)
// ---------------------------------------------------------------------------

func TestPermissionHandler_ListModules_Returns200(t *testing.T) {
	tenantID := uuid.New()
	repo := new(mockPermHandlerPermRepo)
	repo.On("GetModules", mock.Anything).Return([]string{"core", "billing", "crm"}, nil)

	svc := newTestPermSvc(t, repo)
	h := NewPermissionHandler(svc)
	router := setupPermHandlerRouter(h, tenantID, makeAdminCtx(tenantID))

	w := doRequest(router, http.MethodGet, "/api/permissions/modules", "")

	assert.Equal(t, http.StatusOK, w.Code)
	var resp map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	modules, ok := resp["modules"].([]interface{})
	require.True(t, ok)
	assert.Len(t, modules, 3)
}

func TestPermissionHandler_ListModules_Empty_Returns200(t *testing.T) {
	tenantID := uuid.New()
	repo := new(mockPermHandlerPermRepo)
	repo.On("GetModules", mock.Anything).Return([]string{}, nil)

	svc := newTestPermSvc(t, repo)
	h := NewPermissionHandler(svc)
	router := setupPermHandlerRouter(h, tenantID, makeAdminCtx(tenantID))

	w := doRequest(router, http.MethodGet, "/api/permissions/modules", "")

	assert.Equal(t, http.StatusOK, w.Code)
	var resp map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	modules, ok := resp["modules"].([]interface{})
	require.True(t, ok)
	assert.Len(t, modules, 0)
}

func TestPermissionHandler_ListModules_ServiceError_Returns500(t *testing.T) {
	tenantID := uuid.New()
	repo := new(mockPermHandlerPermRepo)
	repo.On("GetModules", mock.Anything).Return(nil, fmt.Errorf("db error"))

	svc := newTestPermSvc(t, repo)
	h := NewPermissionHandler(svc)
	router := setupPermHandlerRouter(h, tenantID, makeAdminCtx(tenantID))

	w := doRequest(router, http.MethodGet, "/api/permissions/modules", "")

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// ---------------------------------------------------------------------------
// Tests: GET /api/permissions/grouped (ListGroupedByModule)
// ---------------------------------------------------------------------------

func TestPermissionHandler_ListGroupedByModule_Returns200(t *testing.T) {
	tenantID := uuid.New()
	repo := new(mockPermHandlerPermRepo)
	repo.On("List", mock.Anything).Return(samplePermissions(), nil)

	svc := newTestPermSvc(t, repo)
	h := NewPermissionHandler(svc)
	router := setupPermHandlerRouter(h, tenantID, makeAdminCtx(tenantID))

	w := doRequest(router, http.MethodGet, "/api/permissions/grouped", "")

	assert.Equal(t, http.StatusOK, w.Code)
	// Response is a list of PermissionsByModule objects
	var resp []interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Len(t, resp, 2) // core, billing
}

func TestPermissionHandler_ListGroupedByModule_ServiceError_Returns500(t *testing.T) {
	tenantID := uuid.New()
	repo := new(mockPermHandlerPermRepo)
	repo.On("List", mock.Anything).Return(nil, fmt.Errorf("db error"))

	svc := newTestPermSvc(t, repo)
	h := NewPermissionHandler(svc)
	router := setupPermHandlerRouter(h, tenantID, makeAdminCtx(tenantID))

	w := doRequest(router, http.MethodGet, "/api/permissions/grouped", "")

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}
