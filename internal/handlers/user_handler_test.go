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
	"github.com/dogukanturhal/falcon-id/internal/services"
	"github.com/dogukanturhal/falcon-id/pkg/config"
)

// ---------------------------------------------------------------------------
// Mock: userServiceUserRepo
// ---------------------------------------------------------------------------

type mockUserServiceUserRepo struct {
	mock.Mock
}

func (m *mockUserServiceUserRepo) Create(ctx context.Context, user *models.User) error {
	args := m.Called(ctx, user)
	// Auto-assign ID to simulate DB behaviour
	if user.ID == uuid.Nil {
		user.ID = uuid.New()
	}
	user.CreatedAt = time.Now()
	user.UpdatedAt = time.Now()
	return args.Error(0)
}

func (m *mockUserServiceUserRepo) GetByID(ctx context.Context, id uuid.UUID) (*models.User, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.User), args.Error(1)
}

func (m *mockUserServiceUserRepo) GetByUsername(ctx context.Context, tenantID uuid.UUID, username string) (*models.User, error) {
	args := m.Called(ctx, tenantID, username)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.User), args.Error(1)
}

func (m *mockUserServiceUserRepo) GetByEmail(ctx context.Context, tenantID uuid.UUID, email string) (*models.User, error) {
	args := m.Called(ctx, tenantID, email)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.User), args.Error(1)
}

func (m *mockUserServiceUserRepo) Update(ctx context.Context, user *models.User) error {
	args := m.Called(ctx, user)
	return args.Error(0)
}

func (m *mockUserServiceUserRepo) Delete(ctx context.Context, id uuid.UUID) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *mockUserServiceUserRepo) List(ctx context.Context, tenantID uuid.UUID, page, pageSize int, search string) ([]models.User, int64, error) {
	args := m.Called(ctx, tenantID, page, pageSize, search)
	if args.Get(0) == nil {
		return nil, args.Get(1).(int64), args.Error(2)
	}
	return args.Get(0).([]models.User), args.Get(1).(int64), args.Error(2)
}

func (m *mockUserServiceUserRepo) ListTenantMemberCards(ctx context.Context, tenantID, viewerID uuid.UUID, limit, offset int) ([]models.User, int, error) {
	args := m.Called(ctx, tenantID, viewerID, limit, offset)
	if args.Get(0) == nil {
		return nil, args.Int(1), args.Error(2)
	}
	return args.Get(0).([]models.User), args.Int(1), args.Error(2)
}

func (m *mockUserServiceUserRepo) AssignRoles(ctx context.Context, userID uuid.UUID, roleIDs []uuid.UUID, assignedBy *uuid.UUID) error {
	args := m.Called(ctx, userID, roleIDs, assignedBy)
	return args.Error(0)
}

func (m *mockUserServiceUserRepo) GetUserRoles(ctx context.Context, userID uuid.UUID) ([]models.Role, error) {
	args := m.Called(ctx, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]models.Role), args.Error(1)
}

func (m *mockUserServiceUserRepo) GetUserPermissions(ctx context.Context, userID uuid.UUID) ([]models.Permission, error) {
	args := m.Called(ctx, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]models.Permission), args.Error(1)
}

func (m *mockUserServiceUserRepo) UnlockUser(ctx context.Context, userID uuid.UUID) error {
	args := m.Called(ctx, userID)
	return args.Error(0)
}

// ---------------------------------------------------------------------------
// Mock: userServiceRoleRepo
// ---------------------------------------------------------------------------

type mockUserServiceRoleRepo struct {
	mock.Mock
}

func (m *mockUserServiceRoleRepo) GetByID(ctx context.Context, id uuid.UUID) (*models.Role, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.Role), args.Error(1)
}

func (m *mockUserServiceRoleRepo) GetDefaultRoles(ctx context.Context, tenantID uuid.UUID) ([]models.Role, error) {
	args := m.Called(ctx, tenantID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]models.Role), args.Error(1)
}

func (m *mockUserServiceRoleRepo) GetByIDAndTenant(ctx context.Context, id, tenantID uuid.UUID) (*models.Role, error) {
	args := m.Called(ctx, id, tenantID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.Role), args.Error(1)
}

func (m *mockUserServiceRoleRepo) GetMaxPriorityForUser(ctx context.Context, userID, tenantID uuid.UUID) (int, error) {
	args := m.Called(ctx, userID, tenantID)
	return args.Int(0), args.Error(1)
}

// ---------------------------------------------------------------------------
// Mock: userServiceTokenService
// ---------------------------------------------------------------------------

type mockUserTokenSvc struct{ mock.Mock }

func (m *mockUserTokenSvc) RevokeAllUserOAuthTokens(ctx context.Context, userID uuid.UUID, reason string) error {
	args := m.Called(ctx, userID, reason)
	return args.Error(0)
}

// ---------------------------------------------------------------------------
// Mock: userServiceAuditService
// ---------------------------------------------------------------------------

type mockUserAuditSvc struct{ mock.Mock }

func (m *mockUserAuditSvc) LogUserAction(ctx context.Context, tenantID uuid.UUID, actorID, targetUserID *uuid.UUID, action string, success bool, details map[string]interface{}) {
	m.Called(ctx, tenantID, actorID, targetUserID, action, success, details)
}

// ---------------------------------------------------------------------------
// Mock: userServiceRealmResolver
// ---------------------------------------------------------------------------

// mockUserServiceRealmResolver is a test double that unconditionally resolves
// any tenant to WellKnownRealmShared, mirroring the production path where every
// tenant has an explicit entry in realm_tenants.
type mockUserServiceRealmResolver struct{}

func (m *mockUserServiceRealmResolver) GetTenantRealm(_ context.Context, _ uuid.UUID) (*models.Realm, error) {
	return &models.Realm{ID: models.WellKnownRealmShared}, nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func newTestUserSvc(t *testing.T, userRepo *mockUserServiceUserRepo) *services.UserService {
	t.Helper()
	cfg := &config.Config{
		PasswordMinLength:      8,
		PasswordRequireUpper:   false,
		PasswordRequireLower:   false,
		PasswordRequireDigit:   false,
		PasswordRequireSpecial: false,
	}
	roleRepo := new(mockUserServiceRoleRepo)
	roleRepo.On("GetDefaultRoles", mock.Anything, mock.Anything).Return([]models.Role{}, nil)
	// Wildcard: SetUserRoles verifies every role exists via GetByID.
	roleRepo.On("GetByID", mock.Anything, mock.Anything).Return(&models.Role{ID: uuid.New(), Name: "role"}, nil)
	// Wildcard: SetUserRoles now uses GetByIDAndTenant for tenant-scoped role verification (C-4).
	roleRepo.On("GetByIDAndTenant", mock.Anything, mock.Anything, mock.Anything).Return(&models.Role{ID: uuid.New(), Name: "role"}, nil)
	// Wildcard: SetUserRoles checks caller priority when assignedBy != nil.
	roleRepo.On("GetMaxPriorityForUser", mock.Anything, mock.Anything, mock.Anything).Return(100, nil)
	tokenSvc := new(mockUserTokenSvc)
	// Wildcard: SetPassword always revokes OAuth tokens after updating.
	tokenSvc.On("RevokeAllUserOAuthTokens", mock.Anything, mock.Anything, mock.Anything).Return(nil)
	auditSvc := new(mockUserAuditSvc)
	auditSvc.On("LogUserAction", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return()
	svc := services.NewUserService(cfg, userRepo, roleRepo, tokenSvc, auditSvc)
	svc.SetRealmResolver(&mockUserServiceRealmResolver{})
	return svc
}

// makeUser constructs a test *models.User seeded in the given tenant.
func makeTestUser(tenantID uuid.UUID) *models.User {
	return &models.User{
		ID:               uuid.New(),
		TenantID:         tenantID,
		Username:         "alice",
		Email:            "alice@example.com",
		IsActive:         true,
		ActivationStatus: "active",
		CreatedAt:        time.Now(),
		UpdatedAt:        time.Now(),
	}
}

func makeAdminCtx(tenantID uuid.UUID) *models.CurrentUser {
	return &models.CurrentUser{
		ID:              uuid.New(),
		TenantID:        tenantID,
		Username:        "admin",
		Roles:           []string{"admin"},
		Permissions:     []string{"*"},
		IsPlatformAdmin: false,
	}
}

// setupUserHandlerRouter creates a gin router with UserHandler routes.
func setupUserHandlerRouter(h *UserHandler, tenantID uuid.UUID, cu *models.CurrentUser) *gin.Engine {
	router := gin.New()
	inject := func(c *gin.Context) {
		c.Set("tenant_id", tenantID)
		c.Set("current_user", cu)
		if cu != nil {
			c.Set("user_id", cu.ID)
		}
		c.Next()
	}
	g := router.Group("/api/users", inject)
	g.GET("", h.List)
	g.POST("", h.Create)
	g.GET("/:id", h.GetByID)
	g.PUT("/:id", h.Update)
	g.DELETE("/:id", h.Delete)
	g.POST("/:id/lock", h.Lock)
	g.POST("/:id/unlock", h.Unlock)
	g.POST("/:id/set-password", h.SetPassword)
	g.GET("/:id/roles", h.GetRoles)
	g.PUT("/:id/roles", h.SetRoles)
	return router
}

func doRequest(router *gin.Engine, method, path, body string) *httptest.ResponseRecorder {
	var req *http.Request
	if body != "" {
		req = httptest.NewRequestWithContext(context.Background(), method, path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
	} else {
		req = httptest.NewRequestWithContext(context.Background(), method, path, nil)
	}
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	return w
}

func requireJSONErrorContains(t *testing.T, w *httptest.ResponseRecorder, status int, substr string) { //nolint:unparam // status is always 400 currently but kept for flexibility
	t.Helper()
	assert.Equal(t, status, w.Code, "unexpected status; body: %s", w.Body.String())
	var body map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body), "invalid JSON: %s", w.Body.String())
	errVal, ok := body["error"]
	require.True(t, ok, "missing 'error' field in: %s", w.Body.String())
	assert.Contains(t, strings.ToLower(fmt.Sprint(errVal)), strings.ToLower(substr))
}

// ---------------------------------------------------------------------------
// Tests: GET /api/users (List)
// ---------------------------------------------------------------------------

func TestUserHandler_List_ReturnsPaginatedList(t *testing.T) {
	tenantID := uuid.New()
	u := makeTestUser(tenantID)

	userRepo := new(mockUserServiceUserRepo)
	userRepo.On("List", mock.Anything, tenantID, 1, 20, "").
		Return([]models.User{*u}, int64(1), nil)
	// UserService.List calls GetUserRoles for each returned user
	userRepo.On("GetUserRoles", mock.Anything, u.ID).Return([]models.Role{}, nil)

	svc := newTestUserSvc(t, userRepo)
	h := NewUserHandler(svc)
	router := setupUserHandlerRouter(h, tenantID, makeAdminCtx(tenantID))

	w := doRequest(router, http.MethodGet, "/api/users", "")

	assert.Equal(t, http.StatusOK, w.Code)
	var resp map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Contains(t, resp, "users")
	total, ok := resp["total"].(float64)
	require.True(t, ok)
	assert.Equal(t, float64(1), total)
}

func TestUserHandler_List_EmptyResult(t *testing.T) {
	tenantID := uuid.New()

	userRepo := new(mockUserServiceUserRepo)
	userRepo.On("List", mock.Anything, tenantID, 1, 20, "").
		Return([]models.User{}, int64(0), nil)

	svc := newTestUserSvc(t, userRepo)
	h := NewUserHandler(svc)
	router := setupUserHandlerRouter(h, tenantID, makeAdminCtx(tenantID))

	w := doRequest(router, http.MethodGet, "/api/users", "")

	assert.Equal(t, http.StatusOK, w.Code)
	var resp map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	users, _ := resp["users"].([]interface{})
	assert.Len(t, users, 0)
}

func TestUserHandler_List_ServiceError_Returns500(t *testing.T) {
	tenantID := uuid.New()

	userRepo := new(mockUserServiceUserRepo)
	userRepo.On("List", mock.Anything, tenantID, 1, 20, "").
		Return(nil, int64(0), fmt.Errorf("db down"))

	svc := newTestUserSvc(t, userRepo)
	h := NewUserHandler(svc)
	router := setupUserHandlerRouter(h, tenantID, makeAdminCtx(tenantID))

	w := doRequest(router, http.MethodGet, "/api/users", "")

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestUserHandler_List_SearchParam(t *testing.T) {
	tenantID := uuid.New()

	userRepo := new(mockUserServiceUserRepo)
	userRepo.On("List", mock.Anything, tenantID, 1, 20, "alice").
		Return([]models.User{}, int64(0), nil)

	svc := newTestUserSvc(t, userRepo)
	h := NewUserHandler(svc)
	router := setupUserHandlerRouter(h, tenantID, makeAdminCtx(tenantID))

	w := doRequest(router, http.MethodGet, "/api/users?search=alice", "")

	assert.Equal(t, http.StatusOK, w.Code)
	userRepo.AssertExpectations(t)
}

// ---------------------------------------------------------------------------
// Tests: GET /api/users/:id (GetByID)
// ---------------------------------------------------------------------------

func TestUserHandler_GetByID_Found(t *testing.T) {
	tenantID := uuid.New()
	u := makeTestUser(tenantID)

	userRepo := new(mockUserServiceUserRepo)
	// validateUserTenantAccess calls GetByID (→ GetUserRoles + GetUserPermissions);
	// then the handler calls GetByID again (→ GetUserRoles + GetUserPermissions again)
	userRepo.On("GetByID", mock.Anything, u.ID).Return(u, nil)
	userRepo.On("GetUserRoles", mock.Anything, u.ID).Return([]models.Role{}, nil)
	userRepo.On("GetUserPermissions", mock.Anything, u.ID).Return([]models.Permission{}, nil)

	svc := newTestUserSvc(t, userRepo)
	h := NewUserHandler(svc)
	router := setupUserHandlerRouter(h, tenantID, makeAdminCtx(tenantID))

	w := doRequest(router, http.MethodGet, "/api/users/"+u.ID.String(), "")

	assert.Equal(t, http.StatusOK, w.Code)
	var resp map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, u.ID.String(), resp["id"])
}

func TestUserHandler_GetByID_NotFound(t *testing.T) {
	tenantID := uuid.New()
	targetID := uuid.New()

	userRepo := new(mockUserServiceUserRepo)
	userRepo.On("GetByID", mock.Anything, targetID).Return(nil, fmt.Errorf("user not found"))

	svc := newTestUserSvc(t, userRepo)
	h := NewUserHandler(svc)
	router := setupUserHandlerRouter(h, tenantID, makeAdminCtx(tenantID))

	w := doRequest(router, http.MethodGet, "/api/users/"+targetID.String(), "")

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestUserHandler_GetByID_InvalidUUID(t *testing.T) {
	tenantID := uuid.New()
	userRepo := new(mockUserServiceUserRepo)

	svc := newTestUserSvc(t, userRepo)
	h := NewUserHandler(svc)
	router := setupUserHandlerRouter(h, tenantID, makeAdminCtx(tenantID))

	w := doRequest(router, http.MethodGet, "/api/users/not-a-uuid", "")

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestUserHandler_GetByID_NoCurrentUser_Returns401(t *testing.T) {
	tenantID := uuid.New()
	u := makeTestUser(tenantID)
	userRepo := new(mockUserServiceUserRepo)

	svc := newTestUserSvc(t, userRepo)
	h := NewUserHandler(svc)
	// nil current user → 401
	router := setupUserHandlerRouter(h, tenantID, nil)

	w := doRequest(router, http.MethodGet, "/api/users/"+u.ID.String(), "")

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// ---------------------------------------------------------------------------
// Tests: IDOR prevention
// ---------------------------------------------------------------------------

func TestUserHandler_GetByID_IDORPrevention_DifferentTenant_Returns404(t *testing.T) {
	ownerTenant := uuid.New()
	attackerTenant := uuid.New()
	u := makeTestUser(ownerTenant)

	userRepo := new(mockUserServiceUserRepo)
	// validateUserTenantAccess fetches user (GetByID → GetUserRoles + GetUserPermissions) then detects tenant mismatch
	userRepo.On("GetByID", mock.Anything, u.ID).Return(u, nil)
	userRepo.On("GetUserRoles", mock.Anything, u.ID).Return([]models.Role{}, nil)
	userRepo.On("GetUserPermissions", mock.Anything, u.ID).Return([]models.Permission{}, nil)

	svc := newTestUserSvc(t, userRepo)
	h := NewUserHandler(svc)

	attacker := &models.CurrentUser{
		ID:              uuid.New(),
		TenantID:        attackerTenant,
		Username:        "attacker",
		IsPlatformAdmin: false,
	}
	router := setupUserHandlerRouter(h, attackerTenant, attacker)

	w := doRequest(router, http.MethodGet, "/api/users/"+u.ID.String(), "")

	// SECURITY: 404 prevents tenant enumeration (not 403)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestUserHandler_GetByID_PlatformAdmin_CanCrossTenantsAccess(t *testing.T) {
	ownerTenant := uuid.New()
	platformTenantID := uuid.MustParse(models.HexxlockInternalTenantID)
	u := makeTestUser(ownerTenant)

	userRepo := new(mockUserServiceUserRepo)
	// Platform admin bypass: validateUserTenantAccess returns early (no GetByID call there)
	// But the handler then calls GetByID directly → GetUserRoles + GetUserPermissions
	userRepo.On("GetByID", mock.Anything, u.ID).Return(u, nil)
	userRepo.On("GetUserRoles", mock.Anything, u.ID).Return([]models.Role{}, nil)
	userRepo.On("GetUserPermissions", mock.Anything, u.ID).Return([]models.Permission{}, nil)

	svc := newTestUserSvc(t, userRepo)
	h := NewUserHandler(svc)

	platformAdmin := &models.CurrentUser{
		ID:              uuid.New(),
		TenantID:        platformTenantID,
		Username:        "platform-admin",
		Roles:           []string{"platform_admin"},
		IsPlatformAdmin: true,
	}
	router := setupUserHandlerRouter(h, platformTenantID, platformAdmin)

	w := doRequest(router, http.MethodGet, "/api/users/"+u.ID.String(), "")

	assert.Equal(t, http.StatusOK, w.Code)
}

// ---------------------------------------------------------------------------
// Tests: POST /api/users (Create)
// ---------------------------------------------------------------------------

func TestUserHandler_Create_ValidRequest_Returns201(t *testing.T) {
	tenantID := uuid.New()

	userRepo := new(mockUserServiceUserRepo)
	// UserService.Create: (nil, nil) means "no existing record" — any error is treated as a DB failure.
	userRepo.On("GetByUsername", mock.Anything, tenantID, "newuser").Return(nil, nil)
	userRepo.On("GetByEmail", mock.Anything, tenantID, "new@example.com").Return(nil, nil)
	userRepo.On("Create", mock.Anything, mock.AnythingOfType("*models.User")).Return(nil)
	// UserService.Create fetches roles/permissions to build the response.
	userRepo.On("GetUserRoles", mock.Anything, mock.Anything).Return([]models.Role{}, nil)
	userRepo.On("GetUserPermissions", mock.Anything, mock.Anything).Return([]models.Permission{}, nil)

	svc := newTestUserSvc(t, userRepo)
	h := NewUserHandler(svc)
	router := setupUserHandlerRouter(h, tenantID, makeAdminCtx(tenantID))

	body := fmt.Sprintf(`{"tenant_id":%q,"username":"newuser","email":"new@example.com"}`, tenantID.String())
	w := doRequest(router, http.MethodPost, "/api/users", body)

	assert.Equal(t, http.StatusCreated, w.Code)
}

func TestUserHandler_Create_InvalidJSON_Returns400(t *testing.T) {
	tenantID := uuid.New()
	userRepo := new(mockUserServiceUserRepo)

	svc := newTestUserSvc(t, userRepo)
	h := NewUserHandler(svc)
	router := setupUserHandlerRouter(h, tenantID, makeAdminCtx(tenantID))

	w := doRequest(router, http.MethodPost, "/api/users", `{bad json`)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestUserHandler_Create_MissingUsername_Returns400(t *testing.T) {
	tenantID := uuid.New()
	userRepo := new(mockUserServiceUserRepo)

	svc := newTestUserSvc(t, userRepo)
	h := NewUserHandler(svc)
	router := setupUserHandlerRouter(h, tenantID, makeAdminCtx(tenantID))

	// username is required (min=3)
	body := fmt.Sprintf(`{"tenant_id":%q,"email":"x@example.com"}`, tenantID.String())
	w := doRequest(router, http.MethodPost, "/api/users", body)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestUserHandler_Create_DuplicateUsername_Returns400(t *testing.T) {
	tenantID := uuid.New()
	existing := &models.User{ID: uuid.New(), TenantID: tenantID, Username: "dup"}

	userRepo := new(mockUserServiceUserRepo)
	userRepo.On("GetByUsername", mock.Anything, tenantID, "dup").Return(existing, nil)
	userRepo.On("GetByEmail", mock.Anything, tenantID, mock.AnythingOfType("string")).Return(nil, fmt.Errorf("not found"))

	svc := newTestUserSvc(t, userRepo)
	h := NewUserHandler(svc)
	router := setupUserHandlerRouter(h, tenantID, makeAdminCtx(tenantID))

	body := fmt.Sprintf(`{"tenant_id":%q,"username":"dup","email":"dup@example.com"}`, tenantID.String())
	w := doRequest(router, http.MethodPost, "/api/users", body)

	requireJSONErrorContains(t, w, http.StatusBadRequest, "already exists")
}

func TestUserHandler_Create_DuplicateEmail_Returns400(t *testing.T) {
	tenantID := uuid.New()
	existing := &models.User{ID: uuid.New(), TenantID: tenantID, Email: "dup@example.com"}

	userRepo := new(mockUserServiceUserRepo)
	// Username is free — (nil, nil) means "not found" without a DB error.
	userRepo.On("GetByUsername", mock.Anything, tenantID, "newuser").Return(nil, nil)
	// Email is taken — returning the existing user triggers the "email already exists" error.
	userRepo.On("GetByEmail", mock.Anything, tenantID, "dup@example.com").Return(existing, nil)

	svc := newTestUserSvc(t, userRepo)
	h := NewUserHandler(svc)
	router := setupUserHandlerRouter(h, tenantID, makeAdminCtx(tenantID))

	body := fmt.Sprintf(`{"tenant_id":%q,"username":"newuser","email":"dup@example.com"}`, tenantID.String())
	w := doRequest(router, http.MethodPost, "/api/users", body)

	requireJSONErrorContains(t, w, http.StatusBadRequest, "already exists")
}

// ---------------------------------------------------------------------------
// Tests: PUT /api/users/:id (Update)
// ---------------------------------------------------------------------------

func TestUserHandler_Update_ValidRequest_Returns200(t *testing.T) {
	tenantID := uuid.New()
	u := makeTestUser(tenantID)

	userRepo := new(mockUserServiceUserRepo)
	// validateUserTenantAccess calls GetByID → GetUserRoles + GetUserPermissions
	// service.Update calls GetByID again (no GetUserRoles after that)
	userRepo.On("GetByID", mock.Anything, u.ID).Return(u, nil)
	userRepo.On("GetUserRoles", mock.Anything, u.ID).Return([]models.Role{}, nil)
	userRepo.On("GetUserPermissions", mock.Anything, u.ID).Return([]models.Permission{}, nil)
	userRepo.On("Update", mock.Anything, mock.AnythingOfType("*models.User")).Return(nil)

	svc := newTestUserSvc(t, userRepo)
	h := NewUserHandler(svc)
	router := setupUserHandlerRouter(h, tenantID, makeAdminCtx(tenantID))

	firstName := "Updated"
	body, _ := json.Marshal(models.UpdateUserRequest{FirstName: &firstName})
	w := doRequest(router, http.MethodPut, "/api/users/"+u.ID.String(), string(body))

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestUserHandler_Update_UserNotFound_Returns404(t *testing.T) {
	tenantID := uuid.New()
	targetID := uuid.New()

	userRepo := new(mockUserServiceUserRepo)
	userRepo.On("GetByID", mock.Anything, targetID).Return(nil, fmt.Errorf("not found"))

	svc := newTestUserSvc(t, userRepo)
	h := NewUserHandler(svc)
	router := setupUserHandlerRouter(h, tenantID, makeAdminCtx(tenantID))

	body, _ := json.Marshal(models.UpdateUserRequest{})
	w := doRequest(router, http.MethodPut, "/api/users/"+targetID.String(), string(body))

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestUserHandler_Update_IDORPrevention_Returns404(t *testing.T) {
	ownerTenant := uuid.New()
	attackerTenant := uuid.New()
	u := makeTestUser(ownerTenant)

	userRepo := new(mockUserServiceUserRepo)
	// validateUserTenantAccess → GetByID → GetUserRoles + GetUserPermissions → detects tenant mismatch
	userRepo.On("GetByID", mock.Anything, u.ID).Return(u, nil)
	userRepo.On("GetUserRoles", mock.Anything, u.ID).Return([]models.Role{}, nil)
	userRepo.On("GetUserPermissions", mock.Anything, u.ID).Return([]models.Permission{}, nil)

	svc := newTestUserSvc(t, userRepo)
	h := NewUserHandler(svc)

	attacker := &models.CurrentUser{
		ID:              uuid.New(),
		TenantID:        attackerTenant,
		Username:        "attacker",
		IsPlatformAdmin: false,
	}
	router := setupUserHandlerRouter(h, attackerTenant, attacker)

	firstName := "hacked"
	body, _ := json.Marshal(models.UpdateUserRequest{FirstName: &firstName})
	w := doRequest(router, http.MethodPut, "/api/users/"+u.ID.String(), string(body))

	assert.Equal(t, http.StatusNotFound, w.Code)
}

// ---------------------------------------------------------------------------
// Tests: DELETE /api/users/:id (Delete)
// ---------------------------------------------------------------------------

func TestUserHandler_Delete_Returns200(t *testing.T) {
	tenantID := uuid.New()
	u := makeTestUser(tenantID)

	userRepo := new(mockUserServiceUserRepo)
	// validateUserTenantAccess → GetByID → GetUserRoles + GetUserPermissions
	// service.Delete then calls GetByID again (no role loading)
	userRepo.On("GetByID", mock.Anything, u.ID).Return(u, nil)
	userRepo.On("GetUserRoles", mock.Anything, u.ID).Return([]models.Role{}, nil)
	userRepo.On("GetUserPermissions", mock.Anything, u.ID).Return([]models.Permission{}, nil)
	userRepo.On("Delete", mock.Anything, u.ID).Return(nil)

	svc := newTestUserSvc(t, userRepo)
	h := NewUserHandler(svc)
	router := setupUserHandlerRouter(h, tenantID, makeAdminCtx(tenantID))

	w := doRequest(router, http.MethodDelete, "/api/users/"+u.ID.String(), "")

	assert.Equal(t, http.StatusOK, w.Code)
	var resp map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Contains(t, strings.ToLower(fmt.Sprint(resp["message"])), "deleted")
}

func TestUserHandler_Delete_NotFound_Returns404(t *testing.T) {
	tenantID := uuid.New()
	targetID := uuid.New()

	userRepo := new(mockUserServiceUserRepo)
	userRepo.On("GetByID", mock.Anything, targetID).Return(nil, fmt.Errorf("not found"))

	svc := newTestUserSvc(t, userRepo)
	h := NewUserHandler(svc)
	router := setupUserHandlerRouter(h, tenantID, makeAdminCtx(tenantID))

	w := doRequest(router, http.MethodDelete, "/api/users/"+targetID.String(), "")

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestUserHandler_Delete_IDORPrevention_Returns404(t *testing.T) {
	ownerTenant := uuid.New()
	attackerTenant := uuid.New()
	u := makeTestUser(ownerTenant)

	userRepo := new(mockUserServiceUserRepo)
	// validateUserTenantAccess → GetByID → GetUserRoles + GetUserPermissions → detects tenant mismatch
	userRepo.On("GetByID", mock.Anything, u.ID).Return(u, nil)
	userRepo.On("GetUserRoles", mock.Anything, u.ID).Return([]models.Role{}, nil)
	userRepo.On("GetUserPermissions", mock.Anything, u.ID).Return([]models.Permission{}, nil)

	svc := newTestUserSvc(t, userRepo)
	h := NewUserHandler(svc)

	attacker := &models.CurrentUser{
		ID:              uuid.New(),
		TenantID:        attackerTenant,
		Username:        "attacker",
		IsPlatformAdmin: false,
	}
	router := setupUserHandlerRouter(h, attackerTenant, attacker)

	w := doRequest(router, http.MethodDelete, "/api/users/"+u.ID.String(), "")

	assert.Equal(t, http.StatusNotFound, w.Code)
}

// ---------------------------------------------------------------------------
// Tests: POST /api/users/:id/lock (Lock)
// ---------------------------------------------------------------------------

func TestUserHandler_Lock_Returns200(t *testing.T) {
	tenantID := uuid.New()
	u := makeTestUser(tenantID)

	userRepo := new(mockUserServiceUserRepo)
	// validateUserTenantAccess → GetByID → GetUserRoles + GetUserPermissions
	// service.Lock then calls GetByID again (no role loading)
	userRepo.On("GetByID", mock.Anything, u.ID).Return(u, nil)
	userRepo.On("GetUserRoles", mock.Anything, u.ID).Return([]models.Role{}, nil)
	userRepo.On("GetUserPermissions", mock.Anything, u.ID).Return([]models.Permission{}, nil)
	userRepo.On("Update", mock.Anything, mock.AnythingOfType("*models.User")).Return(nil)

	svc := newTestUserSvc(t, userRepo)
	h := NewUserHandler(svc)
	router := setupUserHandlerRouter(h, tenantID, makeAdminCtx(tenantID))

	body := `{"reason":"policy violation"}`
	w := doRequest(router, http.MethodPost, "/api/users/"+u.ID.String()+"/lock", body)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Contains(t, strings.ToLower(fmt.Sprint(resp["message"])), "lock")
}

func TestUserHandler_Lock_MissingReason_Returns400(t *testing.T) {
	tenantID := uuid.New()
	u := makeTestUser(tenantID)

	userRepo := new(mockUserServiceUserRepo)
	// validateUserTenantAccess → GetByID → GetUserRoles + GetUserPermissions
	userRepo.On("GetByID", mock.Anything, u.ID).Return(u, nil)
	userRepo.On("GetUserRoles", mock.Anything, u.ID).Return([]models.Role{}, nil)
	userRepo.On("GetUserPermissions", mock.Anything, u.ID).Return([]models.Permission{}, nil)

	svc := newTestUserSvc(t, userRepo)
	h := NewUserHandler(svc)
	router := setupUserHandlerRouter(h, tenantID, makeAdminCtx(tenantID))

	// reason is required
	w := doRequest(router, http.MethodPost, "/api/users/"+u.ID.String()+"/lock", `{}`)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestUserHandler_Lock_UserNotFound_Returns404(t *testing.T) {
	tenantID := uuid.New()
	targetID := uuid.New()

	userRepo := new(mockUserServiceUserRepo)
	userRepo.On("GetByID", mock.Anything, targetID).Return(nil, fmt.Errorf("not found"))

	svc := newTestUserSvc(t, userRepo)
	h := NewUserHandler(svc)
	router := setupUserHandlerRouter(h, tenantID, makeAdminCtx(tenantID))

	body := `{"reason":"test"}`
	w := doRequest(router, http.MethodPost, "/api/users/"+targetID.String()+"/lock", body)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

// ---------------------------------------------------------------------------
// Tests: POST /api/users/:id/unlock (Unlock)
// ---------------------------------------------------------------------------

func TestUserHandler_Unlock_Returns200(t *testing.T) {
	tenantID := uuid.New()
	u := makeTestUser(tenantID)
	u.IsLocked = true

	userRepo := new(mockUserServiceUserRepo)
	// validateUserTenantAccess → GetByID → GetUserRoles + GetUserPermissions
	userRepo.On("GetByID", mock.Anything, u.ID).Return(u, nil)
	userRepo.On("GetUserRoles", mock.Anything, u.ID).Return([]models.Role{}, nil)
	userRepo.On("GetUserPermissions", mock.Anything, u.ID).Return([]models.Permission{}, nil)
	userRepo.On("UnlockUser", mock.Anything, u.ID).Return(nil)

	svc := newTestUserSvc(t, userRepo)
	h := NewUserHandler(svc)
	router := setupUserHandlerRouter(h, tenantID, makeAdminCtx(tenantID))

	w := doRequest(router, http.MethodPost, "/api/users/"+u.ID.String()+"/unlock", "")

	assert.Equal(t, http.StatusOK, w.Code)
	var resp map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Contains(t, strings.ToLower(fmt.Sprint(resp["message"])), "unlock")
}

func TestUserHandler_Unlock_UserNotFound_Returns404(t *testing.T) {
	tenantID := uuid.New()
	targetID := uuid.New()

	userRepo := new(mockUserServiceUserRepo)
	userRepo.On("GetByID", mock.Anything, targetID).Return(nil, fmt.Errorf("not found"))

	svc := newTestUserSvc(t, userRepo)
	h := NewUserHandler(svc)
	router := setupUserHandlerRouter(h, tenantID, makeAdminCtx(tenantID))

	w := doRequest(router, http.MethodPost, "/api/users/"+targetID.String()+"/unlock", "")

	assert.Equal(t, http.StatusNotFound, w.Code)
}

// ---------------------------------------------------------------------------
// Tests: POST /api/users/:id/set-password (SetPassword)
// ---------------------------------------------------------------------------

func TestUserHandler_SetPassword_Returns200(t *testing.T) {
	tenantID := uuid.New()
	u := makeTestUser(tenantID)

	userRepo := new(mockUserServiceUserRepo)
	// validateUserTenantAccess → GetByID → GetUserRoles + GetUserPermissions
	// service.SetPassword then calls GetByID again (no role loading)
	userRepo.On("GetByID", mock.Anything, u.ID).Return(u, nil)
	userRepo.On("GetUserRoles", mock.Anything, u.ID).Return([]models.Role{}, nil)
	userRepo.On("GetUserPermissions", mock.Anything, u.ID).Return([]models.Permission{}, nil)
	userRepo.On("Update", mock.Anything, mock.AnythingOfType("*models.User")).Return(nil)

	svc := newTestUserSvc(t, userRepo)
	h := NewUserHandler(svc)
	router := setupUserHandlerRouter(h, tenantID, makeAdminCtx(tenantID))

	body := `{"password":"newpassword1","must_change":false}`
	w := doRequest(router, http.MethodPost, "/api/users/"+u.ID.String()+"/set-password", body)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestUserHandler_SetPassword_TooShort_Returns400(t *testing.T) {
	tenantID := uuid.New()
	u := makeTestUser(tenantID)

	userRepo := new(mockUserServiceUserRepo)
	// validateUserTenantAccess → GetByID → GetUserRoles + GetUserPermissions
	userRepo.On("GetByID", mock.Anything, u.ID).Return(u, nil)
	userRepo.On("GetUserRoles", mock.Anything, u.ID).Return([]models.Role{}, nil)
	userRepo.On("GetUserPermissions", mock.Anything, u.ID).Return([]models.Permission{}, nil)

	svc := newTestUserSvc(t, userRepo)
	h := NewUserHandler(svc)
	router := setupUserHandlerRouter(h, tenantID, makeAdminCtx(tenantID))

	// password binding requires min=8
	body := `{"password":"short","must_change":false}`
	w := doRequest(router, http.MethodPost, "/api/users/"+u.ID.String()+"/set-password", body)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestUserHandler_SetPassword_UserNotFound_Returns404(t *testing.T) {
	tenantID := uuid.New()
	targetID := uuid.New()

	userRepo := new(mockUserServiceUserRepo)
	userRepo.On("GetByID", mock.Anything, targetID).Return(nil, fmt.Errorf("not found"))

	svc := newTestUserSvc(t, userRepo)
	h := NewUserHandler(svc)
	router := setupUserHandlerRouter(h, tenantID, makeAdminCtx(tenantID))

	body := `{"password":"newpassword1","must_change":false}`
	w := doRequest(router, http.MethodPost, "/api/users/"+targetID.String()+"/set-password", body)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

// ---------------------------------------------------------------------------
// Tests: GET /api/users/:id/roles (GetRoles)
// ---------------------------------------------------------------------------

func TestUserHandler_GetRoles_Returns200(t *testing.T) {
	tenantID := uuid.New()
	u := makeTestUser(tenantID)

	userRepo := new(mockUserServiceUserRepo)
	// validateUserTenantAccess → GetByID → GetUserRoles + GetUserPermissions
	// handler then calls GetUserRoles directly on the service
	userRepo.On("GetByID", mock.Anything, u.ID).Return(u, nil)
	userRepo.On("GetUserRoles", mock.Anything, u.ID).Return([]models.Role{}, nil)
	userRepo.On("GetUserPermissions", mock.Anything, u.ID).Return([]models.Permission{}, nil)

	svc := newTestUserSvc(t, userRepo)
	h := NewUserHandler(svc)
	router := setupUserHandlerRouter(h, tenantID, makeAdminCtx(tenantID))

	w := doRequest(router, http.MethodGet, "/api/users/"+u.ID.String()+"/roles", "")

	assert.Equal(t, http.StatusOK, w.Code)
	var resp map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Contains(t, resp, "roles")
}

// ---------------------------------------------------------------------------
// Tests: PUT /api/users/:id/roles (SetRoles)
// ---------------------------------------------------------------------------

func TestUserHandler_SetRoles_Returns200(t *testing.T) {
	tenantID := uuid.New()
	u := makeTestUser(tenantID)
	roleID := uuid.New()

	userRepo := new(mockUserServiceUserRepo)
	// validateUserTenantAccess → GetByID → GetUserRoles + GetUserPermissions
	userRepo.On("GetByID", mock.Anything, u.ID).Return(u, nil)
	userRepo.On("GetUserRoles", mock.Anything, u.ID).Return([]models.Role{}, nil)
	userRepo.On("GetUserPermissions", mock.Anything, u.ID).Return([]models.Permission{}, nil)
	userRepo.On("AssignRoles", mock.Anything, u.ID, mock.Anything, mock.Anything).Return(nil)

	svc := newTestUserSvc(t, userRepo)
	h := NewUserHandler(svc)
	router := setupUserHandlerRouter(h, tenantID, makeAdminCtx(tenantID))

	body := fmt.Sprintf(`{"role_ids":[%q]}`, roleID.String())
	w := doRequest(router, http.MethodPut, "/api/users/"+u.ID.String()+"/roles", body)

	assert.Equal(t, http.StatusOK, w.Code)
}
