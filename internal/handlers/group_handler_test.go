// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
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
)

const testGroupBodyEngineering = `{"name":"engineering"}`

// ---------------------------------------------------------------------------
// Mock: groupServiceGroupRepo
// ---------------------------------------------------------------------------

type mockGroupHandlerGroupRepo struct {
	mock.Mock
}

func (m *mockGroupHandlerGroupRepo) GetByName(ctx context.Context, tenantID uuid.UUID, name string) (*models.Group, error) {
	args := m.Called(ctx, tenantID, name)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.Group), args.Error(1)
}

func (m *mockGroupHandlerGroupRepo) GetByID(ctx context.Context, id uuid.UUID) (*models.Group, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.Group), args.Error(1)
}

func (m *mockGroupHandlerGroupRepo) Create(ctx context.Context, group *models.Group) error {
	args := m.Called(ctx, group)
	return args.Error(0)
}

func (m *mockGroupHandlerGroupRepo) AssignRole(ctx context.Context, groupID, roleID uuid.UUID, assignedBy *uuid.UUID) error {
	args := m.Called(ctx, groupID, roleID, assignedBy)
	return args.Error(0)
}

func (m *mockGroupHandlerGroupRepo) AddMember(ctx context.Context, groupID, userID uuid.UUID, addedBy *uuid.UUID) error {
	args := m.Called(ctx, groupID, userID, addedBy)
	return args.Error(0)
}

func (m *mockGroupHandlerGroupRepo) Update(ctx context.Context, group *models.Group) error {
	args := m.Called(ctx, group)
	return args.Error(0)
}

func (m *mockGroupHandlerGroupRepo) Delete(ctx context.Context, id uuid.UUID) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *mockGroupHandlerGroupRepo) GetRoles(ctx context.Context, groupID uuid.UUID) ([]*models.Role, error) {
	args := m.Called(ctx, groupID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.Role), args.Error(1)
}

func (m *mockGroupHandlerGroupRepo) GetChildGroups(ctx context.Context, parentID uuid.UUID) ([]*models.Group, error) {
	args := m.Called(ctx, parentID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.Group), args.Error(1)
}

func (m *mockGroupHandlerGroupRepo) List(ctx context.Context, tenantID uuid.UUID, page, pageSize int, search string) ([]*models.Group, int, error) {
	args := m.Called(ctx, tenantID, page, pageSize, search)
	if args.Get(0) == nil {
		return nil, args.Int(1), args.Error(2)
	}
	return args.Get(0).([]*models.Group), args.Int(1), args.Error(2)
}

func (m *mockGroupHandlerGroupRepo) GetMembers(ctx context.Context, groupID uuid.UUID, page, pageSize int) ([]*models.GroupMember, int, error) {
	args := m.Called(ctx, groupID, page, pageSize)
	if args.Get(0) == nil {
		return nil, args.Int(1), args.Error(2)
	}
	return args.Get(0).([]*models.GroupMember), args.Int(1), args.Error(2)
}

func (m *mockGroupHandlerGroupRepo) GetUserGroups(ctx context.Context, userID uuid.UUID) ([]*models.Group, error) {
	args := m.Called(ctx, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.Group), args.Error(1)
}

func (m *mockGroupHandlerGroupRepo) RemoveMember(ctx context.Context, groupID, userID uuid.UUID) error {
	args := m.Called(ctx, groupID, userID)
	return args.Error(0)
}

func (m *mockGroupHandlerGroupRepo) RemoveRole(ctx context.Context, groupID, roleID uuid.UUID) error {
	args := m.Called(ctx, groupID, roleID)
	return args.Error(0)
}

func (m *mockGroupHandlerGroupRepo) GetUserEffectiveRoles(ctx context.Context, userID uuid.UUID) ([]*models.EffectiveRole, error) {
	args := m.Called(ctx, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.EffectiveRole), args.Error(1)
}

func (m *mockGroupHandlerGroupRepo) GetRootGroups(ctx context.Context, tenantID uuid.UUID) ([]*models.Group, error) {
	args := m.Called(ctx, tenantID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.Group), args.Error(1)
}

// ---------------------------------------------------------------------------
// Mock: groupServiceUserRepo
// ---------------------------------------------------------------------------

type mockGroupHandlerUserRepo struct {
	mock.Mock
}

func (m *mockGroupHandlerUserRepo) GetByID(ctx context.Context, id uuid.UUID) (*models.User, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.User), args.Error(1)
}

// ---------------------------------------------------------------------------
// Mock: groupServiceRoleRepo
// ---------------------------------------------------------------------------

type mockGroupHandlerRoleRepo struct {
	mock.Mock
}

func (m *mockGroupHandlerRoleRepo) GetByID(ctx context.Context, id uuid.UUID) (*models.Role, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.Role), args.Error(1)
}

// ---------------------------------------------------------------------------
// Test setup helpers
// ---------------------------------------------------------------------------

func newTestGroupSvc(
	groupRepo *mockGroupHandlerGroupRepo,
	userRepo *mockGroupHandlerUserRepo,
	roleRepo *mockGroupHandlerRoleRepo,
) *services.GroupService {
	return services.NewGroupService(groupRepo, userRepo, roleRepo)
}

func makeTestGroup(tenantID uuid.UUID, isSystem bool) *models.Group { //nolint:unparam // isSystem is kept for future test flexibility
	return &models.Group{
		ID:        uuid.New(),
		TenantID:  tenantID,
		Name:      "engineering",
		IsSystem:  isSystem,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
}

func setupGroupHandlerRouter(h *GroupHandler, tenantID uuid.UUID, cu *models.CurrentUser) *gin.Engine {
	router := gin.New()
	inject := func(c *gin.Context) {
		c.Set("tenant_id", tenantID)
		c.Set("current_user", cu)
		if cu != nil {
			c.Set("user_id", cu.ID)
		}
		c.Next()
	}
	g := router.Group("/api/groups", inject)
	g.GET("", h.ListGroups)
	g.POST("", h.CreateGroup)
	g.GET("/:id", h.GetGroup)
	g.PUT("/:id", h.UpdateGroup)
	g.DELETE("/:id", h.DeleteGroup)
	g.GET("/:id/members", h.GetMembers)
	g.POST("/:id/members", h.AddMembers)
	g.DELETE("/:id/members", h.RemoveMembers)
	g.GET("/:id/roles", h.GetGroupRoles)
	g.POST("/:id/roles", h.AssignRoles)
	g.DELETE("/:id/roles", h.RemoveRoles)
	g.PUT("/:id/roles", h.SetRoles)

	// user group endpoints
	u := router.Group("/api/users", inject)
	u.GET("/:id/groups", h.GetUserGroups)
	u.GET("/:id/effective-roles", h.GetUserEffectiveRoles)

	return router
}

// ---------------------------------------------------------------------------
// Tests: GET /api/groups (ListGroups)
// ---------------------------------------------------------------------------

func TestGroupHandler_ListGroups_ReturnsPaginatedGroups(t *testing.T) {
	tenantID := uuid.New()
	g := makeTestGroup(tenantID, false)

	groupRepo := new(mockGroupHandlerGroupRepo)
	userRepo := new(mockGroupHandlerUserRepo)
	roleRepo := new(mockGroupHandlerRoleRepo)
	groupRepo.On("List", mock.Anything, tenantID, 1, 20, "").Return([]*models.Group{g}, 1, nil)

	svc := newTestGroupSvc(groupRepo, userRepo, roleRepo)
	h := NewGroupHandler(svc, nil) // userService nil (not used in ListGroups)
	router := setupGroupHandlerRouter(h, tenantID, makeAdminCtx(tenantID))

	w := doRequest(router, http.MethodGet, "/api/groups", "")

	assert.Equal(t, http.StatusOK, w.Code)
	var resp map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Contains(t, resp, "groups")
	assert.Equal(t, float64(1), resp["total"])
}

func TestGroupHandler_ListGroups_EmptyList(t *testing.T) {
	tenantID := uuid.New()

	groupRepo := new(mockGroupHandlerGroupRepo)
	userRepo := new(mockGroupHandlerUserRepo)
	roleRepo := new(mockGroupHandlerRoleRepo)
	groupRepo.On("List", mock.Anything, tenantID, 1, 20, "").Return([]*models.Group{}, 0, nil)

	svc := newTestGroupSvc(groupRepo, userRepo, roleRepo)
	h := NewGroupHandler(svc, nil)
	router := setupGroupHandlerRouter(h, tenantID, makeAdminCtx(tenantID))

	w := doRequest(router, http.MethodGet, "/api/groups", "")

	assert.Equal(t, http.StatusOK, w.Code)
	var resp map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	groups, _ := resp["groups"].([]interface{})
	assert.Len(t, groups, 0)
}

func TestGroupHandler_ListGroups_ServiceError_Returns500(t *testing.T) {
	tenantID := uuid.New()

	groupRepo := new(mockGroupHandlerGroupRepo)
	userRepo := new(mockGroupHandlerUserRepo)
	roleRepo := new(mockGroupHandlerRoleRepo)
	groupRepo.On("List", mock.Anything, tenantID, 1, 20, "").Return(nil, 0, fmt.Errorf("db error"))

	svc := newTestGroupSvc(groupRepo, userRepo, roleRepo)
	h := NewGroupHandler(svc, nil)
	router := setupGroupHandlerRouter(h, tenantID, makeAdminCtx(tenantID))

	w := doRequest(router, http.MethodGet, "/api/groups", "")

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// ---------------------------------------------------------------------------
// Tests: GET /api/groups/:id (GetGroup)
// ---------------------------------------------------------------------------

func TestGroupHandler_GetGroup_Found(t *testing.T) {
	tenantID := uuid.New()
	g := makeTestGroup(tenantID, false)

	groupRepo := new(mockGroupHandlerGroupRepo)
	userRepo := new(mockGroupHandlerUserRepo)
	roleRepo := new(mockGroupHandlerRoleRepo)
	// validateGroupTenantAccess calls GetByID, then handler calls GetGroup which calls GetByID + GetRoles
	groupRepo.On("GetByID", mock.Anything, g.ID).Return(g, nil)
	groupRepo.On("GetRoles", mock.Anything, g.ID).Return([]*models.Role{}, nil)

	svc := newTestGroupSvc(groupRepo, userRepo, roleRepo)
	h := NewGroupHandler(svc, nil)
	router := setupGroupHandlerRouter(h, tenantID, makeAdminCtx(tenantID))

	w := doRequest(router, http.MethodGet, "/api/groups/"+g.ID.String(), "")

	assert.Equal(t, http.StatusOK, w.Code)
	var resp map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, g.ID.String(), resp["id"])
}

func TestGroupHandler_GetGroup_NotFound_Returns404(t *testing.T) {
	tenantID := uuid.New()
	targetID := uuid.New()

	groupRepo := new(mockGroupHandlerGroupRepo)
	userRepo := new(mockGroupHandlerUserRepo)
	roleRepo := new(mockGroupHandlerRoleRepo)
	groupRepo.On("GetByID", mock.Anything, targetID).Return(nil, fmt.Errorf("not found"))

	svc := newTestGroupSvc(groupRepo, userRepo, roleRepo)
	h := NewGroupHandler(svc, nil)
	router := setupGroupHandlerRouter(h, tenantID, makeAdminCtx(tenantID))

	w := doRequest(router, http.MethodGet, "/api/groups/"+targetID.String(), "")

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestGroupHandler_GetGroup_DifferentTenant_Returns404(t *testing.T) {
	myTenant := uuid.New()
	otherTenant := uuid.New()
	g := makeTestGroup(otherTenant, false)

	groupRepo := new(mockGroupHandlerGroupRepo)
	userRepo := new(mockGroupHandlerUserRepo)
	roleRepo := new(mockGroupHandlerRoleRepo)
	// validateGroupTenantAccess calls GetGroup which calls GetByID + GetRoles
	groupRepo.On("GetByID", mock.Anything, g.ID).Return(g, nil)
	groupRepo.On("GetRoles", mock.Anything, g.ID).Return([]*models.Role{}, nil)

	svc := newTestGroupSvc(groupRepo, userRepo, roleRepo)
	h := NewGroupHandler(svc, nil)
	// inject myTenant so validation fails tenant check
	router := setupGroupHandlerRouter(h, myTenant, makeAdminCtx(myTenant))

	w := doRequest(router, http.MethodGet, "/api/groups/"+g.ID.String(), "")

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestGroupHandler_GetGroup_InvalidUUID_Returns400(t *testing.T) {
	tenantID := uuid.New()
	groupRepo := new(mockGroupHandlerGroupRepo)
	userRepo := new(mockGroupHandlerUserRepo)
	roleRepo := new(mockGroupHandlerRoleRepo)

	svc := newTestGroupSvc(groupRepo, userRepo, roleRepo)
	h := NewGroupHandler(svc, nil)
	router := setupGroupHandlerRouter(h, tenantID, makeAdminCtx(tenantID))

	w := doRequest(router, http.MethodGet, "/api/groups/not-a-uuid", "")

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ---------------------------------------------------------------------------
// Tests: POST /api/groups (CreateGroup)
// ---------------------------------------------------------------------------

func TestGroupHandler_CreateGroup_ValidRequest_Returns201(t *testing.T) {
	tenantID := uuid.New()

	groupRepo := new(mockGroupHandlerGroupRepo)
	userRepo := new(mockGroupHandlerUserRepo)
	roleRepo := new(mockGroupHandlerRoleRepo)
	// No duplicate name
	groupRepo.On("GetByName", mock.Anything, tenantID, "engineering").Return(nil, fmt.Errorf("not found"))
	createdGroup := makeTestGroup(tenantID, false)
	groupRepo.On("Create", mock.Anything, mock.AnythingOfType("*models.Group")).Return(nil)
	groupRepo.On("GetByID", mock.Anything, mock.AnythingOfType("uuid.UUID")).Return(createdGroup, nil)

	svc := newTestGroupSvc(groupRepo, userRepo, roleRepo)
	h := NewGroupHandler(svc, nil)
	router := setupGroupHandlerRouter(h, tenantID, makeAdminCtx(tenantID))

	body := testGroupBodyEngineering
	w := doRequest(router, http.MethodPost, "/api/groups", body)

	assert.Equal(t, http.StatusCreated, w.Code)
}

func TestGroupHandler_CreateGroup_InvalidJSON_Returns400(t *testing.T) {
	tenantID := uuid.New()
	groupRepo := new(mockGroupHandlerGroupRepo)
	userRepo := new(mockGroupHandlerUserRepo)
	roleRepo := new(mockGroupHandlerRoleRepo)

	svc := newTestGroupSvc(groupRepo, userRepo, roleRepo)
	h := NewGroupHandler(svc, nil)
	router := setupGroupHandlerRouter(h, tenantID, makeAdminCtx(tenantID))

	w := doRequest(router, http.MethodPost, "/api/groups", `{invalid}`)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestGroupHandler_CreateGroup_MissingName_Returns400(t *testing.T) {
	tenantID := uuid.New()
	groupRepo := new(mockGroupHandlerGroupRepo)
	userRepo := new(mockGroupHandlerUserRepo)
	roleRepo := new(mockGroupHandlerRoleRepo)

	svc := newTestGroupSvc(groupRepo, userRepo, roleRepo)
	h := NewGroupHandler(svc, nil)
	router := setupGroupHandlerRouter(h, tenantID, makeAdminCtx(tenantID))

	// name is required (min=1)
	body := `{}`
	w := doRequest(router, http.MethodPost, "/api/groups", body)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestGroupHandler_CreateGroup_DuplicateName_Returns400(t *testing.T) {
	tenantID := uuid.New()
	existingGroup := makeTestGroup(tenantID, false)

	groupRepo := new(mockGroupHandlerGroupRepo)
	userRepo := new(mockGroupHandlerUserRepo)
	roleRepo := new(mockGroupHandlerRoleRepo)
	// Simulate name already exists
	groupRepo.On("GetByName", mock.Anything, tenantID, "engineering").Return(existingGroup, nil)

	svc := newTestGroupSvc(groupRepo, userRepo, roleRepo)
	h := NewGroupHandler(svc, nil)
	router := setupGroupHandlerRouter(h, tenantID, makeAdminCtx(tenantID))

	body := testGroupBodyEngineering
	w := doRequest(router, http.MethodPost, "/api/groups", body)

	requireJSONErrorContains(t, w, http.StatusBadRequest, "already exists")
}

func TestGroupHandler_CreateGroup_NoTenantID_Returns400(t *testing.T) {
	groupRepo := new(mockGroupHandlerGroupRepo)
	userRepo := new(mockGroupHandlerUserRepo)
	roleRepo := new(mockGroupHandlerRoleRepo)

	svc := newTestGroupSvc(groupRepo, userRepo, roleRepo)
	h := NewGroupHandler(svc, nil)

	// Router without tenant_id injection
	router := gin.New()
	router.POST("/api/groups", h.CreateGroup)

	body := testGroupBodyEngineering
	w := doRequest(router, http.MethodPost, "/api/groups", body)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ---------------------------------------------------------------------------
// Tests: PUT /api/groups/:id (UpdateGroup)
// ---------------------------------------------------------------------------

func TestGroupHandler_UpdateGroup_ValidRequest_Returns200(t *testing.T) {
	tenantID := uuid.New()
	g := makeTestGroup(tenantID, false)

	groupRepo := new(mockGroupHandlerGroupRepo)
	userRepo := new(mockGroupHandlerUserRepo)
	roleRepo := new(mockGroupHandlerRoleRepo)
	// validateGroupTenantAccess calls GetGroup (GetByID + GetRoles),
	// service UpdateGroup also calls GetByID and finally GetByID again on return
	groupRepo.On("GetByID", mock.Anything, g.ID).Return(g, nil)
	groupRepo.On("GetRoles", mock.Anything, g.ID).Return([]*models.Role{}, nil)
	// UpdateGroup name change: check uniqueness (GetByName returns not-found)
	groupRepo.On("GetByName", mock.Anything, tenantID, "platform-engineering").Return(nil, fmt.Errorf("not found"))
	groupRepo.On("Update", mock.Anything, mock.AnythingOfType("*models.Group")).Return(nil)

	svc := newTestGroupSvc(groupRepo, userRepo, roleRepo)
	h := NewGroupHandler(svc, nil)
	router := setupGroupHandlerRouter(h, tenantID, makeAdminCtx(tenantID))

	newName := "platform-engineering"
	body, _ := json.Marshal(models.UpdateGroupRequest{Name: &newName})
	w := doRequest(router, http.MethodPut, "/api/groups/"+g.ID.String(), string(body))

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestGroupHandler_UpdateGroup_NotFound_Returns404(t *testing.T) {
	tenantID := uuid.New()
	targetID := uuid.New()

	groupRepo := new(mockGroupHandlerGroupRepo)
	userRepo := new(mockGroupHandlerUserRepo)
	roleRepo := new(mockGroupHandlerRoleRepo)
	groupRepo.On("GetByID", mock.Anything, targetID).Return(nil, fmt.Errorf("not found"))

	svc := newTestGroupSvc(groupRepo, userRepo, roleRepo)
	h := NewGroupHandler(svc, nil)
	router := setupGroupHandlerRouter(h, tenantID, makeAdminCtx(tenantID))

	body, _ := json.Marshal(models.UpdateGroupRequest{})
	w := doRequest(router, http.MethodPut, "/api/groups/"+targetID.String(), string(body))

	assert.Equal(t, http.StatusNotFound, w.Code)
}

// ---------------------------------------------------------------------------
// Tests: DELETE /api/groups/:id (DeleteGroup)
// ---------------------------------------------------------------------------

func TestGroupHandler_DeleteGroup_Returns200(t *testing.T) {
	tenantID := uuid.New()
	g := makeTestGroup(tenantID, false)

	groupRepo := new(mockGroupHandlerGroupRepo)
	userRepo := new(mockGroupHandlerUserRepo)
	roleRepo := new(mockGroupHandlerRoleRepo)
	// validateGroupTenantAccess -> GetGroup -> GetByID + GetRoles
	// DeleteGroup service -> GetByID again
	groupRepo.On("GetByID", mock.Anything, g.ID).Return(g, nil)
	groupRepo.On("GetRoles", mock.Anything, g.ID).Return([]*models.Role{}, nil)
	groupRepo.On("Delete", mock.Anything, g.ID).Return(nil)

	svc := newTestGroupSvc(groupRepo, userRepo, roleRepo)
	h := NewGroupHandler(svc, nil)
	router := setupGroupHandlerRouter(h, tenantID, makeAdminCtx(tenantID))

	w := doRequest(router, http.MethodDelete, "/api/groups/"+g.ID.String(), "")

	assert.Equal(t, http.StatusOK, w.Code)
	var resp map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Contains(t, strings.ToLower(fmt.Sprint(resp["message"])), "deleted")
}

func TestGroupHandler_DeleteGroup_NotFound_Returns404(t *testing.T) {
	tenantID := uuid.New()
	targetID := uuid.New()

	groupRepo := new(mockGroupHandlerGroupRepo)
	userRepo := new(mockGroupHandlerUserRepo)
	roleRepo := new(mockGroupHandlerRoleRepo)
	groupRepo.On("GetByID", mock.Anything, targetID).Return(nil, fmt.Errorf("not found"))

	svc := newTestGroupSvc(groupRepo, userRepo, roleRepo)
	h := NewGroupHandler(svc, nil)
	router := setupGroupHandlerRouter(h, tenantID, makeAdminCtx(tenantID))

	w := doRequest(router, http.MethodDelete, "/api/groups/"+targetID.String(), "")

	assert.Equal(t, http.StatusNotFound, w.Code)
}

// ---------------------------------------------------------------------------
// Tests: Member Management
// ---------------------------------------------------------------------------

func TestGroupHandler_GetMembers_Returns200(t *testing.T) {
	tenantID := uuid.New()
	g := makeTestGroup(tenantID, false)
	member := &models.GroupMember{ID: uuid.New(), GroupID: g.ID, UserID: uuid.New(), AddedAt: time.Now()}

	groupRepo := new(mockGroupHandlerGroupRepo)
	userRepo := new(mockGroupHandlerUserRepo)
	roleRepo := new(mockGroupHandlerRoleRepo)
	// validateGroupTenantAccess -> GetGroup -> GetByID + GetRoles
	groupRepo.On("GetByID", mock.Anything, g.ID).Return(g, nil)
	groupRepo.On("GetRoles", mock.Anything, g.ID).Return([]*models.Role{}, nil)
	groupRepo.On("GetMembers", mock.Anything, g.ID, 1, 20).Return([]*models.GroupMember{member}, 1, nil)

	svc := newTestGroupSvc(groupRepo, userRepo, roleRepo)
	h := NewGroupHandler(svc, nil)
	router := setupGroupHandlerRouter(h, tenantID, makeAdminCtx(tenantID))

	w := doRequest(router, http.MethodGet, "/api/groups/"+g.ID.String()+"/members", "")

	assert.Equal(t, http.StatusOK, w.Code)
	var resp map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	members, ok := resp["members"].([]interface{})
	require.True(t, ok)
	assert.Len(t, members, 1)
}

func TestGroupHandler_AddMembers_Returns200(t *testing.T) {
	tenantID := uuid.New()
	g := makeTestGroup(tenantID, false)
	userID := uuid.New()
	u := &models.User{ID: userID, TenantID: tenantID, Username: "bob", Email: "bob@example.com", IsActive: true, ActivationStatus: "active"}

	groupRepo := new(mockGroupHandlerGroupRepo)
	userRepo := new(mockGroupHandlerUserRepo)
	roleRepo := new(mockGroupHandlerRoleRepo)
	// validateGroupTenantAccess -> GetGroup -> GetByID + GetRoles
	// AddMembers service -> GetByID again
	groupRepo.On("GetByID", mock.Anything, g.ID).Return(g, nil)
	groupRepo.On("GetRoles", mock.Anything, g.ID).Return([]*models.Role{}, nil)
	userRepo.On("GetByID", mock.Anything, userID).Return(u, nil)
	groupRepo.On("AddMember", mock.Anything, g.ID, userID, mock.Anything).Return(nil)

	svc := newTestGroupSvc(groupRepo, userRepo, roleRepo)
	h := NewGroupHandler(svc, nil)
	router := setupGroupHandlerRouter(h, tenantID, makeAdminCtx(tenantID))

	body := fmt.Sprintf(`{"user_ids":[%q]}`, userID.String())
	w := doRequest(router, http.MethodPost, "/api/groups/"+g.ID.String()+"/members", body)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Contains(t, strings.ToLower(fmt.Sprint(resp["message"])), "added")
}

func TestGroupHandler_AddMembers_InvalidJSON_Returns400(t *testing.T) {
	tenantID := uuid.New()
	g := makeTestGroup(tenantID, false)

	groupRepo := new(mockGroupHandlerGroupRepo)
	userRepo := new(mockGroupHandlerUserRepo)
	roleRepo := new(mockGroupHandlerRoleRepo)
	// validateGroupTenantAccess -> GetGroup -> GetByID + GetRoles
	groupRepo.On("GetByID", mock.Anything, g.ID).Return(g, nil)
	groupRepo.On("GetRoles", mock.Anything, g.ID).Return([]*models.Role{}, nil)

	svc := newTestGroupSvc(groupRepo, userRepo, roleRepo)
	h := NewGroupHandler(svc, nil)
	router := setupGroupHandlerRouter(h, tenantID, makeAdminCtx(tenantID))

	w := doRequest(router, http.MethodPost, "/api/groups/"+g.ID.String()+"/members", `{bad}`)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestGroupHandler_AddMembers_MissingUserIDs_Returns400(t *testing.T) {
	tenantID := uuid.New()
	g := makeTestGroup(tenantID, false)

	groupRepo := new(mockGroupHandlerGroupRepo)
	userRepo := new(mockGroupHandlerUserRepo)
	roleRepo := new(mockGroupHandlerRoleRepo)
	// validateGroupTenantAccess -> GetGroup -> GetByID + GetRoles
	groupRepo.On("GetByID", mock.Anything, g.ID).Return(g, nil)
	groupRepo.On("GetRoles", mock.Anything, g.ID).Return([]*models.Role{}, nil)

	svc := newTestGroupSvc(groupRepo, userRepo, roleRepo)
	h := NewGroupHandler(svc, nil)
	router := setupGroupHandlerRouter(h, tenantID, makeAdminCtx(tenantID))

	// user_ids required, min=1
	w := doRequest(router, http.MethodPost, "/api/groups/"+g.ID.String()+"/members", `{"user_ids":[]}`)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestGroupHandler_RemoveMembers_Returns200(t *testing.T) {
	tenantID := uuid.New()
	g := makeTestGroup(tenantID, false)
	userID := uuid.New()

	groupRepo := new(mockGroupHandlerGroupRepo)
	userRepo := new(mockGroupHandlerUserRepo)
	roleRepo := new(mockGroupHandlerRoleRepo)
	// validateGroupTenantAccess -> GetGroup -> GetByID + GetRoles
	groupRepo.On("GetByID", mock.Anything, g.ID).Return(g, nil)
	groupRepo.On("GetRoles", mock.Anything, g.ID).Return([]*models.Role{}, nil)
	groupRepo.On("RemoveMember", mock.Anything, g.ID, userID).Return(nil)

	svc := newTestGroupSvc(groupRepo, userRepo, roleRepo)
	h := NewGroupHandler(svc, nil)
	router := setupGroupHandlerRouter(h, tenantID, makeAdminCtx(tenantID))

	body := fmt.Sprintf(`{"user_ids":[%q]}`, userID.String())
	w := doRequest(router, http.MethodDelete, "/api/groups/"+g.ID.String()+"/members", body)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Contains(t, strings.ToLower(fmt.Sprint(resp["message"])), "removed")
}

// ---------------------------------------------------------------------------
// Tests: Role Management
// ---------------------------------------------------------------------------

func TestGroupHandler_GetGroupRoles_Returns200(t *testing.T) {
	tenantID := uuid.New()
	g := makeTestGroup(tenantID, false)
	role := &models.Role{ID: uuid.New(), TenantID: tenantID, Name: "editor", DisplayName: "Editor"}

	groupRepo := new(mockGroupHandlerGroupRepo)
	userRepo := new(mockGroupHandlerUserRepo)
	roleRepo := new(mockGroupHandlerRoleRepo)
	// validateGroupTenantAccess -> GetGroup -> GetByID + GetRoles (call 1)
	// GetGroupRoles handler -> groupService.GetGroupRoles -> GetRoles (call 2)
	// testify mock replays the same return value for repeated calls by default
	groupRepo.On("GetByID", mock.Anything, g.ID).Return(g, nil)
	groupRepo.On("GetRoles", mock.Anything, g.ID).Return([]*models.Role{role}, nil)

	svc := newTestGroupSvc(groupRepo, userRepo, roleRepo)
	h := NewGroupHandler(svc, nil)
	router := setupGroupHandlerRouter(h, tenantID, makeAdminCtx(tenantID))

	w := doRequest(router, http.MethodGet, "/api/groups/"+g.ID.String()+"/roles", "")

	assert.Equal(t, http.StatusOK, w.Code)
	var resp map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	roles, ok := resp["roles"].([]interface{})
	require.True(t, ok)
	assert.Len(t, roles, 1)
}

func TestGroupHandler_AssignRoles_Returns200(t *testing.T) {
	tenantID := uuid.New()
	g := makeTestGroup(tenantID, false)
	roleID := uuid.New()
	role := &models.Role{ID: roleID, TenantID: tenantID, Name: "analyst", DisplayName: "Analyst"}

	groupRepo := new(mockGroupHandlerGroupRepo)
	userRepo := new(mockGroupHandlerUserRepo)
	roleRepo := new(mockGroupHandlerRoleRepo)
	// validateGroupTenantAccess -> GetGroup -> GetByID + GetRoles
	// AssignRoles service -> GetByID again
	groupRepo.On("GetByID", mock.Anything, g.ID).Return(g, nil)
	groupRepo.On("GetRoles", mock.Anything, g.ID).Return([]*models.Role{}, nil)
	roleRepo.On("GetByID", mock.Anything, roleID).Return(role, nil)
	groupRepo.On("AssignRole", mock.Anything, g.ID, roleID, mock.Anything).Return(nil)

	svc := newTestGroupSvc(groupRepo, userRepo, roleRepo)
	h := NewGroupHandler(svc, nil)
	router := setupGroupHandlerRouter(h, tenantID, makeAdminCtx(tenantID))

	body := fmt.Sprintf(`{"role_ids":[%q]}`, roleID.String())
	w := doRequest(router, http.MethodPost, "/api/groups/"+g.ID.String()+"/roles", body)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Contains(t, strings.ToLower(fmt.Sprint(resp["message"])), "assigned")
}

func TestGroupHandler_AssignRoles_MissingRoleIDs_Returns400(t *testing.T) {
	tenantID := uuid.New()
	g := makeTestGroup(tenantID, false)

	groupRepo := new(mockGroupHandlerGroupRepo)
	userRepo := new(mockGroupHandlerUserRepo)
	roleRepo := new(mockGroupHandlerRoleRepo)
	// validateGroupTenantAccess -> GetGroup -> GetByID + GetRoles
	groupRepo.On("GetByID", mock.Anything, g.ID).Return(g, nil)
	groupRepo.On("GetRoles", mock.Anything, g.ID).Return([]*models.Role{}, nil)

	svc := newTestGroupSvc(groupRepo, userRepo, roleRepo)
	h := NewGroupHandler(svc, nil)
	router := setupGroupHandlerRouter(h, tenantID, makeAdminCtx(tenantID))

	// role_ids required, min=1
	w := doRequest(router, http.MethodPost, "/api/groups/"+g.ID.String()+"/roles", `{"role_ids":[]}`)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestGroupHandler_RemoveRoles_Returns200(t *testing.T) {
	tenantID := uuid.New()
	g := makeTestGroup(tenantID, false)
	roleID := uuid.New()

	groupRepo := new(mockGroupHandlerGroupRepo)
	userRepo := new(mockGroupHandlerUserRepo)
	roleRepo := new(mockGroupHandlerRoleRepo)
	// validateGroupTenantAccess -> GetGroup -> GetByID + GetRoles
	groupRepo.On("GetByID", mock.Anything, g.ID).Return(g, nil)
	groupRepo.On("GetRoles", mock.Anything, g.ID).Return([]*models.Role{}, nil)
	groupRepo.On("RemoveRole", mock.Anything, g.ID, roleID).Return(nil)

	svc := newTestGroupSvc(groupRepo, userRepo, roleRepo)
	h := NewGroupHandler(svc, nil)
	router := setupGroupHandlerRouter(h, tenantID, makeAdminCtx(tenantID))

	body := fmt.Sprintf(`{"role_ids":[%q]}`, roleID.String())
	w := doRequest(router, http.MethodDelete, "/api/groups/"+g.ID.String()+"/roles", body)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Contains(t, strings.ToLower(fmt.Sprint(resp["message"])), "removed")
}

func TestGroupHandler_SetRoles_Returns200(t *testing.T) {
	tenantID := uuid.New()
	g := makeTestGroup(tenantID, false)
	roleID := uuid.New()
	role := &models.Role{ID: roleID, TenantID: tenantID, Name: "viewer", DisplayName: "Viewer"}

	groupRepo := new(mockGroupHandlerGroupRepo)
	userRepo := new(mockGroupHandlerUserRepo)
	roleRepo := new(mockGroupHandlerRoleRepo)
	groupRepo.On("GetByID", mock.Anything, g.ID).Return(g, nil)
	groupRepo.On("GetRoles", mock.Anything, g.ID).Return([]*models.Role{}, nil) // no existing roles
	roleRepo.On("GetByID", mock.Anything, roleID).Return(role, nil)
	groupRepo.On("AssignRole", mock.Anything, g.ID, roleID, mock.Anything).Return(nil)

	svc := newTestGroupSvc(groupRepo, userRepo, roleRepo)
	h := NewGroupHandler(svc, nil)
	router := setupGroupHandlerRouter(h, tenantID, makeAdminCtx(tenantID))

	body := fmt.Sprintf(`{"role_ids":[%q]}`, roleID.String())
	w := doRequest(router, http.MethodPut, "/api/groups/"+g.ID.String()+"/roles", body)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Contains(t, strings.ToLower(fmt.Sprint(resp["message"])), "updated")
}

// ---------------------------------------------------------------------------
// Tests: GET /api/users/:id/groups (GetUserGroups)
// ---------------------------------------------------------------------------

func TestGroupHandler_GetUserGroups_SameTenant_Returns200(t *testing.T) {
	tenantID := uuid.New()
	u := makeTestUser(tenantID)
	g := makeTestGroup(tenantID, false)

	groupRepo := new(mockGroupHandlerGroupRepo)
	userRepo := new(mockGroupHandlerUserRepo)
	roleRepo := new(mockGroupHandlerRoleRepo)

	// Need a real UserService for GetUserGroups (handler.userService != nil branch)
	// UserService.GetByID also calls GetUserRoles and GetUserPermissions after fetching the user
	userSvcRepo := new(mockUserServiceUserRepo)
	userSvcRepo.On("GetByID", mock.Anything, u.ID).Return(u, nil)
	userSvcRepo.On("GetUserRoles", mock.Anything, u.ID).Return([]models.Role{}, nil)
	userSvcRepo.On("GetUserPermissions", mock.Anything, u.ID).Return([]models.Permission{}, nil)
	userSvc := newTestUserSvc(t, userSvcRepo)

	groupRepo.On("GetUserGroups", mock.Anything, u.ID).Return([]*models.Group{g}, nil)

	svc := newTestGroupSvc(groupRepo, userRepo, roleRepo)
	h := NewGroupHandler(svc, userSvc)
	router := setupGroupHandlerRouter(h, tenantID, makeAdminCtx(tenantID))

	w := doRequest(router, http.MethodGet, "/api/users/"+u.ID.String()+"/groups", "")

	assert.Equal(t, http.StatusOK, w.Code)
	var resp map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	groups, ok := resp["groups"].([]interface{})
	require.True(t, ok)
	assert.Len(t, groups, 1)
}

func TestGroupHandler_GetUserGroups_DifferentTenant_Returns404(t *testing.T) {
	ownerTenant := uuid.New()
	attackerTenant := uuid.New()
	u := makeTestUser(ownerTenant) // user belongs to ownerTenant

	groupRepo := new(mockGroupHandlerGroupRepo)
	userRepo := new(mockGroupHandlerUserRepo)
	roleRepo := new(mockGroupHandlerRoleRepo)

	userSvcRepo := new(mockUserServiceUserRepo)
	userSvcRepo.On("GetByID", mock.Anything, u.ID).Return(u, nil)
	userSvcRepo.On("GetUserRoles", mock.Anything, u.ID).Return([]models.Role{}, nil)
	userSvcRepo.On("GetUserPermissions", mock.Anything, u.ID).Return([]models.Permission{}, nil)
	userSvc := newTestUserSvc(t, userSvcRepo)

	svc := newTestGroupSvc(groupRepo, userRepo, roleRepo)
	h := NewGroupHandler(svc, userSvc)

	// attacker in different tenant
	attacker := &models.CurrentUser{
		ID:       uuid.New(),
		TenantID: attackerTenant,
		Username: "attacker",
	}
	router := setupGroupHandlerRouter(h, attackerTenant, attacker)

	w := doRequest(router, http.MethodGet, "/api/users/"+u.ID.String()+"/groups", "")

	assert.Equal(t, http.StatusNotFound, w.Code)
}

// ---------------------------------------------------------------------------
// Tests: GET /api/users/:id/effective-roles (GetUserEffectiveRoles)
// ---------------------------------------------------------------------------

func TestGroupHandler_GetUserEffectiveRoles_Returns200(t *testing.T) {
	tenantID := uuid.New()
	u := makeTestUser(tenantID)
	roleID := uuid.New()

	groupRepo := new(mockGroupHandlerGroupRepo)
	userRepo := new(mockGroupHandlerUserRepo)
	roleRepo := new(mockGroupHandlerRoleRepo)

	userSvcRepo := new(mockUserServiceUserRepo)
	userSvcRepo.On("GetByID", mock.Anything, u.ID).Return(u, nil)
	userSvcRepo.On("GetUserRoles", mock.Anything, u.ID).Return([]models.Role{}, nil)
	userSvcRepo.On("GetUserPermissions", mock.Anything, u.ID).Return([]models.Permission{}, nil)
	userSvc := newTestUserSvc(t, userSvcRepo)

	groupRepo.On("GetUserEffectiveRoles", mock.Anything, u.ID).Return([]*models.EffectiveRole{
		{RoleID: roleID, RoleName: "editor", Source: "group"},
	}, nil)

	svc := newTestGroupSvc(groupRepo, userRepo, roleRepo)
	h := NewGroupHandler(svc, userSvc)
	router := setupGroupHandlerRouter(h, tenantID, makeAdminCtx(tenantID))

	w := doRequest(router, http.MethodGet, "/api/users/"+u.ID.String()+"/effective-roles", "")

	assert.Equal(t, http.StatusOK, w.Code)
	var resp map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	roles, ok := resp["roles"].([]interface{})
	require.True(t, ok)
	assert.Len(t, roles, 1)
}
