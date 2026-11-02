// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/internal/repositories"
)

// ---------------------------------------------------------------------------
// Mock: roleServiceRoleRepo
// ---------------------------------------------------------------------------

type mockRoleServiceRoleRepo struct {
	mock.Mock
}

func (m *mockRoleServiceRoleRepo) GetByName(ctx context.Context, tenantID uuid.UUID, name string) (*models.Role, error) {
	args := m.Called(ctx, tenantID, name)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.Role), args.Error(1)
}

func (m *mockRoleServiceRoleRepo) Create(ctx context.Context, role *models.Role) error {
	args := m.Called(ctx, role)
	return args.Error(0)
}

func (m *mockRoleServiceRoleRepo) AssignPermissions(ctx context.Context, roleID uuid.UUID, permissionIDs []uuid.UUID, assignedBy *uuid.UUID) error {
	args := m.Called(ctx, roleID, permissionIDs, assignedBy)
	return args.Error(0)
}

// GrantPermissionsByName is a no-op stub: no test in this file exercises the
// AcmeApp reconcile path.
func (m *mockRoleServiceRoleRepo) GrantPermissionsByName(ctx context.Context, roleID uuid.UUID, permissionNames []string) error {
	return nil
}

func (m *mockRoleServiceRoleRepo) GetRolePermissions(ctx context.Context, roleID uuid.UUID) ([]models.Permission, error) {
	args := m.Called(ctx, roleID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]models.Permission), args.Error(1)
}

func (m *mockRoleServiceRoleRepo) GetByID(ctx context.Context, id uuid.UUID) (*models.Role, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.Role), args.Error(1)
}

func (m *mockRoleServiceRoleRepo) Update(ctx context.Context, role *models.Role) error {
	args := m.Called(ctx, role)
	return args.Error(0)
}

func (m *mockRoleServiceRoleRepo) Delete(ctx context.Context, id uuid.UUID) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *mockRoleServiceRoleRepo) List(ctx context.Context, tenantID uuid.UUID, page, pageSize int, search string) ([]models.Role, int64, error) {
	args := m.Called(ctx, tenantID, page, pageSize, search)
	if args.Get(0) == nil {
		return nil, args.Get(1).(int64), args.Error(2)
	}
	return args.Get(0).([]models.Role), args.Get(1).(int64), args.Error(2)
}

func (m *mockRoleServiceRoleRepo) ListForModules(ctx context.Context, tenantID uuid.UUID, page, pageSize int, search string, modules []string) ([]models.Role, int64, error) {
	args := m.Called(ctx, tenantID, page, pageSize, search, modules)
	if args.Get(0) == nil {
		return nil, args.Get(1).(int64), args.Error(2)
	}
	return args.Get(0).([]models.Role), args.Get(1).(int64), args.Error(2)
}

func (m *mockRoleServiceRoleRepo) CreateSystemRoles(ctx context.Context, tenantID uuid.UUID) error {
	args := m.Called(ctx, tenantID)
	return args.Error(0)
}

func (m *mockRoleServiceRoleRepo) GetByIDAndTenant(ctx context.Context, id, tenantID uuid.UUID) (*models.Role, error) {
	args := m.Called(ctx, id, tenantID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.Role), args.Error(1)
}

func (m *mockRoleServiceRoleRepo) GetMaxPriorityForUser(ctx context.Context, userID, tenantID uuid.UUID) (int, error) {
	args := m.Called(ctx, userID, tenantID)
	return args.Int(0), args.Error(1)
}

func (m *mockRoleServiceRoleRepo) GetRoleMembers(ctx context.Context, tenantID uuid.UUID, roleIdentifier string, page, pageSize int) ([]repositories.RoleMemberResult, int, error) {
	args := m.Called(ctx, tenantID, roleIdentifier, page, pageSize)
	if args.Get(0) == nil {
		return nil, args.Int(1), args.Error(2)
	}
	return args.Get(0).([]repositories.RoleMemberResult), args.Int(1), args.Error(2)
}

// ---------------------------------------------------------------------------
// Mock: roleServicePermissionRepo
// ---------------------------------------------------------------------------

type mockRoleServicePermissionRepo struct {
	mock.Mock
}

func (m *mockRoleServicePermissionRepo) List(ctx context.Context) ([]models.Permission, error) {
	args := m.Called(ctx)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]models.Permission), args.Error(1)
}

func (m *mockRoleServicePermissionRepo) ListByModules(ctx context.Context, modules []string) ([]models.Permission, error) {
	args := m.Called(ctx, modules)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]models.Permission), args.Error(1)
}

func (m *mockRoleServicePermissionRepo) GetModules(ctx context.Context) ([]string, error) {
	args := m.Called(ctx)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]string), args.Error(1)
}

func (m *mockRoleServicePermissionRepo) GetUserPermissionIDs(ctx context.Context, userID, tenantID uuid.UUID) ([]uuid.UUID, error) {
	args := m.Called(ctx, userID, tenantID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]uuid.UUID), args.Error(1)
}

func (m *mockRoleServicePermissionRepo) GetUserPermissionNames(ctx context.Context, userID, tenantID uuid.UUID) ([]string, error) {
	args := m.Called(ctx, userID, tenantID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]string), args.Error(1)
}

func (m *mockRoleServicePermissionRepo) GetPermissionNamesByIDs(ctx context.Context, ids []uuid.UUID) (map[uuid.UUID]string, error) {
	args := m.Called(ctx, ids)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(map[uuid.UUID]string), args.Error(1)
}

func (m *mockRoleServicePermissionRepo) GetByID(ctx context.Context, id uuid.UUID) (*models.Permission, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.Permission), args.Error(1)
}

// ---------------------------------------------------------------------------
// Mock: auditServiceTokenRepo (satisfies auditServiceTokenRepo interface)
// ---------------------------------------------------------------------------

type mockAuditTokenRepo struct {
	mock.Mock
}

func (m *mockAuditTokenRepo) CreateAuditLog(ctx context.Context, log *models.AuditLog) error {
	args := m.Called(ctx, log)
	return args.Error(0)
}

func (m *mockAuditTokenRepo) GetAuditLogByID(ctx context.Context, id uuid.UUID, tenantID uuid.UUID) (*models.AuditLog, error) {
	args := m.Called(ctx, id, tenantID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.AuditLog), args.Error(1)
}

func (m *mockAuditTokenRepo) ListAuditLogs(ctx context.Context, tenantID uuid.UUID, page, pageSize int, filters map[string]interface{}) ([]models.AuditLog, int64, error) {
	args := m.Called(ctx, tenantID, page, pageSize, filters)
	if args.Get(0) == nil {
		return nil, args.Get(1).(int64), args.Error(2)
	}
	return args.Get(0).([]models.AuditLog), args.Get(1).(int64), args.Error(2)
}

// ---------------------------------------------------------------------------
// Mock: EventPublisher
// ---------------------------------------------------------------------------

type mockEventPublisher struct {
	mock.Mock
}

func (m *mockEventPublisher) PublishEvent(ctx context.Context, topic string, key string, payload interface{}) error {
	args := m.Called(ctx, topic, key, payload)
	return args.Error(0)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// newRoleServiceForTest constructs a RoleService wired with mock dependencies.
// The AuditService uses a permissive mock that accepts any CreateAuditLog call.
func newRoleServiceForTest(t *testing.T, roleRepo roleServiceRoleRepo, permRepo roleServicePermissionRepo) (*RoleService, *mockAuditTokenRepo) { //nolint:unparam // mockAuditTokenRepo is returned for potential future use in tests
	t.Helper()
	auditRepo := new(mockAuditTokenRepo)
	auditRepo.On("CreateAuditLog", mock.Anything, mock.AnythingOfType("*models.AuditLog")).Return(nil)
	audit := NewAuditService(auditRepo, nil)
	svc := NewRoleService(roleRepo, permRepo, audit)
	return svc, auditRepo
}

func TestListManageableSelfService_FiltersSystemAndUnmanageableRoles(t *testing.T) {
	tenantID := uuid.New()
	actorID := uuid.New()
	manageable := models.Role{ID: uuid.New(), TenantID: tenantID, Name: "editor", Priority: 10}
	system := models.Role{ID: uuid.New(), TenantID: tenantID, Name: "owner", IsSystem: true, Priority: 100}
	equalPriority := models.Role{ID: uuid.New(), TenantID: tenantID, Name: "admin", Priority: 50}
	otherTenant := models.Role{ID: uuid.New(), TenantID: uuid.New(), Name: "foreign", Priority: 1}

	roles := new(mockRoleServiceRoleRepo)
	perms := new(mockRoleServicePermissionRepo)
	roles.On("GetMaxPriorityForUser", mock.Anything, actorID, tenantID).Return(50, nil)
	roles.On("ListForModules", mock.Anything, tenantID, 1, 100, "", []string{"core", "iam"}).Return([]models.Role{manageable, system, equalPriority, otherTenant}, int64(4), nil)
	roles.On("GetRolePermissions", mock.Anything, manageable.ID).Return([]models.Permission{}, nil)
	svc, _ := newRoleServiceForTest(t, roles, perms)

	response, err := svc.ListManageableSelfService(context.Background(), tenantID, actorID, 1, 20, "")
	require.NoError(t, err)
	require.Len(t, response.Roles, 3)
	assert.Equal(t, manageable.ID, response.Roles[0].ID)
	assert.Equal(t, models.RoleSourceTenantCatalogue, response.Roles[0].Source)
	assert.True(t, response.Roles[0].Editable)
	assert.Equal(t, int64(3), response.Total)
	roles.AssertExpectations(t)
}

func TestListManageableSelfService_PriorityLookupFailure(t *testing.T) {
	tenantID := uuid.New()
	actorID := uuid.New()
	roles := new(mockRoleServiceRoleRepo)
	perms := new(mockRoleServicePermissionRepo)
	roles.On("GetMaxPriorityForUser", mock.Anything, actorID, tenantID).Return(0, errors.New("db unavailable"))
	svc, _ := newRoleServiceForTest(t, roles, perms)

	_, err := svc.ListManageableSelfService(context.Background(), tenantID, actorID, 1, 20, "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "actor priority")
}

func TestListSelfService_EntitlementLookupFailureFailsClosed(t *testing.T) {
	tenantID := uuid.New()
	roles := new(mockRoleServiceRoleRepo)
	perms := new(mockRoleServicePermissionRepo)
	perms.On("GetModules", mock.Anything).Return(nil, errors.New("database unavailable"))
	svc, _ := newRoleServiceForTest(t, roles, perms)
	svc.SetModuleEntitlementChecker(&mockModuleEntitlementChecker{entitled: true})

	_, err := svc.ListSelfService(context.Background(), tenantID, 1, 20, "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "entitlement lookup")
	roles.AssertNotCalled(t, "List", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything)
	roles.AssertNotCalled(t, "ListForModules", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything)
}

// ---------------------------------------------------------------------------
// TestRoleService_Create
// ---------------------------------------------------------------------------

func TestRoleService_Create_Success(t *testing.T) {
	ctx := context.Background()
	tenantID := uuid.New()
	creatorID := uuid.New()

	roleRepo := new(mockRoleServiceRoleRepo)
	permRepo := new(mockRoleServicePermissionRepo)
	svc, _ := newRoleServiceForTest(t, roleRepo, permRepo)

	req := &models.CreateRoleRequest{
		TenantID:    tenantID,
		Name:        "editor",
		DisplayName: "Editor",
	}

	roleRepo.On("GetByName", ctx, tenantID, "editor").Return(nil, nil)
	roleRepo.On("GetMaxPriorityForUser", ctx, creatorID, tenantID).Return(100, nil)
	roleRepo.On("Create", ctx, mock.AnythingOfType("*models.Role")).Return(nil)
	roleRepo.On("GetRolePermissions", ctx, mock.AnythingOfType("uuid.UUID")).Return([]models.Permission{}, nil)

	resp, err := svc.Create(ctx, req, &creatorID)

	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, "editor", resp.Name)
	assert.Equal(t, "Editor", resp.DisplayName)
	assert.False(t, resp.IsSystem)
	roleRepo.AssertExpectations(t)
}

func TestRoleService_Create_DuplicateName(t *testing.T) {
	ctx := context.Background()
	tenantID := uuid.New()

	roleRepo := new(mockRoleServiceRoleRepo)
	permRepo := new(mockRoleServicePermissionRepo)
	svc, _ := newRoleServiceForTest(t, roleRepo, permRepo)

	existing := &models.Role{ID: uuid.New(), TenantID: tenantID, Name: "editor"}
	roleRepo.On("GetByName", ctx, tenantID, "editor").Return(existing, nil)

	req := &models.CreateRoleRequest{
		TenantID:    tenantID,
		Name:        "editor",
		DisplayName: "Editor",
	}

	resp, err := svc.Create(ctx, req, nil)

	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "role name already exists")
	roleRepo.AssertExpectations(t)
}

func TestRoleService_Create_WithPermissionIDs(t *testing.T) {
	ctx := context.Background()
	tenantID := uuid.New()
	creatorID := uuid.New()
	permID1 := uuid.New()
	permID2 := uuid.New()
	permIDs := []uuid.UUID{permID1, permID2}

	roleRepo := new(mockRoleServiceRoleRepo)
	permRepo := new(mockRoleServicePermissionRepo)
	svc, _ := newRoleServiceForTest(t, roleRepo, permRepo)

	req := &models.CreateRoleRequest{
		TenantID:      tenantID,
		Name:          "analyst",
		DisplayName:   "Analyst",
		PermissionIDs: permIDs,
	}

	assignedPerms := []models.Permission{
		{ID: permID1, Name: "crm:contacts:read", Module: "crm", Resource: "contacts", Action: "read"},
		{ID: permID2, Name: "crm:contacts:list", Module: "crm", Resource: "contacts", Action: "list"},
	}

	roleRepo.On("GetByName", ctx, tenantID, "analyst").Return(nil, nil)
	roleRepo.On("GetMaxPriorityForUser", ctx, creatorID, tenantID).Return(100, nil)
	roleRepo.On("Create", ctx, mock.AnythingOfType("*models.Role")).Return(nil)
	// checkCallerCoversPermissions: caller has module wildcard covering all crm permissions
	permRepo.On("GetUserPermissionNames", ctx, creatorID, tenantID).Return([]string{"crm:*:*"}, nil)
	permRepo.On("GetPermissionNamesByIDs", ctx, permIDs).Return(map[uuid.UUID]string{
		permID1: "crm:contacts:read",
		permID2: "crm:contacts:list",
	}, nil)
	roleRepo.On("AssignPermissions", ctx, mock.AnythingOfType("uuid.UUID"), permIDs, &creatorID).Return(nil)
	roleRepo.On("GetRolePermissions", ctx, mock.AnythingOfType("uuid.UUID")).Return(assignedPerms, nil)

	resp, err := svc.Create(ctx, req, &creatorID)

	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Len(t, resp.Permissions, 2)
	roleRepo.AssertExpectations(t)
}

func TestRoleService_Create_RepoError(t *testing.T) {
	ctx := context.Background()
	tenantID := uuid.New()

	roleRepo := new(mockRoleServiceRoleRepo)
	permRepo := new(mockRoleServicePermissionRepo)
	svc, _ := newRoleServiceForTest(t, roleRepo, permRepo)

	roleRepo.On("GetByName", ctx, tenantID, "broken").Return(nil, errors.New("db error"))

	req := &models.CreateRoleRequest{TenantID: tenantID, Name: "broken", DisplayName: "Broken"}
	resp, err := svc.Create(ctx, req, nil)

	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "failed to check role name")
}

// ---------------------------------------------------------------------------
// TestRoleService_GetByID
// ---------------------------------------------------------------------------

func TestRoleService_GetByID_Found(t *testing.T) {
	ctx := context.Background()
	roleID := uuid.New()
	tenantID := uuid.New()

	roleRepo := new(mockRoleServiceRoleRepo)
	permRepo := new(mockRoleServicePermissionRepo)
	svc, _ := newRoleServiceForTest(t, roleRepo, permRepo)

	role := &models.Role{
		ID:          roleID,
		TenantID:    tenantID,
		Name:        "viewer",
		DisplayName: "Viewer",
	}

	roleRepo.On("GetByID", ctx, roleID).Return(role, nil)
	roleRepo.On("GetRolePermissions", ctx, roleID).Return([]models.Permission{}, nil)

	resp, err := svc.GetByID(ctx, roleID)

	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, roleID, resp.ID)
	assert.Equal(t, "viewer", resp.Name)
	roleRepo.AssertExpectations(t)
}

func TestRoleService_GetByID_NotFound(t *testing.T) {
	ctx := context.Background()
	roleID := uuid.New()

	roleRepo := new(mockRoleServiceRoleRepo)
	permRepo := new(mockRoleServicePermissionRepo)
	svc, _ := newRoleServiceForTest(t, roleRepo, permRepo)

	roleRepo.On("GetByID", ctx, roleID).Return(nil, nil)

	resp, err := svc.GetByID(ctx, roleID)

	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "role not found")
	roleRepo.AssertExpectations(t)
}

// ---------------------------------------------------------------------------
// TestRoleService_Update
// ---------------------------------------------------------------------------

func TestRoleService_Update_ValidUpdate(t *testing.T) {
	ctx := context.Background()
	roleID := uuid.New()
	tenantID := uuid.New()
	updaterID := uuid.New()

	roleRepo := new(mockRoleServiceRoleRepo)
	permRepo := new(mockRoleServicePermissionRepo)
	svc, _ := newRoleServiceForTest(t, roleRepo, permRepo)

	existing := &models.Role{
		ID:          roleID,
		TenantID:    tenantID,
		Name:        "editor",
		DisplayName: "Editor",
		IsSystem:    false,
	}

	newDisplayName := "Senior Editor"
	req := &models.UpdateRoleRequest{
		DisplayName: &newDisplayName,
	}

	roleRepo.On("GetByID", ctx, roleID).Return(existing, nil)
	roleRepo.On("Update", ctx, mock.AnythingOfType("*models.Role")).Return(nil)
	roleRepo.On("GetRolePermissions", ctx, roleID).Return([]models.Permission{}, nil)

	resp, err := svc.Update(ctx, roleID, req, &updaterID)

	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, "Senior Editor", resp.DisplayName)
	roleRepo.AssertExpectations(t)
}

func TestRoleService_Update_SystemRoleProtection_BlocksPropertyChange(t *testing.T) {
	ctx := context.Background()
	roleID := uuid.New()
	tenantID := uuid.New()

	roleRepo := new(mockRoleServiceRoleRepo)
	permRepo := new(mockRoleServicePermissionRepo)
	svc, _ := newRoleServiceForTest(t, roleRepo, permRepo)

	systemRole := &models.Role{
		ID:       roleID,
		TenantID: tenantID,
		Name:     "admin",
		IsSystem: true,
	}

	newDisplayName := "Hacked Admin"
	req := &models.UpdateRoleRequest{
		DisplayName: &newDisplayName,
	}

	roleRepo.On("GetByID", ctx, roleID).Return(systemRole, nil)

	resp, err := svc.Update(ctx, roleID, req, nil)

	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "cannot modify system role properties")
	roleRepo.AssertExpectations(t)
}

func TestRoleService_Update_SystemRoleAllowsDescriptionChange(t *testing.T) {
	ctx := context.Background()
	roleID := uuid.New()
	tenantID := uuid.New()
	updaterID := uuid.New()

	roleRepo := new(mockRoleServiceRoleRepo)
	permRepo := new(mockRoleServicePermissionRepo)
	svc, _ := newRoleServiceForTest(t, roleRepo, permRepo)

	systemRole := &models.Role{
		ID:       roleID,
		TenantID: tenantID,
		Name:     "admin",
		IsSystem: true,
	}

	desc := "Updated description"
	req := &models.UpdateRoleRequest{
		Description: &desc,
	}

	roleRepo.On("GetByID", ctx, roleID).Return(systemRole, nil)
	roleRepo.On("Update", ctx, mock.AnythingOfType("*models.Role")).Return(nil)
	roleRepo.On("GetRolePermissions", ctx, roleID).Return([]models.Permission{}, nil)

	resp, err := svc.Update(ctx, roleID, req, &updaterID)

	require.NoError(t, err)
	require.NotNil(t, resp)
	roleRepo.AssertExpectations(t)
}

func TestRoleService_Update_NotFound(t *testing.T) {
	ctx := context.Background()
	roleID := uuid.New()

	roleRepo := new(mockRoleServiceRoleRepo)
	permRepo := new(mockRoleServicePermissionRepo)
	svc, _ := newRoleServiceForTest(t, roleRepo, permRepo)

	roleRepo.On("GetByID", ctx, roleID).Return(nil, nil)

	req := &models.UpdateRoleRequest{}
	resp, err := svc.Update(ctx, roleID, req, nil)

	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "role not found")
}

// ---------------------------------------------------------------------------
// TestRoleService_Delete
// ---------------------------------------------------------------------------

func TestRoleService_Delete_Success(t *testing.T) {
	ctx := context.Background()
	roleID := uuid.New()
	tenantID := uuid.New()
	deleterID := uuid.New()

	roleRepo := new(mockRoleServiceRoleRepo)
	permRepo := new(mockRoleServicePermissionRepo)
	svc, _ := newRoleServiceForTest(t, roleRepo, permRepo)

	role := &models.Role{
		ID:       roleID,
		TenantID: tenantID,
		Name:     "editor",
		IsSystem: false,
	}

	roleRepo.On("GetByID", ctx, roleID).Return(role, nil)
	roleRepo.On("GetMaxPriorityForUser", ctx, deleterID, tenantID).Return(100, nil)
	roleRepo.On("Delete", ctx, roleID).Return(nil)

	err := svc.Delete(ctx, roleID, &deleterID)

	require.NoError(t, err)
	roleRepo.AssertExpectations(t)
}

func TestRoleService_Delete_SystemRoleProtection(t *testing.T) {
	ctx := context.Background()
	roleID := uuid.New()
	tenantID := uuid.New()

	roleRepo := new(mockRoleServiceRoleRepo)
	permRepo := new(mockRoleServicePermissionRepo)
	svc, _ := newRoleServiceForTest(t, roleRepo, permRepo)

	systemRole := &models.Role{
		ID:       roleID,
		TenantID: tenantID,
		Name:     "admin",
		IsSystem: true,
	}

	roleRepo.On("GetByID", ctx, roleID).Return(systemRole, nil)

	err := svc.Delete(ctx, roleID, nil)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "cannot delete system role")
	roleRepo.AssertExpectations(t)
}

func TestRoleService_Delete_NotFound(t *testing.T) {
	ctx := context.Background()
	roleID := uuid.New()

	roleRepo := new(mockRoleServiceRoleRepo)
	permRepo := new(mockRoleServicePermissionRepo)
	svc, _ := newRoleServiceForTest(t, roleRepo, permRepo)

	roleRepo.On("GetByID", ctx, roleID).Return(nil, nil)

	err := svc.Delete(ctx, roleID, nil)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "role not found")
}

func TestRoleService_Delete_WithSpiceDBEventPublisher(t *testing.T) {
	ctx := context.Background()
	roleID := uuid.New()
	tenantID := uuid.New()
	deleterID := uuid.New()

	roleRepo := new(mockRoleServiceRoleRepo)
	permRepo := new(mockRoleServicePermissionRepo)
	svc, _ := newRoleServiceForTest(t, roleRepo, permRepo)

	publisher := new(mockEventPublisher)
	svc.SetEventPublisher(publisher)

	role := &models.Role{
		ID:       roleID,
		TenantID: tenantID,
		Name:     "editor",
		IsSystem: false,
	}

	roleRepo.On("GetByID", ctx, roleID).Return(role, nil)
	roleRepo.On("GetMaxPriorityForUser", ctx, deleterID, tenantID).Return(100, nil)
	roleRepo.On("Delete", ctx, roleID).Return(nil)
	publisher.On("PublishEvent", ctx, IAMEventTopics.RoleDeleted, roleID.String(), mock.Anything).Return(nil)

	err := svc.Delete(ctx, roleID, &deleterID)

	require.NoError(t, err)
	roleRepo.AssertExpectations(t)
	publisher.AssertExpectations(t)
}

// ---------------------------------------------------------------------------
// TestRoleService_List
// ---------------------------------------------------------------------------

func TestRoleService_List_Pagination(t *testing.T) {
	ctx := context.Background()
	tenantID := uuid.New()

	roleRepo := new(mockRoleServiceRoleRepo)
	permRepo := new(mockRoleServicePermissionRepo)
	svc, _ := newRoleServiceForTest(t, roleRepo, permRepo)

	roles := []models.Role{
		{ID: uuid.New(), TenantID: tenantID, Name: "role1", DisplayName: "Role 1"},
		{ID: uuid.New(), TenantID: tenantID, Name: "role2", DisplayName: "Role 2"},
	}

	roleRepo.On("List", ctx, tenantID, 1, 20, "").Return(roles, int64(2), nil)
	roleRepo.On("GetRolePermissions", ctx, roles[0].ID).Return([]models.Permission{}, nil)
	roleRepo.On("GetRolePermissions", ctx, roles[1].ID).Return([]models.Permission{}, nil)

	result, err := svc.List(ctx, tenantID, 1, 20, "")

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Len(t, result.Roles, 2)
	assert.Equal(t, int64(2), result.Total)
	assert.Equal(t, 1, result.Page)
	assert.Equal(t, 20, result.PageSize)
	assert.Equal(t, 1, result.TotalPages)
	roleRepo.AssertExpectations(t)
}

func TestRoleService_List_PaginationDefaults(t *testing.T) {
	ctx := context.Background()
	tenantID := uuid.New()

	roleRepo := new(mockRoleServiceRoleRepo)
	permRepo := new(mockRoleServicePermissionRepo)
	svc, _ := newRoleServiceForTest(t, roleRepo, permRepo)

	// page=0 and pageSize=0 should default to page=1, pageSize=20
	roleRepo.On("List", ctx, tenantID, 1, 20, "").Return([]models.Role{}, int64(0), nil)

	result, err := svc.List(ctx, tenantID, 0, 0, "")

	require.NoError(t, err)
	assert.Equal(t, 1, result.Page)
	assert.Equal(t, 20, result.PageSize)
}

func TestRoleService_List_WithSearch(t *testing.T) {
	ctx := context.Background()
	tenantID := uuid.New()

	roleRepo := new(mockRoleServiceRoleRepo)
	permRepo := new(mockRoleServicePermissionRepo)
	svc, _ := newRoleServiceForTest(t, roleRepo, permRepo)

	role := models.Role{ID: uuid.New(), TenantID: tenantID, Name: "editor", DisplayName: "Editor"}
	roleRepo.On("List", ctx, tenantID, 1, 20, "edit").Return([]models.Role{role}, int64(1), nil)
	roleRepo.On("GetRolePermissions", ctx, role.ID).Return([]models.Permission{}, nil)

	result, err := svc.List(ctx, tenantID, 1, 20, "edit")

	require.NoError(t, err)
	assert.Len(t, result.Roles, 1)
	assert.Equal(t, "editor", result.Roles[0].Name)
}

func TestRoleService_List_TotalPagesCalculation(t *testing.T) {
	ctx := context.Background()
	tenantID := uuid.New()

	roleRepo := new(mockRoleServiceRoleRepo)
	permRepo := new(mockRoleServicePermissionRepo)
	svc, _ := newRoleServiceForTest(t, roleRepo, permRepo)

	// 25 total, page size 10 → 3 pages
	roles := make([]models.Role, 10)
	for i := range roles {
		roles[i] = models.Role{ID: uuid.New(), TenantID: tenantID, Name: "role"}
		roleRepo.On("GetRolePermissions", ctx, roles[i].ID).Return([]models.Permission{}, nil)
	}
	roleRepo.On("List", ctx, tenantID, 1, 10, "").Return(roles, int64(25), nil)

	result, err := svc.List(ctx, tenantID, 1, 10, "")

	require.NoError(t, err)
	assert.Equal(t, 3, result.TotalPages)
}

// ---------------------------------------------------------------------------
// TestRoleService_InitializeTenantRoles (CreateSystemRoles)
// ---------------------------------------------------------------------------

func TestRoleService_InitializeTenantRoles_Success(t *testing.T) {
	ctx := context.Background()
	tenantID := uuid.New()

	roleRepo := new(mockRoleServiceRoleRepo)
	permRepo := new(mockRoleServicePermissionRepo)
	svc, _ := newRoleServiceForTest(t, roleRepo, permRepo)

	roleRepo.On("CreateSystemRoles", ctx, tenantID).Return(nil)

	err := svc.InitializeTenantRoles(ctx, tenantID)

	require.NoError(t, err)
	roleRepo.AssertExpectations(t)
}

func TestRoleService_InitializeTenantRoles_Error(t *testing.T) {
	ctx := context.Background()
	tenantID := uuid.New()

	roleRepo := new(mockRoleServiceRoleRepo)
	permRepo := new(mockRoleServicePermissionRepo)
	svc, _ := newRoleServiceForTest(t, roleRepo, permRepo)

	roleRepo.On("CreateSystemRoles", ctx, tenantID).Return(errors.New("db error"))

	err := svc.InitializeTenantRoles(ctx, tenantID)

	assert.Error(t, err)
}

// ---------------------------------------------------------------------------
// TestRoleService_AssignPermissions
// ---------------------------------------------------------------------------

func TestRoleService_AssignPermissions_Valid(t *testing.T) {
	ctx := context.Background()
	roleID := uuid.New()
	tenantID := uuid.New()
	assignerID := uuid.New()
	permID := uuid.New()

	roleRepo := new(mockRoleServiceRoleRepo)
	permRepo := new(mockRoleServicePermissionRepo)
	svc, _ := newRoleServiceForTest(t, roleRepo, permRepo)

	role := &models.Role{
		ID:       roleID,
		TenantID: tenantID,
		Name:     "editor",
	}

	assignedPerms := []models.Permission{
		{ID: permID, Name: "core:contacts:read", Module: "core"},
	}

	roleRepo.On("GetByID", ctx, roleID).Return(role, nil)
	// checkCallerCoversPermissions: assigner has module wildcard covering all permissions
	permRepo.On("GetUserPermissionNames", ctx, assignerID, tenantID).Return([]string{"core:*:*"}, nil)
	permRepo.On("GetPermissionNamesByIDs", ctx, []uuid.UUID{permID}).Return(map[uuid.UUID]string{permID: "core:contacts:read"}, nil)
	// ADR-A10 boundary check (checkGrantBoundaryForIDs): resolves the
	// permission's module before deciding whether the grant is within the
	// tenant's entitlement boundary. No entitlementChecker is wired in
	// this test, so EntitledModules fails closed to UniversalModules
	// (core, iam) — use a core permission so the boundary passes.
	permRepo.On("GetByID", ctx, permID).Return(&models.Permission{ID: permID, Name: "core:contacts:read", Module: "core"}, nil)
	roleRepo.On("AssignPermissions", ctx, roleID, []uuid.UUID{permID}, &assignerID).Return(nil)
	roleRepo.On("GetRolePermissions", ctx, roleID).Return(assignedPerms, nil)

	err := svc.AssignPermissions(ctx, roleID, []uuid.UUID{permID}, &assignerID)

	require.NoError(t, err)
	roleRepo.AssertExpectations(t)
}

func TestRoleService_AssignPermissions_RoleNotFound(t *testing.T) {
	ctx := context.Background()
	roleID := uuid.New()

	roleRepo := new(mockRoleServiceRoleRepo)
	permRepo := new(mockRoleServicePermissionRepo)
	svc, _ := newRoleServiceForTest(t, roleRepo, permRepo)

	roleRepo.On("GetByID", ctx, roleID).Return(nil, nil)

	err := svc.AssignPermissions(ctx, roleID, []uuid.UUID{uuid.New()}, nil)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "role not found")
}

func TestRoleService_AssignPermissions_AssignError(t *testing.T) {
	ctx := context.Background()
	roleID := uuid.New()
	tenantID := uuid.New()
	permID := uuid.New()

	roleRepo := new(mockRoleServiceRoleRepo)
	permRepo := new(mockRoleServicePermissionRepo)
	svc, _ := newRoleServiceForTest(t, roleRepo, permRepo)

	role := &models.Role{ID: roleID, TenantID: tenantID, Name: "editor"}
	roleRepo.On("GetByID", ctx, roleID).Return(role, nil)
	// ADR-A10 boundary check runs before the DB write regardless of
	// assignedBy — see checkGrantBoundaryForIDs.
	permRepo.On("GetByID", ctx, permID).Return(&models.Permission{ID: permID, Name: "core:contacts:read", Module: "core"}, nil)
	roleRepo.On("AssignPermissions", ctx, roleID, []uuid.UUID{permID}, mock.Anything).Return(errors.New("invalid permission ID"))

	err := svc.AssignPermissions(ctx, roleID, []uuid.UUID{permID}, nil)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to assign permissions")
}

// ---------------------------------------------------------------------------
// TestRoleService_ListAllPermissions
// ---------------------------------------------------------------------------

func TestRoleService_ListAllPermissions(t *testing.T) {
	ctx := context.Background()

	roleRepo := new(mockRoleServiceRoleRepo)
	permRepo := new(mockRoleServicePermissionRepo)
	svc, _ := newRoleServiceForTest(t, roleRepo, permRepo)

	perms := []models.Permission{
		{ID: uuid.New(), Module: "crm", Resource: "contacts", Action: "read", Name: "crm:contacts:read"},
		{ID: uuid.New(), Module: "crm", Resource: "contacts", Action: "write", Name: "crm:contacts:write"},
	}

	permRepo.On("List", ctx).Return(perms, nil)

	result, err := svc.ListAllPermissions(ctx)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, int64(2), result.Total)
	assert.Len(t, result.Permissions, 2)
	permRepo.AssertExpectations(t)
}

// ---------------------------------------------------------------------------
// TestRoleService_EventPublisher (SpiceDB sync path)
// ---------------------------------------------------------------------------

func TestRoleService_Create_PublishesEvent(t *testing.T) {
	ctx := context.Background()
	tenantID := uuid.New()
	creatorID := uuid.New()

	roleRepo := new(mockRoleServiceRoleRepo)
	permRepo := new(mockRoleServicePermissionRepo)
	svc, _ := newRoleServiceForTest(t, roleRepo, permRepo)

	publisher := new(mockEventPublisher)
	svc.SetEventPublisher(publisher)

	req := &models.CreateRoleRequest{
		TenantID:    tenantID,
		Name:        "reporter",
		DisplayName: "Reporter",
	}

	roleRepo.On("GetByName", ctx, tenantID, "reporter").Return(nil, nil)
	roleRepo.On("GetMaxPriorityForUser", ctx, creatorID, tenantID).Return(100, nil)
	roleRepo.On("Create", ctx, mock.AnythingOfType("*models.Role")).Return(nil)
	roleRepo.On("GetRolePermissions", ctx, mock.AnythingOfType("uuid.UUID")).Return([]models.Permission{}, nil)
	publisher.On("PublishEvent", ctx, IAMEventTopics.RoleCreated, mock.AnythingOfType("string"), mock.Anything).Return(nil)

	resp, err := svc.Create(ctx, req, &creatorID)

	require.NoError(t, err)
	require.NotNil(t, resp)
	publisher.AssertExpectations(t)
}

// ---------------------------------------------------------------------------
// TestRoleService_publishEvent_NoPublisherNoPanic
// ---------------------------------------------------------------------------

func TestRoleService_PublishEvent_NoPublisherNoPanic(t *testing.T) {
	ctx := context.Background()
	tenantID := uuid.New()
	creatorID := uuid.New()

	roleRepo := new(mockRoleServiceRoleRepo)
	permRepo := new(mockRoleServicePermissionRepo)
	// No event publisher set — publishEvent should be a no-op
	svc, _ := newRoleServiceForTest(t, roleRepo, permRepo)

	req := &models.CreateRoleRequest{
		TenantID:    tenantID,
		Name:        "noevent",
		DisplayName: "No Event",
	}

	roleRepo.On("GetByName", ctx, tenantID, "noevent").Return(nil, nil)
	roleRepo.On("GetMaxPriorityForUser", ctx, creatorID, tenantID).Return(100, nil)
	roleRepo.On("Create", ctx, mock.AnythingOfType("*models.Role")).Return(nil)
	roleRepo.On("GetRolePermissions", ctx, mock.AnythingOfType("uuid.UUID")).Return([]models.Permission{}, nil)

	assert.NotPanics(t, func() {
		_, _ = svc.Create(ctx, req, &creatorID)
	})
}
