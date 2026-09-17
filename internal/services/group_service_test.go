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
)

// ==================== Mock declarations ====================

// MockGroupRepo mocks the groupServiceGroupRepo interface.
type MockGroupRepo struct {
	mock.Mock
}

func (m *MockGroupRepo) GetByName(ctx context.Context, tenantID uuid.UUID, name string) (*models.Group, error) {
	args := m.Called(ctx, tenantID, name)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.Group), args.Error(1)
}

func (m *MockGroupRepo) GetByID(ctx context.Context, id uuid.UUID) (*models.Group, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.Group), args.Error(1)
}

func (m *MockGroupRepo) Create(ctx context.Context, group *models.Group) error {
	args := m.Called(ctx, group)
	return args.Error(0)
}

func (m *MockGroupRepo) AssignRole(ctx context.Context, groupID, roleID uuid.UUID, assignedBy *uuid.UUID) error {
	args := m.Called(ctx, groupID, roleID, assignedBy)
	return args.Error(0)
}

func (m *MockGroupRepo) AddMember(ctx context.Context, groupID, userID uuid.UUID, addedBy *uuid.UUID) error {
	args := m.Called(ctx, groupID, userID, addedBy)
	return args.Error(0)
}

func (m *MockGroupRepo) Update(ctx context.Context, group *models.Group) error {
	args := m.Called(ctx, group)
	return args.Error(0)
}

func (m *MockGroupRepo) Delete(ctx context.Context, id uuid.UUID) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *MockGroupRepo) GetRoles(ctx context.Context, groupID uuid.UUID) ([]*models.Role, error) {
	args := m.Called(ctx, groupID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.Role), args.Error(1)
}

func (m *MockGroupRepo) GetChildGroups(ctx context.Context, parentID uuid.UUID) ([]*models.Group, error) {
	args := m.Called(ctx, parentID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.Group), args.Error(1)
}

func (m *MockGroupRepo) List(ctx context.Context, tenantID uuid.UUID, page, pageSize int, search string) ([]*models.Group, int, error) {
	args := m.Called(ctx, tenantID, page, pageSize, search)
	if args.Get(0) == nil {
		return nil, args.Int(1), args.Error(2)
	}
	return args.Get(0).([]*models.Group), args.Int(1), args.Error(2)
}

func (m *MockGroupRepo) GetMembers(ctx context.Context, groupID uuid.UUID, page, pageSize int) ([]*models.GroupMember, int, error) {
	args := m.Called(ctx, groupID, page, pageSize)
	if args.Get(0) == nil {
		return nil, args.Int(1), args.Error(2)
	}
	return args.Get(0).([]*models.GroupMember), args.Int(1), args.Error(2)
}

func (m *MockGroupRepo) GetUserGroups(ctx context.Context, userID uuid.UUID) ([]*models.Group, error) {
	args := m.Called(ctx, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.Group), args.Error(1)
}

func (m *MockGroupRepo) RemoveMember(ctx context.Context, groupID, userID uuid.UUID) error {
	args := m.Called(ctx, groupID, userID)
	return args.Error(0)
}

func (m *MockGroupRepo) RemoveRole(ctx context.Context, groupID, roleID uuid.UUID) error {
	args := m.Called(ctx, groupID, roleID)
	return args.Error(0)
}

func (m *MockGroupRepo) GetUserEffectiveRoles(ctx context.Context, userID uuid.UUID) ([]*models.EffectiveRole, error) {
	args := m.Called(ctx, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.EffectiveRole), args.Error(1)
}

func (m *MockGroupRepo) GetRootGroups(ctx context.Context, tenantID uuid.UUID) ([]*models.Group, error) {
	args := m.Called(ctx, tenantID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.Group), args.Error(1)
}

// MockGroupUserRepo mocks groupServiceUserRepo.
type MockGroupUserRepo struct {
	mock.Mock
}

func (m *MockGroupUserRepo) GetByID(ctx context.Context, id uuid.UUID) (*models.User, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.User), args.Error(1)
}

// MockGroupRoleRepo mocks groupServiceRoleRepo.
type MockGroupRoleRepo struct {
	mock.Mock
}

func (m *MockGroupRoleRepo) GetByID(ctx context.Context, id uuid.UUID) (*models.Role, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.Role), args.Error(1)
}

// ==================== Helpers ====================

func newGroupService(gr *MockGroupRepo, ur *MockGroupUserRepo, rr *MockGroupRoleRepo) *GroupService {
	return NewGroupService(gr, ur, rr)
}

// ==================== CreateGroup ====================

func TestGroupService_CreateGroup_Valid(t *testing.T) {
	ctx := context.Background()
	tenantID := uuid.New()
	createdBy := uuid.New()

	gr := new(MockGroupRepo)
	ur := new(MockGroupUserRepo)
	rr := new(MockGroupRoleRepo)
	svc := newGroupService(gr, ur, rr)

	req := &models.CreateGroupRequest{
		Name: "engineering",
	}

	created := &models.Group{ID: uuid.New(), TenantID: tenantID, Name: "engineering"}

	gr.On("GetByName", ctx, tenantID, "engineering").Return(nil, errors.New("not found"))
	gr.On("Create", ctx, mock.AnythingOfType("*models.Group")).Return(nil)
	gr.On("GetByID", ctx, mock.AnythingOfType("uuid.UUID")).Return(created, nil)

	group, err := svc.CreateGroup(ctx, tenantID, req, &createdBy)

	require.NoError(t, err)
	assert.NotNil(t, group)
	assert.Equal(t, "engineering", group.Name)
	gr.AssertExpectations(t)
}

func TestGroupService_CreateGroup_DuplicateName(t *testing.T) {
	ctx := context.Background()
	tenantID := uuid.New()

	gr := new(MockGroupRepo)
	ur := new(MockGroupUserRepo)
	rr := new(MockGroupRoleRepo)
	svc := newGroupService(gr, ur, rr)

	existing := &models.Group{ID: uuid.New(), TenantID: tenantID, Name: "engineering"}
	gr.On("GetByName", ctx, tenantID, "engineering").Return(existing, nil)

	req := &models.CreateGroupRequest{Name: "engineering"}
	group, err := svc.CreateGroup(ctx, tenantID, req, nil)

	assert.Error(t, err)
	assert.Nil(t, group)
	assert.Contains(t, err.Error(), "already exists")
	gr.AssertExpectations(t)
}

func TestGroupService_CreateGroup_WithParentGroup(t *testing.T) {
	ctx := context.Background()
	tenantID := uuid.New()
	parentID := uuid.New()
	createdBy := uuid.New()

	gr := new(MockGroupRepo)
	ur := new(MockGroupUserRepo)
	rr := new(MockGroupRoleRepo)
	svc := newGroupService(gr, ur, rr)

	parent := &models.Group{ID: parentID, TenantID: tenantID}
	created := &models.Group{ID: uuid.New(), TenantID: tenantID, Name: "child", ParentGroupID: &parentID}

	gr.On("GetByName", ctx, tenantID, "child").Return(nil, errors.New("not found"))
	gr.On("GetByID", ctx, parentID).Return(parent, nil)
	gr.On("Create", ctx, mock.AnythingOfType("*models.Group")).Return(nil)
	gr.On("GetByID", ctx, mock.AnythingOfType("uuid.UUID")).Return(created, nil)

	req := &models.CreateGroupRequest{Name: "child", ParentGroupID: &parentID}
	group, err := svc.CreateGroup(ctx, tenantID, req, &createdBy)

	require.NoError(t, err)
	assert.NotNil(t, group)
	gr.AssertExpectations(t)
}

func TestGroupService_CreateGroup_WithRoleIDs(t *testing.T) {
	ctx := context.Background()
	tenantID := uuid.New()
	createdBy := uuid.New()
	roleID := uuid.New()

	gr := new(MockGroupRepo)
	ur := new(MockGroupUserRepo)
	rr := new(MockGroupRoleRepo)
	svc := newGroupService(gr, ur, rr)

	created := &models.Group{ID: uuid.New(), TenantID: tenantID, Name: "devs"}

	gr.On("GetByName", ctx, tenantID, "devs").Return(nil, errors.New("not found"))
	gr.On("Create", ctx, mock.AnythingOfType("*models.Group")).Return(nil)
	gr.On("AssignRole", ctx, mock.AnythingOfType("uuid.UUID"), roleID, &createdBy).Return(nil)
	gr.On("GetByID", ctx, mock.AnythingOfType("uuid.UUID")).Return(created, nil)

	req := &models.CreateGroupRequest{Name: "devs", RoleIDs: []uuid.UUID{roleID}}
	group, err := svc.CreateGroup(ctx, tenantID, req, &createdBy)

	require.NoError(t, err)
	assert.NotNil(t, group)
	gr.AssertExpectations(t)
}

func TestGroupService_CreateGroup_WithMemberIDs(t *testing.T) {
	ctx := context.Background()
	tenantID := uuid.New()
	createdBy := uuid.New()
	memberID := uuid.New()

	gr := new(MockGroupRepo)
	ur := new(MockGroupUserRepo)
	rr := new(MockGroupRoleRepo)
	svc := newGroupService(gr, ur, rr)

	created := &models.Group{ID: uuid.New(), TenantID: tenantID, Name: "devs"}

	gr.On("GetByName", ctx, tenantID, "devs").Return(nil, errors.New("not found"))
	gr.On("Create", ctx, mock.AnythingOfType("*models.Group")).Return(nil)
	gr.On("AddMember", ctx, mock.AnythingOfType("uuid.UUID"), memberID, &createdBy).Return(nil)
	gr.On("GetByID", ctx, mock.AnythingOfType("uuid.UUID")).Return(created, nil)

	req := &models.CreateGroupRequest{Name: "devs", MemberIDs: []uuid.UUID{memberID}}
	group, err := svc.CreateGroup(ctx, tenantID, req, &createdBy)

	require.NoError(t, err)
	assert.NotNil(t, group)
	gr.AssertExpectations(t)
}

// ==================== GetGroup ====================

func TestGroupService_GetGroup_FoundWithRoles(t *testing.T) {
	ctx := context.Background()
	groupID := uuid.New()

	gr := new(MockGroupRepo)
	ur := new(MockGroupUserRepo)
	rr := new(MockGroupRoleRepo)
	svc := newGroupService(gr, ur, rr)

	roleName := "admin"
	roles := []*models.Role{{ID: uuid.New(), Name: roleName}}
	group := &models.Group{ID: groupID, Name: "ops"}

	gr.On("GetByID", ctx, groupID).Return(group, nil)
	gr.On("GetRoles", ctx, groupID).Return(roles, nil)

	result, err := svc.GetGroup(ctx, groupID)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "ops", result.Name)
	assert.Len(t, result.Roles, 1)
	assert.Equal(t, roleName, result.Roles[0].Name)
	gr.AssertExpectations(t)
}

func TestGroupService_GetGroup_NotFound(t *testing.T) {
	ctx := context.Background()
	groupID := uuid.New()

	gr := new(MockGroupRepo)
	ur := new(MockGroupUserRepo)
	rr := new(MockGroupRoleRepo)
	svc := newGroupService(gr, ur, rr)

	gr.On("GetByID", ctx, groupID).Return(nil, errors.New("group not found"))

	result, err := svc.GetGroup(ctx, groupID)

	assert.Error(t, err)
	assert.Nil(t, result)
	gr.AssertExpectations(t)
}

// ==================== GetGroupWithDetails ====================

func TestGroupService_GetGroupWithDetails_WithChildrenAndParent(t *testing.T) {
	ctx := context.Background()
	groupID := uuid.New()
	parentID := uuid.New()

	gr := new(MockGroupRepo)
	ur := new(MockGroupUserRepo)
	rr := new(MockGroupRoleRepo)
	svc := newGroupService(gr, ur, rr)

	parent := &models.Group{ID: parentID, Name: "parent"}
	child := &models.Group{ID: uuid.New(), Name: "child", ParentGroupID: &groupID}
	group := &models.Group{ID: groupID, Name: "middle", ParentGroupID: &parentID}

	gr.On("GetByID", ctx, groupID).Return(group, nil)
	gr.On("GetRoles", ctx, groupID).Return([]*models.Role{}, nil)
	gr.On("GetChildGroups", ctx, groupID).Return([]*models.Group{child}, nil)
	gr.On("GetByID", ctx, parentID).Return(parent, nil)

	result, err := svc.GetGroupWithDetails(ctx, groupID)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Len(t, result.ChildGroups, 1)
	require.NotNil(t, result.ParentGroup)
	assert.Equal(t, "parent", result.ParentGroup.Name)
	gr.AssertExpectations(t)
}

// ==================== UpdateGroup ====================

func TestGroupService_UpdateGroup_Valid(t *testing.T) {
	ctx := context.Background()
	groupID := uuid.New()
	tenantID := uuid.New()

	gr := new(MockGroupRepo)
	ur := new(MockGroupUserRepo)
	rr := new(MockGroupRoleRepo)
	svc := newGroupService(gr, ur, rr)

	newName := "updated-name"
	existing := &models.Group{ID: groupID, TenantID: tenantID, Name: "old-name", IsSystem: false}
	updated := &models.Group{ID: groupID, TenantID: tenantID, Name: newName}

	gr.On("GetByID", ctx, groupID).Return(existing, nil).Once()
	gr.On("GetByName", ctx, tenantID, newName).Return(nil, errors.New("not found"))
	gr.On("Update", ctx, mock.AnythingOfType("*models.Group")).Return(nil)
	gr.On("GetByID", ctx, groupID).Return(updated, nil).Once()

	req := &models.UpdateGroupRequest{Name: &newName}
	result, err := svc.UpdateGroup(ctx, groupID, req)

	require.NoError(t, err)
	assert.NotNil(t, result)
	gr.AssertExpectations(t)
}

func TestGroupService_UpdateGroup_SystemGroupError(t *testing.T) {
	ctx := context.Background()
	groupID := uuid.New()

	gr := new(MockGroupRepo)
	ur := new(MockGroupUserRepo)
	rr := new(MockGroupRoleRepo)
	svc := newGroupService(gr, ur, rr)

	systemGroup := &models.Group{ID: groupID, Name: "system-group", IsSystem: true}
	gr.On("GetByID", ctx, groupID).Return(systemGroup, nil)

	newName := "new-name"
	req := &models.UpdateGroupRequest{Name: &newName}
	result, err := svc.UpdateGroup(ctx, groupID, req)

	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "cannot modify system group")
	gr.AssertExpectations(t)
}

func TestGroupService_UpdateGroup_DuplicateRename(t *testing.T) {
	ctx := context.Background()
	groupID := uuid.New()
	tenantID := uuid.New()

	gr := new(MockGroupRepo)
	ur := new(MockGroupUserRepo)
	rr := new(MockGroupRoleRepo)
	svc := newGroupService(gr, ur, rr)

	existing := &models.Group{ID: groupID, TenantID: tenantID, Name: "original", IsSystem: false}
	duplicate := &models.Group{ID: uuid.New(), TenantID: tenantID, Name: "taken-name"}

	gr.On("GetByID", ctx, groupID).Return(existing, nil)
	gr.On("GetByName", ctx, tenantID, "taken-name").Return(duplicate, nil)

	takenName := "taken-name"
	req := &models.UpdateGroupRequest{Name: &takenName}
	result, err := svc.UpdateGroup(ctx, groupID, req)

	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "already exists")
	gr.AssertExpectations(t)
}

// ==================== DeleteGroup ====================

func TestGroupService_DeleteGroup_Success(t *testing.T) {
	ctx := context.Background()
	groupID := uuid.New()

	gr := new(MockGroupRepo)
	ur := new(MockGroupUserRepo)
	rr := new(MockGroupRoleRepo)
	svc := newGroupService(gr, ur, rr)

	group := &models.Group{ID: groupID, Name: "to-delete", IsSystem: false}
	gr.On("GetByID", ctx, groupID).Return(group, nil)
	gr.On("Delete", ctx, groupID).Return(nil)

	err := svc.DeleteGroup(ctx, groupID)

	require.NoError(t, err)
	gr.AssertExpectations(t)
}

func TestGroupService_DeleteGroup_SystemGroupError(t *testing.T) {
	ctx := context.Background()
	groupID := uuid.New()

	gr := new(MockGroupRepo)
	ur := new(MockGroupUserRepo)
	rr := new(MockGroupRoleRepo)
	svc := newGroupService(gr, ur, rr)

	systemGroup := &models.Group{ID: groupID, Name: "system-group", IsSystem: true}
	gr.On("GetByID", ctx, groupID).Return(systemGroup, nil)

	err := svc.DeleteGroup(ctx, groupID)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "cannot delete system group")
	gr.AssertExpectations(t)
}

// ==================== AddMembers ====================

func TestGroupService_AddMembers_Valid(t *testing.T) {
	ctx := context.Background()
	groupID := uuid.New()
	tenantID := uuid.New()
	userID := uuid.New()
	addedBy := uuid.New()

	gr := new(MockGroupRepo)
	ur := new(MockGroupUserRepo)
	rr := new(MockGroupRoleRepo)
	svc := newGroupService(gr, ur, rr)

	group := &models.Group{ID: groupID, TenantID: tenantID}
	user := &models.User{ID: userID, TenantID: tenantID}

	gr.On("GetByID", ctx, groupID).Return(group, nil)
	ur.On("GetByID", ctx, userID).Return(user, nil)
	gr.On("AddMember", ctx, groupID, userID, &addedBy).Return(nil)

	err := svc.AddMembers(ctx, groupID, []uuid.UUID{userID}, &addedBy)

	require.NoError(t, err)
	gr.AssertExpectations(t)
	ur.AssertExpectations(t)
}

func TestGroupService_AddMembers_UserNotFound_Skipped(t *testing.T) {
	ctx := context.Background()
	groupID := uuid.New()
	tenantID := uuid.New()
	userID := uuid.New()

	gr := new(MockGroupRepo)
	ur := new(MockGroupUserRepo)
	rr := new(MockGroupRoleRepo)
	svc := newGroupService(gr, ur, rr)

	group := &models.Group{ID: groupID, TenantID: tenantID}

	gr.On("GetByID", ctx, groupID).Return(group, nil)
	ur.On("GetByID", ctx, userID).Return(nil, errors.New("user not found"))

	// AddMember should NOT be called since user lookup failed
	err := svc.AddMembers(ctx, groupID, []uuid.UUID{userID}, nil)

	require.NoError(t, err) // errors are swallowed; operation succeeds
	gr.AssertExpectations(t)
	ur.AssertExpectations(t)
}

func TestGroupService_AddMembers_DifferentTenant_Skipped(t *testing.T) {
	ctx := context.Background()
	groupID := uuid.New()
	tenantID := uuid.New()
	otherTenantID := uuid.New()
	userID := uuid.New()

	gr := new(MockGroupRepo)
	ur := new(MockGroupUserRepo)
	rr := new(MockGroupRoleRepo)
	svc := newGroupService(gr, ur, rr)

	group := &models.Group{ID: groupID, TenantID: tenantID}
	user := &models.User{ID: userID, TenantID: otherTenantID}

	gr.On("GetByID", ctx, groupID).Return(group, nil)
	ur.On("GetByID", ctx, userID).Return(user, nil)

	err := svc.AddMembers(ctx, groupID, []uuid.UUID{userID}, nil)

	require.NoError(t, err)
	gr.AssertNumberOfCalls(t, "AddMember", 0)
}

// ==================== RemoveMembers ====================

func TestGroupService_RemoveMembers_Valid(t *testing.T) {
	ctx := context.Background()
	groupID := uuid.New()
	userID := uuid.New()

	gr := new(MockGroupRepo)
	ur := new(MockGroupUserRepo)
	rr := new(MockGroupRoleRepo)
	svc := newGroupService(gr, ur, rr)

	gr.On("RemoveMember", ctx, groupID, userID).Return(nil)

	err := svc.RemoveMembers(ctx, groupID, []uuid.UUID{userID})

	require.NoError(t, err)
	gr.AssertExpectations(t)
}

func TestGroupService_RemoveMembers_ErrorSwallowed(t *testing.T) {
	ctx := context.Background()
	groupID := uuid.New()
	userID := uuid.New()

	gr := new(MockGroupRepo)
	ur := new(MockGroupUserRepo)
	rr := new(MockGroupRoleRepo)
	svc := newGroupService(gr, ur, rr)

	gr.On("RemoveMember", ctx, groupID, userID).Return(errors.New("not a member"))

	// Errors from RemoveMember are swallowed
	err := svc.RemoveMembers(ctx, groupID, []uuid.UUID{userID})

	require.NoError(t, err)
	gr.AssertExpectations(t)
}

// ==================== AssignRoles ====================

func TestGroupService_AssignRoles_Valid(t *testing.T) {
	ctx := context.Background()
	groupID := uuid.New()
	tenantID := uuid.New()
	roleID := uuid.New()
	assignedBy := uuid.New()

	gr := new(MockGroupRepo)
	ur := new(MockGroupUserRepo)
	rr := new(MockGroupRoleRepo)
	svc := newGroupService(gr, ur, rr)

	group := &models.Group{ID: groupID, TenantID: tenantID}
	role := &models.Role{ID: roleID, TenantID: tenantID}

	gr.On("GetByID", ctx, groupID).Return(group, nil)
	rr.On("GetByID", ctx, roleID).Return(role, nil)
	gr.On("AssignRole", ctx, groupID, roleID, &assignedBy).Return(nil)

	err := svc.AssignRoles(ctx, groupID, []uuid.UUID{roleID}, &assignedBy)

	require.NoError(t, err)
	gr.AssertExpectations(t)
	rr.AssertExpectations(t)
}

func TestGroupService_AssignRoles_RoleNotFound_Skipped(t *testing.T) {
	ctx := context.Background()
	groupID := uuid.New()
	tenantID := uuid.New()
	roleID := uuid.New()

	gr := new(MockGroupRepo)
	ur := new(MockGroupUserRepo)
	rr := new(MockGroupRoleRepo)
	svc := newGroupService(gr, ur, rr)

	group := &models.Group{ID: groupID, TenantID: tenantID}

	gr.On("GetByID", ctx, groupID).Return(group, nil)
	rr.On("GetByID", ctx, roleID).Return(nil, errors.New("role not found"))

	err := svc.AssignRoles(ctx, groupID, []uuid.UUID{roleID}, nil)

	require.NoError(t, err)
	gr.AssertNumberOfCalls(t, "AssignRole", 0)
}

// ==================== RemoveRoles ====================

func TestGroupService_RemoveRoles_Valid(t *testing.T) {
	ctx := context.Background()
	groupID := uuid.New()
	roleID := uuid.New()

	gr := new(MockGroupRepo)
	ur := new(MockGroupUserRepo)
	rr := new(MockGroupRoleRepo)
	svc := newGroupService(gr, ur, rr)

	gr.On("RemoveRole", ctx, groupID, roleID).Return(nil)

	err := svc.RemoveRoles(ctx, groupID, []uuid.UUID{roleID})

	require.NoError(t, err)
	gr.AssertExpectations(t)
}

// ==================== ListGroups ====================

func TestGroupService_ListGroups_Pagination(t *testing.T) {
	ctx := context.Background()
	tenantID := uuid.New()

	gr := new(MockGroupRepo)
	ur := new(MockGroupUserRepo)
	rr := new(MockGroupRoleRepo)
	svc := newGroupService(gr, ur, rr)

	groups := []*models.Group{
		{ID: uuid.New(), Name: "group-1"},
		{ID: uuid.New(), Name: "group-2"},
	}
	gr.On("List", ctx, tenantID, 1, 10, "").Return(groups, 25, nil)

	result, err := svc.ListGroups(ctx, tenantID, 1, 10, "")

	require.NoError(t, err)
	assert.Len(t, result.Groups, 2)
	assert.Equal(t, 25, result.Total)
	assert.Equal(t, 1, result.Page)
	assert.Equal(t, 10, result.PageSize)
	assert.Equal(t, 3, result.TotalPages) // ceil(25/10)
}

func TestGroupService_ListGroups_Search(t *testing.T) {
	ctx := context.Background()
	tenantID := uuid.New()

	gr := new(MockGroupRepo)
	ur := new(MockGroupUserRepo)
	rr := new(MockGroupRoleRepo)
	svc := newGroupService(gr, ur, rr)

	groups := []*models.Group{{ID: uuid.New(), Name: "engineering"}}
	gr.On("List", ctx, tenantID, 1, 20, "eng").Return(groups, 1, nil)

	result, err := svc.ListGroups(ctx, tenantID, 1, 20, "eng")

	require.NoError(t, err)
	assert.Len(t, result.Groups, 1)
}

// ==================== GetUserGroups ====================

func TestGroupService_GetUserGroups_ReturnsGroups(t *testing.T) {
	ctx := context.Background()
	userID := uuid.New()

	gr := new(MockGroupRepo)
	ur := new(MockGroupUserRepo)
	rr := new(MockGroupRoleRepo)
	svc := newGroupService(gr, ur, rr)

	groups := []*models.Group{
		{ID: uuid.New(), Name: "alpha"},
		{ID: uuid.New(), Name: "beta"},
	}
	gr.On("GetUserGroups", ctx, userID).Return(groups, nil)

	result, err := svc.GetUserGroups(ctx, userID)

	require.NoError(t, err)
	assert.Len(t, result, 2)
	gr.AssertExpectations(t)
}

// ==================== GetUserEffectiveRoles ====================

func TestGroupService_GetUserEffectiveRoles_DirectAndGroupInherited(t *testing.T) {
	ctx := context.Background()
	userID := uuid.New()
	groupID := uuid.New()

	gr := new(MockGroupRepo)
	ur := new(MockGroupUserRepo)
	rr := new(MockGroupRoleRepo)
	svc := newGroupService(gr, ur, rr)

	effectiveRoles := []*models.EffectiveRole{
		{RoleID: uuid.New(), RoleName: "editor", Source: "direct"},
		{RoleID: uuid.New(), RoleName: "viewer", Source: "group", SourceID: &groupID},
	}
	gr.On("GetUserEffectiveRoles", ctx, userID).Return(effectiveRoles, nil)

	result, err := svc.GetUserEffectiveRoles(ctx, userID)

	require.NoError(t, err)
	assert.Len(t, result, 2)
	assert.Equal(t, "direct", result[0].Source)
	assert.Equal(t, "group", result[1].Source)
	assert.NotNil(t, result[1].SourceID)
}

// ==================== GetGroupHierarchy (tree) ====================

func TestGroupService_GetGroupTree_RootWithChildren(t *testing.T) {
	ctx := context.Background()
	tenantID := uuid.New()
	rootID := uuid.New()
	childID := uuid.New()

	gr := new(MockGroupRepo)
	ur := new(MockGroupUserRepo)
	rr := new(MockGroupRoleRepo)
	svc := newGroupService(gr, ur, rr)

	rootGroup := &models.Group{ID: rootID, Name: "root"}
	childGroup := &models.Group{ID: childID, Name: "child", ParentGroupID: &rootID}

	gr.On("GetRootGroups", ctx, tenantID).Return([]*models.Group{rootGroup}, nil)
	gr.On("GetChildGroups", ctx, rootID).Return([]*models.Group{childGroup}, nil)
	gr.On("GetChildGroups", ctx, childID).Return([]*models.Group{}, nil)

	result, err := svc.GetGroupTree(ctx, tenantID)

	require.NoError(t, err)
	require.Len(t, result, 1)
	assert.Equal(t, "root", result[0].Name)
	require.Len(t, result[0].ChildGroups, 1)
	assert.Equal(t, "child", result[0].ChildGroups[0].Name)
}

func TestGroupService_GetGroupTree_Empty(t *testing.T) {
	ctx := context.Background()
	tenantID := uuid.New()

	gr := new(MockGroupRepo)
	ur := new(MockGroupUserRepo)
	rr := new(MockGroupRoleRepo)
	svc := newGroupService(gr, ur, rr)

	gr.On("GetRootGroups", ctx, tenantID).Return([]*models.Group{}, nil)

	result, err := svc.GetGroupTree(ctx, tenantID)

	require.NoError(t, err)
	assert.Empty(t, result)
}
