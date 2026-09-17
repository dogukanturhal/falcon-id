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

// ---------------------------------------------------------------------------
// Mock: organizationServiceOrgRepo
// ---------------------------------------------------------------------------

type MockOrgRepo struct {
	mock.Mock
}

func (m *MockOrgRepo) Create(ctx context.Context, org *models.Organization) error {
	args := m.Called(ctx, org)
	return args.Error(0)
}

func (m *MockOrgRepo) GetByID(ctx context.Context, id uuid.UUID) (*models.Organization, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.Organization), args.Error(1)
}

func (m *MockOrgRepo) GetByName(ctx context.Context, tenantID uuid.UUID, name string, parentID *uuid.UUID) (*models.Organization, error) {
	args := m.Called(ctx, tenantID, name, parentID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.Organization), args.Error(1)
}

func (m *MockOrgRepo) List(ctx context.Context, tenantID uuid.UUID, page, pageSize int, search string, orgType string) ([]*models.Organization, int, error) {
	args := m.Called(ctx, tenantID, page, pageSize, search, orgType)
	if args.Get(0) == nil {
		return nil, args.Int(1), args.Error(2)
	}
	return args.Get(0).([]*models.Organization), args.Int(1), args.Error(2)
}

func (m *MockOrgRepo) Update(ctx context.Context, org *models.Organization) error {
	args := m.Called(ctx, org)
	return args.Error(0)
}

func (m *MockOrgRepo) Delete(ctx context.Context, id uuid.UUID) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *MockOrgRepo) AddMember(ctx context.Context, orgID, userID uuid.UUID, role string, title *string, isPrimary bool, addedBy *uuid.UUID) error {
	args := m.Called(ctx, orgID, userID, role, title, isPrimary, addedBy)
	return args.Error(0)
}

func (m *MockOrgRepo) RemoveMember(ctx context.Context, orgID, userID uuid.UUID) error {
	args := m.Called(ctx, orgID, userID)
	return args.Error(0)
}

func (m *MockOrgRepo) UpdateMember(ctx context.Context, orgID, userID uuid.UUID, role *string, title *string, isPrimary *bool) error {
	args := m.Called(ctx, orgID, userID, role, title, isPrimary)
	return args.Error(0)
}

func (m *MockOrgRepo) GetMembers(ctx context.Context, orgID uuid.UUID, page, pageSize int) ([]*models.OrgMember, int, error) {
	args := m.Called(ctx, orgID, page, pageSize)
	if args.Get(0) == nil {
		return nil, args.Int(1), args.Error(2)
	}
	return args.Get(0).([]*models.OrgMember), args.Int(1), args.Error(2)
}

func (m *MockOrgRepo) GetUserOrganizations(ctx context.Context, userID uuid.UUID) ([]*models.OrgMember, error) {
	args := m.Called(ctx, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.OrgMember), args.Error(1)
}

func (m *MockOrgRepo) GetUserPrimaryOrganization(ctx context.Context, userID uuid.UUID) (*models.OrgMember, error) {
	args := m.Called(ctx, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.OrgMember), args.Error(1)
}

func (m *MockOrgRepo) GetChildren(ctx context.Context, parentID uuid.UUID) ([]*models.Organization, error) {
	args := m.Called(ctx, parentID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.Organization), args.Error(1)
}

func (m *MockOrgRepo) GetRootOrganizations(ctx context.Context, tenantID uuid.UUID) ([]*models.Organization, error) {
	args := m.Called(ctx, tenantID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.Organization), args.Error(1)
}

func (m *MockOrgRepo) GetDescendants(ctx context.Context, orgID uuid.UUID) ([]*models.Organization, error) {
	args := m.Called(ctx, orgID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.Organization), args.Error(1)
}

func (m *MockOrgRepo) GetAncestors(ctx context.Context, orgID uuid.UUID) ([]*models.Organization, error) {
	args := m.Called(ctx, orgID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.Organization), args.Error(1)
}

func (m *MockOrgRepo) GetOrgRoleAssignments(ctx context.Context, orgID uuid.UUID) ([]models.OrgRoleAssignment, error) {
	args := m.Called(ctx, orgID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]models.OrgRoleAssignment), args.Error(1)
}

func (m *MockOrgRepo) AssignOrgRole(ctx context.Context, orgID, roleID uuid.UUID, inherit bool, assignedBy *uuid.UUID) error {
	args := m.Called(ctx, orgID, roleID, inherit, assignedBy)
	return args.Error(0)
}

func (m *MockOrgRepo) RemoveOrgRole(ctx context.Context, orgID, roleID uuid.UUID) error {
	args := m.Called(ctx, orgID, roleID)
	return args.Error(0)
}

// ---------------------------------------------------------------------------
// Mock: organizationServiceUserRepo (re-uses type from user_service_test.go pattern)
// ---------------------------------------------------------------------------

type MockOrgUserRepo struct {
	mock.Mock
}

func (m *MockOrgUserRepo) GetByID(ctx context.Context, id uuid.UUID) (*models.User, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.User), args.Error(1)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func newOrgService(orgRepo *MockOrgRepo, userRepo *MockOrgUserRepo) *OrganizationService {
	return NewOrganizationService(orgRepo, userRepo)
}

func makeOrg(tenantID uuid.UUID, name string) *models.Organization {
	return &models.Organization{
		ID:          uuid.New(),
		TenantID:    tenantID,
		Name:        name,
		OrgType:     models.OrgTypeDepartment,
		IsActive:    true,
		MemberCount: 0,
	}
}

// ---------------------------------------------------------------------------
// Tests: CreateOrganization
// ---------------------------------------------------------------------------

func TestOrganizationService_Create_Success(t *testing.T) {
	ctx := context.Background()
	orgRepo := new(MockOrgRepo)
	userRepo := new(MockOrgUserRepo)
	svc := newOrgService(orgRepo, userRepo)

	tenantID := uuid.New()
	createdBy := uuid.New()

	req := &models.CreateOrganizationRequest{
		Name:    "Engineering",
		OrgType: models.OrgTypeDepartment,
	}

	// GetByName returns error → name is not taken
	orgRepo.On("GetByName", ctx, tenantID, "Engineering", (*uuid.UUID)(nil)).Return((*models.Organization)(nil), errors.New("not found"))
	orgRepo.On("Create", ctx, mock.AnythingOfType("*models.Organization")).Return(nil)
	orgRepo.On("GetByID", ctx, mock.AnythingOfType("uuid.UUID")).Return(
		&models.Organization{
			ID:       uuid.New(),
			TenantID: tenantID,
			Name:     "Engineering",
			OrgType:  models.OrgTypeDepartment,
		}, nil)

	org, err := svc.CreateOrganization(ctx, tenantID, req, &createdBy)

	require.NoError(t, err)
	require.NotNil(t, org)
	assert.Equal(t, "Engineering", org.Name)
	orgRepo.AssertExpectations(t)
}

func TestOrganizationService_Create_DuplicateName(t *testing.T) {
	ctx := context.Background()
	orgRepo := new(MockOrgRepo)
	userRepo := new(MockOrgUserRepo)
	svc := newOrgService(orgRepo, userRepo)

	tenantID := uuid.New()

	existing := makeOrg(tenantID, "Engineering")
	req := &models.CreateOrganizationRequest{
		Name:    "Engineering",
		OrgType: models.OrgTypeDepartment,
	}

	// GetByName succeeds → name is taken
	orgRepo.On("GetByName", ctx, tenantID, "Engineering", (*uuid.UUID)(nil)).Return(existing, nil)

	org, err := svc.CreateOrganization(ctx, tenantID, req, nil)

	assert.Error(t, err)
	assert.Nil(t, org)
	assert.Contains(t, err.Error(), "already exists")
	orgRepo.AssertExpectations(t)
}

func TestOrganizationService_Create_WithParent(t *testing.T) {
	ctx := context.Background()
	orgRepo := new(MockOrgRepo)
	userRepo := new(MockOrgUserRepo)
	svc := newOrgService(orgRepo, userRepo)

	tenantID := uuid.New()
	parentID := uuid.New()

	parent := &models.Organization{
		ID:       parentID,
		TenantID: tenantID,
		Name:     "Division",
		OrgType:  models.OrgTypeDivision,
	}

	req := &models.CreateOrganizationRequest{
		Name:     "Sub-Team",
		OrgType:  models.OrgTypeTeam,
		ParentID: &parentID,
	}

	orgRepo.On("GetByName", ctx, tenantID, "Sub-Team", &parentID).Return((*models.Organization)(nil), errors.New("not found"))
	orgRepo.On("GetByID", ctx, parentID).Return(parent, nil)
	orgRepo.On("Create", ctx, mock.AnythingOfType("*models.Organization")).Return(nil)
	orgRepo.On("GetByID", ctx, mock.AnythingOfType("uuid.UUID")).Return(
		&models.Organization{
			ID:       uuid.New(),
			TenantID: tenantID,
			ParentID: &parentID,
			Name:     "Sub-Team",
		}, nil).Once()

	org, err := svc.CreateOrganization(ctx, tenantID, req, nil)

	require.NoError(t, err)
	require.NotNil(t, org)
	orgRepo.AssertExpectations(t)
}

func TestOrganizationService_Create_InvalidOrgType(t *testing.T) {
	ctx := context.Background()
	orgRepo := new(MockOrgRepo)
	userRepo := new(MockOrgUserRepo)
	svc := newOrgService(orgRepo, userRepo)

	tenantID := uuid.New()
	req := &models.CreateOrganizationRequest{
		Name:    "TestOrg",
		OrgType: "invalid-type",
	}

	orgRepo.On("GetByName", ctx, tenantID, "TestOrg", (*uuid.UUID)(nil)).Return((*models.Organization)(nil), errors.New("not found"))

	org, err := svc.CreateOrganization(ctx, tenantID, req, nil)

	assert.Error(t, err)
	assert.Nil(t, org)
	assert.Contains(t, err.Error(), "invalid organization type")
	orgRepo.AssertExpectations(t)
}

// ---------------------------------------------------------------------------
// Tests: UpdateOrganization
// ---------------------------------------------------------------------------

func TestOrganizationService_Update_Success(t *testing.T) {
	ctx := context.Background()
	orgRepo := new(MockOrgRepo)
	userRepo := new(MockOrgUserRepo)
	svc := newOrgService(orgRepo, userRepo)

	tenantID := uuid.New()
	orgID := uuid.New()

	existing := &models.Organization{
		ID:       orgID,
		TenantID: tenantID,
		Name:     "Old Name",
		OrgType:  models.OrgTypeDepartment,
	}

	newName := testAPIKeyNewName
	req := &models.UpdateOrganizationRequest{
		Name: &newName,
	}

	orgRepo.On("GetByID", ctx, orgID).Return(existing, nil).Once()
	orgRepo.On("GetByName", ctx, tenantID, testAPIKeyNewName, (*uuid.UUID)(nil)).Return((*models.Organization)(nil), errors.New("not found"))
	orgRepo.On("Update", ctx, mock.AnythingOfType("*models.Organization")).Return(nil)
	orgRepo.On("GetByID", ctx, orgID).Return(
		&models.Organization{ID: orgID, TenantID: tenantID, Name: testAPIKeyNewName}, nil).Once()

	org, err := svc.UpdateOrganization(ctx, orgID, req)

	require.NoError(t, err)
	require.NotNil(t, org)
	assert.Equal(t, testAPIKeyNewName, org.Name)
	orgRepo.AssertExpectations(t)
}

func TestOrganizationService_Update_CircularParent(t *testing.T) {
	ctx := context.Background()
	orgRepo := new(MockOrgRepo)
	userRepo := new(MockOrgUserRepo)
	svc := newOrgService(orgRepo, userRepo)

	tenantID := uuid.New()
	orgID := uuid.New()
	childID := uuid.New()

	existing := &models.Organization{
		ID:       orgID,
		TenantID: tenantID,
		Name:     "Parent Org",
	}

	// Attempt to set a descendant as the parent
	req := &models.UpdateOrganizationRequest{
		ParentID: &childID,
	}

	descendant := &models.Organization{ID: childID, TenantID: tenantID}

	orgRepo.On("GetByID", ctx, orgID).Return(existing, nil)
	orgRepo.On("GetDescendants", ctx, orgID).Return([]*models.Organization{descendant}, nil)

	org, err := svc.UpdateOrganization(ctx, orgID, req)

	assert.Error(t, err)
	assert.Nil(t, org)
	assert.Contains(t, err.Error(), "circular")
	orgRepo.AssertExpectations(t)
}

func TestOrganizationService_Update_SelfAsParent(t *testing.T) {
	ctx := context.Background()
	orgRepo := new(MockOrgRepo)
	userRepo := new(MockOrgUserRepo)
	svc := newOrgService(orgRepo, userRepo)

	tenantID := uuid.New()
	orgID := uuid.New()

	existing := &models.Organization{
		ID:       orgID,
		TenantID: tenantID,
		Name:     "Self-loop",
	}

	req := &models.UpdateOrganizationRequest{
		ParentID: &orgID, // same as orgID → self reference
	}

	orgRepo.On("GetByID", ctx, orgID).Return(existing, nil)

	org, err := svc.UpdateOrganization(ctx, orgID, req)

	assert.Error(t, err)
	assert.Nil(t, org)
	assert.Contains(t, err.Error(), "own parent")
	orgRepo.AssertExpectations(t)
}

// ---------------------------------------------------------------------------
// Tests: DeleteOrganization
// ---------------------------------------------------------------------------

func TestOrganizationService_Delete_Success(t *testing.T) {
	ctx := context.Background()
	orgRepo := new(MockOrgRepo)
	userRepo := new(MockOrgUserRepo)
	svc := newOrgService(orgRepo, userRepo)

	orgID := uuid.New()
	existing := &models.Organization{
		ID:          orgID,
		Name:        "Leaf Dept",
		MemberCount: 0,
	}

	orgRepo.On("GetByID", ctx, orgID).Return(existing, nil)
	orgRepo.On("GetChildren", ctx, orgID).Return([]*models.Organization{}, nil)
	orgRepo.On("Delete", ctx, orgID).Return(nil)

	err := svc.DeleteOrganization(ctx, orgID)

	require.NoError(t, err)
	orgRepo.AssertExpectations(t)
}

func TestOrganizationService_Delete_HasChildren(t *testing.T) {
	ctx := context.Background()
	orgRepo := new(MockOrgRepo)
	userRepo := new(MockOrgUserRepo)
	svc := newOrgService(orgRepo, userRepo)

	tenantID := uuid.New()
	orgID := uuid.New()
	childID := uuid.New()

	existing := &models.Organization{
		ID:       orgID,
		TenantID: tenantID,
	}
	child := &models.Organization{ID: childID}

	orgRepo.On("GetByID", ctx, orgID).Return(existing, nil)
	orgRepo.On("GetChildren", ctx, orgID).Return([]*models.Organization{child}, nil)

	err := svc.DeleteOrganization(ctx, orgID)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "child organizations")
	orgRepo.AssertExpectations(t)
}

func TestOrganizationService_Delete_HasMembers(t *testing.T) {
	ctx := context.Background()
	orgRepo := new(MockOrgRepo)
	userRepo := new(MockOrgUserRepo)
	svc := newOrgService(orgRepo, userRepo)

	orgID := uuid.New()
	existing := &models.Organization{
		ID:          orgID,
		Name:        "Full Dept",
		MemberCount: 5, // has members
	}

	orgRepo.On("GetByID", ctx, orgID).Return(existing, nil)
	orgRepo.On("GetChildren", ctx, orgID).Return([]*models.Organization{}, nil)

	err := svc.DeleteOrganization(ctx, orgID)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "members")
	orgRepo.AssertExpectations(t)
}

// ---------------------------------------------------------------------------
// Tests: AddMember
// ---------------------------------------------------------------------------

func TestOrganizationService_AddMember_Success(t *testing.T) {
	ctx := context.Background()
	orgRepo := new(MockOrgRepo)
	userRepo := new(MockOrgUserRepo)
	svc := newOrgService(orgRepo, userRepo)

	tenantID := uuid.New()
	orgID := uuid.New()
	userID := uuid.New()
	addedBy := uuid.New()

	org := &models.Organization{ID: orgID, TenantID: tenantID}
	user := &models.User{ID: userID, TenantID: tenantID}

	req := &models.AddOrgMemberRequest{
		UserID: userID,
		Role:   models.OrgRoleMember,
	}

	orgRepo.On("GetByID", ctx, orgID).Return(org, nil)
	userRepo.On("GetByID", ctx, userID).Return(user, nil)
	orgRepo.On("AddMember", ctx, orgID, userID, models.OrgRoleMember, (*string)(nil), false, &addedBy).Return(nil)

	err := svc.AddMember(ctx, orgID, req, &addedBy)

	require.NoError(t, err)
	orgRepo.AssertExpectations(t)
	userRepo.AssertExpectations(t)
}

func TestOrganizationService_AddMember_InvalidRole(t *testing.T) {
	ctx := context.Background()
	orgRepo := new(MockOrgRepo)
	userRepo := new(MockOrgUserRepo)
	svc := newOrgService(orgRepo, userRepo)

	tenantID := uuid.New()
	orgID := uuid.New()
	userID := uuid.New()

	org := &models.Organization{ID: orgID, TenantID: tenantID}
	user := &models.User{ID: userID, TenantID: tenantID}

	req := &models.AddOrgMemberRequest{
		UserID: userID,
		Role:   "superhero", // invalid role
	}

	orgRepo.On("GetByID", ctx, orgID).Return(org, nil)
	userRepo.On("GetByID", ctx, userID).Return(user, nil)

	err := svc.AddMember(ctx, orgID, req, nil)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid role")
	orgRepo.AssertExpectations(t)
	userRepo.AssertExpectations(t)
}

func TestOrganizationService_AddMember_UserFromDifferentTenant(t *testing.T) {
	ctx := context.Background()
	orgRepo := new(MockOrgRepo)
	userRepo := new(MockOrgUserRepo)
	svc := newOrgService(orgRepo, userRepo)

	tenantID := uuid.New()
	otherTenantID := uuid.New()
	orgID := uuid.New()
	userID := uuid.New()

	org := &models.Organization{ID: orgID, TenantID: tenantID}
	user := &models.User{ID: userID, TenantID: otherTenantID} // different tenant

	req := &models.AddOrgMemberRequest{
		UserID: userID,
		Role:   models.OrgRoleMember,
	}

	orgRepo.On("GetByID", ctx, orgID).Return(org, nil)
	userRepo.On("GetByID", ctx, userID).Return(user, nil)

	err := svc.AddMember(ctx, orgID, req, nil)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "different tenant")
	orgRepo.AssertExpectations(t)
	userRepo.AssertExpectations(t)
}

func TestOrganizationService_AddMember_DefaultRole(t *testing.T) {
	ctx := context.Background()
	orgRepo := new(MockOrgRepo)
	userRepo := new(MockOrgUserRepo)
	svc := newOrgService(orgRepo, userRepo)

	tenantID := uuid.New()
	orgID := uuid.New()
	userID := uuid.New()

	org := &models.Organization{ID: orgID, TenantID: tenantID}
	user := &models.User{ID: userID, TenantID: tenantID}

	// No role specified → should default to "member"
	req := &models.AddOrgMemberRequest{
		UserID: userID,
		Role:   "",
	}

	orgRepo.On("GetByID", ctx, orgID).Return(org, nil)
	userRepo.On("GetByID", ctx, userID).Return(user, nil)
	orgRepo.On("AddMember", ctx, orgID, userID, models.OrgRoleMember, (*string)(nil), false, (*uuid.UUID)(nil)).Return(nil)

	err := svc.AddMember(ctx, orgID, req, nil)

	require.NoError(t, err)
	orgRepo.AssertExpectations(t)
}

// ---------------------------------------------------------------------------
// Tests: RemoveMembers
// ---------------------------------------------------------------------------

func TestOrganizationService_RemoveMembers_Success(t *testing.T) {
	ctx := context.Background()
	orgRepo := new(MockOrgRepo)
	userRepo := new(MockOrgUserRepo)
	svc := newOrgService(orgRepo, userRepo)

	orgID := uuid.New()
	userID1 := uuid.New()
	userID2 := uuid.New()

	orgRepo.On("RemoveMember", ctx, orgID, userID1).Return(nil)
	orgRepo.On("RemoveMember", ctx, orgID, userID2).Return(nil)

	err := svc.RemoveMembers(ctx, orgID, []uuid.UUID{userID1, userID2})

	require.NoError(t, err)
	orgRepo.AssertExpectations(t)
}

// ---------------------------------------------------------------------------
// Tests: GetOrganizationTree
// ---------------------------------------------------------------------------

func TestOrganizationService_GetOrganizationTree_Success(t *testing.T) {
	ctx := context.Background()
	orgRepo := new(MockOrgRepo)
	userRepo := new(MockOrgUserRepo)
	svc := newOrgService(orgRepo, userRepo)

	tenantID := uuid.New()
	rootID := uuid.New()
	childID := uuid.New()

	root := &models.Organization{ID: rootID, TenantID: tenantID, Name: "Root"}
	child := &models.Organization{ID: childID, TenantID: tenantID, Name: "Child", ParentID: &rootID}

	orgRepo.On("GetRootOrganizations", ctx, tenantID).Return([]*models.Organization{root}, nil)
	orgRepo.On("GetChildren", ctx, rootID).Return([]*models.Organization{child}, nil)
	orgRepo.On("GetChildren", ctx, childID).Return([]*models.Organization{}, nil)

	tree, err := svc.GetOrganizationTree(ctx, tenantID)

	require.NoError(t, err)
	require.Len(t, tree, 1)
	assert.Equal(t, "Root", tree[0].Name)
	require.Len(t, tree[0].Children, 1)
	assert.Equal(t, "Child", tree[0].Children[0].Name)
	orgRepo.AssertExpectations(t)
}

func TestOrganizationService_GetOrganizationTree_Empty(t *testing.T) {
	ctx := context.Background()
	orgRepo := new(MockOrgRepo)
	userRepo := new(MockOrgUserRepo)
	svc := newOrgService(orgRepo, userRepo)

	tenantID := uuid.New()
	orgRepo.On("GetRootOrganizations", ctx, tenantID).Return([]*models.Organization{}, nil)

	tree, err := svc.GetOrganizationTree(ctx, tenantID)

	require.NoError(t, err)
	assert.Empty(t, tree)
	orgRepo.AssertExpectations(t)
}

// ---------------------------------------------------------------------------
// Tests: GetMembers
// ---------------------------------------------------------------------------

func TestOrganizationService_GetMembers_Success(t *testing.T) {
	ctx := context.Background()
	orgRepo := new(MockOrgRepo)
	userRepo := new(MockOrgUserRepo)
	svc := newOrgService(orgRepo, userRepo)

	orgID := uuid.New()
	members := []*models.OrgMember{
		{ID: uuid.New(), OrganizationID: orgID, Role: models.OrgRoleMember},
		{ID: uuid.New(), OrganizationID: orgID, Role: models.OrgRoleManager},
	}

	orgRepo.On("GetMembers", ctx, orgID, 1, 20).Return(members, 2, nil)

	result, err := svc.GetMembers(ctx, orgID, 1, 20)

	require.NoError(t, err)
	assert.Len(t, result.Members, 2)
	assert.Equal(t, 2, result.Total)
	assert.Equal(t, 1, result.TotalPages)
	orgRepo.AssertExpectations(t)
}

// ---------------------------------------------------------------------------
// Tests: ListOrganizations
// ---------------------------------------------------------------------------

func TestOrganizationService_List_Success(t *testing.T) {
	ctx := context.Background()
	orgRepo := new(MockOrgRepo)
	userRepo := new(MockOrgUserRepo)
	svc := newOrgService(orgRepo, userRepo)

	tenantID := uuid.New()
	orgs := []*models.Organization{
		makeOrg(tenantID, "Dept A"),
		makeOrg(tenantID, "Dept B"),
	}

	orgRepo.On("List", ctx, tenantID, 1, 20, "", "").Return(orgs, 2, nil)

	result, err := svc.ListOrganizations(ctx, tenantID, 1, 20, "", "")

	require.NoError(t, err)
	assert.Len(t, result.Organizations, 2)
	assert.Equal(t, 2, result.Total)
	assert.Equal(t, 1, result.Page)
	orgRepo.AssertExpectations(t)
}

// ---------------------------------------------------------------------------
// Tests: GetAncestors / GetDescendants
// ---------------------------------------------------------------------------

func TestOrganizationService_GetAncestors_Success(t *testing.T) {
	ctx := context.Background()
	orgRepo := new(MockOrgRepo)
	userRepo := new(MockOrgUserRepo)
	svc := newOrgService(orgRepo, userRepo)

	orgID := uuid.New()
	ancestors := []*models.Organization{
		{ID: uuid.New(), Name: "Grandparent"},
		{ID: uuid.New(), Name: "Parent"},
	}

	orgRepo.On("GetAncestors", ctx, orgID).Return(ancestors, nil)

	result, err := svc.GetAncestors(ctx, orgID)

	require.NoError(t, err)
	assert.Len(t, result, 2)
	orgRepo.AssertExpectations(t)
}

func TestOrganizationService_GetDescendants_Success(t *testing.T) {
	ctx := context.Background()
	orgRepo := new(MockOrgRepo)
	userRepo := new(MockOrgUserRepo)
	svc := newOrgService(orgRepo, userRepo)

	orgID := uuid.New()
	descendants := []*models.Organization{
		{ID: uuid.New(), Name: "Child"},
		{ID: uuid.New(), Name: "Grandchild"},
	}

	orgRepo.On("GetDescendants", ctx, orgID).Return(descendants, nil)

	result, err := svc.GetDescendants(ctx, orgID)

	require.NoError(t, err)
	assert.Len(t, result, 2)
	orgRepo.AssertExpectations(t)
}

// ---------------------------------------------------------------------------
// Tests: GetOrgTypes / GetOrgRoles
// ---------------------------------------------------------------------------

func TestOrganizationService_GetOrgTypes(t *testing.T) {
	orgRepo := new(MockOrgRepo)
	userRepo := new(MockOrgUserRepo)
	svc := newOrgService(orgRepo, userRepo)

	types := svc.GetOrgTypes()

	assert.Contains(t, types, models.OrgTypeDepartment)
	assert.Contains(t, types, models.OrgTypeTeam)
	assert.Contains(t, types, models.OrgTypeCompany)
}

func TestOrganizationService_GetOrgRoles(t *testing.T) {
	orgRepo := new(MockOrgRepo)
	userRepo := new(MockOrgUserRepo)
	svc := newOrgService(orgRepo, userRepo)

	roles := svc.GetOrgRoles()

	assert.Contains(t, roles, models.OrgRoleMember)
	assert.Contains(t, roles, models.OrgRoleManager)
	assert.Contains(t, roles, models.OrgRoleOwner)
}

// ---------------------------------------------------------------------------
// Tests: UpdateMember
// ---------------------------------------------------------------------------

func TestOrganizationService_UpdateMember_Success(t *testing.T) {
	ctx := context.Background()
	orgRepo := new(MockOrgRepo)
	userRepo := new(MockOrgUserRepo)
	svc := newOrgService(orgRepo, userRepo)

	orgID := uuid.New()
	userID := uuid.New()

	newRole := models.OrgRoleManager
	req := &models.UpdateOrgMemberRequest{
		Role: &newRole,
	}

	orgRepo.On("UpdateMember", ctx, orgID, userID, &newRole, (*string)(nil), (*bool)(nil)).Return(nil)

	err := svc.UpdateMember(ctx, orgID, userID, req)

	require.NoError(t, err)
	orgRepo.AssertExpectations(t)
}

func TestOrganizationService_UpdateMember_InvalidRole(t *testing.T) {
	ctx := context.Background()
	orgRepo := new(MockOrgRepo)
	userRepo := new(MockOrgUserRepo)
	svc := newOrgService(orgRepo, userRepo)

	orgID := uuid.New()
	userID := uuid.New()

	badRole := "invalidrole"
	req := &models.UpdateOrgMemberRequest{
		Role: &badRole,
	}

	err := svc.UpdateMember(ctx, orgID, userID, req)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid role")
}

// ---------------------------------------------------------------------------
// Tests: AddMembers (bulk)
// ---------------------------------------------------------------------------

func TestOrganizationService_AddMembers_SkipsInvalidUsers(t *testing.T) {
	ctx := context.Background()
	orgRepo := new(MockOrgRepo)
	userRepo := new(MockOrgUserRepo)
	svc := newOrgService(orgRepo, userRepo)

	tenantID := uuid.New()
	orgID := uuid.New()
	addedBy := uuid.New()

	validUserID := uuid.New()
	missingUserID := uuid.New()

	org := &models.Organization{ID: orgID, TenantID: tenantID}
	validUser := &models.User{ID: validUserID, TenantID: tenantID}

	req := &models.AddOrgMembersRequest{
		UserIDs: []uuid.UUID{validUserID, missingUserID},
		Role:    models.OrgRoleMember,
	}

	orgRepo.On("GetByID", ctx, orgID).Return(org, nil)
	userRepo.On("GetByID", ctx, validUserID).Return(validUser, nil)
	userRepo.On("GetByID", ctx, missingUserID).Return((*models.User)(nil), errors.New("not found"))
	orgRepo.On("AddMember", ctx, orgID, validUserID, models.OrgRoleMember, (*string)(nil), false, &addedBy).Return(nil)

	// Should succeed — invalid users are silently skipped
	err := svc.AddMembers(ctx, orgID, req, &addedBy)

	require.NoError(t, err)
	orgRepo.AssertExpectations(t)
	userRepo.AssertExpectations(t)
}

// ---------------------------------------------------------------------------
// Tests: GetUserOrganizations / GetUserPrimaryOrganization
// ---------------------------------------------------------------------------

func TestOrganizationService_GetUserOrganizations(t *testing.T) {
	ctx := context.Background()
	orgRepo := new(MockOrgRepo)
	userRepo := new(MockOrgUserRepo)
	svc := newOrgService(orgRepo, userRepo)

	userID := uuid.New()
	orgID1 := uuid.New()
	orgID2 := uuid.New()

	memberships := []*models.OrgMember{
		{OrganizationID: orgID1, UserID: userID},
		{OrganizationID: orgID2, UserID: userID},
	}

	orgRepo.On("GetUserOrganizations", ctx, userID).Return(memberships, nil)

	result, err := svc.GetUserOrganizations(ctx, userID)

	require.NoError(t, err)
	assert.Len(t, result, 2)
	orgRepo.AssertExpectations(t)
}

func TestOrganizationService_GetUserPrimaryOrganization(t *testing.T) {
	ctx := context.Background()
	orgRepo := new(MockOrgRepo)
	userRepo := new(MockOrgUserRepo)
	svc := newOrgService(orgRepo, userRepo)

	userID := uuid.New()
	orgID := uuid.New()

	primaryMembership := &models.OrgMember{
		OrganizationID: orgID,
		UserID:         userID,
		IsPrimary:      true,
	}

	orgRepo.On("GetUserPrimaryOrganization", ctx, userID).Return(primaryMembership, nil)

	result, err := svc.GetUserPrimaryOrganization(ctx, userID)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, result.IsPrimary)
	orgRepo.AssertExpectations(t)
}

// ---------------------------------------------------------------------------
// Tests: GetOrganizationWithDetails
// ---------------------------------------------------------------------------

func TestOrganizationService_GetOrganizationWithDetails_Success(t *testing.T) {
	ctx := context.Background()
	orgRepo := new(MockOrgRepo)
	userRepo := new(MockOrgUserRepo)
	svc := newOrgService(orgRepo, userRepo)

	tenantID := uuid.New()
	parentID := uuid.New()
	orgID := uuid.New()
	childID := uuid.New()

	org := &models.Organization{
		ID:       orgID,
		TenantID: tenantID,
		Name:     "My Org",
		ParentID: &parentID,
	}
	parent := &models.Organization{ID: parentID, Name: "Parent"}
	child := &models.Organization{ID: childID, Name: "Child"}
	ancestors := []*models.Organization{{ID: parentID, Name: "Parent"}}

	orgRepo.On("GetByID", ctx, orgID).Return(org, nil)
	orgRepo.On("GetAncestors", ctx, orgID).Return(ancestors, nil)
	orgRepo.On("GetChildren", ctx, orgID).Return([]*models.Organization{child}, nil)
	orgRepo.On("GetByID", ctx, parentID).Return(parent, nil)

	result, err := svc.GetOrganizationWithDetails(ctx, orgID)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Len(t, result.Ancestors, 1)
	assert.Len(t, result.Children, 1)
	assert.NotNil(t, result.Parent)
	orgRepo.AssertExpectations(t)
}

// ---------------------------------------------------------------------------
// Tests: Create with parent from different tenant
// ---------------------------------------------------------------------------

func TestOrganizationService_Create_ParentDifferentTenant(t *testing.T) {
	ctx := context.Background()
	orgRepo := new(MockOrgRepo)
	userRepo := new(MockOrgUserRepo)
	svc := newOrgService(orgRepo, userRepo)

	tenantID := uuid.New()
	otherTenantID := uuid.New()
	parentID := uuid.New()

	// Parent belongs to different tenant
	parent := &models.Organization{
		ID:       parentID,
		TenantID: otherTenantID,
		Name:     "Foreign Parent",
	}

	req := &models.CreateOrganizationRequest{
		Name:     "Child",
		OrgType:  models.OrgTypeDepartment,
		ParentID: &parentID,
	}

	orgRepo.On("GetByName", ctx, tenantID, "Child", &parentID).Return((*models.Organization)(nil), errors.New("not found"))
	orgRepo.On("GetByID", ctx, parentID).Return(parent, nil)

	org, err := svc.CreateOrganization(ctx, tenantID, req, nil)

	assert.Error(t, err)
	assert.Nil(t, org)
	assert.Contains(t, err.Error(), "different tenant")
	orgRepo.AssertExpectations(t)
}
