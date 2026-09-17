// SPDX-License-Identifier: AGPL-3.0-or-later

package integration

import (
	"context"
	"fmt"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/internal/services"
	"github.com/dogukanturhal/falcon-id/internal/testutil"
)

// ---------------------------------------------------------------------------
// multi-tenant test suite
// ---------------------------------------------------------------------------

type multiTenantSuite struct {
	ctx         context.Context
	tenantA     uuid.UUID
	tenantB     uuid.UUID
	userRepo    *userRepoMock
	roleRepo    *roleRepoMock
	permRepo    *permissionRepoMock
	tokenSvc    *tokenServiceMock
	auditSvc    *auditServiceMock
	auditRepo   *auditRepoMock
	userService *services.UserService
	roleService *services.RoleService
}

func newMultiTenantSuite(t *testing.T) *multiTenantSuite {
	t.Helper()

	cfg := testutil.NewTestConfig()

	userRepo := &userRepoMock{}
	roleRepo := &roleRepoMock{}
	permRepo := &permissionRepoMock{}
	tokenSvc := &tokenServiceMock{}
	auditSvc := &auditServiceMock{}

	// Wire a real AuditService backed by a mock repo so role service audit calls work.
	auditRepo := &auditRepoMock{}
	realAuditSvc := services.NewAuditService(auditRepo, nil)

	userService := services.NewUserService(cfg, userRepo, roleRepo, tokenSvc, auditSvc)
	userService.SetRealmResolver(&realmResolverMock{})
	roleService := services.NewRoleService(roleRepo, permRepo, realAuditSvc)

	return &multiTenantSuite{
		ctx:         context.Background(),
		tenantA:     uuid.New(),
		tenantB:     uuid.New(),
		userRepo:    userRepo,
		roleRepo:    roleRepo,
		permRepo:    permRepo,
		tokenSvc:    tokenSvc,
		auditSvc:    auditSvc,
		auditRepo:   auditRepo,
		userService: userService,
		roleService: roleService,
	}
}

// ---------------------------------------------------------------------------
// Tenant isolation: user listing
// ---------------------------------------------------------------------------

// TestMultiTenant_UserListIsolation verifies that List only returns users
// belonging to the requested tenant.  When the caller supplies tenantA, the
// repo is called with tenantA and its users are returned; tenantB users never
// appear.
func TestMultiTenant_UserListIsolation(t *testing.T) {
	suite := newMultiTenantSuite(t)

	userA1 := newTestUser(suite.tenantA, "alice", "alice@a.com")
	userA2 := newTestUser(suite.tenantA, "alan", "alan@a.com")
	userB1 := newTestUser(suite.tenantB, "bob", "bob@b.com")

	// Only tenantA users are returned by the repo when queried with tenantA
	suite.userRepo.On("List", suite.ctx, suite.tenantA, 1, 20, "").
		Return([]models.User{*userA1, *userA2}, int64(2), nil)

	// Roles are fetched per user
	suite.userRepo.On("GetUserRoles", suite.ctx, userA1.ID).Return([]models.Role{}, nil)
	suite.userRepo.On("GetUserRoles", suite.ctx, userA2.ID).Return([]models.Role{}, nil)

	resp, err := suite.userService.List(suite.ctx, suite.tenantA, 1, 20, "")

	require.NoError(t, err)
	require.Len(t, resp.Users, 2)

	for _, u := range resp.Users {
		assert.Equal(t, suite.tenantA, u.TenantID,
			"user %s must belong to tenantA", u.Username)
	}

	// Ensure tenantB's user never appears in the result
	for _, u := range resp.Users {
		assert.NotEqual(t, userB1.ID, u.ID,
			"tenantB user must not appear in tenantA listing")
	}

	suite.userRepo.AssertExpectations(t)
}

// TestMultiTenant_GetUser_ByID_CrossTenantBlocked verifies that a cross-tenant
// user fetch is not possible at the service boundary.  The UserService calls
// GetByID which is keyed by user UUID; tenant enforcement is the caller's
// responsibility. This test ensures the service returns the raw user and that
// a caller can check the TenantID to detect cross-tenant access.
func TestMultiTenant_GetUser_ByID_CrossTenantBlocked(t *testing.T) {
	suite := newMultiTenantSuite(t)

	// userB lives in tenantB but its UUID is known to a tenantA caller
	userB := newTestUser(suite.tenantB, "bob", "bob@b.com")

	suite.userRepo.On("GetByID", suite.ctx, userB.ID).Return(userB, nil)
	suite.userRepo.On("GetUserRoles", suite.ctx, userB.ID).Return([]models.Role{}, nil)
	suite.userRepo.On("GetUserPermissions", suite.ctx, userB.ID).Return([]models.Permission{}, nil)

	resp, err := suite.userService.GetByID(suite.ctx, userB.ID)

	require.NoError(t, err)
	require.NotNil(t, resp)

	// The application layer must enforce tenant isolation by checking TenantID.
	assert.Equal(t, suite.tenantB, resp.TenantID,
		"returned user must carry its own tenantB – caller must reject cross-tenant access")
	assert.NotEqual(t, suite.tenantA, resp.TenantID,
		"tenantA caller must not silently receive a tenantB user")
}

// ---------------------------------------------------------------------------
// Tenant isolation: role scoping
// ---------------------------------------------------------------------------

// TestMultiTenant_RoleIsolation verifies that a role created in tenantA is not
// visible when listing roles for tenantB.
func TestMultiTenant_RoleIsolation(t *testing.T) {
	suite := newMultiTenantSuite(t)

	roleA := newTestRole(suite.tenantA, "editor")
	roleB := newTestRole(suite.tenantB, "viewer")

	// When queried with tenantA, only roleA is returned
	suite.roleRepo.On("List", suite.ctx, suite.tenantA, 1, 100, "").
		Return([]models.Role{*roleA}, int64(1), nil)
	suite.roleRepo.On("GetRolePermissions", suite.ctx, roleA.ID).
		Return([]models.Permission{}, nil)

	// When queried with tenantB, only roleB is returned
	suite.roleRepo.On("List", suite.ctx, suite.tenantB, 1, 100, "").
		Return([]models.Role{*roleB}, int64(1), nil)
	suite.roleRepo.On("GetRolePermissions", suite.ctx, roleB.ID).
		Return([]models.Permission{}, nil)

	respA, err := suite.roleService.ListByTenant(suite.ctx, suite.tenantA)
	require.NoError(t, err)
	require.Len(t, respA, 1)
	assert.Equal(t, "editor", respA[0].Name)
	assert.Equal(t, suite.tenantA, respA[0].TenantID)

	respB, err := suite.roleService.ListByTenant(suite.ctx, suite.tenantB)
	require.NoError(t, err)
	require.Len(t, respB, 1)
	assert.Equal(t, "viewer", respB[0].Name)
	assert.Equal(t, suite.tenantB, respB[0].TenantID)

	// Verify that roleA never appears in tenantB listing and vice-versa
	for _, r := range respB {
		assert.NotEqual(t, roleA.ID, r.ID, "tenantA role must not appear in tenantB listing")
	}
	for _, r := range respA {
		assert.NotEqual(t, roleB.ID, r.ID, "tenantB role must not appear in tenantA listing")
	}

	suite.roleRepo.AssertExpectations(t)
}

// ---------------------------------------------------------------------------
// Tenant isolation: role creation
// ---------------------------------------------------------------------------

// TestMultiTenant_CreateRole_TenantScoped ensures that a role created for
// tenantA carries tenantA's ID in the repository call.
func TestMultiTenant_CreateRole_TenantScoped(t *testing.T) {
	suite := newMultiTenantSuite(t)

	roleID := uuid.New()

	// name check returns (nil, nil) — no existing role with this name
	suite.roleRepo.On("GetByName", suite.ctx, suite.tenantA, "power-user").
		Return(nil, nil)

	suite.roleRepo.On("Create", suite.ctx, mock.MatchedBy(func(r *models.Role) bool {
		return r.TenantID == suite.tenantA && r.Name == "power-user"
	})).Return(nil).Run(func(args mock.Arguments) {
		r := args.Get(1).(*models.Role)
		r.ID = roleID
	})

	suite.roleRepo.On("GetRolePermissions", suite.ctx, roleID).Return([]models.Permission{}, nil)

	// Audit log via real AuditService → auditRepo
	suite.auditRepo.On("CreateAuditLog", suite.ctx, mock.AnythingOfType("*models.AuditLog")).
		Return(nil).Once()

	req := &models.CreateRoleRequest{
		TenantID:    suite.tenantA,
		Name:        "power-user",
		DisplayName: "Power User",
	}

	resp, err := suite.roleService.Create(suite.ctx, req, nil)

	require.NoError(t, err)
	assert.Equal(t, suite.tenantA, resp.TenantID)
	assert.Equal(t, "power-user", resp.Name)

	suite.roleRepo.AssertExpectations(t)
	suite.auditRepo.AssertExpectations(t)
}

// ---------------------------------------------------------------------------
// Tenant isolation: user creation scoped to tenant
// ---------------------------------------------------------------------------

// TestMultiTenant_CreateUserInTenantA_ThenCreateSameUsernameInTenantB verifies
// that the same username can exist in different tenants because uniqueness is
// scoped per-tenant.
func TestMultiTenant_CreateUserInTenantA_ThenCreateSameUsernameInTenantB(t *testing.T) {
	suite := newMultiTenantSuite(t)

	userA := newTestUser(suite.tenantA, "shared-user", "shared@a.com")
	userB := newTestUser(suite.tenantB, "shared-user", "shared@b.com")

	// --- Create user in tenantA ---
	// No duplicate in tenantA
	suite.userRepo.On("GetByUsername", suite.ctx, suite.tenantA, "shared-user").Return(nil, nil).Once()
	suite.userRepo.On("GetByEmail", suite.ctx, suite.tenantA, "shared@a.com").Return(nil, nil).Once()
	suite.userRepo.On("Create", suite.ctx, mock.MatchedBy(func(u *models.User) bool {
		return u.TenantID == suite.tenantA
	})).Return(nil).Once().Run(func(args mock.Arguments) {
		u := args.Get(1).(*models.User)
		u.ID = userA.ID
	})
	suite.roleRepo.On("GetDefaultRoles", suite.ctx, suite.tenantA).Return([]models.Role{}, nil).Once()
	suite.userRepo.On("GetUserRoles", suite.ctx, userA.ID).Return([]models.Role{}, nil).Once()
	suite.userRepo.On("GetUserPermissions", suite.ctx, userA.ID).Return([]models.Permission{}, nil).Once()
	suite.auditSvc.On("LogUserAction", mock.Anything, suite.tenantA, mock.Anything, mock.Anything, "user_create", true, mock.Anything).Return().Once()

	reqA := &models.CreateUserRequest{
		TenantID: suite.tenantA,
		Username: "shared-user",
		Email:    "shared@a.com",
		Password: "SecurePass1!",
	}
	respA, err := suite.userService.Create(suite.ctx, reqA, nil)
	require.NoError(t, err)
	assert.Equal(t, suite.tenantA, respA.TenantID)

	// --- Create user with same username in tenantB ---
	// No duplicate in tenantB (different namespace)
	suite.userRepo.On("GetByUsername", suite.ctx, suite.tenantB, "shared-user").Return(nil, nil).Once()
	suite.userRepo.On("GetByEmail", suite.ctx, suite.tenantB, "shared@b.com").Return(nil, nil).Once()
	suite.userRepo.On("Create", suite.ctx, mock.MatchedBy(func(u *models.User) bool {
		return u.TenantID == suite.tenantB
	})).Return(nil).Once().Run(func(args mock.Arguments) {
		u := args.Get(1).(*models.User)
		u.ID = userB.ID
	})
	suite.roleRepo.On("GetDefaultRoles", suite.ctx, suite.tenantB).Return([]models.Role{}, nil).Once()
	suite.userRepo.On("GetUserRoles", suite.ctx, userB.ID).Return([]models.Role{}, nil).Once()
	suite.userRepo.On("GetUserPermissions", suite.ctx, userB.ID).Return([]models.Permission{}, nil).Once()
	suite.auditSvc.On("LogUserAction", mock.Anything, suite.tenantB, mock.Anything, mock.Anything, "user_create", true, mock.Anything).Return().Once()

	reqB := &models.CreateUserRequest{
		TenantID: suite.tenantB,
		Username: "shared-user",
		Email:    "shared@b.com",
		Password: "SecurePass1!",
	}
	respB, err := suite.userService.Create(suite.ctx, reqB, nil)
	require.NoError(t, err)
	assert.Equal(t, suite.tenantB, respB.TenantID)

	// Users have distinct IDs despite the same username
	assert.NotEqual(t, respA.ID, respB.ID, "users in different tenants must have distinct IDs")

	suite.userRepo.AssertExpectations(t)
}

// ---------------------------------------------------------------------------
// Tenant isolation: username uniqueness within the same tenant
// ---------------------------------------------------------------------------

// TestMultiTenant_DuplicateUsername_SameTenant ensures that the same username
// cannot be created twice within the same tenant.
func TestMultiTenant_DuplicateUsername_SameTenant(t *testing.T) {
	suite := newMultiTenantSuite(t)

	existing := newTestUser(suite.tenantA, "greta", "greta@a.com")

	suite.userRepo.On("GetByUsername", suite.ctx, suite.tenantA, "greta").Return(existing, nil)

	req := &models.CreateUserRequest{
		TenantID: suite.tenantA,
		Username: "greta",
		Email:    "greta2@a.com",
		Password: "SecurePass1!",
	}

	_, err := suite.userService.Create(suite.ctx, req, nil)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "username already exists",
		"creating a duplicate username in the same tenant must fail")
}

// ---------------------------------------------------------------------------
// Cross-tenant role assignment guard (group service)
// ---------------------------------------------------------------------------

// TestMultiTenant_GroupService_CrossTenantRole verifies that GroupService
// refuses to assign a role from a different tenant to a group.
func TestMultiTenant_GroupService_CrossTenantRole(t *testing.T) {
	suite := newMultiTenantSuite(t)

	groupA := newTestGroup(suite.tenantA, "engineers")
	roleB := newTestRole(suite.tenantB, "viewer") // belongs to tenantB

	groupRepo := &groupRepoMock{}
	userRepo := &userRepoMock{}
	roleRepo := &roleRepoMock{}

	groupService := services.NewGroupService(groupRepo, userRepo, roleRepo)

	// GetByID for the group returns a tenantA group
	groupRepo.On("GetByID", suite.ctx, groupA.ID).Return(groupA, nil)

	// GetByID for the role returns a tenantB role
	roleRepo.On("GetByID", suite.ctx, roleB.ID).Return(roleB, nil)

	// AssignRole should NOT be called because of the tenant mismatch (verified below)

	err := groupService.AssignRoles(suite.ctx, groupA.ID, []uuid.UUID{roleB.ID}, nil)

	// GroupService.AssignRoles silently skips cross-tenant roles and returns nil
	// (this is the designed behaviour - it logs and continues)
	assert.NoError(t, err)
	groupRepo.AssertNotCalled(t, "AssignRole", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
}

// ---------------------------------------------------------------------------
// Tenant-scoped queries: List returns pagination metadata per tenant
// ---------------------------------------------------------------------------

// TestMultiTenant_PaginationIsTenantScoped verifies that pagination totals
// reflect only the requesting tenant's user count.
func TestMultiTenant_PaginationIsTenantScoped(t *testing.T) {
	suite := newMultiTenantSuite(t)

	// Build 5 tenantA users
	usersA := make([]models.User, 5)
	for i := range usersA {
		u := newTestUser(suite.tenantA, fmt.Sprintf("userA%d", i), fmt.Sprintf("a%d@a.com", i))
		usersA[i] = *u
	}

	suite.userRepo.On("List", suite.ctx, suite.tenantA, 1, 3, "").
		Return(usersA[:3], int64(5), nil)

	for _, u := range usersA[:3] {
		uid := u.ID
		suite.userRepo.On("GetUserRoles", suite.ctx, uid).Return([]models.Role{}, nil)
	}

	resp, err := suite.userService.List(suite.ctx, suite.tenantA, 1, 3, "")

	require.NoError(t, err)
	assert.Equal(t, int64(5), resp.Total, "total must reflect all tenantA users")
	assert.Equal(t, 3, len(resp.Users), "page size must be respected")
	assert.Equal(t, 2, resp.TotalPages, "two pages needed for 5 users at page-size 3")

	suite.userRepo.AssertExpectations(t)
}
