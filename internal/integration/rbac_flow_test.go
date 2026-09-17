// SPDX-License-Identifier: AGPL-3.0-or-later

package integration

import (
	"context"
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
// wireRBACServices builds a minimal, fully-wired set of RBAC services.
// ---------------------------------------------------------------------------

type rbacSuite struct {
	ctx         context.Context
	tenantID    uuid.UUID
	userRepo    *userRepoMock
	roleRepo    *roleRepoMock
	permRepo    *permissionRepoMock
	tokenSvc    *tokenServiceMock
	auditSvc    *auditServiceMock
	auditRepo   *auditRepoMock
	userService *services.UserService
	roleService *services.RoleService
}

func newRBACsuite(t *testing.T) *rbacSuite {
	t.Helper()

	cfg := testutil.NewTestConfig()
	tenantID := uuid.New()

	userRepo := &userRepoMock{}
	roleRepo := &roleRepoMock{}
	permRepo := &permissionRepoMock{}
	tokenSvc := &tokenServiceMock{}
	auditSvc := &auditServiceMock{}

	// Wire a real AuditService (with a mock repo) so RoleService audit calls work.
	auditRepo := &auditRepoMock{}
	realAuditSvc := services.NewAuditService(auditRepo, nil) // nil pool is ok for log-only calls

	userService := services.NewUserService(cfg, userRepo, roleRepo, tokenSvc, auditSvc)
	userService.SetRealmResolver(&realmResolverMock{})
	roleService := services.NewRoleService(roleRepo, permRepo, realAuditSvc)

	return &rbacSuite{
		ctx:         context.Background(),
		tenantID:    tenantID,
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
// RoleService-only tests (audit-free path via nil AuditService)
// ---------------------------------------------------------------------------

// TestRBAC_CreateRole_WithPermissions verifies that creating a role via
// RoleService triggers a Create call and then an AssignPermissions call on
// the role repository.
func TestRBAC_CreateRole_WithPermissions(t *testing.T) {
	suite := newRBACsuite(t)

	perm := newTestPermission("crm", "contacts", "read")
	role := newTestRole(suite.tenantID, "crm-viewer")

	// "name does not exist yet" check — must return (nil, nil) so RoleService
	// knows the name is available (an error is treated as a lookup failure).
	suite.roleRepo.On("GetByName", suite.ctx, suite.tenantID, "crm-viewer").
		Return(nil, nil).Once()

	// The Create call mutates role.ID inside the mock helper
	suite.roleRepo.On("Create", suite.ctx, mock.AnythingOfType("*models.Role")).
		Return(nil).Once().
		Run(func(args mock.Arguments) {
			r := args.Get(1).(*models.Role)
			r.ID = role.ID // assign the pre-generated ID
		})

	// Permissions assigned after creation
	suite.roleRepo.On("AssignPermissions", suite.ctx, role.ID, []uuid.UUID{perm.ID}, (*uuid.UUID)(nil)).
		Return(nil).Once()

	// GetRolePermissions called to build the response
	suite.roleRepo.On("GetRolePermissions", suite.ctx, role.ID).
		Return([]models.Permission{*perm}, nil).Once()

	// Audit log (via the real AuditService → auditRepo.CreateAuditLog)
	suite.auditRepo.On("CreateAuditLog", suite.ctx, mock.AnythingOfType("*models.AuditLog")).
		Return(nil).Once()

	req := &models.CreateRoleRequest{
		TenantID:      suite.tenantID,
		Name:          "crm-viewer",
		DisplayName:   "CRM Viewer",
		PermissionIDs: []uuid.UUID{perm.ID},
	}

	resp, err := suite.roleService.Create(suite.ctx, req, nil)

	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, "crm-viewer", resp.Name)
	assert.Len(t, resp.Permissions, 1)
	assert.Equal(t, "crm:contacts:read", resp.Permissions[0].Name)

	suite.roleRepo.AssertExpectations(t)
	suite.auditRepo.AssertExpectations(t)
}

// TestRBAC_AssignRoleToUser verifies the full assign-role-to-user flow using
// UserService: role existence check → AssignRoles call → response reflects new role.
func TestRBAC_AssignRoleToUser(t *testing.T) {
	suite := newRBACsuite(t)

	user := newTestUser(suite.tenantID, "alice", "alice@example.com")
	role := newTestRole(suite.tenantID, "editor")
	perm := newTestPermission("docs", "document", "write")
	role.Permissions = []models.Permission{*perm}

	// SetUserRoles: verify user exists
	suite.userRepo.On("GetByID", suite.ctx, user.ID).Return(user, nil)

	// SetUserRoles: verify role exists AND belongs to user's tenant (C-4)
	suite.roleRepo.On("GetByIDAndTenant", suite.ctx, role.ID, suite.tenantID).Return(role, nil)

	// Existing roles before update (empty)
	suite.userRepo.On("GetUserRoles", suite.ctx, user.ID).Return([]models.Role{}, nil)

	// AssignRoles persists
	suite.userRepo.On("AssignRoles", suite.ctx, user.ID, []uuid.UUID{role.ID}, (*uuid.UUID)(nil)).
		Return(nil)

	// Second GetByID for event publishing path
	suite.userRepo.On("GetByID", suite.ctx, user.ID).Return(user, nil)

	err := suite.userService.SetUserRoles(suite.ctx, user.ID, []uuid.UUID{role.ID}, nil)

	require.NoError(t, err)
	suite.userRepo.AssertExpectations(t)
	suite.roleRepo.AssertExpectations(t)
}

// TestRBAC_VerifyUserHasPermissions tests that after assigning a role the user
// inherits the role's permissions via GetUserPermissions.
func TestRBAC_VerifyUserHasPermissions(t *testing.T) {
	suite := newRBACsuite(t)

	user := newTestUser(suite.tenantID, "bob", "bob@example.com")
	perm := newTestPermission("crm", "contacts", "write")

	suite.userRepo.On("GetUserPermissions", suite.ctx, user.ID).
		Return([]models.Permission{*perm}, nil)

	perms, err := suite.userService.GetUserPermissions(suite.ctx, user.ID)

	require.NoError(t, err)
	require.Len(t, perms, 1)
	assert.Equal(t, "crm:contacts:write", perms[0].Name)

	suite.userRepo.AssertExpectations(t)
}

// TestRBAC_RemoveRole_PermissionsRevoked verifies that after a role is deleted
// from RoleService the delete propagates to the repo.
func TestRBAC_RemoveRole_PermissionsRevoked(t *testing.T) {
	suite := newRBACsuite(t)

	role := newTestRole(suite.tenantID, "temp-role")

	// Delete path: GetByID then Delete
	suite.roleRepo.On("GetByID", suite.ctx, role.ID).Return(role, nil)
	suite.roleRepo.On("Delete", suite.ctx, role.ID).Return(nil)

	// Audit log emitted after successful deletion
	suite.auditRepo.On("CreateAuditLog", suite.ctx, mock.AnythingOfType("*models.AuditLog")).
		Return(nil).Once()

	err := suite.roleService.Delete(suite.ctx, role.ID, nil)

	require.NoError(t, err)
	suite.roleRepo.AssertExpectations(t)
	suite.auditRepo.AssertExpectations(t)
}

// TestRBAC_RemoveRole_SystemRoleBlocked ensures system roles cannot be deleted.
func TestRBAC_RemoveRole_SystemRoleBlocked(t *testing.T) {
	suite := newRBACsuite(t)

	systemRole := newTestRole(suite.tenantID, "admin")
	systemRole.IsSystem = true

	suite.roleRepo.On("GetByID", suite.ctx, systemRole.ID).Return(systemRole, nil)

	err := suite.roleService.Delete(suite.ctx, systemRole.ID, nil)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "cannot delete system role")
	// Delete should NOT be called
	suite.roleRepo.AssertNotCalled(t, "Delete", mock.Anything, mock.Anything)
}

// ---------------------------------------------------------------------------
// UserService CRUD lifecycle
// ---------------------------------------------------------------------------

// TestRBAC_CreateUser_ThenGetWithRoles exercises Create → GetByID → GetUserRoles.
func TestRBAC_CreateUser_ThenGetWithRoles(t *testing.T) {
	suite := newRBACsuite(t)

	tenantID := suite.tenantID
	role := newTestRole(tenantID, "viewer")

	req := &models.CreateUserRequest{
		TenantID: tenantID,
		Username: "charlie",
		Email:    "charlie@example.com",
		Password: "SecurePass1!",
	}

	createdUser := newTestUser(tenantID, "charlie", "charlie@example.com")

	// Duplicate checks
	suite.userRepo.On("GetByUsername", suite.ctx, tenantID, "charlie").Return(nil, nil)
	suite.userRepo.On("GetByEmail", suite.ctx, tenantID, "charlie@example.com").Return(nil, nil)

	// Create
	suite.userRepo.On("Create", suite.ctx, mock.AnythingOfType("*models.User")).
		Return(nil).Run(func(args mock.Arguments) {
		u := args.Get(1).(*models.User)
		u.ID = createdUser.ID
	})

	// No explicit role IDs → default role lookup
	suite.roleRepo.On("GetDefaultRoles", suite.ctx, tenantID).Return([]models.Role{}, nil)

	// GetUserRoles and GetUserPermissions for response
	suite.userRepo.On("GetUserRoles", suite.ctx, createdUser.ID).Return([]models.Role{*role}, nil)
	suite.userRepo.On("GetUserPermissions", suite.ctx, createdUser.ID).Return([]models.Permission{}, nil)

	// Audit
	suite.auditSvc.On("LogUserAction", suite.ctx, tenantID, (*uuid.UUID)(nil), mock.Anything, "user_create", true, mock.Anything).Return()

	resp, err := suite.userService.Create(suite.ctx, req, nil)

	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, "charlie", resp.Username)
	assert.Equal(t, "charlie@example.com", resp.Email)

	suite.userRepo.AssertExpectations(t)
	suite.auditSvc.AssertExpectations(t)
}

// TestRBAC_CreateUser_DuplicateUsername verifies the duplicate-username guard.
func TestRBAC_CreateUser_DuplicateUsername(t *testing.T) {
	suite := newRBACsuite(t)

	existing := newTestUser(suite.tenantID, "dave", "dave@example.com")

	suite.userRepo.On("GetByUsername", suite.ctx, suite.tenantID, "dave").
		Return(existing, nil)

	req := &models.CreateUserRequest{
		TenantID: suite.tenantID,
		Username: "dave",
		Email:    "dave-new@example.com",
		Password: "SecurePass1!",
	}

	_, err := suite.userService.Create(suite.ctx, req, nil)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "username already exists")
}

// TestRBAC_LockAndUnlockUser exercises Lock → Unlock on UserService.
func TestRBAC_LockAndUnlockUser(t *testing.T) {
	suite := newRBACsuite(t)

	user := newTestUser(suite.tenantID, "eve", "eve@example.com")
	adminID := uuid.New()

	// Lock path
	suite.userRepo.On("GetByID", suite.ctx, user.ID).Return(user, nil).Once()
	suite.userRepo.On("Update", suite.ctx, mock.AnythingOfType("*models.User")).Return(nil).Once()
	suite.auditSvc.On("LogUserAction", suite.ctx, suite.tenantID, &adminID, &user.ID, "user_lock", true, mock.Anything).Return()

	err := suite.userService.Lock(suite.ctx, user.ID, "policy violation", &adminID)
	require.NoError(t, err)

	// Unlock path
	suite.userRepo.On("UnlockUser", suite.ctx, user.ID).Return(nil)
	suite.userRepo.On("GetByID", suite.ctx, user.ID).Return(user, nil).Once()
	suite.auditSvc.On("LogUserAction", suite.ctx, suite.tenantID, &adminID, &user.ID, "user_unlock", true, mock.Anything).Return()

	err = suite.userService.Unlock(suite.ctx, user.ID, &adminID)
	require.NoError(t, err)

	suite.userRepo.AssertExpectations(t)
}

// TestRBAC_SetPassword_ValidatesPolicy verifies that SetPassword enforces the
// configured password policy (minimum length, upper, lower, digit).
func TestRBAC_SetPassword_ValidatesPolicy(t *testing.T) {
	suite := newRBACsuite(t)

	user := newTestUser(suite.tenantID, "frank", "frank@example.com")
	adminID := uuid.New()

	suite.userRepo.On("GetByID", suite.ctx, user.ID).Return(user, nil)

	// Password does not satisfy policy (no uppercase, no digit)
	err := suite.userService.SetPassword(suite.ctx, user.ID, "weakpassword", false, &adminID)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "password validation failed")
}

// ---------------------------------------------------------------------------
// RoleService.GetByID and permissions
// ---------------------------------------------------------------------------

// TestRBAC_GetRolePermissions verifies the GetPermissions accessor.
func TestRBAC_GetRolePermissions(t *testing.T) {
	suite := newRBACsuite(t)

	role := newTestRole(suite.tenantID, "billing-admin")
	perm1 := newTestPermission("billing", "invoices", "create")
	perm2 := newTestPermission("billing", "invoices", "read")

	suite.roleRepo.On("GetByID", suite.ctx, role.ID).Return(role, nil)
	suite.roleRepo.On("GetRolePermissions", suite.ctx, role.ID).
		Return([]models.Permission{*perm1, *perm2}, nil)

	perms, err := suite.roleService.GetPermissions(suite.ctx, role.ID)

	require.NoError(t, err)
	require.Len(t, perms, 2)

	names := []string{perms[0].Name, perms[1].Name}
	assert.Contains(t, names, "billing:invoices:create")
	assert.Contains(t, names, "billing:invoices:read")
}

// TestRBAC_ListAllPermissions verifies the full permissions list via RoleService.
func TestRBAC_ListAllPermissions(t *testing.T) {
	suite := newRBACsuite(t)

	perms := []models.Permission{
		*newTestPermission("crm", "contacts", "read"),
		*newTestPermission("crm", "contacts", "write"),
		*newTestPermission("billing", "invoices", "read"),
	}

	suite.permRepo.On("List", suite.ctx).Return(perms, nil)

	resp, err := suite.roleService.ListAllPermissions(suite.ctx)

	require.NoError(t, err)
	assert.Equal(t, int64(3), resp.Total)
	assert.Len(t, resp.Permissions, 3)
}
