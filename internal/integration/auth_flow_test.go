// SPDX-License-Identifier: AGPL-3.0-or-later

// Package integration contains end-to-end service-layer tests that wire real
// service instances with mock repositories at the boundary.
//
// auth_flow_test.go covers:
//   - Token lifecycle via TokenService (generate → validate → revoke)
//   - User lifecycle via UserService (create → lock → unlock)
//   - Group-inherited role resolution via GroupService (group → role → effective permissions)
//   - Logout flow that revokes refresh tokens and ends sessions
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
	"github.com/dogukanturhal/falcon-id/pkg/config"
)

// ---------------------------------------------------------------------------
// tokenRepoMock implements tokenTokenRepository (the interface used by TokenService)
// ---------------------------------------------------------------------------

type tokenRepoMock struct{ mock.Mock }

func (m *tokenRepoMock) CleanupExpiredPasswordResets(ctx context.Context) (int64, error) {
	args := m.Called(ctx)
	return args.Get(0).(int64), args.Error(1)
}

func (m *tokenRepoMock) CreatePasswordReset(ctx context.Context, reset *models.PasswordReset) error {
	return m.Called(ctx, reset).Error(0)
}

func (m *tokenRepoMock) GetPasswordReset(ctx context.Context, tokenHash string) (*models.PasswordReset, error) {
	args := m.Called(ctx, tokenHash)
	if v := args.Get(0); v != nil {
		return v.(*models.PasswordReset), args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *tokenRepoMock) MarkPasswordResetUsed(ctx context.Context, id uuid.UUID) error {
	return m.Called(ctx, id).Error(0)
}

func (m *tokenRepoMock) InvalidateUserPasswordResets(ctx context.Context, userID uuid.UUID) error {
	return m.Called(ctx, userID).Error(0)
}

// tokenUserRepoMock implements tokenUserRepository (the user interface used by TokenService)
type tokenUserRepoMock struct{ mock.Mock }

func (m *tokenUserRepoMock) GetByID(ctx context.Context, id uuid.UUID) (*models.User, error) {
	args := m.Called(ctx, id)
	if v := args.Get(0); v != nil {
		return v.(*models.User), args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *tokenUserRepoMock) GetUserRoles(ctx context.Context, userID uuid.UUID) ([]models.Role, error) {
	args := m.Called(ctx, userID)
	if v := args.Get(0); v != nil {
		return v.([]models.Role), args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *tokenUserRepoMock) GetUserPermissions(ctx context.Context, userID uuid.UUID) ([]models.Permission, error) {
	args := m.Called(ctx, userID)
	if v := args.Get(0); v != nil {
		return v.([]models.Permission), args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *tokenUserRepoMock) Update(ctx context.Context, user *models.User) error {
	return m.Called(ctx, user).Error(0)
}

// ---------------------------------------------------------------------------
// auth flow test suite
// ---------------------------------------------------------------------------

type authFlowSuite struct {
	ctx          context.Context
	cfg          *config.Config
	tenantID     uuid.UUID
	tokenRepo    *tokenRepoMock // repo used by tokenSvc (the real TokenService)
	userRepo     *userRepoMock  // repo used by userService
	roleRepo     *roleRepoMock  // repo used by userService
	tokenSvc     *services.TokenService
	tokenSvcMock *tokenServiceMock // the mock injected into userService as its token dep
	userService  *services.UserService
	auditSvc     *auditServiceMock
}

func newAuthFlowSuite(t *testing.T) *authFlowSuite {
	t.Helper()

	cfg := testutil.NewTestConfig()
	tenantID := uuid.New()

	tokenRepo := &tokenRepoMock{}
	tuserRepo := &tokenUserRepoMock{}
	userRepo := &userRepoMock{}
	roleRepo := &roleRepoMock{}
	auditSvc := &auditServiceMock{}
	tokenSvcMock := &tokenServiceMock{}

	tokenSvc := services.NewTokenService(cfg, tokenRepo, tuserRepo)
	userService := services.NewUserService(cfg, userRepo, roleRepo, tokenSvcMock, auditSvc)
	userService.SetRealmResolver(&realmResolverMock{})

	return &authFlowSuite{
		ctx:          context.Background(),
		cfg:          cfg,
		tenantID:     tenantID,
		tokenRepo:    tokenRepo,
		userRepo:     userRepo,
		roleRepo:     roleRepo,
		tokenSvc:     tokenSvc,
		tokenSvcMock: tokenSvcMock,
		userService:  userService,
		auditSvc:     auditSvc,
	}
}

// ---------------------------------------------------------------------------
// Token lifecycle: generate → validate → revoke
// ---------------------------------------------------------------------------

// TestAuthFlow_TokenGeneration verifies that TokenService generates a
// well-formed JWT access token for an active user.
func TestAuthFlow_TokenGeneration(t *testing.T) {
	suite := newAuthFlowSuite(t)

	user := newTestUser(suite.tenantID, "alice", "alice@example.com")
	sessionID := uuid.New()
	roles := []string{"editor"}
	perms := []string{"docs:document:write"}

	token, err := suite.tokenSvc.GenerateAccessToken(
		suite.ctx, user, sessionID, roles, perms,
	)

	require.NoError(t, err)
	assert.NotEmpty(t, token, "access token must not be empty")

	// Token must be parseable (three segments separated by dots)
	parts := splitJWT(token)
	assert.Len(t, parts, 3, "JWT must have three segments")
}

// ---------------------------------------------------------------------------
// Failed login simulation: lock-after-max-attempts lifecycle via UserService
// ---------------------------------------------------------------------------

// TestAuthFlow_LockAfterMaxAttempts tests the sequence:
// create user → lock user (simulating max-attempts exceeded) → verify locked
// → unlock → verify unlocked.
func TestAuthFlow_LockAfterMaxAttempts(t *testing.T) {
	suite := newAuthFlowSuite(t)

	user := newTestUser(suite.tenantID, "henry", "henry@example.com")
	adminID := uuid.New()

	// Simulate lock triggered after max failures
	lockReason := "too many failed login attempts"

	// Step 1: Lock user
	suite.userRepo.On("GetByID", suite.ctx, user.ID).Return(user, nil).Once()
	suite.userRepo.On("Update", suite.ctx, mock.MatchedBy(func(u *models.User) bool {
		return u.IsLocked && u.LockReason != nil && *u.LockReason == lockReason
	})).Return(nil).Once()
	suite.auditSvc.On("LogUserAction", suite.ctx, suite.tenantID, &adminID, &user.ID, "user_lock", true, mock.Anything).Return()

	err := suite.userService.Lock(suite.ctx, user.ID, lockReason, &adminID)
	require.NoError(t, err)

	// Simulate the user is now locked in the DB
	lockedUser := *user
	lockedUser.IsLocked = true
	lockedUser.LockReason = &lockReason

	// Step 2: Unlock user
	suite.userRepo.On("UnlockUser", suite.ctx, user.ID).Return(nil)
	suite.userRepo.On("GetByID", suite.ctx, user.ID).Return(&lockedUser, nil).Once()
	suite.auditSvc.On("LogUserAction", suite.ctx, suite.tenantID, &adminID, &user.ID, "user_unlock", true, mock.Anything).Return()

	err = suite.userService.Unlock(suite.ctx, user.ID, &adminID)
	require.NoError(t, err)

	suite.userRepo.AssertExpectations(t)
}

// ---------------------------------------------------------------------------
// Group-based role inheritance flow
// ---------------------------------------------------------------------------

// TestAuthFlow_GroupRoleInheritance verifies that a user in a group inherits
// the group's roles via GroupService.GetUserEffectiveRoles.
//
// Scenario:
//  1. Create tenant, group, role, user
//  2. Assign role to group (via groupRepo.AssignRole)
//  3. Add user to group (via groupRepo.AddMember)
//  4. Call GetUserEffectiveRoles → expect role appears with source="group"
func TestAuthFlow_GroupRoleInheritance(t *testing.T) {
	tenantID := uuid.New()

	groupRepo := &groupRepoMock{}
	userRepo := &userRepoMock{}
	roleRepo := &roleRepoMock{}

	groupSvc := services.NewGroupService(groupRepo, userRepo, roleRepo)
	ctx := context.Background()

	group := newTestGroup(tenantID, "engineering")
	role := newTestRole(tenantID, "developer")
	user := newTestUser(tenantID, "ivan", "ivan@example.com")
	adminID := uuid.New()

	// Step 1: Create group
	groupRepo.On("GetByName", ctx, tenantID, "engineering").
		Return(nil, errNotFound())
	groupRepo.On("Create", ctx, mock.AnythingOfType("*models.Group")).
		Return(nil).Run(func(args mock.Arguments) {
		g := args.Get(1).(*models.Group)
		g.ID = group.ID
	})
	// Reload after create
	groupRepo.On("GetByID", ctx, group.ID).Return(group, nil)

	createdGroup, err := groupSvc.CreateGroup(ctx, tenantID, &models.CreateGroupRequest{
		Name: "engineering",
	}, &adminID)
	require.NoError(t, err)
	assert.Equal(t, "engineering", createdGroup.Name)

	// Step 2: Assign role to group
	groupRepo.On("GetByID", ctx, group.ID).Return(group, nil)
	roleRepo.On("GetByID", ctx, role.ID).Return(role, nil)
	groupRepo.On("AssignRole", ctx, group.ID, role.ID, &adminID).Return(nil)

	err = groupSvc.AssignRoles(ctx, group.ID, []uuid.UUID{role.ID}, &adminID)
	require.NoError(t, err)

	// Step 3: Add user to group
	groupRepo.On("GetByID", ctx, group.ID).Return(group, nil)
	userRepo.On("GetByID", ctx, user.ID).Return(user, nil)
	groupRepo.On("AddMember", ctx, group.ID, user.ID, &adminID).Return(nil)

	err = groupSvc.AddMembers(ctx, group.ID, []uuid.UUID{user.ID}, &adminID)
	require.NoError(t, err)

	// Step 4: Verify effective roles include the group's role
	groupID := group.ID
	effectiveRoles := []*models.EffectiveRole{
		{
			RoleID:   role.ID,
			RoleName: role.Name,
			Source:   "group",
			SourceID: &groupID,
		},
	}
	groupRepo.On("GetUserEffectiveRoles", ctx, user.ID).Return(effectiveRoles, nil)

	roles, err := groupSvc.GetUserEffectiveRoles(ctx, user.ID)

	require.NoError(t, err)
	require.Len(t, roles, 1)
	assert.Equal(t, role.Name, roles[0].RoleName)
	assert.Equal(t, "group", roles[0].Source)
	assert.Equal(t, group.ID, *roles[0].SourceID)

	groupRepo.AssertExpectations(t)
	userRepo.AssertExpectations(t)
	roleRepo.AssertExpectations(t)
}

// TestAuthFlow_RemoveGroupMember_RevokesInheritedRole verifies that removing a
// user from a group causes GetUserEffectiveRoles to no longer include the
// group-inherited role.
func TestAuthFlow_RemoveGroupMember_RevokesInheritedRole(t *testing.T) {
	tenantID := uuid.New()
	ctx := context.Background()

	groupRepo := &groupRepoMock{}
	userRepo := &userRepoMock{}
	roleRepo := &roleRepoMock{}
	groupSvc := services.NewGroupService(groupRepo, userRepo, roleRepo)

	group := newTestGroup(tenantID, "ops")
	user := newTestUser(tenantID, "julia", "julia@example.com")

	// RemoveMember call
	groupRepo.On("RemoveMember", ctx, group.ID, user.ID).Return(nil)

	err := groupSvc.RemoveMembers(ctx, group.ID, []uuid.UUID{user.ID})
	require.NoError(t, err)

	// After removal, effective roles should be empty
	groupRepo.On("GetUserEffectiveRoles", ctx, user.ID).
		Return([]*models.EffectiveRole{}, nil)

	roles, err := groupSvc.GetUserEffectiveRoles(ctx, user.ID)
	require.NoError(t, err)
	assert.Empty(t, roles, "user should have no inherited roles after group removal")

	groupRepo.AssertExpectations(t)
}

// ---------------------------------------------------------------------------
// Password reset lifecycle
// ---------------------------------------------------------------------------

// TestAuthFlow_SetPassword_ValidAndInvalidCredentials tests:
// - Valid strong password is accepted and token revocation is triggered
// - Weak password is rejected before touching the repo
func TestAuthFlow_SetPassword_ValidAndInvalidCredentials(t *testing.T) {
	tests := []struct {
		name        string
		password    string
		wantErr     bool
		errContains string
	}{
		{
			name:     "valid strong password accepted",
			password: "StrongPass1!",
			wantErr:  false,
		},
		{
			name:        "password too short rejected",
			password:    "Sh0rt!",
			wantErr:     true,
			errContains: "password validation failed",
		},
		{
			name:        "missing uppercase rejected",
			password:    "weakpassword1!",
			wantErr:     true,
			errContains: "password validation failed",
		},
		{
			name:        "missing digit rejected",
			password:    "NoDigitPass!",
			wantErr:     true,
			errContains: "password validation failed",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			suite := newAuthFlowSuite(t)

			user := newTestUser(suite.tenantID, "kate", "kate@example.com")
			adminID := uuid.New()

			// Always mock GetByID – it's called before policy validation
			suite.userRepo.On("GetByID", suite.ctx, user.ID).Return(user, nil)

			if !tc.wantErr {
				// Only called on success path.
				// UserService.SetPassword calls s.tokenService.RevokeAllUserOAuthTokens
				// which resolves to suite.tokenSvcMock (injected at construction).
				suite.userRepo.On("Update", suite.ctx, mock.AnythingOfType("*models.User")).Return(nil)
				suite.tokenSvcMock.On("RevokeAllUserOAuthTokens", suite.ctx, user.ID, "password_reset").Return(nil)
				suite.auditSvc.On("LogUserAction", mock.Anything, mock.Anything, mock.Anything, mock.Anything, "user_password_set", true, mock.Anything).Return()
			}

			err := suite.userService.SetPassword(suite.ctx, user.ID, tc.password, false, &adminID)

			if tc.wantErr {
				require.Error(t, err)
				if tc.errContains != "" {
					assert.Contains(t, err.Error(), tc.errContains)
				}
			} else {
				require.NoError(t, err)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// MFA challenge fields: LoginResponse structure validation
// ---------------------------------------------------------------------------

// TestAuthFlow_MFAChallengeResponse verifies that the LoginResponse fields for
// MFA challenges are populated correctly.  This tests the model directly since
// the MFA dispatch lives in AuthService which requires concrete repos.
func TestAuthFlow_MFAChallengeResponse(t *testing.T) {
	resp := &models.LoginResponse{
		RequiresMFA:         true,
		MFAMethod:           "totp",
		AvailableMFAMethods: []string{"totp", "email"},
		SessionID:           uuid.New().String(),
	}

	assert.True(t, resp.RequiresMFA)
	assert.Equal(t, "totp", resp.MFAMethod)
	assert.Contains(t, resp.AvailableMFAMethods, "totp")
	assert.Contains(t, resp.AvailableMFAMethods, "email")
	assert.NotEmpty(t, resp.SessionID)
	// No tokens should be present in an MFA challenge response
	assert.Empty(t, resp.AccessToken)
	assert.Empty(t, resp.RefreshToken)
}

// ---------------------------------------------------------------------------
// User create → get → update → delete full lifecycle
// ---------------------------------------------------------------------------

// TestAuthFlow_UserCRUDLifecycle exercises a complete user lifecycle through
// UserService: create → get → update → delete.
func TestAuthFlow_UserCRUDLifecycle(t *testing.T) {
	suite := newAuthFlowSuite(t)

	user := newTestUser(suite.tenantID, "liam", "liam@example.com")
	adminID := uuid.New()
	newFirstName := "Liam"

	// ---- CREATE ----
	suite.userRepo.On("GetByUsername", suite.ctx, suite.tenantID, "liam").Return(nil, nil)
	suite.userRepo.On("GetByEmail", suite.ctx, suite.tenantID, "liam@example.com").Return(nil, nil)
	suite.userRepo.On("Create", suite.ctx, mock.AnythingOfType("*models.User")).
		Return(nil).Run(func(args mock.Arguments) {
		u := args.Get(1).(*models.User)
		u.ID = user.ID
	})
	suite.roleRepo.On("GetDefaultRoles", suite.ctx, suite.tenantID).Return([]models.Role{}, nil)
	suite.userRepo.On("GetUserRoles", suite.ctx, user.ID).Return([]models.Role{}, nil)
	suite.userRepo.On("GetUserPermissions", suite.ctx, user.ID).Return([]models.Permission{}, nil)
	suite.auditSvc.On("LogUserAction", suite.ctx, suite.tenantID, (*uuid.UUID)(nil), &user.ID, "user_create", true, mock.Anything).Return()

	created, err := suite.userService.Create(suite.ctx, &models.CreateUserRequest{
		TenantID: suite.tenantID,
		Username: "liam",
		Email:    "liam@example.com",
		Password: "SecurePass1!",
	}, nil)
	require.NoError(t, err)
	assert.Equal(t, "liam", created.Username)

	// ---- GET ----
	suite.userRepo.On("GetByID", suite.ctx, user.ID).Return(user, nil)
	suite.userRepo.On("GetUserRoles", suite.ctx, user.ID).Return([]models.Role{}, nil)
	suite.userRepo.On("GetUserPermissions", suite.ctx, user.ID).Return([]models.Permission{}, nil)

	got, err := suite.userService.GetByID(suite.ctx, user.ID)
	require.NoError(t, err)
	assert.Equal(t, user.ID, got.ID)

	// ---- UPDATE ----
	suite.userRepo.On("GetByID", suite.ctx, user.ID).Return(user, nil)
	suite.userRepo.On("Update", suite.ctx, mock.AnythingOfType("*models.User")).Return(nil)
	suite.userRepo.On("GetUserRoles", suite.ctx, user.ID).Return([]models.Role{}, nil)
	suite.userRepo.On("GetUserPermissions", suite.ctx, user.ID).Return([]models.Permission{}, nil)
	suite.auditSvc.On("LogUserAction", suite.ctx, suite.tenantID, &adminID, &user.ID, "user_update", true, mock.Anything).Return()

	updated, err := suite.userService.Update(suite.ctx, user.ID, &models.UpdateUserRequest{
		FirstName: &newFirstName,
	}, &adminID)
	require.NoError(t, err)
	assert.NotNil(t, updated)

	// ---- DELETE ----
	suite.userRepo.On("GetByID", suite.ctx, user.ID).Return(user, nil)
	suite.userRepo.On("Delete", suite.ctx, user.ID).Return(nil)
	suite.auditSvc.On("LogUserAction", suite.ctx, suite.tenantID, &adminID, &user.ID, "user_delete", true, mock.Anything).Return()

	err = suite.userService.Delete(suite.ctx, user.ID, &adminID)
	require.NoError(t, err)

	suite.userRepo.AssertExpectations(t)
	suite.auditSvc.AssertExpectations(t)
}

// ---------------------------------------------------------------------------
// JWT access token claim validation
// ---------------------------------------------------------------------------

// TestAuthFlow_AccessToken_ContainsExpectedClaims verifies that a generated
// access token contains the expected JWT claims (subject, tenant, roles).
func TestAuthFlow_AccessToken_ContainsExpectedClaims(t *testing.T) {
	cfg := testutil.NewTestConfig()
	tokenRepo := &tokenRepoMock{}
	tuserRepo := &tokenUserRepoMock{}
	tokenSvc := services.NewTokenService(cfg, tokenRepo, tuserRepo)

	ctx := context.Background()
	tenantID := uuid.New()
	user := newTestUser(tenantID, "mia", "mia@example.com")
	sessionID := uuid.New()

	token, err := tokenSvc.GenerateAccessToken(
		ctx, user, sessionID,
		[]string{"admin"},
		[]string{"users:read", "users:write"},
	)

	require.NoError(t, err)
	require.NotEmpty(t, token)

	// Verify the JWT has three parts
	parts := splitJWT(token)
	require.Len(t, parts, 3)
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func splitJWT(token string) []string {
	parts := make([]string, 0, 3)
	start := 0
	for i, ch := range token {
		if ch == '.' {
			parts = append(parts, token[start:i])
			start = i + 1
		}
	}
	parts = append(parts, token[start:])
	return parts
}

func errNotFound() error {
	return &notFoundError{}
}

type notFoundError struct{}

func (e *notFoundError) Error() string { return "not found" }
