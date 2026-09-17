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

	"github.com/dogukanturhal/platform-shared/quota"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/pkg/config"
)

// MockUserRepository mocks the user repository
type MockUserRepository struct {
	mock.Mock
}

func (m *MockUserRepository) Create(ctx context.Context, user *models.User) error {
	args := m.Called(ctx, user)
	return args.Error(0)
}

func (m *MockUserRepository) HasAnyMFAFactor(ctx context.Context, id uuid.UUID) (bool, error) {
	args := m.Called(ctx, id)
	return args.Bool(0), args.Error(1)
}

func (m *MockUserRepository) HasNonPrimaryMFAFactor(ctx context.Context, id uuid.UUID) (bool, error) {
	args := m.Called(ctx, id)
	return args.Bool(0), args.Error(1)
}

func (m *MockUserRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.User, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.User), args.Error(1)
}

func (m *MockUserRepository) GetByUsername(ctx context.Context, tenantID uuid.UUID, username string) (*models.User, error) {
	args := m.Called(ctx, tenantID, username)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.User), args.Error(1)
}

func (m *MockUserRepository) GetByEmail(ctx context.Context, tenantID uuid.UUID, email string) (*models.User, error) {
	args := m.Called(ctx, tenantID, email)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.User), args.Error(1)
}

func (m *MockUserRepository) Update(ctx context.Context, user *models.User) error {
	args := m.Called(ctx, user)
	return args.Error(0)
}

func (m *MockUserRepository) Delete(ctx context.Context, id uuid.UUID) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *MockUserRepository) List(ctx context.Context, tenantID uuid.UUID, page, pageSize int, search string) ([]models.User, int64, error) {
	args := m.Called(ctx, tenantID, page, pageSize, search)
	if args.Get(0) == nil {
		return nil, args.Get(1).(int64), args.Error(2)
	}
	return args.Get(0).([]models.User), args.Get(1).(int64), args.Error(2)
}

func (m *MockUserRepository) ListTenantMemberCards(ctx context.Context, tenantID, viewerID uuid.UUID, limit, offset int) ([]models.User, int, error) {
	args := m.Called(ctx, tenantID, viewerID, limit, offset)
	if args.Get(0) == nil {
		return nil, args.Int(1), args.Error(2)
	}
	return args.Get(0).([]models.User), args.Int(1), args.Error(2)
}

func (m *MockUserRepository) AssignRoles(ctx context.Context, userID uuid.UUID, roleIDs []uuid.UUID, assignedBy *uuid.UUID) error {
	args := m.Called(ctx, userID, roleIDs, assignedBy)
	return args.Error(0)
}

func (m *MockUserRepository) GetUserRoles(ctx context.Context, userID uuid.UUID) ([]models.Role, error) {
	args := m.Called(ctx, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]models.Role), args.Error(1)
}

func (m *MockUserRepository) GetUserPermissions(ctx context.Context, userID uuid.UUID) ([]models.Permission, error) {
	args := m.Called(ctx, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]models.Permission), args.Error(1)
}

func (m *MockUserRepository) UnlockUser(ctx context.Context, id uuid.UUID) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

// MockRoleRepository mocks the role repository
type MockRoleRepository struct {
	mock.Mock
}

func (m *MockRoleRepository) GetDefaultRoles(ctx context.Context, tenantID uuid.UUID) ([]models.Role, error) {
	args := m.Called(ctx, tenantID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]models.Role), args.Error(1)
}

func (m *MockRoleRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.Role, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.Role), args.Error(1)
}

func (m *MockRoleRepository) GetByIDAndTenant(ctx context.Context, id, tenantID uuid.UUID) (*models.Role, error) {
	args := m.Called(ctx, id, tenantID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.Role), args.Error(1)
}

func (m *MockRoleRepository) GetMaxPriorityForUser(ctx context.Context, userID, tenantID uuid.UUID) (int, error) {
	args := m.Called(ctx, userID, tenantID)
	return args.Int(0), args.Error(1)
}

// MockTokenService mocks the token service
type MockTokenService struct {
	mock.Mock
}

func (m *MockTokenService) RevokeAllUserOAuthTokens(ctx context.Context, userID uuid.UUID, reason string) error {
	args := m.Called(ctx, userID, reason)
	return args.Error(0)
}

// MockUserAuditService mocks the audit service for user service tests
type MockUserAuditService struct {
	mock.Mock
}

func (m *MockUserAuditService) LogUserAction(ctx context.Context, tenantID uuid.UUID, actorID *uuid.UUID, targetUserID *uuid.UUID, action string, success bool, metadata map[string]interface{}) {
	m.Called(ctx, tenantID, actorID, targetUserID, action, success, metadata)
}

// mockRealmResolver is a test double for userServiceRealmResolver that always
// returns WellKnownRealmShared, simulating a production environment where every
// tenant has an explicit realm assignment in realm_tenants.
type mockRealmResolver struct{}

func (m *mockRealmResolver) GetTenantRealm(_ context.Context, _ uuid.UUID) (*models.Realm, error) {
	return &models.Realm{ID: models.WellKnownRealmShared}, nil
}

func TestUserService_Create_Success(t *testing.T) {
	ctx := context.Background()
	tenantID := uuid.New()
	creatorID := uuid.New()

	mockUserRepo := new(MockUserRepository)
	mockRoleRepo := new(MockRoleRepository)
	mockTokenService := new(MockTokenService)
	mockAuditService := new(MockUserAuditService)

	cfg := &config.Config{
		PasswordMinLength:      8,
		PasswordRequireUpper:   true,
		PasswordRequireLower:   true,
		PasswordRequireDigit:   true,
		PasswordRequireSpecial: false,
	}

	service := NewUserService(cfg, mockUserRepo, mockRoleRepo, mockTokenService, mockAuditService)
	service.SetRealmResolver(&mockRealmResolver{})

	req := &models.CreateUserRequest{
		TenantID:  tenantID,
		Username:  "testuser",
		Email:     "test@example.com",
		FirstName: strPtr("Test"),
		LastName:  strPtr("User"),
		Password:  "SecureP@ss123",
		RoleIDs:   []uuid.UUID{uuid.New()},
	}

	// Setup mocks
	mockUserRepo.On("GetByUsername", ctx, tenantID, "testuser").Return(nil, nil)
	mockUserRepo.On("GetByEmail", ctx, tenantID, "test@example.com").Return(nil, nil)
	mockUserRepo.On("Create", ctx, mock.AnythingOfType("*models.User")).Return(nil)
	mockUserRepo.On("AssignRoles", ctx, mock.AnythingOfType("uuid.UUID"), req.RoleIDs, &creatorID).Return(nil)
	mockUserRepo.On("GetUserRoles", ctx, mock.AnythingOfType("uuid.UUID")).Return([]models.Role{}, nil)
	mockUserRepo.On("GetUserPermissions", ctx, mock.AnythingOfType("uuid.UUID")).Return([]models.Permission{}, nil)
	mockAuditService.On("LogUserAction", ctx, tenantID, &creatorID, mock.AnythingOfType("*uuid.UUID"), "user_create", true, mock.Anything)

	// Execute
	user, err := service.Create(ctx, req, &creatorID)

	// Assert
	require.NoError(t, err)
	assert.NotNil(t, user)
	assert.Equal(t, req.Username, user.Username)
	assert.Equal(t, req.Email, user.Email)
	mockUserRepo.AssertExpectations(t)
	mockAuditService.AssertExpectations(t)
}

func TestUserService_Create_StillValidatesNormalPasswordRequests(t *testing.T) {
	service := signupPolicyUserService()
	_, err := service.Create(context.Background(), &models.CreateUserRequest{Password: "short"}, nil)
	require.ErrorContains(t, err, "password validation failed")
}

func TestUserService_CreatePreparedForSignup_DoesNotRepeatBestEffortBreachDecision(t *testing.T) {
	ctx := context.Background()
	tenantID := uuid.New()
	userRepo, roleRepo, tokenService, auditService := new(MockUserRepository), new(MockRoleRepository), new(MockTokenService), new(MockUserAuditService)
	service := NewUserService(&config.Config{PasswordMinLength: 8, PasswordRequireUpper: true, PasswordRequireLower: true, PasswordRequireDigit: true}, userRepo, roleRepo, tokenService, auditService)
	service.SetRealmResolver(&mockRealmResolver{})
	checker := &signupBreachStub{err: errors.New("first lookup outage")}
	service.breachChecker = checker
	password := "PreparedPassword1"
	credential, err := service.PrepareSignupCredential(ctx, password)
	require.NoError(t, err)
	require.Equal(t, 1, checker.calls)

	// A second lookup would conclusively reject. Prepared creation must use the
	// accepted pre-provision result rather than make that contradictory call.
	checker.err = nil
	checker.breached = true
	req := &models.CreateUserRequest{TenantID: tenantID, Username: "prepared", Email: "prepared@example.invalid", Password: password, RoleIDs: []uuid.UUID{uuid.New()}}
	userRepo.On("GetByUsername", ctx, tenantID, req.Username).Return(nil, nil)
	userRepo.On("GetByEmail", ctx, tenantID, req.Email).Return(nil, nil)
	userRepo.On("Create", ctx, mock.MatchedBy(func(user *models.User) bool { return user.PasswordHash != nil && *user.PasswordHash != "" })).Return(nil)
	userRepo.On("AssignRoles", ctx, mock.AnythingOfType("uuid.UUID"), req.RoleIDs, (*uuid.UUID)(nil)).Return(nil)
	userRepo.On("GetUserRoles", ctx, mock.AnythingOfType("uuid.UUID")).Return([]models.Role{}, nil)
	userRepo.On("GetUserPermissions", ctx, mock.AnythingOfType("uuid.UUID")).Return([]models.Permission{}, nil)
	auditService.On("LogUserAction", ctx, tenantID, (*uuid.UUID)(nil), mock.AnythingOfType("*uuid.UUID"), "user_create", true, mock.Anything)
	_, err = service.CreatePreparedForSignup(ctx, req, credential)
	require.NoError(t, err)
	assert.Equal(t, 1, checker.calls)
	userRepo.AssertExpectations(t)
	auditService.AssertExpectations(t)
}

func TestUserService_CreatePreparedForSignup_RejectsUnboundCredential(t *testing.T) {
	service := signupPolicyUserService()
	credential := &PreparedSignupCredential{passwordHash: "test-hash"}
	_, err := service.CreatePreparedForSignup(context.Background(), &models.CreateUserRequest{Password: "other"}, credential)
	require.ErrorContains(t, err, "invalid prepared signup credential")
}

func TestUserService_Create_DuplicateUsername(t *testing.T) {
	ctx := context.Background()
	tenantID := uuid.New()

	mockUserRepo := new(MockUserRepository)
	mockRoleRepo := new(MockRoleRepository)
	mockTokenService := new(MockTokenService)
	mockAuditService := new(MockUserAuditService)

	cfg := &config.Config{}
	service := NewUserService(cfg, mockUserRepo, mockRoleRepo, mockTokenService, mockAuditService)

	req := &models.CreateUserRequest{
		TenantID: tenantID,
		Username: "existinguser",
		Email:    "test@example.com",
		Password: "SecureP@ss123",
	}

	existingUser := &models.User{
		ID:       uuid.New(),
		Username: "existinguser",
	}

	mockUserRepo.On("GetByUsername", ctx, tenantID, "existinguser").Return(existingUser, nil)

	// Execute
	user, err := service.Create(ctx, req, nil)

	// Assert
	assert.Error(t, err)
	assert.Nil(t, user)
	assert.Contains(t, err.Error(), "username already exists")
	mockUserRepo.AssertExpectations(t)
}

func TestUserService_Create_DuplicateEmail(t *testing.T) {
	ctx := context.Background()
	tenantID := uuid.New()

	mockUserRepo := new(MockUserRepository)
	mockRoleRepo := new(MockRoleRepository)
	mockTokenService := new(MockTokenService)
	mockAuditService := new(MockUserAuditService)

	cfg := &config.Config{}
	service := NewUserService(cfg, mockUserRepo, mockRoleRepo, mockTokenService, mockAuditService)

	req := &models.CreateUserRequest{
		TenantID: tenantID,
		Username: "newuser",
		Email:    "existing@example.com",
		Password: "SecureP@ss123",
	}

	existingUser := &models.User{
		ID:    uuid.New(),
		Email: "existing@example.com",
	}

	mockUserRepo.On("GetByUsername", ctx, tenantID, "newuser").Return(nil, nil)
	mockUserRepo.On("GetByEmail", ctx, tenantID, "existing@example.com").Return(existingUser, nil)

	// Execute
	user, err := service.Create(ctx, req, nil)

	// Assert
	assert.Error(t, err)
	assert.Nil(t, user)
	assert.Contains(t, err.Error(), "email already exists")
	mockUserRepo.AssertExpectations(t)
}

func TestUserService_GetByID_Success(t *testing.T) {
	ctx := context.Background()
	userID := uuid.New()

	mockUserRepo := new(MockUserRepository)
	mockRoleRepo := new(MockRoleRepository)
	mockTokenService := new(MockTokenService)
	mockAuditService := new(MockUserAuditService)

	cfg := &config.Config{}
	service := NewUserService(cfg, mockUserRepo, mockRoleRepo, mockTokenService, mockAuditService)

	expectedUser := &models.User{
		ID:       userID,
		Username: "testuser",
		Email:    "test@example.com",
	}

	mockUserRepo.On("GetByID", ctx, userID).Return(expectedUser, nil)
	mockUserRepo.On("GetUserRoles", ctx, userID).Return([]models.Role{}, nil)
	mockUserRepo.On("GetUserPermissions", ctx, userID).Return([]models.Permission{}, nil)

	// Execute
	user, err := service.GetByID(ctx, userID)

	// Assert
	require.NoError(t, err)
	assert.NotNil(t, user)
	assert.Equal(t, expectedUser.Username, user.Username)
	mockUserRepo.AssertExpectations(t)
}

func TestUserService_GetByID_NotFound(t *testing.T) {
	ctx := context.Background()
	userID := uuid.New()

	mockUserRepo := new(MockUserRepository)
	mockRoleRepo := new(MockRoleRepository)
	mockTokenService := new(MockTokenService)
	mockAuditService := new(MockUserAuditService)

	cfg := &config.Config{}
	service := NewUserService(cfg, mockUserRepo, mockRoleRepo, mockTokenService, mockAuditService)

	mockUserRepo.On("GetByID", ctx, userID).Return(nil, nil)

	// Execute
	user, err := service.GetByID(ctx, userID)

	// Assert
	assert.Error(t, err)
	assert.Nil(t, user)
	assert.Contains(t, err.Error(), "user not found")
	mockUserRepo.AssertExpectations(t)
}

func TestUserService_Update_Success(t *testing.T) {
	ctx := context.Background()
	userID := uuid.New()
	updaterID := uuid.New()
	tenantID := uuid.New()

	mockUserRepo := new(MockUserRepository)
	mockRoleRepo := new(MockRoleRepository)
	mockTokenService := new(MockTokenService)
	mockAuditService := new(MockUserAuditService)

	cfg := &config.Config{}
	service := NewUserService(cfg, mockUserRepo, mockRoleRepo, mockTokenService, mockAuditService)

	existingUser := &models.User{
		ID:       userID,
		TenantID: tenantID,
		Username: "testuser",
		Email:    "test@example.com",
	}

	newFirstName := "UpdatedName"
	req := &models.UpdateUserRequest{
		FirstName: &newFirstName,
	}

	mockUserRepo.On("GetByID", ctx, userID).Return(existingUser, nil)
	mockUserRepo.On("Update", ctx, mock.AnythingOfType("*models.User")).Return(nil)
	mockUserRepo.On("GetUserRoles", ctx, userID).Return([]models.Role{}, nil)
	mockUserRepo.On("GetUserPermissions", ctx, userID).Return([]models.Permission{}, nil)
	mockAuditService.On("LogUserAction", ctx, tenantID, &updaterID, &userID, "user_update", true, mock.Anything)

	// Execute
	user, err := service.Update(ctx, userID, req, &updaterID)

	// Assert
	require.NoError(t, err)
	assert.NotNil(t, user)
	mockUserRepo.AssertExpectations(t)
	mockAuditService.AssertExpectations(t)
}

func TestUserService_Delete_Success(t *testing.T) {
	ctx := context.Background()
	userID := uuid.New()
	deleterID := uuid.New()
	tenantID := uuid.New()

	mockUserRepo := new(MockUserRepository)
	mockRoleRepo := new(MockRoleRepository)
	mockTokenService := new(MockTokenService)
	mockAuditService := new(MockUserAuditService)

	cfg := &config.Config{}
	service := NewUserService(cfg, mockUserRepo, mockRoleRepo, mockTokenService, mockAuditService)

	existingUser := &models.User{
		ID:       userID,
		TenantID: tenantID,
	}

	mockUserRepo.On("GetByID", ctx, userID).Return(existingUser, nil)
	mockUserRepo.On("Delete", ctx, userID).Return(nil)
	mockAuditService.On("LogUserAction", ctx, tenantID, &deleterID, &userID, "user_delete", true, mock.Anything)

	// Execute
	err := service.Delete(ctx, userID, &deleterID)

	// Assert
	require.NoError(t, err)
	mockUserRepo.AssertExpectations(t)
	mockAuditService.AssertExpectations(t)
}

func TestUserService_List_Success(t *testing.T) {
	ctx := context.Background()
	tenantID := uuid.New()

	mockUserRepo := new(MockUserRepository)
	mockRoleRepo := new(MockRoleRepository)
	mockTokenService := new(MockTokenService)
	mockAuditService := new(MockUserAuditService)

	cfg := &config.Config{}
	service := NewUserService(cfg, mockUserRepo, mockRoleRepo, mockTokenService, mockAuditService)

	users := []models.User{
		{ID: uuid.New(), Username: "user1", Email: "user1@example.com"},
		{ID: uuid.New(), Username: "user2", Email: "user2@example.com"},
	}

	mockUserRepo.On("List", ctx, tenantID, 1, 20, "").Return(users, int64(2), nil)
	mockUserRepo.On("GetUserRoles", ctx, users[0].ID).Return([]models.Role{}, nil)
	mockUserRepo.On("GetUserRoles", ctx, users[1].ID).Return([]models.Role{}, nil)

	// Execute
	result, err := service.List(ctx, tenantID, 1, 20, "")

	// Assert
	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.Len(t, result.Users, 2)
	assert.Equal(t, int64(2), result.Total)
	mockUserRepo.AssertExpectations(t)
}

func TestUserService_List_InvalidPagination(t *testing.T) {
	ctx := context.Background()
	tenantID := uuid.New()

	mockUserRepo := new(MockUserRepository)
	mockRoleRepo := new(MockRoleRepository)
	mockTokenService := new(MockTokenService)
	mockAuditService := new(MockUserAuditService)

	cfg := &config.Config{}
	service := NewUserService(cfg, mockUserRepo, mockRoleRepo, mockTokenService, mockAuditService)

	// Test with invalid page (should default to 1)
	mockUserRepo.On("List", ctx, tenantID, 1, 20, "").Return([]models.User{}, int64(0), nil)

	result, err := service.List(ctx, tenantID, 0, 0, "")

	require.NoError(t, err)
	assert.NotNil(t, result)
	mockUserRepo.AssertExpectations(t)
}

func TestUserService_SetPassword_Success(t *testing.T) {
	ctx := context.Background()
	userID := uuid.New()
	setterID := uuid.New()
	tenantID := uuid.New()

	mockUserRepo := new(MockUserRepository)
	mockRoleRepo := new(MockRoleRepository)
	mockTokenService := new(MockTokenService)
	mockAuditService := new(MockUserAuditService)

	cfg := &config.Config{
		PasswordMinLength:      8,
		PasswordRequireUpper:   true,
		PasswordRequireLower:   true,
		PasswordRequireDigit:   true,
		PasswordRequireSpecial: false,
	}

	service := NewUserService(cfg, mockUserRepo, mockRoleRepo, mockTokenService, mockAuditService)

	existingUser := &models.User{
		ID:       userID,
		TenantID: tenantID,
		Username: "testuser",
	}

	mockUserRepo.On("GetByID", ctx, userID).Return(existingUser, nil)
	mockUserRepo.On("Update", ctx, mock.AnythingOfType("*models.User")).Return(nil)
	mockTokenService.On("RevokeAllUserOAuthTokens", ctx, userID, "password_reset").Return(nil)
	mockAuditService.On("LogUserAction", ctx, tenantID, &setterID, &userID, "user_password_set", true, mock.Anything)

	// Execute
	err := service.SetPassword(ctx, userID, "NewSecureP@ss123", false, &setterID)

	// Assert
	require.NoError(t, err)
	mockUserRepo.AssertExpectations(t)
	mockTokenService.AssertExpectations(t)
	mockAuditService.AssertExpectations(t)
}

func TestUserService_SetPassword_LDAPUserError(t *testing.T) {
	ctx := context.Background()
	userID := uuid.New()

	mockUserRepo := new(MockUserRepository)
	mockRoleRepo := new(MockRoleRepository)
	mockTokenService := new(MockTokenService)
	mockAuditService := new(MockUserAuditService)

	cfg := &config.Config{}
	service := NewUserService(cfg, mockUserRepo, mockRoleRepo, mockTokenService, mockAuditService)

	ldapType := "ldap"
	existingUser := &models.User{
		ID:             userID,
		Username:       "testuser",
		FederationType: &ldapType,
	}

	mockUserRepo.On("GetByID", ctx, userID).Return(existingUser, nil)

	// Execute
	err := service.SetPassword(ctx, userID, "NewSecureP@ss123", false, nil)

	// Assert
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "cannot set password for LDAP users")
	mockUserRepo.AssertExpectations(t)
}

func TestUserService_Lock_Success(t *testing.T) {
	ctx := context.Background()
	userID := uuid.New()
	lockerID := uuid.New()
	tenantID := uuid.New()

	mockUserRepo := new(MockUserRepository)
	mockRoleRepo := new(MockRoleRepository)
	mockTokenService := new(MockTokenService)
	mockAuditService := new(MockUserAuditService)

	cfg := &config.Config{}
	service := NewUserService(cfg, mockUserRepo, mockRoleRepo, mockTokenService, mockAuditService)

	existingUser := &models.User{
		ID:       userID,
		TenantID: tenantID,
		Username: "testuser",
	}

	reason := "security violation"

	mockUserRepo.On("GetByID", ctx, userID).Return(existingUser, nil)
	mockUserRepo.On("Update", ctx, mock.AnythingOfType("*models.User")).Return(nil)
	mockAuditService.On("LogUserAction", ctx, tenantID, &lockerID, &userID, "user_lock", true, map[string]interface{}{"reason": reason})

	// Execute
	err := service.Lock(ctx, userID, reason, &lockerID)

	// Assert
	require.NoError(t, err)
	mockUserRepo.AssertExpectations(t)
	mockAuditService.AssertExpectations(t)
}

func TestUserService_Unlock_Success(t *testing.T) {
	ctx := context.Background()
	userID := uuid.New()
	unlockerID := uuid.New()
	tenantID := uuid.New()

	mockUserRepo := new(MockUserRepository)
	mockRoleRepo := new(MockRoleRepository)
	mockTokenService := new(MockTokenService)
	mockAuditService := new(MockUserAuditService)

	cfg := &config.Config{}
	service := NewUserService(cfg, mockUserRepo, mockRoleRepo, mockTokenService, mockAuditService)

	existingUser := &models.User{
		ID:       userID,
		TenantID: tenantID,
	}

	mockUserRepo.On("UnlockUser", ctx, userID).Return(nil)
	mockUserRepo.On("GetByID", ctx, userID).Return(existingUser, nil)
	mockAuditService.On("LogUserAction", ctx, tenantID, &unlockerID, &userID, "user_unlock", true, mock.Anything)

	// Execute
	err := service.Unlock(ctx, userID, &unlockerID)

	// Assert
	require.NoError(t, err)
	mockUserRepo.AssertExpectations(t)
	mockAuditService.AssertExpectations(t)
}

func TestUserService_SetUserRoles_Success(t *testing.T) {
	ctx := context.Background()
	userID := uuid.New()
	assignerID := uuid.New()
	tenantID := uuid.New()
	roleID1 := uuid.New()
	roleID2 := uuid.New()

	mockUserRepo := new(MockUserRepository)
	mockRoleRepo := new(MockRoleRepository)
	mockTokenService := new(MockTokenService)
	mockAuditService := new(MockUserAuditService)

	cfg := &config.Config{}
	service := NewUserService(cfg, mockUserRepo, mockRoleRepo, mockTokenService, mockAuditService)

	existingUser := &models.User{
		ID:       userID,
		TenantID: tenantID,
	}

	newRoleIDs := []uuid.UUID{roleID1, roleID2}

	mockUserRepo.On("GetByID", ctx, userID).Return(existingUser, nil)
	// SetUserRoles now verifies roles using GetByIDAndTenant for tenant isolation (C-4)
	mockRoleRepo.On("GetByIDAndTenant", ctx, roleID1, tenantID).Return(&models.Role{ID: roleID1, TenantID: tenantID, Priority: 10}, nil)
	mockRoleRepo.On("GetByIDAndTenant", ctx, roleID2, tenantID).Return(&models.Role{ID: roleID2, TenantID: tenantID, Priority: 10}, nil)
	// C-1: caller priority check for assignedBy (assigner has max priority 100, roles have priority 10)
	mockRoleRepo.On("GetMaxPriorityForUser", ctx, assignerID, tenantID).Return(100, nil)
	mockUserRepo.On("GetUserRoles", ctx, userID).Return([]models.Role{}, nil)
	mockUserRepo.On("AssignRoles", ctx, userID, newRoleIDs, &assignerID).Return(nil)

	// Execute
	err := service.SetUserRoles(ctx, userID, newRoleIDs, &assignerID)

	// Assert
	require.NoError(t, err)
	mockUserRepo.AssertExpectations(t)
	mockRoleRepo.AssertExpectations(t)
}

func TestUserService_SetUserRoles_InvalidRole(t *testing.T) {
	ctx := context.Background()
	userID := uuid.New()
	roleID := uuid.New()

	mockUserRepo := new(MockUserRepository)
	mockRoleRepo := new(MockRoleRepository)
	mockTokenService := new(MockTokenService)
	mockAuditService := new(MockUserAuditService)

	cfg := &config.Config{}
	service := NewUserService(cfg, mockUserRepo, mockRoleRepo, mockTokenService, mockAuditService)

	existingUser := &models.User{
		ID: userID,
	}

	mockUserRepo.On("GetByID", ctx, userID).Return(existingUser, nil)
	// SetUserRoles now uses GetByIDAndTenant for tenant isolation (C-4)
	mockRoleRepo.On("GetByIDAndTenant", ctx, roleID, uuid.Nil).Return(nil, errors.New("role not found"))

	// Execute
	err := service.SetUserRoles(ctx, userID, []uuid.UUID{roleID}, nil)

	// Assert
	assert.Error(t, err)
	mockUserRepo.AssertExpectations(t)
	mockRoleRepo.AssertExpectations(t)
}

// mockQuotaClient is a test double for userServiceQuotaClient
// (feat/seat-quota-enforcement) — lets tests control MustCheckQuota's
// allowed/exceeded outcome without a live quota-service.
type mockQuotaClient struct {
	mock.Mock
}

func (m *mockQuotaClient) MustCheckQuota(ctx context.Context, tenantID uuid.UUID, resourceType quota.ResourceType, amount int64) error {
	args := m.Called(ctx, tenantID, resourceType, amount)
	return args.Error(0)
}

func (m *mockQuotaClient) IncrementUsage(ctx context.Context, tenantID uuid.UUID, resourceType quota.ResourceType, amount int64) (bool, error) {
	args := m.Called(ctx, tenantID, resourceType, amount)
	return args.Bool(0), args.Error(1)
}

func (m *mockQuotaClient) DecrementUsage(ctx context.Context, tenantID uuid.UUID, resourceType quota.ResourceType, amount int64) error {
	args := m.Called(ctx, tenantID, resourceType, amount)
	return args.Error(0)
}

// TestUserService_Create_SeatLimitExceeded_BlocksWrite is the "fail" half
// of the seat-quota enforcement control pair: when quota-service reports
// the tenant's seat quota exceeded, Create must return
// *SeatLimitExceededError WITHOUT ever calling userRepo.Create. No
// mockUserRepo.On("Create", ...) expectation is registered below — if the
// enforcement check did NOT block the write, mockUserRepo.Create would be
// invoked as an unexpected call and testify's mock.Mock would fail the
// test on that call, which is what makes this a control: an enforcement
// bug that lets the write through cannot pass silently.
func TestUserService_Create_SeatLimitExceeded_BlocksWrite(t *testing.T) {
	ctx := context.Background()
	tenantID := uuid.New()
	creatorID := uuid.New()

	mockUserRepo := new(MockUserRepository)
	mockRoleRepo := new(MockRoleRepository)
	mockTokenService := new(MockTokenService)
	mockAuditService := new(MockUserAuditService)
	mockQuota := new(mockQuotaClient)

	cfg := &config.Config{
		PasswordMinLength:       8,
		PasswordRequireUpper:    true,
		PasswordRequireLower:    true,
		PasswordRequireDigit:    true,
		QuotaEnforcementEnabled: true,
	}

	service := NewUserService(cfg, mockUserRepo, mockRoleRepo, mockTokenService, mockAuditService)
	service.SetRealmResolver(&mockRealmResolver{})
	service.SetQuotaClient(mockQuota)

	req := &models.CreateUserRequest{
		TenantID: tenantID,
		Username: "seatlimited",
		Email:    "seatlimited@example.com",
		Password: "SecureP@ss123",
	}

	mockUserRepo.On("GetByUsername", ctx, tenantID, "seatlimited").Return(nil, nil)
	mockUserRepo.On("GetByEmail", ctx, tenantID, "seatlimited@example.com").Return(nil, nil)
	mockQuota.On("MustCheckQuota", ctx, tenantID, quota.ResourceTypeUsers, int64(1)).
		Return(&quota.QuotaExceededError{
			ResourceType: quota.ResourceTypeUsers,
			CurrentUsage: 5,
			Limit:        5,
			Message:      "seat limit reached for plan",
		})
	// Deliberately NOT stubbing mockUserRepo.On("Create", ...) — see doc
	// comment above.

	user, err := service.Create(ctx, req, &creatorID)

	require.Error(t, err)
	assert.Nil(t, user)
	var seatErr *SeatLimitExceededError
	require.ErrorAs(t, err, &seatErr)
	assert.True(t, errors.Is(err, ErrSeatLimitExceeded))
	assert.Equal(t, int64(5), seatErr.CurrentUsage)
	assert.Equal(t, int64(5), seatErr.Limit)

	mockQuota.AssertExpectations(t)
	mockUserRepo.AssertExpectations(t)
	mockUserRepo.AssertNotCalled(t, "Create", mock.Anything, mock.Anything)
}

// TestUserService_Create_SeatQuotaAllowed_ProceedsToWrite is the "pass"
// half of the control pair: when quota-service allows the seat
// (MustCheckQuota returns nil), Create must proceed to call
// userRepo.Create exactly as it would with no quota client wired at all.
func TestUserService_Create_SeatQuotaAllowed_ProceedsToWrite(t *testing.T) {
	ctx := context.Background()
	tenantID := uuid.New()
	creatorID := uuid.New()

	mockUserRepo := new(MockUserRepository)
	mockRoleRepo := new(MockRoleRepository)
	mockTokenService := new(MockTokenService)
	mockAuditService := new(MockUserAuditService)
	mockQuota := new(mockQuotaClient)

	cfg := &config.Config{
		PasswordMinLength:       8,
		PasswordRequireUpper:    true,
		PasswordRequireLower:    true,
		PasswordRequireDigit:    true,
		QuotaEnforcementEnabled: true,
	}

	service := NewUserService(cfg, mockUserRepo, mockRoleRepo, mockTokenService, mockAuditService)
	service.SetRealmResolver(&mockRealmResolver{})
	service.SetQuotaClient(mockQuota)

	req := &models.CreateUserRequest{
		TenantID: tenantID,
		Username: "seatok",
		Email:    "seatok@example.com",
		Password: "SecureP@ss123",
	}

	mockUserRepo.On("GetByUsername", ctx, tenantID, "seatok").Return(nil, nil)
	mockUserRepo.On("GetByEmail", ctx, tenantID, "seatok@example.com").Return(nil, nil)
	mockQuota.On("MustCheckQuota", ctx, tenantID, quota.ResourceTypeUsers, int64(1)).Return(nil)
	mockUserRepo.On("Create", ctx, mock.AnythingOfType("*models.User")).Return(nil)
	mockUserRepo.On("GetUserRoles", ctx, mock.AnythingOfType("uuid.UUID")).Return([]models.Role{}, nil)
	mockUserRepo.On("GetUserPermissions", ctx, mock.AnythingOfType("uuid.UUID")).Return([]models.Permission{}, nil)
	mockAuditService.On("LogUserAction", ctx, tenantID, &creatorID, mock.AnythingOfType("*uuid.UUID"), "user_create", true, mock.Anything)
	mockRoleRepo.On("GetDefaultRoles", ctx, tenantID).Return([]models.Role{}, nil)
	// IncrementUsage fires in a best-effort goroutine after a successful
	// Create; .Maybe() avoids a flaky expectation race against that
	// goroutine while still permitting the call if it lands before the
	// test returns.
	mockQuota.On("IncrementUsage", mock.Anything, tenantID, quota.ResourceTypeUsers, int64(1)).Return(true, nil).Maybe()

	user, err := service.Create(ctx, req, &creatorID)

	require.NoError(t, err)
	assert.NotNil(t, user)
	mockQuota.AssertCalled(t, "MustCheckQuota", ctx, tenantID, quota.ResourceTypeUsers, int64(1))
	mockUserRepo.AssertCalled(t, "Create", ctx, mock.AnythingOfType("*models.User"))
}
