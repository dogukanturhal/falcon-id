// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

const (
	testExportNameAlice = "Alice"
	testExportIP192     = "192.168.1.1"
)

// ---------------------------------------------------------------------------
// Mock implementations
// ---------------------------------------------------------------------------

type mockDataExportUserRepo struct {
	mock.Mock
}

func (m *mockDataExportUserRepo) GetByID(ctx context.Context, id uuid.UUID) (*models.User, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.User), args.Error(1)
}

func (m *mockDataExportUserRepo) GetUserRoles(ctx context.Context, userID uuid.UUID) ([]models.Role, error) {
	args := m.Called(ctx, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]models.Role), args.Error(1)
}

func (m *mockDataExportUserRepo) GetUserPermissions(ctx context.Context, userID uuid.UUID) ([]models.Permission, error) {
	args := m.Called(ctx, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]models.Permission), args.Error(1)
}

type mockDataExportSessionRepo struct {
	mock.Mock
}

func (m *mockDataExportSessionRepo) GetActiveSessions(ctx context.Context, userID uuid.UUID) ([]models.Session, error) {
	args := m.Called(ctx, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]models.Session), args.Error(1)
}

type mockDataExportDeviceRepo struct {
	mock.Mock
}

func (m *mockDataExportDeviceRepo) GetByUserID(ctx context.Context, userID uuid.UUID, page, pageSize int) ([]models.Device, int64, error) {
	args := m.Called(ctx, userID, page, pageSize)
	if args.Get(0) == nil {
		return nil, args.Get(1).(int64), args.Error(2)
	}
	return args.Get(0).([]models.Device), args.Get(1).(int64), args.Error(2)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// newTestDataExportService creates a DataExportService with nil db.
// getAuditLogs guards against nil db and returns an empty slice gracefully,
// so no live database is required for these unit tests.
func newTestDataExportService(
	userRepo dataExportUserRepo,
	sessionRepo dataExportSessionRepo,
	deviceRepo dataExportDeviceRepo,
) *DataExportService {
	return &DataExportService{
		userRepo:    userRepo,
		sessionRepo: sessionRepo,
		deviceRepo:  deviceRepo,
		db:          nil, // nil-safe: getAuditLogs returns [] when db is nil
	}
}

func buildTestUser() *models.User {
	firstName := testExportNameAlice
	lastName := "Smith"
	now := time.Now().UTC()
	return &models.User{
		ID:              uuid.New(),
		TenantID:        uuid.New(),
		RealmID:         uuid.New(),
		Username:        "alice",
		Email:           "alice@example.com",
		FirstName:       &firstName,
		LastName:        &lastName,
		IsActive:        true,
		IsEmailVerified: true,
		MFAEnabled:      false,
		CreatedAt:       now,
		UpdatedAt:       now,
	}
}

func buildTestUserWithMFA() *models.User {
	u := buildTestUser()
	u.MFAEnabled = true
	u.MFATOTPEnabled = true
	u.MFAEmailEnabled = true
	preferred := authMethodTOTP
	u.MFAPreferredMethod = &preferred
	return u
}

// strPtr returns a pointer to the given string literal.
// Note: saml_sp_service.go also defines strPtr in this package.
// We do not redeclare it; instead use the shared definition.

// ---------------------------------------------------------------------------
// TestDataExportService_CollectUserData
// ---------------------------------------------------------------------------

func TestDataExportService_CollectUserData_Success(t *testing.T) {
	ctx := context.Background()
	user := buildTestUser()

	roles := []models.Role{
		{ID: uuid.New(), Name: "admin"},
		{ID: uuid.New(), Name: "viewer"},
	}
	permissions := []models.Permission{
		{ID: uuid.New(), Name: "users:read"},
	}
	ip := testExportIP192
	sessions := []models.Session{
		{
			ID:             uuid.New(),
			UserID:         user.ID,
			IPAddress:      &ip,
			CreatedAt:      time.Now(),
			LastActivityAt: time.Now(),
			ExpiresAt:      time.Now().Add(24 * time.Hour),
		},
	}
	deviceType := routingDeviceDesktop
	devices := []models.Device{
		{
			ID:              uuid.New(),
			UserID:          user.ID,
			FingerprintHash: "abc123def456abc123def456abc123de",
			DeviceType:      &deviceType,
			IsTrusted:       true,
			FirstSeenAt:     time.Now(),
			LastSeenAt:      time.Now(),
		},
	}

	userRepo := new(mockDataExportUserRepo)
	sessionRepo := new(mockDataExportSessionRepo)
	deviceRepo := new(mockDataExportDeviceRepo)

	userRepo.On("GetByID", ctx, user.ID).Return(user, nil)
	userRepo.On("GetUserRoles", ctx, user.ID).Return(roles, nil)
	userRepo.On("GetUserPermissions", ctx, user.ID).Return(permissions, nil)
	sessionRepo.On("GetActiveSessions", ctx, user.ID).Return(sessions, nil)
	deviceRepo.On("GetByUserID", ctx, user.ID, 1, 1000).Return(devices, int64(1), nil)

	svc := newTestDataExportService(userRepo, sessionRepo, deviceRepo)
	result, err := svc.CollectUserData(ctx, user.ID)

	require.NoError(t, err)
	require.NotNil(t, result)

	// Verify user data fields
	assert.Equal(t, user.ID.String(), result.User.ID)
	assert.Equal(t, user.TenantID.String(), result.User.TenantID)
	assert.Equal(t, user.Username, result.User.Username)
	assert.Equal(t, user.Email, result.User.Email)
	assert.Equal(t, user.FirstName, result.User.FirstName)
	assert.Equal(t, user.IsActive, result.User.IsActive)
	assert.Equal(t, user.IsEmailVerified, result.User.IsEmailVerified)

	// Verify roles and permissions
	require.Len(t, result.User.Roles, 2)
	assert.Contains(t, result.User.Roles, "admin")
	assert.Contains(t, result.User.Roles, "viewer")
	require.Len(t, result.User.Permissions, 1)
	assert.Equal(t, "users:read", result.User.Permissions[0])

	// Verify sessions
	require.Len(t, result.Sessions, 1)
	assert.Equal(t, sessions[0].ID.String(), result.Sessions[0].ID)

	// Verify devices
	require.Len(t, result.Devices, 1)
	assert.Equal(t, devices[0].ID.String(), result.Devices[0].ID)
	assert.True(t, result.Devices[0].IsTrusted)
	// Fingerprint is truncated to 16 chars + "..." when longer than 16 chars
	assert.Contains(t, result.Devices[0].Fingerprint, "abc123def456abc1")

	// MFA nil since user.MFAEnabled == false
	assert.Nil(t, result.MFA)
	// Audit logs empty since db is nil (nil-safe guard)
	assert.Empty(t, result.Audit)

	userRepo.AssertExpectations(t)
	sessionRepo.AssertExpectations(t)
	deviceRepo.AssertExpectations(t)
}

func TestDataExportService_CollectUserData_WithMFA(t *testing.T) {
	ctx := context.Background()
	user := buildTestUserWithMFA()

	userRepo := new(mockDataExportUserRepo)
	sessionRepo := new(mockDataExportSessionRepo)
	deviceRepo := new(mockDataExportDeviceRepo)

	userRepo.On("GetByID", ctx, user.ID).Return(user, nil)
	userRepo.On("GetUserRoles", ctx, user.ID).Return([]models.Role{}, nil)
	userRepo.On("GetUserPermissions", ctx, user.ID).Return([]models.Permission{}, nil)
	sessionRepo.On("GetActiveSessions", ctx, user.ID).Return([]models.Session{}, nil)
	deviceRepo.On("GetByUserID", ctx, user.ID, 1, 1000).Return(nil, int64(0), nil)

	svc := newTestDataExportService(userRepo, sessionRepo, deviceRepo)
	result, err := svc.CollectUserData(ctx, user.ID)

	require.NoError(t, err)
	require.NotNil(t, result.MFA)
	assert.True(t, result.MFA.Enabled)
	assert.True(t, result.MFA.TOTPEnabled)
	assert.True(t, result.MFA.EmailEnabled)
	require.NotNil(t, result.MFA.PreferredMethod)
	assert.Equal(t, authMethodTOTP, *result.MFA.PreferredMethod)
}

func TestDataExportService_CollectUserData_UserNotFound(t *testing.T) {
	ctx := context.Background()
	userID := uuid.New()

	userRepo := new(mockDataExportUserRepo)
	sessionRepo := new(mockDataExportSessionRepo)
	deviceRepo := new(mockDataExportDeviceRepo)

	userRepo.On("GetByID", ctx, userID).Return(nil, nil)

	svc := newTestDataExportService(userRepo, sessionRepo, deviceRepo)
	result, err := svc.CollectUserData(ctx, userID)

	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "user not found")
}

func TestDataExportService_CollectUserData_GetByIDError(t *testing.T) {
	ctx := context.Background()
	userID := uuid.New()

	userRepo := new(mockDataExportUserRepo)
	sessionRepo := new(mockDataExportSessionRepo)
	deviceRepo := new(mockDataExportDeviceRepo)

	userRepo.On("GetByID", ctx, userID).Return(nil, errors.New("db connection error"))

	svc := newTestDataExportService(userRepo, sessionRepo, deviceRepo)
	result, err := svc.CollectUserData(ctx, userID)

	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "failed to get user")
}

func TestDataExportService_CollectUserData_RolesError_ContinuesGracefully(t *testing.T) {
	ctx := context.Background()
	user := buildTestUser()

	userRepo := new(mockDataExportUserRepo)
	sessionRepo := new(mockDataExportSessionRepo)
	deviceRepo := new(mockDataExportDeviceRepo)

	userRepo.On("GetByID", ctx, user.ID).Return(user, nil)
	userRepo.On("GetUserRoles", ctx, user.ID).Return(nil, errors.New("roles unavailable"))
	userRepo.On("GetUserPermissions", ctx, user.ID).Return([]models.Permission{}, nil)
	sessionRepo.On("GetActiveSessions", ctx, user.ID).Return([]models.Session{}, nil)
	deviceRepo.On("GetByUserID", ctx, user.ID, 1, 1000).Return(nil, int64(0), nil)

	svc := newTestDataExportService(userRepo, sessionRepo, deviceRepo)
	result, err := svc.CollectUserData(ctx, user.ID)

	// Service continues despite roles error
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Empty(t, result.User.Roles)
}

func TestDataExportService_CollectUserData_SessionsError_ContinuesGracefully(t *testing.T) {
	ctx := context.Background()
	user := buildTestUser()

	userRepo := new(mockDataExportUserRepo)
	sessionRepo := new(mockDataExportSessionRepo)
	deviceRepo := new(mockDataExportDeviceRepo)

	userRepo.On("GetByID", ctx, user.ID).Return(user, nil)
	userRepo.On("GetUserRoles", ctx, user.ID).Return([]models.Role{}, nil)
	userRepo.On("GetUserPermissions", ctx, user.ID).Return([]models.Permission{}, nil)
	sessionRepo.On("GetActiveSessions", ctx, user.ID).Return(nil, errors.New("session store offline"))
	deviceRepo.On("GetByUserID", ctx, user.ID, 1, 1000).Return(nil, int64(0), nil)

	svc := newTestDataExportService(userRepo, sessionRepo, deviceRepo)
	result, err := svc.CollectUserData(ctx, user.ID)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Empty(t, result.Sessions)
}

func TestDataExportService_CollectUserData_DevicesError_ContinuesGracefully(t *testing.T) {
	ctx := context.Background()
	user := buildTestUser()

	userRepo := new(mockDataExportUserRepo)
	sessionRepo := new(mockDataExportSessionRepo)
	deviceRepo := new(mockDataExportDeviceRepo)

	userRepo.On("GetByID", ctx, user.ID).Return(user, nil)
	userRepo.On("GetUserRoles", ctx, user.ID).Return([]models.Role{}, nil)
	userRepo.On("GetUserPermissions", ctx, user.ID).Return([]models.Permission{}, nil)
	sessionRepo.On("GetActiveSessions", ctx, user.ID).Return([]models.Session{}, nil)
	deviceRepo.On("GetByUserID", ctx, user.ID, 1, 1000).Return(nil, int64(0), errors.New("device store unavailable"))

	svc := newTestDataExportService(userRepo, sessionRepo, deviceRepo)
	result, err := svc.CollectUserData(ctx, user.ID)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Empty(t, result.Devices)
}

// ---------------------------------------------------------------------------
// TestDataExportService_ExportToJSON
// ---------------------------------------------------------------------------

func TestDataExportService_ExportToJSON_ValidOutput(t *testing.T) {
	svc := newTestDataExportService(nil, nil, nil)

	firstName := testExportNameAlice
	data := &UserExportData{
		User: &UserData{
			ID:        uuid.New().String(),
			TenantID:  uuid.New().String(),
			RealmID:   uuid.New().String(),
			Username:  "alice",
			Email:     "alice@example.com",
			FirstName: &firstName,
			IsActive:  true,
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
			Roles:     []string{"admin"},
		},
		Sessions: []SessionData{},
		Devices:  []DeviceData{},
		Audit:    []AuditLogData{},
	}

	jsonBytes, err := svc.ExportToJSON(data)

	require.NoError(t, err)
	require.NotEmpty(t, jsonBytes)

	// Verify valid JSON is produced
	var parsed map[string]interface{}
	require.NoError(t, json.Unmarshal(jsonBytes, &parsed))

	// Verify top-level keys are present
	assert.Contains(t, parsed, "user")
	assert.Contains(t, parsed, "sessions")
	assert.Contains(t, parsed, "devices")
	assert.Contains(t, parsed, "audit_logs")

	// Verify user fields
	userMap, ok := parsed["user"].(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, "alice", userMap["username"])
	assert.Equal(t, "alice@example.com", userMap["email"])
	assert.Equal(t, true, userMap["is_active"])
}

func TestDataExportService_ExportToJSON_MFAOmittedWhenNil(t *testing.T) {
	svc := newTestDataExportService(nil, nil, nil)

	data := &UserExportData{
		User: &UserData{
			ID:        uuid.New().String(),
			TenantID:  uuid.New().String(),
			RealmID:   uuid.New().String(),
			Username:  "bob",
			Email:     "bob@example.com",
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
			Roles:     []string{},
		},
		Sessions: []SessionData{},
		Devices:  []DeviceData{},
		Audit:    []AuditLogData{},
		MFA:      nil, // should be omitted from JSON
	}

	jsonBytes, err := svc.ExportToJSON(data)
	require.NoError(t, err)

	var parsed map[string]interface{}
	require.NoError(t, json.Unmarshal(jsonBytes, &parsed))
	assert.NotContains(t, parsed, "mfa")
}

// ---------------------------------------------------------------------------
// TestDataExportService_ExportToCSV
// ---------------------------------------------------------------------------

func TestDataExportService_ExportToCSV_ContainsExpectedSections(t *testing.T) {
	svc := newTestDataExportService(nil, nil, nil)

	firstName := testExportNameAlice
	deviceType := routingDeviceDesktop
	ip := testAuthIP
	data := &UserExportData{
		User: &UserData{
			ID:        uuid.New().String(),
			TenantID:  uuid.New().String(),
			RealmID:   uuid.New().String(),
			Username:  "alice",
			Email:     "alice@example.com",
			FirstName: &firstName,
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
			Roles:     []string{},
		},
		Sessions: []SessionData{
			{
				ID:        uuid.New().String(),
				IPAddress: &ip,
				CreatedAt: time.Now(),
				ExpiresAt: time.Now().Add(24 * time.Hour),
			},
		},
		Devices: []DeviceData{
			{
				ID:          uuid.New().String(),
				Fingerprint: "abcdef...",
				DeviceType:  &deviceType,
				FirstSeenAt: time.Now(),
				LastSeenAt:  time.Now(),
			},
		},
		Audit: []AuditLogData{
			{
				ID:        uuid.New().String(),
				Action:    "login",
				Success:   true,
				CreatedAt: time.Now(),
			},
		},
	}

	csvBytes, err := svc.ExportToCSV(data)

	require.NoError(t, err)
	require.NotEmpty(t, csvBytes)

	csvStr := string(csvBytes)
	assert.Contains(t, csvStr, "=== USER DATA ===")
	assert.Contains(t, csvStr, "=== SESSIONS ===")
	assert.Contains(t, csvStr, "=== DEVICES ===")
	assert.Contains(t, csvStr, "=== AUDIT LOGS ===")
	assert.Contains(t, csvStr, "alice")
	assert.Contains(t, csvStr, "alice@example.com")
	assert.Contains(t, csvStr, testAuthIP)
	assert.Contains(t, csvStr, "login")
}

func TestDataExportService_ExportToCSV_EmptySections(t *testing.T) {
	svc := newTestDataExportService(nil, nil, nil)

	data := &UserExportData{
		User: &UserData{
			ID:        uuid.New().String(),
			TenantID:  uuid.New().String(),
			RealmID:   uuid.New().String(),
			Username:  "testuser",
			Email:     "testuser@example.com",
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
			Roles:     []string{},
		},
		Sessions: []SessionData{},
		Devices:  []DeviceData{},
		Audit:    []AuditLogData{},
	}

	csvBytes, err := svc.ExportToCSV(data)

	require.NoError(t, err)
	assert.Contains(t, string(csvBytes), "testuser")
}

// ---------------------------------------------------------------------------
// TestDataExportService_DeviceFingerprintTruncation
// ---------------------------------------------------------------------------

func TestDataExportService_CollectUserData_FingerprintTruncation(t *testing.T) {
	tests := []struct {
		name            string
		fingerprintHash string
		wantContains    string
	}{
		{
			name:            "long fingerprint is truncated with ellipsis",
			fingerprintHash: "abcdef1234567890abcdef1234567890",
			wantContains:    "abcdef1234567890...",
		},
		{
			name:            "short fingerprint kept as-is",
			fingerprintHash: "abc123",
			wantContains:    "abc123",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			user := buildTestUser()

			userRepo := new(mockDataExportUserRepo)
			sessionRepo := new(mockDataExportSessionRepo)
			deviceRepo := new(mockDataExportDeviceRepo)

			deviceType := routingDeviceDesktop
			devices := []models.Device{
				{
					ID:              uuid.New(),
					UserID:          user.ID,
					FingerprintHash: tt.fingerprintHash,
					DeviceType:      &deviceType,
					FirstSeenAt:     time.Now(),
					LastSeenAt:      time.Now(),
				},
			}

			userRepo.On("GetByID", ctx, user.ID).Return(user, nil)
			userRepo.On("GetUserRoles", ctx, user.ID).Return([]models.Role{}, nil)
			userRepo.On("GetUserPermissions", ctx, user.ID).Return([]models.Permission{}, nil)
			sessionRepo.On("GetActiveSessions", ctx, user.ID).Return([]models.Session{}, nil)
			deviceRepo.On("GetByUserID", ctx, user.ID, 1, 1000).Return(devices, int64(1), nil)

			svc := newTestDataExportService(userRepo, sessionRepo, deviceRepo)
			result, err := svc.CollectUserData(ctx, user.ID)

			require.NoError(t, err)
			require.Len(t, result.Devices, 1)
			assert.Equal(t, tt.wantContains, result.Devices[0].Fingerprint)
		})
	}
}

// ---------------------------------------------------------------------------
// TestDataExportService_CompleteExportFlow
// ---------------------------------------------------------------------------

func TestDataExportService_CompleteExportFlow(t *testing.T) {
	ctx := context.Background()
	user := buildTestUser()

	userRepo := new(mockDataExportUserRepo)
	sessionRepo := new(mockDataExportSessionRepo)
	deviceRepo := new(mockDataExportDeviceRepo)

	userRepo.On("GetByID", ctx, user.ID).Return(user, nil)
	userRepo.On("GetUserRoles", ctx, user.ID).Return([]models.Role{}, nil)
	userRepo.On("GetUserPermissions", ctx, user.ID).Return([]models.Permission{}, nil)
	sessionRepo.On("GetActiveSessions", ctx, user.ID).Return([]models.Session{}, nil)
	deviceRepo.On("GetByUserID", ctx, user.ID, 1, 1000).Return(nil, int64(0), nil)

	svc := newTestDataExportService(userRepo, sessionRepo, deviceRepo)

	exportData, err := svc.CollectUserData(ctx, user.ID)
	require.NoError(t, err)

	// Export to JSON
	jsonBytes, err := svc.ExportToJSON(exportData)
	require.NoError(t, err)
	assert.Greater(t, len(jsonBytes), 0)

	// Export to CSV
	csvBytes, err := svc.ExportToCSV(exportData)
	require.NoError(t, err)
	assert.Greater(t, len(csvBytes), 0)

	// JSON should be parseable and contain the correct username
	var jsonResult UserExportData
	require.NoError(t, json.Unmarshal(jsonBytes, &jsonResult))
	assert.Equal(t, user.Username, jsonResult.User.Username)
}

func TestDataExportService_CollectUserData_EmptyRolesAndPermissions(t *testing.T) {
	ctx := context.Background()
	user := buildTestUser()

	userRepo := new(mockDataExportUserRepo)
	sessionRepo := new(mockDataExportSessionRepo)
	deviceRepo := new(mockDataExportDeviceRepo)

	userRepo.On("GetByID", ctx, user.ID).Return(user, nil)
	userRepo.On("GetUserRoles", ctx, user.ID).Return([]models.Role{}, nil)
	userRepo.On("GetUserPermissions", ctx, user.ID).Return([]models.Permission{}, nil)
	sessionRepo.On("GetActiveSessions", ctx, user.ID).Return([]models.Session{}, nil)
	deviceRepo.On("GetByUserID", ctx, user.ID, 1, 1000).Return(nil, int64(0), nil)

	svc := newTestDataExportService(userRepo, sessionRepo, deviceRepo)
	result, err := svc.CollectUserData(ctx, user.ID)

	require.NoError(t, err)
	assert.NotNil(t, result.User.Roles)
	assert.NotNil(t, result.User.Permissions)
	assert.Empty(t, result.User.Roles)
	assert.Empty(t, result.User.Permissions)
	assert.Empty(t, result.Sessions)
	assert.Empty(t, result.Devices)
}

// Table-driven test for core error scenarios
func TestDataExportService_CollectUserData_TableDriven(t *testing.T) {
	type testCase struct {
		name          string
		user          *models.User
		userRepoErr   error
		wantErr       bool
		wantErrSubstr string
	}

	tests := []testCase{
		{
			name:    "nil user returned means not found",
			user:    nil,
			wantErr: true,
		},
		{
			name:          "repo error propagates",
			user:          nil,
			userRepoErr:   errors.New("connection refused"),
			wantErr:       true,
			wantErrSubstr: "failed to get user",
		},
		{
			name:    "valid user succeeds",
			user:    buildTestUser(),
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			userID := uuid.New()
			if tt.user != nil {
				userID = tt.user.ID
			}

			userRepo := new(mockDataExportUserRepo)
			sessionRepo := new(mockDataExportSessionRepo)
			deviceRepo := new(mockDataExportDeviceRepo)

			userRepo.On("GetByID", ctx, userID).Return(tt.user, tt.userRepoErr)

			if tt.user != nil {
				userRepo.On("GetUserRoles", ctx, userID).Return([]models.Role{}, nil)
				userRepo.On("GetUserPermissions", ctx, userID).Return([]models.Permission{}, nil)
				sessionRepo.On("GetActiveSessions", ctx, userID).Return([]models.Session{}, nil)
				deviceRepo.On("GetByUserID", ctx, userID, 1, 1000).Return(nil, int64(0), nil)
			}

			svc := newTestDataExportService(userRepo, sessionRepo, deviceRepo)
			result, err := svc.CollectUserData(ctx, userID)

			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, result)
				if tt.wantErrSubstr != "" {
					assert.Contains(t, err.Error(), tt.wantErrSubstr)
				}
			} else {
				require.NoError(t, err)
				assert.NotNil(t, result)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// TestDataExportService_UserData_FieldMapping
// ---------------------------------------------------------------------------

func TestDataExportService_CollectUserData_AllUserFieldsMapped(t *testing.T) {
	ctx := context.Background()

	phone := "+1234567890"
	department := "Engineering"
	title := "Software Engineer"
	avatarURL := "https://example.com/avatar.png"
	fedType := "saml"
	fedID := "fed-123"
	fedSource := "okta"
	displayName := "Alice Smith"
	lastIP := "10.0.0.5"
	now := time.Now().UTC()
	passChangedAt := now.Add(-24 * time.Hour)
	lastLoginAt := now.Add(-1 * time.Hour)

	user := &models.User{
		ID:                uuid.New(),
		TenantID:          uuid.New(),
		RealmID:           uuid.New(),
		Username:          "alice",
		Email:             "alice@example.com",
		DisplayName:       &displayName,
		Phone:             &phone,
		Department:        &department,
		Title:             &title,
		AvatarURL:         &avatarURL,
		FederationType:    &fedType,
		FederationID:      &fedID,
		FederationSource:  &fedSource,
		IsActive:          true,
		IsEmailVerified:   true,
		MFAEnabled:        false,
		LastLoginAt:       &lastLoginAt,
		LastLoginIP:       &lastIP,
		PasswordChangedAt: &passChangedAt,
		CreatedAt:         now,
		UpdatedAt:         now,
	}

	userRepo := new(mockDataExportUserRepo)
	sessionRepo := new(mockDataExportSessionRepo)
	deviceRepo := new(mockDataExportDeviceRepo)

	userRepo.On("GetByID", ctx, user.ID).Return(user, nil)
	userRepo.On("GetUserRoles", ctx, user.ID).Return([]models.Role{}, nil)
	userRepo.On("GetUserPermissions", ctx, user.ID).Return([]models.Permission{}, nil)
	sessionRepo.On("GetActiveSessions", ctx, user.ID).Return([]models.Session{}, nil)
	deviceRepo.On("GetByUserID", ctx, user.ID, 1, 1000).Return(nil, int64(0), nil)

	svc := newTestDataExportService(userRepo, sessionRepo, deviceRepo)
	result, err := svc.CollectUserData(ctx, user.ID)

	require.NoError(t, err)
	require.NotNil(t, result.User)

	ud := result.User
	assert.Equal(t, user.ID.String(), ud.ID)
	assert.Equal(t, user.TenantID.String(), ud.TenantID)
	assert.Equal(t, &displayName, ud.DisplayName)
	assert.Equal(t, &phone, ud.Phone)
	assert.Equal(t, &department, ud.Department)
	assert.Equal(t, &title, ud.Title)
	assert.Equal(t, &avatarURL, ud.AvatarURL)
	assert.Equal(t, &fedType, ud.FederationType)
	assert.Equal(t, &fedID, ud.FederationID)
	assert.Equal(t, &fedSource, ud.FederationSource)
	assert.Equal(t, &lastIP, ud.LastLoginIP)
	assert.Equal(t, &passChangedAt, ud.PasswordChangedAt)
	assert.Equal(t, &lastLoginAt, ud.LastLoginAt)
}
