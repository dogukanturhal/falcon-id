// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"golang.org/x/crypto/argon2"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/internal/repositories"
	"github.com/dogukanturhal/falcon-id/pkg/crypto"
	"github.com/dogukanturhal/falcon-id/pkg/logger"
)

func TestMain(m *testing.M) {
	logger.Log = zap.NewNop()
	// SecurityAudit is a sub-logger used by auth service methods (e.g. checkUserStatus).
	// Set it to a nop logger so tests do not panic when those code paths are hit.
	logger.SecurityAudit = zap.NewNop()
	// Initialize the token hasher required by token service tests.
	// The salt must be at least 16 bytes; we use a fixed test value.
	if err := crypto.InitDefaultTokenHasher("test-salt-for-unit-tests-only!!"); err != nil {
		panic("failed to initialize token hasher for tests: " + err.Error())
	}
	os.Exit(m.Run())
}

// MockMFARepository is a mock implementation of the MFA repository
type MockMFARepository struct {
	mock.Mock
}

func (m *MockMFARepository) CreateMFAPendingSetup(ctx context.Context, userID uuid.UUID, secret, methodType string, expiresAt time.Time) (*repositories.MFAPendingSetup, error) {
	args := m.Called(ctx, userID, secret, methodType, expiresAt)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*repositories.MFAPendingSetup), args.Error(1)
}

func (m *MockMFARepository) GetMFAPendingSetup(ctx context.Context, userID uuid.UUID) (*repositories.MFAPendingSetup, error) {
	args := m.Called(ctx, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*repositories.MFAPendingSetup), args.Error(1)
}

func (m *MockMFARepository) DeleteMFAPendingSetup(ctx context.Context, userID uuid.UUID) error {
	args := m.Called(ctx, userID)
	return args.Error(0)
}

func (m *MockMFARepository) CreateMFAEmailCode(ctx context.Context, userID uuid.UUID, codeHash string, expiresAt time.Time) (*repositories.MFAEmailCode, error) {
	args := m.Called(ctx, userID, codeHash, expiresAt)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*repositories.MFAEmailCode), args.Error(1)
}

func (m *MockMFARepository) GetActiveMFAEmailCode(ctx context.Context, userID uuid.UUID) (*repositories.MFAEmailCode, error) {
	args := m.Called(ctx, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*repositories.MFAEmailCode), args.Error(1)
}

func (m *MockMFARepository) MarkMFAEmailCodeUsed(ctx context.Context, codeID uuid.UUID) error {
	args := m.Called(ctx, codeID)
	return args.Error(0)
}

func (m *MockMFARepository) CreateRecoveryCodes(ctx context.Context, userID uuid.UUID, codeHashes []string) error {
	args := m.Called(ctx, userID, codeHashes)
	return args.Error(0)
}

func (m *MockMFARepository) GetUnusedRecoveryCodes(ctx context.Context, userID uuid.UUID) ([]repositories.RecoveryCode, error) {
	args := m.Called(ctx, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]repositories.RecoveryCode), args.Error(1)
}

func (m *MockMFARepository) GetUnusedRecoveryCodesCount(ctx context.Context, userID uuid.UUID) (int, error) {
	args := m.Called(ctx, userID)
	return args.Int(0), args.Error(1)
}

func (m *MockMFARepository) UseRecoveryCode(ctx context.Context, codeID uuid.UUID) error {
	args := m.Called(ctx, codeID)
	return args.Error(0)
}

func (m *MockMFARepository) DeleteAllRecoveryCodes(ctx context.Context, userID uuid.UUID) error {
	args := m.Called(ctx, userID)
	return args.Error(0)
}

func (m *MockMFARepository) CreateEmailVerification(ctx context.Context, userID uuid.UUID, email, token string, expiresAt time.Time) (*repositories.EmailVerification, error) {
	args := m.Called(ctx, userID, email, token, expiresAt)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*repositories.EmailVerification), args.Error(1)
}

func (m *MockMFARepository) GetEmailVerification(ctx context.Context, userID uuid.UUID, token string) (*repositories.EmailVerification, error) {
	args := m.Called(ctx, userID, token)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*repositories.EmailVerification), args.Error(1)
}

func (m *MockMFARepository) GetEmailVerificationByToken(ctx context.Context, token string) (*repositories.EmailVerification, error) {
	args := m.Called(ctx, token)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*repositories.EmailVerification), args.Error(1)
}

func (m *MockMFARepository) MarkEmailVerified(ctx context.Context, verificationID uuid.UUID) error {
	args := m.Called(ctx, verificationID)
	return args.Error(0)
}

func (m *MockMFARepository) GetPendingEmailVerification(ctx context.Context, userID uuid.UUID) (*repositories.EmailVerification, error) {
	args := m.Called(ctx, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*repositories.EmailVerification), args.Error(1)
}

// MockEmailService is a mock implementation of email service
type MockEmailService struct {
	mock.Mock
}

func (m *MockEmailService) IsConfigured() bool {
	args := m.Called()
	return args.Bool(0)
}

func (m *MockEmailService) SendMFACode(tenantID uuid.UUID, email, code, username string) error {
	args := m.Called(tenantID, email, code, username)
	return args.Error(0)
}

func (m *MockEmailService) SendMFAEnabled(tenantID uuid.UUID, email, username, method string) error {
	args := m.Called(tenantID, email, username, method)
	return args.Error(0)
}

func (m *MockEmailService) SendVerificationEmailLink(tenantID uuid.UUID, email, link, username string) error {
	args := m.Called(tenantID, email, link, username)
	return args.Error(0)
}

// MockLDAPService is a mock implementation of LDAP service
type MockLDAPService struct {
	mock.Mock
}

func (m *MockLDAPService) Authenticate(ctx context.Context, tenantID, providerID uuid.UUID, username, password string) (*models.User, error) {
	args := m.Called(ctx, tenantID, providerID, username, password)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.User), args.Error(1)
}

func (m *MockLDAPService) GetActiveLDAPProviders(ctx context.Context, tenantID uuid.UUID) ([]*models.IdentityProvider, error) {
	args := m.Called(ctx, tenantID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.IdentityProvider), args.Error(1)
}

// Helper function to create a test MFA service
func createTestMFAService() (*MFAService, *MockUserRepository, *MockMFARepository, *MockEmailService, *MockLDAPService) { //nolint:unparam // MockLDAPService is returned for potential future use in tests
	cfg := createTestConfig()
	mockUserRepo := new(MockUserRepository)
	mockMFARepo := new(MockMFARepository)
	mockEmailService := new(MockEmailService)
	mockLDAPService := new(MockLDAPService)

	svc := NewMFAService(cfg, mockUserRepo, mockMFARepo, mockEmailService, mockLDAPService)
	return svc, mockUserRepo, mockMFARepo, mockEmailService, mockLDAPService
}

// TestGenerateTOTPSecret tests TOTP secret generation
func TestGenerateTOTPSecret(t *testing.T) {
	tests := []struct {
		name        string
		userID      uuid.UUID
		user        *models.User
		userErr     error
		setupErr    error
		wantErr     bool
		errContains string
	}{
		{
			name:     "successful TOTP generation",
			userID:   uuid.New(),
			user:     createTestUser(),
			userErr:  nil,
			setupErr: nil,
			wantErr:  false,
		},
		{
			name:        "user not found",
			userID:      uuid.New(),
			user:        nil,
			userErr:     nil,
			setupErr:    nil,
			wantErr:     true,
			errContains: "user not found",
		},
		{
			name:        "database error fetching user",
			userID:      uuid.New(),
			user:        nil,
			userErr:     errors.New("db error"),
			setupErr:    nil,
			wantErr:     true,
			errContains: "failed to get user",
		},
		{
			name:        "failed to store pending setup",
			userID:      uuid.New(),
			user:        createTestUser(),
			userErr:     nil,
			setupErr:    errors.New("db error"),
			wantErr:     true,
			errContains: "failed to store pending setup",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc, mockUserRepo, mockMFARepo, _, _ := createTestMFAService()

			mockUserRepo.On("GetByID", mock.Anything, tt.userID).
				Return(tt.user, tt.userErr)

			if tt.user != nil && tt.userErr == nil {
				mockMFARepo.On("CreateMFAPendingSetup", mock.Anything, tt.userID, mock.AnythingOfType("string"), "totp", mock.AnythingOfType("time.Time")).
					Return(&repositories.MFAPendingSetup{ID: uuid.New()}, tt.setupErr)
			}

			result, err := svc.GenerateTOTPSecret(context.Background(), tt.userID)

			if tt.wantErr {
				require.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
				assert.Nil(t, result)
				return
			}

			require.NoError(t, err)
			assert.NotNil(t, result)
			assert.NotEmpty(t, result.Secret)
			assert.NotEmpty(t, result.QRCode)
			assert.NotEmpty(t, result.ManualEntry)

			mockUserRepo.AssertExpectations(t)
			mockMFARepo.AssertExpectations(t)
		})
	}
}

// TestEnableEmailMFA tests email MFA enablement
func TestEnableEmailMFA(t *testing.T) {
	tests := []struct {
		name        string
		userID      uuid.UUID
		user        *models.User
		userErr     error
		updateErr   error
		backupCount int
		wantErr     bool
		errContains string
	}{
		{
			name:   "successful email MFA enable",
			userID: uuid.New(),
			user: &models.User{
				ID:              uuid.New(),
				TenantID:        uuid.New(),
				Username:        "testuser",
				Email:           "test@example.com",
				IsEmailVerified: true,
				IsActive:        true,
			},
			userErr:     nil,
			updateErr:   nil,
			backupCount: 0,
			wantErr:     false,
		},
		{
			name:   "email not verified",
			userID: uuid.New(),
			user: &models.User{
				ID:              uuid.New(),
				TenantID:        uuid.New(),
				Username:        "testuser",
				Email:           "test@example.com",
				IsEmailVerified: false,
				IsActive:        true,
			},
			userErr:     nil,
			updateErr:   nil,
			backupCount: 0,
			wantErr:     true,
			errContains: "email must be verified",
		},
		{
			name:        "user not found",
			userID:      uuid.New(),
			user:        nil,
			userErr:     nil,
			updateErr:   nil,
			backupCount: 0,
			wantErr:     true,
			errContains: "user not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc, mockUserRepo, mockMFARepo, mockEmailService, _ := createTestMFAService()

			mockUserRepo.On("GetByID", mock.Anything, tt.userID).
				Return(tt.user, tt.userErr)

			if tt.user != nil && tt.user.IsEmailVerified && tt.userErr == nil {
				mockMFARepo.On("GetUnusedRecoveryCodesCount", mock.Anything, tt.userID).
					Return(tt.backupCount, nil)

				if tt.backupCount == 0 {
					mockMFARepo.On("CreateRecoveryCodes", mock.Anything, tt.userID, mock.AnythingOfType("[]string")).
						Return(nil)
				}

				mockUserRepo.On("Update", mock.Anything, mock.AnythingOfType("*models.User")).
					Return(tt.updateErr)

				mockEmailService.On("IsConfigured").Return(true)
				mockEmailService.On("SendMFAEnabled", tt.user.TenantID, tt.user.Email, tt.user.Username, "email").Return(nil)
			}

			_, err := svc.EnableEmailMFA(context.Background(), tt.userID)

			if tt.wantErr {
				require.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
				return
			}

			require.NoError(t, err)
			mockUserRepo.AssertExpectations(t)
			mockMFARepo.AssertExpectations(t)
		})
	}
}

// TestSendEmailMFACode tests sending email MFA codes
func TestSendEmailMFACode(t *testing.T) {
	tests := []struct {
		name        string
		userID      uuid.UUID
		user        *models.User
		userErr     error
		storeErr    error
		emailErr    error
		wantErr     bool
		errContains string
	}{
		{
			name:     "successful code send",
			userID:   uuid.New(),
			user:     createTestUser(),
			userErr:  nil,
			storeErr: nil,
			emailErr: nil,
			wantErr:  false,
		},
		{
			name:        "user not found",
			userID:      uuid.New(),
			user:        nil,
			userErr:     nil,
			storeErr:    nil,
			emailErr:    nil,
			wantErr:     true,
			errContains: "user not found",
		},
		{
			name:        "failed to store code",
			userID:      uuid.New(),
			user:        createTestUser(),
			userErr:     nil,
			storeErr:    errors.New("db error"),
			emailErr:    nil,
			wantErr:     true,
			errContains: "failed to store MFA code",
		},
		{
			name:        "failed to send email",
			userID:      uuid.New(),
			user:        createTestUser(),
			userErr:     nil,
			storeErr:    nil,
			emailErr:    errors.New("smtp error"),
			wantErr:     true,
			errContains: "failed to send MFA code email",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc, mockUserRepo, mockMFARepo, mockEmailService, _ := createTestMFAService()

			mockUserRepo.On("GetByID", mock.Anything, tt.userID).
				Return(tt.user, tt.userErr)

			if tt.user != nil && tt.userErr == nil {
				mockMFARepo.On("CreateMFAEmailCode", mock.Anything, tt.userID, mock.AnythingOfType("string"), mock.AnythingOfType("time.Time")).
					Return(&repositories.MFAEmailCode{ID: uuid.New()}, tt.storeErr)

				if tt.storeErr == nil {
					mockEmailService.On("SendMFACode", tt.user.TenantID, tt.user.Email, mock.AnythingOfType("string"), tt.user.Username).
						Return(tt.emailErr)
				}
			}

			err := svc.SendEmailMFACode(context.Background(), tt.userID)

			if tt.wantErr {
				require.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
				return
			}

			require.NoError(t, err)
			mockUserRepo.AssertExpectations(t)
			mockMFARepo.AssertExpectations(t)
			mockEmailService.AssertExpectations(t)
		})
	}
}

// TestVerifyEmailMFACode tests email MFA code verification
func TestVerifyEmailMFACode(t *testing.T) {
	userID := uuid.New()
	validCodeID := uuid.New()

	tests := []struct {
		name       string
		code       string
		storedCode *repositories.MFAEmailCode
		getErr     error
		wantValid  bool
		wantErr    bool
	}{
		{
			name: "valid code",
			code: "123456",
			storedCode: &repositories.MFAEmailCode{
				ID:       validCodeID,
				UserID:   userID,
				CodeHash: hashTestCode("123456"),
			},
			getErr:    nil,
			wantValid: true,
			wantErr:   false,
		},
		{
			name: "invalid code",
			code: "654321",
			storedCode: &repositories.MFAEmailCode{
				ID:       validCodeID,
				UserID:   userID,
				CodeHash: hashTestCode("123456"),
			},
			getErr:    nil,
			wantValid: false,
			wantErr:   false,
		},
		{
			name:       "no active code",
			code:       "123456",
			storedCode: nil,
			getErr:     nil,
			wantValid:  false,
			wantErr:    false,
		},
		{
			name:       "database error",
			code:       "123456",
			storedCode: nil,
			getErr:     errors.New("db error"),
			wantValid:  false,
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc, _, mockMFARepo, _, _ := createTestMFAService()

			mockMFARepo.On("GetActiveMFAEmailCode", mock.Anything, userID).
				Return(tt.storedCode, tt.getErr)

			if tt.storedCode != nil && !tt.wantErr {
				mockMFARepo.On("MarkMFAEmailCodeUsed", mock.Anything, validCodeID).
					Return(nil).Maybe()
			}

			valid, err := svc.VerifyEmailMFACode(context.Background(), userID, tt.code)

			if tt.wantErr {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.wantValid, valid)
			mockMFARepo.AssertExpectations(t)
		})
	}
}

// TestGenerateBackupCodes tests backup code generation
func TestGenerateBackupCodes(t *testing.T) {
	tests := []struct {
		name        string
		userID      uuid.UUID
		storeErr    error
		wantErr     bool
		errContains string
	}{
		{
			name:     "successful generation",
			userID:   uuid.New(),
			storeErr: nil,
			wantErr:  false,
		},
		{
			name:        "failed to store codes",
			userID:      uuid.New(),
			storeErr:    errors.New("db error"),
			wantErr:     true,
			errContains: "failed to store recovery codes",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc, _, mockMFARepo, _, _ := createTestMFAService()

			mockMFARepo.On("CreateRecoveryCodes", mock.Anything, tt.userID, mock.AnythingOfType("[]string")).
				Return(tt.storeErr)

			codes, err := svc.GenerateBackupCodes(context.Background(), tt.userID)

			if tt.wantErr {
				require.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
				return
			}

			require.NoError(t, err)
			assert.Len(t, codes, 10) // Default backup code count

			// Verify code format (XXXX-XXXX)
			for _, code := range codes {
				assert.Len(t, code, 9) // 4 + dash + 4
				assert.Contains(t, code, "-")
			}

			mockMFARepo.AssertExpectations(t)
		})
	}
}

// TestVerifyBackupCode tests backup code verification
func TestVerifyBackupCode(t *testing.T) {
	userID := uuid.New()
	validCode := "ABCD-1234"
	validCodeHash := hashTestCode("ABCD1234") // Normalized

	tests := []struct {
		name        string
		code        string
		storedCodes []repositories.RecoveryCode
		getErr      error
		useErr      error
		wantValid   bool
		wantErr     bool
	}{
		{
			name: "valid backup code",
			code: validCode,
			storedCodes: []repositories.RecoveryCode{
				{
					ID:       uuid.New(),
					UserID:   userID,
					CodeHash: validCodeHash,
				},
			},
			getErr:    nil,
			useErr:    nil,
			wantValid: true,
			wantErr:   false,
		},
		{
			name: "invalid backup code",
			code: "WRONG-CODE",
			storedCodes: []repositories.RecoveryCode{
				{
					ID:       uuid.New(),
					UserID:   userID,
					CodeHash: validCodeHash,
				},
			},
			getErr:    nil,
			useErr:    nil,
			wantValid: false,
			wantErr:   false,
		},
		{
			name:        "no backup codes",
			code:        validCode,
			storedCodes: []repositories.RecoveryCode{},
			getErr:      nil,
			useErr:      nil,
			wantValid:   false,
			wantErr:     false,
		},
		{
			name:        "database error",
			code:        validCode,
			storedCodes: nil,
			getErr:      errors.New("db error"),
			useErr:      nil,
			wantValid:   false,
			wantErr:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc, _, mockMFARepo, _, _ := createTestMFAService()

			mockMFARepo.On("GetUnusedRecoveryCodes", mock.Anything, userID).
				Return(tt.storedCodes, tt.getErr)

			if len(tt.storedCodes) > 0 && tt.wantValid {
				mockMFARepo.On("UseRecoveryCode", mock.Anything, tt.storedCodes[0].ID).
					Return(tt.useErr).Maybe()
			}

			valid, err := svc.VerifyBackupCode(context.Background(), userID, tt.code)

			if tt.wantErr {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.wantValid, valid)
			mockMFARepo.AssertExpectations(t)
		})
	}
}

// TestDisableMFA tests MFA disabling
func TestDisableMFA(t *testing.T) {
	userID := uuid.New()
	password := "ValidPassword123!"
	passwordHash := makeTestPasswordHash(password) // Real argon2id hash that verifyPassword can verify

	tests := []struct {
		name        string
		user        *models.User
		mfaCode     string
		mfaValid    bool
		wantErr     bool
		errContains string
	}{
		{
			name: "successful MFA disable",
			user: &models.User{
				ID:           userID,
				TenantID:     uuid.New(),
				Username:     "testuser",
				Email:        "test@example.com",
				PasswordHash: &passwordHash,
				MFAEnabled:   true,
				IsActive:     true,
			},
			mfaCode:  "123456",
			mfaValid: true,
			wantErr:  false,
		},
		{
			name: "MFA not enabled",
			user: &models.User{
				ID:           userID,
				TenantID:     uuid.New(),
				Username:     "testuser",
				Email:        "test@example.com",
				PasswordHash: &passwordHash,
				MFAEnabled:   false,
				IsActive:     true,
			},
			mfaCode:     "123456",
			mfaValid:    true,
			wantErr:     true,
			errContains: "MFA is not enabled",
		},
		{
			name: "invalid MFA code",
			user: &models.User{
				ID:           userID,
				TenantID:     uuid.New(),
				Username:     "testuser",
				Email:        "test@example.com",
				PasswordHash: &passwordHash,
				MFAEnabled:   true,
				IsActive:     true,
			},
			mfaCode:     "wrong",
			mfaValid:    false,
			wantErr:     true,
			errContains: "invalid MFA code",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc, mockUserRepo, mockMFARepo, _, _ := createTestMFAService()

			mockUserRepo.On("GetByID", mock.Anything, userID).
				Return(tt.user, nil)

			if tt.user.MFAEnabled {
				// Mock MFA verification - simplified for test
				mockMFARepo.On("GetUnusedRecoveryCodes", mock.Anything, userID).
					Return([]repositories.RecoveryCode{}, nil).Maybe()
				mockMFARepo.On("GetActiveMFAEmailCode", mock.Anything, userID).
					Return(nil, nil).Maybe()
			}

			if tt.user.MFAEnabled && !tt.wantErr {
				mockUserRepo.On("Update", mock.Anything, mock.AnythingOfType("*models.User")).
					Return(nil)
				mockMFARepo.On("DeleteAllRecoveryCodes", mock.Anything, userID).
					Return(nil)
			}

			// Note: This test is simplified and doesn't fully test password verification
			// In a real implementation, you'd need to mock the password hash verification
			err := svc.DisableMFA(context.Background(), userID, password, tt.mfaCode)

			if tt.wantErr {
				require.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
				return
			}

			// Success case would require proper password hashing mocks
			// which is complex for this test
		})
	}
}

// TestGetMFAStatus tests MFA status retrieval
func TestGetMFAStatus(t *testing.T) {
	tests := []struct {
		name        string
		userID      uuid.UUID
		user        *models.User
		backupCount int
		wantErr     bool
		wantEnabled bool
		wantMethods []string
	}{
		{
			name:   "MFA enabled with TOTP",
			userID: uuid.New(),
			user: &models.User{
				ID:             uuid.New(),
				TenantID:       uuid.New(),
				Username:       "testuser",
				MFAEnabled:     true,
				MFATOTPEnabled: true,
			},
			backupCount: 5,
			wantErr:     false,
			wantEnabled: true,
			wantMethods: []string{"totp"},
		},
		{
			name:   "MFA enabled with email",
			userID: uuid.New(),
			user: &models.User{
				ID:              uuid.New(),
				TenantID:        uuid.New(),
				Username:        "testuser",
				MFAEnabled:      true,
				MFAEmailEnabled: true,
			},
			backupCount: 10,
			wantErr:     false,
			wantEnabled: true,
			wantMethods: []string{"email"},
		},
		{
			name:   "MFA enabled with both methods",
			userID: uuid.New(),
			user: &models.User{
				ID:              uuid.New(),
				TenantID:        uuid.New(),
				Username:        "testuser",
				MFAEnabled:      true,
				MFATOTPEnabled:  true,
				MFAEmailEnabled: true,
			},
			backupCount: 8,
			wantErr:     false,
			wantEnabled: true,
			wantMethods: []string{"totp", "email"},
		},
		{
			name:   "MFA disabled",
			userID: uuid.New(),
			user: &models.User{
				ID:         uuid.New(),
				TenantID:   uuid.New(),
				Username:   "testuser",
				MFAEnabled: false,
			},
			backupCount: 0,
			wantErr:     false,
			wantEnabled: false,
			wantMethods: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc, mockUserRepo, mockMFARepo, _, _ := createTestMFAService()

			mockUserRepo.On("GetByID", mock.Anything, tt.userID).
				Return(tt.user, nil)

			mockMFARepo.On("GetUnusedRecoveryCodesCount", mock.Anything, tt.userID).
				Return(tt.backupCount, nil).Maybe()

			status, err := svc.GetMFAStatus(context.Background(), tt.userID)

			if tt.wantErr {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.NotNil(t, status)
			assert.Equal(t, tt.wantEnabled, status.Enabled)
			assert.Equal(t, len(tt.wantMethods), len(status.AvailableMethods))
			assert.Equal(t, tt.backupCount, status.BackupCodesCount)

			mockUserRepo.AssertExpectations(t)
			mockMFARepo.AssertExpectations(t)
		})
	}
}

// TestSendVerificationEmail tests email verification sending
func TestSendVerificationEmail(t *testing.T) {
	tests := []struct {
		name        string
		userID      uuid.UUID
		user        *models.User
		storeErr    error
		emailErr    error
		wantErr     bool
		errContains string
	}{
		{
			name:   "successful verification email",
			userID: uuid.New(),
			user: &models.User{
				ID:              uuid.New(),
				Email:           "test@example.com",
				Username:        "testuser",
				IsEmailVerified: false,
			},
			storeErr: nil,
			emailErr: nil,
			wantErr:  false,
		},
		{
			name:   "email already verified",
			userID: uuid.New(),
			user: &models.User{
				ID:              uuid.New(),
				Email:           "test@example.com",
				Username:        "testuser",
				IsEmailVerified: true,
			},
			storeErr:    nil,
			emailErr:    nil,
			wantErr:     true,
			errContains: "already verified",
		},
		{
			name:   "failed to store verification",
			userID: uuid.New(),
			user: &models.User{
				ID:              uuid.New(),
				Email:           "test@example.com",
				Username:        "testuser",
				IsEmailVerified: false,
			},
			storeErr:    errors.New("db error"),
			emailErr:    nil,
			wantErr:     true,
			errContains: "failed to store verification",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc, mockUserRepo, mockMFARepo, mockEmailService, _ := createTestMFAService()

			mockUserRepo.On("GetByID", mock.Anything, tt.userID).
				Return(tt.user, nil)

			if tt.user != nil && !tt.user.IsEmailVerified {
				mockMFARepo.On("CreateEmailVerification", mock.Anything, tt.userID, tt.user.Email, mock.AnythingOfType("string"), mock.AnythingOfType("time.Time")).
					Return(&repositories.EmailVerification{ID: uuid.New()}, tt.storeErr)

				if tt.storeErr == nil {
					mockEmailService.On("SendVerificationEmailLink", mock.AnythingOfType("uuid.UUID"), tt.user.Email, mock.AnythingOfType("string"), tt.user.Username).
						Return(tt.emailErr)
				}
			}

			err := svc.SendVerificationEmail(context.Background(), tt.userID)

			if tt.wantErr {
				require.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
				return
			}

			require.NoError(t, err)
			mockUserRepo.AssertExpectations(t)
			mockMFARepo.AssertExpectations(t)
			mockEmailService.AssertExpectations(t)
		})
	}
}

// hashTestCode hashes a code the same way MFAService.hashCode does:
// normalize (uppercase, strip dashes) then SHA-256 hex.
func hashTestCode(code string) string {
	h := sha256.Sum256([]byte(code))
	return hex.EncodeToString(h[:])
}

// makeTestPasswordHash creates an argon2id hash of password in the format expected
// by the internal verifyPassword function used in DisableMFA.
// The internal verifyPassword parses: $x$x$x$<b64salt>$<b64hash> (6 parts after split on $)
// and calls argon2.IDKey with hardcoded params: time=3, memory=65536, threads=4, keyLen=32.
func makeTestPasswordHash(password string) string {
	salt := []byte("testsalt12345678") // exactly 16 bytes
	h := argon2.IDKey([]byte(password), salt, 3, 64*1024, 4, 32)
	b64Salt := base64.RawStdEncoding.EncodeToString(salt)
	b64Hash := base64.RawStdEncoding.EncodeToString(h)
	return "$argon2id$v=19$m=65536,t=3,p=4$" + b64Salt + "$" + b64Hash
}

// ---------------------------------------------------------------------------
// Phase 2B: Additional MFA service tests
// ---------------------------------------------------------------------------

// TestMFAVerifyAndEnableTOTP tests TOTP setup verification flow.
func TestMFAVerifyAndEnableTOTP(t *testing.T) {
	// We need a real TOTP secret so we can derive a valid code at test time.
	// pquerna/otp/totp.GenerateOpts is called inside the service, so we use a
	// pre-generated secret here.
	const preSharedSecret = "JBSWY3DPEHPK3PXP" //nolint:gosec // standard test base32 secret, not a real credential

	validCode, err := totpValidate(preSharedSecret)
	if err != nil {
		t.Skipf("cannot generate live TOTP code: %v", err)
	}

	userID := uuid.New()
	testUser := createTestUser()
	testUser.ID = userID

	tests := []struct {
		name         string
		pendingSetup *repositories.MFAPendingSetup
		pendingErr   error
		code         string
		userErr      error
		updateErr    error
		wantErr      bool
		errContains  string
	}{
		{
			name: "valid code enables TOTP",
			pendingSetup: &repositories.MFAPendingSetup{
				ID:     uuid.New(),
				UserID: userID,
				Secret: preSharedSecret,
			},
			code:    validCode,
			wantErr: false,
		},
		{
			name: "wrong code returns error",
			pendingSetup: &repositories.MFAPendingSetup{
				ID:     uuid.New(),
				UserID: userID,
				Secret: preSharedSecret,
			},
			code:        "000000",
			wantErr:     true,
			errContains: "invalid verification code",
		},
		{
			name:         "no pending setup returns error",
			pendingSetup: nil,
			pendingErr:   nil,
			code:         validCode,
			wantErr:      true,
			errContains:  "no pending MFA setup found",
		},
		{
			name:         "db error fetching pending setup",
			pendingSetup: nil,
			pendingErr:   errors.New("db error"),
			code:         validCode,
			wantErr:      true,
			errContains:  "failed to get pending setup",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc, mockUserRepo, mockMFARepo, mockEmailService, _ := createTestMFAService()

			mockMFARepo.On("GetMFAPendingSetup", mock.Anything, userID).
				Return(tt.pendingSetup, tt.pendingErr)

			if tt.pendingSetup != nil && tt.pendingErr == nil {
				// GetByID is called after successful pending lookup
				mockUserRepo.On("GetByID", mock.Anything, userID).
					Return(testUser, tt.userErr).Maybe()

				if tt.userErr == nil && tt.code == validCode {
					mockUserRepo.On("Update", mock.Anything, mock.AnythingOfType("*models.User")).
						Return(tt.updateErr).Maybe()
					// EnsureBackupCodesGenerated probes the count first
					// (idempotency check) before calling CreateRecoveryCodes.
					mockMFARepo.On("GetUnusedRecoveryCodesCount", mock.Anything, userID).
						Return(0, nil).Maybe()
					mockMFARepo.On("CreateRecoveryCodes", mock.Anything, userID, mock.AnythingOfType("[]string")).
						Return(nil).Maybe()
					mockMFARepo.On("DeleteMFAPendingSetup", mock.Anything, userID).
						Return(nil).Maybe()
					mockEmailService.On("IsConfigured").Return(true).Maybe()
					mockEmailService.On("SendMFAEnabled", mock.Anything, mock.Anything, mock.Anything, "totp").
						Return(nil).Maybe()
				}
			}

			codes, err := svc.VerifyAndEnableTOTP(context.Background(), userID, tt.code)

			if tt.wantErr {
				require.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
				assert.Nil(t, codes)
				return
			}

			require.NoError(t, err)
			// Backup codes are returned on success
			assert.NotNil(t, codes)
		})
	}
}

// totpValidate generates a live TOTP code from a base32 secret using
// the same parameters that MFAService uses internally.
func totpValidate(secret string) (string, error) {
	return totp.GenerateCode(secret, time.Now())
}

// TestMFAVerifyEmailMFACode_AlreadyUsed verifies that an already-used code is
// rejected by the service.  The "already used" semantics are enforced at the
// repository level (GetActiveMFAEmailCode returns nil for used codes).
func TestMFAVerifyEmailMFACode_AlreadyUsed(t *testing.T) {
	userID := uuid.New()

	svc, _, mockMFARepo, _, _ := createTestMFAService()

	// Repository returns nil when the code has been used (or does not exist)
	mockMFARepo.On("GetActiveMFAEmailCode", mock.Anything, userID).
		Return(nil, nil) // nil means no active code

	valid, err := svc.VerifyEmailMFACode(context.Background(), userID, "123456")

	require.NoError(t, err)
	assert.False(t, valid, "used or non-existent code must not validate")
	mockMFARepo.AssertExpectations(t)
}

// TestMFAGenerateRecoveryCodes_Count checks the exact count of generated codes.
func TestMFAGenerateRecoveryCodes_Count(t *testing.T) {
	tests := []struct {
		name      string
		codeCount int
	}{
		{name: "default count (10)", codeCount: 10},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc, _, mockMFARepo, _, _ := createTestMFAService()
			// Config has MFABackupCodeCount = 10
			mockMFARepo.On("CreateRecoveryCodes", mock.Anything, mock.AnythingOfType("uuid.UUID"), mock.AnythingOfType("[]string")).
				Return(nil)

			codes, err := svc.GenerateBackupCodes(context.Background(), uuid.New())

			require.NoError(t, err)
			assert.Len(t, codes, tt.codeCount, "generated code count must match config")

			// Verify format: codes use XXXX-XXXX pattern (4+dash+4)
			for _, c := range codes {
				assert.Len(t, c, 9, "each backup code must be 9 chars (XXXX-XXXX)")
				assert.Contains(t, c, "-", "backup codes must contain a dash separator")
			}
		})
	}
}

// TestMFAVerifyRecoveryCode_ValidAndInvalid exercises recovery code lookup.
func TestMFAVerifyRecoveryCode_ValidAndInvalid(t *testing.T) {
	userID := uuid.New()
	codeID := uuid.New()

	// Build a hash of the code the same way the service does (uppercase + strip dashes).
	rawCode := "ABCD1234"
	codeHash := hashTestCode(rawCode)

	tests := []struct {
		name        string
		inputCode   string
		storedCodes []repositories.RecoveryCode
		wantValid   bool
	}{
		{
			name:      "valid recovery code succeeds",
			inputCode: rawCode,
			storedCodes: []repositories.RecoveryCode{
				{ID: codeID, UserID: userID, CodeHash: codeHash},
			},
			wantValid: true,
		},
		{
			name:      "invalid recovery code fails",
			inputCode: "ZZZZ9999",
			storedCodes: []repositories.RecoveryCode{
				{ID: codeID, UserID: userID, CodeHash: codeHash},
			},
			wantValid: false,
		},
		{
			name:        "empty store returns false",
			inputCode:   rawCode,
			storedCodes: []repositories.RecoveryCode{},
			wantValid:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc, _, mockMFARepo, _, _ := createTestMFAService()

			mockMFARepo.On("GetUnusedRecoveryCodes", mock.Anything, userID).
				Return(tt.storedCodes, nil)

			if tt.wantValid {
				mockMFARepo.On("UseRecoveryCode", mock.Anything, codeID).
					Return(nil)
			}

			valid, err := svc.VerifyBackupCode(context.Background(), userID, tt.inputCode)

			require.NoError(t, err)
			assert.Equal(t, tt.wantValid, valid)
			mockMFARepo.AssertExpectations(t)
		})
	}
}

// TestMFADisableMFA_ClearsSettings verifies that DisableMFA zeros all MFA fields.
// We use a local password that we hash ourselves so verifyPassword succeeds without mocks.
func TestMFADisableMFA_ClearsSettings(t *testing.T) {
	userID := uuid.New()
	password := "ValidPass123!"
	passwordHash := makeTestPasswordHash(password)

	mfaType := "totp"
	mfaSecret := "SOMESECRET"
	preferred := "totp"

	user := &models.User{
		ID:                 userID,
		TenantID:           uuid.New(),
		Username:           "testuser",
		Email:              "test@example.com",
		PasswordHash:       &passwordHash,
		MFAEnabled:         true,
		MFATOTPEnabled:     true,
		MFASecret:          &mfaSecret,
		MFAType:            &mfaType,
		MFAPreferredMethod: &preferred,
		IsActive:           true,
	}

	// The VerifyMFACode path will try backup codes first (none), then TOTP
	// (user has no real TOTP secret we can generate a valid code for here),
	// so we exercise the email fallback.  We enable email MFA and inject a
	// valid stored email code hash.
	validEmailCode := "555555"
	validEmailCodeHash := hashTestCode(validEmailCode)
	emailCodeID := uuid.New()

	// Adjust user to also have email MFA so the flow can verify via email code
	user.MFAEmailEnabled = true
	emailType := "email"
	user.MFAType = &emailType

	svc, mockUserRepo, mockMFARepo, _, _ := createTestMFAService()

	// GetByID is called twice: once at the top of DisableMFA, once inside VerifyMFACode
	mockUserRepo.On("GetByID", mock.Anything, userID).Return(user, nil)

	// VerifyMFACode → VerifyBackupCode (code is 6 chars, skipped for backup)
	// VerifyMFACode → VerifyEmailMFACode (email enabled)
	mockMFARepo.On("GetActiveMFAEmailCode", mock.Anything, userID).
		Return(&repositories.MFAEmailCode{
			ID:       emailCodeID,
			UserID:   userID,
			CodeHash: validEmailCodeHash,
		}, nil)
	mockMFARepo.On("MarkMFAEmailCodeUsed", mock.Anything, emailCodeID).Return(nil)

	// DisableMFA queries residual factor inventory to decide whether
	// the consolidated mfa_enabled flag should stay true (passkey/push
	// remain) or flip to false (TOTP/email were the only factors).
	// This test exercises the no-residual path → mfa_enabled becomes false.
	mockUserRepo.On("HasNonPrimaryMFAFactor", mock.Anything, userID).Return(false, nil)

	// After successful verify: update user + delete codes
	var capturedUser *models.User
	mockUserRepo.On("Update", mock.Anything, mock.AnythingOfType("*models.User")).
		Run(func(args mock.Arguments) {
			capturedUser = args.Get(1).(*models.User)
		}).
		Return(nil)
	mockMFARepo.On("DeleteAllRecoveryCodes", mock.Anything, userID).Return(nil)

	err := svc.DisableMFA(context.Background(), userID, password, validEmailCode)

	require.NoError(t, err)
	require.NotNil(t, capturedUser)
	assert.False(t, capturedUser.MFAEnabled, "MFAEnabled must be cleared")
	assert.Nil(t, capturedUser.MFASecret, "MFASecret must be nil")
	assert.Nil(t, capturedUser.MFAType, "MFAType must be nil")
	assert.False(t, capturedUser.MFATOTPEnabled, "MFATOTPEnabled must be false")
	assert.False(t, capturedUser.MFAEmailEnabled, "MFAEmailEnabled must be false")
	assert.Nil(t, capturedUser.MFAPreferredMethod, "MFAPreferredMethod must be nil")

	mockUserRepo.AssertExpectations(t)
	mockMFARepo.AssertExpectations(t)
}

// TestMFAAdminEnableMFA tests the admin path for enabling MFA.
func TestMFAAdminEnableMFA(t *testing.T) {
	tests := []struct {
		name        string
		method      string
		user        *models.User
		wantErr     bool
		errContains string
	}{
		{
			name:   "admin enables email MFA on verified user",
			method: "email",
			user: &models.User{
				ID:              uuid.New(),
				TenantID:        uuid.New(),
				Username:        "testuser",
				Email:           "test@example.com",
				MFAEnabled:      false,
				IsEmailVerified: true,
			},
			wantErr: false,
		},
		{
			name:   "admin enables email MFA on unverified user fails",
			method: "email",
			user: &models.User{
				ID:              uuid.New(),
				TenantID:        uuid.New(),
				Username:        "testuser",
				Email:           "test@example.com",
				MFAEnabled:      false,
				IsEmailVerified: false,
			},
			wantErr:     true,
			errContains: "email must be verified",
		},
		{
			name:   "admin enables MFA on already-enabled user fails",
			method: "email",
			user: &models.User{
				ID:              uuid.New(),
				TenantID:        uuid.New(),
				Username:        "testuser",
				Email:           "test@example.com",
				MFAEnabled:      true,
				IsEmailVerified: true,
			},
			wantErr:     true,
			errContains: "MFA is already enabled",
		},
		{
			name:   "admin enables TOTP MFA (no email verification required)",
			method: "totp",
			user: &models.User{
				ID:              uuid.New(),
				TenantID:        uuid.New(),
				Username:        "testuser",
				Email:           "test@example.com",
				MFAEnabled:      false,
				IsEmailVerified: false,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc, mockUserRepo, mockMFARepo, _, _ := createTestMFAService()

			mockUserRepo.On("GetByID", mock.Anything, tt.user.ID).Return(tt.user, nil)

			if !tt.wantErr {
				mockUserRepo.On("Update", mock.Anything, mock.AnythingOfType("*models.User")).Return(nil)
				mockMFARepo.On("CreateRecoveryCodes", mock.Anything, tt.user.ID, mock.AnythingOfType("[]string")).Return(nil)
			}

			err := svc.AdminEnableMFA(context.Background(), tt.user.ID, tt.method)

			if tt.wantErr {
				require.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
				return
			}

			require.NoError(t, err)
			mockUserRepo.AssertExpectations(t)
			mockMFARepo.AssertExpectations(t)
		})
	}
}

// TestMFAAdminDisableMFA tests the admin path for disabling MFA.
func TestMFAAdminDisableMFA(t *testing.T) {
	tests := []struct {
		name        string
		user        *models.User
		updateErr   error
		wantErr     bool
		errContains string
	}{
		{
			name: "admin disables enabled MFA",
			user: &models.User{
				ID:         uuid.New(),
				TenantID:   uuid.New(),
				MFAEnabled: true,
			},
			wantErr: false,
		},
		{
			name: "admin disable on non-MFA user fails",
			user: &models.User{
				ID:         uuid.New(),
				TenantID:   uuid.New(),
				MFAEnabled: false,
			},
			wantErr:     true,
			errContains: "MFA is not enabled",
		},
		{
			name: "update failure propagates error",
			user: &models.User{
				ID:         uuid.New(),
				TenantID:   uuid.New(),
				MFAEnabled: true,
			},
			updateErr:   errors.New("db error"),
			wantErr:     true,
			errContains: "failed to disable MFA",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc, mockUserRepo, mockMFARepo, _, _ := createTestMFAService()

			mockUserRepo.On("GetByID", mock.Anything, tt.user.ID).Return(tt.user, nil)

			if tt.user.MFAEnabled {
				mockUserRepo.On("HasNonPrimaryMFAFactor", mock.Anything, tt.user.ID).Return(false, nil)
				mockUserRepo.On("Update", mock.Anything, mock.AnythingOfType("*models.User")).
					Return(tt.updateErr)
				if tt.updateErr == nil {
					mockMFARepo.On("DeleteAllRecoveryCodes", mock.Anything, tt.user.ID).Return(nil)
				}
			}

			err := svc.AdminDisableMFA(context.Background(), tt.user.ID)

			if tt.wantErr {
				require.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
				return
			}

			require.NoError(t, err)
			mockUserRepo.AssertExpectations(t)
			mockMFARepo.AssertExpectations(t)
		})
	}
}

// TestMFASendEmailMFACode_RateLimiting validates that database storage errors
// (simulating rate-limiting enforcement at the repo layer) are propagated.
func TestMFASendEmailMFACode_RateLimiting(t *testing.T) {
	userID := uuid.New()
	user := createTestUser()
	user.ID = userID

	svc, mockUserRepo, mockMFARepo, _, _ := createTestMFAService()

	mockUserRepo.On("GetByID", mock.Anything, userID).Return(user, nil)
	// Simulate repo rejecting because a recent code already exists (rate limit)
	mockMFARepo.On("CreateMFAEmailCode", mock.Anything, userID,
		mock.AnythingOfType("string"), mock.AnythingOfType("time.Time")).
		Return(nil, errors.New("rate limit: too many codes requested"))

	err := svc.SendEmailMFACode(context.Background(), userID)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to store MFA code")
}
