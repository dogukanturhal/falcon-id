// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/pkg/config"
	"github.com/dogukanturhal/falcon-id/pkg/crypto"
)

// MockTokenRepository is a mock implementation of the token repository
type MockTokenRepository struct {
	mock.Mock
}

func (m *MockTokenRepository) CleanupExpiredPasswordResets(ctx context.Context) (int64, error) {
	args := m.Called(ctx)
	return args.Get(0).(int64), args.Error(1)
}

func (m *MockTokenRepository) CreatePasswordReset(ctx context.Context, reset *models.PasswordReset) error {
	args := m.Called(ctx, reset)
	return args.Error(0)
}

func (m *MockTokenRepository) GetPasswordReset(ctx context.Context, tokenHash string) (*models.PasswordReset, error) {
	args := m.Called(ctx, tokenHash)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.PasswordReset), args.Error(1)
}

func (m *MockTokenRepository) InvalidateUserPasswordResets(ctx context.Context, userID uuid.UUID) error {
	args := m.Called(ctx, userID)
	return args.Error(0)
}

func (m *MockTokenRepository) MarkPasswordResetUsed(ctx context.Context, resetID uuid.UUID) error {
	args := m.Called(ctx, resetID)
	return args.Error(0)
}

// MockTokenUserRepository is a mock implementation of the user repository for token tests
type MockTokenUserRepository struct {
	mock.Mock
}

func (m *MockTokenUserRepository) GetByID(ctx context.Context, userID uuid.UUID) (*models.User, error) {
	args := m.Called(ctx, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.User), args.Error(1)
}

func (m *MockTokenUserRepository) GetUserRoles(ctx context.Context, userID uuid.UUID) ([]models.Role, error) {
	args := m.Called(ctx, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]models.Role), args.Error(1)
}

func (m *MockTokenUserRepository) GetUserPermissions(ctx context.Context, userID uuid.UUID) ([]models.Permission, error) {
	args := m.Called(ctx, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]models.Permission), args.Error(1)
}

func (m *MockTokenUserRepository) Update(ctx context.Context, user *models.User) error {
	args := m.Called(ctx, user)
	return args.Error(0)
}

// MockSessionCache is a mock implementation of the session cache
type MockSessionCache struct {
	mock.Mock
}

func (m *MockSessionCache) SetSessionData(ctx context.Context, sessionID uuid.UUID, data interface{}) error {
	args := m.Called(ctx, sessionID, data)
	return args.Error(0)
}

func (m *MockSessionCache) GetSessionData(ctx context.Context, sessionID uuid.UUID) (interface{}, error) {
	args := m.Called(ctx, sessionID)
	return args.Get(0), args.Error(1)
}

func (m *MockSessionCache) Delete(ctx context.Context, sessionID uuid.UUID) error {
	args := m.Called(ctx, sessionID)
	return args.Error(0)
}

// MockTokenBlacklist is a mock implementation of the token blacklist
type MockTokenBlacklist struct {
	mock.Mock
}

func (m *MockTokenBlacklist) IsSessionBlacklisted(ctx context.Context, sessionID uuid.UUID) (bool, string, error) {
	args := m.Called(ctx, sessionID)
	return args.Bool(0), args.String(1), args.Error(2)
}

func (m *MockTokenBlacklist) IsUserBlacklisted(ctx context.Context, userID uuid.UUID) (bool, error) {
	args := m.Called(ctx, userID)
	return args.Bool(0), args.Error(1)
}

// Helper function to create a test config
func createTestConfig() *config.Config {
	return &config.Config{
		JWTSecret:                "test-secret-key-for-jwt-signing-at-least-32-chars",
		JWTIssuer:                "hexxlock-test",
		JWTHMACFallbackEnabled:   true, // allow HS256 tokens during tests
		AccessTokenExpiry:        15 * time.Minute,
		SessionRotationOnRefresh: true,
		SpiceDBTokenV2Enabled:    false,
		SpiceDBTokenV2Percentage: 0,
		MFAIssuer:                "Hexxlock Test",
		MFATOTPDigits:            6,
		MFATOTPPeriod:            30,
		MFABackupCodeCount:       10,
		MFAEmailCodeTTL:          10 * time.Minute,
		FrontendURL:              "http://localhost:3000",
	}
}

// Helper function to create a test user
func createTestUser() *models.User {
	tenantID := uuid.New()
	return &models.User{
		ID:              uuid.New(),
		TenantID:        tenantID,
		RealmID:         models.DefaultRealmID,
		Username:        "testuser",
		Email:           "test@example.com",
		IsActive:        true,
		IsLocked:        false,
		IsEmailVerified: true,
	}
}

// TestGenerateAccessToken tests basic access token generation
func TestGenerateAccessToken(t *testing.T) {
	tests := []struct {
		name        string
		user        *models.User
		sessionID   uuid.UUID
		roles       []string
		permissions []string
		wantErr     bool
		errContains string
	}{
		{
			name:        "successful token generation",
			user:        createTestUser(),
			sessionID:   uuid.New(),
			roles:       []string{"admin", "user"},
			permissions: []string{"read:users", "write:users"},
			wantErr:     false,
		},
		{
			name:        "token with no roles",
			user:        createTestUser(),
			sessionID:   uuid.New(),
			roles:       []string{},
			permissions: []string{"read:public"},
			wantErr:     false,
		},
		{
			name:        "token with many permissions",
			user:        createTestUser(),
			sessionID:   uuid.New(),
			roles:       []string{"superadmin"},
			permissions: generateManyPermissions(100),
			wantErr:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := createTestConfig()
			mockTokenRepo := new(MockTokenRepository)
			mockUserRepo := new(MockTokenUserRepository)

			svc := NewTokenService(cfg, mockTokenRepo, mockUserRepo)

			token, err := svc.GenerateAccessToken(context.Background(), tt.user, tt.sessionID, tt.roles, tt.permissions)

			if tt.wantErr {
				require.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
				return
			}

			require.NoError(t, err)
			assert.NotEmpty(t, token)

			// Verify token can be parsed
			parsed, err := jwt.Parse(token, func(_ *jwt.Token) (interface{}, error) {
				return []byte(cfg.JWTSecret), nil
			})
			require.NoError(t, err)
			assert.True(t, parsed.Valid)

			// Verify claims
			claims, ok := parsed.Claims.(jwt.MapClaims)
			require.True(t, ok)
			assert.Equal(t, tt.user.ID.String(), claims["user_id"])
			assert.Equal(t, tt.user.TenantID.String(), claims["tenant_id"])
			assert.Equal(t, tt.sessionID.String(), claims["session_id"])
		})
	}
}

// TestGenerateAccessTokenWithOptions tests token generation with options
func TestGenerateAccessTokenWithOptions(t *testing.T) {
	tests := []struct {
		name        string
		user        *models.User
		sessionID   uuid.UUID
		roles       []string
		permissions []string
		opts        TokenGenerationOptions
		wantErr     bool
	}{
		{
			name:        "tenant scope token",
			user:        createTestUser(),
			sessionID:   uuid.New(),
			roles:       []string{"user"},
			permissions: []string{"read:profile"},
			opts: TokenGenerationOptions{
				RealmID:   models.DefaultRealmID,
				RealmSlug: "default",
				RealmType: "shared",
				Scope:     "tenant",
			},
			wantErr: false,
		},
		{
			name:        "platform scope token",
			user:        createTestUser(),
			sessionID:   uuid.New(),
			roles:       []string{"platform_admin"},
			permissions: []string{"manage:all"},
			opts: TokenGenerationOptions{
				RealmID: models.DefaultRealmID,
				Scope:   "platform",
			},
			wantErr: false,
		},
		{
			name:        "minimal token format",
			user:        createTestUser(),
			sessionID:   uuid.New(),
			roles:       []string{"user"},
			permissions: []string{"read:profile"},
			opts: TokenGenerationOptions{
				RealmID:    models.DefaultRealmID,
				UseMinimal: true,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := createTestConfig()
			mockTokenRepo := new(MockTokenRepository)
			mockUserRepo := new(MockTokenUserRepository)

			svc := NewTokenService(cfg, mockTokenRepo, mockUserRepo)

			token, err := svc.GenerateAccessTokenWithOptions(context.Background(), tt.user, tt.sessionID, tt.roles, tt.permissions, tt.opts)

			if tt.wantErr {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.NotEmpty(t, token)
		})
	}
}

// TestGenerateAccessTokenV2 tests v2 token generation (SpiceDB)
func TestGenerateAccessTokenV2(t *testing.T) {
	tests := []struct {
		name      string
		user      *models.User
		sessionID uuid.UUID
		roles     []string
		opts      TokenGenerationOptions
		wantErr   bool
	}{
		{
			name:      "v2 token without permissions",
			user:      createTestUser(),
			sessionID: uuid.New(),
			roles:     []string{"admin"},
			opts: TokenGenerationOptions{
				RealmID: models.DefaultRealmID,
			},
			wantErr: false,
		},
		{
			name:      "v2 token with nil realm",
			user:      createTestUser(),
			sessionID: uuid.New(),
			roles:     []string{"user"},
			opts:      TokenGenerationOptions{},
			wantErr:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := createTestConfig()
			mockTokenRepo := new(MockTokenRepository)
			mockUserRepo := new(MockTokenUserRepository)

			svc := NewTokenService(cfg, mockTokenRepo, mockUserRepo)

			token, err := svc.GenerateAccessTokenV2(context.Background(), tt.user, tt.sessionID, tt.roles, tt.opts)

			if tt.wantErr {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.NotEmpty(t, token)

			// Verify token is valid JWT
			parsed, err := jwt.Parse(token, func(_ *jwt.Token) (interface{}, error) {
				return []byte(cfg.JWTSecret), nil
			})
			require.NoError(t, err)
			assert.True(t, parsed.Valid)

			// Verify v2 token has minimal claims
			claims, ok := parsed.Claims.(jwt.MapClaims)
			require.True(t, ok)
			assert.Equal(t, float64(models.TokenVersionSpiceDB), claims["v"])
		})
	}
}

// TestShouldUseV2Token tests v2 token canary deployment logic
func TestShouldUseV2Token(t *testing.T) {
	tests := []struct {
		name         string
		enabled      bool
		percentage   int
		userID       uuid.UUID
		expectResult bool
	}{
		{
			name:         "v2 disabled",
			enabled:      false,
			percentage:   100,
			userID:       uuid.New(),
			expectResult: false,
		},
		{
			name:         "v2 enabled 100%",
			enabled:      true,
			percentage:   100,
			userID:       uuid.New(),
			expectResult: true,
		},
		{
			name:         "v2 enabled 0%",
			enabled:      true,
			percentage:   0,
			userID:       uuid.New(),
			expectResult: false,
		},
		{
			name:         "v2 enabled 50%",
			enabled:      true,
			percentage:   50,
			userID:       uuid.MustParse("00000000-0000-0000-0000-000000000000"), // First byte = 0x00
			expectResult: true,
		},
		{
			name:         "v2 enabled 50% high byte",
			enabled:      true,
			percentage:   50,
			userID:       uuid.MustParse("ff000000-0000-0000-0000-000000000000"), // First byte = 0xff
			expectResult: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := createTestConfig()
			cfg.SpiceDBTokenV2Enabled = tt.enabled
			cfg.SpiceDBTokenV2Percentage = tt.percentage

			mockTokenRepo := new(MockTokenRepository)
			mockUserRepo := new(MockTokenUserRepository)

			svc := NewTokenService(cfg, mockTokenRepo, mockUserRepo)
			result := svc.ShouldUseV2Token(tt.userID)

			assert.Equal(t, tt.expectResult, result)
		})
	}
}


// TestCreatePasswordResetToken tests password reset token creation
func TestCreatePasswordResetToken(t *testing.T) {
	tests := []struct {
		name          string
		userID        uuid.UUID
		ipAddress     *string
		invalidateErr error
		createErr     error
		wantErr       bool
		errContains   string
	}{
		{
			name:          "successful creation",
			userID:        uuid.New(),
			ipAddress:     stringPtr("192.168.1.1"),
			invalidateErr: nil,
			createErr:     nil,
			wantErr:       false,
		},
		{
			name:          "creation without IP",
			userID:        uuid.New(),
			ipAddress:     nil,
			invalidateErr: nil,
			createErr:     nil,
			wantErr:       false,
		},
		{
			name:          "invalidate existing tokens fails",
			userID:        uuid.New(),
			ipAddress:     stringPtr("10.0.0.1"),
			invalidateErr: errors.New("db error"),
			createErr:     nil,
			wantErr:       true,
			errContains:   "failed to invalidate existing tokens",
		},
		{
			name:          "create new token fails",
			userID:        uuid.New(),
			ipAddress:     stringPtr("10.0.0.1"),
			invalidateErr: nil,
			createErr:     errors.New("db error"),
			wantErr:       true,
			errContains:   "failed to store password reset",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := createTestConfig()
			mockTokenRepo := new(MockTokenRepository)
			mockUserRepo := new(MockTokenUserRepository)

			mockTokenRepo.On("InvalidateUserPasswordResets", mock.Anything, tt.userID).
				Return(tt.invalidateErr)

			if tt.invalidateErr == nil {
				mockTokenRepo.On("CreatePasswordReset", mock.Anything, mock.AnythingOfType("*models.PasswordReset")).
					Return(tt.createErr)
			}

			svc := NewTokenService(cfg, mockTokenRepo, mockUserRepo)

			token, err := svc.CreatePasswordResetToken(context.Background(), tt.userID, tt.ipAddress)

			if tt.wantErr {
				require.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
				return
			}

			require.NoError(t, err)
			assert.NotEmpty(t, token)
			assert.Len(t, token, 44) // Secure tokens are base64url-encoded 32 bytes = 44 characters

			mockTokenRepo.AssertExpectations(t)
		})
	}
}

// TestValidatePasswordResetToken tests password reset token validation
func TestValidatePasswordResetToken(t *testing.T) {
	validToken, _ := crypto.GenerateSecureToken()
	validHash, _ := crypto.HashToken(validToken)
	expiredToken, _ := crypto.GenerateSecureToken()
	expiredHash, _ := crypto.HashToken(expiredToken)
	usedToken, _ := crypto.GenerateSecureToken()
	usedHash, _ := crypto.HashToken(usedToken)

	now := time.Now()
	usedAt := now

	tests := []struct {
		name        string
		tokenString string
		mockReturn  *models.PasswordReset
		mockError   error
		wantErr     bool
		errContains string
	}{
		{
			name:        "valid token",
			tokenString: validToken,
			mockReturn: &models.PasswordReset{
				ID:        uuid.New(),
				UserID:    uuid.New(),
				TokenHash: validHash,
				ExpiresAt: now.Add(1 * time.Hour),
				UsedAt:    nil,
			},
			mockError: nil,
			wantErr:   false,
		},
		{
			name:        "expired token",
			tokenString: expiredToken,
			mockReturn: &models.PasswordReset{
				ID:        uuid.New(),
				UserID:    uuid.New(),
				TokenHash: expiredHash,
				ExpiresAt: now.Add(-1 * time.Hour),
				UsedAt:    nil,
			},
			mockError:   nil,
			wantErr:     true,
			errContains: "has expired",
		},
		{
			name:        "used token",
			tokenString: usedToken,
			mockReturn: &models.PasswordReset{
				ID:        uuid.New(),
				UserID:    uuid.New(),
				TokenHash: usedHash,
				ExpiresAt: now.Add(1 * time.Hour),
				UsedAt:    &usedAt,
			},
			mockError:   nil,
			wantErr:     true,
			errContains: "has been used",
		},
		{
			name:        "token not found",
			tokenString: validToken,
			mockReturn:  nil,
			mockError:   nil,
			wantErr:     true,
			errContains: "not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := createTestConfig()
			mockTokenRepo := new(MockTokenRepository)
			mockUserRepo := new(MockTokenUserRepository)

			tokenHash, _ := crypto.HashToken(tt.tokenString)
			mockTokenRepo.On("GetPasswordReset", mock.Anything, tokenHash).
				Return(tt.mockReturn, tt.mockError)

			svc := NewTokenService(cfg, mockTokenRepo, mockUserRepo)

			result, err := svc.ValidatePasswordResetToken(context.Background(), tt.tokenString)

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
			assert.Equal(t, tt.mockReturn.UserID, result.UserID)

			mockTokenRepo.AssertExpectations(t)
		})
	}
}

// TestCleanupExpiredTokens tests token cleanup
func TestCleanupExpiredTokens(t *testing.T) {
	tests := []struct {
		name                 string
		passwordResetDeleted int64
		passwordErr          error
		wantErr              bool
		errContains          string
	}{
		{
			name:                 "successful cleanup",
			passwordResetDeleted: 5,
			passwordErr:          nil,
			wantErr:              false,
		},
		{
			name:                 "no expired tokens",
			passwordResetDeleted: 0,
			passwordErr:          nil,
			wantErr:              false,
		},
		{
			name:                 "password reset cleanup fails",
			passwordResetDeleted: 0,
			passwordErr:          errors.New("db error"),
			wantErr:              true,
			errContains:          "failed to cleanup password resets",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := createTestConfig()
			mockTokenRepo := new(MockTokenRepository)
			mockUserRepo := new(MockTokenUserRepository)

			mockTokenRepo.On("CleanupExpiredPasswordResets", mock.Anything).
				Return(tt.passwordResetDeleted, tt.passwordErr)

			svc := NewTokenService(cfg, mockTokenRepo, mockUserRepo)

			err := svc.CleanupExpiredTokens(context.Background())

			if tt.wantErr {
				require.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
				return
			}

			require.NoError(t, err)
			mockTokenRepo.AssertExpectations(t)
		})
	}
}

// TestGenerateImpersonationAccessToken tests impersonation token generation
func TestGenerateImpersonationAccessToken(t *testing.T) {
	user := createTestUser()
	sessionID := uuid.New()
	roles := []string{"admin"}
	permissions := []string{"read:all", "write:all"}
	impersonatorID := uuid.New()
	impersonationSessionID := uuid.New()

	cfg := createTestConfig()
	mockTokenRepo := new(MockTokenRepository)
	mockUserRepo := new(MockTokenUserRepository)

	svc := NewTokenService(cfg, mockTokenRepo, mockUserRepo)

	token, err := svc.GenerateImpersonationAccessToken(
		context.Background(),
		user,
		sessionID,
		roles,
		permissions,
		impersonatorID,
		impersonationSessionID,
	)

	require.NoError(t, err)
	assert.NotEmpty(t, token)

	// Verify token
	parsed, err := jwt.Parse(token, func(_ *jwt.Token) (interface{}, error) {
		return []byte(cfg.JWTSecret), nil
	})
	require.NoError(t, err)
	assert.True(t, parsed.Valid)

	claims, ok := parsed.Claims.(jwt.MapClaims)
	require.True(t, ok)
	assert.Equal(t, impersonatorID.String(), claims["impersonator_id"])
	assert.Equal(t, impersonationSessionID.String(), claims["impersonation_session_id"])
}

// Helper functions
func stringPtr(s string) *string {
	return &s
}

func generateManyPermissions(count int) []string {
	perms := make([]string, count)
	for i := 0; i < count; i++ {
		perms[i] = "permission:" + string(rune(i))
	}
	return perms
}

// ---------------------------------------------------------------------------
// Phase 2C: Additional TokenService tests
// ---------------------------------------------------------------------------

// TestTokenValidateAccessToken_ValidToken tests legacy (v0) access token validation.
func TestTokenValidateAccessToken_ValidToken(t *testing.T) {
	cfg := createTestConfig()
	mockTokenRepo := new(MockTokenRepository)
	mockUserRepo := new(MockTokenUserRepository)

	svc := NewTokenService(cfg, mockTokenRepo, mockUserRepo)

	user := createTestUser()
	sessionID := uuid.New()

	// Generate a legacy (v0) token - no session cache, so it uses legacy format
	tokenString, err := svc.GenerateAccessToken(context.Background(), user, sessionID,
		[]string{"admin"}, []string{"crm:contacts:read"})
	require.NoError(t, err)
	require.NotEmpty(t, tokenString)

	claims, err := svc.ValidateAccessToken(tokenString)

	require.NoError(t, err)
	require.NotNil(t, claims)
	assert.Equal(t, user.ID, claims.UserID)
	assert.Equal(t, user.TenantID, claims.TenantID)
	assert.Equal(t, sessionID, claims.SessionID)
	assert.Contains(t, claims.Roles, "admin")
	assert.Contains(t, claims.Permissions, "crm:contacts:read")
}

// TestTokenValidateAccessToken_ExpiredToken verifies that an expired JWT is rejected.
func TestTokenValidateAccessToken_ExpiredToken(t *testing.T) {
	cfg := createTestConfig()
	// Issue a token that is already expired
	cfg.AccessTokenExpiry = -1 * time.Second

	mockTokenRepo := new(MockTokenRepository)
	mockUserRepo := new(MockTokenUserRepository)

	svc := NewTokenService(cfg, mockTokenRepo, mockUserRepo)

	user := createTestUser()
	sessionID := uuid.New()

	tokenString, err := svc.GenerateAccessToken(context.Background(), user, sessionID,
		[]string{"user"}, []string{})
	require.NoError(t, err)

	claims, err := svc.ValidateAccessToken(tokenString)

	require.Error(t, err, "expired token must not validate")
	assert.Contains(t, err.Error(), "invalid token")
	assert.Nil(t, claims)
}

// TestTokenValidateAccessToken_TamperedToken verifies that a token with a modified
// signature or payload is rejected.
func TestTokenValidateAccessToken_TamperedToken(t *testing.T) {
	cfg := createTestConfig()
	mockTokenRepo := new(MockTokenRepository)
	mockUserRepo := new(MockTokenUserRepository)

	svc := NewTokenService(cfg, mockTokenRepo, mockUserRepo)

	user := createTestUser()
	sessionID := uuid.New()

	validToken, err := svc.GenerateAccessToken(context.Background(), user, sessionID,
		[]string{"user"}, []string{})
	require.NoError(t, err)

	// Append garbage to invalidate the signature
	tamperedToken := validToken + "tampered"

	claims, err := svc.ValidateAccessToken(tamperedToken)

	require.Error(t, err, "tampered token must be rejected")
	assert.Nil(t, claims)
}

// TestTokenValidateAccessToken_WrongSecret verifies that a token signed with a
// different secret is rejected.
func TestTokenValidateAccessToken_WrongSecret(t *testing.T) {
	cfg := createTestConfig()

	// Signing service uses a different secret
	signingCfg := *cfg
	signingCfg.JWTSecret = "a-completely-different-secret-that-is-long-enough"
	mockTokenRepo := new(MockTokenRepository)
	mockUserRepo := new(MockTokenUserRepository)
	signerSvc := NewTokenService(&signingCfg, mockTokenRepo, mockUserRepo)

	user := createTestUser()
	tokenString, err := signerSvc.GenerateAccessToken(context.Background(), user, uuid.New(),
		[]string{"user"}, []string{})
	require.NoError(t, err)

	// Validator uses original (different) secret
	validatorSvc := NewTokenService(cfg, mockTokenRepo, mockUserRepo)
	claims, err := validatorSvc.ValidateAccessToken(tokenString)

	require.Error(t, err, "token signed with wrong secret must be rejected")
	assert.Nil(t, claims)
}

// TestTokenValidateAccessTokenWithSessionCheck_NoBlacklist verifies the happy
// path: valid legacy (v0) token without a configured blacklist passes through.
// (TokenService.tokenBlacklist is a concrete *redis.TokenBlacklist so we test
// the nil-guard path, i.e. no blacklist configured.)
func TestTokenValidateAccessTokenWithSessionCheck_NoBlacklist(t *testing.T) {
	cfg := createTestConfig()
	mockTokenRepo := new(MockTokenRepository)
	mockUserRepo := new(MockTokenUserRepository)

	svc := NewTokenService(cfg, mockTokenRepo, mockUserRepo)
	// tokenBlacklist is nil by default → blacklist check is skipped

	user := createTestUser()
	sessionID := uuid.New()

	tokenString, err := svc.GenerateAccessToken(context.Background(), user, sessionID,
		[]string{"user"}, []string{"crm:contacts:read"})
	require.NoError(t, err)

	claims, err := svc.ValidateAccessTokenWithContext(context.Background(), tokenString)

	require.NoError(t, err)
	require.NotNil(t, claims)
	assert.Equal(t, user.ID, claims.UserID)
	assert.Equal(t, sessionID, claims.SessionID)
}

// TestTokenValidateAccessTokenWithSessionCheck_ParsesAllLegacyClaims verifies
// that all standard legacy (v0) claims are parsed correctly.
func TestTokenValidateAccessTokenWithSessionCheck_ParsesAllLegacyClaims(t *testing.T) {
	cfg := createTestConfig()
	mockTokenRepo := new(MockTokenRepository)
	mockUserRepo := new(MockTokenUserRepository)

	svc := NewTokenService(cfg, mockTokenRepo, mockUserRepo)

	user := createTestUser()
	sessionID := uuid.New()
	roles := []string{"admin", "manager"}
	perms := []string{"crm:contacts:read", "crm:contacts:write"}

	tokenString, err := svc.GenerateAccessTokenWithOptions(context.Background(), user, sessionID,
		roles, perms, TokenGenerationOptions{
			RealmID:   models.DefaultRealmID,
			RealmSlug: "default",
			RealmType: "shared",
			Scope:     "tenant",
		})
	require.NoError(t, err)

	claims, err := svc.ValidateAccessTokenWithContext(context.Background(), tokenString)

	require.NoError(t, err)
	require.NotNil(t, claims)
	assert.Equal(t, user.ID, claims.UserID)
	assert.Equal(t, user.TenantID, claims.TenantID)
	assert.Equal(t, sessionID, claims.SessionID)
	assert.ElementsMatch(t, roles, claims.Roles)
	assert.ElementsMatch(t, perms, claims.Permissions)
	assert.Equal(t, "tenant", claims.Scope)
}

// TestTokenValidateAccessTokenWithSessionCheck_MinimalTokenNoCache verifies
// that validating a minimal (v1) token without a session cache returns an error.
func TestTokenValidateAccessTokenWithSessionCheck_MinimalTokenNoCache(t *testing.T) {
	cfg := createTestConfig()
	mockTokenRepo := new(MockTokenRepository)
	mockUserRepo := new(MockTokenUserRepository)

	svc := NewTokenService(cfg, mockTokenRepo, mockUserRepo)

	user := createTestUser()
	sessionID := uuid.New()

	// UseMinimal=true forces minimal token format (v1)
	tokenString, err := svc.GenerateAccessTokenWithOptions(context.Background(), user, sessionID,
		[]string{"user"}, []string{"crm:contacts:read"}, TokenGenerationOptions{
			RealmID:    models.DefaultRealmID,
			UseMinimal: true,
		})
	require.NoError(t, err)
	require.NotEmpty(t, tokenString)

	// Validation without session cache must fail for v1 tokens
	claims, err := svc.ValidateAccessTokenWithContext(context.Background(), tokenString)

	require.Error(t, err, "v1 token validation requires session cache")
	assert.Contains(t, err.Error(), "session cache")
	assert.Nil(t, claims)
}


// TestGenerateMinimalToken_ResolverError_OmitsProductsClaim asserts the
// fail-closed contract for the v1 minimal-token mint path
// (generateMinimalToken, used by GenerateAccessTokenWithOptions with
// UseMinimal): when the product subscription resolver errors, the token
// must carry NO `products` claim at all — never an empty array (which some
// gates could misread) and never "all products" (which would be a
// privilege-escalation bug). This locks the behaviour documented at
// token_service.go's resolver-error log.Warn call site.
func TestGenerateMinimalToken_ResolverError_OmitsProductsClaim(t *testing.T) {
	cfg := createTestConfig()
	mockTokenRepo := new(MockTokenRepository)
	mockUserRepo := new(MockTokenUserRepository)

	svc := NewTokenService(cfg, mockTokenRepo, mockUserRepo)
	failingResolver := NewProductSubscriptionResolver(
		&mockSubscriptionInstanceRepo{err: errors.New("db unavailable")},
		&mockSubscriptionProductRepo{products: map[uuid.UUID]*models.Product{}},
	)
	svc.SetProductSubscriptionResolver(failingResolver)

	user := createTestUser()
	sessionID := uuid.New()

	tokenString, err := svc.GenerateAccessTokenWithOptions(context.Background(), user, sessionID,
		[]string{"user"}, []string{"crm:contacts:read"}, TokenGenerationOptions{
			RealmID:    models.DefaultRealmID,
			UseMinimal: true,
		})
	require.NoError(t, err)
	require.NotEmpty(t, tokenString)

	parsed, err := jwt.Parse(tokenString, func(_ *jwt.Token) (interface{}, error) {
		return []byte(cfg.JWTSecret), nil
	})
	require.NoError(t, err)
	claims, ok := parsed.Claims.(jwt.MapClaims)
	require.True(t, ok)

	_, present := claims["products"]
	assert.False(t, present, "resolver error must fail closed: products claim must be entirely absent, not empty or all-products")
}

// TestGenerateAccessTokenV2_ResolverError_OmitsProductsClaim is the v2
// (SpiceDB) mint-path counterpart of
// TestGenerateMinimalToken_ResolverError_OmitsProductsClaim.
func TestGenerateAccessTokenV2_ResolverError_OmitsProductsClaim(t *testing.T) {
	cfg := createTestConfig()
	mockTokenRepo := new(MockTokenRepository)
	mockUserRepo := new(MockTokenUserRepository)

	svc := NewTokenService(cfg, mockTokenRepo, mockUserRepo)
	failingResolver := NewProductSubscriptionResolver(
		&mockSubscriptionInstanceRepo{err: errors.New("db unavailable")},
		&mockSubscriptionProductRepo{products: map[uuid.UUID]*models.Product{}},
	)
	svc.SetProductSubscriptionResolver(failingResolver)

	user := createTestUser()
	sessionID := uuid.New()

	tokenString, err := svc.GenerateAccessTokenV2(context.Background(), user, sessionID,
		[]string{"user"}, TokenGenerationOptions{RealmID: models.DefaultRealmID})
	require.NoError(t, err)
	require.NotEmpty(t, tokenString)

	parsed, err := jwt.Parse(tokenString, func(_ *jwt.Token) (interface{}, error) {
		return []byte(cfg.JWTSecret), nil
	})
	require.NoError(t, err)
	claims, ok := parsed.Claims.(jwt.MapClaims)
	require.True(t, ok)

	_, present := claims["products"]
	assert.False(t, present, "resolver error must fail closed: products claim must be entirely absent, not empty or all-products")
}
