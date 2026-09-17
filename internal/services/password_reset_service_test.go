// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/pkg/config"
	"github.com/dogukanturhal/falcon-id/pkg/crypto"
)

// ---------------------------------------------------------------------------
// Mock: passwordResetServiceUserRepo
// ---------------------------------------------------------------------------

type MockPwdResetUserRepo struct {
	mock.Mock
}

func (m *MockPwdResetUserRepo) GetByEmail(ctx context.Context, tenantID uuid.UUID, email string) (*models.User, error) {
	args := m.Called(ctx, tenantID, email)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.User), args.Error(1)
}

func (m *MockPwdResetUserRepo) GetByID(ctx context.Context, id uuid.UUID) (*models.User, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.User), args.Error(1)
}

func (m *MockPwdResetUserRepo) Update(ctx context.Context, user *models.User) error {
	args := m.Called(ctx, user)
	return args.Error(0)
}

// ---------------------------------------------------------------------------
// Mock: passwordResetServiceTokenRepo
// ---------------------------------------------------------------------------

type MockPwdResetTokenRepo struct {
	mock.Mock
}

func (m *MockPwdResetTokenRepo) InvalidateUserPasswordResets(ctx context.Context, userID uuid.UUID) error {
	args := m.Called(ctx, userID)
	return args.Error(0)
}

func (m *MockPwdResetTokenRepo) CreatePasswordReset(ctx context.Context, reset *models.PasswordReset) error {
	args := m.Called(ctx, reset)
	return args.Error(0)
}

func (m *MockPwdResetTokenRepo) GetPasswordReset(ctx context.Context, tokenHash string) (*models.PasswordReset, error) {
	args := m.Called(ctx, tokenHash)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.PasswordReset), args.Error(1)
}

func (m *MockPwdResetTokenRepo) MarkPasswordResetUsed(ctx context.Context, id uuid.UUID) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

// ---------------------------------------------------------------------------
// Mock: passwordResetServiceSessionRepo
// ---------------------------------------------------------------------------

type MockPwdResetSessionRepo struct {
	mock.Mock
}

func (m *MockPwdResetSessionRepo) EndAllUserSessions(ctx context.Context, userID uuid.UUID, reason string) error {
	args := m.Called(ctx, userID, reason)
	return args.Error(0)
}

// MockAuditTokenRepo is declared in audit_service_test.go (shared across the package).

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func newPasswordResetService(
	userRepo *MockPwdResetUserRepo,
	tokenRepo *MockPwdResetTokenRepo,
) (*PasswordResetService, *MockAuditTokenRepo) { //nolint:unparam // MockAuditTokenRepo is returned for potential future use in tests
	cfg := &config.Config{
		PasswordMinLength:      8,
		PasswordRequireUpper:   false,
		PasswordRequireLower:   false,
		PasswordRequireDigit:   false,
		PasswordRequireSpecial: false,
	}

	// EmailService with no SMTP configured — SendPasswordReset will fail,
	// but we test only the token/DB logic paths where email sending is
	// a non-critical side-effect OR we mock the critical user/token repos.
	emailSvc := NewEmailService(cfg)

	auditRepo := new(MockAuditTokenRepo)
	// Audit logging is fire-and-forget; allow any call
	auditRepo.On("CreateAuditLog", mock.Anything, mock.Anything).Return(nil).Maybe()
	auditSvc := NewAuditService(auditRepo, nil)

	svc := NewPasswordResetService(cfg, userRepo, tokenRepo, emailSvc, auditSvc)
	return svc, auditRepo
}

// generatePlaintextToken creates a real token + its hash for test use.
// Returns (plaintext, hash).
func generatePlaintextToken(t *testing.T) (string, string) {
	t.Helper()
	token, err := crypto.GenerateSecureToken()
	require.NoError(t, err, "failed to generate secure token")
	hash, err := crypto.HashToken(token)
	require.NoError(t, err, "failed to hash token")
	return token, hash
}

// ---------------------------------------------------------------------------
// Tests: RequestPasswordReset
// ---------------------------------------------------------------------------

func TestPasswordResetService_RequestReset_UserNotFound_NoError(t *testing.T) {
	// SECURITY: non-existent email should return nil to prevent enumeration
	ctx := context.Background()
	tenantID := uuid.New()

	userRepo := new(MockPwdResetUserRepo)
	tokenRepo := new(MockPwdResetTokenRepo)
	svc, _ := newPasswordResetService(userRepo, tokenRepo)

	userRepo.On("GetByEmail", ctx, tenantID, "ghost@example.com").Return((*models.User)(nil), nil)

	err := svc.RequestPasswordReset(ctx, tenantID, "ghost@example.com", "127.0.0.1")

	// Must succeed (no error) — prevents email enumeration
	assert.NoError(t, err)
	userRepo.AssertExpectations(t)
}

func TestPasswordResetService_RequestReset_LDAPUser_NoError(t *testing.T) {
	// SECURITY: LDAP users cannot reset via email — still returns nil
	ctx := context.Background()
	tenantID := uuid.New()

	userRepo := new(MockPwdResetUserRepo)
	tokenRepo := new(MockPwdResetTokenRepo)
	svc, _ := newPasswordResetService(userRepo, tokenRepo)

	ldapType := "ldap"
	ldapUser := &models.User{
		ID:             uuid.New(),
		TenantID:       tenantID,
		Email:          "ldap@example.com",
		IsActive:       true,
		FederationType: &ldapType,
	}

	userRepo.On("GetByEmail", ctx, tenantID, "ldap@example.com").Return(ldapUser, nil)

	err := svc.RequestPasswordReset(ctx, tenantID, "ldap@example.com", "10.0.0.1")

	assert.NoError(t, err)
	userRepo.AssertExpectations(t)
	// tokenRepo should NOT have been called
	tokenRepo.AssertNotCalled(t, "InvalidateUserPasswordResets")
	tokenRepo.AssertNotCalled(t, "CreatePasswordReset")
}

func TestPasswordResetService_RequestReset_ValidUser_CreatesToken(t *testing.T) {
	ctx := context.Background()
	tenantID := uuid.New()

	userRepo := new(MockPwdResetUserRepo)
	tokenRepo := new(MockPwdResetTokenRepo)
	svc, _ := newPasswordResetService(userRepo, tokenRepo)

	userID := uuid.New()
	user := &models.User{
		ID:       userID,
		TenantID: tenantID,
		Email:    "valid@example.com",
		Username: "validuser",
		IsActive: true,
	}

	userRepo.On("GetByEmail", ctx, tenantID, "valid@example.com").Return(user, nil)
	tokenRepo.On("InvalidateUserPasswordResets", ctx, userID).Return(nil)
	tokenRepo.On("CreatePasswordReset", ctx, mock.AnythingOfType("*models.PasswordReset")).Return(nil)

	// SendPasswordReset will fail (no SMTP) — but RequestPasswordReset
	// propagates that as an error. Test that token records were created.
	// In a production test suite you'd inject a mock email sender.
	// Here we just confirm the token logic path ran.
	_ = svc.RequestPasswordReset(ctx, tenantID, "valid@example.com", "127.0.0.1")

	// These must have been called regardless of email send outcome
	tokenRepo.AssertCalled(t, "InvalidateUserPasswordResets", ctx, userID)
	tokenRepo.AssertCalled(t, "CreatePasswordReset", ctx, mock.AnythingOfType("*models.PasswordReset"))
}

// ---------------------------------------------------------------------------
// Tests: ResetPassword
// ---------------------------------------------------------------------------

func TestPasswordResetService_ResetPassword_InvalidToken(t *testing.T) {
	ctx := context.Background()

	userRepo := new(MockPwdResetUserRepo)
	tokenRepo := new(MockPwdResetTokenRepo)
	svc, _ := newPasswordResetService(userRepo, tokenRepo)

	// GetPasswordReset returns nil → invalid token
	tokenRepo.On("GetPasswordReset", ctx, mock.AnythingOfType("string")).Return((*models.PasswordReset)(nil), nil)

	err := svc.ResetPassword(ctx, "totally-invalid-token", "NewP@ss123", "127.0.0.1")

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid or expired")
	tokenRepo.AssertExpectations(t)
}

func TestPasswordResetService_ResetPassword_ExpiredToken(t *testing.T) {
	ctx := context.Background()

	userRepo := new(MockPwdResetUserRepo)
	tokenRepo := new(MockPwdResetTokenRepo)
	svc, _ := newPasswordResetService(userRepo, tokenRepo)

	token, hash := generatePlaintextToken(t)

	reset := &models.PasswordReset{
		ID:        uuid.New(),
		UserID:    uuid.New(),
		TokenHash: hash,
		ExpiresAt: time.Now().Add(-2 * time.Hour), // already expired
	}

	tokenRepo.On("GetPasswordReset", ctx, mock.AnythingOfType("string")).Return(reset, nil)

	err := svc.ResetPassword(ctx, token, "NewP@ss123", "127.0.0.1")

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid or expired")
	tokenRepo.AssertExpectations(t)
}

func TestPasswordResetService_ResetPassword_AlreadyUsedToken(t *testing.T) {
	ctx := context.Background()

	userRepo := new(MockPwdResetUserRepo)
	tokenRepo := new(MockPwdResetTokenRepo)
	svc, _ := newPasswordResetService(userRepo, tokenRepo)

	token, hash := generatePlaintextToken(t)

	usedAt := time.Now().Add(-30 * time.Minute)
	reset := &models.PasswordReset{
		ID:        uuid.New(),
		UserID:    uuid.New(),
		TokenHash: hash,
		ExpiresAt: time.Now().Add(30 * time.Minute), // still valid time-wise
		UsedAt:    &usedAt,                          // but already used
	}

	tokenRepo.On("GetPasswordReset", ctx, mock.AnythingOfType("string")).Return(reset, nil)

	err := svc.ResetPassword(ctx, token, "NewP@ss123", "127.0.0.1")

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid or expired")
	tokenRepo.AssertExpectations(t)
}

func TestPasswordResetService_ResetPassword_UserNotActive(t *testing.T) {
	ctx := context.Background()

	userRepo := new(MockPwdResetUserRepo)
	tokenRepo := new(MockPwdResetTokenRepo)
	svc, _ := newPasswordResetService(userRepo, tokenRepo)

	token, hash := generatePlaintextToken(t)
	userID := uuid.New()

	reset := &models.PasswordReset{
		ID:        uuid.New(),
		UserID:    userID,
		TokenHash: hash,
		ExpiresAt: time.Now().Add(1 * time.Hour),
	}

	inactiveUser := &models.User{
		ID:       userID,
		IsActive: false, // disabled
	}

	tokenRepo.On("GetPasswordReset", ctx, mock.AnythingOfType("string")).Return(reset, nil)
	userRepo.On("GetByID", ctx, userID).Return(inactiveUser, nil)

	err := svc.ResetPassword(ctx, token, "NewP@ss123", "127.0.0.1")

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "disabled")
	userRepo.AssertExpectations(t)
	tokenRepo.AssertExpectations(t)
}

func TestPasswordResetService_ResetPassword_ValidToken_Success(t *testing.T) {
	ctx := context.Background()

	userRepo := new(MockPwdResetUserRepo)
	tokenRepo := new(MockPwdResetTokenRepo)
	svc, _ := newPasswordResetService(userRepo, tokenRepo)
	sessionRepo := new(MockPwdResetSessionRepo)
	svc.SetSessionRepo(sessionRepo)

	token, hash := generatePlaintextToken(t)
	userID := uuid.New()
	tenantID := uuid.New()
	resetID := uuid.New()

	reset := &models.PasswordReset{
		ID:        resetID,
		UserID:    userID,
		TokenHash: hash,
		ExpiresAt: time.Now().Add(1 * time.Hour),
	}

	activeUser := &models.User{
		ID:       userID,
		TenantID: tenantID,
		Username: "testuser",
		IsActive: true,
	}

	tokenRepo.On("GetPasswordReset", ctx, mock.AnythingOfType("string")).Return(reset, nil)
	userRepo.On("GetByID", ctx, userID).Return(activeUser, nil)
	userRepo.On("Update", ctx, mock.AnythingOfType("*models.User")).Return(nil)
	tokenRepo.On("MarkPasswordResetUsed", ctx, resetID).Return(nil)
	tokenRepo.On("InvalidateUserPasswordResets", ctx, userID).Return(nil)
	sessionRepo.On("EndAllUserSessions", ctx, userID, "password_reset").Return(nil)

	// Use a password that meets the permissive config (MinLength=8, no other requirements)
	err := svc.ResetPassword(ctx, token, "newpassword", "127.0.0.1")

	require.NoError(t, err)
	userRepo.AssertExpectations(t)
	tokenRepo.AssertExpectations(t)
	sessionRepo.AssertExpectations(t)
}

func TestPasswordResetService_ResetPassword_WeakPassword(t *testing.T) {
	ctx := context.Background()

	userRepo := new(MockPwdResetUserRepo)
	tokenRepo := new(MockPwdResetTokenRepo)

	// Build service with strict password policy
	cfg := &config.Config{
		PasswordMinLength:      12,
		PasswordRequireUpper:   true,
		PasswordRequireLower:   true,
		PasswordRequireDigit:   true,
		PasswordRequireSpecial: false,
	}
	emailSvc := NewEmailService(cfg)
	auditRepo := new(MockAuditTokenRepo)
	auditRepo.On("CreateAuditLog", mock.Anything, mock.Anything).Return(nil).Maybe()
	auditSvc := NewAuditService(auditRepo, nil)
	svc := NewPasswordResetService(cfg, userRepo, tokenRepo, emailSvc, auditSvc)

	token, hash := generatePlaintextToken(t)
	userID := uuid.New()
	tenantID := uuid.New()

	reset := &models.PasswordReset{
		ID:        uuid.New(),
		UserID:    userID,
		TokenHash: hash,
		ExpiresAt: time.Now().Add(1 * time.Hour),
	}

	activeUser := &models.User{
		ID:       userID,
		TenantID: tenantID,
		IsActive: true,
	}

	tokenRepo.On("GetPasswordReset", ctx, mock.AnythingOfType("string")).Return(reset, nil)
	userRepo.On("GetByID", ctx, userID).Return(activeUser, nil)

	// "short" is only 5 characters, below MinLength=12
	err := svc.ResetPassword(ctx, token, "short", "127.0.0.1")

	assert.Error(t, err)
	tokenRepo.AssertExpectations(t)
	userRepo.AssertExpectations(t)
}

func TestPasswordResetService_ResetPassword_SessionsInvalidatedAfterReset(t *testing.T) {
	ctx := context.Background()

	userRepo := new(MockPwdResetUserRepo)
	tokenRepo := new(MockPwdResetTokenRepo)
	svc, _ := newPasswordResetService(userRepo, tokenRepo)

	sessionRepo := new(MockPwdResetSessionRepo)
	svc.SetSessionRepo(sessionRepo)

	token, hash := generatePlaintextToken(t)
	userID := uuid.New()
	tenantID := uuid.New()
	resetID := uuid.New()

	reset := &models.PasswordReset{
		ID:        resetID,
		UserID:    userID,
		TokenHash: hash,
		ExpiresAt: time.Now().Add(1 * time.Hour),
	}

	activeUser := &models.User{
		ID:       userID,
		TenantID: tenantID,
		IsActive: true,
	}

	tokenRepo.On("GetPasswordReset", ctx, mock.AnythingOfType("string")).Return(reset, nil)
	userRepo.On("GetByID", ctx, userID).Return(activeUser, nil)
	userRepo.On("Update", ctx, mock.AnythingOfType("*models.User")).Return(nil)
	tokenRepo.On("MarkPasswordResetUsed", ctx, resetID).Return(nil)
	tokenRepo.On("InvalidateUserPasswordResets", ctx, userID).Return(nil)
	// This is the critical assertion: all sessions must be invalidated
	sessionRepo.On("EndAllUserSessions", ctx, userID, "password_reset").Return(nil).Once()

	err := svc.ResetPassword(ctx, token, "newsecurepass", "127.0.0.1")

	require.NoError(t, err)
	sessionRepo.AssertExpectations(t)
}

// ---------------------------------------------------------------------------
// Tests: SetSessionRepo
// ---------------------------------------------------------------------------

func TestPasswordResetService_SetSessionRepo(t *testing.T) {
	userRepo := new(MockPwdResetUserRepo)
	tokenRepo := new(MockPwdResetTokenRepo)
	svc, _ := newPasswordResetService(userRepo, tokenRepo)

	sessionRepo := new(MockPwdResetSessionRepo)
	svc.SetSessionRepo(sessionRepo)

	// Just verify it doesn't panic — the session repo is used in ResetPassword
	assert.NotNil(t, svc)
}
