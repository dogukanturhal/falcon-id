// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/pkg/config"
)

const (
	testUserEmail = "user@example.com"
)

// ---------------------------------------------------------------------------
// Mocks for magicLinkServiceMagicRepo
// ---------------------------------------------------------------------------

type mockMagicLinkMagicRepo struct {
	mock.Mock
}

func (m *mockMagicLinkMagicRepo) CountRecentByEmail(ctx context.Context, email string, since time.Time) (int, error) {
	args := m.Called(ctx, email, since)
	return args.Int(0), args.Error(1)
}

func (m *mockMagicLinkMagicRepo) CountRecentByIP(ctx context.Context, ip string, since time.Time) (int, error) {
	args := m.Called(ctx, ip, since)
	return args.Int(0), args.Error(1)
}

func (m *mockMagicLinkMagicRepo) Create(ctx context.Context, link *models.MagicLink) error {
	args := m.Called(ctx, link)
	return args.Error(0)
}

func (m *mockMagicLinkMagicRepo) GetByTokenHash(ctx context.Context, tokenHash string) (*models.MagicLink, error) {
	args := m.Called(ctx, tokenHash)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.MagicLink), args.Error(1)
}

func (m *mockMagicLinkMagicRepo) MarkAsUsed(ctx context.Context, id uuid.UUID) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *mockMagicLinkMagicRepo) DeleteExpired(ctx context.Context) (int64, error) {
	args := m.Called(ctx)
	return args.Get(0).(int64), args.Error(1)
}

// ---------------------------------------------------------------------------
// Mocks for magicLinkServiceUserRepo
// ---------------------------------------------------------------------------

type mockMagicLinkUserRepo struct {
	mock.Mock
}

func (m *mockMagicLinkUserRepo) GetByEmail(ctx context.Context, tenantID uuid.UUID, email string) (*models.User, error) {
	args := m.Called(ctx, tenantID, email)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.User), args.Error(1)
}

func (m *mockMagicLinkUserRepo) GetByID(ctx context.Context, id uuid.UUID) (*models.User, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.User), args.Error(1)
}

func (m *mockMagicLinkUserRepo) GetUserRoles(ctx context.Context, userID uuid.UUID) ([]models.Role, error) {
	args := m.Called(ctx, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]models.Role), args.Error(1)
}

func (m *mockMagicLinkUserRepo) GetUserPermissions(ctx context.Context, userID uuid.UUID) ([]models.Permission, error) {
	args := m.Called(ctx, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]models.Permission), args.Error(1)
}

func (m *mockMagicLinkUserRepo) Update(ctx context.Context, user *models.User) error {
	args := m.Called(ctx, user)
	return args.Error(0)
}

// ---------------------------------------------------------------------------
// Mocks for magicLinkServiceSessionRepo
// ---------------------------------------------------------------------------

type mockMagicLinkSessionRepo struct {
	mock.Mock
}

func (m *mockMagicLinkSessionRepo) Create(ctx context.Context, session *models.Session) error {
	args := m.Called(ctx, session)
	return args.Error(0)
}

// ---------------------------------------------------------------------------
// Helper
// ---------------------------------------------------------------------------

func newMagicLinkService(
	magicRepo *mockMagicLinkMagicRepo,
	userRepo *mockMagicLinkUserRepo,
	sessionRepo *mockMagicLinkSessionRepo,
) *MagicLinkService {
	cfg := &config.Config{
		FrontendURL:   "https://app.example.com",
		SessionExpiry: 24 * time.Hour,
	}
	// Concrete services that are only invoked on the full happy path (successful verify).
	// For tests that never reach those calls we pass nil.
	return NewMagicLinkService(cfg, magicRepo, userRepo, sessionRepo, nil, nil, nil)
}

// ---------------------------------------------------------------------------
// Tests: RequestMagicLink
// ---------------------------------------------------------------------------

func TestMagicLink_Request_EmailRateLimitExceeded_NoError(t *testing.T) {
	// Rate-limit exceeded silently returns nil to prevent email enumeration.
	ctx := context.Background()
	magicRepo := new(mockMagicLinkMagicRepo)
	userRepo := new(mockMagicLinkUserRepo)
	sessionRepo := new(mockMagicLinkSessionRepo)
	svc := newMagicLinkService(magicRepo, userRepo, sessionRepo)

	tenantID := uuid.New()
	email := testUserEmail

	magicRepo.On("CountRecentByEmail", ctx, email, mock.AnythingOfType("time.Time")).
		Return(MaxMagicLinksPerHour, nil)

	err := svc.RequestMagicLink(ctx, tenantID, email, "127.0.0.1", "TestAgent")

	require.NoError(t, err) // Must not surface rate limit to caller
	magicRepo.AssertExpectations(t)
}

func TestMagicLink_Request_IPRateLimitExceeded_NoError(t *testing.T) {
	ctx := context.Background()
	magicRepo := new(mockMagicLinkMagicRepo)
	userRepo := new(mockMagicLinkUserRepo)
	sessionRepo := new(mockMagicLinkSessionRepo)
	svc := newMagicLinkService(magicRepo, userRepo, sessionRepo)

	tenantID := uuid.New()
	email := testUserEmail
	ip := "10.0.0.1"

	// Email count is under limit
	magicRepo.On("CountRecentByEmail", ctx, email, mock.AnythingOfType("time.Time")).
		Return(0, nil)
	// IP count is at limit
	magicRepo.On("CountRecentByIP", ctx, ip, mock.AnythingOfType("time.Time")).
		Return(MaxMagicLinksPerIPPerHour, nil)

	err := svc.RequestMagicLink(ctx, tenantID, email, ip, "TestAgent")

	require.NoError(t, err) // Must not surface rate limit
	magicRepo.AssertExpectations(t)
}

func TestMagicLink_Request_UserNotFound_NoError(t *testing.T) {
	// Non-existent user silently returns nil to prevent enumeration.
	ctx := context.Background()
	magicRepo := new(mockMagicLinkMagicRepo)
	userRepo := new(mockMagicLinkUserRepo)
	sessionRepo := new(mockMagicLinkSessionRepo)
	svc := newMagicLinkService(magicRepo, userRepo, sessionRepo)

	tenantID := uuid.New()
	email := "nonexistent@example.com"

	magicRepo.On("CountRecentByEmail", ctx, email, mock.AnythingOfType("time.Time")).Return(0, nil)
	magicRepo.On("CountRecentByIP", ctx, "1.2.3.4", mock.AnythingOfType("time.Time")).Return(0, nil)
	userRepo.On("GetByEmail", ctx, tenantID, email).Return(nil, nil)

	err := svc.RequestMagicLink(ctx, tenantID, email, "1.2.3.4", "UA")

	require.NoError(t, err)
	userRepo.AssertExpectations(t)
}

func TestMagicLink_Request_InactiveUser_NoError(t *testing.T) {
	ctx := context.Background()
	magicRepo := new(mockMagicLinkMagicRepo)
	userRepo := new(mockMagicLinkUserRepo)
	sessionRepo := new(mockMagicLinkSessionRepo)
	svc := newMagicLinkService(magicRepo, userRepo, sessionRepo)

	tenantID := uuid.New()
	email := "inactive@example.com"

	magicRepo.On("CountRecentByEmail", ctx, email, mock.AnythingOfType("time.Time")).Return(0, nil)
	magicRepo.On("CountRecentByIP", ctx, "1.2.3.4", mock.AnythingOfType("time.Time")).Return(0, nil)
	userRepo.On("GetByEmail", ctx, tenantID, email).Return(&models.User{
		ID:       uuid.New(),
		Email:    email,
		IsActive: false,
	}, nil)

	err := svc.RequestMagicLink(ctx, tenantID, email, "1.2.3.4", "UA")

	require.NoError(t, err)
}

func TestMagicLink_Request_LockedUser_NoError(t *testing.T) {
	ctx := context.Background()
	magicRepo := new(mockMagicLinkMagicRepo)
	userRepo := new(mockMagicLinkUserRepo)
	sessionRepo := new(mockMagicLinkSessionRepo)
	svc := newMagicLinkService(magicRepo, userRepo, sessionRepo)

	tenantID := uuid.New()
	email := "locked@example.com"

	magicRepo.On("CountRecentByEmail", ctx, email, mock.AnythingOfType("time.Time")).Return(0, nil)
	magicRepo.On("CountRecentByIP", ctx, "1.2.3.4", mock.AnythingOfType("time.Time")).Return(0, nil)
	userRepo.On("GetByEmail", ctx, tenantID, email).Return(&models.User{
		ID:       uuid.New(),
		Email:    email,
		IsActive: true,
		IsLocked: true,
	}, nil)

	err := svc.RequestMagicLink(ctx, tenantID, email, "1.2.3.4", "UA")

	require.NoError(t, err)
}

func TestMagicLink_Request_EmailCountError_ReturnsError(t *testing.T) {
	ctx := context.Background()
	magicRepo := new(mockMagicLinkMagicRepo)
	userRepo := new(mockMagicLinkUserRepo)
	sessionRepo := new(mockMagicLinkSessionRepo)
	svc := newMagicLinkService(magicRepo, userRepo, sessionRepo)

	tenantID := uuid.New()
	email := testUserEmail

	magicRepo.On("CountRecentByEmail", ctx, email, mock.AnythingOfType("time.Time")).
		Return(0, errors.New("db error"))

	err := svc.RequestMagicLink(ctx, tenantID, email, "1.2.3.4", "UA")

	// Internal error propagates as a generic message
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to process request")
}

func TestMagicLink_Request_StoresLink_WhenValidUser(t *testing.T) {
	// The service must store the magic link when all pre-conditions are met.
	// Email send will fail (no SMTP) but that failure is logged and swallowed.
	ctx := context.Background()
	magicRepo := new(mockMagicLinkMagicRepo)
	userRepo := new(mockMagicLinkUserRepo)
	sessionRepo := new(mockMagicLinkSessionRepo)

	cfg := &config.Config{
		FrontendURL:   "https://app.example.com",
		SessionExpiry: 24 * time.Hour,
	}
	// Create a real EmailService with no SMTP configured; SendMagicLink will
	// fail internally but the error is swallowed by RequestMagicLink.
	emailSvc := NewEmailService(cfg)
	svc := NewMagicLinkService(cfg, magicRepo, userRepo, sessionRepo, nil, emailSvc, nil)

	tenantID := uuid.New()
	userID := uuid.New()
	email := testUserEmail
	firstName := testExportNameAlice

	magicRepo.On("CountRecentByEmail", ctx, email, mock.AnythingOfType("time.Time")).Return(0, nil)
	magicRepo.On("CountRecentByIP", ctx, "1.2.3.4", mock.AnythingOfType("time.Time")).Return(0, nil)
	userRepo.On("GetByEmail", ctx, tenantID, email).Return(&models.User{
		ID:        userID,
		TenantID:  tenantID,
		Email:     email,
		Username:  "alice",
		FirstName: &firstName,
		IsActive:  true,
		IsLocked:  false,
	}, nil)
	magicRepo.On("Create", ctx, mock.AnythingOfType("*models.MagicLink")).Return(nil)

	err := svc.RequestMagicLink(ctx, tenantID, email, "1.2.3.4", "TestAgent")

	require.NoError(t, err)
	magicRepo.AssertExpectations(t)
	userRepo.AssertExpectations(t)
}

// ---------------------------------------------------------------------------
// Tests: VerifyMagicLink – error cases only (full path needs concrete token/audit services)
// ---------------------------------------------------------------------------

func TestMagicLink_Verify_InvalidTokenHash_Error(t *testing.T) {
	ctx := context.Background()
	magicRepo := new(mockMagicLinkMagicRepo)
	userRepo := new(mockMagicLinkUserRepo)
	sessionRepo := new(mockMagicLinkSessionRepo)
	svc := newMagicLinkService(magicRepo, userRepo, sessionRepo)

	// GetByTokenHash returns error
	magicRepo.On("GetByTokenHash", ctx, mock.AnythingOfType("string")).
		Return(nil, errors.New("db error"))

	_, err := svc.VerifyMagicLink(ctx, "somevalidtoken", "1.2.3.4", "UA")

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid or expired link")
}

func TestMagicLink_Verify_NotFound_Error(t *testing.T) {
	ctx := context.Background()
	magicRepo := new(mockMagicLinkMagicRepo)
	userRepo := new(mockMagicLinkUserRepo)
	sessionRepo := new(mockMagicLinkSessionRepo)
	svc := newMagicLinkService(magicRepo, userRepo, sessionRepo)

	magicRepo.On("GetByTokenHash", ctx, mock.AnythingOfType("string")).Return(nil, nil)

	_, err := svc.VerifyMagicLink(ctx, "token-that-does-not-exist", "1.2.3.4", "UA")

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid or expired link")
}

func TestMagicLink_Verify_AlreadyUsed_Error(t *testing.T) {
	ctx := context.Background()
	magicRepo := new(mockMagicLinkMagicRepo)
	userRepo := new(mockMagicLinkUserRepo)
	sessionRepo := new(mockMagicLinkSessionRepo)
	svc := newMagicLinkService(magicRepo, userRepo, sessionRepo)

	usedAt := time.Now().Add(-5 * time.Minute)
	link := &models.MagicLink{
		ID:        uuid.New(),
		Email:     testUserEmail,
		TokenHash: "hash",
		UsedAt:    &usedAt, // already used
		ExpiresAt: time.Now().Add(10 * time.Minute),
	}

	magicRepo.On("GetByTokenHash", ctx, mock.AnythingOfType("string")).Return(link, nil)

	_, err := svc.VerifyMagicLink(ctx, "some-token", "1.2.3.4", "UA")

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "already been used")
}

func TestMagicLink_Verify_Expired_Error(t *testing.T) {
	ctx := context.Background()
	magicRepo := new(mockMagicLinkMagicRepo)
	userRepo := new(mockMagicLinkUserRepo)
	sessionRepo := new(mockMagicLinkSessionRepo)
	svc := newMagicLinkService(magicRepo, userRepo, sessionRepo)

	link := &models.MagicLink{
		ID:        uuid.New(),
		Email:     testUserEmail,
		TokenHash: "hash",
		UsedAt:    nil,
		ExpiresAt: time.Now().Add(-1 * time.Minute), // expired
	}

	magicRepo.On("GetByTokenHash", ctx, mock.AnythingOfType("string")).Return(link, nil)

	_, err := svc.VerifyMagicLink(ctx, "some-token", "1.2.3.4", "UA")

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "has expired")
}

// ---------------------------------------------------------------------------
// Tests: CleanupExpired
// ---------------------------------------------------------------------------

func TestMagicLink_CleanupExpired_Success(t *testing.T) {
	ctx := context.Background()
	magicRepo := new(mockMagicLinkMagicRepo)
	userRepo := new(mockMagicLinkUserRepo)
	sessionRepo := new(mockMagicLinkSessionRepo)
	svc := newMagicLinkService(magicRepo, userRepo, sessionRepo)

	magicRepo.On("DeleteExpired", ctx).Return(int64(7), nil)

	count, err := svc.CleanupExpired(ctx)

	require.NoError(t, err)
	assert.Equal(t, int64(7), count)
	magicRepo.AssertExpectations(t)
}

func TestMagicLink_CleanupExpired_RepoError(t *testing.T) {
	ctx := context.Background()
	magicRepo := new(mockMagicLinkMagicRepo)
	userRepo := new(mockMagicLinkUserRepo)
	sessionRepo := new(mockMagicLinkSessionRepo)
	svc := newMagicLinkService(magicRepo, userRepo, sessionRepo)

	magicRepo.On("DeleteExpired", ctx).Return(int64(0), errors.New("db error"))

	count, err := svc.CleanupExpired(ctx)

	assert.Error(t, err)
	assert.Equal(t, int64(0), count)
}

func TestMagicLink_CleanupExpired_ZeroDeleted(t *testing.T) {
	ctx := context.Background()
	magicRepo := new(mockMagicLinkMagicRepo)
	userRepo := new(mockMagicLinkUserRepo)
	sessionRepo := new(mockMagicLinkSessionRepo)
	svc := newMagicLinkService(magicRepo, userRepo, sessionRepo)

	magicRepo.On("DeleteExpired", ctx).Return(int64(0), nil)

	count, err := svc.CleanupExpired(ctx)

	require.NoError(t, err)
	assert.Equal(t, int64(0), count)
}

// ---------------------------------------------------------------------------
// Tests: MagicLink model helper methods
// ---------------------------------------------------------------------------

func TestMagicLink_Model_IsExpired(t *testing.T) {
	tests := []struct {
		name    string
		link    models.MagicLink
		expired bool
	}{
		{
			name:    "not expired",
			link:    models.MagicLink{ExpiresAt: time.Now().Add(time.Hour)},
			expired: false,
		},
		{
			name:    "expired",
			link:    models.MagicLink{ExpiresAt: time.Now().Add(-time.Second)},
			expired: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expired, tc.link.IsExpired())
		})
	}
}

func TestMagicLink_Model_IsUsed(t *testing.T) {
	usedAt := time.Now()
	used := models.MagicLink{UsedAt: &usedAt}
	unused := models.MagicLink{UsedAt: nil}

	assert.True(t, used.IsUsed())
	assert.False(t, unused.IsUsed())
}

func TestMagicLink_Model_IsValid(t *testing.T) {
	usedAt := time.Now()
	tests := []struct {
		name  string
		link  models.MagicLink
		valid bool
	}{
		{
			name:  "valid: not used, not expired",
			link:  models.MagicLink{ExpiresAt: time.Now().Add(time.Hour)},
			valid: true,
		},
		{
			name:  "invalid: used",
			link:  models.MagicLink{UsedAt: &usedAt, ExpiresAt: time.Now().Add(time.Hour)},
			valid: false,
		},
		{
			name:  "invalid: expired",
			link:  models.MagicLink{ExpiresAt: time.Now().Add(-time.Second)},
			valid: false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.valid, tc.link.IsValid())
		})
	}
}

// ---------------------------------------------------------------------------
// Tests: Constants
// ---------------------------------------------------------------------------

func TestMagicLink_Constants(t *testing.T) {
	assert.Equal(t, 15*time.Minute, MagicLinkExpiry)
	assert.Equal(t, 5, MaxMagicLinksPerHour)
	assert.Equal(t, 10, MaxMagicLinksPerIPPerHour)
}
