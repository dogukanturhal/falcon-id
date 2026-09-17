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

// ==================== Mock declarations ====================

// MockInvitationRepo mocks invitationServiceInvitationRepo.
type MockInvitationRepo struct {
	mock.Mock
}

func (m *MockInvitationRepo) RevokePendingByUserID(ctx context.Context, userID uuid.UUID) error {
	args := m.Called(ctx, userID)
	return args.Error(0)
}

func (m *MockInvitationRepo) Create(ctx context.Context, inv *models.UserInvitation) error {
	args := m.Called(ctx, inv)
	return args.Error(0)
}

func (m *MockInvitationRepo) UpdateEmailSent(ctx context.Context, id uuid.UUID) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *MockInvitationRepo) GetByTokenHash(ctx context.Context, tokenHash string) (*models.UserInvitation, error) {
	args := m.Called(ctx, tokenHash)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.UserInvitation), args.Error(1)
}

func (m *MockInvitationRepo) GetByUserID(ctx context.Context, userID uuid.UUID) (*models.UserInvitation, error) {
	args := m.Called(ctx, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.UserInvitation), args.Error(1)
}

func (m *MockInvitationRepo) UpdateTokenHash(ctx context.Context, id uuid.UUID, tokenHash string, expiresAt time.Time) error {
	args := m.Called(ctx, id, tokenHash, expiresAt)
	return args.Error(0)
}

func (m *MockInvitationRepo) MarkAsAccepted(ctx context.Context, id uuid.UUID, ipAddress string) error {
	args := m.Called(ctx, id, ipAddress)
	return args.Error(0)
}

func (m *MockInvitationRepo) ExpireOldInvitations(ctx context.Context) (int64, error) {
	args := m.Called(ctx)
	return args.Get(0).(int64), args.Error(1)
}

func (m *MockInvitationRepo) GetByID(ctx context.Context, id uuid.UUID) (*models.UserInvitation, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.UserInvitation), args.Error(1)
}

// MockInvitationUserRepo mocks invitationServiceUserRepo.
type MockInvitationUserRepo struct {
	mock.Mock
}

func (m *MockInvitationUserRepo) GetByID(ctx context.Context, id uuid.UUID) (*models.User, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.User), args.Error(1)
}

func (m *MockInvitationUserRepo) UpdateActivationStatus(ctx context.Context, userID uuid.UUID, status string) error {
	args := m.Called(ctx, userID, status)
	return args.Error(0)
}

func (m *MockInvitationUserRepo) Update(ctx context.Context, user *models.User) error {
	args := m.Called(ctx, user)
	return args.Error(0)
}

func (m *MockInvitationUserRepo) GetUserRoles(ctx context.Context, userID uuid.UUID) ([]models.Role, error) {
	args := m.Called(ctx, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]models.Role), args.Error(1)
}

func (m *MockInvitationUserRepo) GetUserPermissions(ctx context.Context, userID uuid.UUID) ([]models.Permission, error) {
	args := m.Called(ctx, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]models.Permission), args.Error(1)
}

// MockInvitationSessionRepo mocks invitationServiceSessionRepo.
type MockInvitationSessionRepo struct {
	mock.Mock
}

func (m *MockInvitationSessionRepo) Create(ctx context.Context, session *models.Session) error {
	args := m.Called(ctx, session)
	return args.Error(0)
}

// ==================== Helpers ====================

func newInvitationService(ir *MockInvitationRepo, ur *MockInvitationUserRepo) *InvitationService {
	cfg := &config.Config{
		FrontendURL:       "http://localhost:3000",
		AccessTokenExpiry: 15 * time.Minute,
		SessionExpiry:     24 * time.Hour,
	}
	return &InvitationService{
		config:         cfg,
		invitationRepo: ir,
		userRepo:       ur,
		// tokenService, emailService, auditService intentionally nil for tests
		// that do not reach those code paths.
	}
}

func buildPendingInvitation(userID, tenantID uuid.UUID) *models.UserInvitation {
	return &models.UserInvitation{
		ID:             uuid.New(),
		UserID:         userID,
		TenantID:       tenantID,
		Email:          "user@example.com",
		InvitationType: models.InvitationTypeTenantAdmin,
		Status:         models.InvitationStatusPending,
		ExpiresAt:      time.Now().Add(72 * time.Hour),
		CreatedAt:      time.Now(),
		UpdatedAt:      time.Now(),
	}
}

// ==================== ValidateToken ====================

func TestInvitationService_ValidateToken_Valid(t *testing.T) {
	// ValidateToken hashes the token internally then calls GetByTokenHash.
	// We exercise ValidateToken with a stored invitation that is valid.
	// Since we cannot predict the computed hash from a random token, we instead
	// test the branch where GetByTokenHash returns a valid invitation.
	ctx := context.Background()
	userID := uuid.New()
	tenantID := uuid.New()
	inv := buildPendingInvitation(userID, tenantID)

	ir := new(MockInvitationRepo)
	ur := new(MockInvitationUserRepo)
	svc := newInvitationService(ir, ur)

	// GetByTokenHash is called with the hashed form of any token we send.
	// We use mock.AnythingOfType to avoid computing the hash ourselves.
	ir.On("GetByTokenHash", ctx, mock.AnythingOfType("string")).Return(inv, nil)

	resp, err := svc.ValidateToken(ctx, "some-raw-token-value")

	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.True(t, resp.Valid)
	assert.Equal(t, inv.Email, resp.Email)
}

func TestInvitationService_ValidateToken_NotFound(t *testing.T) {
	ctx := context.Background()

	ir := new(MockInvitationRepo)
	ur := new(MockInvitationUserRepo)
	svc := newInvitationService(ir, ur)

	ir.On("GetByTokenHash", ctx, mock.AnythingOfType("string")).Return(nil, errors.New("not found"))

	resp, err := svc.ValidateToken(ctx, "bad-token")

	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.False(t, resp.Valid)
	assert.NotEmpty(t, resp.Error)
}

func TestInvitationService_ValidateToken_Expired(t *testing.T) {
	ctx := context.Background()
	userID := uuid.New()
	tenantID := uuid.New()

	expiredInv := buildPendingInvitation(userID, tenantID)
	expiredInv.ExpiresAt = time.Now().Add(-1 * time.Hour) // in the past

	ir := new(MockInvitationRepo)
	ur := new(MockInvitationUserRepo)
	svc := newInvitationService(ir, ur)

	ir.On("GetByTokenHash", ctx, mock.AnythingOfType("string")).Return(expiredInv, nil)

	resp, err := svc.ValidateToken(ctx, "expired-token")

	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.False(t, resp.Valid)
	assert.Contains(t, resp.Error, "expired")
}

func TestInvitationService_ValidateToken_AlreadyAccepted(t *testing.T) {
	ctx := context.Background()
	userID := uuid.New()
	tenantID := uuid.New()

	acceptedInv := buildPendingInvitation(userID, tenantID)
	acceptedInv.Status = models.InvitationStatusAccepted

	ir := new(MockInvitationRepo)
	ur := new(MockInvitationUserRepo)
	svc := newInvitationService(ir, ur)

	ir.On("GetByTokenHash", ctx, mock.AnythingOfType("string")).Return(acceptedInv, nil)

	resp, err := svc.ValidateToken(ctx, "used-token")

	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.False(t, resp.Valid)
	assert.Contains(t, resp.Error, "already been used")
}

func TestInvitationService_ValidateToken_Revoked(t *testing.T) {
	ctx := context.Background()
	userID := uuid.New()
	tenantID := uuid.New()

	revokedInv := buildPendingInvitation(userID, tenantID)
	revokedInv.Status = models.InvitationStatusRevoked

	ir := new(MockInvitationRepo)
	ur := new(MockInvitationUserRepo)
	svc := newInvitationService(ir, ur)

	ir.On("GetByTokenHash", ctx, mock.AnythingOfType("string")).Return(revokedInv, nil)

	resp, err := svc.ValidateToken(ctx, "revoked-token")

	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.False(t, resp.Valid)
	assert.Contains(t, resp.Error, "revoked")
}

// ==================== RevokeInvitation ====================

func TestInvitationService_RevokeInvitation_Valid(t *testing.T) {
	ctx := context.Background()
	userID := uuid.New()

	ir := new(MockInvitationRepo)
	ur := new(MockInvitationUserRepo)
	svc := newInvitationService(ir, ur)

	ir.On("RevokePendingByUserID", ctx, userID).Return(nil)

	err := svc.RevokeInvitation(ctx, userID)

	require.NoError(t, err)
	ir.AssertExpectations(t)
}

func TestInvitationService_RevokeInvitation_RepoError(t *testing.T) {
	ctx := context.Background()
	userID := uuid.New()

	ir := new(MockInvitationRepo)
	ur := new(MockInvitationUserRepo)
	svc := newInvitationService(ir, ur)

	ir.On("RevokePendingByUserID", ctx, userID).Return(errors.New("db error"))

	err := svc.RevokeInvitation(ctx, userID)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to revoke invitation")
}

// ==================== GetPendingInvitation ====================

func TestInvitationService_GetPendingInvitation_Found(t *testing.T) {
	ctx := context.Background()
	userID := uuid.New()
	tenantID := uuid.New()

	inv := buildPendingInvitation(userID, tenantID)

	ir := new(MockInvitationRepo)
	ur := new(MockInvitationUserRepo)
	svc := newInvitationService(ir, ur)

	ir.On("GetByUserID", ctx, userID).Return(inv, nil)

	result, err := svc.GetPendingInvitation(ctx, userID)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, inv.Email, result.Email)
}

func TestInvitationService_GetPendingInvitation_NoneFound(t *testing.T) {
	ctx := context.Background()
	userID := uuid.New()

	ir := new(MockInvitationRepo)
	ur := new(MockInvitationUserRepo)
	svc := newInvitationService(ir, ur)

	ir.On("GetByUserID", ctx, userID).Return(nil, nil)

	result, err := svc.GetPendingInvitation(ctx, userID)

	require.NoError(t, err)
	assert.Nil(t, result)
}

// ==================== ExpireOldInvitations ====================

func TestInvitationService_ExpireOldInvitations_Success(t *testing.T) {
	ctx := context.Background()

	ir := new(MockInvitationRepo)
	ur := new(MockInvitationUserRepo)
	svc := newInvitationService(ir, ur)

	ir.On("ExpireOldInvitations", ctx).Return(int64(5), nil)

	count, err := svc.ExpireOldInvitations(ctx)

	require.NoError(t, err)
	assert.Equal(t, int64(5), count)
}

func TestInvitationService_ExpireOldInvitations_Zero(t *testing.T) {
	ctx := context.Background()

	ir := new(MockInvitationRepo)
	ur := new(MockInvitationUserRepo)
	svc := newInvitationService(ir, ur)

	ir.On("ExpireOldInvitations", ctx).Return(int64(0), nil)

	count, err := svc.ExpireOldInvitations(ctx)

	require.NoError(t, err)
	assert.Equal(t, int64(0), count)
}

// ==================== CreateInvitation (user-not-found / user-already-active paths) ====================

func TestInvitationService_CreateInvitation_UserNotFound(t *testing.T) {
	ctx := context.Background()
	tenantID := uuid.New()
	userID := uuid.New()

	ir := new(MockInvitationRepo)
	ur := new(MockInvitationUserRepo)
	svc := newInvitationService(ir, ur)

	ur.On("GetByID", ctx, userID).Return(nil, nil) // user is nil

	req := &models.CreateInvitationRequest{
		UserID:         userID,
		TenantID:       tenantID,
		InvitationType: models.InvitationTypeTenantAdmin,
		Email:          "nobody@example.com",
	}

	resp, token, err := svc.CreateInvitation(ctx, req)

	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Empty(t, token)
	assert.Contains(t, err.Error(), "user not found")
}

func TestInvitationService_CreateInvitation_UserAlreadyActive(t *testing.T) {
	ctx := context.Background()
	tenantID := uuid.New()
	userID := uuid.New()

	ir := new(MockInvitationRepo)
	ur := new(MockInvitationUserRepo)
	svc := newInvitationService(ir, ur)

	passwordHash := "some-hash"
	activeUser := &models.User{
		ID:               userID,
		TenantID:         tenantID,
		Email:            "active@example.com",
		PasswordHash:     &passwordHash,
		ActivationStatus: string(models.UserActivationActive),
	}

	ur.On("GetByID", ctx, userID).Return(activeUser, nil)

	req := &models.CreateInvitationRequest{
		UserID:         userID,
		TenantID:       tenantID,
		InvitationType: models.InvitationTypeTenantAdmin,
		Email:          "active@example.com",
	}

	resp, token, err := svc.CreateInvitation(ctx, req)

	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Empty(t, token)
	assert.Contains(t, err.Error(), "already has an active account")
}

// ==================== CreateInvitation (happy path - no email send) ====================

func TestInvitationService_CreateInvitation_Valid_NoEmail(t *testing.T) {
	ctx := context.Background()
	tenantID := uuid.New()
	userID := uuid.New()

	ir := new(MockInvitationRepo)
	ur := new(MockInvitationUserRepo)
	svc := newInvitationService(ir, ur)

	user := &models.User{
		ID:               userID,
		TenantID:         tenantID,
		Email:            "newuser@example.com",
		ActivationStatus: string(models.UserActivationPendingInvitation),
	}

	ur.On("GetByID", ctx, userID).Return(user, nil)
	ir.On("RevokePendingByUserID", ctx, userID).Return(nil)
	ir.On("Create", ctx, mock.AnythingOfType("*models.UserInvitation")).Return(nil)
	ur.On("UpdateActivationStatus", ctx, userID, string(models.UserActivationPendingInvitation)).Return(nil)

	req := &models.CreateInvitationRequest{
		UserID:         userID,
		TenantID:       tenantID,
		InvitationType: models.InvitationTypeTenantAdmin,
		Email:          "newuser@example.com",
		SendEmail:      false, // skip email sending branch
	}

	resp, token, err := svc.CreateInvitation(ctx, req)

	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.NotEmpty(t, token)
	ir.AssertExpectations(t)
	ur.AssertExpectations(t)
}

// ==================== ResendInvitation ====================

func TestInvitationService_ResendInvitation_UserNotFound(t *testing.T) {
	ctx := context.Background()
	userID := uuid.New()

	ir := new(MockInvitationRepo)
	ur := new(MockInvitationUserRepo)
	svc := newInvitationService(ir, ur)

	ir.On("GetByUserID", ctx, userID).Return(nil, nil)
	ur.On("GetByID", ctx, userID).Return(nil, nil) // user nil

	_, err := svc.ResendInvitation(ctx, userID, false)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "user not found")
}

func TestInvitationService_ResendInvitation_RateLimitExceeded(t *testing.T) {
	ctx := context.Background()
	userID := uuid.New()
	tenantID := uuid.New()

	ir := new(MockInvitationRepo)
	ur := new(MockInvitationUserRepo)
	svc := newInvitationService(ir, ur)

	// Invitation that has hit the rate limit (EmailSendCount >= 5)
	lastSent := time.Now().Add(-1 * time.Minute) // less than 5 min ago
	inv := buildPendingInvitation(userID, tenantID)
	inv.EmailSendCount = 5
	inv.LastEmailSentAt = &lastSent

	user := &models.User{ID: userID, TenantID: tenantID, Email: "u@example.com"}

	ir.On("GetByUserID", ctx, userID).Return(inv, nil)
	ur.On("GetByID", ctx, userID).Return(user, nil)

	_, err := svc.ResendInvitation(ctx, userID, false)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "please wait")
}
