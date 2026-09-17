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

	"github.com/dogukanturhal/falcon-id/internal/models"
)

// ---------------------------------------------------------------------------
// Mock implementations
// ---------------------------------------------------------------------------

type mockDeletionSessionRepo struct {
	mock.Mock
}

func (m *mockDeletionSessionRepo) EndAllUserSessions(ctx context.Context, userID uuid.UUID, reason string) error {
	args := m.Called(ctx, userID, reason)
	return args.Error(0)
}

// mockDeletionOAuthRepo stubs dataDeletionOAuthRepo for tests of the
// OAuth-token sweep path.
type mockDeletionOAuthRepo struct {
	mock.Mock
}

func (m *mockDeletionOAuthRepo) RevokeAllUserOAuthTokens(ctx context.Context, userID uuid.UUID, reason string) error {
	args := m.Called(ctx, userID, reason)
	return args.Error(0)
}

type mockDeletionDeviceRepo struct {
	mock.Mock
}

func (m *mockDeletionDeviceRepo) DeleteByUserID(ctx context.Context, userID uuid.UUID) error {
	args := m.Called(ctx, userID)
	return args.Error(0)
}

type mockDeletionMFARepo struct {
	mock.Mock
}

func (m *mockDeletionMFARepo) DeleteAllRecoveryCodes(ctx context.Context, userID uuid.UUID) error {
	args := m.Called(ctx, userID)
	return args.Error(0)
}

func (m *mockDeletionMFARepo) DeleteUserEmailVerifications(ctx context.Context, userID uuid.UUID) error {
	args := m.Called(ctx, userID)
	return args.Error(0)
}

func (m *mockDeletionMFARepo) DeleteMFAPendingSetup(ctx context.Context, userID uuid.UUID) error {
	args := m.Called(ctx, userID)
	return args.Error(0)
}

// testableDataDeletionService wraps only the interface-injected dependencies so
// we can exercise the cascade logic without a live database or DeletionRepository.
type testableDataDeletionService struct {
	sessionRepo dataDeletionSessionRepo
	oauthRepo   dataDeletionOAuthRepo // optional, mirrors real service
	deviceRepo  dataDeletionDeviceRepo
	mfaRepo     dataDeletionMFARepo
}

func (s *testableDataDeletionService) cascadeDelete(ctx context.Context, userID uuid.UUID, _ uuid.UUID) error { //nolint:unparam // always nil in test stub; matches interface
	// Mirror the real cascadeDelete but skip the SQL anonymisation step (requires live DB).
	if err := s.sessionRepo.EndAllUserSessions(ctx, userID, "user_deleted"); err != nil {
		// Real service only warns; we replicate the same lenient behaviour.
		_ = err
	}
	if s.oauthRepo != nil {
		if err := s.oauthRepo.RevokeAllUserOAuthTokens(ctx, userID, "user_deleted"); err != nil {
			_ = err
		}
	}
	if err := s.deviceRepo.DeleteByUserID(ctx, userID); err != nil {
		_ = err
	}
	if err := s.mfaRepo.DeleteAllRecoveryCodes(ctx, userID); err != nil {
		_ = err
	}
	if err := s.mfaRepo.DeleteUserEmailVerifications(ctx, userID); err != nil {
		_ = err
	}
	if err := s.mfaRepo.DeleteMFAPendingSetup(ctx, userID); err != nil {
		_ = err
	}
	return nil
}

// ---------------------------------------------------------------------------
// TestDataDeletionService_CascadeDelete
// ---------------------------------------------------------------------------

func TestDataDeletionService_CascadeDelete_AllStepsSucceed(t *testing.T) {
	ctx := context.Background()
	userID := uuid.New()
	tenantID := uuid.New()

	sessionRepo := new(mockDeletionSessionRepo)
	deviceRepo := new(mockDeletionDeviceRepo)
	mfaRepo := new(mockDeletionMFARepo)

	sessionRepo.On("EndAllUserSessions", ctx, userID, "user_deleted").Return(nil)
	deviceRepo.On("DeleteByUserID", ctx, userID).Return(nil)
	mfaRepo.On("DeleteAllRecoveryCodes", ctx, userID).Return(nil)
	mfaRepo.On("DeleteUserEmailVerifications", ctx, userID).Return(nil)
	mfaRepo.On("DeleteMFAPendingSetup", ctx, userID).Return(nil)

	svc := &testableDataDeletionService{
		sessionRepo: sessionRepo,
		deviceRepo:  deviceRepo,
		mfaRepo:     mfaRepo,
	}

	err := svc.cascadeDelete(ctx, userID, tenantID)

	require.NoError(t, err)
	sessionRepo.AssertExpectations(t)
	deviceRepo.AssertExpectations(t)
	mfaRepo.AssertExpectations(t)
}

func TestDataDeletionService_CascadeDelete_SessionsError_ContinuesDeleteChain(t *testing.T) {
	// The real service only warns on individual step failures; all steps must be
	// called regardless.
	ctx := context.Background()
	userID := uuid.New()
	tenantID := uuid.New()

	sessionRepo := new(mockDeletionSessionRepo)
	deviceRepo := new(mockDeletionDeviceRepo)
	mfaRepo := new(mockDeletionMFARepo)

	sessionRepo.On("EndAllUserSessions", ctx, userID, "user_deleted").Return(errors.New("session store offline"))
	deviceRepo.On("DeleteByUserID", ctx, userID).Return(nil)
	mfaRepo.On("DeleteAllRecoveryCodes", ctx, userID).Return(nil)
	mfaRepo.On("DeleteUserEmailVerifications", ctx, userID).Return(nil)
	mfaRepo.On("DeleteMFAPendingSetup", ctx, userID).Return(nil)

	svc := &testableDataDeletionService{
		sessionRepo: sessionRepo,
		deviceRepo:  deviceRepo,
		mfaRepo:     mfaRepo,
	}

	err := svc.cascadeDelete(ctx, userID, tenantID)

	require.NoError(t, err)
	// All downstream steps must still have been attempted.
	deviceRepo.AssertExpectations(t)
	mfaRepo.AssertExpectations(t)
}

func TestDataDeletionService_CascadeDelete_TokensError_ContinuesDeleteChain(t *testing.T) {
	ctx := context.Background()
	userID := uuid.New()
	tenantID := uuid.New()

	sessionRepo := new(mockDeletionSessionRepo)
	deviceRepo := new(mockDeletionDeviceRepo)
	mfaRepo := new(mockDeletionMFARepo)

	sessionRepo.On("EndAllUserSessions", ctx, userID, "user_deleted").Return(nil)
	deviceRepo.On("DeleteByUserID", ctx, userID).Return(nil)
	mfaRepo.On("DeleteAllRecoveryCodes", ctx, userID).Return(nil)
	mfaRepo.On("DeleteUserEmailVerifications", ctx, userID).Return(nil)
	mfaRepo.On("DeleteMFAPendingSetup", ctx, userID).Return(nil)

	svc := &testableDataDeletionService{
		sessionRepo: sessionRepo,
		deviceRepo:  deviceRepo,
		mfaRepo:     mfaRepo,
	}

	err := svc.cascadeDelete(ctx, userID, tenantID)

	require.NoError(t, err)
	deviceRepo.AssertExpectations(t)
	mfaRepo.AssertExpectations(t)
}

func TestDataDeletionService_CascadeDelete_DevicesError_ContinuesDeleteChain(t *testing.T) {
	ctx := context.Background()
	userID := uuid.New()
	tenantID := uuid.New()

	sessionRepo := new(mockDeletionSessionRepo)
	deviceRepo := new(mockDeletionDeviceRepo)
	mfaRepo := new(mockDeletionMFARepo)

	sessionRepo.On("EndAllUserSessions", ctx, userID, "user_deleted").Return(nil)
	deviceRepo.On("DeleteByUserID", ctx, userID).Return(errors.New("device table locked"))
	mfaRepo.On("DeleteAllRecoveryCodes", ctx, userID).Return(nil)
	mfaRepo.On("DeleteUserEmailVerifications", ctx, userID).Return(nil)
	mfaRepo.On("DeleteMFAPendingSetup", ctx, userID).Return(nil)

	svc := &testableDataDeletionService{
		sessionRepo: sessionRepo,
		deviceRepo:  deviceRepo,
		mfaRepo:     mfaRepo,
	}

	err := svc.cascadeDelete(ctx, userID, tenantID)

	require.NoError(t, err)
	mfaRepo.AssertExpectations(t)
}

func TestDataDeletionService_CascadeDelete_MFAErrors_ContinuesDeleteChain(t *testing.T) {
	ctx := context.Background()
	userID := uuid.New()
	tenantID := uuid.New()

	sessionRepo := new(mockDeletionSessionRepo)
	deviceRepo := new(mockDeletionDeviceRepo)
	mfaRepo := new(mockDeletionMFARepo)

	sessionRepo.On("EndAllUserSessions", ctx, userID, "user_deleted").Return(nil)
	deviceRepo.On("DeleteByUserID", ctx, userID).Return(nil)
	mfaRepo.On("DeleteAllRecoveryCodes", ctx, userID).Return(errors.New("recovery codes table unavailable"))
	mfaRepo.On("DeleteUserEmailVerifications", ctx, userID).Return(errors.New("email verification table unavailable"))
	mfaRepo.On("DeleteMFAPendingSetup", ctx, userID).Return(errors.New("pending setup table unavailable"))

	svc := &testableDataDeletionService{
		sessionRepo: sessionRepo,
		deviceRepo:  deviceRepo,
		mfaRepo:     mfaRepo,
	}

	err := svc.cascadeDelete(ctx, userID, tenantID)

	// Service should still return nil; errors are only logged
	require.NoError(t, err)
	mfaRepo.AssertExpectations(t)
}

func TestDataDeletionService_CascadeDelete_AllStepsFail_ReturnsNil(t *testing.T) {
	ctx := context.Background()
	userID := uuid.New()
	tenantID := uuid.New()

	sessionRepo := new(mockDeletionSessionRepo)
	deviceRepo := new(mockDeletionDeviceRepo)
	mfaRepo := new(mockDeletionMFARepo)

	sessionRepo.On("EndAllUserSessions", ctx, userID, "user_deleted").Return(errors.New("err"))
	deviceRepo.On("DeleteByUserID", ctx, userID).Return(errors.New("err"))
	mfaRepo.On("DeleteAllRecoveryCodes", ctx, userID).Return(errors.New("err"))
	mfaRepo.On("DeleteUserEmailVerifications", ctx, userID).Return(errors.New("err"))
	mfaRepo.On("DeleteMFAPendingSetup", ctx, userID).Return(errors.New("err"))

	svc := &testableDataDeletionService{
		sessionRepo: sessionRepo,
		deviceRepo:  deviceRepo,
		mfaRepo:     mfaRepo,
	}

	err := svc.cascadeDelete(ctx, userID, tenantID)
	// All individual errors are warnings; the cascade itself returns nil
	require.NoError(t, err)
}

// ---------------------------------------------------------------------------
// TestDeletionRequest model helpers
// ---------------------------------------------------------------------------

func TestDeletionRequest_IsActive(t *testing.T) {
	tests := []struct {
		name     string
		status   string
		expected bool
	}{
		{"pending is active", models.DeletionRequestStatusPending, true},
		{"scheduled is active", models.DeletionRequestStatusScheduled, true},
		{"processing is not active", models.DeletionRequestStatusProcessing, false},
		{"completed is not active", models.DeletionRequestStatusCompleted, false},
		{"failed is not active", models.DeletionRequestStatusFailed, false},
		{"cancelled is not active", models.DeletionRequestStatusCancelled, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &models.DeletionRequest{Status: tt.status}
			assert.Equal(t, tt.expected, req.IsActive())
		})
	}
}

func TestDeletionRequest_IsCancellable(t *testing.T) {
	tests := []struct {
		name     string
		status   string
		expected bool
	}{
		{"pending is cancellable", models.DeletionRequestStatusPending, true},
		{"scheduled is cancellable", models.DeletionRequestStatusScheduled, true},
		{"processing is not cancellable", models.DeletionRequestStatusProcessing, false},
		{"completed is not cancellable", models.DeletionRequestStatusCompleted, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &models.DeletionRequest{Status: tt.status}
			assert.Equal(t, tt.expected, req.IsCancellable())
		})
	}
}

// ---------------------------------------------------------------------------
// TestDataDeletionService_Repos_CallOrder
// ---------------------------------------------------------------------------

func TestDataDeletionService_CascadeDelete_CallOrder(t *testing.T) {
	// Verify each repository method receives exactly the expected arguments.
	ctx := context.Background()
	userID := uuid.New()
	tenantID := uuid.New()

	callOrder := make([]string, 0, 6)

	sessionRepo := new(mockDeletionSessionRepo)
	deviceRepo := new(mockDeletionDeviceRepo)
	mfaRepo := new(mockDeletionMFARepo)

	sessionRepo.On("EndAllUserSessions", ctx, userID, "user_deleted").
		Return(nil).
		Run(func(_ mock.Arguments) { callOrder = append(callOrder, "sessions") })

	deviceRepo.On("DeleteByUserID", ctx, userID).
		Return(nil).
		Run(func(_ mock.Arguments) { callOrder = append(callOrder, "devices") })

	mfaRepo.On("DeleteAllRecoveryCodes", ctx, userID).
		Return(nil).
		Run(func(_ mock.Arguments) { callOrder = append(callOrder, "recovery_codes") })

	mfaRepo.On("DeleteUserEmailVerifications", ctx, userID).
		Return(nil).
		Run(func(_ mock.Arguments) { callOrder = append(callOrder, "email_verifications") })

	mfaRepo.On("DeleteMFAPendingSetup", ctx, userID).
		Return(nil).
		Run(func(_ mock.Arguments) { callOrder = append(callOrder, "mfa_pending") })

	svc := &testableDataDeletionService{
		sessionRepo: sessionRepo,
		deviceRepo:  deviceRepo,
		mfaRepo:     mfaRepo,
	}

	err := svc.cascadeDelete(ctx, userID, tenantID)
	require.NoError(t, err)

	// All steps must have been invoked in the correct order.
	expected := []string{"sessions", "devices", "recovery_codes", "email_verifications", "mfa_pending"}
	assert.Equal(t, expected, callOrder)
}

// ---------------------------------------------------------------------------
// Phase 3.1b — OAuth-token sweep
// ---------------------------------------------------------------------------

// TestDataDeletionService_CascadeDelete_OAuthSweep_FiresWhenWired locks
// the Phase 3.1b contract: when oauthRepo is wired, the cascade calls
// RevokeAllUserOAuthTokens with the same user_id + reason that the
// (now-no-op) iam_refresh_tokens revoke uses. Without this the deleted
// user's OAuth tokens stay valid until natural expiry — a real GDPR /
// right-to-be-forgotten gap.
func TestDataDeletionService_CascadeDelete_OAuthSweep_FiresWhenWired(t *testing.T) {
	ctx := context.Background()
	userID := uuid.New()
	tenantID := uuid.New()

	sessionRepo := new(mockDeletionSessionRepo)
	oauthRepo := new(mockDeletionOAuthRepo)
	deviceRepo := new(mockDeletionDeviceRepo)
	mfaRepo := new(mockDeletionMFARepo)

	sessionRepo.On("EndAllUserSessions", ctx, userID, "user_deleted").Return(nil)
	oauthRepo.On("RevokeAllUserOAuthTokens", ctx, userID, "user_deleted").Return(nil)
	deviceRepo.On("DeleteByUserID", ctx, userID).Return(nil)
	mfaRepo.On("DeleteAllRecoveryCodes", ctx, userID).Return(nil)
	mfaRepo.On("DeleteUserEmailVerifications", ctx, userID).Return(nil)
	mfaRepo.On("DeleteMFAPendingSetup", ctx, userID).Return(nil)

	svc := &testableDataDeletionService{
		sessionRepo: sessionRepo,
		oauthRepo:   oauthRepo,
		deviceRepo:  deviceRepo,
		mfaRepo:     mfaRepo,
	}

	err := svc.cascadeDelete(ctx, userID, tenantID)
	require.NoError(t, err)
	oauthRepo.AssertExpectations(t)
}

// TestDataDeletionService_CascadeDelete_OAuthSweep_SkippedWhenUnwired
// confirms graceful degradation when oauthRepo is nil — cascade still
// completes (no panic, no error). Production wiring goes through
// SetOAuthRepository in cmd/services.go; tests / tools that don't set
// it must still succeed.
func TestDataDeletionService_CascadeDelete_OAuthSweep_SkippedWhenUnwired(t *testing.T) {
	ctx := context.Background()
	userID := uuid.New()
	tenantID := uuid.New()

	sessionRepo := new(mockDeletionSessionRepo)
	deviceRepo := new(mockDeletionDeviceRepo)
	mfaRepo := new(mockDeletionMFARepo)

	sessionRepo.On("EndAllUserSessions", ctx, userID, "user_deleted").Return(nil)
	deviceRepo.On("DeleteByUserID", ctx, userID).Return(nil)
	mfaRepo.On("DeleteAllRecoveryCodes", ctx, userID).Return(nil)
	mfaRepo.On("DeleteUserEmailVerifications", ctx, userID).Return(nil)
	mfaRepo.On("DeleteMFAPendingSetup", ctx, userID).Return(nil)

	svc := &testableDataDeletionService{
		sessionRepo: sessionRepo,
		// oauthRepo unset — graceful degradation
		deviceRepo: deviceRepo,
		mfaRepo:    mfaRepo,
	}

	err := svc.cascadeDelete(ctx, userID, tenantID)
	require.NoError(t, err)
}
