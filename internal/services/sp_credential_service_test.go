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
)

// ---------------------------------------------------------------------------
// Mock: mockSPCredentialRepo
// ---------------------------------------------------------------------------

type mockSPCredentialRepo struct {
	mock.Mock
}

func (m *mockSPCredentialRepo) Create(ctx context.Context, cred *models.SPCredential) error {
	args := m.Called(ctx, cred)
	return args.Error(0)
}

func (m *mockSPCredentialRepo) GetByID(ctx context.Context, id uuid.UUID) (*models.SPCredential, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.SPCredential), args.Error(1)
}

func (m *mockSPCredentialRepo) ListBySP(ctx context.Context, spID uuid.UUID) ([]models.SPCredential, error) {
	args := m.Called(ctx, spID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]models.SPCredential), args.Error(1)
}

func (m *mockSPCredentialRepo) Revoke(ctx context.Context, id uuid.UUID) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *mockSPCredentialRepo) CleanupExpired(ctx context.Context) (int64, error) {
	args := m.Called(ctx)
	return args.Get(0).(int64), args.Error(1)
}

func (m *mockSPCredentialRepo) DeleteBySP(ctx context.Context, spID uuid.UUID) error {
	args := m.Called(ctx, spID)
	return args.Error(0)
}

func (m *mockSPCredentialRepo) ListExpiringSoon(ctx context.Context, withinDays int) ([]models.SPCredential, error) {
	args := m.Called(ctx, withinDays)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]models.SPCredential), args.Error(1)
}

func (m *mockSPCredentialRepo) RecordUsage(ctx context.Context, credID uuid.UUID) error {
	args := m.Called(ctx, credID)
	return args.Error(0)
}

func (m *mockSPCredentialRepo) ListUnused(ctx context.Context, unusedDays int) ([]models.SPCredential, error) {
	args := m.Called(ctx, unusedDays)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]models.SPCredential), args.Error(1)
}

// ---------------------------------------------------------------------------
// Tests: AddRSAKeyCredential
// ---------------------------------------------------------------------------

func TestSPCredentialService_AddRSAKeyCredential_Success(t *testing.T) {
	ctx := context.Background()
	repo := new(mockSPCredentialRepo)
	svc := NewSPCredentialService(repo)

	spID := uuid.New()
	repo.On("Create", ctx, mock.AnythingOfType("*models.SPCredential")).Return(nil)

	cred, privKey, err := svc.AddRSAKeyCredential(ctx, spID, nil)

	require.NoError(t, err)
	require.NotNil(t, cred)
	assert.NotEmpty(t, privKey)
	assert.Equal(t, spID, cred.SPID)
	assert.Equal(t, models.SPCredentialTypeRSAKey, cred.CredentialType)
	assert.Equal(t, models.SPCredentialStatusActive, cred.Status)
	assert.NotNil(t, cred.KeyID)
	assert.NotNil(t, cred.PublicKeyPEM)
	assert.Contains(t, privKey, "RSA PRIVATE KEY")
	assert.Contains(t, *cred.PublicKeyPEM, "PUBLIC KEY")

	repo.AssertExpectations(t)
}

func TestSPCredentialService_AddRSAKeyCredential_WithExpiry(t *testing.T) {
	ctx := context.Background()
	repo := new(mockSPCredentialRepo)
	svc := NewSPCredentialService(repo)

	spID := uuid.New()
	expiry := time.Now().Add(24 * time.Hour)
	repo.On("Create", ctx, mock.AnythingOfType("*models.SPCredential")).Return(nil)

	cred, _, err := svc.AddRSAKeyCredential(ctx, spID, &expiry)

	require.NoError(t, err)
	require.NotNil(t, cred)
	require.NotNil(t, cred.ExpiresAt)
	assert.Equal(t, expiry, *cred.ExpiresAt)

	repo.AssertExpectations(t)
}

func TestSPCredentialService_AddRSAKeyCredential_RepoError(t *testing.T) {
	ctx := context.Background()
	repo := new(mockSPCredentialRepo)
	svc := NewSPCredentialService(repo)

	spID := uuid.New()
	repo.On("Create", ctx, mock.AnythingOfType("*models.SPCredential")).
		Return(errors.New("db error"))

	cred, privKey, err := svc.AddRSAKeyCredential(ctx, spID, nil)

	assert.Error(t, err)
	assert.Nil(t, cred)
	assert.Empty(t, privKey)
	assert.Contains(t, err.Error(), "SPCredentialService.AddRSAKeyCredential")

	repo.AssertExpectations(t)
}

// ---------------------------------------------------------------------------
// Tests: AddSecretCredential
// ---------------------------------------------------------------------------

func TestSPCredentialService_AddSecretCredential_Success(t *testing.T) {
	ctx := context.Background()
	repo := new(mockSPCredentialRepo)
	svc := NewSPCredentialService(repo)

	spID := uuid.New()
	repo.On("Create", ctx, mock.AnythingOfType("*models.SPCredential")).Return(nil)

	cred, plainSecret, err := svc.AddSecretCredential(ctx, spID, nil)

	require.NoError(t, err)
	require.NotNil(t, cred)
	assert.NotEmpty(t, plainSecret)
	assert.Len(t, plainSecret, 64) // 32 bytes = 64 hex chars
	assert.Equal(t, spID, cred.SPID)
	assert.Equal(t, models.SPCredentialTypeClientSecret, cred.CredentialType)
	assert.Equal(t, models.SPCredentialStatusActive, cred.Status)
	assert.NotNil(t, cred.SecretHash)
	assert.NotNil(t, cred.DisplayHint)
	assert.Len(t, *cred.DisplayHint, 4) // last 4 chars

	repo.AssertExpectations(t)
}

func TestSPCredentialService_AddSecretCredential_RepoError(t *testing.T) {
	ctx := context.Background()
	repo := new(mockSPCredentialRepo)
	svc := NewSPCredentialService(repo)

	spID := uuid.New()
	repo.On("Create", ctx, mock.AnythingOfType("*models.SPCredential")).
		Return(errors.New("db error"))

	cred, secret, err := svc.AddSecretCredential(ctx, spID, nil)

	assert.Error(t, err)
	assert.Nil(t, cred)
	assert.Empty(t, secret)

	repo.AssertExpectations(t)
}

// ---------------------------------------------------------------------------
// Tests: RevokeCredential
// ---------------------------------------------------------------------------

func TestSPCredentialService_RevokeCredential_Success(t *testing.T) {
	ctx := context.Background()
	repo := new(mockSPCredentialRepo)
	svc := NewSPCredentialService(repo)

	credID := uuid.New()
	cred := &models.SPCredential{
		ID:     credID,
		Status: models.SPCredentialStatusActive,
	}

	repo.On("GetByID", ctx, credID).Return(cred, nil)
	repo.On("Revoke", ctx, credID).Return(nil)

	err := svc.RevokeCredential(ctx, credID)

	require.NoError(t, err)
	repo.AssertExpectations(t)
}

func TestSPCredentialService_RevokeCredential_AlreadyRevoked(t *testing.T) {
	ctx := context.Background()
	repo := new(mockSPCredentialRepo)
	svc := NewSPCredentialService(repo)

	credID := uuid.New()
	cred := &models.SPCredential{
		ID:     credID,
		Status: models.SPCredentialStatusRevoked,
	}

	repo.On("GetByID", ctx, credID).Return(cred, nil)

	err := svc.RevokeCredential(ctx, credID)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "already revoked")
	repo.AssertNotCalled(t, "Revoke")
}

func TestSPCredentialService_RevokeCredential_NotFound(t *testing.T) {
	ctx := context.Background()
	repo := new(mockSPCredentialRepo)
	svc := NewSPCredentialService(repo)

	credID := uuid.New()
	repo.On("GetByID", ctx, credID).Return(nil, errors.New("not found"))

	err := svc.RevokeCredential(ctx, credID)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

// ---------------------------------------------------------------------------
// Tests: ListCredentials
// ---------------------------------------------------------------------------

func TestSPCredentialService_ListCredentials_Success(t *testing.T) {
	ctx := context.Background()
	repo := new(mockSPCredentialRepo)
	svc := NewSPCredentialService(repo)

	spID := uuid.New()
	expected := []models.SPCredential{
		{ID: uuid.New(), SPID: spID, CredentialType: models.SPCredentialTypeRSAKey, Status: models.SPCredentialStatusActive},
		{ID: uuid.New(), SPID: spID, CredentialType: models.SPCredentialTypeClientSecret, Status: models.SPCredentialStatusActive},
	}

	repo.On("ListBySP", ctx, spID).Return(expected, nil)

	creds, err := svc.ListCredentials(ctx, spID)

	require.NoError(t, err)
	assert.Len(t, creds, 2)

	repo.AssertExpectations(t)
}

func TestSPCredentialService_ListCredentials_Empty(t *testing.T) {
	ctx := context.Background()
	repo := new(mockSPCredentialRepo)
	svc := NewSPCredentialService(repo)

	spID := uuid.New()
	repo.On("ListBySP", ctx, spID).Return([]models.SPCredential{}, nil)

	creds, err := svc.ListCredentials(ctx, spID)

	require.NoError(t, err)
	assert.Empty(t, creds)

	repo.AssertExpectations(t)
}

// ---------------------------------------------------------------------------
// Tests: CleanupExpired
// ---------------------------------------------------------------------------

func TestSPCredentialService_CleanupExpired_Success(t *testing.T) {
	ctx := context.Background()
	repo := new(mockSPCredentialRepo)
	svc := NewSPCredentialService(repo)

	repo.On("CleanupExpired", ctx).Return(int64(5), nil)

	count, err := svc.CleanupExpired(ctx)

	require.NoError(t, err)
	assert.Equal(t, int64(5), count)

	repo.AssertExpectations(t)
}

func TestSPCredentialService_CleanupExpired_Zero(t *testing.T) {
	ctx := context.Background()
	repo := new(mockSPCredentialRepo)
	svc := NewSPCredentialService(repo)

	repo.On("CleanupExpired", ctx).Return(int64(0), nil)

	count, err := svc.CleanupExpired(ctx)

	require.NoError(t, err)
	assert.Zero(t, count)

	repo.AssertExpectations(t)
}

// ---------------------------------------------------------------------------
// Tests: DeleteAllForSP
// ---------------------------------------------------------------------------

func TestSPCredentialService_DeleteAllForSP_Success(t *testing.T) {
	ctx := context.Background()
	repo := new(mockSPCredentialRepo)
	svc := NewSPCredentialService(repo)

	spID := uuid.New()
	repo.On("DeleteBySP", ctx, spID).Return(nil)

	err := svc.DeleteAllForSP(ctx, spID)

	require.NoError(t, err)
	repo.AssertExpectations(t)
}

func TestSPCredentialService_DeleteAllForSP_Error(t *testing.T) {
	ctx := context.Background()
	repo := new(mockSPCredentialRepo)
	svc := NewSPCredentialService(repo)

	spID := uuid.New()
	repo.On("DeleteBySP", ctx, spID).Return(errors.New("db error"))

	err := svc.DeleteAllForSP(ctx, spID)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "SPCredentialService.DeleteAllForSP")

	repo.AssertExpectations(t)
}

// ---------------------------------------------------------------------------
// Tests: CheckExpiringCredentials
// ---------------------------------------------------------------------------

func TestCheckExpiringCredentials_Success(t *testing.T) {
	ctx := context.Background()
	repo := new(mockSPCredentialRepo)
	svc := NewSPCredentialService(repo)

	expiresAt := time.Now().Add(15 * 24 * time.Hour)
	expected := []models.SPCredential{
		{
			ID:             uuid.New(),
			SPID:           uuid.New(),
			CredentialType: models.SPCredentialTypeClientSecret,
			Status:         models.SPCredentialStatusActive,
			ExpiresAt:      &expiresAt,
			CreatedAt:      time.Now().Add(-30 * 24 * time.Hour),
		},
		{
			ID:             uuid.New(),
			SPID:           uuid.New(),
			CredentialType: models.SPCredentialTypeRSAKey,
			Status:         models.SPCredentialStatusActive,
			ExpiresAt:      &expiresAt,
			CreatedAt:      time.Now().Add(-60 * 24 * time.Hour),
		},
	}

	repo.On("ListExpiringSoon", ctx, 30).Return(expected, nil)

	creds, err := svc.CheckExpiringCredentials(ctx)

	require.NoError(t, err)
	require.Len(t, creds, 2)
	assert.Equal(t, expected[0].ID, creds[0].ID)
	assert.Equal(t, expected[1].ID, creds[1].ID)
	assert.Equal(t, models.SPCredentialStatusActive, creds[0].Status)
	assert.NotNil(t, creds[0].ExpiresAt)

	repo.AssertExpectations(t)
}

func TestCheckExpiringCredentials_Empty(t *testing.T) {
	ctx := context.Background()
	repo := new(mockSPCredentialRepo)
	svc := NewSPCredentialService(repo)

	repo.On("ListExpiringSoon", ctx, 30).Return([]models.SPCredential{}, nil)

	creds, err := svc.CheckExpiringCredentials(ctx)

	require.NoError(t, err)
	assert.Empty(t, creds)

	repo.AssertExpectations(t)
}

func TestCheckExpiringCredentials_RepoError(t *testing.T) {
	ctx := context.Background()
	repo := new(mockSPCredentialRepo)
	svc := NewSPCredentialService(repo)

	repo.On("ListExpiringSoon", ctx, 30).Return(nil, errors.New("connection refused"))

	creds, err := svc.CheckExpiringCredentials(ctx)

	assert.Error(t, err)
	assert.Nil(t, creds)
	assert.Contains(t, err.Error(), "SPCredentialService.CheckExpiringCredentials")
	assert.Contains(t, err.Error(), "connection refused")

	repo.AssertExpectations(t)
}

// ---------------------------------------------------------------------------
// Tests: RecordUsage
// ---------------------------------------------------------------------------

func TestSPCredentialService_RecordUsage_Success(t *testing.T) {
	ctx := context.Background()
	repo := new(mockSPCredentialRepo)
	svc := NewSPCredentialService(repo)

	credID := uuid.New()
	repo.On("RecordUsage", ctx, credID).Return(nil)

	err := svc.RecordUsage(ctx, credID)

	require.NoError(t, err)
	repo.AssertExpectations(t)
}

func TestSPCredentialService_RecordUsage_RepoError(t *testing.T) {
	ctx := context.Background()
	repo := new(mockSPCredentialRepo)
	svc := NewSPCredentialService(repo)

	credID := uuid.New()
	repo.On("RecordUsage", ctx, credID).Return(errors.New("db error"))

	err := svc.RecordUsage(ctx, credID)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "SPCredentialService.RecordUsage")
	assert.Contains(t, err.Error(), "db error")
	repo.AssertExpectations(t)
}

// ---------------------------------------------------------------------------
// Tests: ListUnusedCredentials
// ---------------------------------------------------------------------------

func TestListUnusedCredentials_Success(t *testing.T) {
	ctx := context.Background()
	repo := new(mockSPCredentialRepo)
	svc := NewSPCredentialService(repo)

	expected := []models.SPCredential{
		{ID: uuid.New(), SPID: uuid.New(), CredentialType: models.SPCredentialTypeClientSecret, Status: models.SPCredentialStatusActive},
		{ID: uuid.New(), SPID: uuid.New(), CredentialType: models.SPCredentialTypeRSAKey, Status: models.SPCredentialStatusActive},
	}

	repo.On("ListUnused", ctx, 90).Return(expected, nil)

	creds, err := svc.ListUnusedCredentials(ctx, 90)

	require.NoError(t, err)
	require.Len(t, creds, 2)
	assert.Equal(t, expected[0].ID, creds[0].ID)
	assert.Equal(t, expected[1].ID, creds[1].ID)
	repo.AssertExpectations(t)
}

func TestListUnusedCredentials_Empty(t *testing.T) {
	ctx := context.Background()
	repo := new(mockSPCredentialRepo)
	svc := NewSPCredentialService(repo)

	repo.On("ListUnused", ctx, 30).Return([]models.SPCredential{}, nil)

	creds, err := svc.ListUnusedCredentials(ctx, 30)

	require.NoError(t, err)
	assert.Empty(t, creds)
	repo.AssertExpectations(t)
}

func TestListUnusedCredentials_RepoError(t *testing.T) {
	ctx := context.Background()
	repo := new(mockSPCredentialRepo)
	svc := NewSPCredentialService(repo)

	repo.On("ListUnused", ctx, 90).Return(nil, errors.New("timeout"))

	creds, err := svc.ListUnusedCredentials(ctx, 90)

	assert.Error(t, err)
	assert.Nil(t, creds)
	assert.Contains(t, err.Error(), "SPCredentialService.ListUnusedCredentials")
	assert.Contains(t, err.Error(), "timeout")
	repo.AssertExpectations(t)
}

// ---------------------------------------------------------------------------
// Tests: AnalyzeCredentialUsage
// ---------------------------------------------------------------------------

func TestAnalyzeCredentialUsage(t *testing.T) {
	now := time.Now()
	ago35d := now.Add(-35 * 24 * time.Hour)
	ago95d := now.Add(-95 * 24 * time.Hour)

	// all active (returned by ListUnused with 0 days): 4 creds
	// 2 never used (LastUsedAt == nil), 1 used 35d ago, 1 used 95d ago
	allActive := []models.SPCredential{
		{ID: uuid.New(), Status: models.SPCredentialStatusActive, LastUsedAt: nil},
		{ID: uuid.New(), Status: models.SPCredentialStatusActive, LastUsedAt: nil},
		{ID: uuid.New(), Status: models.SPCredentialStatusActive, LastUsedAt: &ago35d},
		{ID: uuid.New(), Status: models.SPCredentialStatusActive, LastUsedAt: &ago95d},
	}

	// unused >30d: the 35d and 95d ones + the 2 nil ones = 4 total
	// but the service calls ListUnused(30) which returns creds with last_used_at < 30d ago or NULL
	unused30 := []models.SPCredential{
		allActive[0], // never used
		allActive[1], // never used
		allActive[2], // 35d ago > 30d threshold
		allActive[3], // 95d ago > 30d threshold
	}

	// unused >90d: only the 95d one + the 2 nil ones = 3 total
	unused90 := []models.SPCredential{
		allActive[0], // never used
		allActive[1], // never used
		allActive[3], // 95d ago > 90d threshold
	}

	ctx := context.Background()
	repo := new(mockSPCredentialRepo)
	svc := NewSPCredentialService(repo)

	repo.On("ListUnused", ctx, 0).Return(allActive, nil)
	repo.On("ListUnused", ctx, 30).Return(unused30, nil)
	repo.On("ListUnused", ctx, 90).Return(unused90, nil)

	summary, err := svc.AnalyzeCredentialUsage(ctx)

	require.NoError(t, err)
	require.NotNil(t, summary)
	assert.Equal(t, 4, summary.TotalActive)
	assert.Equal(t, 4, summary.UnusedOver30)
	assert.Equal(t, 3, summary.UnusedOver90)
	assert.Equal(t, 2, summary.NeverUsed)
	repo.AssertExpectations(t)
}

func TestAnalyzeCredentialUsage_RepoError(t *testing.T) {
	ctx := context.Background()
	repo := new(mockSPCredentialRepo)
	svc := NewSPCredentialService(repo)

	repo.On("ListUnused", ctx, 0).Return(nil, errors.New("db down"))

	summary, err := svc.AnalyzeCredentialUsage(ctx)

	assert.Error(t, err)
	assert.Nil(t, summary)
	assert.Contains(t, err.Error(), "SPCredentialService.AnalyzeCredentialUsage")
	repo.AssertExpectations(t)
}
