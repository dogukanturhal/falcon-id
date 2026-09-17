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
// Mock: mockAppConsentRepo
// ---------------------------------------------------------------------------

type mockAppConsentRepo struct {
	mock.Mock
}

func (m *mockAppConsentRepo) Upsert(ctx context.Context, consent *models.AppConsent) error {
	args := m.Called(ctx, consent)
	return args.Error(0)
}

func (m *mockAppConsentRepo) Revoke(ctx context.Context, id uuid.UUID) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *mockAppConsentRepo) RevokeByAppAndTenant(ctx context.Context, appID, tenantID uuid.UUID) error {
	args := m.Called(ctx, appID, tenantID)
	return args.Error(0)
}

func (m *mockAppConsentRepo) HasConsent(ctx context.Context, appID, tenantID uuid.UUID) (bool, error) {
	args := m.Called(ctx, appID, tenantID)
	return args.Bool(0), args.Error(1)
}

func (m *mockAppConsentRepo) ListByApp(ctx context.Context, appID uuid.UUID) ([]models.AppConsent, error) {
	args := m.Called(ctx, appID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]models.AppConsent), args.Error(1)
}

func (m *mockAppConsentRepo) ListByTenant(ctx context.Context, tenantID uuid.UUID) ([]models.AppConsent, error) {
	args := m.Called(ctx, tenantID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]models.AppConsent), args.Error(1)
}

// ---------------------------------------------------------------------------
// Tests: GrantAdminConsent
// ---------------------------------------------------------------------------

func TestAppConsentService_GrantAdminConsent_Success(t *testing.T) {
	ctx := context.Background()
	repo := new(mockAppConsentRepo)
	svc := NewAppConsentService(repo)

	appID := uuid.New()
	tenantID := uuid.New()
	userID := uuid.New()
	scopes := []string{"openid", "profile", "email"}

	repo.On("Upsert", ctx, mock.AnythingOfType("*models.AppConsent")).Return(nil)

	consent, err := svc.GrantAdminConsent(ctx, appID, tenantID, userID, scopes)

	require.NoError(t, err)
	require.NotNil(t, consent)
	assert.Equal(t, appID, consent.ApplicationID)
	assert.Equal(t, tenantID, consent.TenantID)
	assert.Equal(t, userID, consent.ConsentedBy)
	assert.Equal(t, models.AppConsentTypeAdmin, consent.ConsentType)
	assert.Equal(t, models.AppConsentStatusGranted, consent.Status)
	assert.Equal(t, scopes, consent.Scopes)
	assert.NotEqual(t, uuid.Nil, consent.ID)

	repo.AssertExpectations(t)
}

func TestAppConsentService_GrantAdminConsent_NilScopes(t *testing.T) {
	ctx := context.Background()
	repo := new(mockAppConsentRepo)
	svc := NewAppConsentService(repo)

	repo.On("Upsert", ctx, mock.AnythingOfType("*models.AppConsent")).Return(nil)

	consent, err := svc.GrantAdminConsent(ctx, uuid.New(), uuid.New(), uuid.New(), nil)

	require.NoError(t, err)
	require.NotNil(t, consent)
	assert.NotNil(t, consent.Scopes)
	assert.Empty(t, consent.Scopes)

	repo.AssertExpectations(t)
}

func TestAppConsentService_GrantAdminConsent_RepoError(t *testing.T) {
	ctx := context.Background()
	repo := new(mockAppConsentRepo)
	svc := NewAppConsentService(repo)

	repo.On("Upsert", ctx, mock.AnythingOfType("*models.AppConsent")).
		Return(errors.New("db error"))

	consent, err := svc.GrantAdminConsent(ctx, uuid.New(), uuid.New(), uuid.New(), nil)

	assert.Error(t, err)
	assert.Nil(t, consent)
	assert.Contains(t, err.Error(), "AppConsentService.GrantAdminConsent")

	repo.AssertExpectations(t)
}

// ---------------------------------------------------------------------------
// Tests: GrantUserConsent
// ---------------------------------------------------------------------------

func TestAppConsentService_GrantUserConsent_Success(t *testing.T) {
	ctx := context.Background()
	repo := new(mockAppConsentRepo)
	svc := NewAppConsentService(repo)

	appID := uuid.New()
	tenantID := uuid.New()
	userID := uuid.New()
	scopes := []string{"read:contacts"}

	repo.On("Upsert", ctx, mock.AnythingOfType("*models.AppConsent")).Return(nil)

	consent, err := svc.GrantUserConsent(ctx, appID, tenantID, userID, scopes)

	require.NoError(t, err)
	require.NotNil(t, consent)
	assert.Equal(t, models.AppConsentTypeUser, consent.ConsentType)
	assert.Equal(t, scopes, consent.Scopes)

	repo.AssertExpectations(t)
}

// ---------------------------------------------------------------------------
// Tests: RevokeConsent
// ---------------------------------------------------------------------------

func TestAppConsentService_RevokeConsent_Success(t *testing.T) {
	ctx := context.Background()
	repo := new(mockAppConsentRepo)
	svc := NewAppConsentService(repo)

	consentID := uuid.New()
	repo.On("Revoke", ctx, consentID).Return(nil)

	err := svc.RevokeConsent(ctx, consentID)

	require.NoError(t, err)
	repo.AssertExpectations(t)
}

func TestAppConsentService_RevokeConsent_Error(t *testing.T) {
	ctx := context.Background()
	repo := new(mockAppConsentRepo)
	svc := NewAppConsentService(repo)

	consentID := uuid.New()
	repo.On("Revoke", ctx, consentID).Return(errors.New("not found"))

	err := svc.RevokeConsent(ctx, consentID)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "AppConsentService.RevokeConsent")

	repo.AssertExpectations(t)
}

// ---------------------------------------------------------------------------
// Tests: RevokeAllForAppInTenant
// ---------------------------------------------------------------------------

func TestAppConsentService_RevokeAllForAppInTenant_Success(t *testing.T) {
	ctx := context.Background()
	repo := new(mockAppConsentRepo)
	svc := NewAppConsentService(repo)

	appID := uuid.New()
	tenantID := uuid.New()
	repo.On("RevokeByAppAndTenant", ctx, appID, tenantID).Return(nil)

	err := svc.RevokeAllForAppInTenant(ctx, appID, tenantID)

	require.NoError(t, err)
	repo.AssertExpectations(t)
}

// ---------------------------------------------------------------------------
// Tests: HasConsent
// ---------------------------------------------------------------------------

func TestAppConsentService_HasConsent_True(t *testing.T) {
	ctx := context.Background()
	repo := new(mockAppConsentRepo)
	svc := NewAppConsentService(repo)

	appID := uuid.New()
	tenantID := uuid.New()
	repo.On("HasConsent", ctx, appID, tenantID).Return(true, nil)

	has, err := svc.HasConsent(ctx, appID, tenantID)

	require.NoError(t, err)
	assert.True(t, has)

	repo.AssertExpectations(t)
}

func TestAppConsentService_HasConsent_False(t *testing.T) {
	ctx := context.Background()
	repo := new(mockAppConsentRepo)
	svc := NewAppConsentService(repo)

	appID := uuid.New()
	tenantID := uuid.New()
	repo.On("HasConsent", ctx, appID, tenantID).Return(false, nil)

	has, err := svc.HasConsent(ctx, appID, tenantID)

	require.NoError(t, err)
	assert.False(t, has)

	repo.AssertExpectations(t)
}

func TestAppConsentService_HasConsent_Error(t *testing.T) {
	ctx := context.Background()
	repo := new(mockAppConsentRepo)
	svc := NewAppConsentService(repo)

	appID := uuid.New()
	tenantID := uuid.New()
	repo.On("HasConsent", ctx, appID, tenantID).Return(false, errors.New("db error"))

	has, err := svc.HasConsent(ctx, appID, tenantID)

	assert.Error(t, err)
	assert.False(t, has)

	repo.AssertExpectations(t)
}

// ---------------------------------------------------------------------------
// Tests: ListByApp
// ---------------------------------------------------------------------------

func TestAppConsentService_ListByApp_Success(t *testing.T) {
	ctx := context.Background()
	repo := new(mockAppConsentRepo)
	svc := NewAppConsentService(repo)

	appID := uuid.New()
	expected := []models.AppConsent{
		{ID: uuid.New(), ApplicationID: appID, ConsentType: models.AppConsentTypeAdmin},
		{ID: uuid.New(), ApplicationID: appID, ConsentType: models.AppConsentTypeUser},
	}

	repo.On("ListByApp", ctx, appID).Return(expected, nil)

	consents, err := svc.ListByApp(ctx, appID)

	require.NoError(t, err)
	assert.Len(t, consents, 2)

	repo.AssertExpectations(t)
}

func TestAppConsentService_ListByApp_Empty(t *testing.T) {
	ctx := context.Background()
	repo := new(mockAppConsentRepo)
	svc := NewAppConsentService(repo)

	appID := uuid.New()
	repo.On("ListByApp", ctx, appID).Return([]models.AppConsent{}, nil)

	consents, err := svc.ListByApp(ctx, appID)

	require.NoError(t, err)
	assert.Empty(t, consents)

	repo.AssertExpectations(t)
}

// ---------------------------------------------------------------------------
// Tests: ListByTenant
// ---------------------------------------------------------------------------

func TestAppConsentService_ListByTenant_Success(t *testing.T) {
	ctx := context.Background()
	repo := new(mockAppConsentRepo)
	svc := NewAppConsentService(repo)

	tenantID := uuid.New()
	expected := []models.AppConsent{
		{ID: uuid.New(), TenantID: tenantID},
	}

	repo.On("ListByTenant", ctx, tenantID).Return(expected, nil)

	consents, err := svc.ListByTenant(ctx, tenantID)

	require.NoError(t, err)
	assert.Len(t, consents, 1)

	repo.AssertExpectations(t)
}
