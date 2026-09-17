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
// Mock: mockCredentialPolicyRepo
// ---------------------------------------------------------------------------

type mockCredentialPolicyRepo struct {
	mock.Mock
}

func (m *mockCredentialPolicyRepo) GetByScope(ctx context.Context, scopeType models.CredentialPolicyScopeType, scopeID *uuid.UUID) (*models.CredentialPolicy, error) {
	args := m.Called(ctx, scopeType, scopeID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.CredentialPolicy), args.Error(1)
}

func (m *mockCredentialPolicyRepo) GetEffective(ctx context.Context, tenantID uuid.UUID) (*models.CredentialPolicy, error) {
	args := m.Called(ctx, tenantID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.CredentialPolicy), args.Error(1)
}

func (m *mockCredentialPolicyRepo) Upsert(ctx context.Context, policy *models.CredentialPolicy) error {
	args := m.Called(ctx, policy)
	return args.Error(0)
}

func (m *mockCredentialPolicyRepo) Delete(ctx context.Context, id uuid.UUID) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *mockCredentialPolicyRepo) List(ctx context.Context) ([]models.CredentialPolicy, error) {
	args := m.Called(ctx)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]models.CredentialPolicy), args.Error(1)
}

// ---------------------------------------------------------------------------
// Tests: GetPlatformPolicy
// ---------------------------------------------------------------------------

func TestCredentialPolicyService_GetPlatformPolicy_Success(t *testing.T) {
	ctx := context.Background()
	repo := new(mockCredentialPolicyRepo)
	svc := NewCredentialPolicyService(repo)

	expected := &models.CredentialPolicy{
		ID:                    uuid.New(),
		ScopeType:             models.CredentialPolicyScopePlatform,
		MaxSecretLifetimeDays: 365,
		MaxCertLifetimeDays:   730,
	}
	repo.On("GetByScope", ctx, models.CredentialPolicyScopePlatform, (*uuid.UUID)(nil)).Return(expected, nil)

	result, err := svc.GetPlatformPolicy(ctx)

	require.NoError(t, err)
	assert.Equal(t, expected.ID, result.ID)
	repo.AssertExpectations(t)
}

func TestCredentialPolicyService_GetPlatformPolicy_NotFound(t *testing.T) {
	ctx := context.Background()
	repo := new(mockCredentialPolicyRepo)
	svc := NewCredentialPolicyService(repo)

	repo.On("GetByScope", ctx, models.CredentialPolicyScopePlatform, (*uuid.UUID)(nil)).Return(nil, errors.New("not found"))

	result, err := svc.GetPlatformPolicy(ctx)

	assert.Error(t, err)
	assert.Nil(t, result)
	repo.AssertExpectations(t)
}

// ---------------------------------------------------------------------------
// Tests: UpsertPolicy
// ---------------------------------------------------------------------------

func TestCredentialPolicyService_UpsertPolicy_Success(t *testing.T) {
	ctx := context.Background()
	repo := new(mockCredentialPolicyRepo)
	svc := NewCredentialPolicyService(repo)

	maxSecret := 180
	maxCert := 365
	requireExpiry := true
	req := &models.CreateCredentialPolicyRequest{
		ScopeType:             models.CredentialPolicyScopePlatform,
		MaxSecretLifetimeDays: &maxSecret,
		MaxCertLifetimeDays:   &maxCert,
		RequireExpiry:         &requireExpiry,
	}

	repo.On("Upsert", ctx, mock.AnythingOfType("*models.CredentialPolicy")).Return(nil)

	result, err := svc.UpsertPolicy(ctx, req)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, 180, result.MaxSecretLifetimeDays)
	assert.Equal(t, 365, result.MaxCertLifetimeDays)
	assert.True(t, result.RequireExpiry)
	repo.AssertExpectations(t)
}

func TestCredentialPolicyService_UpsertPolicy_Defaults(t *testing.T) {
	ctx := context.Background()
	repo := new(mockCredentialPolicyRepo)
	svc := NewCredentialPolicyService(repo)

	req := &models.CreateCredentialPolicyRequest{
		ScopeType: models.CredentialPolicyScopePlatform,
	}

	repo.On("Upsert", ctx, mock.AnythingOfType("*models.CredentialPolicy")).Return(nil)

	result, err := svc.UpsertPolicy(ctx, req)

	require.NoError(t, err)
	assert.Equal(t, 365, result.MaxSecretLifetimeDays)
	assert.Equal(t, 730, result.MaxCertLifetimeDays)
	assert.False(t, result.RequireExpiry)
	repo.AssertExpectations(t)
}

func TestCredentialPolicyService_UpsertPolicy_RepoError(t *testing.T) {
	ctx := context.Background()
	repo := new(mockCredentialPolicyRepo)
	svc := NewCredentialPolicyService(repo)

	req := &models.CreateCredentialPolicyRequest{
		ScopeType: models.CredentialPolicyScopePlatform,
	}

	repo.On("Upsert", ctx, mock.AnythingOfType("*models.CredentialPolicy")).Return(errors.New("db error"))

	result, err := svc.UpsertPolicy(ctx, req)

	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "CredentialPolicyService.UpsertPolicy")
	repo.AssertExpectations(t)
}

// ---------------------------------------------------------------------------
// Tests: DeletePolicy
// ---------------------------------------------------------------------------

func TestCredentialPolicyService_DeletePolicy_Success(t *testing.T) {
	ctx := context.Background()
	repo := new(mockCredentialPolicyRepo)
	svc := NewCredentialPolicyService(repo)

	id := uuid.New()
	repo.On("Delete", ctx, id).Return(nil)

	err := svc.DeletePolicy(ctx, id)

	require.NoError(t, err)
	repo.AssertExpectations(t)
}

// ---------------------------------------------------------------------------
// Tests: ListPolicies
// ---------------------------------------------------------------------------

func TestCredentialPolicyService_ListPolicies_Success(t *testing.T) {
	ctx := context.Background()
	repo := new(mockCredentialPolicyRepo)
	svc := NewCredentialPolicyService(repo)

	expected := []models.CredentialPolicy{
		{ID: uuid.New(), ScopeType: models.CredentialPolicyScopePlatform},
		{ID: uuid.New(), ScopeType: models.CredentialPolicyScopeTenant},
	}
	repo.On("List", ctx).Return(expected, nil)

	result, err := svc.ListPolicies(ctx)

	require.NoError(t, err)
	assert.Len(t, result, 2)
	repo.AssertExpectations(t)
}

// ---------------------------------------------------------------------------
// Tests: ValidateCredentialExpiry
// ---------------------------------------------------------------------------

func TestValidateCredentialExpiry_SecretWithinPolicy(t *testing.T) {
	ctx := context.Background()
	repo := new(mockCredentialPolicyRepo)
	svc := NewCredentialPolicyService(repo)

	tenantID := uuid.New()
	policy := &models.CredentialPolicy{
		MaxSecretLifetimeDays: 365,
		MaxCertLifetimeDays:   730,
	}
	repo.On("GetEffective", ctx, tenantID).Return(policy, nil)

	expires := time.Now().Add(180 * 24 * time.Hour)
	err := svc.ValidateCredentialExpiry(ctx, tenantID, models.SPCredentialTypeClientSecret, &expires)

	require.NoError(t, err)
	repo.AssertExpectations(t)
}

func TestValidateCredentialExpiry_SecretExceedsPolicy(t *testing.T) {
	ctx := context.Background()
	repo := new(mockCredentialPolicyRepo)
	svc := NewCredentialPolicyService(repo)

	tenantID := uuid.New()
	policy := &models.CredentialPolicy{
		MaxSecretLifetimeDays: 180,
		MaxCertLifetimeDays:   730,
	}
	repo.On("GetEffective", ctx, tenantID).Return(policy, nil)

	expires := time.Now().Add(365 * 24 * time.Hour)
	err := svc.ValidateCredentialExpiry(ctx, tenantID, models.SPCredentialTypeClientSecret, &expires)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "limits client_secret lifetime to 180 days")
	repo.AssertExpectations(t)
}

func TestValidateCredentialExpiry_CertExceedsPolicy(t *testing.T) {
	ctx := context.Background()
	repo := new(mockCredentialPolicyRepo)
	svc := NewCredentialPolicyService(repo)

	tenantID := uuid.New()
	policy := &models.CredentialPolicy{
		MaxSecretLifetimeDays: 365,
		MaxCertLifetimeDays:   365,
	}
	repo.On("GetEffective", ctx, tenantID).Return(policy, nil)

	expires := time.Now().Add(500 * 24 * time.Hour)
	err := svc.ValidateCredentialExpiry(ctx, tenantID, models.SPCredentialTypeRSAKey, &expires)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "limits rsa_key lifetime to 365 days")
	repo.AssertExpectations(t)
}

func TestValidateCredentialExpiry_RequireExpiryNoExpiry(t *testing.T) {
	ctx := context.Background()
	repo := new(mockCredentialPolicyRepo)
	svc := NewCredentialPolicyService(repo)

	tenantID := uuid.New()
	policy := &models.CredentialPolicy{
		MaxSecretLifetimeDays: 365,
		MaxCertLifetimeDays:   730,
		RequireExpiry:         true,
	}
	repo.On("GetEffective", ctx, tenantID).Return(policy, nil)

	err := svc.ValidateCredentialExpiry(ctx, tenantID, models.SPCredentialTypeClientSecret, nil)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "requires an expiration date")
	repo.AssertExpectations(t)
}

func TestValidateCredentialExpiry_NoPolicyAllowsAll(t *testing.T) {
	ctx := context.Background()
	repo := new(mockCredentialPolicyRepo)
	svc := NewCredentialPolicyService(repo)

	tenantID := uuid.New()
	repo.On("GetEffective", ctx, tenantID).Return(nil, errors.New("not found"))

	err := svc.ValidateCredentialExpiry(ctx, tenantID, models.SPCredentialTypeClientSecret, nil)

	require.NoError(t, err)
	repo.AssertExpectations(t)
}

func TestValidateCredentialExpiry_NilExpiryAllowedWhenNotRequired(t *testing.T) {
	ctx := context.Background()
	repo := new(mockCredentialPolicyRepo)
	svc := NewCredentialPolicyService(repo)

	tenantID := uuid.New()
	policy := &models.CredentialPolicy{
		MaxSecretLifetimeDays: 365,
		MaxCertLifetimeDays:   730,
		RequireExpiry:         false,
	}
	repo.On("GetEffective", ctx, tenantID).Return(policy, nil)

	err := svc.ValidateCredentialExpiry(ctx, tenantID, models.SPCredentialTypeClientSecret, nil)

	require.NoError(t, err)
	repo.AssertExpectations(t)
}
