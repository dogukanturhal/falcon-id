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

// ==================== Mock ====================

// mockRegistrationPolicyRepo is a testify/mock implementation of registrationPolicyRepo.
type mockRegistrationPolicyRepo struct {
	mock.Mock
}

func (m *mockRegistrationPolicyRepo) Create(ctx context.Context, p *models.RegistrationPolicy) error {
	args := m.Called(ctx, p)
	return args.Error(0)
}

func (m *mockRegistrationPolicyRepo) GetByID(ctx context.Context, id uuid.UUID) (*models.RegistrationPolicy, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.RegistrationPolicy), args.Error(1)
}

func (m *mockRegistrationPolicyRepo) GetDefault(ctx context.Context) (*models.RegistrationPolicy, error) {
	args := m.Called(ctx)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.RegistrationPolicy), args.Error(1)
}

func (m *mockRegistrationPolicyRepo) Update(ctx context.Context, p *models.RegistrationPolicy) error {
	args := m.Called(ctx, p)
	return args.Error(0)
}

func (m *mockRegistrationPolicyRepo) Delete(ctx context.Context, id uuid.UUID) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *mockRegistrationPolicyRepo) List(ctx context.Context) ([]models.RegistrationPolicy, error) {
	args := m.Called(ctx)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]models.RegistrationPolicy), args.Error(1)
}

func (m *mockRegistrationPolicyRepo) CountByTenantID(ctx context.Context, tenantID uuid.UUID) (int, error) {
	args := m.Called(ctx, tenantID)
	return args.Int(0), args.Error(1)
}

// ==================== Helpers ====================

func newTestRegistrationPolicyService(repo *mockRegistrationPolicyRepo) *RegistrationPolicyService {
	return NewRegistrationPolicyService(repo)
}

func samplePolicy(opts ...func(*models.RegistrationPolicy)) *models.RegistrationPolicy {
	p := &models.RegistrationPolicy{
		ID:                      uuid.New(),
		Name:                    "Default Policy",
		RequireApproval:         false,
		AllowedRedirectPatterns: []string{"https://*.example.com/*"},
		MaxAppsPerTenant:        50,
		AllowedGrantTypes:       []string{"authorization_code", "client_credentials"},
		IsDefault:               true,
		CreatedAt:               time.Now(),
		UpdatedAt:               time.Now(),
	}
	for _, opt := range opts {
		opt(p)
	}
	return p
}

// ==================== Create ====================

func TestRegistrationPolicyService_Create_Success(t *testing.T) {
	repo := new(mockRegistrationPolicyRepo)
	svc := newTestRegistrationPolicyService(repo)
	ctx := context.Background()

	req := &models.CreateRegistrationPolicyRequest{
		Name:              "Strict Policy",
		AllowedGrantTypes: []string{"authorization_code"},
	}

	repo.On("Create", ctx, mock.AnythingOfType("*models.RegistrationPolicy")).
		Return(nil).
		Run(func(args mock.Arguments) {
			p := args.Get(1).(*models.RegistrationPolicy)
			p.CreatedAt = time.Now()
			p.UpdatedAt = time.Now()
		})

	policy, err := svc.Create(ctx, req)

	require.NoError(t, err)
	assert.Equal(t, "Strict Policy", policy.Name)
	assert.Equal(t, []string{"authorization_code"}, policy.AllowedGrantTypes)
	assert.False(t, policy.RequireApproval)
	assert.Equal(t, defaultMaxAppsPerTenant, policy.MaxAppsPerTenant)
	repo.AssertExpectations(t)
}

func TestRegistrationPolicyService_Create_AppliesDefaults(t *testing.T) {
	repo := new(mockRegistrationPolicyRepo)
	svc := newTestRegistrationPolicyService(repo)
	ctx := context.Background()

	req := &models.CreateRegistrationPolicyRequest{Name: "Minimal"}

	repo.On("Create", ctx, mock.AnythingOfType("*models.RegistrationPolicy")).Return(nil)

	policy, err := svc.Create(ctx, req)

	require.NoError(t, err)
	assert.Equal(t, defaultAllowedGrantTypes, policy.AllowedGrantTypes)
	assert.Equal(t, defaultMaxAppsPerTenant, policy.MaxAppsPerTenant)
	assert.False(t, policy.IsDefault)
	repo.AssertExpectations(t)
}

func TestRegistrationPolicyService_Create_RepoError(t *testing.T) {
	repo := new(mockRegistrationPolicyRepo)
	svc := newTestRegistrationPolicyService(repo)
	ctx := context.Background()

	req := &models.CreateRegistrationPolicyRequest{Name: "Bad"}
	repo.On("Create", ctx, mock.AnythingOfType("*models.RegistrationPolicy")).
		Return(errors.New("db error"))

	_, err := svc.Create(ctx, req)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "RegistrationPolicyService.Create")
	repo.AssertExpectations(t)
}

// ==================== GetDefault ====================

func TestRegistrationPolicyService_GetDefault_Success(t *testing.T) {
	repo := new(mockRegistrationPolicyRepo)
	svc := newTestRegistrationPolicyService(repo)
	ctx := context.Background()

	expected := samplePolicy()
	repo.On("GetDefault", ctx).Return(expected, nil)

	policy, err := svc.GetDefault(ctx)

	require.NoError(t, err)
	assert.Equal(t, expected.ID, policy.ID)
	assert.True(t, policy.IsDefault)
	repo.AssertExpectations(t)
}

func TestRegistrationPolicyService_GetDefault_NotFound(t *testing.T) {
	repo := new(mockRegistrationPolicyRepo)
	svc := newTestRegistrationPolicyService(repo)
	ctx := context.Background()

	repo.On("GetDefault", ctx).Return(nil, errors.New("no rows in result set"))

	_, err := svc.GetDefault(ctx)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "RegistrationPolicyService.GetDefault")
	repo.AssertExpectations(t)
}

// ==================== Delete ====================

func TestRegistrationPolicyService_Delete_DefaultPolicy_Rejected(t *testing.T) {
	repo := new(mockRegistrationPolicyRepo)
	svc := newTestRegistrationPolicyService(repo)
	ctx := context.Background()

	defaultPolicy := samplePolicy(func(p *models.RegistrationPolicy) {
		p.IsDefault = true
	})

	repo.On("GetByID", ctx, defaultPolicy.ID).Return(defaultPolicy, nil)

	err := svc.Delete(ctx, defaultPolicy.ID)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "cannot delete the default registration policy")
	// Delete on the repo must NOT be called.
	repo.AssertNotCalled(t, "Delete", mock.Anything, mock.Anything)
	repo.AssertExpectations(t)
}

func TestRegistrationPolicyService_Delete_NonDefaultPolicy_Success(t *testing.T) {
	repo := new(mockRegistrationPolicyRepo)
	svc := newTestRegistrationPolicyService(repo)
	ctx := context.Background()

	nonDefault := samplePolicy(func(p *models.RegistrationPolicy) {
		p.IsDefault = false
		p.Name = "Non-Default"
	})

	repo.On("GetByID", ctx, nonDefault.ID).Return(nonDefault, nil)
	repo.On("Delete", ctx, nonDefault.ID).Return(nil)

	err := svc.Delete(ctx, nonDefault.ID)

	require.NoError(t, err)
	repo.AssertExpectations(t)
}

func TestRegistrationPolicyService_Delete_NotFound(t *testing.T) {
	repo := new(mockRegistrationPolicyRepo)
	svc := newTestRegistrationPolicyService(repo)
	ctx := context.Background()

	id := uuid.New()
	repo.On("GetByID", ctx, id).Return(nil, errors.New("no rows in result set"))

	err := svc.Delete(ctx, id)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "registration policy not found")
	repo.AssertExpectations(t)
}

// ==================== ValidateRegistration ====================

func TestRegistrationPolicyService_ValidateRegistration_RedirectURIAllowed(t *testing.T) {
	repo := new(mockRegistrationPolicyRepo)
	svc := newTestRegistrationPolicyService(repo)
	ctx := context.Background()

	tenantID := uuid.New()
	policy := samplePolicy(func(p *models.RegistrationPolicy) {
		p.AllowedRedirectPatterns = []string{"https://app.example.com/*"}
		p.AllowedGrantTypes = []string{"authorization_code"}
		p.MaxAppsPerTenant = 10
	})

	repo.On("GetDefault", ctx).Return(policy, nil)
	repo.On("CountByTenantID", ctx, tenantID).Return(3, nil)

	req := &models.AppRegistrationValidationRequest{
		TenantID:     tenantID,
		RedirectURIs: []string{"https://app.example.com/callback"},
		GrantTypes:   []string{"authorization_code"},
	}

	err := svc.ValidateRegistration(ctx, req)

	require.NoError(t, err)
	repo.AssertExpectations(t)
}

func TestRegistrationPolicyService_ValidateRegistration_RedirectURIBlocked(t *testing.T) {
	repo := new(mockRegistrationPolicyRepo)
	svc := newTestRegistrationPolicyService(repo)
	ctx := context.Background()

	tenantID := uuid.New()
	policy := samplePolicy(func(p *models.RegistrationPolicy) {
		p.AllowedRedirectPatterns = []string{"https://app.example.com/*"}
		p.AllowedGrantTypes = []string{"authorization_code"}
		p.MaxAppsPerTenant = 10
	})

	repo.On("GetDefault", ctx).Return(policy, nil)

	req := &models.AppRegistrationValidationRequest{
		TenantID:     tenantID,
		RedirectURIs: []string{"https://evil.attacker.com/steal"},
		GrantTypes:   []string{"authorization_code"},
	}

	err := svc.ValidateRegistration(ctx, req)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "does not match any allowed pattern")
	repo.AssertExpectations(t)
}

func TestRegistrationPolicyService_ValidateRegistration_GrantTypeBlocked(t *testing.T) {
	repo := new(mockRegistrationPolicyRepo)
	svc := newTestRegistrationPolicyService(repo)
	ctx := context.Background()

	tenantID := uuid.New()
	policy := samplePolicy(func(p *models.RegistrationPolicy) {
		p.AllowedRedirectPatterns = []string{} // unrestricted
		p.AllowedGrantTypes = []string{"authorization_code"}
		p.MaxAppsPerTenant = 10
	})

	repo.On("GetDefault", ctx).Return(policy, nil)

	req := &models.AppRegistrationValidationRequest{
		TenantID:     tenantID,
		RedirectURIs: []string{"https://app.example.com/callback"},
		GrantTypes:   []string{"implicit"}, // not in allowed list
	}

	err := svc.ValidateRegistration(ctx, req)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "grant type")
	assert.Contains(t, err.Error(), "not allowed")
	repo.AssertExpectations(t)
}

func TestRegistrationPolicyService_ValidateRegistration_MaxAppsExceeded(t *testing.T) {
	repo := new(mockRegistrationPolicyRepo)
	svc := newTestRegistrationPolicyService(repo)
	ctx := context.Background()

	tenantID := uuid.New()
	policy := samplePolicy(func(p *models.RegistrationPolicy) {
		p.AllowedRedirectPatterns = []string{} // unrestricted
		p.AllowedGrantTypes = []string{"authorization_code"}
		p.MaxAppsPerTenant = 2
	})

	repo.On("GetDefault", ctx).Return(policy, nil)
	repo.On("CountByTenantID", ctx, tenantID).Return(2, nil) // already at limit

	req := &models.AppRegistrationValidationRequest{
		TenantID:     tenantID,
		RedirectURIs: []string{"https://app.example.com/cb"},
		GrantTypes:   []string{"authorization_code"},
	}

	err := svc.ValidateRegistration(ctx, req)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "maximum number of app registrations")
	repo.AssertExpectations(t)
}

func TestRegistrationPolicyService_ValidateRegistration_NoPolicyAllowsAll(t *testing.T) {
	repo := new(mockRegistrationPolicyRepo)
	svc := newTestRegistrationPolicyService(repo)
	ctx := context.Background()

	// No default policy configured — validation must pass.
	repo.On("GetDefault", ctx).Return(nil, errors.New("no rows in result set"))

	req := &models.AppRegistrationValidationRequest{
		TenantID:     uuid.New(),
		RedirectURIs: []string{"https://anywhere.com/callback"},
		GrantTypes:   []string{"implicit"},
	}

	err := svc.ValidateRegistration(ctx, req)

	require.NoError(t, err)
	repo.AssertExpectations(t)
}

// ==================== List ====================

func TestRegistrationPolicyService_List_Success(t *testing.T) {
	repo := new(mockRegistrationPolicyRepo)
	svc := newTestRegistrationPolicyService(repo)
	ctx := context.Background()

	policies := []models.RegistrationPolicy{
		*samplePolicy(func(p *models.RegistrationPolicy) { p.Name = "Policy A" }),
		*samplePolicy(func(p *models.RegistrationPolicy) { p.Name = "Policy B"; p.IsDefault = false }),
	}
	repo.On("List", ctx).Return(policies, nil)

	result, err := svc.List(ctx)

	require.NoError(t, err)
	assert.Len(t, result, 2)
	assert.Equal(t, "Policy A", result[0].Name)
	assert.Equal(t, "Policy B", result[1].Name)
	repo.AssertExpectations(t)
}

func TestRegistrationPolicyService_List_RepoError(t *testing.T) {
	repo := new(mockRegistrationPolicyRepo)
	svc := newTestRegistrationPolicyService(repo)
	ctx := context.Background()

	repo.On("List", ctx).Return(nil, errors.New("db error"))

	_, err := svc.List(ctx)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "RegistrationPolicyService.List")
	repo.AssertExpectations(t)
}

// ==================== matchesAnyPattern (unit) ====================

func TestMatchesAnyPattern(t *testing.T) {
	tests := []struct {
		name     string
		s        string
		patterns []string
		want     bool
	}{
		{
			name:     "empty patterns allows all",
			s:        "https://evil.com/callback",
			patterns: []string{},
			want:     true,
		},
		{
			name:     "exact match",
			s:        "https://app.example.com/callback",
			patterns: []string{"https://app.example.com/callback"},
			want:     true,
		},
		{
			name:     "wildcard suffix match",
			s:        "https://app.example.com/callback",
			patterns: []string{"https://app.example.com/*"},
			want:     true,
		},
		{
			name:     "no match",
			s:        "https://evil.com/steal",
			patterns: []string{"https://app.example.com/*"},
			want:     false,
		},
		{
			name:     "first of multiple patterns matches",
			s:        "https://app.example.com/cb",
			patterns: []string{"https://app.example.com/*", "https://other.com/*"},
			want:     true,
		},
		{
			name:     "second of multiple patterns matches",
			s:        "https://other.com/cb",
			patterns: []string{"https://app.example.com/*", "https://other.com/*"},
			want:     true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := matchesAnyPattern(tc.s, tc.patterns)
			assert.Equal(t, tc.want, got)
		})
	}
}
