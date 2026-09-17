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
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

// ---------------------------------------------------------------------------
// Mock
// ---------------------------------------------------------------------------

type mockSCPRepo struct {
	mock.Mock
}

func (m *mockSCPRepo) Create(ctx context.Context, scp *models.ServiceControlPolicy) error {
	args := m.Called(ctx, scp)
	return args.Error(0)
}

func (m *mockSCPRepo) GetByID(ctx context.Context, id uuid.UUID) (*models.ServiceControlPolicy, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.ServiceControlPolicy), args.Error(1)
}

func (m *mockSCPRepo) List(ctx context.Context, scope string, page, pageSize int) ([]*models.ServiceControlPolicy, int64, error) {
	args := m.Called(ctx, scope, page, pageSize)
	if args.Get(0) == nil {
		return nil, args.Get(1).(int64), args.Error(2)
	}
	return args.Get(0).([]*models.ServiceControlPolicy), args.Get(1).(int64), args.Error(2)
}

func (m *mockSCPRepo) Update(ctx context.Context, id uuid.UUID, req *models.UpdateSCPRequest) (*models.ServiceControlPolicy, error) {
	args := m.Called(ctx, id, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.ServiceControlPolicy), args.Error(1)
}

func (m *mockSCPRepo) Delete(ctx context.Context, id uuid.UUID) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *mockSCPRepo) SetEnabled(ctx context.Context, id uuid.UUID, enabled bool) error {
	args := m.Called(ctx, id, enabled)
	return args.Error(0)
}

func (m *mockSCPRepo) ListApplicable(ctx context.Context, tenantID, realmID uuid.UUID) ([]*models.ServiceControlPolicy, error) {
	args := m.Called(ctx, tenantID, realmID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.ServiceControlPolicy), args.Error(1)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func newSCPService(t *testing.T) (*SCPService, *mockSCPRepo) {
	t.Helper()
	repo := new(mockSCPRepo)
	svc := NewSCPService(repo, zap.NewNop())
	return svc, repo
}

func makeSCP(scope models.SCPScope, scopeID *uuid.UUID, deniedActions, deniedResources []string) *models.ServiceControlPolicy {
	id := uuid.New()
	return &models.ServiceControlPolicy{
		ID:          id,
		Name:        "test-policy",
		Description: "a test scp",
		Scope:       scope,
		ScopeID:     scopeID,
		PolicyDocument: models.SCPPolicyDocument{
			DeniedActions:   deniedActions,
			DeniedResources: deniedResources,
		},
		Priority:  10,
		IsEnabled: true,
	}
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

func TestSCPService_Create(t *testing.T) {
	svc, repo := newSCPService(t)

	tenantID := uuid.New()
	req := &models.CreateSCPRequest{
		Name:        "block-delete",
		Description: "Prevent delete operations",
		Scope:       models.SCPScopeTenant,
		ScopeID:     &tenantID,
		PolicyDocument: models.SCPPolicyDocument{
			DeniedActions: []string{"iam:DeleteUser"},
		},
		Priority: 50,
	}

	// Simulate the repo populating the ID.
	repo.On("Create", mock.Anything, mock.MatchedBy(func(scp *models.ServiceControlPolicy) bool {
		scp.ID = uuid.New()
		return scp.Name == req.Name &&
			scp.Scope == req.Scope &&
			scp.ScopeID != nil &&
			*scp.ScopeID == tenantID &&
			scp.IsEnabled
	})).Return(nil)

	result, err := svc.Create(context.Background(), req)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, req.Name, result.Name)
	assert.Equal(t, req.Scope, result.Scope)
	assert.Equal(t, req.Priority, result.Priority)
	assert.True(t, result.IsEnabled, "newly created SCP must be enabled by default")
	repo.AssertExpectations(t)
}

func TestSCPService_Create_RequiresScopeID(t *testing.T) {
	tests := []struct {
		name  string
		scope models.SCPScope
	}{
		{"realm scope without scope_id", models.SCPScopeRealm},
		{"tenant scope without scope_id", models.SCPScopeTenant},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			svc, repo := newSCPService(t)

			req := &models.CreateSCPRequest{
				Name:    "bad-policy",
				Scope:   tc.scope,
				ScopeID: nil, // intentionally missing
				PolicyDocument: models.SCPPolicyDocument{
					DeniedActions: []string{"iam:DeleteUser"},
				},
			}

			result, err := svc.Create(context.Background(), req)

			assert.Error(t, err)
			assert.Nil(t, result)
			assert.Contains(t, err.Error(), "scope_id is required")
			// Repo must never be called when validation fails.
			repo.AssertNotCalled(t, "Create")
		})
	}
}

func TestSCPService_Create_PlatformScopeDoesNotRequireScopeID(t *testing.T) {
	svc, repo := newSCPService(t)

	req := &models.CreateSCPRequest{
		Name:    "platform-guardrail",
		Scope:   models.SCPScopePlatform,
		ScopeID: nil, // platform scope — no ID required
		PolicyDocument: models.SCPPolicyDocument{
			DeniedActions: []string{"billing:Delete"},
		},
		Priority: 100,
	}

	repo.On("Create", mock.Anything, mock.MatchedBy(func(scp *models.ServiceControlPolicy) bool {
		scp.ID = uuid.New()
		return scp.Scope == models.SCPScopePlatform && scp.ScopeID == nil
	})).Return(nil)

	result, err := svc.Create(context.Background(), req)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, models.SCPScopePlatform, result.Scope)
	assert.Nil(t, result.ScopeID)
	repo.AssertExpectations(t)
}

func TestSCPService_EvaluateSCPs_DenyOverridesAllow(t *testing.T) {
	svc, repo := newSCPService(t)

	tenantID := uuid.New()
	realmID := uuid.New()

	policy := makeSCP(models.SCPScopeTenant, &tenantID, []string{"iam:DeleteUser"}, nil)

	repo.On("ListApplicable", mock.Anything, tenantID, realmID).
		Return([]*models.ServiceControlPolicy{policy}, nil)

	denied, reason, err := svc.EvaluateSCPs(context.Background(), tenantID, realmID, "iam:DeleteUser", "iam:users:abc")

	require.NoError(t, err)
	assert.True(t, denied, "action in denied_actions must be denied")
	assert.Contains(t, reason, "test-policy")
	repo.AssertExpectations(t)
}

func TestSCPService_EvaluateSCPs_AllowedWhenNoMatch(t *testing.T) {
	svc, repo := newSCPService(t)

	tenantID := uuid.New()
	realmID := uuid.New()

	// Policy denies a different action — queried action should pass.
	policy := makeSCP(models.SCPScopeTenant, &tenantID, []string{"iam:DeleteUser"}, nil)

	repo.On("ListApplicable", mock.Anything, tenantID, realmID).
		Return([]*models.ServiceControlPolicy{policy}, nil)

	denied, reason, err := svc.EvaluateSCPs(context.Background(), tenantID, realmID, "iam:CreateUser", "iam:users:abc")

	require.NoError(t, err)
	assert.False(t, denied, "action not in denied_actions must not be denied")
	assert.Empty(t, reason)
	repo.AssertExpectations(t)
}

func TestSCPService_EvaluateSCPs_WildcardDeniesAll(t *testing.T) {
	svc, repo := newSCPService(t)

	tenantID := uuid.New()
	realmID := uuid.New()

	// "*" in denied_actions means deny every action.
	policy := makeSCP(models.SCPScopePlatform, nil, []string{"*"}, nil)

	repo.On("ListApplicable", mock.Anything, tenantID, realmID).
		Return([]*models.ServiceControlPolicy{policy}, nil)

	for _, action := range []string{"iam:Read", "billing:Write", "crm:Delete"} {
		t.Run(action, func(t *testing.T) {
			denied, reason, err := svc.EvaluateSCPs(context.Background(), tenantID, realmID, action, "any:resource")

			require.NoError(t, err)
			assert.True(t, denied, "wildcard SCP must deny any action")
			assert.NotEmpty(t, reason)
		})
	}

	repo.AssertExpectations(t)
}

func TestSCPService_EvaluateSCPs_PlatformSCPApplies(t *testing.T) {
	svc, repo := newSCPService(t)

	tenantID := uuid.New()
	realmID := uuid.New()

	// Platform-scoped SCP has no ScopeID and applies globally.
	policy := makeSCP(models.SCPScopePlatform, nil, []string{"billing:Delete"}, nil)

	repo.On("ListApplicable", mock.Anything, tenantID, realmID).
		Return([]*models.ServiceControlPolicy{policy}, nil)

	denied, reason, err := svc.EvaluateSCPs(context.Background(), tenantID, realmID, "billing:Delete", "billing:invoices:123")

	require.NoError(t, err)
	assert.True(t, denied, "platform SCP must apply to all tenants")
	assert.Contains(t, reason, "test-policy")
	repo.AssertExpectations(t)
}

func TestSCPService_EvaluateSCPs_ResourceDeny(t *testing.T) {
	svc, repo := newSCPService(t)

	tenantID := uuid.New()
	realmID := uuid.New()

	// Policy has no denied actions but denies a specific resource.
	policy := makeSCP(models.SCPScopeTenant, &tenantID, nil, []string{"iam:users:protected"})

	repo.On("ListApplicable", mock.Anything, tenantID, realmID).
		Return([]*models.ServiceControlPolicy{policy}, nil)

	denied, reason, err := svc.EvaluateSCPs(context.Background(), tenantID, realmID, "iam:Read", "iam:users:protected")

	require.NoError(t, err)
	assert.True(t, denied, "resource in denied_resources must be denied")
	assert.Contains(t, reason, "iam:users:protected")
	repo.AssertExpectations(t)
}

func TestSCPService_EvaluateSCPs_ResourceDeny_WildcardResource(t *testing.T) {
	svc, repo := newSCPService(t)

	tenantID := uuid.New()
	realmID := uuid.New()

	// "*" in denied_resources blocks all resources.
	policy := makeSCP(models.SCPScopePlatform, nil, nil, []string{"*"})

	repo.On("ListApplicable", mock.Anything, tenantID, realmID).
		Return([]*models.ServiceControlPolicy{policy}, nil)

	denied, reason, err := svc.EvaluateSCPs(context.Background(), tenantID, realmID, "iam:Read", "any:resource:whatsoever")

	require.NoError(t, err)
	assert.True(t, denied, "wildcard resource SCP must block any resource")
	assert.NotEmpty(t, reason)
	repo.AssertExpectations(t)
}

func TestSCPService_EvaluateSCPs_RepoError(t *testing.T) {
	svc, repo := newSCPService(t)

	tenantID := uuid.New()
	realmID := uuid.New()
	repoErr := errors.New("database unavailable")

	repo.On("ListApplicable", mock.Anything, tenantID, realmID).
		Return(nil, repoErr)

	denied, reason, err := svc.EvaluateSCPs(context.Background(), tenantID, realmID, "iam:Read", "anything")

	require.Error(t, err)
	assert.False(t, denied)
	assert.Empty(t, reason)
	assert.ErrorIs(t, err, repoErr)
	repo.AssertExpectations(t)
}

func TestSCPService_EvaluateSCPs_DisabledPolicyIgnored(t *testing.T) {
	svc, repo := newSCPService(t)

	tenantID := uuid.New()
	realmID := uuid.New()

	policy := makeSCP(models.SCPScopeTenant, &tenantID, []string{"iam:DeleteUser"}, nil)
	policy.IsEnabled = false // explicitly disabled

	repo.On("ListApplicable", mock.Anything, tenantID, realmID).
		Return([]*models.ServiceControlPolicy{policy}, nil)

	denied, reason, err := svc.EvaluateSCPs(context.Background(), tenantID, realmID, "iam:DeleteUser", "resource")

	require.NoError(t, err)
	assert.False(t, denied, "disabled SCP must not block the action")
	assert.Empty(t, reason)
	repo.AssertExpectations(t)
}
