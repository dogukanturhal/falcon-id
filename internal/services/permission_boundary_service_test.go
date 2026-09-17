// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// ---------------------------------------------------------------------------
// Mock
// ---------------------------------------------------------------------------

type mockPermissionBoundaryRepo struct {
	mock.Mock
}

func (m *mockPermissionBoundaryRepo) Upsert(ctx context.Context, boundary *PermissionBoundary) error {
	args := m.Called(ctx, boundary)
	return args.Error(0)
}

func (m *mockPermissionBoundaryRepo) GetByTarget(ctx context.Context, targetType string, targetID, tenantID uuid.UUID) (*PermissionBoundary, error) {
	args := m.Called(ctx, targetType, targetID, tenantID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*PermissionBoundary), args.Error(1)
}

func (m *mockPermissionBoundaryRepo) Delete(ctx context.Context, targetType string, targetID, tenantID uuid.UUID) error {
	args := m.Called(ctx, targetType, targetID, tenantID)
	return args.Error(0)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func newBoundaryService(t *testing.T) (*PermissionBoundaryService, *mockPermissionBoundaryRepo) {
	t.Helper()
	repo := new(mockPermissionBoundaryRepo)
	svc := NewPermissionBoundaryService(repo, zap.NewNop())
	return svc, repo
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

func TestPermissionBoundary_SetBoundary(t *testing.T) {
	svc, repo := newBoundaryService(t)

	targetID := uuid.New()
	tenantID := uuid.New()
	maxPerms := []string{"iam:users:read", "iam:users:create"}

	repo.On("Upsert", mock.Anything, mock.MatchedBy(func(b *PermissionBoundary) bool {
		return b.TargetType == "user" &&
			b.TargetID == targetID &&
			b.TenantID == tenantID &&
			len(b.MaxPermissions) == 2
	})).Return(nil)

	boundary, err := svc.SetBoundary(context.Background(), "user", targetID, tenantID, maxPerms)

	require.NoError(t, err)
	require.NotNil(t, boundary)
	assert.Equal(t, "user", boundary.TargetType)
	assert.Equal(t, targetID, boundary.TargetID)
	assert.Equal(t, tenantID, boundary.TenantID)
	assert.Equal(t, maxPerms, boundary.MaxPermissions)
	repo.AssertExpectations(t)
}

func TestPermissionBoundary_SetBoundary_AllValidTargetTypes(t *testing.T) {
	validTypes := []string{"user", "role", "service_principal"}

	for _, tt := range validTypes {
		t.Run(tt, func(t *testing.T) {
			svc, repo := newBoundaryService(t)

			targetID := uuid.New()
			tenantID := uuid.New()

			repo.On("Upsert", mock.Anything, mock.Anything).Return(nil)

			boundary, err := svc.SetBoundary(context.Background(), tt, targetID, tenantID, []string{"read"})

			require.NoError(t, err)
			assert.Equal(t, tt, boundary.TargetType)
			repo.AssertExpectations(t)
		})
	}
}

func TestPermissionBoundary_InvalidTargetType(t *testing.T) {
	invalidTypes := []string{"", "group", "organisation", "admin", "ROLE"}

	for _, tt := range invalidTypes {
		t.Run(tt, func(t *testing.T) {
			svc, repo := newBoundaryService(t)

			_, err := svc.SetBoundary(context.Background(), tt, uuid.New(), uuid.New(), []string{"read"})

			assert.Error(t, err)
			assert.Contains(t, err.Error(), "invalid target_type")
			repo.AssertNotCalled(t, "Upsert")
		})
	}
}

func TestPermissionBoundary_ApplyBoundary_Intersection(t *testing.T) {
	svc, repo := newBoundaryService(t)

	targetID := uuid.New()
	tenantID := uuid.New()

	boundary := &PermissionBoundary{
		TargetType:     "user",
		TargetID:       targetID,
		TenantID:       tenantID,
		MaxPermissions: []string{"iam:users:read", "iam:users:create"},
	}

	repo.On("GetByTarget", mock.Anything, "user", targetID, tenantID).Return(boundary, nil)

	// grantedPermissions includes one perm inside the boundary and one outside.
	granted := []string{"iam:users:read", "iam:users:delete", "billing:invoices:read"}

	effective, err := svc.ApplyBoundary(context.Background(), "user", targetID, tenantID, granted)

	require.NoError(t, err)
	assert.Equal(t, []string{"iam:users:read"}, effective,
		"only permissions present in both granted and max should survive")
	repo.AssertExpectations(t)
}

func TestPermissionBoundary_ApplyBoundary_NoBoundary(t *testing.T) {
	svc, repo := newBoundaryService(t)

	targetID := uuid.New()
	tenantID := uuid.New()

	// Repo returns nil boundary (no restriction configured).
	repo.On("GetByTarget", mock.Anything, "role", targetID, tenantID).Return(nil, nil)

	granted := []string{"iam:users:read", "billing:write", "crm:contacts:delete"}

	effective, err := svc.ApplyBoundary(context.Background(), "role", targetID, tenantID, granted)

	require.NoError(t, err)
	assert.Equal(t, granted, effective,
		"when no boundary is set the full granted set must be returned")
	repo.AssertExpectations(t)
}

func TestPermissionBoundary_ApplyBoundary_Wildcard(t *testing.T) {
	svc, repo := newBoundaryService(t)

	targetID := uuid.New()
	tenantID := uuid.New()

	// "*" in MaxPermissions means no restriction.
	boundary := &PermissionBoundary{
		TargetType:     "service_principal",
		TargetID:       targetID,
		TenantID:       tenantID,
		MaxPermissions: []string{"*"},
	}

	repo.On("GetByTarget", mock.Anything, "service_principal", targetID, tenantID).Return(boundary, nil)

	granted := []string{"iam:users:read", "billing:write", "crm:contacts:delete"}

	effective, err := svc.ApplyBoundary(context.Background(), "service_principal", targetID, tenantID, granted)

	require.NoError(t, err)
	assert.Equal(t, granted, effective,
		"wildcard boundary must return the full granted set unchanged")
	repo.AssertExpectations(t)
}

func TestPermissionBoundary_ApplyBoundary_EmptyMax(t *testing.T) {
	svc, repo := newBoundaryService(t)

	targetID := uuid.New()
	tenantID := uuid.New()

	// Empty MaxPermissions means the boundary restricts to zero permissions.
	boundary := &PermissionBoundary{
		TargetType:     "user",
		TargetID:       targetID,
		TenantID:       tenantID,
		MaxPermissions: []string{},
	}

	repo.On("GetByTarget", mock.Anything, "user", targetID, tenantID).Return(boundary, nil)

	granted := []string{"iam:users:read", "billing:write"}

	effective, err := svc.ApplyBoundary(context.Background(), "user", targetID, tenantID, granted)

	require.NoError(t, err)
	assert.Empty(t, effective,
		"empty max_permissions boundary must yield an empty effective set")
	repo.AssertExpectations(t)
}

func TestPermissionBoundary_ApplyBoundary_EmptyGranted(t *testing.T) {
	svc, repo := newBoundaryService(t)

	targetID := uuid.New()
	tenantID := uuid.New()

	boundary := &PermissionBoundary{
		TargetType:     "user",
		TargetID:       targetID,
		TenantID:       tenantID,
		MaxPermissions: []string{"iam:users:read"},
	}

	repo.On("GetByTarget", mock.Anything, "user", targetID, tenantID).Return(boundary, nil)

	effective, err := svc.ApplyBoundary(context.Background(), "user", targetID, tenantID, []string{})

	require.NoError(t, err)
	assert.Empty(t, effective)
	repo.AssertExpectations(t)
}

func TestPermissionBoundary_RemoveBoundary(t *testing.T) {
	svc, repo := newBoundaryService(t)

	targetID := uuid.New()
	tenantID := uuid.New()

	repo.On("Delete", mock.Anything, "user", targetID, tenantID).Return(nil)

	err := svc.RemoveBoundary(context.Background(), "user", targetID, tenantID)

	require.NoError(t, err)
	repo.AssertExpectations(t)
}

func TestPermissionBoundary_RemoveBoundary_InvalidTargetType(t *testing.T) {
	svc, repo := newBoundaryService(t)

	err := svc.RemoveBoundary(context.Background(), "group", uuid.New(), uuid.New())

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid target_type")
	repo.AssertNotCalled(t, "Delete")
}

func TestPermissionBoundary_GetBoundary_InvalidTargetType(t *testing.T) {
	svc, repo := newBoundaryService(t)

	boundary, err := svc.GetBoundary(context.Background(), "invalid", uuid.New(), uuid.New())

	assert.Error(t, err)
	assert.Nil(t, boundary)
	repo.AssertNotCalled(t, "GetByTarget")
}
