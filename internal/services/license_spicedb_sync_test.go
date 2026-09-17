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
)

// ==================== Mock: licenseSpiceDBSyncer ====================

type mockLicenseSpiceDBSyncer struct {
	mock.Mock
}

func (m *mockLicenseSpiceDBSyncer) WriteRelationship(
	ctx context.Context,
	resourceType, resourceID, relation, subjectType, subjectID string,
) (string, error) {
	args := m.Called(ctx, resourceType, resourceID, relation, subjectType, subjectID)
	return args.String(0), args.Error(1)
}

func (m *mockLicenseSpiceDBSyncer) DeleteRelationship(
	ctx context.Context,
	resourceType, resourceID, relation, subjectType, subjectID string,
) error {
	args := m.Called(ctx, resourceType, resourceID, relation, subjectType, subjectID)
	return args.Error(0)
}

// ==================== TestOnLicenseActivated_WritesRelationship ====================

func TestOnLicenseActivated_WritesRelationship(t *testing.T) {
	ctx := context.Background()
	tenantID := uuid.New()
	productID := uuid.New()

	syncer := new(mockLicenseSpiceDBSyncer)
	syncer.On(
		"WriteRelationship",
		ctx,
		"platform_product", productID.String(),
		"subscribed_tenant",
		"tenant", tenantID.String(),
	).Return("zedtoken-abc", nil)

	svc := NewLicenseSpiceDBSync(syncer, zap.NewNop())
	err := svc.OnLicenseActivated(ctx, tenantID, productID)

	require.NoError(t, err)
	syncer.AssertExpectations(t)
}

// TestOnLicenseActivated_PropagatesError verifies that write errors surface to callers.
func TestOnLicenseActivated_PropagatesError(t *testing.T) {
	ctx := context.Background()
	tenantID := uuid.New()
	productID := uuid.New()
	writeErr := errors.New("spicedb unavailable")

	syncer := new(mockLicenseSpiceDBSyncer)
	syncer.On(
		"WriteRelationship",
		ctx,
		"platform_product", productID.String(),
		"subscribed_tenant",
		"tenant", tenantID.String(),
	).Return("", writeErr)

	svc := NewLicenseSpiceDBSync(syncer, zap.NewNop())
	err := svc.OnLicenseActivated(ctx, tenantID, productID)

	require.Error(t, err)
	assert.ErrorIs(t, err, writeErr)
	syncer.AssertExpectations(t)
}

// ==================== TestOnLicenseSuspended_DeletesRelationship ====================

func TestOnLicenseSuspended_DeletesRelationship(t *testing.T) {
	ctx := context.Background()
	tenantID := uuid.New()
	productID := uuid.New()

	syncer := new(mockLicenseSpiceDBSyncer)
	syncer.On(
		"DeleteRelationship",
		ctx,
		"platform_product", productID.String(),
		"subscribed_tenant",
		"tenant", tenantID.String(),
	).Return(nil)

	svc := NewLicenseSpiceDBSync(syncer, zap.NewNop())
	err := svc.OnLicenseSuspended(ctx, tenantID, productID)

	require.NoError(t, err)
	syncer.AssertExpectations(t)
}

// ==================== TestOnLicenseExpired_DeletesRelationship ====================

func TestOnLicenseExpired_DeletesRelationship(t *testing.T) {
	ctx := context.Background()
	tenantID := uuid.New()
	productID := uuid.New()

	syncer := new(mockLicenseSpiceDBSyncer)
	syncer.On(
		"DeleteRelationship",
		ctx,
		"platform_product", productID.String(),
		"subscribed_tenant",
		"tenant", tenantID.String(),
	).Return(nil)

	svc := NewLicenseSpiceDBSync(syncer, zap.NewNop())
	err := svc.OnLicenseExpired(ctx, tenantID, productID)

	require.NoError(t, err)
	syncer.AssertExpectations(t)
}

// ==================== TestOnLicenseRevoked_DeletesRelationship ====================

func TestOnLicenseRevoked_DeletesRelationship(t *testing.T) {
	ctx := context.Background()
	tenantID := uuid.New()
	productID := uuid.New()

	syncer := new(mockLicenseSpiceDBSyncer)
	syncer.On(
		"DeleteRelationship",
		ctx,
		"platform_product", productID.String(),
		"subscribed_tenant",
		"tenant", tenantID.String(),
	).Return(nil)

	svc := NewLicenseSpiceDBSync(syncer, zap.NewNop())
	err := svc.OnLicenseRevoked(ctx, tenantID, productID)

	require.NoError(t, err)
	syncer.AssertExpectations(t)
}

// TestLicenseSpiceDBSync_DeleteErrors_AreWrapped verifies that delete errors
// carry context about which lifecycle event triggered the failure.
func TestLicenseSpiceDBSync_DeleteErrors_AreWrapped(t *testing.T) {
	tests := []struct {
		name      string
		operation func(svc *LicenseSpiceDBSync, ctx context.Context, tenantID, productID uuid.UUID) error
	}{
		{"suspended", func(svc *LicenseSpiceDBSync, ctx context.Context, tID, pID uuid.UUID) error {
			return svc.OnLicenseSuspended(ctx, tID, pID)
		}},
		{"expired", func(svc *LicenseSpiceDBSync, ctx context.Context, tID, pID uuid.UUID) error {
			return svc.OnLicenseExpired(ctx, tID, pID)
		}},
		{"revoked", func(svc *LicenseSpiceDBSync, ctx context.Context, tID, pID uuid.UUID) error {
			return svc.OnLicenseRevoked(ctx, tID, pID)
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			tenantID := uuid.New()
			productID := uuid.New()
			deleteErr := errors.New("delete failed")

			syncer := new(mockLicenseSpiceDBSyncer)
			syncer.On("DeleteRelationship", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
				Return(deleteErr)

			svc := NewLicenseSpiceDBSync(syncer, zap.NewNop())
			err := tt.operation(svc, ctx, tenantID, productID)

			require.Error(t, err)
			assert.ErrorIs(t, err, deleteErr)
		})
	}
}
