// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

// licenseSpiceDBSyncer is the subset of the SpiceDB client used by LicenseSpiceDBSync.
// Using a local interface follows the project pattern of accept-interfaces, return-structs
// and makes the service trivially testable.
type licenseSpiceDBSyncer interface {
	WriteRelationship(ctx context.Context, resourceType, resourceID, relation, subjectType, subjectID string) (string, error)
	DeleteRelationship(ctx context.Context, resourceType, resourceID, relation, subjectType, subjectID string) error
}

// LicenseSpiceDBSync keeps SpiceDB tenant-product subscription relationships
// in sync with license lifecycle events.
//
// The relationship schema is:
//
//	platform_product:{productID}#subscribed_tenant@tenant:{tenantID}
type LicenseSpiceDBSync struct {
	syncer licenseSpiceDBSyncer
	logger *zap.Logger
}

// NewLicenseSpiceDBSync creates a new LicenseSpiceDBSync.
func NewLicenseSpiceDBSync(syncer licenseSpiceDBSyncer, log *zap.Logger) *LicenseSpiceDBSync {
	if log == nil {
		log = zap.NewNop()
	}
	return &LicenseSpiceDBSync{
		syncer: syncer,
		logger: log,
	}
}

// OnLicenseActivated writes a subscribed_tenant relationship when a license is activated.
// platform_product:{productID}#subscribed_tenant@tenant:{tenantID}
func (s *LicenseSpiceDBSync) OnLicenseActivated(ctx context.Context, tenantID, productID uuid.UUID) error {
	_, err := s.syncer.WriteRelationship(
		ctx,
		"platform_product", productID.String(),
		"subscribed_tenant",
		"tenant", tenantID.String(),
	)
	if err != nil {
		s.logger.Error("LicenseSpiceDBSync: failed to write activated relationship",
			zap.String("tenant_id", tenantID.String()),
			zap.String("product_id", productID.String()),
			zap.Error(err),
		)
		return fmt.Errorf("LicenseSpiceDBSync.OnLicenseActivated: %w", err)
	}

	s.logger.Info("LicenseSpiceDBSync: wrote activated relationship",
		zap.String("tenant_id", tenantID.String()),
		zap.String("product_id", productID.String()),
	)
	return nil
}

// OnLicenseSuspended removes the subscribed_tenant relationship when a license
// is temporarily suspended.
func (s *LicenseSpiceDBSync) OnLicenseSuspended(ctx context.Context, tenantID, productID uuid.UUID) error {
	return s.deleteSubscription(ctx, tenantID, productID, "suspended")
}

// OnLicenseExpired removes the subscribed_tenant relationship when a license expires.
func (s *LicenseSpiceDBSync) OnLicenseExpired(ctx context.Context, tenantID, productID uuid.UUID) error {
	return s.deleteSubscription(ctx, tenantID, productID, "expired")
}

// OnLicenseRevoked removes the subscribed_tenant relationship when a license is
// permanently revoked.
func (s *LicenseSpiceDBSync) OnLicenseRevoked(ctx context.Context, tenantID, productID uuid.UUID) error {
	return s.deleteSubscription(ctx, tenantID, productID, "revoked")
}

// deleteSubscription is the shared helper that removes a subscribed_tenant relationship.
func (s *LicenseSpiceDBSync) deleteSubscription(
	ctx context.Context,
	tenantID, productID uuid.UUID,
	reason string,
) error {
	err := s.syncer.DeleteRelationship(
		ctx,
		"platform_product", productID.String(),
		"subscribed_tenant",
		"tenant", tenantID.String(),
	)
	if err != nil {
		s.logger.Error("LicenseSpiceDBSync: failed to delete relationship",
			zap.String("tenant_id", tenantID.String()),
			zap.String("product_id", productID.String()),
			zap.String("reason", reason),
			zap.Error(err),
		)
		return fmt.Errorf("LicenseSpiceDBSync.deleteSubscription (%s): %w", reason, err)
	}

	s.logger.Info("LicenseSpiceDBSync: deleted relationship",
		zap.String("tenant_id", tenantID.String()),
		zap.String("product_id", productID.String()),
		zap.String("reason", reason),
	)
	return nil
}
