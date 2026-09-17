// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/pkg/logger"
)

// SubscriptionProvisioningBridge triggers product provisioning when a
// subscription is activated. This is the connective tissue between the
// subscription-management service and Falcon-ID's provisioning orchestrator.
//
// Call TriggerProvisioning from an HTTP handler, Kafka consumer, or webhook
// that receives subscription.activated events.
type SubscriptionProvisioningBridge struct {
	instanceRepo subscriptionBridgeInstanceRepo
	productRepo  subscriptionBridgeProductRepo
}

// subscriptionBridgeInstanceRepo is the narrow interface for creating product instances.
type subscriptionBridgeInstanceRepo interface {
	Create(ctx context.Context, instance *models.ProductInstance) error
	GetByTenantAndProduct(ctx context.Context, tenantID, productID uuid.UUID) (*models.ProductInstance, error)
}

// subscriptionBridgeProductRepo resolves product IDs from slugs.
type subscriptionBridgeProductRepo interface {
	GetBySlug(ctx context.Context, slug string) (*models.Product, error)
	GetByID(ctx context.Context, id uuid.UUID) (*models.Product, error)
}

// NewSubscriptionProvisioningBridge creates a new bridge.
func NewSubscriptionProvisioningBridge(
	instanceRepo subscriptionBridgeInstanceRepo,
	productRepo subscriptionBridgeProductRepo,
) *SubscriptionProvisioningBridge {
	return &SubscriptionProvisioningBridge{
		instanceRepo: instanceRepo,
		productRepo:  productRepo,
	}
}

// TriggerProvisioning creates a pending product instance for a tenant,
// which the ProvisioningOrchestrator will pick up in its next reconciliation
// loop. This is idempotent — if an instance already exists for the
// tenant+product pair, it returns the existing one.
func (b *SubscriptionProvisioningBridge) TriggerProvisioning(
	ctx context.Context,
	tenantID uuid.UUID,
	productID uuid.UUID,
	isolationTier string,
) (*models.ProductInstance, error) {
	// Verify product exists
	product, err := b.productRepo.GetByID(ctx, productID)
	if err != nil {
		return nil, fmt.Errorf("subscription bridge: product not found: %w", err)
	}

	// Idempotency: check if instance already exists
	existing, err := b.instanceRepo.GetByTenantAndProduct(ctx, tenantID, productID)
	if err == nil && existing != nil {
		logger.Info("Subscription bridge: product instance already exists (idempotent)",
			zap.String("tenant_id", tenantID.String()),
			zap.String("product_id", productID.String()),
			zap.String("state", string(existing.ProvisioningState)),
		)
		return existing, nil
	}

	// Determine isolation tier from subscription or product default
	tier := isolationTier
	if tier == "" {
		manifest, parseErr := product.ParseManifest()
		if parseErr == nil && manifest != nil && manifest.Database != nil {
			tier = manifest.Database.IsolationDefault
		}
		if tier == "" {
			tier = models.IsolationPool // safe default
		}
	}

	planID := &tier
	instance := &models.ProductInstance{
		ID:                uuid.New(),
		TenantID:          tenantID,
		ProductID:         productID,
		ProvisioningState: models.ProvisioningStatePending,
		PlanID:            planID,
	}

	if err := b.instanceRepo.Create(ctx, instance); err != nil {
		return nil, fmt.Errorf("subscription bridge: create instance: %w", err)
	}

	logger.Info("Subscription bridge: product instance created (pending provisioning)",
		zap.String("instance_id", instance.ID.String()),
		zap.String("tenant_id", tenantID.String()),
		zap.String("product", product.Slug),
		zap.String("isolation_tier", tier),
	)

	return instance, nil
}
