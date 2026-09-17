// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/pkg/logger"
)

// entitlementInstanceRepo lists active product instances for a tenant.
type entitlementInstanceRepo interface {
	ListByTenantAll(ctx context.Context, tenantID uuid.UUID) ([]models.ProductInstance, error)
}

// entitlementProductRepo fetches product details (including manifest).
type entitlementProductRepo interface {
	GetByID(ctx context.Context, id uuid.UUID) (*models.Product, error)
}

// DefaultModuleEntitlementChecker verifies module entitlement by checking
// whether the tenant has an active product instance whose manifest declares
// permissions for the requested module.
//
// The checker extracts the module name from the permission string
// (e.g., "crm" from "crm:contacts:read") and verifies that the tenant
// has an active product instance whose slug matches the module OR whose
// manifest explicitly declares permissions for that module's resources.
type DefaultModuleEntitlementChecker struct {
	instanceRepo entitlementInstanceRepo
	productRepo  entitlementProductRepo
}

// NewDefaultModuleEntitlementChecker creates a new entitlement checker.
func NewDefaultModuleEntitlementChecker(
	instanceRepo entitlementInstanceRepo,
	productRepo entitlementProductRepo,
) *DefaultModuleEntitlementChecker {
	return &DefaultModuleEntitlementChecker{
		instanceRepo: instanceRepo,
		productRepo:  productRepo,
	}
}

// IsTenantEntitled checks if the tenant has an active product instance that
// provides the requested module.
func (c *DefaultModuleEntitlementChecker) IsTenantEntitled(ctx context.Context, tenantID uuid.UUID, module string) (bool, error) {
	module = strings.ToLower(module)

	instances, err := c.instanceRepo.ListByTenantAll(ctx, tenantID)
	if err != nil {
		return false, fmt.Errorf("entitlement check: list instances: %w", err)
	}

	for _, inst := range instances {
		if inst.ProvisioningState != models.ProvisioningStateActive {
			continue
		}

		// Fetch product to check slug and manifest
		product, err := c.productRepo.GetByID(ctx, inst.ProductID)
		if err != nil {
			logger.Debug("entitlement: failed to fetch product",
				zap.String("product_id", inst.ProductID.String()),
				zap.Error(err),
			)
			continue
		}

		// Direct slug match: product slug == module name
		if strings.ToLower(product.Slug) == module {
			return true, nil
		}

		// Check manifest permissions for module match
		manifest, parseErr := product.ParseManifest()
		if parseErr != nil || manifest == nil {
			continue
		}

		for _, perm := range manifest.Permissions {
			// If the product declares permissions for resources in this module,
			// it means the module is part of this product
			if strings.HasPrefix(strings.ToLower(perm.Resource), module) {
				return true, nil
			}
		}
	}

	// No matching product instance found — module not entitled.
	// Note: we return false, nil (not an error) — the caller decides
	// whether to deny or fail-open.
	return false, nil
}
