// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"fmt"
	"sort"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

// resourceManifestRepo is the narrow read-only interface the orchestrator uses
// to load a product's resource manifest.
type resourceManifestRepo interface {
	ListByProduct(ctx context.Context, productID uuid.UUID) ([]models.ProductResourceManifest, error)
}

// resourceInstanceRepo is the narrow write interface the orchestrator uses to
// record provisioning results.
type resourceInstanceRepo interface {
	Create(ctx context.Context, instance *models.TenantResourceInstance) error
	UpdateStatus(ctx context.Context, id uuid.UUID, status string, config map[string]interface{}, errMsg string) error
	ListByInstance(ctx context.Context, instanceID uuid.UUID) ([]models.TenantResourceInstance, error)
}

// ResourceOrchestrator provisions and deprovisions ALL resources declared in a
// product's manifest for a given tenant activation.  It reads the manifest,
// creates a resource instance row per entry, then calls the appropriate
// ResourceProvisioner from the registry.
//
// Resources are provisioned in priority order (ascending).  A failed required
// resource causes the entire provisioning to return an error after exhausting
// remaining non-required resources (best-effort for optional ones).
// Deprovisioning runs in reverse priority order.
type ResourceOrchestrator struct {
	registry     *ResourceProvisionerRegistry
	manifestRepo resourceManifestRepo
	instanceRepo resourceInstanceRepo
	log          *zap.SugaredLogger
}

// NewResourceOrchestrator creates a ResourceOrchestrator.
func NewResourceOrchestrator(
	registry *ResourceProvisionerRegistry,
	manifestRepo resourceManifestRepo,
	instanceRepo resourceInstanceRepo,
	log *zap.SugaredLogger,
) *ResourceOrchestrator {
	return &ResourceOrchestrator{
		registry:     registry,
		manifestRepo: manifestRepo,
		instanceRepo: instanceRepo,
		log:          log,
	}
}

// ProvisionAll provisions every resource in the product's manifest for the
// given tenant activation.  Resources are provisioned in ascending priority
// order.  For each entry:
//
//  1. A tenant_resource_instance row is inserted with status "creating".
//  2. The registry is consulted for a matching provisioner.
//  3. The provisioner's Provision() method is called.
//  4. The row is updated to "active" on success or "failed" on error.
//
// If a required resource fails, ProvisionAll returns a non-nil error after
// attempting all remaining optional resources.  Optional resources log their
// failure but do not block overall success.
func (o *ResourceOrchestrator) ProvisionAll(
	ctx context.Context,
	tenantID, productID, instanceID uuid.UUID,
	region, tier string,
) ([]models.TenantResourceInstance, error) {
	manifests, err := o.manifestRepo.ListByProduct(ctx, productID)
	if err != nil {
		return nil, fmt.Errorf("load product manifest for %s: %w", productID, err)
	}

	if len(manifests) == 0 {
		o.log.Infow("No resource manifest entries found for product — skipping resource provisioning",
			"product_id", productID,
			"instance_id", instanceID,
		)
		return nil, nil
	}

	// Sort by priority ascending (ListByProduct already does this via ORDER BY,
	// but we sort here defensively in case the repo is swapped in tests).
	sort.Slice(manifests, func(i, j int) bool {
		return manifests[i].Priority < manifests[j].Priority
	})

	results := make([]models.TenantResourceInstance, 0, len(manifests))
	var firstRequiredErr error

	for _, m := range manifests {
		if ctx.Err() != nil {
			return results, ctx.Err()
		}

		inst, err := o.provisionOne(ctx, tenantID, productID, instanceID, region, tier, m)
		if inst != nil {
			results = append(results, *inst)
		}
		if err != nil {
			if m.IsRequired {
				// Record the first required failure; continue provisioning optional resources.
				if firstRequiredErr == nil {
					firstRequiredErr = fmt.Errorf("required resource %s/%s failed: %w", m.ResourceType, m.ResourceName, err)
				}
			} else {
				o.log.Warnw("Optional resource provisioning failed (non-fatal)",
					"resource_type", m.ResourceType,
					"resource_name", m.ResourceName,
					"error", err,
				)
			}
		}
	}

	return results, firstRequiredErr
}

// provisionOne provisions a single manifest entry and records the result.
func (o *ResourceOrchestrator) provisionOne(
	ctx context.Context,
	tenantID, productID, instanceID uuid.UUID,
	region, tier string,
	m models.ProductResourceManifest,
) (*models.TenantResourceInstance, error) {
	// Create the instance record in "creating" status.
	inst := &models.TenantResourceInstance{
		TenantID:     tenantID,
		ProductID:    productID,
		InstanceID:   instanceID,
		ManifestID:   m.ID,
		ResourceType: m.ResourceType,
		ResourceName: m.ResourceName,
		Status:       models.ResourceStatusCreating,
	}
	if err := o.instanceRepo.Create(ctx, inst); err != nil {
		return nil, fmt.Errorf("create resource instance record: %w", err)
	}

	o.log.Infow("Provisioning resource",
		"resource_type", m.ResourceType,
		"resource_name", m.ResourceName,
		"tenant_id", tenantID,
		"instance_id", instanceID,
	)

	// Look up provisioner.
	provisioner, ok := o.registry.Get(m.ResourceType)
	if !ok {
		errMsg := fmt.Sprintf("no provisioner registered for resource type %q", m.ResourceType)
		_ = o.instanceRepo.UpdateStatus(ctx, inst.ID, models.ResourceStatusFailed, nil, errMsg)
		inst.Status = models.ResourceStatusFailed
		errStr := errMsg
		inst.ErrorMessage = &errStr
		return inst, fmt.Errorf("%s", errMsg)
	}

	// Call provisioner.
	result, err := provisioner.Provision(ctx, ResourceProvisionRequest{
		TenantID:     tenantID,
		ProductID:    productID,
		InstanceID:   instanceID,
		ManifestID:   m.ID,
		ResourceName: m.ResourceName,
		Config:       m.ConfigMap(),
		Region:       region,
		Tier:         tier,
	})
	if err != nil {
		errMsg := err.Error()
		_ = o.instanceRepo.UpdateStatus(ctx, inst.ID, models.ResourceStatusFailed, nil, errMsg)
		inst.Status = models.ResourceStatusFailed
		inst.ErrorMessage = &errMsg
		return inst, err
	}

	status := models.ResourceStatusActive
	if result.Status != "" {
		status = result.Status
	}
	_ = o.instanceRepo.UpdateStatus(ctx, inst.ID, status, result.ProvisionedConfig, "")
	inst.Status = status

	o.log.Infow("Resource provisioned successfully",
		"resource_type", m.ResourceType,
		"resource_name", m.ResourceName,
		"tenant_id", tenantID,
		"status", status,
	)

	return inst, nil
}

// DeprovisionAll destroys all provisioned resources for an instance in REVERSE
// priority order (routes before databases, etc.).  Errors are logged but do not
// stop cleanup of remaining resources.
func (o *ResourceOrchestrator) DeprovisionAll(ctx context.Context, instanceID uuid.UUID) error {
	instances, err := o.instanceRepo.ListByInstance(ctx, instanceID)
	if err != nil {
		return fmt.Errorf("list resource instances for %s: %w", instanceID, err)
	}

	if len(instances) == 0 {
		return nil
	}

	// Deprovision in reverse order — higher priority numbers (routes, identity)
	// are destroyed before lower priority numbers (databases).
	// We sort ascending then iterate in reverse.
	sort.Slice(instances, func(i, j int) bool {
		return instances[i].CreatedAt.Before(instances[j].CreatedAt)
	})

	var firstErr error
	for i := len(instances) - 1; i >= 0; i-- {
		inst := instances[i]
		if inst.Status == models.ResourceStatusDeleted {
			continue
		}

		_ = o.instanceRepo.UpdateStatus(ctx, inst.ID, models.ResourceStatusDeleting, nil, "")

		provisioner, ok := o.registry.Get(inst.ResourceType)
		if !ok {
			o.log.Warnw("No provisioner for resource type during deprovisioning (skipping)",
				"resource_type", inst.ResourceType,
				"resource_name", inst.ResourceName,
			)
			_ = o.instanceRepo.UpdateStatus(ctx, inst.ID, models.ResourceStatusDeleted, nil, "")
			continue
		}

		if err := provisioner.Deprovision(ctx, ResourceDeprovisionRequest{
			TenantID:          inst.TenantID,
			ResourceName:      inst.ResourceName,
			ProvisionedConfig: inst.ProvisionedConfigMap(),
		}); err != nil {
			o.log.Errorw("Resource deprovisioning failed",
				"resource_type", inst.ResourceType,
				"resource_name", inst.ResourceName,
				"error", err,
			)
			if firstErr == nil {
				firstErr = err
			}
			_ = o.instanceRepo.UpdateStatus(ctx, inst.ID, models.ResourceStatusFailed, nil, err.Error())
			continue
		}

		_ = o.instanceRepo.UpdateStatus(ctx, inst.ID, models.ResourceStatusDeleted, nil, "")
	}

	return firstErr
}

// HealthCheckAll checks the health of all active provisioned resources for an
// instance and returns one result per resource.
func (o *ResourceOrchestrator) HealthCheckAll(ctx context.Context, instanceID uuid.UUID) ([]ResourceHealthResult, error) {
	instances, err := o.instanceRepo.ListByInstance(ctx, instanceID)
	if err != nil {
		return nil, fmt.Errorf("list resource instances for health check: %w", err)
	}

	results := make([]ResourceHealthResult, 0, len(instances))
	for _, inst := range instances {
		if inst.Status != models.ResourceStatusActive {
			results = append(results, ResourceHealthResult{
				ResourceType: inst.ResourceType,
				ResourceName: inst.ResourceName,
				Healthy:      false,
				Message:      fmt.Sprintf("resource not active (status: %s)", inst.Status),
			})
			continue
		}

		provisioner, ok := o.registry.Get(inst.ResourceType)
		if !ok {
			results = append(results, ResourceHealthResult{
				ResourceType: inst.ResourceType,
				ResourceName: inst.ResourceName,
				Healthy:      false,
				Message:      "no provisioner registered for this resource type",
			})
			continue
		}

		result, err := provisioner.HealthCheck(ctx, ResourceHealthCheckRequest{
			TenantID:          inst.TenantID,
			ResourceName:      inst.ResourceName,
			ProvisionedConfig: inst.ProvisionedConfigMap(),
		})
		if err != nil {
			results = append(results, ResourceHealthResult{
				ResourceType: inst.ResourceType,
				ResourceName: inst.ResourceName,
				Healthy:      false,
				Message:      err.Error(),
			})
			continue
		}
		result.ResourceType = inst.ResourceType
		result.ResourceName = inst.ResourceName
		results = append(results, *result)
	}

	return results, nil
}

// zap field helpers to keep log calls concise.
var _ = zap.String // ensure zap import is not flagged as unused if only SugaredLogger is used
