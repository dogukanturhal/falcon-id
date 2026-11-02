// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

// productInstanceRepo defines repository methods needed by ProductInstanceService.
type productInstanceRepo interface {
	Create(ctx context.Context, pi *models.ProductInstance) error
	GetByID(ctx context.Context, id uuid.UUID) (*models.ProductInstance, error)
	GetByTenantAndProduct(ctx context.Context, tenantID, productID uuid.UUID) (*models.ProductInstance, error)
	ListByTenant(ctx context.Context, tenantID uuid.UUID, page, pageSize int) ([]models.ProductInstance, int64, error)
	ListByProduct(ctx context.Context, productID uuid.UUID) ([]models.ProductInstance, error)
	ListPending(ctx context.Context) ([]models.ProductInstance, error)
	UpdateState(ctx context.Context, id uuid.UUID, state models.ProvisioningState, currentStep *string) error
	CompleteStep(ctx context.Context, id uuid.UUID, step string, newState models.ProvisioningState) error
	SetFailed(ctx context.Context, id uuid.UUID, reason string) error
	SetActive(ctx context.Context, id uuid.UUID) error
	SetDeleted(ctx context.Context, id uuid.UUID) error
	UpdateDatabaseInfo(ctx context.Context, id uuid.UUID, host, dbName, schema, username string, connEnc []byte) error
	UpdateMigrationVersion(ctx context.Context, id uuid.UUID, version int) error
	ResetForRetry(ctx context.Context, id uuid.UUID) error
	ResetForManualRetry(ctx context.Context, id uuid.UUID) error
	ResetForReprovisioning(ctx context.Context, id uuid.UUID) error
	SetFailedWithRetry(ctx context.Context, id uuid.UUID, reason string, retryCount int, nextRetryAt time.Time) error
	SetPermanentlyFailed(ctx context.Context, id uuid.UUID, reason string) error
}

// productInstanceProductRepo defines the product repository methods needed.
type productInstanceProductRepo interface {
	GetByID(ctx context.Context, id uuid.UUID) (*models.Product, error)
}

// ProductInstanceService manages the lifecycle of per-tenant product instances.
type ProductInstanceService struct {
	instanceRepo productInstanceRepo
	productRepo  productInstanceProductRepo
	validator    *ManifestValidator
}

// NewProductInstanceService creates a new product instance service.
func NewProductInstanceService(
	instanceRepo productInstanceRepo,
	productRepo productInstanceProductRepo,
) *ProductInstanceService {
	return &ProductInstanceService{
		instanceRepo: instanceRepo,
		productRepo:  productRepo,
		validator:    NewManifestValidator(),
	}
}

// Provision creates a new product instance for a tenant, starting the
// provisioning workflow. The instance begins in "pending" state.
func (s *ProductInstanceService) Provision(ctx context.Context, productID uuid.UUID, req *models.CreateProductInstanceRequest) (*models.ProductInstance, error) {
	// Validate product exists and is active.
	product, err := s.productRepo.GetByID(ctx, productID)
	if err != nil {
		return nil, fmt.Errorf("product not found: %w", err)
	}
	if !product.IsActive() {
		return nil, fmt.Errorf("product %q is not active (status=%s)", product.Slug, product.Status)
	}

	// Validate manifest if present.
	if err := s.validator.Validate(product.CapabilityManifest); err != nil {
		return nil, fmt.Errorf("invalid product manifest: %w", err)
	}

	// Check for existing instance (unique constraint: tenant_id + product_id).
	existing, lookupErr := s.instanceRepo.GetByTenantAndProduct(ctx, req.TenantID, productID)
	if lookupErr != nil && !errors.Is(lookupErr, pgx.ErrNoRows) {
		return nil, fmt.Errorf("lookup existing product instance: %w", lookupErr)
	}
	if existing != nil {
		if existing.ProvisioningState != models.ProvisioningStateDeleted && existing.ProvisioningState != models.ProvisioningStateFailed {
			if existing.ProvisioningState == models.ProvisioningStateDeleting {
				return nil, fmt.Errorf("product instance is being deleted")
			}
			// A trial root remains the app/recovery shell after module expiry.
			// Paid/comp activation must reuse it, not fail as a duplicate or
			// reset its databases/plan/provisioning history. Entitlement tiers
			// come from canonical module snapshots, not this isolation hint.
			return existing, nil
		}
		// Allow re-provisioning if previous attempt failed or was deleted.
		if err := s.instanceRepo.ResetForReprovisioning(ctx, existing.ID); err != nil {
			return nil, fmt.Errorf("reset instance for re-provisioning: %w", err)
		}
		// Re-read to return fresh state (retry_count, failure_reason, etc. were cleared).
		refreshed, err := s.instanceRepo.GetByID(ctx, existing.ID)
		if err != nil {
			return nil, fmt.Errorf("re-read after reset: %w", err)
		}
		return refreshed, nil
	}

	pi := &models.ProductInstance{
		TenantID:          req.TenantID,
		ProductID:         productID,
		PlanID:            req.PlanID,
		ProvisioningState: models.ProvisioningStatePending,
		CompletedSteps:    []string{},
	}

	if err := s.instanceRepo.Create(ctx, pi); err != nil {
		return nil, fmt.Errorf("ProductInstanceService.Provision: %w", err)
	}

	return pi, nil
}

// GetByID retrieves a product instance by ID.
func (s *ProductInstanceService) GetByID(ctx context.Context, id uuid.UUID) (*models.ProductInstance, error) {
	pi, err := s.instanceRepo.GetByID(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("ProductInstanceService.GetByID: %w", err)
	}
	return pi, nil
}

// ListByTenant returns paginated instances for a tenant.
func (s *ProductInstanceService) ListByTenant(ctx context.Context, tenantID uuid.UUID, page, pageSize int) (*models.ProductInstanceListResponse, error) {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 100 {
		pageSize = 20
	}

	instances, total, err := s.instanceRepo.ListByTenant(ctx, tenantID, page, pageSize)
	if err != nil {
		return nil, fmt.Errorf("ProductInstanceService.ListByTenant: %w", err)
	}

	responses := make([]models.ProductInstanceResponse, 0, len(instances))
	for i := range instances {
		responses = append(responses, *instances[i].ToResponse())
	}

	totalPages := int(math.Ceil(float64(total) / float64(pageSize)))

	return &models.ProductInstanceListResponse{
		Instances:  responses,
		Total:      total,
		Page:       page,
		PageSize:   pageSize,
		TotalPages: totalPages,
	}, nil
}

// ListByProduct returns all instances for a product.
func (s *ProductInstanceService) ListByProduct(ctx context.Context, productID uuid.UUID) ([]models.ProductInstance, error) {
	return s.instanceRepo.ListByProduct(ctx, productID)
}

// ListPending returns all instances awaiting provisioning.
func (s *ProductInstanceService) ListPending(ctx context.Context) ([]models.ProductInstance, error) {
	return s.instanceRepo.ListPending(ctx)
}

// RetryInstance resets a failed instance back to pending for manual retry.
// Clears retry_count and failure info so the reconciler starts fresh.
func (s *ProductInstanceService) RetryInstance(ctx context.Context, id uuid.UUID) (*models.ProductInstance, error) {
	pi, err := s.instanceRepo.GetByID(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("instance not found: %w", err)
	}
	if pi.ProvisioningState != models.ProvisioningStateFailed {
		return nil, fmt.Errorf("instance is not in failed state (state=%s)", pi.ProvisioningState)
	}

	if err := s.instanceRepo.ResetForManualRetry(ctx, id); err != nil {
		return nil, fmt.Errorf("retry instance: %w", err)
	}

	return s.instanceRepo.GetByID(ctx, id)
}

// Deprovision initiates the deletion workflow for an instance.
func (s *ProductInstanceService) Deprovision(ctx context.Context, id uuid.UUID) error {
	pi, err := s.instanceRepo.GetByID(ctx, id)
	if err != nil {
		return fmt.Errorf("instance not found: %w", err)
	}

	if pi.ProvisioningState == models.ProvisioningStateDeleted {
		return fmt.Errorf("instance already deleted")
	}
	if pi.ProvisioningState == models.ProvisioningStateDeleting {
		return nil // already in progress
	}

	step := "deleting"
	return s.instanceRepo.UpdateState(ctx, id, models.ProvisioningStateDeleting, &step)
}
