// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/pkg/logger"
)

// appInstallRepo defines the repository methods needed by AppInstallationService.
type appInstallRepo interface {
	Create(ctx context.Context, inst *models.AppInstallation) error
	GetByID(ctx context.Context, id uuid.UUID) (*models.AppInstallation, error)
	GetByTenantAndProduct(ctx context.Context, tenantID, productID uuid.UUID) (*models.AppInstallation, error)
	List(ctx context.Context, tenantID uuid.UUID, status string, page, pageSize int) ([]models.AppInstallation, int64, error)
	UpdateStatus(ctx context.Context, id uuid.UUID, status models.AppInstallationStatus) error
	SetUninstalledAt(ctx context.Context, id uuid.UUID, t time.Time) error
}

// appInstallProductRepo defines the product repository subset used by AppInstallationService.
type appInstallProductRepo interface {
	GetByID(ctx context.Context, id uuid.UUID) (*models.Product, error)
}

// Sentinel errors for app installation operations.
var (
	// ErrInstallationNotFound indicates the requested installation does not exist.
	ErrInstallationNotFound = errors.New("app installation not found")
	// ErrAlreadyInstalled indicates the product is already installed for the tenant.
	ErrAlreadyInstalled = errors.New("product is already installed for this tenant")
	// ErrProductInactive indicates the product is not active and cannot be installed.
	ErrProductInactive = errors.New("product is not active and cannot be installed")
)

// AppInstallationService manages the app install/uninstall lifecycle for tenants.
type AppInstallationService struct {
	installRepo     appInstallRepo
	productRepo     appInstallProductRepo
	instanceService *ProductInstanceService
}

// NewAppInstallationService creates a new AppInstallationService.
func NewAppInstallationService(
	installRepo appInstallRepo,
	productRepo appInstallProductRepo,
) *AppInstallationService {
	return &AppInstallationService{
		installRepo: installRepo,
		productRepo: productRepo,
	}
}

// SetProductInstanceService wires the product instance service for
// triggering provisioning on install and deprovisioning on uninstall.
func (s *AppInstallationService) SetProductInstanceService(svc *ProductInstanceService) {
	s.instanceService = svc
}

// Install records a new app installation for a tenant. It validates that the
// product exists and is active, and prevents duplicate installs.
func (s *AppInstallationService) Install(
	ctx context.Context,
	tenantID, productID, installedBy uuid.UUID,
	scopes []string,
) (*models.AppInstallation, error) {
	// Validate the product exists and is active.
	product, err := s.productRepo.GetByID(ctx, productID)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrProductNotFound, err)
	}
	if !product.IsActive() {
		return nil, fmt.Errorf("%w: %q", ErrProductInactive, product.Status)
	}

	// Prevent duplicate installs.
	existing, err := s.installRepo.GetByTenantAndProduct(ctx, tenantID, productID)
	if err == nil && existing != nil && existing.Status == models.AppInstallationStatusActive {
		return nil, fmt.Errorf("%w: product %s tenant %s", ErrAlreadyInstalled, productID, tenantID)
	}

	inst := &models.AppInstallation{
		TenantID:      tenantID,
		ProductID:     productID,
		InstalledBy:   installedBy,
		Status:        models.AppInstallationStatusActive,
		ConsentScopes: scopes,
	}

	if err := s.installRepo.Create(ctx, inst); err != nil {
		return nil, fmt.Errorf("AppInstallationService.Install: %w", err)
	}

	logger.Info("App installed",
		zap.String("tenant_id", tenantID.String()),
		zap.String("product_id", productID.String()),
		zap.String("installed_by", installedBy.String()),
	)

	// Trigger product provisioning if instance service is available.
	if s.instanceService != nil {
		req := &models.CreateProductInstanceRequest{TenantID: tenantID}
		if _, err := s.instanceService.Provision(ctx, productID, req); err != nil {
			// Log but don't fail the install — provisioning runs asynchronously.
			logger.Warn("Failed to trigger product provisioning on install",
				zap.String("product_id", productID.String()),
				zap.String("tenant_id", tenantID.String()),
				zap.Error(err),
			)
		}
	}

	return inst, nil
}

// Uninstall marks an installation as uninstalled for the given tenant+product pair.
func (s *AppInstallationService) Uninstall(ctx context.Context, tenantID, productID uuid.UUID) error {
	inst, err := s.installRepo.GetByTenantAndProduct(ctx, tenantID, productID)
	if err != nil {
		return fmt.Errorf("%w: tenant %s product %s", ErrInstallationNotFound, tenantID, productID)
	}

	if err := s.installRepo.UpdateStatus(ctx, inst.ID, models.AppInstallationStatusUninstalled); err != nil {
		return fmt.Errorf("AppInstallationService.Uninstall: %w", err)
	}

	if err := s.installRepo.SetUninstalledAt(ctx, inst.ID, time.Now()); err != nil {
		// Non-fatal: log but do not fail the overall uninstall.
		logger.Warn("failed to stamp uninstalled_at",
			zap.String("installation_id", inst.ID.String()),
			zap.Error(err),
		)
	}

	logger.Info("App uninstalled",
		zap.String("tenant_id", tenantID.String()),
		zap.String("product_id", productID.String()),
	)

	return nil
}

// GetInstallation retrieves an installation record by tenant and product.
func (s *AppInstallationService) GetInstallation(
	ctx context.Context,
	tenantID, productID uuid.UUID,
) (*models.AppInstallation, error) {
	inst, err := s.installRepo.GetByTenantAndProduct(ctx, tenantID, productID)
	if err != nil {
		return nil, fmt.Errorf("%w: tenant %s product %s", ErrInstallationNotFound, tenantID, productID)
	}
	return inst, nil
}

// ListInstallations returns a paginated list of installations for a tenant.
func (s *AppInstallationService) ListInstallations(
	ctx context.Context,
	tenantID uuid.UUID,
	status string,
	page, pageSize int,
) ([]models.AppInstallation, int64, error) {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 100 {
		pageSize = 20
	}

	installations, total, err := s.installRepo.List(ctx, tenantID, status, page, pageSize)
	if err != nil {
		return nil, 0, fmt.Errorf("AppInstallationService.ListInstallations: %w", err)
	}
	return installations, total, nil
}
