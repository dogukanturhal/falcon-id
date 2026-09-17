// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/pkg/config"
	"github.com/dogukanturhal/falcon-id/pkg/logger"
)

// licenseServiceLicenseRepo defines the license repository methods needed by LicenseService.
type licenseServiceLicenseRepo interface {
	Create(ctx context.Context, license *models.License) error
	GetByID(ctx context.Context, id uuid.UUID) (*models.License, error)
	GetByLicenseKey(ctx context.Context, key string) (*models.License, error)
	List(ctx context.Context, page, pageSize int, productID, tenantID *uuid.UUID, status, licenseType string) ([]models.License, int64, error)
	Update(ctx context.Context, id uuid.UUID, req *models.UpdateLicenseRequest) (*models.License, error)
	Suspend(ctx context.Context, id uuid.UUID) error
	Revoke(ctx context.Context, id uuid.UUID, revokedBy uuid.UUID) error
	GetActivation(ctx context.Context, licenseID uuid.UUID, machineID string) (*models.LicenseActivation, error)
	GetActivationByID(ctx context.Context, id uuid.UUID) (*models.LicenseActivation, error)
	UpdateActivationLastValidated(ctx context.Context, id uuid.UUID) error
	AtomicClaimSeatAndActivate(ctx context.Context, licenseID uuid.UUID, activation *models.LicenseActivation) (bool, error)
	DeactivateActivation(ctx context.Context, id uuid.UUID) error
	DecrementUsedSeats(ctx context.Context, id uuid.UUID) error
	ListActivations(ctx context.Context, licenseID uuid.UUID) ([]models.LicenseActivation, error)
}

// licenseServiceProductRepo defines the product repository methods needed by LicenseService.
type licenseServiceProductRepo interface {
	GetByID(ctx context.Context, id uuid.UUID) (*models.Product, error)
}

// Sentinel errors for license operations.
var (
	// ErrLicenseNotFound indicates the requested license does not exist.
	ErrLicenseNotFound = errors.New("license not found")
	// ErrProductNotFound indicates the referenced product does not exist.
	ErrProductNotFound = errors.New("product not found")
	// ErrActivationNotFound indicates the requested activation does not exist.
	ErrActivationNotFound = errors.New("activation not found")
	// ErrLicenseNotActive indicates the license is not in an active state.
	ErrLicenseNotActive = errors.New("license is not active")
	// ErrLicenseExpired indicates the license has passed its expiry date.
	ErrLicenseExpired = errors.New("license has expired")
	// ErrMaxSeatsReached indicates the license has no available seats.
	ErrMaxSeatsReached = errors.New("license has reached its maximum seat count")
)

// offlineGracePeriodSeconds is returned to licensed products so they know how long
// they may operate without a successful phone-home validation.
const offlineGracePeriodSeconds = 86400 // 24 hours

// LicenseService handles license management business logic.
type LicenseService struct {
	licenseRepo  licenseServiceLicenseRepo
	productRepo  licenseServiceProductRepo
	auditService *AuditService
	config       *config.Config
}

// NewLicenseService creates a new license service.
func NewLicenseService(
	licenseRepo licenseServiceLicenseRepo,
	productRepo licenseServiceProductRepo,
	auditService *AuditService,
	cfg *config.Config,
) *LicenseService {
	return &LicenseService{
		licenseRepo:  licenseRepo,
		productRepo:  productRepo,
		auditService: auditService,
		config:       cfg,
	}
}

// Create issues a new license. The license key is generated in HEXX-XXXX-XXXX-XXXX-XXXX format.
func (s *LicenseService) Create(ctx context.Context, req *models.CreateLicenseRequest, createdBy uuid.UUID) (*models.License, error) {
	// Validate that the product exists.
	if _, err := s.productRepo.GetByID(ctx, req.ProductID); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrProductNotFound, err)
	}

	licenseKey, err := s.generateLicenseKey()
	if err != nil {
		return nil, fmt.Errorf("LicenseService.Create: %w", err)
	}

	issuedAt := time.Now()
	if req.IssuedAt != nil {
		issuedAt = *req.IssuedAt
	}

	license := &models.License{
		ProductID:  req.ProductID,
		TenantID:   req.TenantID,
		LicenseKey: licenseKey,
		Type:       req.Type,
		Status:     models.LicenseStatusActive,
		MaxSeats:   req.MaxSeats,
		UsedSeats:  0,
		Features:   req.Features,
		Metadata:   req.Metadata,
		IssuedAt:   issuedAt,
		ExpiresAt:  req.ExpiresAt,
		CreatedBy:  &createdBy,
	}

	if err := s.licenseRepo.Create(ctx, license); err != nil {
		return nil, fmt.Errorf("LicenseService.Create: %w", err)
	}

	return license, nil
}

// GetByID retrieves a license by UUID.
func (s *LicenseService) GetByID(ctx context.Context, id uuid.UUID) (*models.License, error) {
	license, err := s.licenseRepo.GetByID(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrLicenseNotFound, err)
	}
	return license, nil
}

// List returns a paginated list of licenses.
func (s *LicenseService) List(
	ctx context.Context,
	page, pageSize int,
	productID, tenantID *uuid.UUID,
	status, licenseType string,
) ([]models.License, int64, error) {
	licenses, total, err := s.licenseRepo.List(ctx, page, pageSize, productID, tenantID, status, licenseType)
	if err != nil {
		return nil, 0, fmt.Errorf("LicenseService.List: %w", err)
	}
	return licenses, total, nil
}

// Update applies partial updates to a license.
func (s *LicenseService) Update(ctx context.Context, id uuid.UUID, req *models.UpdateLicenseRequest) (*models.License, error) {
	if _, err := s.licenseRepo.GetByID(ctx, id); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrLicenseNotFound, err)
	}

	license, err := s.licenseRepo.Update(ctx, id, req)
	if err != nil {
		return nil, fmt.Errorf("LicenseService.Update: %w", err)
	}
	return license, nil
}

// Suspend temporarily disables a license.
func (s *LicenseService) Suspend(ctx context.Context, id uuid.UUID) error {
	if _, err := s.licenseRepo.GetByID(ctx, id); err != nil {
		return fmt.Errorf("%w: %w", ErrLicenseNotFound, err)
	}

	if err := s.licenseRepo.Suspend(ctx, id); err != nil {
		return fmt.Errorf("LicenseService.Suspend: %w", err)
	}
	return nil
}

// Revoke permanently cancels a license.
func (s *LicenseService) Revoke(ctx context.Context, id uuid.UUID, revokedBy uuid.UUID) error {
	if _, err := s.licenseRepo.GetByID(ctx, id); err != nil {
		return fmt.Errorf("%w: %w", ErrLicenseNotFound, err)
	}

	if err := s.licenseRepo.Revoke(ctx, id, revokedBy); err != nil {
		return fmt.Errorf("LicenseService.Revoke: %w", err)
	}
	return nil
}

// ValidateLicense is a public endpoint used by licensed products to phone home.
// It verifies the license key and machine ID, updates the last_validated_at timestamp,
// and returns features and offline grace period.
func (s *LicenseService) ValidateLicense(ctx context.Context, req *models.LicenseValidationRequest) (*models.LicenseValidationResponse, error) {
	license, err := s.licenseRepo.GetByLicenseKey(ctx, req.LicenseKey)
	if err != nil {
		// Return the same response for not-found to prevent license key enumeration.
		return &models.LicenseValidationResponse{Valid: false}, nil //nolint:nilerr // intentional: same response for not-found to prevent license key enumeration
	}

	// Check license status and expiry.
	if !license.IsActive() || license.IsExpired() {
		return &models.LicenseValidationResponse{Valid: false}, nil
	}

	// Locate the activation for this machine.
	activation, err := s.licenseRepo.GetActivation(ctx, license.ID, req.MachineID)
	if err != nil || activation.Status != models.LicenseActivationStatusActive {
		return &models.LicenseValidationResponse{Valid: false}, nil //nolint:nilerr // intentional: activation not found or inactive means invalid license
	}

	// Stamp the validation time (best-effort, log errors).
	if err := s.licenseRepo.UpdateActivationLastValidated(ctx, activation.ID); err != nil {
		logger.Warn("failed to update last_validated_at",
			zap.String("activation_id", activation.ID.String()), zap.Error(err))
	}

	return &models.LicenseValidationResponse{
		Valid:                     true,
		Tier:                      license.Type,
		Features:                  license.Features,
		ExpiresAt:                 license.ExpiresAt,
		OfflineGracePeriodSeconds: offlineGracePeriodSeconds,
	}, nil
}

// ActivateLicense registers a new machine activation for a license.
// SECURITY: Uses atomic SQL to prevent TOCTOU race conditions on seat limits.
func (s *LicenseService) ActivateLicense(ctx context.Context, req *models.ActivateLicenseRequest, ipAddress, userAgent string) (*models.LicenseActivation, error) {
	license, err := s.licenseRepo.GetByLicenseKey(ctx, req.LicenseKey)
	if err != nil {
		return nil, ErrLicenseNotFound
	}

	if !license.IsActive() {
		return nil, ErrLicenseNotActive
	}

	if license.IsExpired() {
		return nil, ErrLicenseExpired
	}

	// Check whether this machine is already activated.
	existing, err := s.licenseRepo.GetActivation(ctx, license.ID, req.MachineID)
	if err == nil && existing.Status == models.LicenseActivationStatusActive {
		// Already active – stamp last validated and return the existing record.
		if err := s.licenseRepo.UpdateActivationLastValidated(ctx, existing.ID); err != nil {
			logger.Warn("failed to update last_validated_at",
				zap.String("activation_id", existing.ID.String()), zap.Error(err))
		}
		return existing, nil
	}

	// SECURITY: Atomically claim a seat AND create the activation in a single
	// database transaction. This prevents both TOCTOU race conditions on seat
	// limits and permanent seat inflation if the activation insert fails.
	ipAddr := &ipAddress
	ua := &userAgent

	activation := &models.LicenseActivation{
		LicenseID:  license.ID,
		MachineID:  req.MachineID,
		DeviceName: req.DeviceName,
		IPAddress:  ipAddr,
		UserAgent:  ua,
		Status:     models.LicenseActivationStatusActive,
	}

	claimed, err := s.licenseRepo.AtomicClaimSeatAndActivate(ctx, license.ID, activation)
	if err != nil {
		return nil, fmt.Errorf("LicenseService.ActivateLicense: %w", err)
	}
	if !claimed {
		return nil, fmt.Errorf("%w (%d)", ErrMaxSeatsReached, license.MaxSeats)
	}

	return activation, nil
}

// DeactivateActivation releases an activation, freeing a seat.
func (s *LicenseService) DeactivateActivation(ctx context.Context, activationID uuid.UUID) error {
	// Look up the activation to find the parent license for seat decrement.
	activation, err := s.licenseRepo.GetActivationByID(ctx, activationID)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrActivationNotFound, err)
	}

	// Only decrement seats if the activation was active.
	wasActive := activation.Status == models.LicenseActivationStatusActive

	if err := s.licenseRepo.DeactivateActivation(ctx, activationID); err != nil {
		return fmt.Errorf("LicenseService.DeactivateActivation: %w", err)
	}

	// Decrement the seat count now that the activation is released.
	if wasActive {
		if err := s.licenseRepo.DecrementUsedSeats(ctx, activation.LicenseID); err != nil {
			logger.Error("failed to decrement seat count after deactivation",
				zap.String("license_id", activation.LicenseID.String()), zap.Error(err))
		}
	}

	return nil
}

// ListActivations returns all activations for a license.
func (s *LicenseService) ListActivations(ctx context.Context, licenseID uuid.UUID) ([]models.LicenseActivation, error) {
	activations, err := s.licenseRepo.ListActivations(ctx, licenseID)
	if err != nil {
		return nil, fmt.Errorf("LicenseService.ListActivations: %w", err)
	}
	return activations, nil
}

// generateLicenseKey creates a cryptographically random license key in the format
// HEXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX where each X is an uppercase
// hexadecimal character, providing 128 bits of entropy for brute-force resistance.
func (s *LicenseService) generateLicenseKey() (string, error) {
	b := make([]byte, 16) // 16 bytes = 128 bits = 32 hex chars for 8 groups of 4
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generateLicenseKey: crypto/rand unavailable: %w", err)
	}
	hex := fmt.Sprintf("%X", b)

	parts := []string{
		"HEXX",
		hex[0:4], hex[4:8], hex[8:12], hex[12:16],
		hex[16:20], hex[20:24], hex[24:28], hex[28:32],
	}

	return strings.Join(parts, "-"), nil
}
