// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

// PermissionBoundary is the domain model for a permission boundary record.
// It is intentionally kept inside the services package to avoid polluting the
// models package with a construct that has no persistence coupling outside
// this service.
type PermissionBoundary struct {
	ID             uuid.UUID `json:"id"`
	TargetType     string    `json:"target_type"`
	TargetID       uuid.UUID `json:"target_id"`
	TenantID       uuid.UUID `json:"tenant_id"`
	MaxPermissions []string  `json:"max_permissions"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}

// permissionBoundaryRepo defines the persistence contract for permission
// boundaries. The upsert semantics mean that SetBoundary is idempotent.
type permissionBoundaryRepo interface {
	// Upsert inserts or updates the permission boundary for the given target.
	Upsert(ctx context.Context, boundary *PermissionBoundary) error

	// GetByTarget returns the boundary for the identified target, or nil if
	// none exists (no boundary = all permissions allowed).
	GetByTarget(ctx context.Context, targetType string, targetID, tenantID uuid.UUID) (*PermissionBoundary, error)

	// Delete removes the boundary for the identified target.
	Delete(ctx context.Context, targetType string, targetID, tenantID uuid.UUID) error
}

// PermissionBoundaryService controls the maximum set of permissions that may
// be granted to a user, role, or service principal within a tenant.
//
// A permission boundary is an upper bound: even if a user is assigned a role
// that grants "billing:invoices:delete", the boundary can restrict that user
// to a smaller set (e.g. ["billing:invoices:read", "billing:invoices:create"])
// so the effective permissions are the intersection.
//
// When no boundary is set for a target, the full granted set is returned
// unchanged (open by default).
type PermissionBoundaryService struct {
	repo   permissionBoundaryRepo
	logger *zap.Logger
}

// NewPermissionBoundaryService creates a new PermissionBoundaryService.
func NewPermissionBoundaryService(repo permissionBoundaryRepo, logger *zap.Logger) *PermissionBoundaryService {
	return &PermissionBoundaryService{
		repo:   repo,
		logger: logger,
	}
}

// SetBoundary creates or replaces the permission boundary for the given target.
// targetType must be one of "user", "role", or "service_principal".
// maxPermissions is the exhaustive list of permissions the target may ever
// exercise, regardless of what roles it holds.
func (s *PermissionBoundaryService) SetBoundary(
	ctx context.Context,
	targetType string,
	targetID, tenantID uuid.UUID,
	maxPermissions []string,
) (*PermissionBoundary, error) {
	if err := validateBoundaryTargetType(targetType); err != nil {
		return nil, err
	}

	boundary := &PermissionBoundary{
		TargetType:     targetType,
		TargetID:       targetID,
		TenantID:       tenantID,
		MaxPermissions: maxPermissions,
	}

	if err := s.repo.Upsert(ctx, boundary); err != nil {
		return nil, fmt.Errorf("PermissionBoundaryService.SetBoundary: %w", err)
	}

	s.logger.Info("Permission boundary set",
		zap.String("target_type", targetType),
		zap.String("target_id", targetID.String()),
		zap.String("tenant_id", tenantID.String()),
		zap.Int("max_permissions_count", len(maxPermissions)),
	)

	return boundary, nil
}

// GetBoundary returns the permission boundary for the given target.
// If no boundary is configured, it returns nil (no error).
// Callers should treat a nil boundary as "unrestricted".
func (s *PermissionBoundaryService) GetBoundary(
	ctx context.Context,
	targetType string,
	targetID, tenantID uuid.UUID,
) (*PermissionBoundary, error) {
	if err := validateBoundaryTargetType(targetType); err != nil {
		return nil, err
	}

	boundary, err := s.repo.GetByTarget(ctx, targetType, targetID, tenantID)
	if err != nil {
		return nil, fmt.Errorf("PermissionBoundaryService.GetBoundary: %w", err)
	}
	return boundary, nil
}

// ApplyBoundary returns the intersection of grantedPermissions and the
// boundary's MaxPermissions. If no boundary exists for the target, the
// original grantedPermissions slice is returned unchanged.
//
// The wildcard permission "*" in MaxPermissions means the boundary allows
// everything and grantedPermissions is returned as-is.
func (s *PermissionBoundaryService) ApplyBoundary(
	ctx context.Context,
	targetType string,
	targetID, tenantID uuid.UUID,
	grantedPermissions []string,
) ([]string, error) {
	boundary, err := s.GetBoundary(ctx, targetType, targetID, tenantID)
	if err != nil {
		return nil, fmt.Errorf("PermissionBoundaryService.ApplyBoundary: %w", err)
	}

	// No boundary configured — return the full granted set.
	if boundary == nil {
		return grantedPermissions, nil
	}

	// Wildcard in MaxPermissions — no restriction applied.
	for _, p := range boundary.MaxPermissions {
		if p == "*" {
			return grantedPermissions, nil
		}
	}

	// Build a lookup set from the boundary's allowed permissions.
	allowed := make(map[string]struct{}, len(boundary.MaxPermissions))
	for _, p := range boundary.MaxPermissions {
		allowed[p] = struct{}{}
	}

	// Compute the intersection.
	result := make([]string, 0, len(grantedPermissions))
	for _, p := range grantedPermissions {
		if _, ok := allowed[p]; ok {
			result = append(result, p)
		}
	}

	s.logger.Debug("Permission boundary applied",
		zap.String("target_type", targetType),
		zap.String("target_id", targetID.String()),
		zap.Int("granted", len(grantedPermissions)),
		zap.Int("effective", len(result)),
	)

	return result, nil
}

// RemoveBoundary deletes the permission boundary for the identified target,
// restoring unrestricted access (within whatever roles the target holds).
func (s *PermissionBoundaryService) RemoveBoundary(
	ctx context.Context,
	targetType string,
	targetID, tenantID uuid.UUID,
) error {
	if err := validateBoundaryTargetType(targetType); err != nil {
		return err
	}

	if err := s.repo.Delete(ctx, targetType, targetID, tenantID); err != nil {
		return fmt.Errorf("PermissionBoundaryService.RemoveBoundary: %w", err)
	}

	s.logger.Info("Permission boundary removed",
		zap.String("target_type", targetType),
		zap.String("target_id", targetID.String()),
		zap.String("tenant_id", tenantID.String()),
	)

	return nil
}

// validateBoundaryTargetType checks that targetType is one of the accepted values.
func validateBoundaryTargetType(targetType string) error {
	switch targetType {
	case auditResourceTypeUser, "role", "service_principal":
		return nil
	default:
		return fmt.Errorf("invalid target_type %q: must be one of user, role, service_principal", targetType)
	}
}
