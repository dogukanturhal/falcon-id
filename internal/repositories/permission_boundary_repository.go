// SPDX-License-Identifier: AGPL-3.0-or-later

package repositories

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// PermBoundaryRecord is the repository-layer representation of a permission
// boundary. It mirrors services.PermissionBoundary field-for-field so that the
// wiring code in cmd/ can copy values between the two without reflection.
//
// The services package defines the domain struct and the permissionBoundaryRepo
// interface. Because importing services from repositories would create a circular
// dependency, the repository works with this local record type. A thin adapter
// (PermissionBoundaryAdapter) is provided so the wiring layer can satisfy the
// services.permissionBoundaryRepo interface with a single wrapping call.
type PermBoundaryRecord struct {
	ID             uuid.UUID
	TargetType     string
	TargetID       uuid.UUID
	TenantID       uuid.UUID
	MaxPermissions []string
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

// PermissionBoundaryRepository handles persistence for permission boundaries.
// Table: iam_permission_boundaries
// Columns: id, target_type, target_id, tenant_id, max_permissions (text[]),
//
//	created_at, updated_at
//
// Unique constraint: (target_type, target_id, tenant_id).
type PermissionBoundaryRepository struct {
	pool DBPool
}

// NewPermissionBoundaryRepository creates a new PermissionBoundaryRepository
// backed by the given pool.
func NewPermissionBoundaryRepository(pool DBPool) *PermissionBoundaryRepository {
	return &PermissionBoundaryRepository{pool: pool}
}

// Upsert inserts or updates the permission boundary for the given target.
// On conflict (target_type, target_id, tenant_id) it updates max_permissions
// and updated_at. ID and CreatedAt are populated on the record when it is a
// new insert; on update only UpdatedAt is refreshed.
func (r *PermissionBoundaryRepository) Upsert(ctx context.Context, boundary *PermBoundaryRecord) error {
	now := time.Now().UTC()

	// Ensure we have an ID for the insert path.
	if boundary.ID == uuid.Nil {
		boundary.ID = uuid.New()
	}
	if boundary.CreatedAt.IsZero() {
		boundary.CreatedAt = now
	}
	boundary.UpdatedAt = now

	_, err := r.pool.Exec(ctx,
		`INSERT INTO iam_permission_boundaries
		 (id, target_type, target_id, tenant_id, max_permissions, created_at, updated_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7)
		 ON CONFLICT (target_type, target_id, tenant_id)
		 DO UPDATE SET
		     max_permissions = EXCLUDED.max_permissions,
		     updated_at      = EXCLUDED.updated_at`,
		boundary.ID, boundary.TargetType, boundary.TargetID, boundary.TenantID,
		boundary.MaxPermissions, boundary.CreatedAt, boundary.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("permission_boundary_repository.Upsert: exec: %w", err)
	}

	return nil
}

// GetByTarget returns the permission boundary for the identified target, or
// nil (without an error) when no boundary has been configured.
func (r *PermissionBoundaryRepository) GetByTarget(
	ctx context.Context,
	targetType string,
	targetID, tenantID uuid.UUID,
) (*PermBoundaryRecord, error) {
	var rec PermBoundaryRecord

	err := r.pool.QueryRow(ctx,
		`SELECT id, target_type, target_id, tenant_id, max_permissions, created_at, updated_at
		 FROM iam_permission_boundaries
		 WHERE target_type = $1 AND target_id = $2 AND tenant_id = $3`,
		targetType, targetID, tenantID,
	).Scan(
		&rec.ID, &rec.TargetType, &rec.TargetID, &rec.TenantID,
		&rec.MaxPermissions, &rec.CreatedAt, &rec.UpdatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("permission_boundary_repository.GetByTarget: scan: %w", err)
	}

	return &rec, nil
}

// Delete removes the permission boundary for the identified target.
// It is not an error to delete a boundary that does not exist.
func (r *PermissionBoundaryRepository) Delete(
	ctx context.Context,
	targetType string,
	targetID, tenantID uuid.UUID,
) error {
	_, err := r.pool.Exec(ctx,
		`DELETE FROM iam_permission_boundaries
		 WHERE target_type = $1 AND target_id = $2 AND tenant_id = $3`,
		targetType, targetID, tenantID,
	)
	if err != nil {
		return fmt.Errorf("permission_boundary_repository.Delete: exec: %w", err)
	}

	return nil
}
