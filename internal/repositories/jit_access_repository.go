// SPDX-License-Identifier: AGPL-3.0-or-later

package repositories

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

// JITAccessRepository handles persistence for just-in-time access grants.
// It satisfies the jitAccessServiceRepo interface defined in the services package.
type JITAccessRepository struct {
	pool DBPool
}

// NewJITAccessRepository creates a new JITAccessRepository backed by the given pool.
func NewJITAccessRepository(pool DBPool) *JITAccessRepository {
	return &JITAccessRepository{pool: pool}
}

// Create persists a new JIT access grant.
// It populates grant.ID and grant.CreatedAt before the insert.
func (r *JITAccessRepository) Create(ctx context.Context, grant *models.JITAccessGrant) error {
	grant.ID = uuid.New()
	grant.CreatedAt = time.Now().UTC()

	_, err := r.pool.Exec(ctx,
		`INSERT INTO iam_jit_access_grants
		 (id, user_id, role_id, tenant_id, justification, requested_at,
		  approved_by, approved_at, starts_at, expires_at, status, created_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`,
		grant.ID, grant.UserID, grant.RoleID, grant.TenantID, grant.Justification,
		grant.RequestedAt, grant.ApprovedBy, grant.ApprovedAt,
		grant.StartsAt, grant.ExpiresAt, string(grant.Status), grant.CreatedAt,
	)
	if err != nil {
		return fmt.Errorf("jit_access_repository.Create: exec: %w", err)
	}

	return nil
}

// GetByID retrieves a single JIT access grant by its UUID.
// Returns (nil, nil) when no row is found.
func (r *JITAccessRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.JITAccessGrant, error) {
	var grant models.JITAccessGrant
	var status string

	err := r.pool.QueryRow(ctx,
		`SELECT id, user_id, role_id, tenant_id, justification, requested_at,
		        approved_by, approved_at, starts_at, expires_at, status, created_at
		 FROM iam_jit_access_grants
		 WHERE id = $1`, id,
	).Scan(
		&grant.ID, &grant.UserID, &grant.RoleID, &grant.TenantID, &grant.Justification,
		&grant.RequestedAt, &grant.ApprovedBy, &grant.ApprovedAt,
		&grant.StartsAt, &grant.ExpiresAt, &status, &grant.CreatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("jit_access_repository.GetByID: scan: %w", err)
	}

	grant.Status = models.JITAccessStatus(status)
	return &grant, nil
}

// UpdateStatus atomically transitions a grant to a new status.
func (r *JITAccessRepository) UpdateStatus(ctx context.Context, id uuid.UUID, status models.JITAccessStatus) error {
	result, err := r.pool.Exec(ctx,
		`UPDATE iam_jit_access_grants SET status = $1 WHERE id = $2`,
		string(status), id,
	)
	if err != nil {
		return fmt.Errorf("jit_access_repository.UpdateStatus: exec: %w", err)
	}
	if result.RowsAffected() == 0 {
		return fmt.Errorf("jit_access_repository.UpdateStatus: grant not found")
	}

	return nil
}

// Approve records the approver's identity, sets approved_at to the current
// time, updates starts_at, and transitions the grant to the "approved" status.
func (r *JITAccessRepository) Approve(ctx context.Context, id, approverID uuid.UUID, startsAt time.Time) error {
	now := time.Now().UTC()

	result, err := r.pool.Exec(ctx,
		`UPDATE iam_jit_access_grants
		 SET approved_by = $1, approved_at = $2, starts_at = $3, status = 'approved'
		 WHERE id = $4`,
		approverID, now, startsAt, id,
	)
	if err != nil {
		return fmt.Errorf("jit_access_repository.Approve: exec: %w", err)
	}
	if result.RowsAffected() == 0 {
		return fmt.Errorf("jit_access_repository.Approve: grant not found")
	}

	return nil
}

// Activate transitions a grant from "approved" to "active".
func (r *JITAccessRepository) Activate(ctx context.Context, id uuid.UUID) error {
	result, err := r.pool.Exec(ctx,
		`UPDATE iam_jit_access_grants SET status = 'active' WHERE id = $1`,
		id,
	)
	if err != nil {
		return fmt.Errorf("jit_access_repository.Activate: exec: %w", err)
	}
	if result.RowsAffected() == 0 {
		return fmt.Errorf("jit_access_repository.Activate: grant not found")
	}

	return nil
}

// ListByTenant returns a paginated slice of JIT grants for the given tenant,
// optionally filtered by status string (empty = all statuses). Results are
// ordered by requested_at DESC. The second return value is the total count
// matching the filter (before pagination).
func (r *JITAccessRepository) ListByTenant(
	ctx context.Context,
	tenantID uuid.UUID,
	status string,
	page, pageSize int,
) ([]*models.JITAccessGrant, int64, error) {
	offset := (page - 1) * pageSize

	var (
		total    int64
		countErr error
	)

	if status != "" {
		countErr = r.pool.QueryRow(ctx,
			`SELECT COUNT(*) FROM iam_jit_access_grants WHERE tenant_id = $1 AND status = $2`,
			tenantID, status,
		).Scan(&total)
	} else {
		countErr = r.pool.QueryRow(ctx,
			`SELECT COUNT(*) FROM iam_jit_access_grants WHERE tenant_id = $1`,
			tenantID,
		).Scan(&total)
	}
	if countErr != nil {
		return nil, 0, fmt.Errorf("jit_access_repository.ListByTenant: count: %w", countErr)
	}

	var (
		rows pgx.Rows
		err  error
	)

	if status != "" {
		rows, err = r.pool.Query(ctx,
			`SELECT id, user_id, role_id, tenant_id, justification, requested_at,
			        approved_by, approved_at, starts_at, expires_at, status, created_at
			 FROM iam_jit_access_grants
			 WHERE tenant_id = $1 AND status = $2
			 ORDER BY requested_at DESC
			 LIMIT $3 OFFSET $4`,
			tenantID, status, pageSize, offset,
		)
	} else {
		rows, err = r.pool.Query(ctx,
			`SELECT id, user_id, role_id, tenant_id, justification, requested_at,
			        approved_by, approved_at, starts_at, expires_at, status, created_at
			 FROM iam_jit_access_grants
			 WHERE tenant_id = $1
			 ORDER BY requested_at DESC
			 LIMIT $2 OFFSET $3`,
			tenantID, pageSize, offset,
		)
	}
	if err != nil {
		return nil, 0, fmt.Errorf("jit_access_repository.ListByTenant: query: %w", err)
	}
	defer rows.Close()

	grants, err := collectJITGrants(rows)
	if err != nil {
		return nil, 0, err
	}

	return grants, total, nil
}

// ListExpiredActive returns all grants whose status is "active" and whose
// expires_at is in the past, up to the given limit. This is consumed by the
// background expiry worker.
func (r *JITAccessRepository) ListExpiredActive(ctx context.Context, limit int) ([]*models.JITAccessGrant, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT id, user_id, role_id, tenant_id, justification, requested_at,
		        approved_by, approved_at, starts_at, expires_at, status, created_at
		 FROM iam_jit_access_grants
		 WHERE status = 'active' AND expires_at < NOW()
		 ORDER BY expires_at ASC
		 LIMIT $1`,
		limit,
	)
	if err != nil {
		return nil, fmt.Errorf("jit_access_repository.ListExpiredActive: query: %w", err)
	}
	defer rows.Close()

	grants, err := collectJITGrants(rows)
	if err != nil {
		return nil, fmt.Errorf("jit_access_repository.ListExpiredActive: %w", err)
	}

	return grants, nil
}

// collectJITGrants scans all rows from a query result into a slice of
// *models.JITAccessGrant. It is a package-level helper shared by
// ListByTenant and ListExpiredActive.
func collectJITGrants(rows pgx.Rows) ([]*models.JITAccessGrant, error) {
	var result []*models.JITAccessGrant

	for rows.Next() {
		var grant models.JITAccessGrant
		var status string

		if err := rows.Scan(
			&grant.ID, &grant.UserID, &grant.RoleID, &grant.TenantID, &grant.Justification,
			&grant.RequestedAt, &grant.ApprovedBy, &grant.ApprovedAt,
			&grant.StartsAt, &grant.ExpiresAt, &status, &grant.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf("collectJITGrants: scan: %w", err)
		}

		grant.Status = models.JITAccessStatus(status)
		result = append(result, &grant)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("collectJITGrants: rows iteration: %w", err)
	}

	return result, nil
}
