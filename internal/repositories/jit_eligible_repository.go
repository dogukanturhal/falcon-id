// SPDX-License-Identifier: AGPL-3.0-or-later

package repositories

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

// JITEligibleRepository handles persistence for JIT/PIM eligibility — who MAY
// request/activate which role, and the guardrails (max duration, MFA,
// approval) that apply. This is distinct from JITAccessRepository, which
// persists the actual time-boxed grants. Schema: iam_jit_eligible, shipped
// via the GitOps repository MigrationBundle falcon-id-v0.232.258.
type JITEligibleRepository struct {
	pool DBPool
}

// NewJITEligibleRepository creates a new JITEligibleRepository.
func NewJITEligibleRepository(pool DBPool) *JITEligibleRepository {
	return &JITEligibleRepository{pool: pool}
}

const jitEligibleCols = `id, user_id, role_id, tenant_id, max_duration_seconds,
	requires_mfa, requires_approval, valid_from, valid_until, created_by, created_at`

// ListByUser returns all eligibility rows for a user, joined with the role's
// name/display name for the UI. The caller filters by validity window
// (IsCurrentlyValid); both current and not-yet/expired rows are returned so
// the UI can show upcoming/expired eligibility distinctly from active.
func (r *JITEligibleRepository) ListByUser(ctx context.Context, userID uuid.UUID) ([]*models.JITEligible, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT e.id, e.user_id, e.role_id, e.tenant_id, e.max_duration_seconds,
		        e.requires_mfa, e.requires_approval, e.valid_from, e.valid_until,
		        e.created_by, e.created_at, r.name, COALESCE(r.display_name, r.name)
		 FROM iam_jit_eligible e
		 JOIN iam_roles r ON r.id = e.role_id
		 WHERE e.user_id = $1
		 ORDER BY r.name ASC`, userID,
	)
	if err != nil {
		return nil, fmt.Errorf("jit_eligible_repository.ListByUser: query: %w", err)
	}
	defer rows.Close()

	var result []*models.JITEligible
	for rows.Next() {
		var e models.JITEligible
		if err := rows.Scan(
			&e.ID, &e.UserID, &e.RoleID, &e.TenantID, &e.MaxDurationSeconds,
			&e.RequiresMFA, &e.RequiresApproval, &e.ValidFrom, &e.ValidUntil,
			&e.CreatedBy, &e.CreatedAt, &e.RoleName, &e.RoleDisplayName,
		); err != nil {
			return nil, fmt.Errorf("jit_eligible_repository.ListByUser: scan: %w", err)
		}
		result = append(result, &e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("jit_eligible_repository.ListByUser: rows: %w", err)
	}
	return result, nil
}

// GetForUserRole returns the eligibility row for (user, role), or (nil, nil)
// when the user is not eligible for that role. Callers must still check
// IsCurrentlyValid() — a returned non-nil row is not itself proof of
// current validity, only of a standing eligibility record existing.
func (r *JITEligibleRepository) GetForUserRole(ctx context.Context, userID, roleID uuid.UUID) (*models.JITEligible, error) {
	var e models.JITEligible
	err := r.pool.QueryRow(ctx,
		`SELECT `+jitEligibleCols+`
		 FROM iam_jit_eligible
		 WHERE user_id = $1 AND role_id = $2`, userID, roleID,
	).Scan(
		&e.ID, &e.UserID, &e.RoleID, &e.TenantID, &e.MaxDurationSeconds,
		&e.RequiresMFA, &e.RequiresApproval, &e.ValidFrom, &e.ValidUntil,
		&e.CreatedBy, &e.CreatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("jit_eligible_repository.GetForUserRole: scan: %w", err)
	}
	return &e, nil
}

// Upsert creates or updates an eligibility row (one per user+role). Used by
// admin/seed flows to grant eligibility; JIT self-service never calls this.
func (r *JITEligibleRepository) Upsert(ctx context.Context, e *models.JITEligible) error {
	if e.ID == uuid.Nil {
		e.ID = uuid.New()
	}
	_, err := r.pool.Exec(ctx,
		`INSERT INTO iam_jit_eligible
		 (id, user_id, role_id, tenant_id, max_duration_seconds, requires_mfa,
		  requires_approval, valid_from, valid_until, created_by)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
		 ON CONFLICT (user_id, role_id) DO UPDATE SET
		   tenant_id = EXCLUDED.tenant_id,
		   max_duration_seconds = EXCLUDED.max_duration_seconds,
		   requires_mfa = EXCLUDED.requires_mfa,
		   requires_approval = EXCLUDED.requires_approval,
		   valid_from = EXCLUDED.valid_from,
		   valid_until = EXCLUDED.valid_until`,
		e.ID, e.UserID, e.RoleID, e.TenantID, e.MaxDurationSeconds, e.RequiresMFA,
		e.RequiresApproval, e.ValidFrom, e.ValidUntil, e.CreatedBy,
	)
	if err != nil {
		return fmt.Errorf("jit_eligible_repository.Upsert: exec: %w", err)
	}
	return nil
}

// Revoke deletes the eligibility row for (user, role), if any. Deliberately
// separate from Upsert so callers cannot accidentally revoke by upserting a
// zero-value struct.
func (r *JITEligibleRepository) Revoke(ctx context.Context, userID, roleID uuid.UUID) error {
	_, err := r.pool.Exec(ctx,
		`DELETE FROM iam_jit_eligible WHERE user_id = $1 AND role_id = $2`,
		userID, roleID,
	)
	if err != nil {
		return fmt.Errorf("jit_eligible_repository.Revoke: exec: %w", err)
	}
	return nil
}
