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

// RecoveryRepository manages iam_user_recovery_methods (migration 0005) — the
// canonical store of a user's VERIFIED recovery methods. Pending/unverified
// values are never written here; they live in Redis until verified.
type RecoveryRepository struct {
	pool DBTX
}

// NewRecoveryRepository constructs a repository against the supplied pool.
// Pass a *pgxpool.Pool in production and a pgxmock.PgxPoolIface in tests.
func NewRecoveryRepository(pool DBTX) *RecoveryRepository {
	return &RecoveryRepository{pool: pool}
}

// UpsertVerified inserts (or replaces) the user's recovery method of the given
// type, marking it verified as of now. The (user_id, method_type) unique
// constraint means a re-verify cleanly overwrites the previous value.
func (r *RecoveryRepository) UpsertVerified(
	ctx context.Context,
	userID, tenantID uuid.UUID,
	methodType models.RecoveryMethodType,
	value string,
) error {
	const q = `
		INSERT INTO iam_user_recovery_methods
			(user_id, tenant_id, method_type, value, verified, created_at, verified_at)
		VALUES ($1, $2, $3, $4, TRUE, now(), now())
		ON CONFLICT (user_id, method_type)
		DO UPDATE SET value = EXCLUDED.value,
		              verified = TRUE,
		              verified_at = now()`
	_, err := r.pool.Exec(ctx, q, userID, tenantID, string(methodType), value)
	if err != nil {
		return fmt.Errorf("recovery: upsert_verified: %w", err)
	}
	return nil
}

// Get returns the user's recovery method of the given type, or nil if none
// exists. A missing row is NOT an error — it is the common "not configured"
// case.
func (r *RecoveryRepository) Get(
	ctx context.Context,
	userID uuid.UUID,
	methodType models.RecoveryMethodType,
) (*models.RecoveryMethod, error) {
	const q = `
		SELECT id, user_id, tenant_id, method_type, value, verified, created_at, verified_at
		FROM iam_user_recovery_methods
		WHERE user_id = $1 AND method_type = $2`
	row := r.pool.QueryRow(ctx, q, userID, string(methodType))

	var m models.RecoveryMethod
	var mt string
	err := row.Scan(&m.ID, &m.UserID, &m.TenantID, &mt, &m.Value, &m.Verified, &m.CreatedAt, &m.VerifiedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("recovery: get: %w", err)
	}
	m.MethodType = models.RecoveryMethodType(mt)
	return &m, nil
}

// List returns all recovery methods for a user (ordered for stable output).
func (r *RecoveryRepository) List(ctx context.Context, userID uuid.UUID) ([]models.RecoveryMethod, error) {
	const q = `
		SELECT id, user_id, tenant_id, method_type, value, verified, created_at, verified_at
		FROM iam_user_recovery_methods
		WHERE user_id = $1
		ORDER BY method_type`
	rows, err := r.pool.Query(ctx, q, userID)
	if err != nil {
		return nil, fmt.Errorf("recovery: list: %w", err)
	}
	defer rows.Close()

	var out []models.RecoveryMethod
	for rows.Next() {
		var m models.RecoveryMethod
		var mt string
		if err := rows.Scan(&m.ID, &m.UserID, &m.TenantID, &mt, &m.Value, &m.Verified, &m.CreatedAt, &m.VerifiedAt); err != nil {
			return nil, fmt.Errorf("recovery: list scan: %w", err)
		}
		m.MethodType = models.RecoveryMethodType(mt)
		out = append(out, m)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("recovery: list rows: %w", err)
	}
	return out, nil
}

// Delete removes the user's recovery method of the given type. Deleting a
// non-existent method is a no-op (no error).
func (r *RecoveryRepository) Delete(
	ctx context.Context,
	userID uuid.UUID,
	methodType models.RecoveryMethodType,
) error {
	const q = `DELETE FROM iam_user_recovery_methods WHERE user_id = $1 AND method_type = $2`
	_, err := r.pool.Exec(ctx, q, userID, string(methodType))
	if err != nil {
		return fmt.Errorf("recovery: delete: %w", err)
	}
	return nil
}
