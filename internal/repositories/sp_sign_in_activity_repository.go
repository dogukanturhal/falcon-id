// SPDX-License-Identifier: AGPL-3.0-or-later

package repositories

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

// SPSignInActivityRepository handles persistence of service principal sign-in events.
type SPSignInActivityRepository struct {
	pool *pgxpool.Pool
}

// NewSPSignInActivityRepository creates a new SPSignInActivityRepository.
func NewSPSignInActivityRepository(pool *pgxpool.Pool) *SPSignInActivityRepository {
	return &SPSignInActivityRepository{pool: pool}
}

const spSignInActivityColumns = `id, sp_id, application_id, tenant_id, ip_address, user_agent, credential_id, credential_type, success, error_code, signed_in_at`

func scanSPSignInActivity(row interface {
	Scan(dest ...any) error
},
) (*models.SPSignInActivity, error) {
	var a models.SPSignInActivity
	err := row.Scan(
		&a.ID, &a.SPID, &a.ApplicationID, &a.TenantID,
		&a.IPAddress, &a.UserAgent,
		&a.CredentialID, &a.CredentialType,
		&a.Success, &a.ErrorCode, &a.SignedInAt,
	)
	if err != nil {
		return nil, err
	}
	return &a, nil
}

// Record inserts a new sign-in activity event. A new UUID is assigned if ID is nil.
func (r *SPSignInActivityRepository) Record(ctx context.Context, a *models.SPSignInActivity) error {
	if a.ID == uuid.Nil {
		a.ID = uuid.New()
	}
	if a.SignedInAt.IsZero() {
		a.SignedInAt = time.Now()
	}

	_, err := r.pool.Exec(ctx, `
		INSERT INTO iam_sp_sign_in_activity (
			id, sp_id, application_id, tenant_id,
			ip_address, user_agent,
			credential_id, credential_type,
			success, error_code, signed_in_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
		a.ID, a.SPID, a.ApplicationID, a.TenantID,
		a.IPAddress, a.UserAgent,
		a.CredentialID, a.CredentialType,
		a.Success, a.ErrorCode, a.SignedInAt,
	)
	if err != nil {
		return fmt.Errorf("SPSignInActivityRepository.Record: %w", err)
	}
	return nil
}

// ListBySP returns the most recent sign-in events for a given service principal,
// bounded to at most 100 rows (default 50).
func (r *SPSignInActivityRepository) ListBySP(ctx context.Context, spID uuid.UUID, limit int) ([]models.SPSignInActivity, error) {
	limit = clampLimit(limit)

	rows, err := r.pool.Query(ctx, `
		SELECT `+spSignInActivityColumns+`
		FROM iam_sp_sign_in_activity
		WHERE sp_id = $1
		ORDER BY signed_in_at DESC
		LIMIT $2`,
		spID, limit,
	)
	if err != nil {
		return nil, fmt.Errorf("SPSignInActivityRepository.ListBySP: %w", err)
	}
	defer rows.Close()

	var results []models.SPSignInActivity
	for rows.Next() {
		a, err := scanSPSignInActivity(rows)
		if err != nil {
			return nil, fmt.Errorf("SPSignInActivityRepository.ListBySP scan: %w", err)
		}
		results = append(results, *a)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("SPSignInActivityRepository.ListBySP rows: %w", err)
	}
	return results, nil
}

// ListByApp returns the most recent sign-in events across all SPs for a given
// application, bounded to at most 100 rows (default 50).
func (r *SPSignInActivityRepository) ListByApp(ctx context.Context, appID uuid.UUID, limit int) ([]models.SPSignInActivity, error) {
	limit = clampLimit(limit)

	rows, err := r.pool.Query(ctx, `
		SELECT `+spSignInActivityColumns+`
		FROM iam_sp_sign_in_activity
		WHERE application_id = $1
		ORDER BY signed_in_at DESC
		LIMIT $2`,
		appID, limit,
	)
	if err != nil {
		return nil, fmt.Errorf("SPSignInActivityRepository.ListByApp: %w", err)
	}
	defer rows.Close()

	var results []models.SPSignInActivity
	for rows.Next() {
		a, err := scanSPSignInActivity(rows)
		if err != nil {
			return nil, fmt.Errorf("SPSignInActivityRepository.ListByApp scan: %w", err)
		}
		results = append(results, *a)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("SPSignInActivityRepository.ListByApp rows: %w", err)
	}
	return results, nil
}

// GetLastSignIn returns the most recent successful sign-in for a service principal.
// Returns an error (including pgx.ErrNoRows) when no successful sign-in exists.
func (r *SPSignInActivityRepository) GetLastSignIn(ctx context.Context, spID uuid.UUID) (*models.SPSignInActivity, error) {
	a, err := scanSPSignInActivity(r.pool.QueryRow(ctx, `
		SELECT `+spSignInActivityColumns+`
		FROM iam_sp_sign_in_activity
		WHERE sp_id = $1 AND success = true
		ORDER BY signed_in_at DESC
		LIMIT 1`,
		spID,
	))
	if err != nil {
		return nil, fmt.Errorf("SPSignInActivityRepository.GetLastSignIn: %w", err)
	}
	return a, nil
}

// CountByAppSince returns the number of sign-in events (successful or not) for an
// application after the given point in time.
func (r *SPSignInActivityRepository) CountByAppSince(ctx context.Context, appID uuid.UUID, since time.Time) (int, error) {
	var count int
	err := r.pool.QueryRow(ctx, `
		SELECT COUNT(*)
		FROM iam_sp_sign_in_activity
		WHERE application_id = $1 AND signed_in_at > $2`,
		appID, since,
	).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("SPSignInActivityRepository.CountByAppSince: %w", err)
	}
	return count, nil
}

// clampLimit normalises the caller-supplied limit to [1, 100].
func clampLimit(limit int) int {
	if limit <= 0 || limit > 100 {
		return 50
	}
	return limit
}
