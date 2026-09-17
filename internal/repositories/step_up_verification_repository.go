// SPDX-License-Identifier: AGPL-3.0-or-later

package repositories

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// StepUpVerificationRepository persists and queries step-up MFA verification
// records stored in iam_step_up_verifications.
type StepUpVerificationRepository struct {
	db DBPool
}

// NewStepUpVerificationRepository creates a new StepUpVerificationRepository
// backed by the provided connection pool.
func NewStepUpVerificationRepository(db *pgxpool.Pool) *StepUpVerificationRepository {
	return &StepUpVerificationRepository{db: db}
}

// RecordVerification persists a step-up MFA verification for the given session,
// user, and action. The verification expires after the specified TTL.
func (r *StepUpVerificationRepository) RecordVerification(ctx context.Context, sessionID, userID uuid.UUID, action, method string, ttl time.Duration) error {
	query := `
		INSERT INTO iam_step_up_verifications (session_id, user_id, method, action, expires_at)
		VALUES ($1, $2, $3, $4, NOW() + $5::interval)`

	interval := fmt.Sprintf("%d seconds", int(ttl.Seconds()))

	_, err := r.db.Exec(ctx, query, sessionID, userID, method, action, interval)
	if err != nil {
		return fmt.Errorf("RecordVerification: %w", err)
	}
	return nil
}

// HasRecentVerification returns true when at least one verification row exists
// for the given sessionID and action whose expires_at is still in the future
// and whose verified_at is no older than maxAge from now.
func (r *StepUpVerificationRepository) HasRecentVerification(ctx context.Context, sessionID uuid.UUID, action string, maxAge time.Duration) (bool, error) {
	query := `
		SELECT EXISTS (
			SELECT 1 FROM iam_step_up_verifications
			WHERE session_id = $1
			  AND action     = $2
			  AND expires_at > NOW()
			  AND verified_at > NOW() - $3::interval
		)`

	// PostgreSQL interval literal: e.g. "300 seconds"
	interval := fmt.Sprintf("%d seconds", int(maxAge.Seconds()))

	var exists bool
	if err := r.db.QueryRow(ctx, query, sessionID, action, interval).Scan(&exists); err != nil {
		return false, fmt.Errorf("HasRecentVerification: %w", err)
	}
	return exists, nil
}
