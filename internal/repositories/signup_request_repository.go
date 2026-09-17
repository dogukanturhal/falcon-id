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

// SignupRequestRepository persists self-service signup requests.
type SignupRequestRepository struct {
	db DBPool
}

// NewSignupRequestRepository creates a new SignupRequestRepository.
func NewSignupRequestRepository(db DBPool) *SignupRequestRepository {
	return &SignupRequestRepository{db: db}
}

// Create inserts a new signup request into the database.
func (r *SignupRequestRepository) Create(ctx context.Context, req *models.SignupRequest) error {
	query := `
		INSERT INTO iam_signup_requests
			(id, email, first_name, last_name, account_type, company_name, company_slug,
			 verification_token, ip_address, user_agent, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`

	_, err := r.db.Exec(ctx, query,
		req.ID,
		req.Email,
		req.FirstName,
		req.LastName,
		req.AccountType,
		req.CompanyName,
		req.CompanySlug,
		req.VerificationToken,
		req.IPAddress,
		req.UserAgent,
		req.ExpiresAt,
	)
	if err != nil {
		return fmt.Errorf("create signup request: %w", err)
	}
	return nil
}

// scanSignupRequest scans a single row into a SignupRequest.
func scanSignupRequest(row pgx.Row) (*models.SignupRequest, error) {
	var req models.SignupRequest
	err := row.Scan(
		&req.ID,
		&req.Email,
		&req.FirstName,
		&req.LastName,
		&req.AccountType,
		&req.CompanyName,
		&req.CompanySlug,
		&req.VerificationToken,
		&req.Verified,
		&req.VerifiedAt,
		&req.Completed,
		&req.CompletedAt,
		&req.TenantID,
		&req.UserID,
		&req.IPAddress,
		&req.UserAgent,
		&req.ExpiresAt,
		&req.CreatedAt,
		&req.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	return &req, nil
}

const signupSelectColumns = `
	SELECT id, email, first_name, last_name, account_type, company_name, company_slug,
	       verification_token, verified, verified_at, completed, completed_at,
	       tenant_id, user_id, ip_address, user_agent, expires_at, created_at, updated_at
	FROM iam_signup_requests`

// GetByToken finds an uncompleted signup request by its verification token.
// Returns pgx.ErrNoRows (wrapped) if not found or already completed.
func (r *SignupRequestRepository) GetByToken(ctx context.Context, token string) (*models.SignupRequest, error) {
	query := signupSelectColumns + `
	WHERE verification_token = $1 AND NOT completed`

	req, err := scanSignupRequest(r.db.QueryRow(ctx, query, token))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("signup request not found: %w", err)
		}
		return nil, fmt.Errorf("get signup request by token: %w", err)
	}
	return req, nil
}

// GetByID finds a signup request by its primary key.
func (r *SignupRequestRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.SignupRequest, error) {
	query := signupSelectColumns + `
	WHERE id = $1`

	req, err := scanSignupRequest(r.db.QueryRow(ctx, query, id))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("signup request not found: %w", err)
		}
		return nil, fmt.Errorf("get signup request by id: %w", err)
	}
	return req, nil
}

// GetPendingByEmail returns the most recent unexpired, uncompleted signup request
// for the given email address, or an error if none exists.
func (r *SignupRequestRepository) GetPendingByEmail(ctx context.Context, email string) (*models.SignupRequest, error) {
	query := signupSelectColumns + `
	WHERE email = $1 AND NOT completed AND expires_at > NOW()
	ORDER BY created_at DESC
	LIMIT 1`

	req, err := scanSignupRequest(r.db.QueryRow(ctx, query, email))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("no pending signup request: %w", err)
		}
		return nil, fmt.Errorf("get pending signup request: %w", err)
	}
	return req, nil
}

// MarkVerified stamps a signup request as email-verified.
func (r *SignupRequestRepository) MarkVerified(ctx context.Context, id uuid.UUID) error {
	query := `
		UPDATE iam_signup_requests
		SET verified = true, verified_at = NOW(), updated_at = NOW()
		WHERE id = $1`

	_, err := r.db.Exec(ctx, query, id)
	if err != nil {
		return fmt.Errorf("mark signup request verified: %w", err)
	}
	return nil
}

// MarkCompleted marks a signup request as completed and records the provisioned
// tenant and user IDs.
func (r *SignupRequestRepository) MarkCompleted(ctx context.Context, id uuid.UUID, tenantID, userID uuid.UUID) error {
	query := `
		UPDATE iam_signup_requests
		SET completed = true, completed_at = NOW(), tenant_id = $2, user_id = $3, updated_at = NOW()
		WHERE id = $1`

	_, err := r.db.Exec(ctx, query, id, tenantID, userID)
	if err != nil {
		return fmt.Errorf("mark signup request completed: %w", err)
	}
	return nil
}

// DeleteExpired removes all expired, uncompleted signup requests.
// It returns the number of rows deleted.
func (r *SignupRequestRepository) DeleteExpired(ctx context.Context) (int64, error) {
	query := `DELETE FROM iam_signup_requests WHERE NOT completed AND expires_at < NOW()`

	tag, err := r.db.Exec(ctx, query)
	if err != nil {
		return 0, fmt.Errorf("delete expired signup requests: %w", err)
	}
	return tag.RowsAffected(), nil
}
