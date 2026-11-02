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
			 verification_token, ip_address, user_agent, expires_at, continuation,
			 verification_code_hash, verification_code_expires_at,
			 verification_resend_window_start, verification_last_sent_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, NOW(), NOW())`

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
		req.Continuation,
		req.VerificationCodeHash,
		req.VerificationCodeExpiresAt,
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
		&req.Continuation,
		&req.CompletionSecretHash,
		&req.VerificationCodeHash,
		&req.VerificationCodeExpiresAt,
		&req.VerificationAttempts,
		&req.VerificationFailedTotal,
	)
	if err != nil {
		return nil, err
	}
	return &req, nil
}

const signupSelectColumns = `
	SELECT id, email, first_name, last_name, account_type, company_name, company_slug,
	       verification_token, verified, verified_at, completed, completed_at,
	       tenant_id, user_id, ip_address, user_agent, expires_at, created_at, updated_at,
	       continuation, completion_secret_hash,
	       verification_code_hash, verification_code_expires_at, verification_attempts,
	       verification_failed_total
	FROM iam_signup_requests`

// GetByToken finds an uncompleted LEGACY signup request by its verification
// token. Rows that carry a code hash are never matched: their token column holds
// an unused placeholder and they verify by code only.
// Returns pgx.ErrNoRows (wrapped) if not found or already completed.
//
// TODO(2026-12-01): remove with the legacy-token path once every pre-OTP
// pending signup (24h lifetime) and old frontend build is gone.
func (r *SignupRequestRepository) GetByToken(ctx context.Context, token string) (*models.SignupRequest, error) {
	query := signupSelectColumns + `
	WHERE verification_token = $1 AND NOT completed AND verification_code_hash IS NULL`

	req, err := scanSignupRequest(r.db.QueryRow(ctx, query, token))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("signup request not found: %w", err)
		}
		return nil, fmt.Errorf("get signup request by token: %w", err)
	}
	return req, nil
}

// SetContinuation stores an OIDC continuation on a not-yet-completed signup
// request that has none. It never overwrites an existing value: the endpoint is
// unauthenticated, so a later caller must not redirect someone else's signup.
func (r *SignupRequestRepository) SetContinuation(ctx context.Context, id uuid.UUID, continuation string) error {
	_, err := r.db.Exec(ctx, `UPDATE iam_signup_requests SET continuation = $2, updated_at = NOW() WHERE id = $1 AND NOT completed AND continuation IS NULL`, id, continuation)
	if err != nil {
		return fmt.Errorf("set signup continuation: %w", err)
	}
	return nil
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

// SetCompletionSecretHash stores the hash of the single-use completion secret
// issued by VerifyEmail, replacing any earlier one (re-opening the emailed link
// rotates it).
func (r *SignupRequestRepository) SetCompletionSecretHash(ctx context.Context, id uuid.UUID, hash string) error {
	_, err := r.db.Exec(ctx, `UPDATE iam_signup_requests SET completion_secret_hash = $2, updated_at = NOW() WHERE id = $1 AND NOT completed`, id, hash)
	if err != nil {
		return fmt.Errorf("set signup completion secret: %w", err)
	}
	return nil
}

// HasCompletedSignupForUser reports whether userID was created by a verified,
// completed self-service signup for exactly this mailbox. That row is the only
// first-party proof that the account owner controlled the address when the
// account was made; iam_users.is_email_verified alone is also written by
// administrators, LDAP/SAML/social sign-in.
func (r *SignupRequestRepository) HasCompletedSignupForUser(ctx context.Context, userID uuid.UUID, canonicalEmail string) (bool, error) {
	var ok bool
	err := r.db.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM iam_signup_requests
			WHERE user_id = $1 AND verified AND completed
			  AND lower(btrim(email)) = $2
		)`, userID, canonicalEmail).Scan(&ok)
	if err != nil {
		return false, fmt.Errorf("has completed signup for user: %w", err)
	}
	return ok, nil
}

// MarkCompleted marks a signup request as completed and records the provisioned
// tenant and user IDs.
func (r *SignupRequestRepository) MarkCompleted(ctx context.Context, id uuid.UUID, tenantID, userID uuid.UUID) error {
	query := `
		UPDATE iam_signup_requests
		SET completed = true, completed_at = NOW(), tenant_id = $2, user_id = $3, completion_secret_hash = NULL, updated_at = NOW()
		WHERE id = $1`

	_, err := r.db.Exec(ctx, query, id, tenantID, userID)
	if err != nil {
		return fmt.Errorf("mark signup request completed: %w", err)
	}
	return nil
}

// SetProvisionedTenant records that a tenant-management tenant has been
// registered for this signup request, before the (separate, unsagaed)
// local iam_tenants row is created. slug is the tenant-management-accepted
// slug, which is persisted here (overwriting any originally-requested
// candidate) so a resumed CompleteSignup attempt can create the local
// tenant with the SAME slug rather than guessing or re-registering.
//
// This intentionally reuses the existing tenant_id/company_slug columns
// rather than adding new ones: no schema change is needed to make retries
// idempotent.
func (r *SignupRequestRepository) SetProvisionedTenant(ctx context.Context, id uuid.UUID, tenantID uuid.UUID, slug string) error {
	query := `
		UPDATE iam_signup_requests
		SET tenant_id = $2, company_slug = $3, updated_at = NOW()
		WHERE id = $1`

	_, err := r.db.Exec(ctx, query, id, tenantID, slug)
	if err != nil {
		return fmt.Errorf("set provisioned tenant on signup request: %w", err)
	}
	return nil
}

// SetCompanyDetails stores the company name and slug collected at
// completion. It only touches a request that has not provisioned a tenant
// and is not completed, so a resumed completion can never rewrite the slug
// that already registered. An empty slug stores NULL (word-pair fallback).
func (r *SignupRequestRepository) SetCompanyDetails(ctx context.Context, id uuid.UUID, name, slug string) error {
	tag, err := r.db.Exec(ctx, `
		UPDATE iam_signup_requests
		SET company_name = $2, company_slug = NULLIF($3, ''), updated_at = NOW()
		WHERE id = $1 AND tenant_id IS NULL AND completed = false`, id, name, slug)
	if err != nil {
		return fmt.Errorf("set company details on signup request: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("set company details on signup request: request no longer editable")
	}
	return nil
}

// CountStalledSignups returns how many signup requests are verified, not
// completed, not yet expired, and were verified before verifiedBefore —
// i.e. currently sitting in the recoverable window (see internal/signupgap
// for the reconciler that polls this).
//
// This predicate is deliberately narrower than "unconfirmed" in every
// direction that matters for safety: it requires verified = true (so a
// request nobody ever proved control of the address for is never counted
// as a recovery candidate — that is handled by the separate reap
// predicate in DeleteExpired instead), NOT completed (a completed request
// has a real tenant and user; it is definitionally not stalled), and
// expires_at > NOW() (an already-expired row belongs to the reap
// predicate, not this one — the two are mutually exclusive by
// construction, so a single row is never double-counted).
func (r *SignupRequestRepository) CountStalledSignups(ctx context.Context, verifiedBefore time.Time) (int, error) {
	query := `
		SELECT COUNT(*)
		FROM iam_signup_requests
		WHERE verified AND NOT completed AND expires_at > NOW()
		  AND verified_at IS NOT NULL AND verified_at < $1`

	var count int
	if err := r.db.QueryRow(ctx, query, verifiedBefore).Scan(&count); err != nil {
		return 0, fmt.Errorf("count stalled signup requests: %w", err)
	}
	return count, nil
}

// CountCompletedBusinessSignupsByEmailDomain counts COMPLETED business-
// account signup requests whose email's domain equals domain (already
// lowercased by the caller — see signup_service.go's emailDomain helper).
// Used by SignupService.InitiateSignup's one-trial-per-work-domain abuse
// control; see that call site's doc comment for what this is and is not
// meant to stop. No new column or index: iam_signup_requests.email is
// already stored lowercased (InitiateSignup lowercases business emails
// before Create), so split_part on the existing column is sufficient at
// today's signup volume — this is a read-path query, not a hot write
// path, so no schema change was needed for this control.
func (r *SignupRequestRepository) CountCompletedBusinessSignupsByEmailDomain(ctx context.Context, domain string) (int, error) {
	query := `
		SELECT COUNT(*)
		FROM iam_signup_requests
		WHERE completed AND account_type = 'business'
		  AND split_part(email, '@', 2) = $1`

	var count int
	if err := r.db.QueryRow(ctx, query, domain).Scan(&count); err != nil {
		return 0, fmt.Errorf("count completed business signups by email domain: %w", err)
	}
	return count, nil
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

// ReserveVerificationResend atomically admits one more code send for a pending
// request: it requires the cooldown since the last send to have passed and fewer
// than maxPerWindow resends in the current window (a fresh window starts once
// the previous one is older than window). It also refuses once the row has
// absorbed maxFailedTotal wrong guesses over its lifetime, so resends cannot
// reset the guess budget indefinitely. requireUnverified scopes the send to
// the unverified branch (a concurrent verify then wins); the verified-recovery
// branch passes false. It reports false when throttled.
func (r *SignupRequestRepository) ReserveVerificationResend(ctx context.Context, id uuid.UUID, cooldown, window time.Duration, maxPerWindow, maxFailedTotal int, requireUnverified bool) (bool, error) {
	tag, err := r.db.Exec(ctx, `
		UPDATE iam_signup_requests
		SET verification_resends = CASE
		        WHEN verification_resend_window_start IS NULL
		          OR verification_resend_window_start <= NOW() - make_interval(secs => $3)
		        THEN 1 ELSE verification_resends + 1 END,
		    verification_resend_window_start = CASE
		        WHEN verification_resend_window_start IS NULL
		          OR verification_resend_window_start <= NOW() - make_interval(secs => $3)
		        THEN NOW() ELSE verification_resend_window_start END,
		    verification_last_sent_at = NOW(),
		    updated_at = NOW()
		WHERE id = $1 AND NOT completed
		  AND verification_failed_total < $5
		  AND (NOT $6 OR NOT verified)
		  AND (verification_last_sent_at IS NULL
		       OR verification_last_sent_at <= NOW() - make_interval(secs => $2))
		  AND (verification_resend_window_start IS NULL
		       OR verification_resend_window_start <= NOW() - make_interval(secs => $3)
		       OR verification_resends < $4)`,
		id, cooldown.Seconds(), window.Seconds(), maxPerWindow, maxFailedTotal, requireUnverified)
	if err != nil {
		return false, fmt.Errorf("reserve signup verification resend: %w", err)
	}
	return tag.RowsAffected() == 1, nil
}

// SetVerificationCode installs a new code hash, invalidating the previous code
// and resetting the attempt counter.
func (r *SignupRequestRepository) SetVerificationCode(ctx context.Context, id uuid.UUID, hash string, expiresAt time.Time) error {
	_, err := r.db.Exec(ctx, `
		UPDATE iam_signup_requests
		SET verification_code_hash = $2, verification_code_expires_at = $3,
		    verification_attempts = 0, updated_at = NOW()
		WHERE id = $1 AND NOT completed`, id, hash, expiresAt)
	if err != nil {
		return fmt.Errorf("set signup verification code: %w", err)
	}
	return nil
}

// ClaimVerificationAttempt atomically spends one of the request's code
// attempts and returns the stored hash, its expiry and the attempts used
// including this one. The attempt is spent BEFORE the comparison so concurrent
// guesses cannot exceed maxAttempts. verification_failed_total is the per-row
// budget that survives resends (capped at maxFailedTotal); a successful
// ConsumeVerificationCode refunds the attempt, so it counts failures only. ok
// is false when the request has no code, is completed, the code has expired,
// or either budget is exhausted.
func (r *SignupRequestRepository) ClaimVerificationAttempt(ctx context.Context, id uuid.UUID, maxAttempts, maxFailedTotal int) (hash string, expiresAt time.Time, attempts int, ok bool, err error) {
	var exp *time.Time
	err = r.db.QueryRow(ctx, `
		UPDATE iam_signup_requests
		SET verification_attempts = verification_attempts + 1,
		    verification_failed_total = verification_failed_total + 1,
		    updated_at = NOW()
		WHERE id = $1 AND NOT completed
		  AND verification_code_hash IS NOT NULL AND verification_attempts < $2
		  AND verification_failed_total < $3
		  AND verification_code_expires_at > NOW()
		RETURNING verification_code_hash, verification_code_expires_at, verification_attempts`,
		id, maxAttempts, maxFailedTotal).Scan(&hash, &exp, &attempts)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", time.Time{}, 0, false, nil
		}
		return "", time.Time{}, 0, false, fmt.Errorf("claim signup verification attempt: %w", err)
	}
	if exp != nil {
		expiresAt = *exp
	}
	return hash, expiresAt, attempts, true, nil
}

// ConsumeVerificationCode atomically makes the code single-use and marks the
// request verified. It reports false when the hash no longer matches the stored
// one or the code expired, so only one of several concurrent submissions wins.
// The winner's claimed attempt is refunded from verification_failed_total.
func (r *SignupRequestRepository) ConsumeVerificationCode(ctx context.Context, id uuid.UUID, hash string) (bool, error) {
	tag, err := r.db.Exec(ctx, `
		UPDATE iam_signup_requests
		SET verified = true, verified_at = COALESCE(verified_at, NOW()),
		    verification_code_expires_at = NOW(),
		    verification_failed_total = GREATEST(verification_failed_total - 1, 0),
		    updated_at = NOW()
		WHERE id = $1 AND NOT completed
		  AND verification_code_hash = $2 AND verification_code_expires_at > NOW()`, id, hash)
	if err != nil {
		return false, fmt.Errorf("consume signup verification code: %w", err)
	}
	return tag.RowsAffected() == 1, nil
}
