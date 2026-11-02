// SPDX-License-Identifier: AGPL-3.0-or-later

package repositories

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

// Applies 0032_iam_signup_otp.sql (twice: it must be idempotent) over a
// pre-0032 iam_signup_requests and drives the repository's code methods against
// real Postgres. Needs TEST_DATABASE_URL (see hack/run-team-postgres-tests.sh).
func TestSignupOTP_Migration0032_AndRepositoryAgainstPostgres(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL required")
	}
	ctx := context.Background()
	schema := "signup_otp_" + strings.ReplaceAll(uuid.NewString(), "-", "")[:12]
	admin, err := pgx.Connect(ctx, dsn)
	require.NoError(t, err)
	_, err = admin.Exec(ctx, "CREATE SCHEMA "+pgx.Identifier{schema}.Sanitize())
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = admin.Exec(ctx, "DROP SCHEMA "+pgx.Identifier{schema}.Sanitize()+" CASCADE")
		_ = admin.Close(ctx)
	})
	cfg, err := pgxpool.ParseConfig(dsn)
	require.NoError(t, err)
	cfg.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	require.NoError(t, err)
	t.Cleanup(pool.Close)

	// The base table is created outside internal/migrations; mirror its shape
	// as of 0026.
	_, err = pool.Exec(ctx, `CREATE TABLE iam_signup_requests (
		id uuid PRIMARY KEY, email text NOT NULL, first_name text, last_name text,
		account_type text NOT NULL, company_name text, company_slug text,
		verification_token text NOT NULL UNIQUE, verified boolean NOT NULL DEFAULT false,
		verified_at timestamptz, completed boolean NOT NULL DEFAULT false, completed_at timestamptz,
		tenant_id uuid, user_id uuid, ip_address text, user_agent text,
		expires_at timestamptz NOT NULL, created_at timestamptz NOT NULL DEFAULT now(),
		updated_at timestamptz NOT NULL DEFAULT now(), continuation text, completion_secret_hash text)`)
	require.NoError(t, err)

	// A pre-deploy row (hex token, no code).
	legacyID := uuid.New()
	_, err = pool.Exec(ctx, `INSERT INTO iam_signup_requests (id, email, account_type, verification_token, expires_at)
		VALUES ($1, 'old@example.com', 'personal', 'legacytoken', now() + interval '1 hour')`, legacyID)
	require.NoError(t, err)

	sql, err := os.ReadFile("../migrations/0032_iam_signup_otp.sql")
	require.NoError(t, err)
	for i := 0; i < 2; i++ {
		_, err = pool.Exec(ctx, string(sql))
		require.NoError(t, err, "apply #%d", i+1)
	}

	repo := NewSignupRequestRepository(pool)
	legacy, err := repo.GetByToken(ctx, "legacytoken")
	require.NoError(t, err)
	require.Nil(t, legacy.VerificationCodeHash)
	require.Equal(t, 0, legacy.VerificationAttempts)

	// New row with a code: the token column no longer matches via GetByToken.
	id := uuid.New()
	hash := "h1"
	exp := time.Now().Add(15 * time.Minute)
	require.NoError(t, repo.Create(ctx, &models.SignupRequest{
		ID: id, Email: "new@example.com", AccountType: "personal", VerificationToken: "placeholder",
		ExpiresAt: time.Now().Add(24 * time.Hour), VerificationCodeHash: &hash, VerificationCodeExpiresAt: &exp,
	}))
	_, err = repo.GetByToken(ctx, "placeholder")
	require.Error(t, err)

	// Attempts are spent atomically and stop at the cap.
	for i := 1; i <= 5; i++ {
		h, _, n, ok, err := repo.ClaimVerificationAttempt(ctx, id, 5, 15)
		require.NoError(t, err)
		require.True(t, ok)
		require.Equal(t, "h1", h)
		require.Equal(t, i, n)
	}
	_, _, _, ok, err := repo.ClaimVerificationAttempt(ctx, id, 5, 15)
	require.NoError(t, err)
	require.False(t, ok, "burned after 5")

	// Resend: cooldown blocks an immediate second send; a new code resets attempts.
	ok, err = repo.ReserveVerificationResend(ctx, id, time.Minute, time.Hour, 5, 15, true)
	require.NoError(t, err)
	require.False(t, ok, "created just now: cooldown")
	ok, err = repo.ReserveVerificationResend(ctx, id, 0, time.Hour, 5, 15, true)
	require.NoError(t, err)
	require.True(t, ok)
	require.NoError(t, repo.SetVerificationCode(ctx, id, "h2", time.Now().Add(15*time.Minute)))
	_, _, n, ok, err := repo.ClaimVerificationAttempt(ctx, id, 5, 15)
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, 1, n)

	// The window cap: 5 per window.
	for i := 0; i < 4; i++ {
		ok, err = repo.ReserveVerificationResend(ctx, id, 0, time.Hour, 5, 15, true)
		require.NoError(t, err)
		require.True(t, ok)
	}
	ok, err = repo.ReserveVerificationResend(ctx, id, 0, time.Hour, 5, 15, true)
	require.NoError(t, err)
	require.False(t, ok, "hourly cap")

	// Consume is single-use and hash-bound.
	ok, err = repo.ConsumeVerificationCode(ctx, id, "h1")
	require.NoError(t, err)
	require.False(t, ok, "old hash")
	failedTotal := func(rowID uuid.UUID) int {
		var n int
		require.NoError(t, pool.QueryRow(ctx, `SELECT verification_failed_total FROM iam_signup_requests WHERE id = $1`, rowID).Scan(&n))
		return n
	}
	require.Equal(t, 6, failedTotal(id), "5 guesses on h1 + 1 on h2; resends do not reset the row total")
	ok, err = repo.ConsumeVerificationCode(ctx, id, "h2")
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, 5, failedTotal(id), "the winning claim is refunded")
	ok, err = repo.ConsumeVerificationCode(ctx, id, "h2")
	require.NoError(t, err)
	require.False(t, ok, "second use")

	// A verified row is refused by the unverified-scoped resend but admitted by
	// the recovery path (requireUnverified=false).
	_, err = pool.Exec(ctx, `UPDATE iam_signup_requests SET verification_resend_window_start = NULL, verification_last_sent_at = NULL WHERE id = $1`, id)
	require.NoError(t, err)
	ok, err = repo.ReserveVerificationResend(ctx, id, 0, time.Hour, 5, 15, true)
	require.NoError(t, err)
	require.False(t, ok, "verified row: unverified-scoped resend refused")
	ok, err = repo.ReserveVerificationResend(ctx, id, 0, time.Hour, 5, 15, false)
	require.NoError(t, err)
	require.True(t, ok, "verified row: recovery resend admitted")

	// Row cap: 15 wrong guesses across codes block claims and resends for good.
	capID := uuid.New()
	capHash := "c1"
	require.NoError(t, repo.Create(ctx, &models.SignupRequest{
		ID: capID, Email: "cap@example.com", AccountType: "personal", VerificationToken: "cap-placeholder",
		ExpiresAt: time.Now().Add(24 * time.Hour), VerificationCodeHash: &capHash, VerificationCodeExpiresAt: &exp,
	}))
	for round := 0; round < 3; round++ {
		for i := 0; i < 5; i++ {
			_, _, _, ok, err = repo.ClaimVerificationAttempt(ctx, capID, 5, 15)
			require.NoError(t, err)
			require.True(t, ok, "round %d claim %d", round, i)
		}
		if round < 2 {
			ok, err = repo.ReserveVerificationResend(ctx, capID, 0, time.Hour, 5, 15, true)
			require.NoError(t, err)
			require.True(t, ok)
			require.NoError(t, repo.SetVerificationCode(ctx, capID, "c-next", time.Now().Add(15*time.Minute)))
		}
	}
	require.NoError(t, repo.SetVerificationCode(ctx, capID, "c-last", time.Now().Add(15*time.Minute)))
	_, _, _, ok, err = repo.ClaimVerificationAttempt(ctx, capID, 5, 15)
	require.NoError(t, err)
	require.False(t, ok, "row cap holds across resends")
	ok, err = repo.ReserveVerificationResend(ctx, capID, 0, time.Hour, 5, 15, true)
	require.NoError(t, err)
	require.False(t, ok, "no resend once the row cap is hit")

	// An expired code cannot be claimed.
	expID := uuid.New()
	expHash := "e1"
	past := time.Now().Add(-time.Minute)
	require.NoError(t, repo.Create(ctx, &models.SignupRequest{
		ID: expID, Email: "exp@example.com", AccountType: "personal", VerificationToken: "exp-placeholder",
		ExpiresAt: time.Now().Add(24 * time.Hour), VerificationCodeHash: &expHash, VerificationCodeExpiresAt: &past,
	}))
	_, _, _, ok, err = repo.ClaimVerificationAttempt(ctx, expID, 5, 15)
	require.NoError(t, err)
	require.False(t, ok, "expired code is not claimable")
}
