// SPDX-License-Identifier: AGPL-3.0-or-later

package repositories

// user_repository_mfa_grace_test.go covers the three repository methods
// added by migration 235 to drive the configurable MFA-enrollment
// grace period:
//   - StampMFAEnrollmentFirstPrompt — first-prompt-wins idempotency.
//   - IncrementMFAEnrollmentSkipCount — atomic, deadline-gated.
//   - ResetMFAEnrollmentGraceTracking — post-enrollment cleanup.
//
// pgxmock with QueryMatcherRegexp; each test asserts the matched SQL
// includes the WHERE-clause invariants the service relies on (the SQL
// guard is the security boundary — the Go-side caller must NOT need to
// double-check before calling).

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/pashagolub/pgxmock/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStampMFAEnrollmentFirstPrompt_StampsWhenNull(t *testing.T) {
	ctx := context.Background()
	repo, mock := newUserRepo(t)
	userID := uuid.New()
	deadline := time.Now().UTC().Add(14 * 24 * time.Hour)

	// The regex asserts the IS NULL guard — without it, a concurrent
	// login could overwrite a previously-stamped deadline, leaking
	// grace into a second cycle.
	mock.ExpectExec(`UPDATE iam_users\s+SET mfa_enrollment_first_prompted_at = NOW\(\),\s+mfa_enrollment_deadline = \$2,\s+updated_at = NOW\(\)\s+WHERE id = \$1\s+AND mfa_enrollment_first_prompted_at IS NULL`).
		WithArgs(userID, deadline).
		WillReturnResult(pgxmock.NewResult("UPDATE", 1))

	stamped, err := repo.StampMFAEnrollmentFirstPrompt(ctx, userID, deadline)
	require.NoError(t, err)
	assert.True(t, stamped, "first call must report stamped=true")
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestStampMFAEnrollmentFirstPrompt_NoopOnSecondCall(t *testing.T) {
	ctx := context.Background()
	repo, mock := newUserRepo(t)
	userID := uuid.New()
	deadline := time.Now().UTC().Add(14 * 24 * time.Hour)

	mock.ExpectExec(`UPDATE iam_users`).
		WithArgs(userID, deadline).
		WillReturnResult(pgxmock.NewResult("UPDATE", 0))

	stamped, err := repo.StampMFAEnrollmentFirstPrompt(ctx, userID, deadline)
	require.NoError(t, err)
	assert.False(t, stamped, "second call must report stamped=false (idempotent)")
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestIncrementMFAEnrollmentSkipCount_ReturnsNewCountWhenAllowed(t *testing.T) {
	ctx := context.Background()
	repo, mock := newUserRepo(t)
	userID := uuid.New()
	now := time.Now().UTC()

	// The regex asserts both gates that make this safe under
	// concurrent /skip POSTs from the same user: mfa_enabled = false
	// (no skip after enrollment completes mid-flight) AND deadline
	// guard. PostgreSQL row-lock under UPDATE … RETURNING serializes
	// concurrent increments, so the returned count is monotonically
	// correct without an explicit BEGIN/COMMIT.
	mock.ExpectQuery(`UPDATE iam_users\s+SET mfa_enrollment_skip_count = mfa_enrollment_skip_count \+ 1,\s+updated_at = NOW\(\)\s+WHERE id = \$1\s+AND mfa_enabled = false\s+AND \(mfa_enrollment_deadline IS NULL OR mfa_enrollment_deadline > \$2\)\s+RETURNING mfa_enrollment_skip_count`).
		WithArgs(userID, now).
		WillReturnRows(pgxmock.NewRows([]string{"mfa_enrollment_skip_count"}).AddRow(1))

	count, err := repo.IncrementMFAEnrollmentSkipCount(ctx, userID, now)
	require.NoError(t, err)
	assert.Equal(t, 1, count)
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestIncrementMFAEnrollmentSkipCount_ReturnsZeroWhenGateRejects(t *testing.T) {
	ctx := context.Background()
	repo, mock := newUserRepo(t)
	userID := uuid.New()
	now := time.Now().UTC()

	// Simulates the SQL guard firing: either deadline passed or user
	// already enrolled. pgx.ErrNoRows surfaces; the repo wraps it
	// into (0, nil) so the service treats it as "no skip granted".
	mock.ExpectQuery(`UPDATE iam_users`).
		WithArgs(userID, now).
		WillReturnRows(pgxmock.NewRows([]string{"mfa_enrollment_skip_count"}))

	count, err := repo.IncrementMFAEnrollmentSkipCount(ctx, userID, now)
	require.NoError(t, err)
	assert.Equal(t, 0, count, "gated rejection must return zero, not error")
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestResetMFAEnrollmentGraceTracking_ZeroesSkipCount(t *testing.T) {
	ctx := context.Background()
	repo, mock := newUserRepo(t)
	userID := uuid.New()

	// first_prompted_at + deadline intentionally NOT zeroed — they
	// remain queryable as "how long did this user take to enrol",
	// which is a SIEM / compliance signal.
	mock.ExpectExec(`UPDATE iam_users SET mfa_enrollment_skip_count = 0, updated_at = NOW\(\) WHERE id = \$1`).
		WithArgs(userID).
		WillReturnResult(pgxmock.NewResult("UPDATE", 1))

	err := repo.ResetMFAEnrollmentGraceTracking(ctx, userID)
	require.NoError(t, err)
	require.NoError(t, mock.ExpectationsWereMet())
}
