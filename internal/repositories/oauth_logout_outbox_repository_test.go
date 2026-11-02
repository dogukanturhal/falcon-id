// SPDX-License-Identifier: AGPL-3.0-or-later

package repositories

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/pashagolub/pgxmock/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newOutboxMock builds a pgxmock pool. The OAuthLogoutOutboxRepository
// struct holds a *pgxpool.Pool that we can't mock directly, BUT every
// method we exercise here takes a `tx DBTX` parameter and uses the
// mock instead of r.pool — so we construct the repo with pool=nil
// (PendingCount + AcquireDrainerSession + Try/ReleaseAdvisory + BeginTx
// require a real pool and are integration-tested against staging,
// not pgxmocked here).
func newOutboxMock(t *testing.T) (pgxmock.PgxPoolIface, *OAuthLogoutOutboxRepository) {
	t.Helper()
	mock, err := pgxmock.NewPool()
	require.NoError(t, err)
	// Repository with nil pool — only the tx-taking methods are
	// exercised. Insert with tx=nil falls back to r.pool, so we never
	// pass nil in these tests.
	return mock, &OAuthLogoutOutboxRepository{pool: nil}
}

func sampleOutboxRow(t *testing.T) *OAuthLogoutOutboxRow {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Microsecond)
	sub := "00000000-0000-0000-0000-000000000001"
	sid := "abc123"
	return &OAuthLogoutOutboxRow{
		ID:             uuid.MustParse("11111111-1111-1111-1111-111111111111"),
		RPClientID:     "svc-talon",
		LogoutTokenJTI: "jti-test-12345",
		Sub:            &sub,
		Sid:            &sid,
		TargetURI:      "https://auth.internal.example.com/auth/backchannel-logout",
		Payload:        "eyJhbGciOiJSUzI1NiJ9.fake-jwt",
		Status:         OAuthLogoutOutboxPending,
		AttemptCount:   0,
		NextRetryAt:    now,
		CreatedAt:      now,
	}
}

// TestOAuthLogoutOutboxRepository_Insert_Success exercises the canonical
// Insert path: a fresh row goes in, no errors. Asserts the column order
// matches the schema (pgxmock.QueryMatcherEqual would fail loudly on
// drift).
func TestOAuthLogoutOutboxRepository_Insert_Success(t *testing.T) {
	mock, repo := newOutboxMock(t)
	defer mock.Close()

	row := sampleOutboxRow(t)
	mock.ExpectExec("INSERT INTO iam_oauth_logout_outbox").
		WithArgs(
			row.ID, row.RPClientID, row.LogoutTokenJTI, row.Sub, row.Sid,
			row.TargetURI, row.Payload, string(row.Status), row.AttemptCount, row.NextRetryAt,
			row.LastError, row.CreatedAt, row.DeliveredAt,
		).
		WillReturnResult(pgxmock.NewResult("INSERT", 1))

	err := repo.Insert(context.Background(), mock, row)
	require.NoError(t, err)
	require.NoError(t, mock.ExpectationsWereMet())
}

// TestOAuthLogoutOutboxRepository_Insert_DefaultsApplied verifies that
// zero-valued Status / NextRetryAt / CreatedAt are filled in by Insert
// (idempotent default — caller need only set the load-bearing fields).
func TestOAuthLogoutOutboxRepository_Insert_DefaultsApplied(t *testing.T) {
	mock, repo := newOutboxMock(t)
	defer mock.Close()

	row := &OAuthLogoutOutboxRow{
		ID:             uuid.New(),
		RPClientID:     "svc-accounts",
		LogoutTokenJTI: "jti-defaults",
		TargetURI:      "https://accounts.hexxlock.com/api/auth/backchannel-logout",
		Payload:        "eyJ.fake",
	}
	// status, next_retry_at, created_at all start zero — assert
	// they're filled in. We can't pin exact times so use AnyArg for
	// the timestamps.
	mock.ExpectExec("INSERT INTO iam_oauth_logout_outbox").
		WithArgs(
			row.ID, row.RPClientID, row.LogoutTokenJTI, row.Sub, row.Sid,
			row.TargetURI, row.Payload, string(OAuthLogoutOutboxPending),
			row.AttemptCount,
			pgxmock.AnyArg(), // NextRetryAt — defaulted
			row.LastError,
			pgxmock.AnyArg(), // CreatedAt — defaulted
			row.DeliveredAt,
		).
		WillReturnResult(pgxmock.NewResult("INSERT", 1))

	err := repo.Insert(context.Background(), mock, row)
	require.NoError(t, err)

	// Defaults should be set on the supplied row in-place.
	assert.Equal(t, OAuthLogoutOutboxPending, row.Status)
	assert.False(t, row.NextRetryAt.IsZero(), "NextRetryAt default should fire")
	assert.False(t, row.CreatedAt.IsZero(), "CreatedAt default should fire")
}

// TestOAuthLogoutOutboxRepository_Insert_DuplicateJTI verifies the
// unique-constraint path: PG returns SQLSTATE 23505 → repo returns
// ErrOutboxDuplicateJTI sentinel. Callers (BackchannelLogoutService.NotifyLogout)
// SHOULD treat this as success — concurrent enqueue from a sibling pod.
func TestOAuthLogoutOutboxRepository_Insert_DuplicateJTI(t *testing.T) {
	mock, repo := newOutboxMock(t)
	defer mock.Close()

	row := sampleOutboxRow(t)
	mock.ExpectExec("INSERT INTO iam_oauth_logout_outbox").
		WithArgs(anyArgs(13)...).
		WillReturnError(&pgconn.PgError{
			Code:    "23505",
			Message: "duplicate key value violates unique constraint",
		})

	err := repo.Insert(context.Background(), mock, row)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrOutboxDuplicateJTI),
		"unique-violation must wrap ErrOutboxDuplicateJTI; got %v", err)
}

// TestOAuthLogoutOutboxRepository_Insert_NonUniqueErrPropagates: any
// other PG error is wrapped and surfaced to the caller (not silently
// swallowed). Verifies the boundary between idempotent-success
// (duplicate JTI) and genuine failure (anything else).
func TestOAuthLogoutOutboxRepository_Insert_NonUniqueErrPropagates(t *testing.T) {
	mock, repo := newOutboxMock(t)
	defer mock.Close()

	row := sampleOutboxRow(t)
	mock.ExpectExec("INSERT INTO iam_oauth_logout_outbox").
		WithArgs(anyArgs(13)...).
		WillReturnError(&pgconn.PgError{
			Code:    "23502", // not_null_violation
			Message: "null value in column violates not-null constraint",
		})

	err := repo.Insert(context.Background(), mock, row)
	require.Error(t, err)
	assert.False(t, errors.Is(err, ErrOutboxDuplicateJTI), "non-unique errors must NOT collapse to duplicate sentinel")
	assert.Contains(t, err.Error(), "outbox insert")
}

// TestOAuthLogoutOutboxRepository_MarkSent verifies the success-
// transition UPDATE: status='sent', delivered_at=now(), last_error=NULL.
func TestOAuthLogoutOutboxRepository_MarkSent(t *testing.T) {
	mock, repo := newOutboxMock(t)
	defer mock.Close()

	id := uuid.MustParse("22222222-2222-2222-2222-222222222222")
	mock.ExpectExec("UPDATE iam_oauth_logout_outbox").
		WithArgs(id).
		WillReturnResult(pgxmock.NewResult("UPDATE", 1))

	err := repo.MarkSent(context.Background(), mock, id)
	require.NoError(t, err)
	require.NoError(t, mock.ExpectationsWereMet())
}

// TestOAuthLogoutOutboxRepository_MarkRetry verifies the retry-
// transition UPDATE: attempt_count++, next_retry_at, last_error.
func TestOAuthLogoutOutboxRepository_MarkRetry(t *testing.T) {
	mock, repo := newOutboxMock(t)
	defer mock.Close()

	id := uuid.MustParse("33333333-3333-3333-3333-333333333333")
	nextAt := time.Now().UTC().Add(5 * time.Second)
	lastErr := "HTTP 502"
	mock.ExpectExec("UPDATE iam_oauth_logout_outbox").
		WithArgs(id, nextAt, lastErr).
		WillReturnResult(pgxmock.NewResult("UPDATE", 1))

	err := repo.MarkRetry(context.Background(), mock, id, lastErr, nextAt)
	require.NoError(t, err)
}

// TestOAuthLogoutOutboxRepository_MarkDead verifies the terminal-
// transition UPDATE: status='dead', last_error.
func TestOAuthLogoutOutboxRepository_MarkDead(t *testing.T) {
	mock, repo := newOutboxMock(t)
	defer mock.Close()

	id := uuid.MustParse("44444444-4444-4444-4444-444444444444")
	lastErr := "retry budget exhausted: HTTP 502"
	mock.ExpectExec("UPDATE iam_oauth_logout_outbox").
		WithArgs(id, lastErr).
		WillReturnResult(pgxmock.NewResult("UPDATE", 1))

	err := repo.MarkDead(context.Background(), mock, id, lastErr)
	require.NoError(t, err)
}

// TestOAuthLogoutOutboxRepository_SelectPendingForDelivery verifies the
// SELECT … FOR UPDATE SKIP LOCKED claim path: the repo iterates rows,
// converts the status string column to OAuthLogoutOutboxStatus, returns
// the slice.
func TestOAuthLogoutOutboxRepository_SelectPendingForDelivery(t *testing.T) {
	mock, repo := newOutboxMock(t)
	defer mock.Close()

	now := time.Now().UTC().Truncate(time.Microsecond)
	id1 := uuid.New()
	id2 := uuid.New()
	sub := "user-sub"
	sid := "session-sid"

	rows := pgxmock.NewRows([]string{
		"id", "rp_client_id", "logout_token_jti", "sub", "sid",
		"target_uri", "payload", "status", "attempt_count", "next_retry_at",
		"last_error", "created_at", "delivered_at",
	}).
		AddRow(id1, "svc-talon", "jti-1", &sub, &sid,
			"https://auth.internal.example.com/auth/backchannel-logout",
			"eyJ.fake1", "pending", 0, now, (*string)(nil), now, (*time.Time)(nil)).
		AddRow(id2, "svc-accounts", "jti-2", &sub, &sid,
			"https://accounts.hexxlock.com/api/auth/backchannel-logout",
			"eyJ.fake2", "pending", 1, now.Add(5*time.Second),
			strPtr("transient timeout"), now, (*time.Time)(nil))

	mock.ExpectQuery("SELECT").WithArgs(50).WillReturnRows(rows)

	out, err := repo.SelectPendingForDelivery(context.Background(), mock, 50)
	require.NoError(t, err)
	require.Len(t, out, 2)
	assert.Equal(t, OAuthLogoutOutboxPending, out[0].Status)
	assert.Equal(t, "svc-talon", out[0].RPClientID)
	assert.Equal(t, 1, out[1].AttemptCount)
	require.NotNil(t, out[1].LastError)
	assert.Equal(t, "transient timeout", *out[1].LastError)
}

// TestOAuthLogoutOutboxRepository_SelectPendingForDelivery_Empty
// verifies the empty-batch path returns nil slice + no error (drainer
// short-circuits this case).
func TestOAuthLogoutOutboxRepository_SelectPendingForDelivery_Empty(t *testing.T) {
	mock, repo := newOutboxMock(t)
	defer mock.Close()

	emptyRows := pgxmock.NewRows([]string{
		"id", "rp_client_id", "logout_token_jti", "sub", "sid",
		"target_uri", "payload", "status", "attempt_count", "next_retry_at",
		"last_error", "created_at", "delivered_at",
	})
	mock.ExpectQuery("SELECT").WithArgs(50).WillReturnRows(emptyRows)

	out, err := repo.SelectPendingForDelivery(context.Background(), mock, 50)
	require.NoError(t, err)
	assert.Empty(t, out)
}

func strPtr(s string) *string {
	return &s
}
