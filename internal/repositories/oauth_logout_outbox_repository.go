// SPDX-License-Identifier: AGPL-3.0-or-later

package repositories

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// OAuthLogoutOutboxStatus is the canonical status set on
// iam_oauth_logout_outbox.status. Values must match the table-level
// CHECK constraint in keystone bundle falcon-id-v0.234.234.
type OAuthLogoutOutboxStatus string

const (
	// OAuthLogoutOutboxPending: enqueued, not yet attempted (or scheduled
	// for retry after a transient failure).
	OAuthLogoutOutboxPending OAuthLogoutOutboxStatus = "pending"
	// OAuthLogoutOutboxSent: HTTP 2xx received from RP. Terminal state.
	OAuthLogoutOutboxSent OAuthLogoutOutboxStatus = "sent"
	// OAuthLogoutOutboxDead: retry budget exhausted OR RP returned a
	// non-retryable 4xx. Terminal state. Surfaces in operator dashboard
	// for manual triage.
	OAuthLogoutOutboxDead OAuthLogoutOutboxStatus = "dead"
)

// OAuthLogoutOutboxRow models one row in iam_oauth_logout_outbox. Field
// types mirror the keystone bundle DDL exactly; UUID + TEXT + INT +
// TIMESTAMPTZ map to uuid.UUID / string / int / time.Time. NULLable
// columns (sub, sid, last_error, delivered_at) use *string / *time.Time.
type OAuthLogoutOutboxRow struct {
	ID             uuid.UUID
	RPClientID     string
	LogoutTokenJTI string
	Sub            *string
	Sid            *string
	TargetURI      string
	Payload        string
	Status         OAuthLogoutOutboxStatus
	AttemptCount   int
	NextRetryAt    time.Time
	LastError      *string
	CreatedAt      time.Time
	DeliveredAt    *time.Time
}

// ErrOutboxDuplicateJTI is returned by Insert when the unique
// constraint on logout_token_jti fires. Callers SHOULD treat this as
// success — it means a concurrent NotifyLogout already enqueued the
// row and our INSERT was the loser.
var ErrOutboxDuplicateJTI = errors.New("outbox row already exists for this JTI")

// OAuthLogoutOutboxRepository is the canonical accessor for
// iam_oauth_logout_outbox. The table backs the BCL transactional
// outbox introduced in keystone bundle falcon-id-v0.234.234 (Phase 2a
// of the 2026-05-10 SLO restoration plan).
//
// Concurrency notes:
//   - Insert is called from BackchannelLogoutService.NotifyLogout in
//     the request hot path; it MUST be cheap (single round-trip).
//   - SelectPendingForDelivery is called by the drainer goroutine on
//     every tick; it uses FOR UPDATE SKIP LOCKED so concurrent
//     drainers (HA replicas without advisory-lock single-flight) do
//     not double-process rows.
//   - The drainer ALSO takes an advisory lock for cross-replica
//     serialization (TryLockAdvisory). The SKIP LOCKED + advisory lock
//     belt-and-suspenders pair is intentional: advisory lock failure
//     (e.g., split-brain Postgres) should not produce duplicate
//     deliveries.
type OAuthLogoutOutboxRepository struct {
	pool *pgxpool.Pool
}

// NewOAuthLogoutOutboxRepository constructs a repository against the
// supplied pgxpool. The pool is required (not optional) because the
// drainer needs Acquire to pin a connection for the advisory-lock
// session lifetime.
func NewOAuthLogoutOutboxRepository(pool *pgxpool.Pool) *OAuthLogoutOutboxRepository {
	return &OAuthLogoutOutboxRepository{pool: pool}
}

// Insert writes a single outbox row. The caller may supply a
// transaction (typically the same one used to commit session
// termination, for full transactional-outbox semantics). Pass nil to
// have Insert run on the pool directly.
//
// Returns ErrOutboxDuplicateJTI on UNIQUE(logout_token_jti) violation;
// callers SHOULD treat that as success.
func (r *OAuthLogoutOutboxRepository) Insert(ctx context.Context, tx DBTX, row *OAuthLogoutOutboxRow) error {
	const sql = `
INSERT INTO iam_oauth_logout_outbox (
    id, rp_client_id, logout_token_jti, sub, sid,
    target_uri, payload, status, attempt_count, next_retry_at,
    last_error, created_at, delivered_at
) VALUES (
    $1, $2, $3, $4, $5,
    $6, $7, $8, $9, $10,
    $11, $12, $13
)
`
	exec := DBTX(r.pool)
	if tx != nil {
		exec = tx
	}
	if row.Status == "" {
		row.Status = OAuthLogoutOutboxPending
	}
	if row.NextRetryAt.IsZero() {
		row.NextRetryAt = time.Now().UTC()
	}
	if row.CreatedAt.IsZero() {
		row.CreatedAt = time.Now().UTC()
	}
	_, err := exec.Exec(ctx, sql,
		row.ID, row.RPClientID, row.LogoutTokenJTI, row.Sub, row.Sid,
		row.TargetURI, row.Payload, string(row.Status), row.AttemptCount, row.NextRetryAt,
		row.LastError, row.CreatedAt, row.DeliveredAt,
	)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return ErrOutboxDuplicateJTI
		}
		return fmt.Errorf("outbox insert: %w", err)
	}
	return nil
}

// SelectPendingForDelivery returns up to limit rows whose status is
// 'pending' and whose next_retry_at has elapsed. Uses FOR UPDATE
// SKIP LOCKED so concurrent drainers (or this drainer's overlapping
// ticks) never double-claim a row.
//
// IMPORTANT: the rows are locked for the duration of the supplied
// transaction. The drainer is expected to:
//
//  1. BEGIN tx
//  2. SelectPendingForDelivery(ctx, tx, N) → claim rows
//  3. For each row, attempt HTTP delivery and call MarkSent / MarkRetry
//     / MarkDead on the SAME tx
//  4. COMMIT tx — releases locks atomically with status updates.
//
// HTTP delivery happens INSIDE the held lock window. To bound latency
// the drainer enforces an HTTPTimeout per row + a global drain-tick
// budget; rows that fail timeout are simply MarkRetry'd and unlocked
// at COMMIT.
func (r *OAuthLogoutOutboxRepository) SelectPendingForDelivery(ctx context.Context, tx DBTX, limit int) ([]OAuthLogoutOutboxRow, error) {
	const sql = `
SELECT id, rp_client_id, logout_token_jti, sub, sid,
       target_uri, payload, status, attempt_count, next_retry_at,
       last_error, created_at, delivered_at
  FROM iam_oauth_logout_outbox
 WHERE status = 'pending' AND next_retry_at <= now()
 ORDER BY next_retry_at
 LIMIT $1
   FOR UPDATE SKIP LOCKED
`
	rows, err := tx.Query(ctx, sql, limit)
	if err != nil {
		return nil, fmt.Errorf("outbox select pending: %w", err)
	}
	defer rows.Close()

	var out []OAuthLogoutOutboxRow
	for rows.Next() {
		var row OAuthLogoutOutboxRow
		var status string
		if err := rows.Scan(
			&row.ID, &row.RPClientID, &row.LogoutTokenJTI, &row.Sub, &row.Sid,
			&row.TargetURI, &row.Payload, &status, &row.AttemptCount, &row.NextRetryAt,
			&row.LastError, &row.CreatedAt, &row.DeliveredAt,
		); err != nil {
			return nil, fmt.Errorf("outbox scan: %w", err)
		}
		row.Status = OAuthLogoutOutboxStatus(status)
		out = append(out, row)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("outbox iterate: %w", err)
	}
	return out, nil
}

// MarkSent transitions a row to status='sent' with delivered_at=now().
// Caller must run under a transaction that holds the row lock (via
// SelectPendingForDelivery FOR UPDATE).
func (r *OAuthLogoutOutboxRepository) MarkSent(ctx context.Context, tx DBTX, id uuid.UUID) error {
	const sql = `
UPDATE iam_oauth_logout_outbox
   SET status = 'sent',
       delivered_at = now(),
       last_error = NULL
 WHERE id = $1
`
	if _, err := tx.Exec(ctx, sql, id); err != nil {
		return fmt.Errorf("outbox mark sent: %w", err)
	}
	return nil
}

// MarkRetry increments attempt_count and reschedules next_retry_at to
// nextAttemptAt. last_error is captured for diagnostics.
func (r *OAuthLogoutOutboxRepository) MarkRetry(ctx context.Context, tx DBTX, id uuid.UUID, lastErr string, nextAttemptAt time.Time) error {
	const sql = `
UPDATE iam_oauth_logout_outbox
   SET attempt_count = attempt_count + 1,
       next_retry_at = $2,
       last_error = $3
 WHERE id = $1
`
	if _, err := tx.Exec(ctx, sql, id, nextAttemptAt, lastErr); err != nil {
		return fmt.Errorf("outbox mark retry: %w", err)
	}
	return nil
}

// MarkDead transitions a row to terminal status='dead' (retry budget
// exhausted or non-retryable upstream response). Surfaces in the
// operator dashboard for manual triage.
func (r *OAuthLogoutOutboxRepository) MarkDead(ctx context.Context, tx DBTX, id uuid.UUID, lastErr string) error {
	const sql = `
UPDATE iam_oauth_logout_outbox
   SET status = 'dead',
       last_error = $2
 WHERE id = $1
`
	if _, err := tx.Exec(ctx, sql, id, lastErr); err != nil {
		return fmt.Errorf("outbox mark dead: %w", err)
	}
	return nil
}

// PendingCount returns the count of rows in status='pending'. Cheap
// against the partial index idx_iam_oauth_logout_outbox_pending_retry.
// Used by the drainer to update the iam_oauth_bcl_outbox_pending gauge.
func (r *OAuthLogoutOutboxRepository) PendingCount(ctx context.Context) (int64, error) {
	const sql = `SELECT count(*) FROM iam_oauth_logout_outbox WHERE status = 'pending'`
	var n int64
	if err := r.pool.QueryRow(ctx, sql).Scan(&n); err != nil {
		return 0, fmt.Errorf("outbox pending count: %w", err)
	}
	return n, nil
}

// AcquireDrainerSession returns a pinned connection for the drainer to
// hold for one drain tick. The caller MUST release the connection when
// done; failure to do so leaks a pool slot.
//
// Why pin a connection: PostgreSQL advisory locks are connection-
// scoped (pg_try_advisory_lock holds the lock until the connection
// closes or pg_advisory_unlock fires). Without pinning we'd risk
// releasing the connection (and lock) mid-drain.
func (r *OAuthLogoutOutboxRepository) AcquireDrainerSession(ctx context.Context) (*pgxpool.Conn, error) {
	c, err := r.pool.Acquire(ctx)
	if err != nil {
		return nil, fmt.Errorf("outbox acquire drainer conn: %w", err)
	}
	return c, nil
}

// TryLockAdvisory is a thin wrapper over pg_try_advisory_lock that
// tries to acquire a session-level advisory lock identified by lockID.
// Returns (true, nil) on success, (false, nil) if held by another
// session, (false, err) on transport failure.
func (r *OAuthLogoutOutboxRepository) TryLockAdvisory(ctx context.Context, conn *pgxpool.Conn, lockID int64) (bool, error) {
	var locked bool
	if err := conn.QueryRow(ctx, "SELECT pg_try_advisory_lock($1)", lockID).Scan(&locked); err != nil {
		return false, fmt.Errorf("outbox try advisory lock: %w", err)
	}
	return locked, nil
}

// ReleaseAdvisory releases an advisory lock previously acquired by
// TryLockAdvisory. Best-effort: errors are returned but the caller
// should already be on the shutdown path.
func (r *OAuthLogoutOutboxRepository) ReleaseAdvisory(ctx context.Context, conn *pgxpool.Conn, lockID int64) error {
	var ok bool
	if err := conn.QueryRow(ctx, "SELECT pg_advisory_unlock($1)", lockID).Scan(&ok); err != nil {
		return fmt.Errorf("outbox release advisory lock: %w", err)
	}
	if !ok {
		return errors.New("outbox release advisory lock: lock was not held by this session")
	}
	return nil
}

// BeginTx starts a transaction on the supplied pinned connection. The
// drainer uses this so the FOR UPDATE row locks held during delivery
// are released on the SAME connection that holds the advisory lock.
func (r *OAuthLogoutOutboxRepository) BeginTx(ctx context.Context, conn *pgxpool.Conn) (pgx.Tx, error) {
	return conn.Begin(ctx)
}
