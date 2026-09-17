// SPDX-License-Identifier: AGPL-3.0-or-later

package repositories

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// CAEPEventOutboxStatus is the canonical status set on
// iam_caep_event_outbox.status. Values must match the table-level
// CHECK constraint in migration 0003_caep_event_outbox.sql.
type CAEPEventOutboxStatus string

const (
	// CAEPEventOutboxPending: enqueued, not yet attempted (or scheduled
	// for retry after a transient failure).
	CAEPEventOutboxPending CAEPEventOutboxStatus = "pending"
	// CAEPEventOutboxSent: HTTP 2xx received from receiver. Terminal state.
	CAEPEventOutboxSent CAEPEventOutboxStatus = "sent"
	// CAEPEventOutboxDead: retry budget exhausted OR receiver returned a
	// non-retryable 4xx. Terminal state. Surfaces in operator dashboard
	// for manual triage.
	CAEPEventOutboxDead CAEPEventOutboxStatus = "dead"
)

// CAEPEventOutboxRow models one row in iam_caep_event_outbox. Field
// types mirror the migration DDL exactly. NULLable columns
// (LastError, DeliveredAt) use pointers.
//
// Shape note: this is the deliberate sibling of OAuthLogoutOutboxRow —
// the BCL drainer pattern shipped wave 2 is the proven model, and
// keeping the row shapes near-identical means the drainer code can be
// a 1:1 fork with only event-specific delta in the deliver method.
type CAEPEventOutboxRow struct {
	ID            uuid.UUID
	StreamID      uuid.UUID
	EventType     string
	SubjectFormat string
	SubjectIss    string
	SubjectSub    string
	// EventData is the CAEP event-payload subobject; carries
	// event-specific claims (reason_admin, credential_type, etc).
	EventData       json.RawMessage
	Status          CAEPEventOutboxStatus
	AttemptCount    int
	NextRetryAt     time.Time
	LastError       *string
	TargetURI       string
	CreatedAt       time.Time
	DeliveredAt     *time.Time
}

// ErrCAEPOutboxStreamGone is returned by Insert when the supplied
// stream_id no longer exists (FK violation, e.g. concurrent stream
// delete during NotifyEvent). Callers SHOULD treat this as success —
// nothing to deliver to a deleted stream.
var ErrCAEPOutboxStreamGone = errors.New("caep outbox: stream_id no longer exists")

// CAEPEventOutboxRepository is the canonical accessor for
// iam_caep_event_outbox. Mirror of OAuthLogoutOutboxRepository.
//
// Concurrency notes:
//   - Insert is called from the CAEPEmitter outbox-path hot path; it
//     MUST be cheap (single round-trip).
//   - SelectPendingForDelivery uses FOR UPDATE SKIP LOCKED so
//     concurrent drainers (HA replicas) do not double-process rows.
//   - The drainer ALSO takes an advisory lock via TryLockAdvisory for
//     cross-replica single-flight (belt-and-suspenders with SKIP LOCKED).
type CAEPEventOutboxRepository struct {
	pool *pgxpool.Pool
}

// NewCAEPEventOutboxRepository constructs a repository against the
// supplied pgxpool. The pool is required (not optional) because the
// drainer needs Acquire to pin a connection for the advisory-lock
// session lifetime.
func NewCAEPEventOutboxRepository(pool *pgxpool.Pool) *CAEPEventOutboxRepository {
	return &CAEPEventOutboxRepository{pool: pool}
}

// Insert writes a single outbox row. The caller may supply a
// transaction (typically the same one used to commit the underlying
// state change — credential rotation, session terminate — for full
// transactional-outbox semantics). Pass nil to run on the pool
// directly.
//
// Returns ErrCAEPOutboxStreamGone on FK violation (stream_id removed
// between read and insert); callers SHOULD treat that as success.
func (r *CAEPEventOutboxRepository) Insert(ctx context.Context, tx DBTX, row *CAEPEventOutboxRow) error {
	const sql = `
INSERT INTO iam_caep_event_outbox (
    id, stream_id, event_type, subject_format, subject_iss, subject_sub,
    event_data, status, attempt_count, next_retry_at,
    last_error, target_uri, created_at, delivered_at
) VALUES (
    $1, $2, $3, $4, $5, $6,
    $7, $8, $9, $10,
    $11, $12, $13, $14
)
`
	exec := DBTX(r.pool)
	if tx != nil {
		exec = tx
	}
	if row.ID == uuid.Nil {
		row.ID = uuid.New()
	}
	if row.Status == "" {
		row.Status = CAEPEventOutboxPending
	}
	if row.SubjectFormat == "" {
		row.SubjectFormat = "iss_sub"
	}
	if len(row.EventData) == 0 {
		row.EventData = json.RawMessage("{}")
	}
	if row.NextRetryAt.IsZero() {
		row.NextRetryAt = time.Now().UTC()
	}
	if row.CreatedAt.IsZero() {
		row.CreatedAt = time.Now().UTC()
	}
	_, err := exec.Exec(ctx, sql,
		row.ID, row.StreamID, row.EventType, row.SubjectFormat, row.SubjectIss, row.SubjectSub,
		[]byte(row.EventData), string(row.Status), row.AttemptCount, row.NextRetryAt,
		row.LastError, row.TargetURI, row.CreatedAt, row.DeliveredAt,
	)
	if err != nil {
		// FK violation on stream_id — stream was deleted concurrently.
		// SQLSTATE 23503 = foreign_key_violation.
		var pgErr interface {
			SQLState() string
		}
		if errors.As(err, &pgErr) && pgErr.SQLState() == "23503" {
			return ErrCAEPOutboxStreamGone
		}
		return fmt.Errorf("caep outbox insert: %w", err)
	}
	return nil
}

// SelectPendingForDelivery returns up to limit rows whose status is
// 'pending' and whose next_retry_at has elapsed. Uses FOR UPDATE
// SKIP LOCKED so concurrent drainers never double-claim a row.
//
// Lock semantics identical to OAuthLogoutOutboxRepository — see that
// file's matching docstring.
func (r *CAEPEventOutboxRepository) SelectPendingForDelivery(ctx context.Context, tx DBTX, limit int) ([]CAEPEventOutboxRow, error) {
	const sql = `
SELECT id, stream_id, event_type, subject_format, subject_iss, subject_sub,
       event_data, status, attempt_count, next_retry_at,
       last_error, target_uri, created_at, delivered_at
  FROM iam_caep_event_outbox
 WHERE status = 'pending' AND next_retry_at <= now()
 ORDER BY next_retry_at
 LIMIT $1
   FOR UPDATE SKIP LOCKED
`
	rows, err := tx.Query(ctx, sql, limit)
	if err != nil {
		return nil, fmt.Errorf("caep outbox select pending: %w", err)
	}
	defer rows.Close()

	var out []CAEPEventOutboxRow
	for rows.Next() {
		var row CAEPEventOutboxRow
		var status string
		var data []byte
		if err := rows.Scan(
			&row.ID, &row.StreamID, &row.EventType, &row.SubjectFormat, &row.SubjectIss, &row.SubjectSub,
			&data, &status, &row.AttemptCount, &row.NextRetryAt,
			&row.LastError, &row.TargetURI, &row.CreatedAt, &row.DeliveredAt,
		); err != nil {
			return nil, fmt.Errorf("caep outbox scan: %w", err)
		}
		row.Status = CAEPEventOutboxStatus(status)
		row.EventData = json.RawMessage(data)
		out = append(out, row)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("caep outbox iterate: %w", err)
	}
	return out, nil
}

// MarkSent transitions a row to status='sent' with delivered_at=now().
func (r *CAEPEventOutboxRepository) MarkSent(ctx context.Context, tx DBTX, id uuid.UUID) error {
	const sql = `
UPDATE iam_caep_event_outbox
   SET status = 'sent',
       delivered_at = now(),
       last_error = NULL
 WHERE id = $1
`
	if _, err := tx.Exec(ctx, sql, id); err != nil {
		return fmt.Errorf("caep outbox mark sent: %w", err)
	}
	return nil
}

// MarkRetry increments attempt_count and reschedules next_retry_at.
func (r *CAEPEventOutboxRepository) MarkRetry(ctx context.Context, tx DBTX, id uuid.UUID, lastErr string, nextAttemptAt time.Time) error {
	const sql = `
UPDATE iam_caep_event_outbox
   SET attempt_count = attempt_count + 1,
       next_retry_at = $2,
       last_error = $3
 WHERE id = $1
`
	if _, err := tx.Exec(ctx, sql, id, nextAttemptAt, lastErr); err != nil {
		return fmt.Errorf("caep outbox mark retry: %w", err)
	}
	return nil
}

// MarkDead transitions a row to terminal status='dead'.
func (r *CAEPEventOutboxRepository) MarkDead(ctx context.Context, tx DBTX, id uuid.UUID, lastErr string) error {
	const sql = `
UPDATE iam_caep_event_outbox
   SET status = 'dead',
       last_error = $2
 WHERE id = $1
`
	if _, err := tx.Exec(ctx, sql, id, lastErr); err != nil {
		return fmt.Errorf("caep outbox mark dead: %w", err)
	}
	return nil
}

// PendingCount returns the count of rows in status='pending'.
// Cheap against idx_iam_caep_event_outbox_pending_retry.
func (r *CAEPEventOutboxRepository) PendingCount(ctx context.Context) (int64, error) {
	const sql = `SELECT count(*) FROM iam_caep_event_outbox WHERE status = 'pending'`
	var n int64
	if err := r.pool.QueryRow(ctx, sql).Scan(&n); err != nil {
		return 0, fmt.Errorf("caep outbox pending count: %w", err)
	}
	return n, nil
}

// AcquireDrainerSession returns a pinned connection for the drainer to
// hold for one drain tick. The caller MUST release the connection when
// done; failure to do so leaks a pool slot.
//
// Why pin: pg advisory locks are connection-scoped (held until
// pg_advisory_unlock or connection close). Without pinning we'd risk
// releasing the connection mid-drain.
func (r *CAEPEventOutboxRepository) AcquireDrainerSession(ctx context.Context) (*pgxpool.Conn, error) {
	c, err := r.pool.Acquire(ctx)
	if err != nil {
		return nil, fmt.Errorf("caep outbox acquire drainer session: %w", err)
	}
	return c, nil
}

// TryLockAdvisory takes the cross-replica advisory lock. Returns
// (true, nil) when the lock is held by this connection, (false, nil)
// when another replica already holds it.
func (r *CAEPEventOutboxRepository) TryLockAdvisory(ctx context.Context, conn *pgxpool.Conn, lockID int64) (bool, error) {
	const sql = `SELECT pg_try_advisory_lock($1)`
	var ok bool
	if err := conn.QueryRow(ctx, sql, lockID).Scan(&ok); err != nil {
		return false, fmt.Errorf("caep outbox try lock advisory: %w", err)
	}
	return ok, nil
}

// ReleaseAdvisory releases the advisory lock. Idempotent — a
// not-locked return doesn't surface as an error here.
func (r *CAEPEventOutboxRepository) ReleaseAdvisory(ctx context.Context, conn *pgxpool.Conn, lockID int64) error {
	const sql = `SELECT pg_advisory_unlock($1)`
	var ok bool
	if err := conn.QueryRow(ctx, sql, lockID).Scan(&ok); err != nil {
		return fmt.Errorf("caep outbox release advisory: %w", err)
	}
	_ = ok
	return nil
}

// BeginTx begins a transaction on the supplied pinned connection.
// The caller MUST commit or rollback.
func (r *CAEPEventOutboxRepository) BeginTx(ctx context.Context, conn *pgxpool.Conn) (pgx.Tx, error) {
	tx, err := conn.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("caep outbox begin tx: %w", err)
	}
	return tx, nil
}
