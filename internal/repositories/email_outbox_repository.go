// SPDX-License-Identifier: AGPL-3.0-or-later

package repositories

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// EmailOutboxStatus is the canonical status set on
// iam_email_outbox.status. Values must match the table-level CHECK
// constraint in migration 0010_email_outbox.sql.
type EmailOutboxStatus string

const (
	// EmailOutboxPending: enqueued, not yet attempted (or rescheduled
	// after a transient failure).
	EmailOutboxPending EmailOutboxStatus = "pending"
	// EmailOutboxSent: the relay accepted the message. Terminal.
	EmailOutboxSent EmailOutboxStatus = "sent"
	// EmailOutboxDead: retry budget exhausted, or a permanent failure
	// such as SMTP unconfigured for the tenant. Terminal; surfaces for
	// manual triage.
	EmailOutboxDead EmailOutboxStatus = "dead"
)

// EmailOutboxRow models one row in iam_email_outbox. Field types mirror
// the migration DDL exactly; NULLable columns use pointers.
//
// Deliberate sibling of CAEPEventOutboxRow and OAuthLogoutOutboxRow —
// keeping the shapes near-identical is what lets the drainer be a close
// fork with only the delivery method differing.
//
// ⚠ Template is constrained BOTH here (via services.MayQueue on the
// enqueue path) and by a CHECK constraint on the table listing only the
// eight non-credential templates. Credential-bearing mail — one-time
// codes, password-reset and magic links — is never persisted: Falcon-ID
// stores only CodeHash today, and NIST SP 800-63B §5.1.3.2 bounds
// out-of-band auth at 10 minutes with single use, so a retried code is
// a dead code. See internal/services/email_delivery_policy.go.
type EmailOutboxRow struct {
	ID           uuid.UUID
	TenantID     uuid.UUID
	Template     string
	Recipient    string
	Subject      string
	BodyHTML     string
	Status       EmailOutboxStatus
	AttemptCount int
	NextRetryAt  time.Time
	LastError    *string
	CreatedAt    time.Time
	DeliveredAt  *time.Time
}

// EmailOutboxRepository is the data-access layer for iam_email_outbox.
type EmailOutboxRepository struct {
	pool *pgxpool.Pool
}

// NewEmailOutboxRepository constructs the repository.
func NewEmailOutboxRepository(pool *pgxpool.Pool) *EmailOutboxRepository {
	return &EmailOutboxRepository{pool: pool}
}

// Insert enqueues one message.
//
// Takes a DBTX so the enqueue can join the caller's transaction — that
// is the whole point of a transactional outbox: the row and the business
// change commit together, or neither does.
//
// The template is NOT validated here. Validation belongs on the service
// side (services.MayQueue) with the table CHECK as the backstop; a bad
// template reaches Postgres and errors, which is the safe direction.
func (r *EmailOutboxRepository) Insert(ctx context.Context, tx DBTX, row *EmailOutboxRow) error {
	const sql = `
INSERT INTO iam_email_outbox (tenant_id, template, recipient, subject, body_html)
VALUES ($1, $2, $3, $4, $5)
RETURNING id, status, attempt_count, next_retry_at, created_at
`
	var status string
	if err := tx.QueryRow(ctx, sql,
		row.TenantID, row.Template, row.Recipient, row.Subject, row.BodyHTML,
	).Scan(&row.ID, &status, &row.AttemptCount, &row.NextRetryAt, &row.CreatedAt); err != nil {
		return fmt.Errorf("email outbox insert: %w", err)
	}
	row.Status = EmailOutboxStatus(status)
	return nil
}

// SelectPendingForDelivery claims up to limit due rows.
//
// FOR UPDATE SKIP LOCKED so concurrent drainers never contend on the
// same row; combined with the cross-replica advisory lock this gives
// single-flight drain with no duplicate sends in the common path.
func (r *EmailOutboxRepository) SelectPendingForDelivery(ctx context.Context, tx DBTX, limit int) ([]EmailOutboxRow, error) {
	const sql = `
SELECT id, tenant_id, template, recipient, subject, body_html,
       status, attempt_count, next_retry_at, last_error,
       created_at, delivered_at
  FROM iam_email_outbox
 WHERE status = 'pending' AND next_retry_at <= now()
 ORDER BY next_retry_at
 LIMIT $1
   FOR UPDATE SKIP LOCKED
`
	rows, err := tx.Query(ctx, sql, limit)
	if err != nil {
		return nil, fmt.Errorf("email outbox select pending: %w", err)
	}
	defer rows.Close()

	var out []EmailOutboxRow
	for rows.Next() {
		var row EmailOutboxRow
		var status string
		if err := rows.Scan(
			&row.ID, &row.TenantID, &row.Template, &row.Recipient, &row.Subject, &row.BodyHTML,
			&status, &row.AttemptCount, &row.NextRetryAt, &row.LastError,
			&row.CreatedAt, &row.DeliveredAt,
		); err != nil {
			return nil, fmt.Errorf("email outbox scan: %w", err)
		}
		row.Status = EmailOutboxStatus(status)
		out = append(out, row)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("email outbox iterate: %w", err)
	}
	return out, nil
}

// MarkSent transitions a row to status='sent' with delivered_at=now().
//
// body_html is blanked at the same time. The bodies here are
// non-credential by construction, but they still carry PII (recipient
// address, and for security notices the device / location / IP strings
// that triggered them). Once delivered there is no reason to keep the
// rendered copy; the row remains as the audit trail.
func (r *EmailOutboxRepository) MarkSent(ctx context.Context, tx DBTX, id uuid.UUID) error {
	const sql = `
UPDATE iam_email_outbox
   SET status = 'sent',
       delivered_at = now(),
       last_error = NULL,
       body_html = ''
 WHERE id = $1
`
	if _, err := tx.Exec(ctx, sql, id); err != nil {
		return fmt.Errorf("email outbox mark sent: %w", err)
	}
	return nil
}

// MarkRetry increments attempt_count and reschedules next_retry_at.
func (r *EmailOutboxRepository) MarkRetry(ctx context.Context, tx DBTX, id uuid.UUID, lastErr string, nextAttemptAt time.Time) error {
	const sql = `
UPDATE iam_email_outbox
   SET attempt_count = attempt_count + 1,
       next_retry_at = $2,
       last_error = $3
 WHERE id = $1
`
	if _, err := tx.Exec(ctx, sql, id, nextAttemptAt, lastErr); err != nil {
		return fmt.Errorf("email outbox mark retry: %w", err)
	}
	return nil
}

// MarkDead transitions a row to terminal status='dead'.
//
// Also blanks body_html — a dead row is triaged from last_error,
// template and recipient; retaining the rendered PII indefinitely for a
// message that will never be sent serves no purpose.
func (r *EmailOutboxRepository) MarkDead(ctx context.Context, tx DBTX, id uuid.UUID, lastErr string) error {
	const sql = `
UPDATE iam_email_outbox
   SET status = 'dead',
       last_error = $2,
       body_html = ''
 WHERE id = $1
`
	if _, err := tx.Exec(ctx, sql, id, lastErr); err != nil {
		return fmt.Errorf("email outbox mark dead: %w", err)
	}
	return nil
}

// PendingCount returns the count of rows in status='pending'.
// Cheap against idx_iam_email_outbox_pending_retry.
func (r *EmailOutboxRepository) PendingCount(ctx context.Context) (int64, error) {
	const sql = `SELECT count(*) FROM iam_email_outbox WHERE status = 'pending'`
	var n int64
	if err := r.pool.QueryRow(ctx, sql).Scan(&n); err != nil {
		return 0, fmt.Errorf("email outbox pending count: %w", err)
	}
	return n, nil
}

// PruneDelivered deletes sent rows older than the retention window and
// returns how many were removed.
func (r *EmailOutboxRepository) PruneDelivered(ctx context.Context, olderThan time.Duration) (int64, error) {
	const sql = `
DELETE FROM iam_email_outbox
 WHERE status = 'sent'
   AND delivered_at < now() - $1::interval
`
	tag, err := r.pool.Exec(ctx, sql, olderThan.String())
	if err != nil {
		return 0, fmt.Errorf("email outbox prune delivered: %w", err)
	}
	return tag.RowsAffected(), nil
}

// AcquireDrainerSession returns a pinned connection for one drain tick.
// The caller MUST release it; failing to do so leaks a pool slot.
//
// Why pin: pg advisory locks are connection-scoped (held until
// pg_advisory_unlock or the connection closes), so the lock and the
// drain must share one connection.
func (r *EmailOutboxRepository) AcquireDrainerSession(ctx context.Context) (*pgxpool.Conn, error) {
	c, err := r.pool.Acquire(ctx)
	if err != nil {
		return nil, fmt.Errorf("email outbox acquire drainer session: %w", err)
	}
	return c, nil
}

// TryLockAdvisory takes the cross-replica advisory lock. Returns
// (true, nil) when held by this connection, (false, nil) when another
// replica already holds it.
func (r *EmailOutboxRepository) TryLockAdvisory(ctx context.Context, conn *pgxpool.Conn, lockID int64) (bool, error) {
	const sql = `SELECT pg_try_advisory_lock($1)`
	var ok bool
	if err := conn.QueryRow(ctx, sql, lockID).Scan(&ok); err != nil {
		return false, fmt.Errorf("email outbox try lock advisory: %w", err)
	}
	return ok, nil
}

// ReleaseAdvisory releases the advisory lock. Idempotent — a
// not-locked return does not surface as an error.
func (r *EmailOutboxRepository) ReleaseAdvisory(ctx context.Context, conn *pgxpool.Conn, lockID int64) error {
	const sql = `SELECT pg_advisory_unlock($1)`
	var ok bool
	if err := conn.QueryRow(ctx, sql, lockID).Scan(&ok); err != nil {
		return fmt.Errorf("email outbox release advisory: %w", err)
	}
	_ = ok
	return nil
}

// BeginTx begins a transaction on the supplied pinned connection.
// The caller MUST commit or rollback.
func (r *EmailOutboxRepository) BeginTx(ctx context.Context, conn *pgxpool.Conn) (pgx.Tx, error) {
	tx, err := conn.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("email outbox begin tx: %w", err)
	}
	return tx, nil
}
