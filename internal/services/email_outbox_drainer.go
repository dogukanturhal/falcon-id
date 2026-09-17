// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/metrics"
	"github.com/dogukanturhal/falcon-id/internal/repositories"
)

// emailOutboxAdvisoryLockID is a stable 64-bit identifier passed to
// pg_try_advisory_lock for cross-replica drainer single-flight.
//
// ASCII "oalomail" — same naming pattern as the BCL drainer's
// "oalo_bcl" and the CAEP drainer's "oalocaep", so an operator reading
// pg_locks.locktype='advisory' can hex-decode the owner.
const emailOutboxAdvisoryLockID int64 = 0x6F61_6C6F_6D61_696C // ASCII "oalomail"

// emailOutboxBackoffSchedule defines per-attempt next_retry_at delta.
//
// Deliberately SHORTER-tailed than the CAEP schedule. These are
// human-facing notifications ("new device signed in", "password
// changed") — a security notice delivered 36 minutes late has largely
// lost its value, and the user has usually already noticed. Total
// budget: 5s+30s+2m+10m ≈ 12.6 min before the row moves to 'dead'.
//
// Note this is NOT the OTP path: credential mail never enters this
// table (see email_delivery_policy.go and the table CHECK constraint).
var emailOutboxBackoffSchedule = []time.Duration{
	5 * time.Second,
	30 * time.Second,
	2 * time.Minute,
	10 * time.Minute,
}

// EmailOutboxRepo is the minimal interface EmailOutboxDrainer needs.
// Defined here rather than imported wholesale so the service layer is
// testable without a real pgxpool — same rationale as CAEPOutboxRepo.
type EmailOutboxRepo interface {
	PendingCount(ctx context.Context) (int64, error)
	AcquireDrainerSession(ctx context.Context) (*pgxpool.Conn, error)
	TryLockAdvisory(ctx context.Context, conn *pgxpool.Conn, lockID int64) (bool, error)
	ReleaseAdvisory(ctx context.Context, conn *pgxpool.Conn, lockID int64) error
	BeginTx(ctx context.Context, conn *pgxpool.Conn) (pgx.Tx, error)
	SelectPendingForDelivery(ctx context.Context, tx repositories.DBTX, limit int) ([]repositories.EmailOutboxRow, error)
	MarkSent(ctx context.Context, tx repositories.DBTX, id uuid.UUID) error
	MarkRetry(ctx context.Context, tx repositories.DBTX, id uuid.UUID, lastErr string, nextAttemptAt time.Time) error
	MarkDead(ctx context.Context, tx repositories.DBTX, id uuid.UUID, lastErr string) error
}

// renderedSender delivers an already-rendered message. Satisfied by
// *EmailService (SendRendered). Kept narrow so the drainer can be
// tested without an SMTP dialer.
type renderedSender interface {
	SendRendered(ctx context.Context, tenantID uuid.UUID, template, to, subject, htmlBody string) error
}

// EmailOutboxDrainer drains iam_email_outbox in a single-flight,
// at-least-once fashion. Structural mirror of CAEPOutboxDrainer.
//
// WHAT IT DELIBERATELY DOES NOT CARRY
// ===================================
// Credential mail. One-time codes, password-reset and magic links are
// sent synchronously and never persisted — Falcon-ID stores only
// CodeHash today, and NIST SP 800-63B §5.1.3.2 bounds out-of-band auth
// at 10 minutes with single use, so a retried code is a dead code
// delivered after its window while a live one sat at rest. The
// classification lives in email_delivery_policy.go (MayQueue) and is
// enforced again by a CHECK constraint on the table.
type EmailOutboxDrainer struct {
	repo         EmailOutboxRepo
	sender       renderedSender
	tickInterval time.Duration
	batchSize    int
	logger       *zap.Logger
}

// EmailOutboxDrainerConfig holds operational knobs. Same shape as the
// CAEP and BCL drainers so operators keep one mental model.
type EmailOutboxDrainerConfig struct {
	// TickInterval is how often the drainer wakes up. Default 10s.
	TickInterval time.Duration
	// BatchSize bounds rows-per-tick. Default 50.
	BatchSize int
}

// DefaultEmailOutboxDrainerConfig returns conservative defaults.
//
// 10s rather than the CAEP drainer's 5s: notification mail is not
// latency-critical (the latency-critical path is synchronous by
// design), and a slower tick halves the idle query load.
func DefaultEmailOutboxDrainerConfig() EmailOutboxDrainerConfig {
	return EmailOutboxDrainerConfig{
		TickInterval: 10 * time.Second,
		BatchSize:    50,
	}
}

// NewEmailOutboxDrainer constructs a drainer. repo and sender MUST be
// non-nil; a nil logger is replaced with a no-op.
func NewEmailOutboxDrainer(repo EmailOutboxRepo, sender renderedSender, cfg EmailOutboxDrainerConfig, logger *zap.Logger) *EmailOutboxDrainer {
	if cfg.TickInterval <= 0 {
		cfg.TickInterval = 10 * time.Second
	}
	if cfg.BatchSize <= 0 {
		cfg.BatchSize = 50
	}
	if logger == nil {
		logger = zap.NewNop()
	}
	return &EmailOutboxDrainer{
		repo:         repo,
		sender:       sender,
		tickInterval: cfg.TickInterval,
		batchSize:    cfg.BatchSize,
		logger:       logger,
	}
}

// Start launches the drain loop. Blocks until ctx is cancelled.
func (d *EmailOutboxDrainer) Start(ctx context.Context) {
	if d == nil || d.repo == nil || d.sender == nil {
		return
	}
	d.logger.Info("EmailOutboxDrainer.Start: drain loop starting",
		zap.Duration("tick_interval", d.tickInterval),
		zap.Int("batch_size", d.batchSize),
	)
	ticker := time.NewTicker(d.tickInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			d.logger.Info("EmailOutboxDrainer.Start: context cancelled, exiting")
			return
		case <-ticker.C:
			d.drainOnce(ctx)
		}
	}
}

// drainOnce performs one drain cycle: pinned connection, cross-replica
// advisory lock, claim up to batchSize due rows, attempt delivery,
// update status. Errors are logged, never propagated — the next tick
// retries.
//
// Metric contract: every path records exactly ONE label-value of
// EmailOutboxDrainerIterations (drained/no_rows/no_lock/error) and
// observes EmailOutboxDrainerTickDuration.
func (d *EmailOutboxDrainer) drainOnce(ctx context.Context) {
	tickStart := time.Now()
	outcome := "error" // pessimistic default; overwritten on success paths
	defer func() {
		metrics.EmailOutboxDrainerIterations.WithLabelValues(outcome).Inc()
		metrics.EmailOutboxDrainerTickDuration.Observe(time.Since(tickStart).Seconds())
	}()

	if pending, err := d.repo.PendingCount(ctx); err != nil {
		d.logger.Warn("EmailOutboxDrainer.drainOnce: PendingCount failed", zap.Error(err))
	} else {
		metrics.EmailOutboxPending.Set(float64(pending))
	}

	conn, err := d.repo.AcquireDrainerSession(ctx)
	if err != nil {
		d.logger.Warn("EmailOutboxDrainer.drainOnce: failed to acquire drainer connection", zap.Error(err))
		return
	}
	defer conn.Release()

	locked, err := d.repo.TryLockAdvisory(ctx, conn, emailOutboxAdvisoryLockID)
	if err != nil {
		d.logger.Warn("EmailOutboxDrainer.drainOnce: advisory lock probe failed", zap.Error(err))
		return
	}
	if !locked {
		d.logger.Debug("EmailOutboxDrainer.drainOnce: another replica holds the lock, skipping")
		outcome = "no_lock"
		return
	}
	defer func() {
		// Background ctx so a cancelled drain still frees the lock.
		if err := d.repo.ReleaseAdvisory(context.Background(), conn, emailOutboxAdvisoryLockID); err != nil {
			d.logger.Warn("EmailOutboxDrainer.drainOnce: failed to release advisory lock", zap.Error(err))
		}
	}()

	tx, err := d.repo.BeginTx(ctx, conn)
	if err != nil {
		d.logger.Warn("EmailOutboxDrainer.drainOnce: BeginTx failed", zap.Error(err))
		return
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback(context.Background())
		}
	}()

	rows, err := d.repo.SelectPendingForDelivery(ctx, tx, d.batchSize)
	if err != nil {
		d.logger.Warn("EmailOutboxDrainer.drainOnce: SelectPendingForDelivery failed", zap.Error(err))
		return
	}
	if len(rows) == 0 {
		if commitErr := tx.Commit(ctx); commitErr != nil {
			d.logger.Warn("EmailOutboxDrainer.drainOnce: empty-batch commit failed", zap.Error(commitErr))
			return
		}
		committed = true
		outcome = "no_rows"
		return
	}

	for _, row := range rows {
		d.deliverRow(ctx, tx, row)
	}

	if err := tx.Commit(ctx); err != nil {
		d.logger.Warn("EmailOutboxDrainer.drainOnce: commit failed", zap.Error(err))
		return
	}
	committed = true
	outcome = "drained"
}

// deliverRow attempts SMTP delivery for one row and updates its status.
//
//	success                     → MarkSent (and the body is blanked)
//	retry budget remaining      → MarkRetry with backoff
//	budget exhausted            → MarkDead
//
// Note there is no 4xx/5xx split as in the CAEP drainer: gomail's
// DialAndSend collapses transport and protocol failures into one error,
// and a permanent SMTP rejection (bad recipient) is rare on this path
// because recipients are our own users. Everything is treated as
// retryable until the budget runs out, which fails safe — a genuinely
// undeliverable row lands in 'dead' after ~12.6 min rather than being
// discarded on the first error.
func (d *EmailOutboxDrainer) deliverRow(ctx context.Context, tx repositories.DBTX, row repositories.EmailOutboxRow) {
	err := d.sender.SendRendered(ctx, row.TenantID, row.Template, row.Recipient, row.Subject, row.BodyHTML)
	if err == nil {
		if markErr := d.repo.MarkSent(ctx, tx, row.ID); markErr != nil {
			d.logger.Warn("EmailOutboxDrainer.deliverRow: MarkSent failed",
				zap.String("id", row.ID.String()), zap.Error(markErr))
		}
		return
	}

	// Truncate: last_error is operator-facing, and an SMTP error can
	// echo back a large server banner.
	reason := err.Error()
	if len(reason) > 500 {
		reason = reason[:500]
	}
	// Defence in depth — an SMTP server echoing the message back into an
	// error string must not persist a body into last_error.
	reason = strings.ReplaceAll(reason, "\n", " ")

	attempt := row.AttemptCount // attempts already made
	if attempt >= len(emailOutboxBackoffSchedule) {
		d.logger.Warn("EmailOutboxDrainer.deliverRow: retry budget exhausted, marking dead",
			zap.String("id", row.ID.String()),
			zap.String("template", row.Template),
			zap.Int("attempts", attempt),
			zap.Error(err),
		)
		if markErr := d.repo.MarkDead(ctx, tx, row.ID, reason); markErr != nil {
			d.logger.Warn("EmailOutboxDrainer.deliverRow: MarkDead failed",
				zap.String("id", row.ID.String()), zap.Error(markErr))
		}
		return
	}

	next := time.Now().Add(emailOutboxBackoffSchedule[attempt])
	d.logger.Info("EmailOutboxDrainer.deliverRow: delivery failed, scheduling retry",
		zap.String("id", row.ID.String()),
		zap.String("template", row.Template),
		zap.Int("attempt", attempt+1),
		zap.Time("next_retry_at", next),
		zap.Error(err),
	)
	if markErr := d.repo.MarkRetry(ctx, tx, row.ID, reason, next); markErr != nil {
		d.logger.Warn("EmailOutboxDrainer.deliverRow: MarkRetry failed",
			zap.String("id", row.ID.String()), zap.Error(markErr))
	}
}

// ErrTemplateNotQueueable is returned by the enqueue path when a caller
// attempts to queue a credential-bearing (or unclassified) template.
var ErrTemplateNotQueueable = errors.New("template may not be queued: credential-bearing or unclassified")
