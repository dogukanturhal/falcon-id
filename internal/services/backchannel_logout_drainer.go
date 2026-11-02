// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/repositories"
	"github.com/dogukanturhal/falcon-id/pkg/metrics"
)

// outboxAdvisoryLockID is a stable 64-bit identifier passed to
// pg_try_advisory_lock for cross-replica drainer single-flight.
//
// Chosen as 8 ASCII bytes "oalo_bcl" (oalo = oauth_logout_outbox,
// bcl = back-channel logout) so an operator inspecting
// pg_locks.locktype='advisory' can read the lock by hex-decode.
// Any non-zero int64 works — the value just needs to be globally
// recognised within the DB cluster's advisory-lock namespace.
const outboxAdvisoryLockID int64 = 0x6F61_6C6F_5F62_636C // ASCII "oalo_bcl"

// outboxBackoffSchedule defines the per-attempt next_retry_at delta.
// Attempts are 1-indexed: schedule[0] = first retry after attempt 1
// failed. After len(schedule) failures the row transitions to
// status='dead'. Total budget: 1s+5s+30s+5m+30m ≈ 35.6 min worst-case.
//
// Tuned for tier-1 receivers (Talon, accounts BFF, gitlab/harbor
// shims) which should respond in <500ms p99; a row taking >35min to
// deliver is genuinely stuck and pages on-call.
var outboxBackoffSchedule = []time.Duration{
	1 * time.Second,
	5 * time.Second,
	30 * time.Second,
	5 * time.Minute,
	30 * time.Minute,
}

// BackchannelLogoutOutboxRepo is the minimal interface
// BackchannelLogoutDrainer needs from the outbox repository.
// Defined here (rather than imported from internal/repositories) to
// keep the service layer testable without spinning a real pgxpool.
type BackchannelLogoutOutboxRepo interface {
	AcquireDrainerSession(ctx context.Context) (*pgxpool.Conn, error)
	TryLockAdvisory(ctx context.Context, conn *pgxpool.Conn, lockID int64) (bool, error)
	ReleaseAdvisory(ctx context.Context, conn *pgxpool.Conn, lockID int64) error
	BeginTx(ctx context.Context, conn *pgxpool.Conn) (pgx.Tx, error)
	SelectPendingForDelivery(ctx context.Context, tx repositories.DBTX, limit int) ([]repositories.OAuthLogoutOutboxRow, error)
	MarkSent(ctx context.Context, tx repositories.DBTX, id uuid.UUID) error
	MarkRetry(ctx context.Context, tx repositories.DBTX, id uuid.UUID, lastErr string, nextAttemptAt time.Time) error
	MarkDead(ctx context.Context, tx repositories.DBTX, id uuid.UUID, lastErr string) error
	PendingCount(ctx context.Context) (int64, error)
}

// BackchannelLogoutDrainer drains iam_oauth_logout_outbox in a single
// background goroutine, serialised across HA replicas via a Postgres
// session-level advisory lock. Implements the persistent retry layer
// that replaces the in-memory loop in BackchannelLogoutService.
//
// The drainer itself does NOT emit audit events. The writer-side
// `BackchannelLogoutService.enqueueOne` emits a `bcl_enqueued` event
// with the full tenant context; subsequent state transitions
// (sent / dead) are visible in the outbox table directly + the
// `iam_oauth_bcl_outbox_dead_total` Prometheus counter. Audit-archive
// consumers join the enqueued event with the row's final state via
// the JTI.
//
// Why no drainer-side emission: the outbox schema doesn't carry
// tenant_id, so the drainer can't address the integration-bus
// X-Tenant-ID header correctly without a join back to iam_users.sub →
// iam_users.tenant_id (extra DB hop on the hot path, plus the user
// row may have been deleted by the time the drainer fires). Adding
// tenant_id to the outbox schema is a follow-up if forensic queries
// turn out to need per-state-transition rows beyond the join via JTI.
type BackchannelLogoutDrainer struct {
	repo         BackchannelLogoutOutboxRepo
	httpClient   *http.Client
	tickInterval time.Duration
	batchSize    int
	logger       *zap.Logger
}

// BackchannelLogoutDrainerConfig holds operational knobs.
type BackchannelLogoutDrainerConfig struct {
	// TickInterval is how often the drainer wakes up and tries to drain
	// pending rows. Default 5s — fast enough that user-driven Sign Out
	// propagates within 5s under steady state, slow enough that we
	// don't hammer the DB with empty SELECT queries on idle systems.
	TickInterval time.Duration
	// BatchSize bounds rows-per-tick to keep each tick's lock window
	// short. Default 50 — at p99 500ms per delivery, full batch fits
	// inside a 25s window which is well under any reasonable advisory-
	// lock-holder watchdog.
	BatchSize int
	// HTTPTimeout is the per-row delivery timeout. Default 5s —
	// matches the original in-memory delivery timeout.
	HTTPTimeout time.Duration
}

// DefaultBackchannelLogoutDrainerConfig returns conservative
// production defaults.
func DefaultBackchannelLogoutDrainerConfig() BackchannelLogoutDrainerConfig {
	return BackchannelLogoutDrainerConfig{
		TickInterval: 5 * time.Second,
		BatchSize:    50,
		HTTPTimeout:  5 * time.Second,
	}
}

// NewBackchannelLogoutDrainer constructs a drainer. repo + logger
// MUST be non-nil; httpClient is built from cfg.HTTPTimeout.
func NewBackchannelLogoutDrainer(repo BackchannelLogoutOutboxRepo, cfg BackchannelLogoutDrainerConfig, logger *zap.Logger) *BackchannelLogoutDrainer {
	if cfg.TickInterval <= 0 {
		cfg.TickInterval = 5 * time.Second
	}
	if cfg.BatchSize <= 0 {
		cfg.BatchSize = 50
	}
	if cfg.HTTPTimeout <= 0 {
		cfg.HTTPTimeout = 5 * time.Second
	}
	return &BackchannelLogoutDrainer{
		repo:         repo,
		httpClient:   &http.Client{Timeout: cfg.HTTPTimeout},
		tickInterval: cfg.TickInterval,
		batchSize:    cfg.BatchSize,
		logger:       logger,
	}
}

// Start launches the drain loop on the supplied context. Blocks until
// ctx is cancelled. Run from a dedicated goroutine — `go d.Start(ctx)`
// in cmd/background.go.
func (d *BackchannelLogoutDrainer) Start(ctx context.Context) {
	if d == nil || d.repo == nil {
		return
	}
	d.logger.Info("BackchannelLogoutDrainer.Start: drain loop starting",
		zap.Duration("tick_interval", d.tickInterval),
		zap.Int("batch_size", d.batchSize),
	)
	ticker := time.NewTicker(d.tickInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			d.logger.Info("BackchannelLogoutDrainer.Start: context cancelled, exiting")
			return
		case <-ticker.C:
			d.drainOnce(ctx)
		}
	}
}

// drainOnce performs one drain cycle: acquires a pinned connection,
// takes the cross-replica advisory lock, claims up to batchSize
// pending rows, attempts delivery on each, updates status. Errors are
// logged but never propagated — the next tick retries.
func (d *BackchannelLogoutDrainer) drainOnce(ctx context.Context) {
	if n, err := d.repo.PendingCount(ctx); err != nil {
		d.logger.Warn("BackchannelLogoutDrainer.drainOnce: PendingCount failed", zap.Error(err))
	} else {
		metrics.OAuthBCLOutboxPending.Set(float64(n))
	}

	conn, err := d.repo.AcquireDrainerSession(ctx)
	if err != nil {
		d.logger.Warn("BackchannelLogoutDrainer.drainOnce: failed to acquire drainer connection", zap.Error(err))
		return
	}
	defer conn.Release()

	locked, err := d.repo.TryLockAdvisory(ctx, conn, outboxAdvisoryLockID)
	if err != nil {
		d.logger.Warn("BackchannelLogoutDrainer.drainOnce: advisory lock probe failed", zap.Error(err))
		return
	}
	if !locked {
		d.logger.Debug("BackchannelLogoutDrainer.drainOnce: another replica holds the lock, skipping")
		return
	}
	defer func() {
		// Use Background ctx for release so that a cancelled drain ctx
		// still releases the lock. This is critical: a leaked advisory
		// lock blocks every other drainer until the connection is
		// returned to the pool and gc'd.
		if err := d.repo.ReleaseAdvisory(context.Background(), conn, outboxAdvisoryLockID); err != nil {
			d.logger.Warn("BackchannelLogoutDrainer.drainOnce: failed to release advisory lock", zap.Error(err))
		}
	}()

	tx, err := d.repo.BeginTx(ctx, conn)
	if err != nil {
		d.logger.Warn("BackchannelLogoutDrainer.drainOnce: BeginTx failed", zap.Error(err))
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
		d.logger.Warn("BackchannelLogoutDrainer.drainOnce: SelectPendingForDelivery failed", zap.Error(err))
		return
	}
	if len(rows) == 0 {
		if commitErr := tx.Commit(ctx); commitErr != nil {
			d.logger.Warn("BackchannelLogoutDrainer.drainOnce: empty-batch commit failed", zap.Error(commitErr))
			return
		}
		committed = true
		return
	}

	for _, row := range rows {
		d.deliverRow(ctx, tx, row)
	}

	if err := tx.Commit(ctx); err != nil {
		d.logger.Warn("BackchannelLogoutDrainer.drainOnce: commit failed", zap.Error(err))
		return
	}
	committed = true
}

// deliverRow attempts HTTP delivery for one outbox row and updates the
// row status accordingly.
//
// Decision tree:
//
//	HTTP 2xx           → MarkSent + record success metric
//	HTTP 4xx (NOT 408) → MarkDead + record client_error metric (RP rejected; not retryable)
//	HTTP 5xx | timeout | dial-fail | 408 → MarkRetry (with backoff) or MarkDead (budget exhausted)
//
// Counter labels match the existing in-memory path's labels for
// continuity in Grafana — no dashboard rewrite needed.
func (d *BackchannelLogoutDrainer) deliverRow(ctx context.Context, tx repositories.DBTX, row repositories.OAuthLogoutOutboxRow) {
	startedAt := time.Now()

	form := url.Values{}
	form.Set("logout_token", row.Payload)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, row.TargetURI, strings.NewReader(form.Encode()))
	if err != nil {
		d.markDead(ctx, tx, row, fmt.Sprintf("build request: %v", err))
		metrics.OAuthBCLDeliveries.WithLabelValues(row.RPClientID, "build_error").Inc()
		return
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// AUTH MODEL (GAP A — 2026-05-10 SLO restoration plan):
	//
	// The legacy BCL_SHARED_SECRET Bearer header was vestigial — none
	// of the four receivers (Talon, accounts BFF, gitlab-bcl-receiver,
	// harbor-bcl-receiver) verified it. The spec-correct authentication
	// for OIDC Back-Channel Logout 1.0 is twofold:
	//
	//   1. Application-layer auth: the `logout_token` JWT itself is
	//      signed by Falcon-ID's RS256 signing key. Receivers verify
	//      via JWKS (the same JWKS used for id_token verification),
	//      checking iss/aud/iat/events claims per spec §2.6. This is
	//      the canonical authentication channel — see
	//      talon/internal/handlers/backchannel_logout.go and
	//      frontend/packages/falcon-id-client/src/server-backchannel-logout.ts
	//      for the receiver-side JWKS verifiers (already deployed).
	//
	//   2. Transport-layer auth: Linkerd mesh mTLS authenticates the
	//      pod-to-pod TCP connection. Identity assertions land in
	//      l5d-client-id headers; receivers can additionally enforce
	//      sender SPIFFE ID via `shared/mtls/IdentityBindingMiddleware`
	//      if they want belt-and-suspenders.
	//
	// The deleted Bearer header was a third "channel" that nobody
	// enforced — its removal closes a token-scoping inconsistency
	// (BCL_SHARED_SECRET was a static cluster-wide string, not bound
	// to the Falcon-ID identity that signed the logout_token).
	//
	// operational notes — "delete
	// INTERNAL_API_KEY config/middleware/env on sight". BCL_SHARED_SECRET
	// is the same anti-pattern.

	resp, err := d.httpClient.Do(req)
	if err != nil {
		d.markRetryOrDead(ctx, tx, row, fmt.Sprintf("transport: %v", err))
		metrics.OAuthBCLDeliveries.WithLabelValues(row.RPClientID, "timeout").Inc()
		return
	}
	defer resp.Body.Close() //nolint:errcheck,gosec

	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		if err := d.repo.MarkSent(ctx, tx, row.ID); err != nil {
			d.logger.Warn("BackchannelLogoutDrainer.deliverRow: MarkSent failed",
				zap.String("id", row.ID.String()), zap.Error(err),
			)
		}
		metrics.OAuthBCLDeliveries.WithLabelValues(row.RPClientID, "success").Inc()
		metrics.OAuthBCLOutboxE2ESeconds.Observe(time.Since(row.CreatedAt).Seconds())
	case resp.StatusCode == http.StatusRequestTimeout:
		// 408 is retryable in spirit even though it's a 4xx.
		d.markRetryOrDead(ctx, tx, row, fmt.Sprintf("HTTP %d", resp.StatusCode))
		metrics.OAuthBCLDeliveries.WithLabelValues(row.RPClientID, "timeout").Inc()
	case resp.StatusCode >= 400 && resp.StatusCode < 500:
		// 4xx (other than 408) is non-retryable per BCL spec § 2.8 —
		// the RP has rejected the token (signature wrong, audience
		// wrong, replay, etc.). Mark dead immediately; operator must
		// triage.
		d.markDead(ctx, tx, row, fmt.Sprintf("HTTP %d (non-retryable)", resp.StatusCode))
		metrics.OAuthBCLDeliveries.WithLabelValues(row.RPClientID, "client_error").Inc()
	default:
		// 5xx and any other unexpected code → retry.
		d.markRetryOrDead(ctx, tx, row, fmt.Sprintf("HTTP %d", resp.StatusCode))
		metrics.OAuthBCLDeliveries.WithLabelValues(row.RPClientID, "server_error").Inc()
	}

	metrics.OAuthBCLOutboxAttemptDuration.WithLabelValues(row.RPClientID).Observe(time.Since(startedAt).Seconds())
}

// markRetryOrDead chooses MarkRetry (with backoff) or MarkDead based
// on the current attempt_count. The schedule is consulted at index =
// attemptCount because attempt_count is the count of PRIOR failed
// attempts; index 0 is the wait after the first failure, etc.
func (d *BackchannelLogoutDrainer) markRetryOrDead(ctx context.Context, tx repositories.DBTX, row repositories.OAuthLogoutOutboxRow, lastErr string) {
	if row.AttemptCount >= len(outboxBackoffSchedule) {
		d.markDead(ctx, tx, row, fmt.Sprintf("retry budget exhausted: %s", lastErr))
		metrics.OAuthBCLDeliveries.WithLabelValues(row.RPClientID, "retry_exhausted").Inc()
		return
	}
	delay := outboxBackoffSchedule[row.AttemptCount]
	nextAt := time.Now().UTC().Add(delay)
	if err := d.repo.MarkRetry(ctx, tx, row.ID, lastErr, nextAt); err != nil {
		d.logger.Warn("BackchannelLogoutDrainer.markRetryOrDead: MarkRetry failed",
			zap.String("id", row.ID.String()), zap.Error(err),
		)
	}
}

// markDead transitions the row to status='dead' and increments the
// dead counter. Surfaces in the operator dashboard for manual triage.
func (d *BackchannelLogoutDrainer) markDead(ctx context.Context, tx repositories.DBTX, row repositories.OAuthLogoutOutboxRow, lastErr string) {
	if err := d.repo.MarkDead(ctx, tx, row.ID, lastErr); err != nil {
		d.logger.Warn("BackchannelLogoutDrainer.markDead: MarkDead failed",
			zap.String("id", row.ID.String()), zap.Error(err),
		)
	}
	metrics.OAuthBCLOutboxDead.WithLabelValues(row.RPClientID).Inc()
	d.logger.Error("BackchannelLogoutDrainer.markDead: row entered terminal dead state — operator triage required",
		zap.String("id", row.ID.String()),
		zap.String("rp_client_id", row.RPClientID),
		zap.String("logout_token_jti", row.LogoutTokenJTI),
		zap.Int("attempt_count", row.AttemptCount),
		zap.String("last_error", lastErr),
	)
}
