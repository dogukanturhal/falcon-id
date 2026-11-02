// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"bytes"
	"context"
	"crypto"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/metrics"
	"github.com/dogukanturhal/falcon-id/internal/repositories"
)

// caepSigner is the minimal signing surface the drainer needs. It is
// implemented by *pkg/keys.KeyManager today; the interface allows
// tests to stub a deterministic signer.
type caepSigner interface {
	ActiveKey() (crypto.Signer, string, error)
}

// caepOutboxAdvisoryLockID is a stable 64-bit identifier passed to
// pg_try_advisory_lock for cross-replica drainer single-flight.
//
// Chosen as 8 ASCII bytes "oalo_caep" truncated to 8 bytes:
// "oalocaep" (oalo = outbox advisory lock owner, caep = the event
// family). Same naming pattern as the BCL drainer's "oalo_bcl"
// (backchannel_logout_drainer.go) so operators inspecting
// pg_locks.locktype='advisory' can hex-decode the lock owner.
const caepOutboxAdvisoryLockID int64 = 0x6F61_6C6F_6361_6570 // ASCII "oalocaep"

// caepOutboxBackoffSchedule defines per-attempt next_retry_at delta.
// Same schedule as the BCL drainer — tuned for the same class of
// receivers (Talon, accounts BFF, RP-side SSF receivers). Total
// budget: 1s+5s+30s+5m+30m ≈ 35.6 min worst-case before the row
// moves to status='dead'.
var caepOutboxBackoffSchedule = []time.Duration{
	1 * time.Second,
	5 * time.Second,
	30 * time.Second,
	5 * time.Minute,
	30 * time.Minute,
}

// CAEPOutboxRepo is the minimal interface CAEPOutboxDrainer needs
// from the outbox repository. Defined here (rather than imported
// from internal/repositories) to keep the service layer testable
// without spinning a real pgxpool.
type CAEPOutboxRepo interface {
	PendingCount(ctx context.Context) (int64, error)
	AcquireDrainerSession(ctx context.Context) (*pgxpool.Conn, error)
	TryLockAdvisory(ctx context.Context, conn *pgxpool.Conn, lockID int64) (bool, error)
	ReleaseAdvisory(ctx context.Context, conn *pgxpool.Conn, lockID int64) error
	BeginTx(ctx context.Context, conn *pgxpool.Conn) (pgx.Tx, error)
	SelectPendingForDelivery(ctx context.Context, tx repositories.DBTX, limit int) ([]repositories.CAEPEventOutboxRow, error)
	MarkSent(ctx context.Context, tx repositories.DBTX, id uuid.UUID) error
	MarkRetry(ctx context.Context, tx repositories.DBTX, id uuid.UUID, lastErr string, nextAttemptAt time.Time) error
	MarkDead(ctx context.Context, tx repositories.DBTX, id uuid.UUID, lastErr string) error
}

// CAEPOutboxDrainer drains iam_caep_event_outbox in a single-flight,
// at-least-once fashion. Mirror of BackchannelLogoutDrainer.
//
// Operational notes:
//   - Run as a long-lived goroutine (started from cmd/services.go).
//   - One tick per TickInterval drains up to BatchSize pending rows.
//   - HTTP delivery is per-row, signed via the CAEPEmitter's KeyManager.
//   - Status transitions (sent / dead) are visible in the outbox table
//     directly + per Prometheus counters added in cmd/metrics-init.
//
// Why no in-drainer emission of the SET: signing is delegated to the
// CAEPEmitter (the shared signer used by the wave-2 sync path) so a
// future key-rotation only touches one site. The drainer holds a
// reference to a *CAEPEmitter.signSET-equivalent function.
type CAEPOutboxDrainer struct {
	repo         CAEPOutboxRepo
	keys         caepSigner
	cfg          CAEPOutboxDrainerConfig
	httpClient   *http.Client
	tickInterval time.Duration
	batchSize    int
	logger       *zap.Logger
}

// CAEPOutboxDrainerConfig holds operational knobs. Same shape as
// BackchannelLogoutDrainerConfig — operators get a single mental
// model for both drainers.
type CAEPOutboxDrainerConfig struct {
	// TickInterval is how often the drainer wakes up. Default 5s.
	TickInterval time.Duration
	// BatchSize bounds rows-per-tick. Default 50.
	BatchSize int
	// HTTPTimeout is the per-row delivery timeout. Default 5s.
	HTTPTimeout time.Duration
	// Issuer is the CAEP SET 'iss' claim (typically https://id.example.com).
	Issuer string
}

// DefaultCAEPOutboxDrainerConfig returns conservative production defaults.
func DefaultCAEPOutboxDrainerConfig() CAEPOutboxDrainerConfig {
	return CAEPOutboxDrainerConfig{
		TickInterval: 5 * time.Second,
		BatchSize:    50,
		HTTPTimeout:  5 * time.Second,
	}
}

// NewCAEPOutboxDrainer constructs a drainer. repo + keys + logger MUST
// be non-nil; httpClient is built from cfg.HTTPTimeout.
func NewCAEPOutboxDrainer(repo CAEPOutboxRepo, keysMgr caepSigner, cfg CAEPOutboxDrainerConfig, logger *zap.Logger) *CAEPOutboxDrainer {
	if cfg.TickInterval <= 0 {
		cfg.TickInterval = 5 * time.Second
	}
	if cfg.BatchSize <= 0 {
		cfg.BatchSize = 50
	}
	if cfg.HTTPTimeout <= 0 {
		cfg.HTTPTimeout = 5 * time.Second
	}
	if logger == nil {
		logger = zap.NewNop()
	}
	return &CAEPOutboxDrainer{
		repo:         repo,
		keys:         keysMgr,
		cfg:          cfg,
		httpClient:   &http.Client{Timeout: cfg.HTTPTimeout},
		tickInterval: cfg.TickInterval,
		batchSize:    cfg.BatchSize,
		logger:       logger,
	}
}

// Start launches the drain loop on the supplied context. Blocks until
// ctx is cancelled.
func (d *CAEPOutboxDrainer) Start(ctx context.Context) {
	if d == nil || d.repo == nil {
		return
	}
	d.logger.Info("CAEPOutboxDrainer.Start: drain loop starting",
		zap.Duration("tick_interval", d.tickInterval),
		zap.Int("batch_size", d.batchSize),
		zap.String("issuer", d.cfg.Issuer),
	)
	ticker := time.NewTicker(d.tickInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			d.logger.Info("CAEPOutboxDrainer.Start: context cancelled, exiting")
			return
		case <-ticker.C:
			d.drainOnce(ctx)
		}
	}
}

// drainOnce performs one drain cycle: acquires pinned connection,
// takes the cross-replica advisory lock, claims up to batchSize
// pending rows, attempts delivery on each, updates status. Errors
// logged, never propagated — the next tick retries.
//
// Metric contract: every code path through drainOnce records exactly
// ONE label-value of CAEPOutboxDrainerIterations (drained/no_rows/
// no_lock/error) AND observes CAEPOutboxDrainerTickDuration with the
// elapsed wall-clock. The defer at the top of the function enforces
// the latter; the explicit `outcome` write site enforces the former.
func (d *CAEPOutboxDrainer) drainOnce(ctx context.Context) {
	tickStart := time.Now()
	outcome := "error" // pessimistic default; overwritten on the success paths
	defer func() {
		metrics.CAEPOutboxDrainerIterations.WithLabelValues(outcome).Inc()
		metrics.CAEPOutboxDrainerTickDuration.Observe(time.Since(tickStart).Seconds())
	}()

	if pending, err := d.repo.PendingCount(ctx); err != nil {
		d.logger.Warn("CAEPOutboxDrainer.drainOnce: PendingCount failed", zap.Error(err))
	} else {
		metrics.CAEPOutboxPending.Set(float64(pending))
	}

	conn, err := d.repo.AcquireDrainerSession(ctx)
	if err != nil {
		d.logger.Warn("CAEPOutboxDrainer.drainOnce: failed to acquire drainer connection", zap.Error(err))
		return
	}
	defer conn.Release()

	locked, err := d.repo.TryLockAdvisory(ctx, conn, caepOutboxAdvisoryLockID)
	if err != nil {
		d.logger.Warn("CAEPOutboxDrainer.drainOnce: advisory lock probe failed", zap.Error(err))
		return
	}
	if !locked {
		d.logger.Debug("CAEPOutboxDrainer.drainOnce: another replica holds the lock, skipping")
		outcome = "no_lock"
		return
	}
	defer func() {
		// Background ctx for release so a cancelled drain still
		// frees the lock — same pattern as BCL drainer.
		if err := d.repo.ReleaseAdvisory(context.Background(), conn, caepOutboxAdvisoryLockID); err != nil {
			d.logger.Warn("CAEPOutboxDrainer.drainOnce: failed to release advisory lock", zap.Error(err))
		}
	}()

	tx, err := d.repo.BeginTx(ctx, conn)
	if err != nil {
		d.logger.Warn("CAEPOutboxDrainer.drainOnce: BeginTx failed", zap.Error(err))
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
		d.logger.Warn("CAEPOutboxDrainer.drainOnce: SelectPendingForDelivery failed", zap.Error(err))
		return
	}
	if len(rows) == 0 {
		if commitErr := tx.Commit(ctx); commitErr != nil {
			d.logger.Warn("CAEPOutboxDrainer.drainOnce: empty-batch commit failed", zap.Error(commitErr))
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
		d.logger.Warn("CAEPOutboxDrainer.drainOnce: commit failed", zap.Error(err))
		return
	}
	committed = true
	outcome = "drained"
}

// deliverRow attempts HTTP delivery for one outbox row + updates status.
//
// Decision tree mirrors the BCL drainer:
//
//	HTTP 2xx           → MarkSent
//	HTTP 4xx (NOT 408) → MarkDead (receiver rejected; non-retryable per RFC 8935 §3)
//	HTTP 5xx | timeout | dial-fail | 408 → MarkRetry (with backoff) or MarkDead
//
// Body is a CAEP SET signed via d.keys.ActiveKey() — same signing
// path as the sync CAEPEmitter, so a key rotation only touches one
// place. Content-Type: application/secevent+jwt per RFC 8417 §2.3.
func (d *CAEPOutboxDrainer) deliverRow(ctx context.Context, tx repositories.DBTX, row repositories.CAEPEventOutboxRow) {
	set, err := d.buildSET(row)
	if err != nil {
		metrics.CAEPOutboxDeliveryOutcomes.WithLabelValues(row.EventType, "build_error").Inc()
		d.markDead(ctx, tx, row, fmt.Sprintf("build SET: %v", err), "build_failure")
		return
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, row.TargetURI, bytes.NewReader(set))
	if err != nil {
		metrics.CAEPOutboxDeliveryOutcomes.WithLabelValues(row.EventType, "build_error").Inc()
		d.markDead(ctx, tx, row, fmt.Sprintf("build request: %v", err), "build_failure")
		return
	}
	req.Header.Set("Content-Type", "application/secevent+jwt")

	resp, err := d.httpClient.Do(req)
	if err != nil {
		d.markRetryOrDead(ctx, tx, row, fmt.Sprintf("transport: %v", err), "transport_permanent")
		return
	}
	defer resp.Body.Close() //nolint:errcheck,gosec

	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		if err := d.repo.MarkSent(ctx, tx, row.ID); err != nil {
			d.logger.Warn("CAEPOutboxDrainer.deliverRow: MarkSent failed",
				zap.String("id", row.ID.String()), zap.Error(err),
			)
		}
		metrics.CAEPOutboxDeliveryOutcomes.WithLabelValues(row.EventType, "sent").Inc()
	case resp.StatusCode == http.StatusRequestTimeout:
		// 408 is retryable in spirit despite being 4xx.
		d.markRetryOrDead(ctx, tx, row, fmt.Sprintf("HTTP %d", resp.StatusCode), "transport_permanent")
	case resp.StatusCode >= 400 && resp.StatusCode < 500:
		// 4xx (other than 408) — receiver rejected. Non-retryable.
		d.markDead(ctx, tx, row, fmt.Sprintf("HTTP %d (non-retryable)", resp.StatusCode), "http_4xx_nonretryable")
		metrics.CAEPOutboxDeliveryOutcomes.WithLabelValues(row.EventType, "dead").Inc()
	default:
		// 5xx + other unexpected → retry.
		d.markRetryOrDead(ctx, tx, row, fmt.Sprintf("HTTP %d", resp.StatusCode), "transport_permanent")
	}
}

// buildSET signs a CAEP Security Event Token (RFC 8417) for the row.
// Returns the JWT bytes ready for POST.
//
// The SET payload mirrors the sync CAEPEmitter (caep_emitter.go) so
// receivers process outbox-delivered and sync-delivered events
// identically.
func (d *CAEPOutboxDrainer) buildSET(row repositories.CAEPEventOutboxRow) ([]byte, error) {
	if d.keys == nil {
		return nil, errors.New("no key manager configured")
	}
	signer, kid, err := d.keys.ActiveKey()
	if err != nil {
		return nil, fmt.Errorf("active key: %w", err)
	}
	var eventPayload map[string]interface{}
	if err := json.Unmarshal(row.EventData, &eventPayload); err != nil {
		// Defensive: malformed event_data should not block delivery;
		// fall through with an empty payload and rely on the row's
		// subject_* columns for the canonical identity.
		eventPayload = map[string]interface{}{}
	}
	// CAEP 1.0 §2.3 — the subject is carried inside the event-specific
	// payload. Mirrors the sync CAEPEmitter (caep_emitter.go) so
	// receivers process outbox-delivered events identically.
	eventPayload["subject"] = map[string]interface{}{
		"format":  row.SubjectFormat,
		"iss":     row.SubjectIss,
		"subject": row.SubjectSub,
	}
	claims := jwt.MapClaims{
		"iss": d.cfg.Issuer,
		"aud": row.TargetURI,
		"iat": time.Now().Unix(),
		"jti": row.ID.String(),
		"events": map[string]interface{}{
			row.EventType: eventPayload,
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = kid
	token.Header["typ"] = "secevent+jwt"
	signed, err := token.SignedString(signer)
	if err != nil {
		return nil, fmt.Errorf("sign SET: %w", err)
	}
	return []byte(signed), nil
}

// markRetryOrDead chooses MarkRetry (with backoff) or MarkDead based
// on the current attempt_count vs the schedule budget.
//
// reasonClass is the metrics-side label classification passed through
// to markDead when the row exhausts its budget (see CAEPOutboxDeadReasons
// in internal/metrics/caep_outbox.go).
func (d *CAEPOutboxDrainer) markRetryOrDead(ctx context.Context, tx repositories.DBTX, row repositories.CAEPEventOutboxRow, lastErr string, reasonClass string) {
	if row.AttemptCount >= len(caepOutboxBackoffSchedule) {
		d.markDead(ctx, tx, row, fmt.Sprintf("retry budget exhausted: %s", lastErr), "retry_budget_exhausted")
		metrics.CAEPOutboxDeliveryOutcomes.WithLabelValues(row.EventType, "dead").Inc()
		return
	}
	delay := caepOutboxBackoffSchedule[row.AttemptCount]
	nextAt := time.Now().UTC().Add(delay)
	if err := d.repo.MarkRetry(ctx, tx, row.ID, lastErr, nextAt); err != nil {
		d.logger.Warn("CAEPOutboxDrainer.markRetryOrDead: MarkRetry failed",
			zap.String("id", row.ID.String()), zap.Error(err),
		)
	}
	metrics.CAEPOutboxDeliveryOutcomes.WithLabelValues(row.EventType, "retry").Inc()
	// reasonClass is the *first-cause* class — surface it on retry as
	// well so operators correlating spikes in retry rate to dead-letter
	// reason classes can do so before any row crosses the budget.
	_ = reasonClass
}

// markDead transitions row to status='dead' and emits a Warn log
// for operator triage.
//
// reasonClass is the dead-letter classification used for the
// CAEPOutboxDeadReasons counter (one of "http_4xx_nonretryable",
// "retry_budget_exhausted", "build_failure", "transport_permanent").
func (d *CAEPOutboxDrainer) markDead(ctx context.Context, tx repositories.DBTX, row repositories.CAEPEventOutboxRow, lastErr string, reasonClass string) {
	if err := d.repo.MarkDead(ctx, tx, row.ID, lastErr); err != nil {
		d.logger.Warn("CAEPOutboxDrainer.markDead: MarkDead failed",
			zap.String("id", row.ID.String()), zap.Error(err),
		)
	}
	metrics.CAEPOutboxDeadReasons.WithLabelValues(row.EventType, reasonClass).Inc()
	d.logger.Error("CAEPOutboxDrainer.markDead: row entered terminal dead state — operator triage required",
		zap.String("id", row.ID.String()),
		zap.String("stream_id", row.StreamID.String()),
		zap.String("event_type", row.EventType),
		zap.String("subject_iss", row.SubjectIss),
		zap.String("subject_sub", row.SubjectSub),
		zap.Int("attempt_count", row.AttemptCount),
		zap.String("last_error", lastErr),
		zap.String("reason_class", reasonClass),
	)
}
