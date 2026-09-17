// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/pkg/config"
	"github.com/dogukanturhal/falcon-id/pkg/logger"
)

// seatQuotaResourceType is quota-service's resource_type key for seats.
// Must match platform-shared/quota.ResourceTypeUsers and
// hexxlock_quota_service.resource_quotas.resource_type = 'users'.
const seatQuotaResourceType = "users"

// seatQuotaReconcileTimeout caps the time spent reconciling a single tenant's
// call to quota-service. A stalled quota-service request should not block
// the entire scheduler goroutine — same invariant as SpiceDBReconciler's
// tenantPerReconcileTimeout.
const seatQuotaReconcileTimeout = 15 * time.Second

// SeatQuotaReconcileStats holds aggregate metrics for a single reconciliation pass.
type SeatQuotaReconcileStats struct {
	TenantsProcessed int
	TenantsCorrected int
	Errors           int
	StartedAt        time.Time
	CompletedAt      time.Time
}

// seatQuotaReconcileRequest/-Result mirror quota-service's admin reconcile
// wire contract exactly (internal/handlers/quota_handler.go's Reconcile,
// internal/services/reconciliation_service.go's ReconciliationResult in
// hexxlock/platform-commerce) and hexxlock/business's QuotaClient.
// ReconcileAsync C# counterpart. Kept local to this file rather than adding
// a Reconcile method to platform-shared/quota.QuotaClient: doing so would
// require cutting a new platform-shared release and bumping this module's
// go.mod pin before it could be used, which is unnecessary weight for one
// admin call this service alone makes today. Revisit if a second Go
// service needs the same reconcile call.
type seatQuotaReconcileRequest struct {
	TenantID     uuid.UUID `json:"tenant_id"`
	ResourceType string    `json:"resource_type"`
	ActualCount  int64     `json:"actual_count"`
}

type seatQuotaReconcileResult struct {
	TenantID      uuid.UUID `json:"tenant_id"`
	ResourceType  string    `json:"resource_type"`
	RecordedUsage int64     `json:"recorded_usage"`
	ActualUsage   int64     `json:"actual_usage"`
	Drift         int64     `json:"drift"`
	Corrected     bool      `json:"corrected"`
}

type seatQuotaReconcileEnvelope struct {
	Success bool                      `json:"success"`
	Data    *seatQuotaReconcileResult `json:"data"`
}

// SeatQuotaReconciler periodically recounts real, billable, active users
// (seats) per tenant directly from iam_users — the only authoritative
// tenant-user-count source on the platform — and writes the absolute value
// to quota-service via POST /api/v1/quota/admin/reconcile.
//
// WHY a reconciler in ADDITION to UserService's synchronous
// MustCheckQuota/IncrementUsage/DecrementUsage calls around Create/Delete
// (feat/seat-quota-enforcement):
//
// Seats are a STOCK (a current count), not a FLOW like email_sends_monthly
// which only ever accumulates within a billing period. A stock derived
// purely from summing deltas drifts permanently the moment any write path
// skips the delta call — and iam_users has more than one such path:
// direct administrative writes, tenant provisioning/bootstrap flows that
// insert the first user without going through UserService.Create, a
// partially-failed bulk operation, or historical drift predating this
// enforcement existing at all (every user created before this MR landed
// never incremented quota-service). None of that can self-correct via
// increment/decrement alone — only a periodic absolute recount from the
// same source of truth can, regardless of which code path wrote the row.
// This mirrors hexxlock/business's ContactsQuotaReconcilerService for the
// "contacts" resource exactly, and does NOT replace the synchronous
// check/increment/decrement path, which still gates and records in real
// time for the common create/delete case.
//
// WHY THIS LIVES IN FALCON-ID, NOT QUOTA-SERVICE OR A SEPARATE SCRIPT:
// falcon-id owns iam_users — it is the source of truth for tenant
// membership on this platform. Counting from a projection (e.g. a
// tenant_projection-style read model) risks staleness; falcon-id can
// recount directly against its own primary database with no replication
// lag. The existing GET /internal/v1/tenants/:id/users/count endpoint
// (added alongside the synchronous enforcement) was built for an external
// backfill script; this reconciler instead queries the DB pool directly
// in-process (same pattern as SpiceDBReconciler) since it already runs
// inside the owning service and the extra network hop buys nothing.
//
// SERVICE-ACCOUNT EXCLUSION: a service account is not a billable seat.
// falcon-id has a dedicated iam_service_accounts table for machine
// identities (currently empty in production — no service account has been
// provisioned through that proper path yet); those rows are never counted
// here because this query only reads iam_users. Separately, at least one
// machine identity (svc-payment-provider-sync) exists today as an
// iam_users row created as a stopgap outside that table, and iam_users
// carries no dedicated "is this a person" column yet (see the in-flight,
// not-yet-shipped seat_class column proposal, models.SeatClass, which will
// supersede this heuristic once it lands and is backfilled). Until then,
// this reconciler excludes iam_users rows whose username matches the
// "svc-" prefix convention already used for that account — the same
// convention that made svc-payment-provider-sync's own is_active default
// to false. Both signals (is_active AND the svc- prefix exclusion) are
// applied so a future svc-* row that is mistakenly left is_active=true
// still does not get billed as a seat.
type SeatQuotaReconciler struct {
	db              *pgxpool.Pool
	quotaHTTP       *http.Client
	quotaServiceURL string
	config          *config.Config

	stopChan chan struct{}
	stopOnce sync.Once
	wg       sync.WaitGroup

	mu              sync.RWMutex
	lastRunTime     time.Time
	lastRunDuration time.Duration
	lastRunStats    SeatQuotaReconcileStats
}

// NewSeatQuotaReconciler constructs a SeatQuotaReconciler. quotaHTTP must be
// an *http.Client that attaches a Falcon-ID client_credentials Bearer token
// carrying the quota:admin scope (see cmd/services.go's
// buildSeatQuotaReconcilerHTTPClient) — quota-service's admin/reconcile
// route sits behind RequirePermission("quota:admin","platform:admin"),
// distinct from the quota:usage:read/update scopes the synchronous
// check/increment/decrement path uses. A nil quotaHTTP or empty
// quotaServiceURL degrades StartScheduler to a no-op log line rather than
// panicking, matching buildQuotaClient's fallback posture elsewhere in this
// file for fresh-initdb / dev-without-Vault boots.
func NewSeatQuotaReconciler(db *pgxpool.Pool, quotaServiceURL string, quotaHTTP *http.Client, cfg *config.Config) *SeatQuotaReconciler {
	return &SeatQuotaReconciler{
		db:              db,
		quotaHTTP:       quotaHTTP,
		quotaServiceURL: quotaServiceURL,
		config:          cfg,
		stopChan:        make(chan struct{}),
	}
}

// StartScheduler launches the background reconciliation loop. It returns
// immediately; all work happens in a managed goroutine — mirrors
// SpiceDBReconciler.StartScheduler's shape exactly, including the shared
// reconcilerStartupDelay constant (defined in spicedb_reconciler.go, same
// package) so every service backing off after boot converges on one value.
func (r *SeatQuotaReconciler) StartScheduler(ctx context.Context) {
	if !r.config.SeatQuotaReconcilerEnabled {
		logger.Info("Seat-quota reconciler scheduler disabled by configuration")
		return
	}
	if r.db == nil || r.quotaHTTP == nil || r.quotaServiceURL == "" {
		logger.Warn("Seat-quota reconciler scheduler not started: missing db pool, authenticated HTTP client, or quota-service URL")
		return
	}

	interval := r.config.SeatQuotaReconcilerInterval
	if interval <= 0 {
		interval = time.Hour
	}

	logger.Info("Starting seat-quota reconciler scheduler",
		zap.Duration("interval", interval),
		zap.Duration("startup_delay", reconcilerStartupDelay),
	)

	r.wg.Add(1)
	go func() {
		defer r.wg.Done()

		select {
		case <-time.After(reconcilerStartupDelay):
			r.runReconcile(ctx)
		case <-r.stopChan:
			return
		case <-ctx.Done():
			return
		}

		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				r.runReconcile(ctx)
			case <-r.stopChan:
				logger.Info("Seat-quota reconciler scheduler stopped")
				return
			case <-ctx.Done():
				logger.Info("Seat-quota reconciler scheduler context cancelled")
				return
			}
		}
	}()
}

// StopScheduler signals the background goroutine to stop and waits for it
// to exit. Safe to call multiple times.
func (r *SeatQuotaReconciler) StopScheduler() {
	r.stopOnce.Do(func() {
		close(r.stopChan)
	})
	r.wg.Wait()
	logger.Info("Seat-quota reconciler scheduler shutdown complete")
}

// Stats returns a snapshot of the most recent reconciliation pass.
func (r *SeatQuotaReconciler) Stats() SeatQuotaReconcileStats {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.lastRunStats
}

func (r *SeatQuotaReconciler) runReconcile(ctx context.Context) {
	logger.Info("Running seat-quota reconciliation pass")

	stats, err := r.Reconcile(ctx)
	if err != nil {
		logger.Warn("Seat-quota reconciliation pass returned an error", zap.Error(err))
		return
	}

	r.mu.Lock()
	r.lastRunTime = stats.CompletedAt
	r.lastRunDuration = stats.CompletedAt.Sub(stats.StartedAt)
	r.lastRunStats = *stats
	r.mu.Unlock()

	logger.Info("Seat-quota reconciliation pass completed",
		zap.Int("tenants_processed", stats.TenantsProcessed),
		zap.Int("tenants_corrected", stats.TenantsCorrected),
		zap.Int("errors", stats.Errors),
		zap.Duration("duration", r.lastRunDuration),
	)
}

// Reconcile performs a full reconciliation pass across every tenant that
// currently has at least one iam_users row. Exported so an admin endpoint
// can trigger an ad-hoc pass without waiting for the scheduler (same
// convention as SpiceDBReconciler.Reconcile).
func (r *SeatQuotaReconciler) Reconcile(ctx context.Context) (*SeatQuotaReconcileStats, error) {
	if r.db == nil {
		return nil, fmt.Errorf("seat quota reconcile: database pool not initialized")
	}

	stats := &SeatQuotaReconcileStats{StartedAt: time.Now()}

	counts, err := r.countBillableSeatsByTenant(ctx)
	if err != nil {
		return nil, fmt.Errorf("seat quota reconcile: count seats: %w", err)
	}

	for tenantID, count := range counts {
		tenantCtx, cancel := context.WithTimeout(ctx, seatQuotaReconcileTimeout)
		result, err := r.reconcileTenant(tenantCtx, tenantID, count)
		cancel()

		if err != nil {
			logger.Warn("Seat-quota reconciliation failed for tenant",
				zap.String("tenant_id", tenantID.String()),
				zap.Error(err),
			)
			stats.Errors++
			continue
		}

		stats.TenantsProcessed++
		if result != nil && result.Corrected {
			stats.TenantsCorrected++
			logger.Info("Seat-quota drift corrected",
				zap.String("tenant_id", tenantID.String()),
				zap.Int64("recorded_usage", result.RecordedUsage),
				zap.Int64("actual_usage", result.ActualUsage),
				zap.Int64("drift", result.Drift),
			)
		}
	}

	stats.CompletedAt = time.Now()
	return stats, nil
}

// countBillableSeatsByTenant recounts, per tenant, real active users that
// occupy a billable seat.
//
// Exclusions (see the SeatQuotaReconciler doc comment for the full
// rationale):
//   - is_active = false: deactivated/disabled accounts do not occupy a seat.
//     Also already true for svc-payment-provider-sync today.
//   - deletion_scheduled_at IS NOT NULL: users in their pending-deletion
//     grace period — same condition the GET /internal/v1/tenants/:id/
//     users/count endpoint (UserRepository.CountActiveByTenant) already
//     uses.
//   - username ILIKE 'svc-%': the established convention for machine/
//     service identities recorded directly in iam_users outside the
//     dedicated (currently empty) iam_service_accounts table. Applied even
//     though is_active already excludes the one known instance today, so a
//     future svc-* row left active by mistake is still not billed.
func (r *SeatQuotaReconciler) countBillableSeatsByTenant(ctx context.Context) (map[uuid.UUID]int64, error) {
	const query = `
		SELECT tenant_id, COUNT(*)
		FROM iam_users
		WHERE is_active = true
		  AND deletion_scheduled_at IS NULL
		  AND username NOT ILIKE 'svc-%'
		GROUP BY tenant_id
	`

	rows, err := r.db.Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("query billable seats: %w", err)
	}
	defer rows.Close()

	counts := make(map[uuid.UUID]int64)
	for rows.Next() {
		var tenantID uuid.UUID
		var count int64
		if err := rows.Scan(&tenantID, &count); err != nil {
			return nil, fmt.Errorf("scan billable seat row: %w", err)
		}
		counts[tenantID] = count
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate billable seat rows: %w", err)
	}

	return counts, nil
}

// reconcileTenant POSTs the recounted absolute seat value for one tenant to
// quota-service's admin reconcile endpoint.
func (r *SeatQuotaReconciler) reconcileTenant(ctx context.Context, tenantID uuid.UUID, actualCount int64) (*seatQuotaReconcileResult, error) {
	body := seatQuotaReconcileRequest{
		TenantID:     tenantID,
		ResourceType: seatQuotaResourceType,
		ActualCount:  actualCount,
	}
	payload, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("marshal reconcile request: %w", err)
	}

	endpoint := r.quotaServiceURL + "/api/v1/quota/admin/reconcile"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("build reconcile request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := r.quotaHTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("reconcile request transport error: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		// Loud, not swallowed: a rejected quota:admin credential here means
		// seat usage is stuck and cannot self-heal — the whole reason this
		// reconciler exists.
		return nil, fmt.Errorf("reconcile rejected by quota-service (not a transport failure): status %d", resp.StatusCode)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("reconcile failed: status %d", resp.StatusCode)
	}

	var envelope seatQuotaReconcileEnvelope
	if err := json.NewDecoder(resp.Body).Decode(&envelope); err != nil {
		return nil, fmt.Errorf("decode reconcile response: %w", err)
	}
	if envelope.Data == nil {
		return nil, fmt.Errorf("reconcile response missing data")
	}

	return envelope.Data, nil
}
