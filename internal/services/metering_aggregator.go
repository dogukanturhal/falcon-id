// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/pkg/logger"
)

// advisoryLockMeteringAggregator is the PostgreSQL advisory lock key used for
// leader election among MeteringAggregator replicas.  Only one replica should
// run the aggregation loop at a time; the others skip the tick gracefully.
// The value is deliberately distinct from all other advisory lock constants in
// this package (provisioning: 857491001, etc.).
const advisoryLockMeteringAggregator int64 = 857491006

// cpuSecondsPerHour is the conversion factor from Prometheus CPU-seconds to
// compute-hours used when recording compute usage.
const cpuSecondsPerHour = 3600.0

// ─── Scraper interfaces ───────────────────────────────────────────────────────

// PrometheusScraper queries a Prometheus server for metric values.
// Implementations must be safe for concurrent use.
type PrometheusScraper interface {
	// QueryInstant executes an instant PromQL query at the given time and
	// returns the value of the first result vector element.  Zero is returned
	// when the result set is empty (metric absent).
	QueryInstant(ctx context.Context, query string, ts time.Time) (float64, error)
}

// MinIOScraper queries MinIO for tenant bucket storage usage.
// Implementations must be safe for concurrent use.
type MinIOScraper interface {
	// GetTenantStorageBytes returns the total bytes stored across all
	// tenant-prefixed buckets.  Returns 0 when no buckets match.
	GetTenantStorageBytes(ctx context.Context, tenantID uuid.UUID) (int64, error)
}

// APISIXScraper queries the APISIX Prometheus exporter for per-tenant traffic
// metrics.  Implementations must be safe for concurrent use.
type APISIXScraper interface {
	// GetTenantBandwidthBytes returns egress bytes for the tenant.
	GetTenantBandwidthBytes(ctx context.Context, tenantID uuid.UUID) (int64, error)
	// GetTenantAPIRequests returns the total request count for the tenant.
	GetTenantAPIRequests(ctx context.Context, tenantID uuid.UUID) (int64, error)
}

// ─── MeteringAggregator ───────────────────────────────────────────────────────

// MeteringAggregator is a background service that periodically:
//  1. Acquires a PostgreSQL advisory lock (leader election for multi-replica).
//  2. Lists all active tenants from the database.
//  3. Flushes each tenant's Redis real-time counters into iam_usage_records.
//  4. Scrapes external metric sources (Prometheus, MinIO, APISIX) for
//     supplemental metrics that are not self-reported by services.
//
// Each scraper is optional: when nil the corresponding scrape step is skipped
// with a warning log so that deployments without one of the integrations can
// still operate.
type MeteringAggregator struct {
	metering      *UsageMeteringService
	db            *pgxpool.Pool
	promScraper   PrometheusScraper
	minioScraper  MinIOScraper
	apisixScraper APISIXScraper
	cancel        context.CancelFunc
	wg            sync.WaitGroup
	interval      time.Duration
}

// NewMeteringAggregator creates a MeteringAggregator with no external scrapers
// (stub behaviour identical to the pre-Wave-1.2 implementation).  Call
// NewMeteringAggregatorWithScrapers to wire real HTTP clients.
//
// The db pool is used for advisory lock leader election; when nil the lock is
// skipped (e.g. in single-replica or test deployments).
func NewMeteringAggregator(metering *UsageMeteringService, db *pgxpool.Pool, interval time.Duration) *MeteringAggregator {
	return NewMeteringAggregatorWithScrapers(metering, db, interval, nil, nil, nil)
}

// NewMeteringAggregatorWithScrapers creates a MeteringAggregator wired with
// real HTTP scraper clients.  Any scraper may be nil; nil scrapers are skipped
// gracefully during each aggregation tick.
func NewMeteringAggregatorWithScrapers(
	metering *UsageMeteringService,
	db *pgxpool.Pool,
	interval time.Duration,
	prom PrometheusScraper,
	minio MinIOScraper,
	apisix APISIXScraper,
) *MeteringAggregator {
	if interval <= 0 {
		interval = 5 * time.Minute
	}
	return &MeteringAggregator{
		metering:      metering,
		db:            db,
		promScraper:   prom,
		minioScraper:  minio,
		apisixScraper: apisix,
		interval:      interval,
	}
}

// Start launches the background aggregation loop.  The loop runs until Stop is
// called or the parent context is cancelled.  Start is idempotent for the
// lifecycle of a single MeteringAggregator — call Stop before calling Start
// again if a restart is needed.
func (a *MeteringAggregator) Start(ctx context.Context) {
	ctx, a.cancel = context.WithCancel(ctx)
	a.wg.Add(1)
	go func() {
		defer a.wg.Done()
		ticker := time.NewTicker(a.interval)
		defer ticker.Stop()

		logger.Log.Info("Metering aggregator started",
			zap.Duration("interval", a.interval),
		)

		for {
			select {
			case <-ctx.Done():
				logger.Log.Info("Metering aggregator stopped")
				return
			case <-ticker.C:
				a.aggregate(ctx)
			}
		}
	}()
}

// Stop signals the background loop to exit and waits for it to finish.
func (a *MeteringAggregator) Stop() {
	if a.cancel != nil {
		a.cancel()
	}
	a.wg.Wait()
}

// aggregate is one tick of the aggregation loop.
//
// It acquires the advisory lock (if a db pool is configured), then iterates
// over all active tenants.  For each tenant it:
//   - Flushes Redis real-time counters to iam_usage_records.
//   - Runs the supplemental scrape functions for compute, storage, and bandwidth.
//
// Errors for individual tenants are logged and do not abort the loop so that a
// problem with one tenant does not prevent others from being aggregated.
func (a *MeteringAggregator) aggregate(ctx context.Context) {
	// ── Leader election ─────────────────────────────────────────────────────
	if a.db != nil {
		conn, err := a.db.Acquire(ctx)
		if err != nil {
			logger.Log.Error("MeteringAggregator: failed to acquire connection for advisory lock",
				zap.Error(err),
			)
			return
		}
		defer conn.Release()

		var acquired bool
		if err := conn.QueryRow(ctx,
			"SELECT pg_try_advisory_lock($1)", advisoryLockMeteringAggregator,
		).Scan(&acquired); err != nil {
			logger.Log.Error("MeteringAggregator: failed to try advisory lock", zap.Error(err))
			return
		}
		if !acquired {
			logger.Log.Debug("MeteringAggregator: another replica holds the lock — skipping this tick")
			return
		}
		defer func() {
			_, _ = conn.Exec(ctx, "SELECT pg_advisory_unlock($1)", advisoryLockMeteringAggregator)
		}()
	}

	// ── List active tenants ──────────────────────────────────────────────────
	tenantIDs, err := a.listActiveTenants(ctx)
	if err != nil {
		logger.Log.Error("MeteringAggregator: failed to list active tenants", zap.Error(err))
		return
	}

	logger.Log.Info("MeteringAggregator: aggregating tenants",
		zap.Int("tenant_count", len(tenantIDs)),
	)

	for _, tenantID := range tenantIDs {
		if ctx.Err() != nil {
			return
		}
		a.aggregateTenant(ctx, tenantID)
	}
}

// aggregateTenant runs all aggregation steps for a single tenant.
func (a *MeteringAggregator) aggregateTenant(ctx context.Context, tenantID uuid.UUID) {
	tid := tenantID.String()

	// Flush Redis real-time counters to the database.
	if err := a.metering.FlushRealtimeToDatabase(ctx, tenantID); err != nil {
		logger.Log.Error("MeteringAggregator: flush realtime counters failed",
			zap.String("tenant_id", tid),
			zap.Error(err),
		)
		// Continue — scraping is independent of flushing.
	}

	a.aggregateTenantScrapers(ctx, tenantID)
}

// aggregateTenantScrapers runs the three external scrape steps for a tenant.
// Each scrape is independent: failure in one does not abort the others.
// This method is also the entry point used by tests to bypass the flush step.
func (a *MeteringAggregator) aggregateTenantScrapers(ctx context.Context, tenantID uuid.UUID) {
	tid := tenantID.String()

	if err := a.scrapeComputeMetrics(ctx, tenantID); err != nil {
		logger.Log.Warn("MeteringAggregator: compute scrape failed",
			zap.String("tenant_id", tid),
			zap.Error(err),
		)
	}

	if err := a.scrapeStorageMetrics(ctx, tenantID); err != nil {
		logger.Log.Warn("MeteringAggregator: storage scrape failed",
			zap.String("tenant_id", tid),
			zap.Error(err),
		)
	}

	if err := a.scrapeBandwidthMetrics(ctx, tenantID); err != nil {
		logger.Log.Warn("MeteringAggregator: bandwidth scrape failed",
			zap.String("tenant_id", tid),
			zap.Error(err),
		)
	}
}

// listActiveTenants queries the database for all tenants with status = 'active'.
// Returns a slice of tenant UUIDs; an empty slice is valid when no tenants are active.
func (a *MeteringAggregator) listActiveTenants(ctx context.Context) ([]uuid.UUID, error) {
	if a.db == nil {
		return nil, fmt.Errorf("MeteringAggregator.listActiveTenants: no database pool configured")
	}

	rows, err := a.db.Query(ctx, `SELECT id FROM iam_tenants WHERE status = 'active' ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("MeteringAggregator.listActiveTenants: %w", err)
	}
	defer rows.Close()

	var ids []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("MeteringAggregator.listActiveTenants: scan: %w", err)
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("MeteringAggregator.listActiveTenants: rows: %w", err)
	}

	return ids, nil
}

// scrapeComputeMetrics queries Prometheus for container CPU usage in the
// tenant's Kubernetes namespace, converts the result from CPU-seconds to
// compute-hours, and records the metric via RecordRealtimeMetric.
//
// When no Prometheus scraper is configured, the method logs a warning and
// returns nil so the rest of the aggregation loop is unaffected.
func (a *MeteringAggregator) scrapeComputeMetrics(ctx context.Context, tenantID uuid.UUID) error {
	if a.promScraper == nil {
		logger.Log.Debug("MeteringAggregator: Prometheus scraper not configured — skipping compute scrape",
			zap.String("tenant_id", tenantID.String()),
		)
		return nil
	}

	query := fmt.Sprintf(
		`sum(rate(container_cpu_usage_seconds_total{namespace="tenant-%s"}[5m]))`,
		tenantID.String(),
	)

	cpuSeconds, err := a.promScraper.QueryInstant(ctx, query, time.Now())
	if err != nil {
		return fmt.Errorf("scrapeComputeMetrics: query Prometheus: %w", err)
	}

	// Convert CPU-seconds to compute-hours.  Only record when > 0 to avoid
	// flooding the usage table with zero-value entries for idle tenants.
	computeHours := int64(cpuSeconds / cpuSecondsPerHour)
	if computeHours <= 0 {
		logger.Log.Debug("MeteringAggregator: no compute hours to record",
			zap.String("tenant_id", tenantID.String()),
			zap.Float64("cpu_seconds", cpuSeconds),
		)
		return nil
	}

	if err := a.metering.RecordRealtimeMetric(ctx, RealtimeMetric{
		TenantID:   tenantID,
		MetricName: MetricComputeHours,
		Value:      computeHours,
		Timestamp:  time.Now(),
	}); err != nil {
		return fmt.Errorf("scrapeComputeMetrics: record metric: %w", err)
	}

	logger.Log.Debug("MeteringAggregator: compute hours recorded",
		zap.String("tenant_id", tenantID.String()),
		zap.Float64("cpu_seconds", cpuSeconds),
		zap.Int64("compute_hours", computeHours),
	)
	return nil
}

// scrapeStorageMetrics queries MinIO for the tenant's bucket storage usage and
// records it via RecordRealtimeMetric.
//
// When no MinIO scraper is configured, the method logs a warning and returns
// nil so the rest of the aggregation loop is unaffected.
func (a *MeteringAggregator) scrapeStorageMetrics(ctx context.Context, tenantID uuid.UUID) error {
	if a.minioScraper == nil {
		logger.Log.Debug("MeteringAggregator: MinIO scraper not configured — skipping storage scrape",
			zap.String("tenant_id", tenantID.String()),
		)
		return nil
	}

	storageBytes, err := a.minioScraper.GetTenantStorageBytes(ctx, tenantID)
	if err != nil {
		return fmt.Errorf("scrapeStorageMetrics: query MinIO: %w", err)
	}

	if storageBytes <= 0 {
		logger.Log.Debug("MeteringAggregator: no storage bytes to record",
			zap.String("tenant_id", tenantID.String()),
		)
		return nil
	}

	if err := a.metering.RecordRealtimeMetric(ctx, RealtimeMetric{
		TenantID:   tenantID,
		MetricName: MetricStorageBytes,
		Value:      storageBytes,
		Timestamp:  time.Now(),
	}); err != nil {
		return fmt.Errorf("scrapeStorageMetrics: record metric: %w", err)
	}

	logger.Log.Debug("MeteringAggregator: storage bytes recorded",
		zap.String("tenant_id", tenantID.String()),
		zap.Int64("storage_bytes", storageBytes),
	)
	return nil
}

// scrapeBandwidthMetrics queries APISIX for the tenant's egress bandwidth and
// API request count, recording each as separate realtime metrics.
//
// Both metrics are scraped in a single call to avoid a second HTTP round-trip;
// failures in individual metrics are logged but do not abort the other.
//
// When no APISIX scraper is configured, the method logs a warning and returns
// nil so the rest of the aggregation loop is unaffected.
func (a *MeteringAggregator) scrapeBandwidthMetrics(ctx context.Context, tenantID uuid.UUID) error {
	if a.apisixScraper == nil {
		logger.Log.Debug("MeteringAggregator: APISIX scraper not configured — skipping bandwidth scrape",
			zap.String("tenant_id", tenantID.String()),
		)
		return nil
	}

	tid := tenantID.String()
	var lastErr error

	// ── Egress bandwidth ────────────────────────────────────────────────────
	bandwidthBytes, err := a.apisixScraper.GetTenantBandwidthBytes(ctx, tenantID)
	if err != nil {
		logger.Log.Warn("MeteringAggregator: failed to get bandwidth bytes",
			zap.String("tenant_id", tid),
			zap.Error(err),
		)
		lastErr = err
	} else if bandwidthBytes > 0 {
		if recErr := a.metering.RecordRealtimeMetric(ctx, RealtimeMetric{
			TenantID:   tenantID,
			MetricName: MetricBandwidthBytes,
			Value:      bandwidthBytes,
			Timestamp:  time.Now(),
		}); recErr != nil {
			logger.Log.Warn("MeteringAggregator: failed to record bandwidth bytes",
				zap.String("tenant_id", tid),
				zap.Error(recErr),
			)
			lastErr = recErr
		} else {
			logger.Log.Debug("MeteringAggregator: bandwidth bytes recorded",
				zap.String("tenant_id", tid),
				zap.Int64("bandwidth_bytes", bandwidthBytes),
			)
		}
	}

	// ── API request count ───────────────────────────────────────────────────
	if apiErr := a.scrapeAndRecordAPIRequests(ctx, tenantID, tid); apiErr != nil && lastErr == nil {
		lastErr = apiErr
	}

	return lastErr
}

// scrapeAndRecordAPIRequests fetches the API request count for the tenant from APISIX and records it.
func (a *MeteringAggregator) scrapeAndRecordAPIRequests(ctx context.Context, tenantID uuid.UUID, tid string) error {
	apiRequests, err := a.apisixScraper.GetTenantAPIRequests(ctx, tenantID)
	if err != nil {
		logger.Log.Warn("MeteringAggregator: failed to get API requests",
			zap.String("tenant_id", tid),
			zap.Error(err),
		)
		return err
	}
	if apiRequests <= 0 {
		return nil
	}
	if recErr := a.metering.RecordRealtimeMetric(ctx, RealtimeMetric{
		TenantID:   tenantID,
		MetricName: MetricAPIRequests,
		Value:      apiRequests,
		Timestamp:  time.Now(),
	}); recErr != nil {
		logger.Log.Warn("MeteringAggregator: failed to record API requests",
			zap.String("tenant_id", tid),
			zap.Error(recErr),
		)
		return recErr
	}
	logger.Log.Debug("MeteringAggregator: API requests recorded",
		zap.String("tenant_id", tid),
		zap.Int64("api_requests", apiRequests),
	)
	return nil
}
