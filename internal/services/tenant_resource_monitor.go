// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
)

const (
	defaultMonitorInterval = 60 * time.Second

	// noisyConnectionThreshold is the fraction of total active connections
	// a single tenant must hold to be flagged as a noisy neighbor (0.30 = 30 %).
	noisyConnectionThreshold = 0.30

	// noisyQueryTimeThreshold is the fraction of cumulative active-query time
	// a single tenant must hold to be flagged as a noisy neighbor (0.50 = 50 %).
	noisyQueryTimeThreshold = 0.50

	// resourceSnapshotTTL is how long each per-tenant snapshot is kept in Redis.
	resourceSnapshotTTL = 5 * time.Minute

	// noisyFlagTTL is how long the "tenant is noisy" flag lives in Redis.
	// It is shorter than the snapshot TTL so throttling auto-clears when a
	// previously noisy tenant returns to normal usage.
	noisyFlagTTL = 2 * time.Minute
)

// TenantResourceSnapshot captures a point-in-time database resource usage
// reading for a single tenant.
type TenantResourceSnapshot struct {
	TenantID          string  `json:"tenant_id"`
	ActiveConnections int     `json:"active_connections"`
	TotalQueryTimeMS  float64 `json:"total_query_time_ms"`
	QueryCount        int64   `json:"query_count"`
	IsNoisy           bool    `json:"is_noisy"`
	CapturedAt        string  `json:"captured_at"`
}

// TenantResourceMonitor is a background worker that periodically queries
// pg_stat_activity grouped by the per-request tenant context variable
// (app.current_tenant_id) and stores per-tenant resource snapshots in Redis.
//
// Any tenant that consumes more than noisyConnectionThreshold of total
// connections or noisyQueryTimeThreshold of cumulative active-query time is
// flagged as a noisy neighbor via a short-lived Redis key. The
// TenantThrottleMiddleware reads that key to apply back-pressure.
//
// Start the monitor with Start() in a background goroutine; cancel the
// supplied context or call Stop() to shut it down cleanly.
type TenantResourceMonitor struct {
	pool     *pgxpool.Pool
	redis    redis.Cmdable
	interval time.Duration
	log      *zap.SugaredLogger
	stopCh   chan struct{}
}

// NewTenantResourceMonitor creates a TenantResourceMonitor with a 60-second
// sampling interval.
func NewTenantResourceMonitor(
	pool *pgxpool.Pool,
	redisClient redis.Cmdable,
	log *zap.SugaredLogger,
) *TenantResourceMonitor {
	return &TenantResourceMonitor{
		pool:     pool,
		redis:    redisClient,
		interval: defaultMonitorInterval,
		log:      log,
		stopCh:   make(chan struct{}),
	}
}

// Start begins the sampling loop.  Call in a dedicated goroutine:
//
//	go monitor.Start(ctx)
//
// An initial sample is taken immediately so data is available before the
// first interval elapses.
func (m *TenantResourceMonitor) Start(ctx context.Context) {
	m.log.Infow("TenantResourceMonitor: starting",
		"interval", m.interval,
	)

	ticker := time.NewTicker(m.interval)
	defer ticker.Stop()

	m.sample(ctx)

	for {
		select {
		case <-ticker.C:
			m.sample(ctx)
		case <-m.stopCh:
			m.log.Infow("TenantResourceMonitor: stopped")
			return
		case <-ctx.Done():
			m.log.Infow("TenantResourceMonitor: context cancelled, stopping")
			return
		}
	}
}

// Stop signals the worker to cease after the current sample round completes.
// Safe to call more than once.
func (m *TenantResourceMonitor) Stop() {
	select {
	case <-m.stopCh:
		// Already closed.
	default:
		close(m.stopCh)
	}
}

// GetSnapshots retrieves all tenant resource snapshots currently stored in
// Redis.  The result set reflects the most recent sampling round.  An empty
// slice is returned when Redis is unavailable or no data has been collected yet.
func (m *TenantResourceMonitor) GetSnapshots(ctx context.Context) ([]TenantResourceSnapshot, error) {
	if m.redis == nil {
		return nil, fmt.Errorf("TenantResourceMonitor: redis not configured")
	}

	// Scan for all snapshot keys.
	pattern := "tenant_resource:*"
	var keys []string
	var cursor uint64
	for {
		batch, nextCursor, err := m.redis.Scan(ctx, cursor, pattern, 100).Result()
		if err != nil {
			return nil, fmt.Errorf("TenantResourceMonitor.GetSnapshots: scan: %w", err)
		}
		keys = append(keys, batch...)
		cursor = nextCursor
		if cursor == 0 {
			break
		}
	}

	if len(keys) == 0 {
		return []TenantResourceSnapshot{}, nil
	}

	snapshots := make([]TenantResourceSnapshot, 0, len(keys))
	for _, key := range keys {
		raw, err := m.redis.Get(ctx, key).Result()
		if err != nil {
			// Key may have expired between the SCAN and GET — skip it.
			continue
		}

		var snap TenantResourceSnapshot
		if err := json.Unmarshal([]byte(raw), &snap); err != nil {
			m.log.Warnw("TenantResourceMonitor: corrupt snapshot in Redis",
				"key", key,
				"err", err,
			)
			continue
		}
		snapshots = append(snapshots, snap)
	}

	return snapshots, nil
}

// sample executes a single pg_stat_activity query, computes per-tenant
// resource usage, determines noisy neighbors, and stores results in Redis.
func (m *TenantResourceMonitor) sample(ctx context.Context) {
	// Query pg_stat_activity across ALL databases on this PostgreSQL server,
	// not just current_database(). Group by datname to capture per-database
	// (effectively per-tenant in pool isolation mode) resource usage.
	// Fall back to app.current_tenant_id if set, otherwise use datname.
	rows, err := m.pool.Query(ctx, `
		SELECT
			coalesce(
				nullif(current_setting('app.current_tenant_id', true), ''),
				datname
			) AS tenant_id,
			count(*)::int                                                 AS active_connections,
			coalesce(
				sum(extract(epoch from (now() - coalesce(query_start, xact_start, backend_start))) * 1000),
				0
			)::double precision                                           AS total_query_time_ms
		FROM pg_stat_activity
		WHERE pid <> pg_backend_pid()
		  AND datname IS NOT NULL
		  AND datname NOT IN ('template0', 'template1', 'postgres')
		GROUP BY 1
	`)
	if err != nil {
		m.log.Warnw("TenantResourceMonitor: pg_stat_activity query failed", "err", err)
		return
	}
	defer rows.Close()

	type rawRow struct {
		tenantID    string
		connections int
		queryTimeMS float64
	}

	var scannedRows []rawRow
	var totalConns int
	var totalQueryTimeMS float64

	for rows.Next() {
		var r rawRow
		if err := rows.Scan(&r.tenantID, &r.connections, &r.queryTimeMS); err != nil {
			m.log.Warnw("TenantResourceMonitor: row scan error", "err", err)
			continue
		}
		scannedRows = append(scannedRows, r)
		totalConns += r.connections
		totalQueryTimeMS += r.queryTimeMS
	}
	if err := rows.Err(); err != nil {
		m.log.Warnw("TenantResourceMonitor: rows iteration error", "err", err)
	}

	now := time.Now().UTC().Format(time.RFC3339)
	for _, r := range scannedRows {
		if r.tenantID == "" {
			// Skip connections without a tenant context (e.g. background processes).
			continue
		}

		isNoisy := false
		if totalConns > 0 && float64(r.connections)/float64(totalConns) > noisyConnectionThreshold {
			isNoisy = true
		}
		if totalQueryTimeMS > 0 && r.queryTimeMS/totalQueryTimeMS > noisyQueryTimeThreshold {
			isNoisy = true
		}

		snap := TenantResourceSnapshot{
			TenantID:          r.tenantID,
			ActiveConnections: r.connections,
			TotalQueryTimeMS:  r.queryTimeMS,
			IsNoisy:           isNoisy,
			CapturedAt:        now,
		}

		data, err := json.Marshal(snap)
		if err != nil {
			m.log.Warnw("TenantResourceMonitor: marshal snapshot", "tenant_id", r.tenantID, "err", err)
			continue
		}

		snapshotKey := fmt.Sprintf("tenant_resource:%s", r.tenantID)
		if err := m.redis.Set(ctx, snapshotKey, data, resourceSnapshotTTL).Err(); err != nil {
			m.log.Warnw("TenantResourceMonitor: write snapshot to Redis",
				"tenant_id", r.tenantID,
				"err", err,
			)
		}

		// Write or clear the noisy flag.
		noisyKey := fmt.Sprintf("tenant_noisy:%s", r.tenantID)
		if isNoisy {
			if err := m.redis.Set(ctx, noisyKey, "1", noisyFlagTTL).Err(); err != nil {
				m.log.Warnw("TenantResourceMonitor: set noisy flag",
					"tenant_id", r.tenantID,
					"err", err,
				)
			}
			m.log.Warnw("TenantResourceMonitor: noisy neighbor detected",
				"tenant_id", r.tenantID,
				"active_connections", r.connections,
				"total_connections", totalConns,
				"query_time_ms", r.queryTimeMS,
				"total_query_time_ms", totalQueryTimeMS,
			)
		} else {
			// Proactively clear a previously set flag so honest tenants are
			// un-throttled without waiting for the TTL to expire.
			_ = m.redis.Del(ctx, noisyKey).Err()
		}
	}

	m.log.Debugw("TenantResourceMonitor: sample complete",
		"tenants_observed", len(scannedRows),
		"total_connections", totalConns,
	)
}
