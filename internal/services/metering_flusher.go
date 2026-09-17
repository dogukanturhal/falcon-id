// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
)

const (
	// defaultFlusherInterval is how often the flusher wakes up to write
	// accumulated Redis counters to PostgreSQL.
	defaultFlusherInterval = time.Hour

	// meterKeyPrefix is the shared prefix for all metering hash keys.
	// Full key format: meter:{tenant_id}:{YYYYMMDDHH}
	meterKeyPrefix = "meter:"
)

// MeteringFlusher is a background worker that periodically drains per-tenant
// API consumption counters from Redis into the iam_tenant_usage_records
// PostgreSQL table.
//
// The MeteringMiddleware writes incremental counts into Redis hash keys of the
// form   meter:{tenant_id}:{YYYYMMDDHH}
// with a 25-hour TTL.  Once per interval the flusher scans for keys belonging
// to the *previous* hour, reads each hash, upserts a row into
// iam_tenant_usage_records, and deletes the key.
//
// Start the flusher with Start() in a background goroutine; cancel the context
// or call Stop() to stop cleanly.
type MeteringFlusher struct {
	pool     *pgxpool.Pool
	redis    redis.Cmdable
	interval time.Duration
	log      *zap.SugaredLogger
	stopCh   chan struct{}
}

// NewMeteringFlusher creates a MeteringFlusher with a 1-hour flush interval.
func NewMeteringFlusher(
	pool *pgxpool.Pool,
	redisClient redis.Cmdable,
	log *zap.SugaredLogger,
) *MeteringFlusher {
	return &MeteringFlusher{
		pool:     pool,
		redis:    redisClient,
		interval: defaultFlusherInterval,
		log:      log,
		stopCh:   make(chan struct{}),
	}
}

// Start begins the flush loop.  Call in a dedicated goroutine:
//
//	go flusher.Start(ctx)
func (f *MeteringFlusher) Start(ctx context.Context) {
	f.log.Infow("MeteringFlusher: starting", "interval", f.interval)

	ticker := time.NewTicker(f.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			f.flush(ctx)
		case <-f.stopCh:
			f.log.Infow("MeteringFlusher: stopped")
			return
		case <-ctx.Done():
			f.log.Infow("MeteringFlusher: context cancelled, stopping")
			return
		}
	}
}

// Stop signals the worker to cease.  Safe to call multiple times.
func (f *MeteringFlusher) Stop() {
	select {
	case <-f.stopCh:
		// Already closed.
	default:
		close(f.stopCh)
	}
}

// flush scans Redis for metering keys from the previous hour, upserts each
// into iam_tenant_usage_records, then deletes the processed keys.
func (f *MeteringFlusher) flush(ctx context.Context) {
	// Target the previous completed hour bucket.
	prevHour := time.Now().UTC().Add(-time.Hour).Truncate(time.Hour)
	hourSuffix := prevHour.Format("2006010215") // YYYYMMDDHH

	pattern := meterKeyPrefix + "*:" + hourSuffix
	var keys []string
	var cursor uint64
	for {
		batch, nextCursor, err := f.redis.Scan(ctx, cursor, pattern, 200).Result()
		if err != nil {
			f.log.Warnw("MeteringFlusher: Redis SCAN failed",
				"pattern", pattern,
				"err", err,
			)
			return
		}
		keys = append(keys, batch...)
		cursor = nextCursor
		if cursor == 0 {
			break
		}
	}

	if len(keys) == 0 {
		f.log.Debugw("MeteringFlusher: no metering keys to flush", "hour", hourSuffix)
		return
	}

	periodEnd := prevHour.Add(time.Hour)

	flushed := 0
	for _, key := range keys {
		tenantID, ok := tenantIDFromMeterKey(key, hourSuffix)
		if !ok {
			f.log.Warnw("MeteringFlusher: unexpected key format, skipping", "key", key)
			continue
		}

		data, err := f.redis.HGetAll(ctx, key).Result()
		if err != nil {
			f.log.Warnw("MeteringFlusher: HGETALL failed",
				"key", key,
				"err", err,
			)
			continue
		}

		if len(data) == 0 {
			// Key exists but is empty — delete and move on.
			_ = f.redis.Del(ctx, key)
			continue
		}

		requests := parseInt64(data["requests"])
		apiErrors := parseInt64(data["errors"])
		computeMS := parseFloat64(data["compute_ms"])
		computeSec := computeMS / 1000.0

		if err := f.upsert(ctx, tenantID, prevHour, periodEnd, requests, apiErrors, computeSec); err != nil {
			f.log.Warnw("MeteringFlusher: upsert failed",
				"tenant_id", tenantID,
				"hour", hourSuffix,
				"err", err,
			)
			// Do not delete the key — it will be retried next cycle.
			continue
		}

		if err := f.redis.Del(ctx, key).Err(); err != nil {
			f.log.Warnw("MeteringFlusher: failed to delete processed key",
				"key", key,
				"err", err,
			)
		}
		flushed++
	}

	f.log.Infow("MeteringFlusher: flush complete",
		"hour", hourSuffix,
		"keys_found", len(keys),
		"keys_flushed", flushed,
	)
}

// upsert writes (or merges) a usage record row into iam_tenant_usage_records.
// On conflict (same tenant_id + period_start) existing counters are incremented
// so that a partial flush followed by a retry does not lose data.
func (f *MeteringFlusher) upsert(
	ctx context.Context,
	tenantID string,
	periodStart, periodEnd time.Time,
	requests, apiErrors int64,
	computeSeconds float64,
) error {
	const query = `
		INSERT INTO iam_tenant_usage_records
			(tenant_id, period_start, period_end, api_requests, api_errors, compute_seconds, updated_at)
		VALUES
			($1::uuid, $2, $3, $4, $5, $6, NOW())
		ON CONFLICT (tenant_id, period_start) DO UPDATE SET
			api_requests    = iam_tenant_usage_records.api_requests    + EXCLUDED.api_requests,
			api_errors      = iam_tenant_usage_records.api_errors      + EXCLUDED.api_errors,
			compute_seconds = iam_tenant_usage_records.compute_seconds + EXCLUDED.compute_seconds,
			updated_at      = NOW()
	`

	if _, err := f.pool.Exec(ctx, query,
		tenantID, periodStart, periodEnd,
		requests, apiErrors, computeSeconds,
	); err != nil {
		return fmt.Errorf("MeteringFlusher.upsert: %w", err)
	}
	return nil
}

// TenantUsageRecord is the API representation returned by the metering endpoints.
type TenantUsageRecord struct {
	ID                     string  `json:"id"`
	TenantID               string  `json:"tenant_id"`
	PeriodStart            string  `json:"period_start"`
	PeriodEnd              string  `json:"period_end"`
	APIRequests            int64   `json:"api_requests"`
	APIErrors              int64   `json:"api_errors"`
	StorageBytesUploaded   int64   `json:"storage_bytes_uploaded"`
	StorageBytesDownloaded int64   `json:"storage_bytes_downloaded"`
	DBQueries              int64   `json:"db_queries"`
	ComputeSeconds         float64 `json:"compute_seconds"`
	CreatedAt              string  `json:"created_at"`
	UpdatedAt              string  `json:"updated_at"`
}

// GetTenantUsage queries iam_tenant_usage_records for a single tenant within
// an inclusive time range.  Results are ordered by period_start ascending.
func GetTenantUsage(
	ctx context.Context,
	pool *pgxpool.Pool,
	tenantID string,
	from, to time.Time,
) ([]TenantUsageRecord, error) {
	const query = `
		SELECT
			id::text,
			tenant_id::text,
			period_start,
			period_end,
			api_requests,
			api_errors,
			storage_bytes_uploaded,
			storage_bytes_downloaded,
			db_queries,
			compute_seconds,
			created_at,
			updated_at
		FROM iam_tenant_usage_records
		WHERE tenant_id = $1::uuid
		  AND period_start >= $2
		  AND period_start <= $3
		ORDER BY period_start ASC
	`

	rows, err := pool.Query(ctx, query, tenantID, from, to)
	if err != nil {
		return nil, fmt.Errorf("GetTenantUsage: %w", err)
	}
	defer rows.Close()

	var records []TenantUsageRecord
	for rows.Next() {
		var r TenantUsageRecord
		var periodStart, periodEnd, createdAt, updatedAt time.Time
		if err := rows.Scan(
			&r.ID, &r.TenantID,
			&periodStart, &periodEnd,
			&r.APIRequests, &r.APIErrors,
			&r.StorageBytesUploaded, &r.StorageBytesDownloaded,
			&r.DBQueries, &r.ComputeSeconds,
			&createdAt, &updatedAt,
		); err != nil {
			return nil, fmt.Errorf("GetTenantUsage: scan: %w", err)
		}
		r.PeriodStart = periodStart.UTC().Format(time.RFC3339)
		r.PeriodEnd = periodEnd.UTC().Format(time.RFC3339)
		r.CreatedAt = createdAt.UTC().Format(time.RFC3339)
		r.UpdatedAt = updatedAt.UTC().Format(time.RFC3339)
		records = append(records, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("GetTenantUsage: rows: %w", err)
	}
	return records, nil
}

// GetMeteringSummary returns the latest usage record per tenant across all
// tenants, ordered by api_requests descending (highest consumers first).
// Only records whose period_start falls within [from, to] are included.
func GetMeteringSummary(
	ctx context.Context,
	pool *pgxpool.Pool,
	from, to time.Time,
) ([]TenantUsageRecord, error) {
	const query = `
		SELECT
			id::text,
			tenant_id::text,
			period_start,
			period_end,
			api_requests,
			api_errors,
			storage_bytes_uploaded,
			storage_bytes_downloaded,
			db_queries,
			compute_seconds,
			created_at,
			updated_at
		FROM iam_tenant_usage_records
		WHERE period_start >= $1
		  AND period_start <= $2
		ORDER BY api_requests DESC
	`

	rows, err := pool.Query(ctx, query, from, to)
	if err != nil {
		return nil, fmt.Errorf("GetMeteringSummary: %w", err)
	}
	defer rows.Close()

	var records []TenantUsageRecord
	for rows.Next() {
		var r TenantUsageRecord
		var periodStart, periodEnd, createdAt, updatedAt time.Time
		if err := rows.Scan(
			&r.ID, &r.TenantID,
			&periodStart, &periodEnd,
			&r.APIRequests, &r.APIErrors,
			&r.StorageBytesUploaded, &r.StorageBytesDownloaded,
			&r.DBQueries, &r.ComputeSeconds,
			&createdAt, &updatedAt,
		); err != nil {
			return nil, fmt.Errorf("GetMeteringSummary: scan: %w", err)
		}
		r.PeriodStart = periodStart.UTC().Format(time.RFC3339)
		r.PeriodEnd = periodEnd.UTC().Format(time.RFC3339)
		r.CreatedAt = createdAt.UTC().Format(time.RFC3339)
		r.UpdatedAt = updatedAt.UTC().Format(time.RFC3339)
		records = append(records, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("GetMeteringSummary: rows: %w", err)
	}
	return records, nil
}

// tenantIDFromMeterKey extracts the tenant ID segment from a meter key.
// Key format: meter:{tenant_id}:{YYYYMMDDHH}
func tenantIDFromMeterKey(key, hourSuffix string) (tenantID string, ok bool) {
	// Strip leading "meter:" prefix.
	without := strings.TrimPrefix(key, meterKeyPrefix)
	// Strip trailing ":{YYYYMMDDHH}" suffix.
	suffix := ":" + hourSuffix
	if !strings.HasSuffix(without, suffix) {
		return "", false
	}
	tenantID = strings.TrimSuffix(without, suffix)
	if tenantID == "" {
		return "", false
	}
	return tenantID, true
}

func parseInt64(s string) int64 {
	v, _ := strconv.ParseInt(s, 10, 64)
	return v
}

func parseFloat64(s string) float64 {
	v, _ := strconv.ParseFloat(s, 64)
	return v
}
