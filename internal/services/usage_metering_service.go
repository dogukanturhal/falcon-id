// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/pkg/logger"
)

// Metric type constants for real-time metering.
const (
	MetricComputeHours        = "compute_hours"
	MetricStorageBytes        = "storage_bytes"
	MetricBandwidthBytes      = "bandwidth_bytes"
	MetricAPIRequests         = "api_requests"
	MetricFunctionInvocations = "function_invocations"
)

// realtimeMetricMeta describes display metadata for a known metric.
type realtimeMetricMeta struct {
	Unit        string
	Description string
}

// knownMetrics holds display metadata for well-known metric names.
var knownMetrics = map[string]realtimeMetricMeta{
	MetricComputeHours:        {Unit: "hours", Description: "Compute instance-hours consumed"},
	MetricStorageBytes:        {Unit: "bytes", Description: "Object storage bytes used"},
	MetricBandwidthBytes:      {Unit: "bytes", Description: "Egress bandwidth consumed"},
	MetricAPIRequests:         {Unit: "requests", Description: "API gateway requests processed"},
	MetricFunctionInvocations: {Unit: "invocations", Description: "Serverless function invocations"},
}

// usageMeteringRedisClient is the narrow Redis interface used by UsageMeteringService.
// Only the operations required for real-time counter management are included so that
// mocks and alternative implementations remain lightweight.
type usageMeteringRedisClient interface {
	IncrBy(ctx context.Context, key string, value int64) (int64, error)
	Get(ctx context.Context, key string) (string, error)
	Expire(ctx context.Context, key string, ttl time.Duration) error
}

// RealtimeMetric represents a real-time metric counter increment event.
type RealtimeMetric struct {
	TenantID   uuid.UUID `json:"tenant_id"`
	ProductID  uuid.UUID `json:"product_id"`
	MetricName string    `json:"metric_name"`
	Value      int64     `json:"value"`
	Timestamp  time.Time `json:"timestamp"`
}

// RealtimeSummary shows current real-time metric counters for a tenant.
type RealtimeSummary struct {
	TenantID uuid.UUID                     `json:"tenant_id"`
	Metrics  map[string]RealtimeMetricInfo `json:"metrics"`
	AsOf     time.Time                     `json:"as_of"`
}

// RealtimeMetricInfo holds the current value and display metadata for a metric.
type RealtimeMetricInfo struct {
	Current     int64  `json:"current"`
	Unit        string `json:"unit"`
	Description string `json:"description"`
}

// usageRecordRepo defines the repository interface for usage records.
type usageRecordRepo interface {
	Record(ctx context.Context, record *models.UsageRecord) error
	GetByTenantAndProduct(ctx context.Context, tenantID, productID uuid.UUID, metricName string, periodStart, periodEnd time.Time) (*models.UsageRecord, error)
	ListByTenant(ctx context.Context, tenantID uuid.UUID, periodStart, periodEnd time.Time, page, pageSize int) ([]models.UsageRecord, int64, error)
	Aggregate(ctx context.Context, tenantID, productID uuid.UUID, metricName string, from, to time.Time) (int64, error)
}

// UsageMeteringService records and queries product usage metrics for tenants.
// The optional redis field enables real-time counter tracking; when nil, the
// real-time methods return ErrNoRedis and the period-based methods continue to
// work normally.
type UsageMeteringService struct {
	repo  usageRecordRepo
	redis usageMeteringRedisClient
}

// NewUsageMeteringService creates a new UsageMeteringService.
func NewUsageMeteringService(repo usageRecordRepo) *UsageMeteringService {
	return &UsageMeteringService{repo: repo}
}

// SetRedisClient wires a Redis client into the service to enable real-time
// counter tracking.  Call this after construction, before Start/use.
// Passing nil disables real-time tracking (real-time methods return ErrNoRedis).
func (s *UsageMeteringService) SetRedisClient(client usageMeteringRedisClient) {
	s.redis = client
}

// ErrNoRedis is returned by real-time methods when no Redis client is configured.
var ErrNoRedis = errors.New("UsageMeteringService: redis client not configured")

// realtimeKey builds the Redis key for a tenant+metric counter on a given date.
// Pattern: usage:{tenant_id}:{metric_name}:{date}  (date = YYYY-MM-DD UTC)
func realtimeKey(tenantID uuid.UUID, metricName string, date time.Time) string {
	return fmt.Sprintf("usage:%s:%s:%s",
		tenantID.String(),
		metricName,
		date.UTC().Format("2006-01-02"),
	)
}

// RecordUsage persists a usage record event. The record's TenantID and ProductID
// must be non-nil; MetricName must be provided.
func (s *UsageMeteringService) RecordUsage(ctx context.Context, record *models.UsageRecord) error {
	if record.TenantID == uuid.Nil {
		return fmt.Errorf("UsageMeteringService.RecordUsage: tenant_id is required")
	}
	if record.ProductID == uuid.Nil {
		return fmt.Errorf("UsageMeteringService.RecordUsage: product_id is required")
	}
	if record.MetricName == "" {
		return fmt.Errorf("UsageMeteringService.RecordUsage: metric_name is required")
	}

	if err := s.repo.Record(ctx, record); err != nil {
		return fmt.Errorf("UsageMeteringService.RecordUsage: %w", err)
	}

	logger.Info("Usage recorded",
		zap.String("tenant_id", record.TenantID.String()),
		zap.String("product_id", record.ProductID.String()),
		zap.String("metric_name", record.MetricName),
		zap.Int64("value", record.Value),
	)

	return nil
}

// GetUsageSummary returns all usage records for a tenant within the given time range.
func (s *UsageMeteringService) GetUsageSummary(
	ctx context.Context,
	tenantID uuid.UUID,
	from, to time.Time,
) ([]models.UsageRecord, error) {
	if from.IsZero() {
		from = time.Now().AddDate(0, -1, 0) // default: last 30 days
	}
	if to.IsZero() {
		to = time.Now()
	}

	records, _, err := s.repo.ListByTenant(ctx, tenantID, from, to, 1, 1000)
	if err != nil {
		return nil, fmt.Errorf("UsageMeteringService.GetUsageSummary: %w", err)
	}
	return records, nil
}

// GetProductUsage returns the aggregated usage quantity for a specific product
// and metric within the given period.
func (s *UsageMeteringService) GetProductUsage(
	ctx context.Context,
	tenantID, productID uuid.UUID,
	metric string,
	from, to time.Time,
) (int64, error) {
	if metric == "" {
		return 0, fmt.Errorf("UsageMeteringService.GetProductUsage: metric is required")
	}

	total, err := s.repo.Aggregate(ctx, tenantID, productID, metric, from, to)
	if err != nil {
		return 0, fmt.Errorf("UsageMeteringService.GetProductUsage: %w", err)
	}
	return total, nil
}

// RecordRealtimeMetric increments a real-time counter in Redis for the given metric.
// The counter is keyed by tenant, metric name, and the UTC date derived from
// metric.Timestamp (or time.Now() when Timestamp is zero).  A 48-hour TTL is
// applied on every write to allow the background aggregator a full day of slack
// after a counter's calendar day closes before it must flush to the database.
//
// When no Redis client is configured, ErrNoRedis is returned.  Callers that
// treat Redis as a best-effort acceleration layer should log and continue.
func (s *UsageMeteringService) RecordRealtimeMetric(ctx context.Context, metric RealtimeMetric) error {
	if s.redis == nil {
		return ErrNoRedis
	}
	if metric.TenantID == uuid.Nil {
		return fmt.Errorf("UsageMeteringService.RecordRealtimeMetric: tenant_id is required")
	}
	if metric.MetricName == "" {
		return fmt.Errorf("UsageMeteringService.RecordRealtimeMetric: metric_name is required")
	}
	if metric.Value <= 0 {
		return fmt.Errorf("UsageMeteringService.RecordRealtimeMetric: value must be > 0")
	}

	ts := metric.Timestamp
	if ts.IsZero() {
		ts = time.Now()
	}

	key := realtimeKey(metric.TenantID, metric.MetricName, ts)

	if _, err := s.redis.IncrBy(ctx, key, metric.Value); err != nil {
		return fmt.Errorf("UsageMeteringService.RecordRealtimeMetric: %w", err)
	}

	// 48-hour TTL: allows aggregation lag of up to 24 h after the day rolls over.
	const realtimeTTL = 48 * time.Hour
	if err := s.redis.Expire(ctx, key, realtimeTTL); err != nil {
		// Non-fatal: the key was already written; log and continue.
		logger.Log.Warn("UsageMeteringService.RecordRealtimeMetric: failed to set TTL",
			zap.String("key", key),
			zap.Error(err),
		)
	}

	logger.Log.Debug("Realtime metric recorded",
		zap.String("tenant_id", metric.TenantID.String()),
		zap.String("metric_name", metric.MetricName),
		zap.Int64("value", metric.Value),
		zap.String("key", key),
	)

	return nil
}

// GetRealtimeSummary returns the current-day real-time counters for all known
// metrics for the given tenant.  Missing keys (metrics with no activity today)
// are reported with a zero value.
//
// When no Redis client is configured, ErrNoRedis is returned.
func (s *UsageMeteringService) GetRealtimeSummary(ctx context.Context, tenantID uuid.UUID) (*RealtimeSummary, error) {
	if s.redis == nil {
		return nil, ErrNoRedis
	}
	if tenantID == uuid.Nil {
		return nil, fmt.Errorf("UsageMeteringService.GetRealtimeSummary: tenant_id is required")
	}

	now := time.Now().UTC()
	summary := &RealtimeSummary{
		TenantID: tenantID,
		Metrics:  make(map[string]RealtimeMetricInfo, len(knownMetrics)),
		AsOf:     now,
	}

	for name, meta := range knownMetrics {
		key := realtimeKey(tenantID, name, now)
		raw, err := s.redis.Get(ctx, key)

		var current int64
		if err != nil {
			// redis.Nil means the key doesn't exist yet — counter is zero.
			if !errors.Is(err, redis.Nil) {
				return nil, fmt.Errorf("UsageMeteringService.GetRealtimeSummary: metric %q: %w", name, err)
			}
		} else {
			current, _ = strconv.ParseInt(raw, 10, 64)
		}

		summary.Metrics[name] = RealtimeMetricInfo{
			Current:     current,
			Unit:        meta.Unit,
			Description: meta.Description,
		}
	}

	return summary, nil
}

// FlushRealtimeToDatabase moves accumulated today's Redis counters for all known
// metrics into iam_usage_counters via the usage record repository.  This method
// is idempotent: it performs an upsert so repeated flushes in the same calendar
// day safely overwrite the previous aggregation result with the latest counter.
//
// When no Redis client is configured, ErrNoRedis is returned.
func (s *UsageMeteringService) FlushRealtimeToDatabase(ctx context.Context, tenantID uuid.UUID) error {
	if s.redis == nil {
		return ErrNoRedis
	}
	if tenantID == uuid.Nil {
		return fmt.Errorf("UsageMeteringService.FlushRealtimeToDatabase: tenant_id is required")
	}

	now := time.Now().UTC()
	today := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
	tomorrow := today.Add(24 * time.Hour)

	flushed := 0
	for name := range knownMetrics {
		key := realtimeKey(tenantID, name, now)
		raw, err := s.redis.Get(ctx, key)
		if err != nil {
			if errors.Is(err, redis.Nil) {
				// No counter recorded today for this metric — nothing to flush.
				continue
			}
			return fmt.Errorf("UsageMeteringService.FlushRealtimeToDatabase: read metric %q: %w", name, err)
		}

		value, err := strconv.ParseInt(raw, 10, 64)
		if err != nil || value == 0 {
			continue
		}

		record := &models.UsageRecord{
			TenantID:    tenantID,
			ProductID:   uuid.Nil, // realtime counters are product-agnostic at flush time
			MetricName:  name,
			Value:       value,
			PeriodStart: today,
			PeriodEnd:   tomorrow,
		}

		if err := s.repo.Record(ctx, record); err != nil {
			return fmt.Errorf("UsageMeteringService.FlushRealtimeToDatabase: persist metric %q: %w", name, err)
		}
		flushed++
	}

	logger.Log.Info("Realtime counters flushed to database",
		zap.String("tenant_id", tenantID.String()),
		zap.Int("metrics_flushed", flushed),
	)

	return nil
}
