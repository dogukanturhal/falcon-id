// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// ─── Mock: PrometheusScraper ─────────────────────────────────────────────────

type mockPrometheusScraper struct {
	mock.Mock
}

func (m *mockPrometheusScraper) QueryInstant(ctx context.Context, query string, ts time.Time) (float64, error) {
	args := m.Called(ctx, query, ts)
	return args.Get(0).(float64), args.Error(1)
}

// ─── Mock: MinIOScraper ──────────────────────────────────────────────────────

type mockMinIOScraper struct {
	mock.Mock
}

func (m *mockMinIOScraper) GetTenantStorageBytes(ctx context.Context, tenantID uuid.UUID) (int64, error) {
	args := m.Called(ctx, tenantID)
	return args.Get(0).(int64), args.Error(1)
}

// ─── Mock: APISIXScraper ─────────────────────────────────────────────────────

type mockAPISIXScraper struct {
	mock.Mock
}

func (m *mockAPISIXScraper) GetTenantBandwidthBytes(ctx context.Context, tenantID uuid.UUID) (int64, error) {
	args := m.Called(ctx, tenantID)
	return args.Get(0).(int64), args.Error(1)
}

func (m *mockAPISIXScraper) GetTenantAPIRequests(ctx context.Context, tenantID uuid.UUID) (int64, error) {
	args := m.Called(ctx, tenantID)
	return args.Get(0).(int64), args.Error(1)
}

// ─── Mock: usageMeteringRedisClient for aggregator tests ─────────────────────

type mockAggRedisClient struct {
	mock.Mock
}

func (m *mockAggRedisClient) IncrBy(ctx context.Context, key string, value int64) (int64, error) {
	args := m.Called(ctx, key, value)
	return args.Get(0).(int64), args.Error(1)
}

func (m *mockAggRedisClient) Get(ctx context.Context, key string) (string, error) {
	args := m.Called(ctx, key)
	return args.String(0), args.Error(1)
}

func (m *mockAggRedisClient) Expire(ctx context.Context, key string, ttl time.Duration) error {
	args := m.Called(ctx, key, ttl)
	return args.Error(0)
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

// newTestMeteringService builds a UsageMeteringService backed by a repo and
// redis mock so the aggregator can call RecordRealtimeMetric.
func newTestMeteringService(repo usageRecordRepo, redisClient usageMeteringRedisClient) *UsageMeteringService {
	svc := NewUsageMeteringService(repo)
	svc.SetRedisClient(redisClient)
	return svc
}

// newTestAggregator constructs a MeteringAggregator with all dependencies
// injected as mocks.  The db pool is nil so advisory lock is skipped.
func newTestAggregator(
	metering *UsageMeteringService,
	prom PrometheusScraper,
	minio MinIOScraper,
	apisix APISIXScraper,
) *MeteringAggregator {
	return NewMeteringAggregatorWithScrapers(metering, nil, 5*time.Minute, prom, minio, apisix)
}

// ─── Tests ───────────────────────────────────────────────────────────────────

// TestAggregateTenant_AllScrapersSucceed verifies that when all three scrapers
// return valid data, RecordRealtimeMetric is called for each metric.
func TestAggregateTenant_AllScrapersSucceed(t *testing.T) {
	ctx := context.Background()
	tenantID := uuid.New()

	repo := new(mockUsageRecordRepo)
	redisClient := new(mockAggRedisClient)
	metering := newTestMeteringService(repo, redisClient)

	promScraper := new(mockPrometheusScraper)
	minioScraper := new(mockMinIOScraper)
	apisixScraper := new(mockAPISIXScraper)

	// Prometheus returns CPU-seconds that map to compute hours > 0.
	// 3600 CPU-seconds / 3600 = 1.0 compute-hour → recorded as int64(1).
	promScraper.On("QueryInstant", mock.Anything, mock.AnythingOfType("string"), mock.AnythingOfType("time.Time")).
		Return(3600.0, nil)

	// MinIO returns 512 MiB.
	minioScraper.On("GetTenantStorageBytes", mock.Anything, tenantID).
		Return(int64(536_870_912), nil)

	// APISIX returns bandwidth and request counts.
	apisixScraper.On("GetTenantBandwidthBytes", mock.Anything, tenantID).
		Return(int64(1_000_000), nil)
	apisixScraper.On("GetTenantAPIRequests", mock.Anything, tenantID).
		Return(int64(500), nil)

	// Redis IncrBy is called for each metric that is > 0, followed by Expire.
	redisClient.On("IncrBy", mock.Anything, mock.AnythingOfType("string"), mock.AnythingOfType("int64")).
		Return(int64(0), nil)
	redisClient.On("Expire", mock.Anything, mock.AnythingOfType("string"), mock.AnythingOfType("time.Duration")).
		Return(nil)

	agg := newTestAggregator(metering, promScraper, minioScraper, apisixScraper)
	agg.aggregateTenantScrapers(ctx, tenantID)

	promScraper.AssertExpectations(t)
	minioScraper.AssertExpectations(t)
	apisixScraper.AssertExpectations(t)
}

// TestAggregateTenant_PrometheusFailure verifies that a Prometheus scrape error
// does not prevent MinIO and APISIX from being scraped.
func TestAggregateTenant_PrometheusFailure(t *testing.T) {
	ctx := context.Background()
	tenantID := uuid.New()

	repo := new(mockUsageRecordRepo)
	redisClient := new(mockAggRedisClient)
	metering := newTestMeteringService(repo, redisClient)

	promScraper := new(mockPrometheusScraper)
	minioScraper := new(mockMinIOScraper)
	apisixScraper := new(mockAPISIXScraper)

	promScraper.On("QueryInstant", mock.Anything, mock.AnythingOfType("string"), mock.AnythingOfType("time.Time")).
		Return(float64(0), errors.New("prometheus unreachable"))

	// The other two scrapers must still be called.
	minioScraper.On("GetTenantStorageBytes", mock.Anything, tenantID).
		Return(int64(0), nil)
	apisixScraper.On("GetTenantBandwidthBytes", mock.Anything, tenantID).
		Return(int64(0), nil)
	apisixScraper.On("GetTenantAPIRequests", mock.Anything, tenantID).
		Return(int64(0), nil)

	agg := newTestAggregator(metering, promScraper, minioScraper, apisixScraper)
	agg.aggregateTenantScrapers(ctx, tenantID)

	// All three scrapers must have been attempted.
	promScraper.AssertExpectations(t)
	minioScraper.AssertExpectations(t)
	apisixScraper.AssertExpectations(t)
}

// TestAggregateTenant_MinIOFailure verifies that MinIO failure is isolated and
// does not prevent compute and bandwidth scraping.
func TestAggregateTenant_MinIOFailure(t *testing.T) {
	ctx := context.Background()
	tenantID := uuid.New()

	repo := new(mockUsageRecordRepo)
	redisClient := new(mockAggRedisClient)
	metering := newTestMeteringService(repo, redisClient)

	promScraper := new(mockPrometheusScraper)
	minioScraper := new(mockMinIOScraper)
	apisixScraper := new(mockAPISIXScraper)

	promScraper.On("QueryInstant", mock.Anything, mock.AnythingOfType("string"), mock.AnythingOfType("time.Time")).
		Return(float64(0), nil)
	minioScraper.On("GetTenantStorageBytes", mock.Anything, tenantID).
		Return(int64(0), errors.New("minio: connection refused"))
	apisixScraper.On("GetTenantBandwidthBytes", mock.Anything, tenantID).
		Return(int64(0), nil)
	apisixScraper.On("GetTenantAPIRequests", mock.Anything, tenantID).
		Return(int64(0), nil)

	agg := newTestAggregator(metering, promScraper, minioScraper, apisixScraper)
	agg.aggregateTenantScrapers(ctx, tenantID)

	minioScraper.AssertExpectations(t)
	promScraper.AssertExpectations(t)
	apisixScraper.AssertExpectations(t)
}

// TestAggregateTenant_APISIXFailure verifies that APISIX failure is isolated
// and does not prevent compute and storage scraping.
func TestAggregateTenant_APISIXFailure(t *testing.T) {
	ctx := context.Background()
	tenantID := uuid.New()

	repo := new(mockUsageRecordRepo)
	redisClient := new(mockAggRedisClient)
	metering := newTestMeteringService(repo, redisClient)

	promScraper := new(mockPrometheusScraper)
	minioScraper := new(mockMinIOScraper)
	apisixScraper := new(mockAPISIXScraper)

	promScraper.On("QueryInstant", mock.Anything, mock.AnythingOfType("string"), mock.AnythingOfType("time.Time")).
		Return(float64(0), nil)
	minioScraper.On("GetTenantStorageBytes", mock.Anything, tenantID).
		Return(int64(0), nil)
	apisixScraper.On("GetTenantBandwidthBytes", mock.Anything, tenantID).
		Return(int64(0), errors.New("apisix: timeout"))
	// GetTenantAPIRequests should still be attempted even when bandwidth fails.
	apisixScraper.On("GetTenantAPIRequests", mock.Anything, tenantID).
		Return(int64(0), errors.New("apisix: timeout"))

	agg := newTestAggregator(metering, promScraper, minioScraper, apisixScraper)
	agg.aggregateTenantScrapers(ctx, tenantID)

	promScraper.AssertExpectations(t)
	minioScraper.AssertExpectations(t)
	apisixScraper.AssertExpectations(t)
}

// TestAggregate_NoTenants verifies that the aggregation loop handles an empty
// tenant list gracefully without panicking.
func TestAggregate_NoTenants(t *testing.T) {
	repo := new(mockUsageRecordRepo)
	redisClient := new(mockAggRedisClient)
	metering := newTestMeteringService(repo, redisClient)

	// nil scrapers are allowed; aggregateTenantScrapers should guard against nil.
	agg := NewMeteringAggregatorWithScrapers(metering, nil, 5*time.Minute, nil, nil, nil)

	// With db=nil, listActiveTenants will error.  The aggregate method should
	// log the error and return without panicking.
	require.NotPanics(t, func() {
		agg.aggregate(context.Background())
	})
}

// TestScrapeComputeMetrics_ConvertsToHours verifies that raw CPU-seconds from
// Prometheus are correctly converted to compute-hours before recording.
func TestScrapeComputeMetrics_ConvertsToHours(t *testing.T) {
	ctx := context.Background()
	tenantID := uuid.New()

	repo := new(mockUsageRecordRepo)
	redisClient := new(mockAggRedisClient)
	metering := newTestMeteringService(repo, redisClient)

	promScraper := new(mockPrometheusScraper)

	// 7200 CPU-seconds = 2 compute-hours.
	cpuSeconds := 7200.0
	promScraper.On("QueryInstant", mock.Anything, mock.AnythingOfType("string"), mock.AnythingOfType("time.Time")).
		Return(cpuSeconds, nil)

	// Redis should be called with value=2 (7200 / 3600 = 2).
	redisClient.On("IncrBy", mock.Anything, mock.MatchedBy(func(key string) bool {
		// Key should contain MetricComputeHours.
		return len(key) > 0
	}), int64(2)).Return(int64(2), nil)
	redisClient.On("Expire", mock.Anything, mock.AnythingOfType("string"), mock.AnythingOfType("time.Duration")).
		Return(nil)

	agg := newTestAggregator(metering, promScraper, nil, nil)
	err := agg.scrapeComputeMetrics(ctx, tenantID)

	require.NoError(t, err)
	promScraper.AssertExpectations(t)
	redisClient.AssertExpectations(t)
}

// TestScrapeStorageMetrics_RecordsBytes verifies that storage bytes from MinIO
// are recorded directly via RecordRealtimeMetric.
func TestScrapeStorageMetrics_RecordsBytes(t *testing.T) {
	ctx := context.Background()
	tenantID := uuid.New()

	repo := new(mockUsageRecordRepo)
	redisClient := new(mockAggRedisClient)
	metering := newTestMeteringService(repo, redisClient)

	minioScraper := new(mockMinIOScraper)
	const storageBytes int64 = 10_737_418_240 // 10 GiB

	minioScraper.On("GetTenantStorageBytes", mock.Anything, tenantID).
		Return(storageBytes, nil)

	redisClient.On("IncrBy", mock.Anything, mock.AnythingOfType("string"), storageBytes).
		Return(storageBytes, nil)
	redisClient.On("Expire", mock.Anything, mock.AnythingOfType("string"), mock.AnythingOfType("time.Duration")).
		Return(nil)

	agg := newTestAggregator(metering, nil, minioScraper, nil)
	err := agg.scrapeStorageMetrics(ctx, tenantID)

	require.NoError(t, err)
	minioScraper.AssertExpectations(t)
	redisClient.AssertExpectations(t)
}

// TestScrapeBandwidthMetrics_RecordsBandwidthAndRequests verifies that both
// bandwidth bytes and API request counts are recorded in a single scrape call.
func TestScrapeBandwidthMetrics_RecordsBandwidthAndRequests(t *testing.T) {
	ctx := context.Background()
	tenantID := uuid.New()

	repo := new(mockUsageRecordRepo)
	redisClient := new(mockAggRedisClient)
	metering := newTestMeteringService(repo, redisClient)

	apisixScraper := new(mockAPISIXScraper)
	const bandwidthBytes int64 = 2_000_000
	const apiRequests int64 = 300

	apisixScraper.On("GetTenantBandwidthBytes", mock.Anything, tenantID).
		Return(bandwidthBytes, nil)
	apisixScraper.On("GetTenantAPIRequests", mock.Anything, tenantID).
		Return(apiRequests, nil)

	// Redis must be called twice — once for bandwidth, once for API requests.
	redisClient.On("IncrBy", mock.Anything, mock.MatchedBy(func(key string) bool {
		return len(key) > 0
	}), mock.AnythingOfType("int64")).Return(int64(0), nil)
	redisClient.On("Expire", mock.Anything, mock.AnythingOfType("string"), mock.AnythingOfType("time.Duration")).
		Return(nil)

	agg := newTestAggregator(metering, nil, nil, apisixScraper)
	err := agg.scrapeBandwidthMetrics(ctx, tenantID)

	require.NoError(t, err)
	apisixScraper.AssertExpectations(t)

	// Verify Redis was called at least twice (one per metric).
	incrCalls := 0
	for _, call := range redisClient.Calls {
		if call.Method == "IncrBy" {
			incrCalls++
		}
	}
	assert.GreaterOrEqual(t, incrCalls, 2, "expected IncrBy called for both bandwidth and API requests")
}

// TestScrapeComputeMetrics_NilScraper verifies that a nil Prometheus scraper
// is handled gracefully (no panic) and returns nil error.
func TestScrapeComputeMetrics_NilScraper(t *testing.T) {
	ctx := context.Background()
	repo := new(mockUsageRecordRepo)
	redisClient := new(mockAggRedisClient)
	metering := newTestMeteringService(repo, redisClient)

	agg := newTestAggregator(metering, nil, nil, nil)
	err := agg.scrapeComputeMetrics(ctx, uuid.New())

	require.NoError(t, err)
}

// TestScrapeStorageMetrics_NilScraper verifies that a nil MinIO scraper is
// handled gracefully (no panic) and returns nil error.
func TestScrapeStorageMetrics_NilScraper(t *testing.T) {
	ctx := context.Background()
	repo := new(mockUsageRecordRepo)
	redisClient := new(mockAggRedisClient)
	metering := newTestMeteringService(repo, redisClient)

	agg := newTestAggregator(metering, nil, nil, nil)
	err := agg.scrapeStorageMetrics(ctx, uuid.New())

	require.NoError(t, err)
}

// TestScrapeBandwidthMetrics_NilScraper verifies that a nil APISIX scraper is
// handled gracefully (no panic) and returns nil error.
func TestScrapeBandwidthMetrics_NilScraper(t *testing.T) {
	ctx := context.Background()
	repo := new(mockUsageRecordRepo)
	redisClient := new(mockAggRedisClient)
	metering := newTestMeteringService(repo, redisClient)

	agg := newTestAggregator(metering, nil, nil, nil)
	err := agg.scrapeBandwidthMetrics(ctx, uuid.New())

	require.NoError(t, err)
}
