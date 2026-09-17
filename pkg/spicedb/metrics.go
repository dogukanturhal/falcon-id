// SPDX-License-Identifier: AGPL-3.0-or-later

package spicedb

import (
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	// Permission check metrics
	permissionCheckTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "iam_spicedb_permission_check_total",
			Help: "Total number of SpiceDB permission checks",
		},
		[]string{"resource_type", "permission", "result"},
	)

	permissionCheckDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "iam_spicedb_permission_check_duration_seconds",
			Help:    "Duration of SpiceDB permission checks",
			Buckets: []float64{.001, .005, .01, .025, .05, .1, .25, .5, 1},
		},
		[]string{"resource_type", "cache_hit"},
	)

	// Consistency mode tracking
	consistencyModeUsage = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "iam_spicedb_consistency_mode_total",
			Help: "Total permission checks by consistency mode",
		},
		[]string{"mode"}, // "minimize_latency", "at_least_as_fresh", "fully_consistent"
	)

	// Relationship write metrics
	relationshipWriteTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "iam_spicedb_relationship_write_total",
			Help: "Total number of SpiceDB relationship writes",
		},
		[]string{"resource_type", "relation", "operation"},
	)

	relationshipWriteDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "iam_spicedb_relationship_write_duration_seconds",
			Help:    "Duration of SpiceDB relationship writes",
			Buckets: []float64{.01, .025, .05, .1, .25, .5, 1, 2.5},
		},
		[]string{"resource_type", "operation"},
	)

	// Bulk operation metrics
	bulkWriteSize = promauto.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "iam_spicedb_bulk_write_size",
			Help:    "Number of relationships in bulk write operations",
			Buckets: []float64{1, 5, 10, 25, 50, 100, 250, 500, 1000},
		},
	)

	bulkWriteDuration = promauto.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "iam_spicedb_bulk_write_duration_seconds",
			Help:    "Duration of bulk relationship writes",
			Buckets: []float64{.01, .05, .1, .25, .5, 1, 2.5, 5, 10},
		},
	)

	// Cache metrics
	cacheHitTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "iam_spicedb_cache_hit_total",
			Help: "Total SpiceDB cache hits",
		},
		[]string{"cache_type"},
	)

	cacheMissTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "iam_spicedb_cache_miss_total",
			Help: "Total SpiceDB cache misses",
		},
		[]string{"cache_type"},
	)

	cacheInvalidationTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "iam_spicedb_cache_invalidation_total",
			Help: "Total cache invalidations",
		},
		[]string{"invalidation_type"}, // "user", "role", "tenant"
	)

	cacheSize = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "iam_spicedb_cache_size_bytes",
			Help: "Estimated size of SpiceDB cache in bytes",
		},
		[]string{"cache_type"},
	)

	// Error metrics
	errorTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "iam_spicedb_error_total",
			Help: "Total SpiceDB errors",
		},
		[]string{"operation", "error_type"},
	)

	// Connection metrics
	connectionStatus = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "iam_spicedb_connection_status",
			Help: "SpiceDB connection status (1=connected, 0=disconnected)",
		},
	)

	connectionAttempts = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "iam_spicedb_connection_attempts_total",
			Help: "Total SpiceDB connection attempts",
		},
	)

	healthCheckDuration = promauto.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "iam_spicedb_health_check_duration_seconds",
			Help:    "Duration of SpiceDB health checks",
			Buckets: []float64{.001, .005, .01, .025, .05, .1, .25, .5, 1},
		},
	)

	// Rate limiting metrics
	rateLimitWaitDuration = promauto.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "iam_spicedb_rate_limit_wait_duration_seconds",
			Help:    "Time spent waiting for rate limit semaphore",
			Buckets: []float64{.001, .005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5},
		},
	)

	rateLimitQueueSize = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "iam_spicedb_rate_limit_queue_size",
			Help: "Number of requests waiting for rate limit semaphore",
		},
	)

	// Lookup operation metrics
	lookupResourcesTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "iam_spicedb_lookup_resources_total",
			Help: "Total LookupResources operations",
		},
		[]string{"resource_type", "permission"},
	)

	lookupResourcesDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "iam_spicedb_lookup_resources_duration_seconds",
			Help:    "Duration of LookupResources operations",
			Buckets: []float64{.01, .05, .1, .25, .5, 1, 2.5, 5, 10},
		},
		[]string{"resource_type"},
	)

	lookupResourcesResultSize = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "iam_spicedb_lookup_resources_result_size",
			Help:    "Number of resources returned by LookupResources",
			Buckets: []float64{0, 1, 5, 10, 25, 50, 100, 250, 500, 1000},
		},
		[]string{"resource_type"},
	)

	lookupSubjectsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "iam_spicedb_lookup_subjects_total",
			Help: "Total LookupSubjects operations",
		},
		[]string{"resource_type", "permission"},
	)

	lookupSubjectsDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "iam_spicedb_lookup_subjects_duration_seconds",
			Help:    "Duration of LookupSubjects operations",
			Buckets: []float64{.01, .05, .1, .25, .5, 1, 2.5, 5, 10},
		},
		[]string{"resource_type"},
	)

	lookupSubjectsResultSize = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "iam_spicedb_lookup_subjects_result_size",
			Help:    "Number of subjects returned by LookupSubjects",
			Buckets: []float64{0, 1, 5, 10, 25, 50, 100, 250, 500},
		},
		[]string{"resource_type"},
	)

	// ZedToken metrics
	zedTokenStoreTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "iam_spicedb_zedtoken_store_total",
			Help: "Total ZedToken store operations",
		},
		[]string{"entity_type", "result"}, // "user", "role", "user_role"
	)

	zedTokenRetrieveTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "iam_spicedb_zedtoken_retrieve_total",
			Help: "Total ZedToken retrieve operations",
		},
		[]string{"entity_type", "result"}, // "hit", "miss", "error"
	)

	// Tenant isolation metrics
	tenantValidationTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "iam_spicedb_tenant_validation_total",
			Help: "Total tenant context validation checks",
		},
		[]string{"result"}, // "success", "failure"
	)

	tenantValidationFailures = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "iam_spicedb_tenant_validation_failures_total",
			Help: "Total tenant validation failures (security concern)",
		},
		[]string{"failure_type"},
	)

	// Batch check metrics
	batchCheckSize = promauto.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "iam_spicedb_batch_check_size",
			Help:    "Number of permissions checked in batch operations",
			Buckets: []float64{1, 5, 10, 20, 50, 100},
		},
	)

	batchCheckDuration = promauto.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "iam_spicedb_batch_check_duration_seconds",
			Help:    "Duration of batch permission check operations",
			Buckets: []float64{.01, .05, .1, .25, .5, 1, 2.5, 5},
		},
	)

	// Resource metrics by type
	resourceOperationsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "iam_spicedb_resource_operations_total",
			Help: "Total operations by resource type",
		},
		[]string{"resource_type", "operation"}, // operation: "check", "write", "delete", "lookup"
	)

	// Security audit metrics
	authorizationDenialTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "iam_spicedb_authorization_denial_total",
			Help: "Total authorization denials (security audit)",
		},
		[]string{"resource_type", "permission"},
	)

	suspiciousActivityTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "iam_spicedb_suspicious_activity_total",
			Help: "Total suspicious authorization activity detected",
		},
		[]string{"activity_type"}, // "excessive_denials", "unusual_permission", "bulk_check"
	)
)

// RecordPermissionCheck records a permission check with all relevant metadata
func RecordPermissionCheck(_ uuid.UUID, resourceType, permission, result string, duration time.Duration, cacheHit bool) {
	permissionCheckTotal.WithLabelValues(
		resourceType,
		permission,
		result,
	).Inc()

	cacheHitStr := "false"
	if cacheHit {
		cacheHitStr = "true"
		cacheHitTotal.WithLabelValues("permission").Inc()
	} else {
		cacheMissTotal.WithLabelValues("permission").Inc()
	}

	permissionCheckDuration.WithLabelValues(resourceType, cacheHitStr).Observe(duration.Seconds())
	resourceOperationsTotal.WithLabelValues(resourceType, "check").Inc()

	// Track authorization denials for security audit
	if result == spicedbResultDenied {
		authorizationDenialTotal.WithLabelValues(
			resourceType,
			permission,
		).Inc()
	}
}

// RecordConsistencyMode records the usage of a specific consistency mode
func RecordConsistencyMode(mode string) {
	consistencyModeUsage.WithLabelValues(mode).Inc()
}

// RecordRelationshipWrite records a relationship write operation
func RecordRelationshipWrite(_ uuid.UUID, resourceType, relation, operation string, duration time.Duration) {
	relationshipWriteTotal.WithLabelValues(
		resourceType,
		relation,
		operation,
	).Inc()

	relationshipWriteDuration.WithLabelValues(resourceType, operation).Observe(duration.Seconds())
	resourceOperationsTotal.WithLabelValues(resourceType, "write").Inc()
}

// RecordBulkWrite records a bulk relationship write operation
func RecordBulkWrite(_ uuid.UUID, relationshipCount int, duration time.Duration) {
	bulkWriteSize.Observe(float64(relationshipCount))
	bulkWriteDuration.Observe(duration.Seconds())
}

// RecordCacheInvalidation records a cache invalidation
func RecordCacheInvalidation(invalidationType string, _ uuid.UUID) {
	cacheInvalidationTotal.WithLabelValues(invalidationType).Inc()
}

// RecordError records an error with operation and type
func RecordError(operation, errorType string) {
	errorTotal.WithLabelValues(operation, errorType).Inc()
}

// SetConnectionStatus sets the connection status (1=connected, 0=disconnected)
func SetConnectionStatus(connected bool) {
	if connected {
		connectionStatus.Set(1)
	} else {
		connectionStatus.Set(0)
	}
}

// RecordConnectionAttempt increments the connection attempt counter
func RecordConnectionAttempt() {
	connectionAttempts.Inc()
}

// RecordHealthCheck records a health check duration
func RecordHealthCheck(duration time.Duration) {
	healthCheckDuration.Observe(duration.Seconds())
}

// RecordRateLimitWait records time spent waiting for rate limit
func RecordRateLimitWait(duration time.Duration) {
	rateLimitWaitDuration.Observe(duration.Seconds())
}

// SetRateLimitQueueSize sets the current rate limit queue size
func SetRateLimitQueueSize(size int) {
	rateLimitQueueSize.Set(float64(size))
}

// RecordLookupResources records a LookupResources operation
func RecordLookupResources(resourceType, permission string, resultSize int, duration time.Duration) {
	lookupResourcesTotal.WithLabelValues(resourceType, permission).Inc()
	lookupResourcesDuration.WithLabelValues(resourceType).Observe(duration.Seconds())
	lookupResourcesResultSize.WithLabelValues(resourceType).Observe(float64(resultSize))
	resourceOperationsTotal.WithLabelValues(resourceType, "lookup").Inc()
}

// RecordLookupSubjects records a LookupSubjects operation
func RecordLookupSubjects(resourceType, permission string, resultSize int, duration time.Duration) {
	lookupSubjectsTotal.WithLabelValues(resourceType, permission).Inc()
	lookupSubjectsDuration.WithLabelValues(resourceType).Observe(duration.Seconds())
	lookupSubjectsResultSize.WithLabelValues(resourceType).Observe(float64(resultSize))
}

// RecordZedTokenStore records a ZedToken store operation
func RecordZedTokenStore(entityType, result string) {
	zedTokenStoreTotal.WithLabelValues(entityType, result).Inc()
}

// RecordZedTokenRetrieve records a ZedToken retrieve operation
func RecordZedTokenRetrieve(entityType, result string) {
	zedTokenRetrieveTotal.WithLabelValues(entityType, result).Inc()
}

// RecordTenantValidation records a tenant context validation
func RecordTenantValidation(success bool) {
	result := "success"
	if !success {
		result = "failure"
	}
	tenantValidationTotal.WithLabelValues(result).Inc()
}

// RecordTenantValidationFailure records a tenant validation failure (security concern)
func RecordTenantValidationFailure(_ uuid.UUID, failureType string) {
	tenantValidationFailures.WithLabelValues(failureType).Inc()
}

// RecordBatchCheck records a batch permission check
func RecordBatchCheck(_ uuid.UUID, checkCount int, duration time.Duration) {
	batchCheckSize.Observe(float64(checkCount))
	batchCheckDuration.Observe(duration.Seconds())
}

// RecordSuspiciousActivity records suspicious authorization activity
func RecordSuspiciousActivity(_ uuid.UUID, activityType string) {
	suspiciousActivityTotal.WithLabelValues(activityType).Inc()
}

// SetCacheSize sets the estimated cache size in bytes
func SetCacheSize(cacheType string, sizeBytes int64) {
	cacheSize.WithLabelValues(cacheType).Set(float64(sizeBytes))
}

// MetricsSnapshot returns a snapshot of current metrics for internal monitoring
type MetricsSnapshot struct {
	CheckCount      int64
	CacheHits       int64
	CacheMisses     int64
	ErrorCount      int64
	ConnectionOK    bool
	LastHealthCheck time.Time
}

// Note: GetMetricsSnapshot is defined in client.go to avoid circular dependency
// It provides a way to get a snapshot of metrics for health monitoring

// Helper to calculate cache hit ratio
func calculateCacheHitRatio(hits, misses int64) float64 {
	total := hits + misses
	if total == 0 {
		return 0
	}
	return float64(hits) / float64(total)
}

// FormatMetricsForLog formats metrics for structured logging
func FormatMetricsForLog(snapshot MetricsSnapshot) map[string]interface{} {
	hitRatio := calculateCacheHitRatio(snapshot.CacheHits, snapshot.CacheMisses)

	return map[string]interface{}{
		"check_count":       snapshot.CheckCount,
		"cache_hits":        snapshot.CacheHits,
		"cache_misses":      snapshot.CacheMisses,
		"cache_hit_ratio":   fmt.Sprintf("%.2f%%", hitRatio*100),
		"error_count":       snapshot.ErrorCount,
		"connection_ok":     snapshot.ConnectionOK,
		"last_health_check": snapshot.LastHealthCheck,
	}
}
