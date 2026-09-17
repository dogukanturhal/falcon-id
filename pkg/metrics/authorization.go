// SPDX-License-Identifier: AGPL-3.0-or-later

package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	// AuthzCheckTotal is an exported identifier.
	AuthzCheckTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "example_authz_check_total",
			Help: "Total authorization checks by source and result",
		},
		[]string{"source", "result", "permission_type"},
	)

	// AuthzCheckDuration is an exported identifier.
	AuthzCheckDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "example_authz_check_duration_seconds",
			Help:    "Authorization check latency in seconds",
			Buckets: []float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0},
		},
		[]string{"source"},
	)

	// AuthzCacheHits is an exported identifier.
	AuthzCacheHits = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "example_authz_cache_hits_total",
			Help: "Authorization cache hits by layer",
		},
		[]string{"layer"}, // "local", "redis"
	)

	// AuthzCacheMisses is an exported identifier.
	AuthzCacheMisses = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "example_authz_cache_misses_total",
			Help: "Authorization cache misses by layer",
		},
		[]string{"layer"},
	)

	// AuthzDenials is an exported identifier.
	AuthzDenials = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "example_authz_denials_total",
			Help: "Authorization denials by permission and reason",
		},
		[]string{"permission", "reason"},
	)

	// AuthzInvalidations is an exported identifier.
	AuthzInvalidations = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "example_authz_invalidations_total",
			Help: "Permission cache invalidations",
		},
	)

	// AuthzBatchChecks is an exported identifier.
	AuthzBatchChecks = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "example_authz_batch_size",
			Help:    "Number of permissions checked in batch operations",
			Buckets: []float64{1, 5, 10, 20, 50, 100, 200},
		},
		[]string{"source"},
	)

	// AuthzOPAEvaluations is an exported identifier.
	AuthzOPAEvaluations = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "example_authz_opa_evaluations_total",
			Help: "OPA policy evaluations by result",
		},
		[]string{"result"}, // "allowed", "denied", "error"
	)

	// AuthzOPADuration is an exported identifier.
	AuthzOPADuration = promauto.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "example_authz_opa_evaluation_duration_seconds",
			Help:    "OPA policy evaluation latency",
			Buckets: []float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0},
		},
	)

	// AuthzSpiceDBChecks is an exported identifier.
	AuthzSpiceDBChecks = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "example_authz_spicedb_checks_total",
			Help: "SpiceDB permission checks by result",
		},
		[]string{"result"}, // "allowed", "denied", "error"
	)

	// AuthzSpiceDBDuration is an exported identifier.
	AuthzSpiceDBDuration = promauto.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "example_authz_spicedb_check_duration_seconds",
			Help:    "SpiceDB check latency",
			Buckets: []float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0},
		},
	)

	// AuthzRBACChecks is an exported identifier.
	AuthzRBACChecks = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "example_authz_rbac_checks_total",
			Help: "RBAC permission checks by result",
		},
		[]string{"result"}, // "allowed", "denied", "error"
	)

	// AuthzRBACDuration is an exported identifier.
	AuthzRBACDuration = promauto.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "example_authz_rbac_check_duration_seconds",
			Help:    "RBAC check latency",
			Buckets: []float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0},
		},
	)
)

// RecordAuthzCheck records an authorization check with timing
func RecordAuthzCheck(source, result, permissionType string, duration float64) {
	AuthzCheckTotal.WithLabelValues(source, result, permissionType).Inc()
	AuthzCheckDuration.WithLabelValues(source).Observe(duration)
}

// RecordAuthzCacheHit records a cache hit
func RecordAuthzCacheHit(layer string) {
	AuthzCacheHits.WithLabelValues(layer).Inc()
}

// RecordAuthzCacheMiss records a cache miss
func RecordAuthzCacheMiss(layer string) {
	AuthzCacheMisses.WithLabelValues(layer).Inc()
}

// RecordAuthzDenial records an authorization denial
func RecordAuthzDenial(permission, reason string) {
	AuthzDenials.WithLabelValues(permission, reason).Inc()
}

// RecordAuthzInvalidation records a permission cache invalidation
func RecordAuthzInvalidation() {
	AuthzInvalidations.Inc()
}

// RecordAuthzBatchCheck records a batch check operation
func RecordAuthzBatchCheck(source string, size int) {
	AuthzBatchChecks.WithLabelValues(source).Observe(float64(size))
}

// RecordOPAEvaluation records an OPA policy evaluation
func RecordOPAEvaluation(result string, duration float64) {
	AuthzOPAEvaluations.WithLabelValues(result).Inc()
	AuthzOPADuration.Observe(duration)
}

// RecordSpiceDBCheck records a SpiceDB permission check
func RecordSpiceDBCheck(result string, duration float64) {
	AuthzSpiceDBChecks.WithLabelValues(result).Inc()
	AuthzSpiceDBDuration.Observe(duration)
}

// RecordRBACCheck records an RBAC permission check
func RecordRBACCheck(result string, duration float64) {
	AuthzRBACChecks.WithLabelValues(result).Inc()
	AuthzRBACDuration.Observe(duration)
}
