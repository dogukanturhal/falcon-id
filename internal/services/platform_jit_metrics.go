// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Break-glass paging: per AGENT-RULES/brief instruction to "use the
// existing platform alert path" - no ntfy client or Alertmanager webhook
// client exists anywhere in this repo (confirmed by search), so the page
// is a Prometheus metric (the pattern pkg/spicedb/metrics.go already
// uses) that the cluster's existing Alertmanager rules fire on, plus a
// structured zap error-level log line (RunBreakGlass /
// RunBreakGlassSLASweep) for Loki-side correlation. Deliberately not a
// new notification-service/ntfy integration.
var (
	platformBreakGlassActivationsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "iam_platform_break_glass_activations_total",
			Help: "Total number of platform-plane break-glass self-grants activated. Alertmanager pages on any increase (rate() > 0).",
		},
		[]string{"role_key"},
	)

	platformBreakGlassViolationsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "iam_platform_break_glass_violations_total",
			Help: "Total number of break-glass grants that missed the 24h retroactive-approval SLA and were auto-revoked.",
		},
		[]string{"role_key"},
	)

	platformElevationSweepRevokedTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "iam_platform_elevation_auto_revoked_total",
			Help: "Total number of platform-plane JIT elevations auto-revoked by the expiry sweep.",
		},
		[]string{"role_key"},
	)
)

// RecordBreakGlassActivation increments the break-glass activation
// counter (the metric Alertmanager's paging rule watches).
func RecordBreakGlassActivation(roleKey string) {
	platformBreakGlassActivationsTotal.WithLabelValues(roleKey).Inc()
}

// RecordBreakGlassViolation increments the break-glass SLA-violation
// counter.
func RecordBreakGlassViolation(roleKey string) {
	platformBreakGlassViolationsTotal.WithLabelValues(roleKey).Inc()
}

// RecordPlatformElevationSweepRevoke increments the auto-revoke-sweep
// counter.
func RecordPlatformElevationSweepRevoke(roleKey string) {
	platformElevationSweepRevokedTotal.WithLabelValues(roleKey).Inc()
}
