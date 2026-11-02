// SPDX-License-Identifier: AGPL-3.0-or-later

package signupgap

import "github.com/prometheus/client_golang/prometheus"

// GapMetrics carries the Prometheus instruments GapReconciler reports
// against.
//
// Suggested alerts (to be added alongside this change in
// the GitOps repository):
//   - stalled_signups_current sustained high (operator picks the
//     threshold once real traffic volume is known) with no corresponding
//     drop: signups are verifying and then getting stuck, at a rate
//     nothing is currently acting on (see this package's doc comment for
//     why no automated recovery action exists yet).
//   - cycles_total{outcome="error"} rate sustained > 0: detection itself
//     is broken — the gauge above cannot be trusted while this fires.
type GapMetrics struct {
	StalledSignupsCurrent prometheus.Gauge
	CyclesTotal           *prometheus.CounterVec
	CycleDurationSeconds  prometheus.Histogram
}

// NewGapMetrics constructs the signup-stall-gap metric set and registers
// it under the supplied Prometheus registry.
func NewGapMetrics(reg prometheus.Registerer) *GapMetrics {
	m := &GapMetrics{
		StalledSignupsCurrent: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "falcon_id_signup_gap_stalled_signups_current",
			Help: "Current count of verified, not-yet-completed, not-yet-expired signup requests older than the stall threshold.",
		}),
		CyclesTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "falcon_id_signup_gap_detect_cycles_total",
			Help: "Number of signup stall detection cycles, by outcome (ok|error).",
		}, []string{"outcome"}),
		CycleDurationSeconds: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "falcon_id_signup_gap_detect_cycle_duration_seconds",
			Help:    "Duration of a single signup stall detection cycle.",
			Buckets: []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5},
		}),
	}
	reg.MustRegister(m.StalledSignupsCurrent)
	reg.MustRegister(m.CyclesTotal)
	reg.MustRegister(m.CycleDurationSeconds)
	return m
}
