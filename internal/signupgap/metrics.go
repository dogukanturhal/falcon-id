// SPDX-License-Identifier: AGPL-3.0-or-later

package signupgap

import "github.com/prometheus/client_golang/prometheus"

// Metrics carries the Prometheus instruments Reconciler reports against.
// Pass the same *prometheus.Registry the service uses for /metrics.
//
// Naming follows platform convention: `<service>_signup_gap_*`, mirroring
// tenant-management's `tenant_management_trial_expiry_*`.
//
// Suggested alerts (to be added alongside this change in
// the GitOps repository):
//   - cycles_total{outcome="error"} rate sustained > 0: the reaper is
//     failing every cycle — expired signup requests are accumulating
//     again with nothing cleaning them up.
type Metrics struct {
	SignupsReapedTotal   prometheus.Counter
	CyclesTotal          *prometheus.CounterVec
	CycleDurationSeconds prometheus.Histogram
}

// NewMetrics constructs the signup-gap reap metric set and registers it
// under the supplied Prometheus registry.
func NewMetrics(reg prometheus.Registerer) *Metrics {
	m := &Metrics{
		SignupsReapedTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "falcon_id_signup_gap_signups_reaped_total",
			Help: "Number of expired, never-completed signup requests deleted by the signup gap reconciler.",
		}),
		CyclesTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "falcon_id_signup_gap_cycles_total",
			Help: "Number of signup gap reap cycles, by outcome (reaped|idle|error).",
		}, []string{"outcome"}),
		CycleDurationSeconds: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "falcon_id_signup_gap_cycle_duration_seconds",
			Help:    "Duration of a single signup gap reap cycle.",
			Buckets: []float64{0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10},
		}),
	}
	reg.MustRegister(m.SignupsReapedTotal)
	reg.MustRegister(m.CyclesTotal)
	reg.MustRegister(m.CycleDurationSeconds)
	return m
}
