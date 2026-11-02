// SPDX-License-Identifier: AGPL-3.0-or-later

package metrics

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// ── Provisioning Metrics ────────────────────────────────────────────────────
//
// These metrics track the lifecycle of product instance provisioning:
// step transitions, durations, failures, retries, and in-flight counts.

var (
	// ProvisioningStepsTotal counts provisioning step transitions.
	// Labels: step (creating|migrating|seeding|configuring_auth|registering_service),
	//         product (examplesuite|example-pms|...).
	ProvisioningStepsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "falcon_provisioning_steps_total",
			Help: "Total provisioning step transitions by step and product",
		},
		[]string{"step", "product"},
	)

	// ProvisioningDuration tracks how long each provisioning step takes.
	// Labels: step, product, result (success|failure).
	ProvisioningDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "falcon_provisioning_step_duration_seconds",
			Help:    "Duration of each provisioning step in seconds",
			Buckets: []float64{0.1, 0.5, 1, 2, 5, 10, 30, 60, 120, 300},
		},
		[]string{"step", "product", "result"},
	)

	// ProvisioningFailures counts provisioning failures by step and reason.
	ProvisioningFailures = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "falcon_provisioning_failures_total",
			Help: "Total provisioning failures by step, product, and reason",
		},
		[]string{"step", "product", "reason"},
	)

	// ProvisioningActive tracks the number of in-flight provisioning operations.
	ProvisioningActive = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "falcon_provisioning_active",
			Help: "Number of in-flight provisioning operations by step",
		},
		[]string{"step"},
	)

	// ProvisioningRetries counts automatic retries triggered by the orchestrator.
	ProvisioningRetries = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "falcon_provisioning_retries_total",
			Help: "Total provisioning retries by product",
		},
		[]string{"product"},
	)

	// ProvisioningDatabaseCount tracks how many databases are provisioned per instance.
	ProvisioningDatabaseCount = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "falcon_provisioning_database_count",
			Help:    "Number of databases provisioned per product instance",
			Buckets: []float64{1, 5, 10, 15, 20, 25, 30},
		},
		[]string{"product"},
	)

	// ProvisioningE2EDuration tracks total end-to-end provisioning time (pending → active).
	ProvisioningE2EDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "falcon_provisioning_e2e_duration_seconds",
			Help:    "End-to-end provisioning duration from pending to active",
			Buckets: []float64{1, 5, 10, 30, 60, 120, 300, 600, 1800},
		},
		[]string{"product", "isolation_mode"},
	)
)

// ── Helpers ─────────────────────────────────────────────────────────────────

// ProvisioningTimer tracks the duration of a provisioning step.
type ProvisioningTimer struct {
	step    string
	product string
	start   time.Time
}

// NewProvisioningTimer starts a new timer for a provisioning step.
// Call ObserveSuccess() or ObserveFailure() when the step completes.
func NewProvisioningTimer(step, product string) *ProvisioningTimer {
	ProvisioningStepsTotal.WithLabelValues(step, product).Inc()
	ProvisioningActive.WithLabelValues(step).Inc()
	return &ProvisioningTimer{
		step:    step,
		product: product,
		start:   time.Now(),
	}
}

// ObserveSuccess records a successful step completion.
func (t *ProvisioningTimer) ObserveSuccess() {
	duration := time.Since(t.start).Seconds()
	ProvisioningDuration.WithLabelValues(t.step, t.product, "success").Observe(duration)
	ProvisioningActive.WithLabelValues(t.step).Dec()
}

// ObserveFailure records a failed step with a reason.
func (t *ProvisioningTimer) ObserveFailure(reason string) {
	duration := time.Since(t.start).Seconds()
	ProvisioningDuration.WithLabelValues(t.step, t.product, "failure").Observe(duration)
	ProvisioningFailures.WithLabelValues(t.step, t.product, reason).Inc()
	ProvisioningActive.WithLabelValues(t.step).Dec()
}
