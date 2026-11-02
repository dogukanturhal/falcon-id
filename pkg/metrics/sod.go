// SPDX-License-Identifier: AGPL-3.0-or-later

package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// ── SoD continuous re-evaluation (spec 23 section 5.2) ──────────────────────
//
// Alert on `falcon_id_sod_violations_open > 0` for warn-mode visibility and on
// `rate(falcon_id_sod_reevaluation_runs_total{result="error"}[1d]) > 0` for a
// job that stopped converging.
var (
	// SoDReevaluationRuns counts re-evaluation passes. trigger is "daily" or
	// "rule_change"; result is "ok", "error" or "skipped" (another replica
	// held the leader lock).
	SoDReevaluationRuns = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "falcon_id_sod_reevaluation_runs_total",
			Help: "SoD re-evaluation passes by trigger and result.",
		},
		[]string{"trigger", "result"},
	)

	// SoDViolationsDetected counts violations that newly opened (or reopened)
	// during a re-evaluation, by rule mode.
	SoDViolationsDetected = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "falcon_id_sod_violations_detected_total",
			Help: "SoD violations newly opened by the continuous re-evaluation job, by rule mode.",
		},
		[]string{"mode"},
	)

	// SoDViolationsResolved counts violations the job resolved because the
	// conflict no longer holds.
	SoDViolationsResolved = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "falcon_id_sod_violations_resolved_total",
			Help: "SoD violations resolved by the re-evaluation job because the conflict no longer holds.",
		},
	)

	// SoDViolationsOpen is the number of unresolved violations after the last
	// full (daily) pass.
	SoDViolationsOpen = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "falcon_id_sod_violations_open",
			Help: "Unresolved SoD violations after the last full re-evaluation pass.",
		},
	)
)
