// SPDX-License-Identifier: AGPL-3.0-or-later

// CAEP transactional-outbox + drainer instrumentation.
//
// Background
// ==========
// Falcon-ID emits CAEP (Continuous Access Evaluation Profile, OpenID
// Foundation Shared Signals) Security Event Tokens to Talon, accounts
// BFFs, and external RP-side SSF receivers when downstream-relevant
// identity-state transitions happen (credential-change, session-revoked,
// risk-score-change, assurance-level-change).
//
// In wave-2 the emit was best-effort synchronous: the HTTP POST happened
// inline with the auth flow, and a transient receiver outage was lost.
// Phase 6 (ADR 0040 §Phase 6, also operational notes)
// promotes emit to a PG-backed transactional outbox + a separate drainer
// goroutine that delivers with at-least-once semantics and a 35.6-minute
// retry budget before a row enters status='dead'.
//
// Before flipping CAEP_OUTBOX_ENABLED=true in production we instrument
// every state transition so operators see:
//
//   - depth of the pending queue (lag indicator)
//   - per-event-type delivery outcome distribution (sent / retry / dead)
//   - per-iteration drainer wall-clock latency (health indicator)
//   - per-iteration drainer outcome (no_lock / no_rows / drained / error)
//
// The PrometheusRule shipped alongside this file (see
// deploy/helm/falcon-id/templates/prometheusrule.yaml) consumes ALL the
// metrics defined here. Any future drainer-side change MUST keep these
// names + label sets stable, or update the chart's rule file in the
// same commit.
//
// Cardinality budget
// ==================
// Two label sources contribute:
//
//   - event_type: CAEP event family + version. Enumerated by RFC 8417
//     IANA registry (≈ 12 known event types as of 2026). Falcon-ID
//     emits ≤ 6 of them. Hard ceiling: 12.
//   - outcome / reason_class: small enums (4 outcomes, 6 reason classes).
//     Hard ceiling: 6 + 4 = 10.
//
// Worst-case series per metric = 12 × 10 = 120; comfortably under the
// platform Prometheus per-job 1000-series soft limit (cf. how the
// surrounding `iam_discover_*` and `iam_mfa_enrollment_*` cardinality
// is bounded — same convention applies here).
//
// Naming convention
// =================
// All metrics live in the `iam_caep_outbox_*` namespace to mirror the
// existing `iam_oauth_bcl_outbox_*` pattern (chart prometheusrule.yaml
// already references that family). Helm template strings used in the
// PrometheusRule must match these names exactly.
package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	// CAEPOutboxPending tracks the number of rows in iam_caep_event_outbox
	// with status='pending' as observed by the drainer's PendingCount()
	// call at the start of every tick.
	//
	// Set site: internal/services/caep_outbox_drainer.go, drainOnce(),
	// immediately after the PendingCount call returns successfully.
	// Unset (left stale) on PendingCount error — the staleness is itself
	// a signal that gets caught by CAEPOutboxDrainerIterations{outcome=
	// "error"}.
	//
	// Alert pattern (recommended):
	//   iam_caep_outbox_pending > 50 FOR 10m
	// 50 is the BatchSize default — sustained backlog at or above batch
	// size means delivery is not keeping up.
	CAEPOutboxPending = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "iam_caep_outbox_pending",
			Help: "Rows in iam_caep_event_outbox with status='pending', sampled by the drainer at every tick",
		},
	)

	// CAEPOutboxDeliveryOutcomes counts the result of each per-row HTTP
	// delivery attempt by the drainer.
	//
	// Labels:
	//   - event_type: CAEP event family (e.g. "credential-change",
	//     "session-revoked", "verification", "device-compliance-change").
	//     Pulled from the outbox row's event_type column. Cardinality
	//     bounded by the IANA SET registry — ≤ 12 series per outcome.
	//   - outcome: one of "sent" | "retry" | "dead" | "build_error".
	//     "build_error" covers the cases where the SET could not be
	//     constructed (signing failure, malformed event_data) before
	//     the HTTP POST. "retry" and "dead" mirror the markRetryOrDead
	//     decision tree in drainer.go:337.
	//
	// Increment site: internal/services/caep_outbox_drainer.go,
	// deliverRow() (and its markDead/markRetry callees), exactly once
	// per row per drain tick.
	//
	// Alert pattern (paired with CAEPOutboxDeadTotal):
	//   sum(increase(iam_caep_outbox_delivery_outcomes_total{outcome="dead"}[10m])) by (event_type) > 0
	CAEPOutboxDeliveryOutcomes = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "iam_caep_outbox_delivery_outcomes_total",
			Help: "Per-row CAEP outbox delivery outcomes from the drainer, by event_type and outcome",
		},
		[]string{"event_type", "outcome"},
	)

	// CAEPOutboxDeadReasons counts the underlying reason class when a
	// row transitions to status='dead'. Separate from
	// CAEPOutboxDeliveryOutcomes because dead is the only outcome
	// operators must triage — the reason_class drives the runbook
	// branch.
	//
	// Labels:
	//   - event_type: same as above.
	//   - reason_class: bounded enum of:
	//       "http_4xx_nonretryable" — receiver rejected, RFC 8935 §3
	//       "retry_budget_exhausted" — survived 5 attempts (35.6m), still failing
	//       "build_failure"         — SET construction failure
	//       "transport_permanent"   — DNS / cert / unreachable beyond budget
	//
	// Increment site: internal/services/caep_outbox_drainer.go,
	// markDead(), exactly once per dead transition.
	//
	// Alert pattern:
	//   sum(increase(iam_caep_outbox_dead_total[10m])) by (event_type, reason_class) > 0
	// Any non-zero dead rate fires; operators inspect by reason_class.
	CAEPOutboxDeadReasons = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "iam_caep_outbox_dead_total",
			Help: "CAEP outbox rows that entered status='dead', by event_type and reason class",
		},
		[]string{"event_type", "reason_class"},
	)

	// CAEPOutboxDrainerIterations counts drainOnce ticks by outcome.
	// Distinguishes between healthy idle ticks (no_rows), contended
	// ticks (no_lock — another replica is draining), and broken ticks
	// (error — repo call failed before any rows could be touched).
	//
	// Labels:
	//   - outcome: one of "drained" | "no_rows" | "no_lock" | "error".
	//     "drained" = ≥ 1 row attempted.
	//     "no_rows" = healthy idle (pending=0 at tick).
	//     "no_lock" = another replica won the advisory lock.
	//     "error" = PendingCount, AcquireDrainerSession, TryLockAdvisory,
	//               BeginTx, SelectPendingForDelivery, or Commit failed.
	//
	// Increment site: internal/services/caep_outbox_drainer.go,
	// drainOnce(), exactly once per tick at exit.
	//
	// Alert pattern (drainer-health watchdog):
	//   rate(iam_caep_outbox_drainer_iterations_total[5m]) == 0 FOR 1m
	// Drainer must tick at least every TickInterval (5s default); zero
	// rate for 60s means the goroutine is wedged or the deployment is
	// down. Paired with CAEP_OUTBOX_ENABLED config — see runbook.
	CAEPOutboxDrainerIterations = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "iam_caep_outbox_drainer_iterations_total",
			Help: "Drainer tick outcomes (drained/no_rows/no_lock/error) — also serves as the drainer-alive signal",
		},
		[]string{"outcome"},
	)

	// CAEPOutboxDrainerTickDuration measures wall-clock per-tick latency
	// of drainOnce. Used to spot pathologically slow ticks (PG row-lock
	// contention, slow receivers stalling the in-tx HTTP POSTs).
	//
	// Buckets sized for the BCL/CAEP delivery class: most ticks are
	// sub-100ms (no rows or 1-5 rows, fast receivers). Tail above 5s
	// suggests receiver-side timeouts dominating; tail above 30s
	// suggests advisory-lock starvation or PG contention.
	//
	// Observe site: internal/services/caep_outbox_drainer.go,
	// drainOnce(), via time.Since(tickStart) at exit.
	CAEPOutboxDrainerTickDuration = promauto.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "iam_caep_outbox_drainer_tick_seconds",
			Help:    "Wall-clock duration of one CAEP outbox drainer tick (drainOnce)",
			Buckets: []float64{0.01, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30},
		},
	)
)
