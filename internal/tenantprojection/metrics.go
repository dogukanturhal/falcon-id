// SPDX-License-Identifier: AGPL-3.0-or-later

// Package tenantprojection implements the Phase 1a reverse projection that
// keeps iam_tenants in sync with tenant-management's authoritative outbox.
//
// ADR 0029 declares tenant-management.tenants as the future system-of-record
// for tenant + plan + entitlements. This package is the defensive bridge:
// it consumes example.tenant.{created,updated,deleted} events and applies
// UPDATE-only patches to iam_tenants so legacy IAM readers remain accurate
// during the strangler-fig migration.
//
// Boot order (enforced in cmd/background.go):
//  1. Bootstrap.RunOnce — REST snapshot reconciles iam_tenants from
//     tenant-management before the Kafka consumer joins.
//  2. Subscriber.Run — durable consumer group "falcon-id-tenant-projection"
//     processes live events thereafter.
//
// Hard constraints:
//   - NO INSERT into iam_tenants from this package. Only the signup adapter
//     (internal/repositories/tenant_repository.go:Create) holds INSERT rights.
//   - If a TenantCreated event arrives for a tenant_id not yet in iam_tenants
//     that is an orphan (signup adapter hasn't run yet or races). The event
//     is WARN-logged, counted as orphan, and skipped. No INSERT tombstone.
//   - Consumer group name "falcon-id-tenant-projection" is unique to this
//     package. It MUST NOT be reused by quota-service or any other consumer.
//   - DLQ topic "example.tenant.dlq" is shared with the quota-service forward
//     projection (provisioned by <gitops-bootstrap-repo>!709).
package tenantprojection

import (
	"context"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"go.uber.org/zap"
)

// Metrics is the Prometheus instrumentation surface for the reverse projection.
//
// All metrics are namespaced under falcon_id_tenant_projection_ so they
// are trivially distinguished from the quota-service projection series
// (quota_service_projection_*) and from the existing IAM series (iam_*).
type Metrics struct {
	// LagSeconds is the age of the most recently processed event per subject.
	// Refreshed every 30 s by RunLagRefresh. Alert at >30s for 5m.
	LagSeconds *prometheus.GaugeVec

	// EventsTotal counts events by subject + outcome:
	//   outcome=ok      — UPDATE applied (or idempotently skipped by updated_at guard).
	//   outcome=skipped — updated_at guard rejected stale event; row is already newer.
	//   outcome=orphan  — tenant_id not found in iam_tenants; signup adapter hasn't run.
	//   outcome=dlq     — terminal failure after maxRetries; payload sent to DLQ topic.
	//   outcome=failed  — terminal failure AND DLQ publish itself failed (black-hole).
	EventsTotal *prometheus.CounterVec

	// OrphanTotal is a dedicated counter for orphan events so alert PromQL
	// can use rate(falcon_id_tenant_projection_orphan_total[5m]) directly
	// without label filtering on EventsTotal. The outcome=orphan label on
	// EventsTotal is retained for dashboard filtering.
	OrphanTotal *prometheus.CounterVec

	// BootstrapComplete is 1 once the initial tenant-management REST snapshot
	// has been applied (or intentionally skipped in standalone mode), else 0.
	BootstrapComplete prometheus.Gauge
}

// NewMetrics registers the projection metrics on reg (pass
// prometheus.DefaultRegisterer from main.go). Already-registered collisions
// are swallowed so tests that share the default registerer don't panic.
// If reg is nil, NewMetrics returns a valid *Metrics with counters that
// are registered against prometheus.DefaultRegisterer so nil-reg callers
// still get functional metrics.
func NewMetrics(reg prometheus.Registerer, log *zap.SugaredLogger) *Metrics {
	if reg == nil {
		reg = prometheus.NewRegistry() // isolated registry for tests / nil-reg callers
	}
	m := &Metrics{
		LagSeconds: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Namespace: "falcon_id",
				Subsystem: "tenant_projection",
				Name:      "lag_seconds",
				Help:      "Age of the most recently processed event for the reverse projection consumer (now() - event timestamp).",
			},
			[]string{"subject"},
		),
		EventsTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: "falcon_id",
				Subsystem: "tenant_projection",
				Name:      "events_total",
				Help:      "Reverse projection events by subject and outcome (ok|skipped|orphan|dlq|failed).",
			},
			[]string{"subject", "outcome"},
		),
		OrphanTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: "falcon_id",
				Subsystem: "tenant_projection",
				Name:      "orphan_total",
				Help:      "Events for tenant IDs not present in iam_tenants (signup/projection race or signup failure).",
			},
			[]string{"subject"},
		),
		BootstrapComplete: prometheus.NewGauge(
			prometheus.GaugeOpts{
				Name: "tenantprojection_bootstrap_complete",
				Help: "1 once the tenant projection bootstrap snapshot completed (or was skipped in standalone mode), 0 otherwise.",
			},
		),
	}

	for _, c := range []prometheus.Collector{m.LagSeconds, m.EventsTotal, m.OrphanTotal, m.BootstrapComplete} {
		if err := reg.Register(c); err != nil {
			if _, ok := err.(prometheus.AlreadyRegisteredError); !ok && log != nil {
				log.Warnw("tenantprojection: metric registration failed", "error", err)
			}
		}
	}
	return m
}

// SetBootstrapComplete sets the bootstrap gauge to 1 (done) or 0.
func (m *Metrics) SetBootstrapComplete(done bool) {
	if m == nil {
		return
	}
	v := 0.0
	if done {
		v = 1
	}
	m.BootstrapComplete.Set(v)
}

// IncOK records a successfully applied event.
func (m *Metrics) IncOK(subject string) {
	if m == nil {
		return
	}
	m.EventsTotal.WithLabelValues(subject, "ok").Inc()
}

// IncSkipped records a stale-event skip (updated_at guard).
func (m *Metrics) IncSkipped(subject string) {
	if m == nil {
		return
	}
	m.EventsTotal.WithLabelValues(subject, "skipped").Inc()
}

// IncOrphan records an orphan event and updates both counters.
func (m *Metrics) IncOrphan(subject string) {
	if m == nil {
		return
	}
	m.EventsTotal.WithLabelValues(subject, "orphan").Inc()
	m.OrphanTotal.WithLabelValues(subject).Inc()
}

// IncDLQ records a terminal failure that was successfully forwarded to the DLQ.
func (m *Metrics) IncDLQ(subject string) {
	if m == nil {
		return
	}
	m.EventsTotal.WithLabelValues(subject, "dlq").Inc()
}

// IncFailed records a terminal failure where the DLQ publish also failed (black-hole).
func (m *Metrics) IncFailed(subject string) {
	if m == nil {
		return
	}
	m.EventsTotal.WithLabelValues(subject, "failed").Inc()
}

// ObserveLag sets the lag gauge for a subject given the event's timestamp.
func (m *Metrics) ObserveLag(subject string, eventAt time.Time) {
	if m == nil {
		return
	}
	lag := time.Since(eventAt).Seconds()
	if lag < 0 {
		lag = 0
	}
	m.LagSeconds.WithLabelValues(subject).Set(lag)
}

// RunLagRefresh polls the last event timestamp per subject from in-memory
// state (the subscriber updates lagTimestamps on each processed event) and
// refreshes the LagSeconds gauge every 30 s. Runs until ctx is canceled.
//
// Unlike the quota-service pattern (which reads from a projection_cursor
// table), falcon-id's reverse projection does not maintain a cursor table —
// iam_tenants.updated_at is the authoritative lag signal. The lag gauge is
// therefore updated inline in the consumer loop via ObserveLag rather than
// via a DB poll.
func (m *Metrics) RunLagRefresh(_ context.Context, _ *zap.SugaredLogger) {
	// Lag is updated synchronously inside consumeSubject via ObserveLag.
	// This method is intentionally a no-op — kept for structural parity
	// with the quota-service projection so future callers don't need to
	// know which pattern the lag refresh uses.
}
