// SPDX-License-Identifier: AGPL-3.0-or-later

// Package entitlementsync consumes example.tenant.modules.sync
// (the product roadmap §4.1) — the full per-tenant module-entitlement
// snapshot published by tenant-management — and upserts
// iam_tenant_module_entitlements / iam_tenant_entitlement_flags via
// services.TenantEntitlementService.PutSnapshot /
// .PutFlagsSnapshot.
//
// Modeled directly on internal/tenantprojection (the only other
// currently-wired-into-production Kafka consumer in this service): one
// *kafka.Reader per topic (here, exactly one topic), retry-then-DLQ with
// diagnostic headers, SASL/SCRAM dialer/transport helpers. Deliberately a
// SEPARATE package/consumer-group/DLQ-writer from tenantprojection: the two
// consume different topics for different tables and must never share
// Kafka offsets (see kafkauser-falcon-id-entitlements-sync.yaml's
// rationale comment in <gitops-bootstrap-repo>).
//
// Unlike internal/services/kafka_provisioning_worker.go and
// internal/services/hcm_employee_consumer.go (both orphaned — never wired
// into any cmd/ entrypoint), this consumer MUST be started from
// cmd/background.go alongside tenantprojection.
package entitlementsync

import (
	"context"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"go.uber.org/zap"
)

// Metrics is the Prometheus instrumentation surface for the entitlement
// sync consumer, namespaced under falcon_id_entitlement_sync_ so it is
// trivially distinguished from falcon_id_tenant_projection_*.
type Metrics struct {
	// LagSeconds is the age of the most recently processed snapshot.
	LagSeconds prometheus.Gauge

	// EventsTotal counts events by outcome:
	//   outcome=ok      — snapshot applied (or idempotently skipped by
	//                     the event_version guard, which is indistinguishable
	//                     from "applied" at the metrics level by design —
	//                     see outcome=skipped below for the version guard
	//                     specifically).
	//   outcome=skipped — event_version guard rejected a stale/duplicate
	//                     redelivery.
	//   outcome=dlq     — terminal failure after maxRetries; sent to DLQ.
	//   outcome=failed  — terminal failure AND DLQ publish also failed.
	EventsTotal *prometheus.CounterVec
}

// NewMetrics registers the entitlement sync metrics on reg. Already
// registered collisions are swallowed so shared-registerer tests don't
// panic. If reg is nil, an isolated registry is used.
func NewMetrics(reg prometheus.Registerer, log *zap.SugaredLogger) *Metrics {
	if reg == nil {
		reg = prometheus.NewRegistry()
	}
	m := &Metrics{
		LagSeconds: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: "falcon_id",
			Subsystem: "entitlement_sync",
			Name:      "lag_seconds",
			Help:      "Age of the most recently processed example.tenant.modules.sync snapshot (now() - event timestamp).",
		}),
		EventsTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: "falcon_id",
				Subsystem: "entitlement_sync",
				Name:      "events_total",
				Help:      "example.tenant.modules.sync events by outcome (ok|skipped|dlq|failed).",
			},
			[]string{"outcome"},
		),
	}

	for _, c := range []prometheus.Collector{m.LagSeconds, m.EventsTotal} {
		if err := reg.Register(c); err != nil {
			if _, ok := err.(prometheus.AlreadyRegisteredError); !ok && log != nil {
				log.Warnw("entitlementsync: metric registration failed", "error", err)
			}
		}
	}
	return m
}

// IncOK records a successfully applied snapshot.
func (m *Metrics) IncOK() {
	if m == nil {
		return
	}
	m.EventsTotal.WithLabelValues("ok").Inc()
}

// IncSkipped records a stale/duplicate snapshot rejected by the
// event_version guard.
func (m *Metrics) IncSkipped() {
	if m == nil {
		return
	}
	m.EventsTotal.WithLabelValues("skipped").Inc()
}

// IncDLQ records a terminal failure forwarded to the DLQ.
func (m *Metrics) IncDLQ() {
	if m == nil {
		return
	}
	m.EventsTotal.WithLabelValues("dlq").Inc()
}

// IncFailed records a terminal failure where the DLQ publish also failed.
func (m *Metrics) IncFailed() {
	if m == nil {
		return
	}
	m.EventsTotal.WithLabelValues("failed").Inc()
}

// ObserveLag sets the lag gauge from the snapshot's event timestamp.
func (m *Metrics) ObserveLag(eventAt time.Time) {
	if m == nil {
		return
	}
	lag := time.Since(eventAt).Seconds()
	if lag < 0 {
		lag = 0
	}
	m.LagSeconds.Set(lag)
}

// RunLagRefresh is kept for structural parity with tenantprojection's
// Metrics.RunLagRefresh; lag is updated synchronously via ObserveLag
// inside the consume loop, so this is intentionally a no-op.
func (m *Metrics) RunLagRefresh(_ context.Context, _ *zap.SugaredLogger) {}
