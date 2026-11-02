// SPDX-License-Identifier: AGPL-3.0-or-later

package tenantstatus

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"go.uber.org/zap"
)

// Metrics instruments the example.tenant.status consumer
// (falcon_id_tenant_status_*).
type Metrics struct {
	LagSeconds prometheus.Gauge
	// EventsTotal outcomes: applied | skipped (stale/duplicate version) |
	// rejected (protected tenant) | dlq | failed (DLQ publish also failed).
	EventsTotal *prometheus.CounterVec
	// DeniedTotal counts requests denied by the gate, by path
	// (login|token|refresh|session).
	DeniedTotal *prometheus.CounterVec
}

// NewMetrics registers the metrics; nil reg uses an isolated registry.
func NewMetrics(reg prometheus.Registerer, log *zap.SugaredLogger) *Metrics {
	if reg == nil {
		reg = prometheus.NewRegistry()
	}
	m := &Metrics{
		LagSeconds: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: "falcon_id", Subsystem: "tenant_status", Name: "lag_seconds",
			Help: "Age of the most recently processed example.tenant.status event.",
		}),
		EventsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "falcon_id", Subsystem: "tenant_status", Name: "events_total",
			Help: "example.tenant.status events by outcome (applied|skipped|rejected|dlq|failed).",
		}, []string{"outcome"}),
		DeniedTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "falcon_id", Subsystem: "tenant_status", Name: "denied_total",
			Help: "Requests denied because the tenant is suspended, by path.",
		}, []string{"path"}),
	}
	for _, c := range []prometheus.Collector{m.LagSeconds, m.EventsTotal, m.DeniedTotal} {
		if err := reg.Register(c); err != nil {
			if _, ok := err.(prometheus.AlreadyRegisteredError); !ok && log != nil {
				log.Warnw("tenantstatus: metric registration failed", "error", err)
			}
		}
	}
	return m
}

func (m *Metrics) inc(outcome string) {
	if m != nil {
		m.EventsTotal.WithLabelValues(outcome).Inc()
	}
}

// ObserveLag sets the lag gauge from the event timestamp.
func (m *Metrics) ObserveLag(at time.Time) {
	if m == nil {
		return
	}
	lag := time.Since(at).Seconds()
	if lag < 0 {
		lag = 0
	}
	m.LagSeconds.Set(lag)
}

// IncDenied records a request denied for a suspended tenant.
func (m *Metrics) IncDenied(path string) {
	if m != nil {
		m.DeniedTotal.WithLabelValues(path).Inc()
	}
}
