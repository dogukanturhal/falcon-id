// SPDX-License-Identifier: AGPL-3.0-or-later

// Home Realm Discovery (HRD) counters.
//
// The /api/v1/auth/discover endpoint is the entry point of every
// login flow — the login UI calls it with an email, gets back the
// auth method (password / sso / signup / contact_admin) plus tenant
// branding. Before this file, the handler swallowed errors from the
// service (4 possible failure steps — invalid_email, domain_lookup,
// tenant_lookup, user_lookup — were all collapsed into a generic
// HTTP 500 `{"error":"discovery failed"}` with no log line that
// names the failing step).
//
// Diagnosed live 2026-05-20: 4 transient 500s in a 4-minute burst
// with sub-5ms latency. Because the handler logged no zap-Error
// line and the request_logger middleware only emits the status
// code, the underlying cause was unrecoverable from telemetry.
//
// This counter closes the observability gap. Cardinality stays
// bounded at ~10 steps × ~8 codes = 80 series; well under the
// per-job 1000-series soft limit on the platform Prometheus.
//
// Naming convention iam_discover_* mirrors the surrounding
// iam_mfa_enrollment_* / iam_oauth_token_* counters in this
// package.
package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	// DiscoverRequests counts every POST /api/v1/auth/discover
	// (success + failure). Outcome is "ok" on 200, the matching
	// DiscoverStep on a service error, "bad_request" on a malformed
	// HTTP body. tenant_known tells the dashboard whether the email
	// hit a domain-claimed tenant (true) or fell through to the
	// global-user / signup branch (false).
	//
	// Increment site: internal/handlers/discover_handler.go,
	// Discover(), exactly once per request at the end of the handler.
	DiscoverRequests = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "iam_discover_requests_total",
			Help: "Total HRD /api/v1/auth/discover requests, by outcome and whether a tenant was resolved",
		},
		[]string{"outcome", "tenant_known"},
	)

	// DiscoverErrors counts failures by service step. step is the
	// DiscoverStep that errored (invalid_email, domain_lookup,
	// tenant_lookup, user_lookup). code is the wrapped PgError's
	// SQLSTATE when the underlying error is *pgconn.PgError, else
	// the literal "other" — bounds cardinality even when arbitrary
	// upstream errors flow through.
	//
	// Increment site: internal/handlers/discover_handler.go,
	// Discover(), on the error-return path.
	//
	// Alert pattern (recommended Grafana / Alertmanager rule):
	//   increase(iam_discover_errors_total{step!="invalid_email"}[5m]) > 5
	// (invalid_email is user-input bug, not a server condition).
	DiscoverErrors = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "iam_discover_errors_total",
			Help: "HRD /api/v1/auth/discover errors, by failing step and underlying SQLSTATE (or 'other')",
		},
		[]string{"step", "code"},
	)
)
