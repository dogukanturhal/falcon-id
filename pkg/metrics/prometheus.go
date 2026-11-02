// SPDX-License-Identifier: AGPL-3.0-or-later

package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	// HTTPRequestsTotal is an exported identifier.
	HTTPRequestsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "iam_http_requests_total",
			Help: "Total number of HTTP requests",
		},
		[]string{"method", "path", "status"},
	)

	// HTTPRequestDuration is an exported identifier.
	HTTPRequestDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "iam_http_request_duration_seconds",
			Help:    "HTTP request duration in seconds",
			Buckets: []float64{.005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5, 10},
		},
		[]string{"method", "path"},
	)

	// HTTPRequestsInFlight is an exported identifier.
	HTTPRequestsInFlight = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "iam_http_requests_in_flight",
			Help: "Number of HTTP requests currently being processed",
		},
	)

	// AuthLoginAttempts is an exported identifier.
	AuthLoginAttempts = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "iam_auth_login_attempts_total",
			Help: "Total number of login attempts",
		},
		[]string{"status", "mfa_required", "auth_type"},
	// AuthTokenValidations is an exported identifier.
	)

	// AuthTokenValidations is an exported identifier.
	AuthTokenValidations = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "iam_auth_token_validations_total",
			Help: "Total number of token validations",
		},
		[]string{"status"},
	)

	// AuthTokenRefresh is an exported identifier.
	// Labels:
	//   status: success | fail
	//   reason: rotated | not_found | expired | reuse_detected | user_inactive |
	//           user_not_found | internal_error
	AuthTokenRefresh = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "iam_auth_token_refresh_total",
			Help: "Total number of token refresh attempts, labelled by outcome and reason",
		},
		[]string{"status", "reason"},
	)

	// AuthTokenReuseDetected counts refresh-token reuse events per OAuth 2.0
	// Security BCP §4.14. This is a security signal: each non-zero increment
	// means the reuse was NOT absorbed by the rotation grace window —
	// either an older-generation replay (attacker) or a malformed lineage.
	// SRE should alert on rate > 0.1/min sustained.
	AuthTokenReuseDetected = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "iam_auth_token_reuse_detected_total",
			Help: "Total refresh-token reuse events — potential theft or lineage bug (excludes grace-window absorbed races)",
		},
	)

	// AuthTokenConcurrentRace counts concurrent-refresh races absorbed by
	// the rotation grace window (Auth0 "leeway" / Okta "grace period").
	// These are benign — the loser gets a fresh sibling token pair and the
	// family is NOT revoked. A high rate indicates a client-side
	// coordination gap (missing Redis mutex, missing navigator.locks, etc.)
	// and should surface in dashboards but NOT page OnCall.
	AuthTokenConcurrentRace = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "iam_auth_token_concurrent_race_total",
			Help: "Refresh races absorbed by the rotation grace window — benign, indicates client coordination gap if elevated",
		},
	)

	// AuthTokenReplacedByWriteFailed counts rotations whose replaced_by lineage
	// pointer could not be recorded (that token loses lost-response recovery,
	// or a pointer was already set). Sustained non-zero means a store problem.
	AuthTokenReplacedByWriteFailed = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "iam_auth_token_replaced_by_write_failed_total",
			Help: "Refresh rotations whose replaced_by lineage pointer write failed",
		},
	)

	// AuthMFAVerifications is an exported identifier.
	AuthMFAVerifications = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "iam_auth_mfa_verifications_total",
			Help: "Total number of MFA verifications",
		},
		[]string{"method", "status"},
	)

	// RateLimitHits is an exported identifier.
	RateLimitHits = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "iam_rate_limit_hits_total",
			Help: "Total number of rate limit hits",
		},
		[]string{"rule_name", "blocked"},
	)
	// RateLimitChecks is an exported identifier.
	RateLimitChecks = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "iam_rate_limit_checks_total",
			Help: "Total number of rate limit checks",
		},
		[]string{"source"},
	)

	// ActiveSessions is an exported identifier.
	ActiveSessions = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "iam_active_sessions",
			Help: "Number of active sessions",
		},
		[]string{"tenant_id"},
	)
	// SessionCreated is an exported identifier.
	SessionCreated = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "iam_sessions_created_total",
			Help: "Total number of sessions created",
		},
		[]string{"tenant_id"},
	)
	// SessionTerminated is an exported identifier.
	SessionTerminated = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "iam_sessions_terminated_total",
			Help: "Total number of sessions terminated",
		},
		[]string{"tenant_id", "reason"},
	)

	// RedisCacheHits is an exported identifier.
	RedisCacheHits = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "iam_redis_cache_hits_total",
			Help: "Total number of Redis cache hits",
		},
		[]string{"cache_type", "hit"},
	)

	// RedisOperationDuration is an exported identifier.
	RedisOperationDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "iam_redis_operation_duration_seconds",
			Help:    "Redis operation duration in seconds",
			Buckets: []float64{.001, .005, .01, .025, .05, .1, .25, .5, 1},
		},
		[]string{"operation"},
	)

	// RedisErrors is an exported identifier.
	RedisErrors = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "iam_redis_errors_total",
			Help: "Total number of Redis errors",
		},
		[]string{"operation"},
	)

	// DatabaseQueryDuration is an exported identifier.
	DatabaseQueryDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "iam_database_query_duration_seconds",
			Help:    "Database query duration in seconds",
			Buckets: []float64{.001, .005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5},
		},
		[]string{"query_type"},
	)

	// DatabaseErrors is an exported identifier.
	DatabaseErrors = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "iam_database_errors_total",
			Help: "Total number of database errors",
		},
		[]string{"query_type"},
	)

	// DatabaseConnections is an exported identifier.
	DatabaseConnections = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "iam_database_connections",
			Help: "Number of database connections",
		},
		[]string{"state"},
	)

	// UsersTotal is an exported identifier.
	UsersTotal = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "iam_users_total",
			Help: "Total number of users",
		},
		[]string{"tenant_id", "status"},
	)

	// UserRegistrations is an exported identifier.
	UserRegistrations = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "iam_user_registrations_total",
			Help: "Total number of user registrations",
		},
		[]string{"tenant_id", "method"},
	)

	// ErrorsTotal is an exported identifier.
	ErrorsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "iam_errors_total",
			Help: "Total number of errors",
		},
		[]string{"type", "code"},
	)

	// LDAPSyncDuration is an exported identifier.
	LDAPSyncDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "iam_ldap_sync_duration_seconds",
			Help:    "LDAP sync operation duration in seconds",
			Buckets: []float64{1, 5, 10, 30, 60, 120, 300, 600},
		},
		[]string{"sync_type"},
	)

	// LDAPSyncUsers is an exported identifier.
	LDAPSyncUsers = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "iam_ldap_sync_users_total",
			Help: "Total number of users synced from LDAP",
		},
		[]string{"action"},
	)

	// LDAPErrors is an exported identifier.
	LDAPErrors = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "iam_ldap_errors_total",
			Help: "Total number of LDAP errors",
		},
		[]string{"operation"},
	)

	// DDILOfflineAuthz counts governed offline-authorization events (DDIL P3.2).
	// When SpiceDB is unreachable, falcon-id may serve a signed, time-boxed
	// last-known-good decision within budget, otherwise it fails closed. The
	// "event" label distinguishes: recorded (cached a fresh online decision),
	// served_allow / served_deny (offline degrade within budget), and the
	// fail-closed reasons denied_no_cache / denied_expired / denied_revoked.
	// A sustained rate on served_* means a real central-dependency partition;
	// denied_revoked proves offline revocation is being honoured.
	DDILOfflineAuthz = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "iam_ddil_offline_authz_total",
			Help: "Governed offline-authorization events by outcome (DDIL P3.2)",
		},
		[]string{"event"},
	)

	// OAuthBCLNoClients counts logout invocations whose tenant has zero
	// BCL-registered RPs. A non-zero rate means either a fresh-initdb-style
	// regression has wiped backchannel_logout_uri seeds, or a tenant has
	// genuinely no first-party RPs registered. SRE alert: rate>0/h sustained
	// for the platform tenant is a regression signal — every legitimate
	// logout MUST fan out at minimum to svc-talon (admin tier) or
	// svc-accounts (customer tier).
	OAuthBCLNoClients = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "iam_oauth_bcl_no_clients_total",
			Help: "Total Sign Out events that found zero BCL-registered RPs to notify (regression signal — see docs/audits/2026-05-10-slo-bcl-fcl-regression.md)",
		},
		[]string{"tenant_id"},
	)

	// OAuthFCLNoClients counts logout-page renders whose tenant has zero
	// FCL-registered RPs. Same regression signal as OAuthBCLNoClients but
	// for the iframe-driven path. Lower-priority alert (FCL is a
	// complementary path; BCL covers the load-bearing case).
	OAuthFCLNoClients = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "iam_oauth_fcl_no_clients_total",
			Help: "Total Sign Out renders that found zero FCL-registered RPs (regression signal — see docs/audits/2026-05-10-slo-bcl-fcl-regression.md)",
		},
		[]string{"tenant_id"},
	)

	// OAuthBCLDeliveries is the exported identifier for per-RP delivery
	// outcomes. Status one of: success | retry | client_error |
	// server_error | timeout | build_error.
	OAuthBCLDeliveries = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "iam_oauth_bcl_deliveries_total",
			Help: "Total back-channel logout delivery attempts, labelled by outcome",
		},
		[]string{"client_id", "status"},
	)

	// OAuthBCLFanOutSize observes the count of RPs the OP attempted to
	// notify per Sign Out event. Histogram buckets sized for typical
	// 1-12 RP estate; alarm if >50 (means wildcard fan-out misconfig).
	OAuthBCLFanOutSize = promauto.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "iam_oauth_bcl_fanout_size",
			Help:    "Distribution of BCL fan-out RP count per Sign Out event",
			Buckets: []float64{0, 1, 2, 5, 10, 20, 50, 100},
		},
	)

	// OAuthBCLOutboxPending is the live gauge of rows currently in
	// status='pending' on iam_oauth_logout_outbox. The drainer updates
	// it on every tick (regardless of whether it holds the advisory
	// lock) so dashboards always show a fresh queue depth.
	//
	// SRE alert: pending>50 sustained for 10min indicates either a
	// receiver outage or a drainer crash-loop.
	OAuthBCLOutboxPending = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "iam_oauth_bcl_outbox_pending",
			Help: "Count of pending rows in iam_oauth_logout_outbox awaiting delivery",
		},
	)

	// OAuthBCLOutboxDead is incremented every time the drainer
	// transitions a row to terminal status='dead'. Dead rows always
	// represent partial-logout state on a privileged-tools estate —
	// page on-call.
	//
	// SRE alert: rate > 0/5min for any rp_client_id pages on-call.
	OAuthBCLOutboxDead = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "iam_oauth_bcl_outbox_dead_total",
			Help: "Total outbox rows transitioned to dead state — partial-logout audit risk",
		},
		[]string{"rp_client_id"},
	)

	// OAuthBCLOutboxE2ESeconds is the end-to-end latency from row
	// INSERT (created_at) to successful delivery (status=sent). Buckets
	// span 1s (steady state — drainer ticks every 5s) to 1h (worst-
	// case retry budget = 35.6min). Anything above the 30min bucket is
	// effectively "in last-resort retry" and is a high-signal anomaly.
	OAuthBCLOutboxE2ESeconds = promauto.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "iam_oauth_bcl_outbox_e2e_seconds",
			Help:    "End-to-end seconds from outbox INSERT to status=sent",
			Buckets: []float64{1, 5, 10, 30, 60, 300, 600, 1800, 3600},
		},
	)

	// OAuthBCLOutboxAttemptDuration observes per-row delivery attempt
	// duration as seen by the drainer (HTTP roundtrip wall time).
	// Useful for spotting slow receivers in isolation.
	OAuthBCLOutboxAttemptDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "iam_oauth_bcl_outbox_attempt_duration_seconds",
			Help:    "Per-row delivery attempt duration in seconds",
			Buckets: []float64{.05, .1, .25, .5, 1, 2.5, 5, 10},
		},
		[]string{"rp_client_id"},
	)
)

// RecordHTTPRequest records HTTP request metrics
func RecordHTTPRequest(method, path, status string, duration float64) {
	HTTPRequestsTotal.WithLabelValues(method, path, status).Inc()
	HTTPRequestDuration.WithLabelValues(method, path).Observe(duration)
}

// RecordLoginAttempt records login attempt metrics
func RecordLoginAttempt(status, mfaRequired, authType string) {
	AuthLoginAttempts.WithLabelValues(status, mfaRequired, authType).Inc()
}

// RecordTokenValidation records token validation metrics
func RecordTokenValidation(status string) {
	AuthTokenValidations.WithLabelValues(status).Inc()
}

// RecordRateLimitHit records rate limit hit metrics
func RecordRateLimitHit(ruleName string, blocked bool) {
	blockedStr := "false"
	if blocked {
		blockedStr = "true"
	}
	RateLimitHits.WithLabelValues(ruleName, blockedStr).Inc()
}

// RecordRedisOperation records Redis operation metrics
func RecordRedisOperation(operation string, duration float64, err error) {
	RedisOperationDuration.WithLabelValues(operation).Observe(duration)
	if err != nil {
		RedisErrors.WithLabelValues(operation).Inc()
	}
}

// RecordDatabaseQuery records database query metrics
func RecordDatabaseQuery(queryType string, duration float64, err error) {
	DatabaseQueryDuration.WithLabelValues(queryType).Observe(duration)
	if err != nil {
		DatabaseErrors.WithLabelValues(queryType).Inc()
	}
}

// RecordError records error metrics
func RecordError(errorType, code string) {
	ErrorsTotal.WithLabelValues(errorType, code).Inc()
}

// RecordDDILOfflineAuthz records a governed offline-authorization event (P3.2).
// See the DDILOfflineAuthz metric for the valid event values.
func RecordDDILOfflineAuthz(event string) {
	DDILOfflineAuthz.WithLabelValues(event).Inc()
}
