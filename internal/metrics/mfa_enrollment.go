// SPDX-License-Identifier: AGPL-3.0-or-later

// Package metrics holds Prometheus instrumentation for Falcon-ID's
// auth pipelines. Each subsystem owns one file in this package so
// scrape targets are obvious from grep alone.
//
// MFA enrollment counters (this file) close the observability gap
// surfaced 2026-05-12: until now the enrollment flow only emitted
// audit log lines (auth.mfa.enrollment_interrupt /
// auth.mfa.enrollment_init_failed). Operators had no way to dashboard
// enrollment funnel performance — completion rates, abandonment by
// step, method distribution — without grepping logs.
//
// Metric naming follows the IAM convention (iam_mfa_enrollment_*):
//
//	iam_mfa_enrollment_initiated_total{reason, method}    counter
//	iam_mfa_enrollment_completed_total{method}            counter
//	iam_mfa_enrollment_failed_total{step, method, reason} counter
//	iam_mfa_enrollment_duration_seconds{method, outcome}  histogram
//
// All counters use promauto.NewCounterVec so they self-register on
// init() and the cmd/-side wiring stays unchanged. The /metrics
// endpoint mounted in cmd/routes.go (line ~250 area) emits them.
//
// Dashboard recommendations (Grafana):
//
//	enrollment funnel = sum(initiated) → sum(completed) by method
//	abandonment by step =
//	  initiated - (completed + failed-by-step)
//	method preference = sum(initiated) by method
//	risk-vs-policy split = sum(initiated) by reason
package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	// MFAEnrollmentInitiated counts every issued enrollment interrupt
	// (the moment Falcon-ID mints an enrollment_token in response to
	// /api/v1/auth/login). Labelled by the trigger reason — "risk" for
	// risk-engine-driven interrupts, "policy" for unconditional
	// realm-policy enforcement — and by the offered method when the
	// user has already picked one (else "any" before the picker).
	//
	// Increment site: internal/services/auth_service.go,
	// createMFAEnrollmentInterrupt(), right after the audit log line.
	MFAEnrollmentInitiated = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "iam_mfa_enrollment_initiated_total",
			Help: "Total MFA enrollment interrupts issued, by trigger reason and method",
		},
		[]string{"reason", "method"},
	)

	// MFAEnrollmentMethodPicked counts every successful call to
	// /api/v1/auth/mfa/enrollment/init (user has picked a method and
	// got the setup material — QR for TOTP, code sent for email).
	// The delta between Initiated and MethodPicked is the
	// "abandoned at method picker" funnel step.
	//
	// Increment site: internal/handlers/auth_handler.go,
	// MFAEnrollmentInit(), at the success-response point per method.
	MFAEnrollmentMethodPicked = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "iam_mfa_enrollment_method_picked_total",
			Help: "Total successful enrollment method-picks, by method",
		},
		[]string{"method"},
	)

	// MFAEnrollmentCompleted counts every successful verify (factor
	// activated + session minted). The delta between MethodPicked and
	// Completed is the "abandoned at verify" funnel step — typically
	// the user couldn't get the TOTP code or didn't receive the email.
	//
	// Increment site: internal/handlers/auth_handler.go,
	// MFAEnrollmentVerify(), on the success path right before
	// JSON response.
	MFAEnrollmentCompleted = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "iam_mfa_enrollment_completed_total",
			Help: "Total MFA enrollments completed (factor activated, session issued), by method",
		},
		[]string{"method"},
	)

	// MFAEnrollmentFailed counts every error path in the enrollment
	// flow. The `step` label identifies WHERE the failure occurred
	// (init, verify) so dashboards can isolate problems quickly;
	// `reason` carries the failure class (invalid_code, expired_token,
	// service_unavailable, internal_error).
	//
	// Increment site: every error-response path in
	// MFAEnrollmentInit() / MFAEnrollmentVerify().
	MFAEnrollmentFailed = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "iam_mfa_enrollment_failed_total",
			Help: "Total MFA enrollment failures, by step and failure reason",
		},
		[]string{"step", "method", "reason"},
	)

	// MFAEnrollmentDuration histograms the wall-clock latency from
	// interrupt-issued to either completed or expired. Useful for
	// detecting backend slowdowns (TOTP secret generation, email
	// send latency) AND user-side abandonment patterns ("if users
	// haven't completed in 60s, they probably won't").
	//
	// Increment site: paired with MFAEnrollmentCompleted /
	// MFAEnrollmentFailed in the verify handler.
	MFAEnrollmentDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "iam_mfa_enrollment_duration_seconds",
			Help:    "Wall-clock seconds from enrollment interrupt to terminal outcome (completed or failed), by method and outcome",
			Buckets: []float64{1, 5, 10, 30, 60, 120, 300, 600},
		},
		[]string{"method", "outcome"},
	)
)
