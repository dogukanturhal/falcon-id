// SPDX-License-Identifier: AGPL-3.0-or-later

// Email delivery instrumentation (this file) closes the observability
// gap surfaced 2026-08-02 while root-causing "falcon-id email OTP not
// sending".
//
// The OTP *was* being sent. Proxmox Mail Gateway greylisted it for ~6
// minutes (measured: delay=358s, blocked=2 on the cgreylist triplet)
// because the in-cluster relay reaches PMG as an ordinary internet
// client. Users gave up long before the mail landed, and the code's
// 10-minute TTL left almost no margin.
//
// Nothing in Falcon-ID could have told us that. The send path emitted no
// metric at all, so a six-minute SMTP handoff and an instant one were
// indistinguishable from inside the service — and the failure stayed
// invisible for two days. Worse, sendEmail returned nil when SMTP was
// unconfigured, so a total non-delivery was indistinguishable from a
// success.
//
// Metric naming follows the IAM convention (iam_email_*):
//
//	iam_email_send_duration_seconds{template, outcome}  histogram
//	iam_email_send_total{template, outcome}             counter
//	iam_email_send_failures_total{template, reason}     counter
//
// `outcome` is one of: sent, failed, unconfigured.
// `reason` narrows a failure: smtp_unconfigured, smtp_dial, config_resolve.
//
// The histogram buckets are deliberately stretched well past a "normal"
// SMTP handoff (sub-second on a healthy path) into the minutes, because
// the incident this file exists for lived at 358 seconds. Buckets that
// top out at 10s would have shown nothing but +Inf.
//
// Recommended alerting (see the GitOps repository mail-path rules):
//
//	OTP delivery SLO   p95 < 30s, p99 < 60s over 30m
//	  histogram_quantile(0.95,
//	    sum by (le) (rate(iam_email_send_duration_seconds_bucket{
//	      template="mfa_code"}[30m])))
//
//	Any unconfigured send is a hard fault, never routine:
//	  increase(iam_email_send_failures_total{reason="smtp_unconfigured"}[15m]) > 0
package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	// EmailSendDuration measures the full send attempt: tenant SMTP
	// config resolution plus DialAndSend. This is the number that makes
	// a greylist stall visible.
	EmailSendDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name: "iam_email_send_duration_seconds",
			Help: "Time to resolve SMTP config and hand the message to the relay, by template and outcome.",
			// 0.1s .. ~13min. The upper range is not padding: the
			// 2026-08-02 greylist incident sat at 358s.
			Buckets: []float64{0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60, 120, 300, 600, 800},
		},
		[]string{"template", "outcome"},
	)

	// EmailSendTotal counts every send attempt by terminal outcome.
	EmailSendTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "iam_email_send_total",
			Help: "Email send attempts by template and outcome (sent, failed, unconfigured).",
		},
		[]string{"template", "outcome"},
	)

	// EmailSendFailures narrows failures to an actionable reason so an
	// alert can distinguish "the relay is down" from "this deployment
	// has no SMTP configured at all", which are very different pages.
	EmailSendFailures = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "iam_email_send_failures_total",
			Help: "Email send failures by template and reason (smtp_unconfigured, smtp_dial, config_resolve).",
		},
		[]string{"template", "reason"},
	)
)

var (
	// EmailOutboxPending is the current depth of iam_email_outbox in
	// status='pending'. Mirrors CAEPOutboxPending.
	EmailOutboxPending = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "iam_email_outbox_pending",
			Help: "Rows in iam_email_outbox awaiting delivery.",
		},
	)

	// EmailOutboxDrainerIterations counts drain ticks by outcome
	// (drained, no_rows, no_lock, error). Exactly one label-value is
	// recorded per tick — same metric contract as the CAEP drainer.
	EmailOutboxDrainerIterations = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "iam_email_outbox_drainer_iterations_total",
			Help: "Email outbox drain ticks by outcome.",
		},
		[]string{"outcome"},
	)

	// EmailOutboxDrainerTickDuration observes wall-clock per drain tick.
	EmailOutboxDrainerTickDuration = promauto.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "iam_email_outbox_drainer_tick_seconds",
			Help:    "Wall-clock duration of one email outbox drain tick.",
			Buckets: []float64{0.005, 0.01, 0.05, 0.1, 0.5, 1, 2.5, 5, 10, 30},
		},
	)
)

// Email delivery outcomes and failure reasons. Kept as constants so a
// typo cannot silently create a new time series.
const (
	EmailOutcomeSent         = "sent"
	EmailOutcomeFailed       = "failed"
	EmailOutcomeUnconfigured = "unconfigured"

	EmailReasonSMTPUnconfigured = "smtp_unconfigured"
	EmailReasonSMTPDial         = "smtp_dial"
	EmailReasonConfigResolve    = "config_resolve"
)

// Template labels. Bounded set — never derive a label from a subject
// line or a recipient address, both of which are unbounded and would
// blow up cardinality.
const (
	EmailTemplateVerificationCode   = "verification_code"
	EmailTemplateVerificationLink   = "verification_link"
	EmailTemplateMFACode            = "mfa_code"
	EmailTemplatePasswordReset      = "password_reset"
	EmailTemplateMFAEnabled         = "mfa_enabled"
	EmailTemplateMagicLink          = "magic_link"
	EmailTemplateInvitation         = "invitation"
	EmailTemplateSignupVerification = "signup_verification"
	EmailTemplateSMTPTest           = "smtp_test"

	// Account-security notifications (internal/services/email_security_events.go).
	// These are not auth-critical in the OTP sense — a delayed "new device
	// sign-in" notice is bad but not blocking — so they are labelled
	// separately to keep them out of the OTP delivery SLO.
	EmailTemplateMFAFactorRemoved    = "mfa_factor_removed"
	EmailTemplatePasswordChanged     = "password_changed"
	EmailTemplateRecoveryEmailChange = "recovery_email_changed"
	EmailTemplateNewDeviceSignIn     = "new_device_signin"
	EmailTemplateAccountLocked       = "account_locked"
	EmailTemplateSuspiciousLogin     = "suspicious_login"
	EmailTemplateDeviceWitnessTOTP   = "device_witness_totp"
)
