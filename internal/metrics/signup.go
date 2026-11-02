// SPDX-License-Identifier: AGPL-3.0-or-later

package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// SignupVerifyFailures counts rejected signup email-code submissions by
// reason (invalid, attempts_exceeded), so guessing shows up on a dashboard.
var SignupVerifyFailures = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Name: "signup_verify_failures_total",
		Help: "Failed signup email-code verifications by reason (invalid, attempts_exceeded).",
	},
	[]string{"reason"},
)

// Signup funnel stages for SignupFunnel.
const (
	SignupStageInitiated = "initiated"
	SignupStageVerified  = "verified"
	SignupStageCompleted = "completed"
	SignupStageFailed    = "failed"
)

// SignupFunnel counts signup progress by stage (initiated, verified,
// completed, failed) and whether a company name was supplied, so the
// company-at-complete step can be compared against the old flow.
var SignupFunnel = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Name: "iam_signup_funnel_total",
		Help: "Signup funnel events by stage (initiated, verified, completed, failed) and with_company (true, false).",
	},
	[]string{"stage", "with_company"},
)

// SignupDuration observes the time from signup row creation to completion.
var SignupDuration = promauto.NewHistogram(
	prometheus.HistogramOpts{
		Name: "iam_signup_duration_seconds",
		Help: "Time from signup request creation to successful completion.",
		// 10s .. 24h (the signup row TTL).
		Buckets: []float64{10, 30, 60, 120, 300, 600, 1800, 3600, 21600, 86400},
	},
)

// SignupFunnelInc records one funnel event.
func SignupFunnelInc(stage string, withCompany bool) {
	label := "false"
	if withCompany {
		label = "true"
	}
	SignupFunnel.WithLabelValues(stage, label).Inc()
}
