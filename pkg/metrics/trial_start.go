// SPDX-License-Identifier: AGPL-3.0-or-later

package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// ── Post-signup Trial Start Metrics ─────────────────────────────────────────
//
// TrialStartFailures tracks failures of the cardless-trial-start step in
// PostSignupProvisioner.OnSignupComplete (see signup_post_provisioner.go).
// Unlike product-entitlement provisioning failures (falcon_provisioning_*
// above), a failed trial start previously produced only a Warn log line and
// nothing else -- no metric, no retry, no operator-visible signal -- which is
// exactly how tenant 029a3c7e-b733-4c47-8854-37957dee6633 became a permanent,
// unlimited free account (subscription_status='trial' but trial_ends_at
// stayed NULL forever, invisible to tenant-management's expiry reconciler).
//
// This counter, plus the Warn->Error log-level bump alongside it, is the
// signup-side half of closing that gap: an operator can now alert on
// `rate(falcon_id_trial_start_failed_total[15m]) > 0` instead of relying on
// log-grepping. The actual repair for tenants that slip through anyway is
// tenant-management's trial_ends_at-gap reconciler (internal/trialexpiry),
// not a retry loop here -- see that package's doc comment for why.
var TrialStartFailures = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Name: "falcon_id_trial_start_failed_total",
		Help: "Total failures of the cardless trial-start step in post-signup provisioning, by account_type.",
	},
	[]string{"account_type"},
)
