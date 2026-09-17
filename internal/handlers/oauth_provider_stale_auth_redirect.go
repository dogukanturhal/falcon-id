// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import "net/url"

// staleAuthRedirectInput captures the decision inputs for the routing
// branch that fires when /oauth/authorize sees its max_age gate
// breached. Split out from the Authorize handler so the routing rule
// can be unit-tested without the full service/middleware/DB stack.
type staleAuthRedirectInput struct {
	// CurrentUserPresent reflects whether middleware populated a
	// CurrentUser on the gin context — i.e. the user has an active
	// IdP session even if its auth_time is stale.
	CurrentUserPresent bool
	// Prompt mirrors the OIDC `prompt` parameter on the inbound
	// /authorize request. RFC 9470 + OIDC Core §3.1.2.1 specify that
	// `prompt=login` MUST drive the user through full re-authentication
	// (no shortcut via MFA-only) — preserve that contract.
	Prompt string
	// HasMFAFactor is the source-of-truth (iam_users + iam_webauthn_
	// credentials + iam_push_mfa_devices union) result from
	// UserHasAnyMFAFactor. False when the user has zero factors —
	// in that case there's nothing to challenge with, so we must
	// fall through to /oauth/login for full re-auth.
	HasMFAFactor bool
	// SafeRedirect is the already-validated post-step-up resume
	// URL (the original /oauth/authorize URL with all params). Used
	// as the `rd=` parameter on the chosen step-up destination.
	SafeRedirect string
}

// staleAuthRedirect picks the right step-up destination when the
// max_age freshness gate has rejected the current session.
//
// Returns one of:
//
//	/auth/mfa/challenge?rd=<safe>   — canonical: user has a session +
//	                                  MFA factor and didn't ask for
//	                                  prompt=login. Single-factor
//	                                  re-verification re-establishes
//	                                  AAL2 per NIST SP 800-63B-4 §5.1,
//	                                  which is what max_age is gating.
//	                                  Matches Auth0 / Microsoft Entra.
//	/oauth/login?redirect=<safe>    — full re-authentication required.
//	                                  Fires when there is no existing
//	                                  IdP session, OR the user has zero
//	                                  MFA factors enrolled (nothing to
//	                                  challenge with), OR prompt=login
//	                                  was explicitly requested.
func staleAuthRedirect(in staleAuthRedirectInput) string {
	if in.CurrentUserPresent && in.Prompt != "login" && in.HasMFAFactor {
		return "/auth/mfa/challenge?rd=" + url.QueryEscape(in.SafeRedirect)
	}
	return "/oauth/login?redirect=" + url.QueryEscape(in.SafeRedirect)
}
