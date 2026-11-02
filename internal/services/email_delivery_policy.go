// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import "github.com/dogukanturhal/falcon-id/internal/metrics"

// TeamInvitationEmailTemplate identifies the synchronous Team invite. Its
// rendered body contains a role-acceptance token and is never queued.
const TeamInvitationEmailTemplate = "team_invitation"

// Delivery policy for outbound mail: which templates may be queued for
// durable, retried delivery, and which MUST be sent synchronously and
// never persisted.
//
// WHY THIS FILE EXISTS
// ====================
// An email outbox was proposed on 2026-08-02 (durable retry, auditable
// delivery trail, API not blocking on SMTP) after PMG greylisting delayed
// an OTP by 358s. Applying it uniformly would have been a security
// REGRESSION, for three independent reasons:
//
//  1. Falcon-ID never persists a plaintext one-time code today. The MFA
//     repository stores only CodeHash (see MFARepository.CreateMFAEmailCode);
//     the plaintext exists in memory for the length of one request and is
//     handed straight to the mail transport. An outbox row holding the
//     RENDERED BODY would put live, currently-valid authentication codes
//     at rest in Postgres where none exist now. Any DB read — backup,
//     replica, logical dump, a SELECT by an operator — would yield working
//     credentials.
//
//  2. Retry semantics are wrong for a one-time code. NIST SP 800-63B
//     §5.1.3.2 bounds out-of-band authentication at 10 minutes and requires
//     the secret be accepted only once within that window. A durable queue
//     that redelivers after an outage delivers a DEAD code, while having
//     extended the period a live one sat in storage. The failure mode an
//     outbox exists to fix — "deliver it later" — is precisely the one that
//     must not happen here. The correct behaviour is to fail fast and let
//     the user request a new code.
//
//  3. The durability win is negligible for interactive flows. Post-cutover
//     handoff to the relay is 0.09–0.37s. A user sitting at a login prompt
//     can simply ask for another code; a queued retry helps nobody.
//
// (Worth recording: NIST SP 800-63B does not recognise email as an
// out-of-band authenticator at all — "methods that do not prove possession
// of a specific device, such as VOIP or email, are excluded". Email OTP is
// a product decision taken outside the 800-63B AAL2 envelope. That is a
// separate discussion; it does not change the storage argument above, it
// strengthens it.)
//
// Non-credential mail is the opposite case. A security notice or an "MFA
// enabled" confirmation carries no live secret, and a late delivery is still
// useful — exactly the workload a transactional outbox is for. The
// transactional-outbox literature is silent on payload sensitivity, so the
// classification has to be made explicitly here rather than inherited from
// the pattern.
//
// THE RULE
// ========
// Credential-bearing templates are sent synchronously and are never written
// to any durable queue. Everything else may be queued. When the outbox
// lands, its enqueue path MUST call MayQueue and refuse anything that
// returns false — this is a compile-time-visible guard, not a comment
// somebody has to remember.
//
// Adding a template? Decide deliberately. If the rendered body would let a
// reader authenticate as, or take over, the recipient, it is
// credential-bearing.

// credentialBearingTemplates enumerates templates whose rendered body
// contains a live authentication secret or an account-takeover capability.
//
// password_reset and magic_link are included because their bodies embed a
// single-use link that is itself an authenticator — possession of the
// rendered body is possession of the account.
var credentialBearingTemplates = map[string]bool{
	metrics.EmailTemplateMFACode:            true, // login OTP
	metrics.EmailTemplateVerificationCode:   true, // email-verification OTP
	metrics.EmailTemplateVerificationLink:   true, // single-use verification link
	metrics.EmailTemplateSignupVerification: true, // signup token
	metrics.EmailTemplatePasswordReset:      true, // reset link == account takeover
	metrics.EmailTemplateMagicLink:          true, // passwordless sign-in link
	metrics.EmailTemplateInvitation:         true, // account-activation link
	TeamInvitationEmailTemplate:             true, // team role-acceptance link
}

// IsCredentialBearing reports whether a template's rendered body contains a
// live authentication secret. Such mail must not be persisted.
func IsCredentialBearing(template string) bool {
	return credentialBearingTemplates[template]
}

// MayQueue reports whether a template may be written to a durable outbox.
//
// Unknown templates return false — fail closed. A template nobody has
// classified is treated as if it carries a secret, so the failure mode of
// forgetting to classify is "sent synchronously" (correct but less durable)
// rather than "credentials written to disk" (a breach).
func MayQueue(template string) bool {
	if template == "" {
		return false
	}
	if _, known := knownTemplates[template]; !known {
		return false
	}
	return !IsCredentialBearing(template)
}

// knownTemplates is the closed set of templates the policy has an opinion
// about. Kept separate from credentialBearingTemplates so that MayQueue can
// distinguish "classified as safe" from "never classified".
var knownTemplates = map[string]struct{}{
	metrics.EmailTemplateMFACode:             {},
	metrics.EmailTemplateVerificationCode:    {},
	metrics.EmailTemplateVerificationLink:    {},
	metrics.EmailTemplateSignupVerification:  {},
	metrics.EmailTemplatePasswordReset:       {},
	metrics.EmailTemplateMagicLink:           {},
	metrics.EmailTemplateInvitation:          {},
	metrics.EmailTemplateMFAEnabled:          {},
	metrics.EmailTemplateSMTPTest:            {},
	metrics.EmailTemplateMFAFactorRemoved:    {},
	metrics.EmailTemplatePasswordChanged:     {},
	metrics.EmailTemplateRecoveryEmailChange: {},
	metrics.EmailTemplateNewDeviceSignIn:     {},
	metrics.EmailTemplateAccountLocked:       {},
	metrics.EmailTemplateSuspiciousLogin:     {},
	metrics.EmailTemplateDeviceWitnessTOTP:   {},
	TeamInvitationEmailTemplate:              {},
}
