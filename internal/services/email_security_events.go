// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"fmt"
	"html/template"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/dogukanturhal/falcon-id/internal/metrics"
)

// This file holds EmailService send-methods for SECURITY EVENT
// notifications — emails the user gets when something securitydirectly
// happens to their account. These are distinct from operational mail
// (welcome, invitations, magic-link) in two ways:
//
//   1. They cannot be silenced for "security-critical" event types.
//      Disabling them would undermine the compensating-control story
//      for trust placed in the RFC 9470 step-up gate alone (see
//      cmd/routes.go for the /mfa/disable* design rationale).
//
//   2. They MUST include the contextual signals an attacker cannot
//      forge after the fact: when, from where, on what device. The
//      legitimate user needs to be able to recognise "that wasn't me"
//      at a glance and click the embedded "secure your account" CTA.
//
// All templates render the same five context fields in a consistent
// "what / when / where / device" stack so users learn to scan the
// same shape across all four events.

// securityEventContext is the common payload for every security-event
// email. Fields are sourced from the request context at the point the
// mutation succeeds (login handler / step-up gate / risk service).
type securityEventContext struct {
	// When the event fired (UTC). Rendered in user's locale.
	Timestamp time.Time
	// IP the request came from (Cloudflare cf-connecting-ip honored).
	IPAddress string
	// Human-readable location ("Istanbul, TR") if available; "" suppresses the line.
	Location string
	// Browser + OS parsed from User-Agent ("Chrome on iOS") if available; "" suppresses.
	DeviceLabel string
	// Raw user-agent — fallback when DeviceLabel can't be parsed.
	UserAgent string
}

// renderEventContext renders the standard 4-line context stack as
// styled HTML rows. Designed to be embedded inside any security-event
// email body via fmt.Sprintf.
func renderEventContext(ctx securityEventContext) string {
	when := ctx.Timestamp
	if when.IsZero() {
		when = time.Now()
	}
	// RFC 1123 in UTC — unambiguous timestamp users in any locale can read.
	timeStr := when.UTC().Format("Mon, 02 Jan 2026 15:04:05 MST")

	device := ctx.DeviceLabel
	if device == "" {
		device = ctx.UserAgent
	}
	if device == "" {
		device = "Unknown device"
	}

	ip := ctx.IPAddress
	if ip == "" {
		ip = "Unknown IP"
	}

	location := ctx.Location
	locationRow := ""
	if location != "" {
		locationRow = fmt.Sprintf(
			`<tr><td style="padding:6px 0;color:#64748b;width:90px;">Location</td><td style="padding:6px 0;color:#0f172a;">%s</td></tr>`,
			template.HTMLEscapeString(location),
		)
	}

	return fmt.Sprintf(`
<table style="width:100%%;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;font-size:14px;border-top:1px solid #e2e8f0;margin-top:16px;">
    <tr><td style="padding:6px 0;color:#64748b;width:90px;">When</td><td style="padding:6px 0;color:#0f172a;">%s</td></tr>
    <tr><td style="padding:6px 0;color:#64748b;">From IP</td><td style="padding:6px 0;color:#0f172a;font-family:monospace;">%s</td></tr>
    %s
    <tr><td style="padding:6px 0;color:#64748b;">Device</td><td style="padding:6px 0;color:#0f172a;">%s</td></tr>
</table>`,
		template.HTMLEscapeString(timeStr),
		template.HTMLEscapeString(ip),
		locationRow,
		template.HTMLEscapeString(device),
	)
}

// securityEventShell wraps a one-line "what happened" header + the
// context table + a "wasn't you?" CTA in the same visual frame across
// all four email types. Differences are in the header gradient color
// and the title/body text.
func securityEventShell(headerColor, title, lead, contextHTML, ctaURL string) string {
	cta := ""
	if ctaURL != "" {
		cta = fmt.Sprintf(`
        <div style="text-align:center;margin:24px 0 8px 0;">
            <a href="%s" style="display:inline-block;padding:12px 28px;background:#dc2626;color:white;text-decoration:none;border-radius:6px;font-weight:600;font-size:14px;">Secure my account</a>
        </div>
        <p style="color:#64748b;font-size:12px;text-align:center;margin:8px 0 0 0;">If this was you, no action is needed.</p>`,
			template.HTMLEscapeString(ctaURL))
	}

	return fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>%s</title>
</head>
<body style="font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background-color:#f4f4f5;margin:0;padding:20px;">
    <div style="max-width:600px;margin:0 auto;background:white;border-radius:8px;overflow:hidden;box-shadow:0 2px 4px rgba(0,0,0,0.08);">
        <div style="background:linear-gradient(135deg,%s);padding:24px 30px;">
            <h1 style="color:white;margin:0;font-size:20px;font-weight:600;">%s</h1>
        </div>
        <div style="padding:24px 30px;">
            <p style="color:#475569;line-height:1.6;margin:0 0 8px 0;">%s</p>
            %s
            %s
        </div>
        <div style="padding:16px 30px;background:#f8fafc;color:#94a3b8;font-size:11px;text-align:center;border-top:1px solid #e2e8f0;">
            <p style="margin:0;">You're receiving this because of activity on your HexxLock account.</p>
            <p style="margin:4px 0 0 0;">&copy; HexxLock Corporation. All rights reserved.</p>
        </div>
    </div>
</body>
</html>`, title, headerColor, title, lead, contextHTML, cta)
}

// accountSecurityCTAURL builds the deep-link the user clicks from a
// security email to begin recovery (revoke sessions, change password,
// review devices). Falls back to /security when frontend URL is unset.
func (s *EmailService) accountSecurityCTAURL() string {
	base := s.config.FrontendURL
	if base == "" {
		base = defaultFrontendURL
	}
	return strings.TrimRight(base, "/") + "/security"
}

// SendMFAFactorRemoved notifies the user that a specific MFA factor
// was removed. Fires from MFAService.DisableMFA / DisableTOTPOnly /
// DisableEmailMFAOnly after the DB commit succeeds. Security-critical
// — never silenced. The mutation itself was already authorized by the
// RFC 9470 freshAuth gate; this email is the legitimate user's
// out-of-band signal to detect "wasn't me, my session was stolen and
// the attacker just stepped up with a phished factor."
//
// factorLabel: human-readable factor name ("authenticator app",
// "email-based two-factor", "passkey", "push device").
// remainingFactors: hint string for the body ("you still have a
// passkey enrolled" / "your account is no longer protected by MFA").
func (s *EmailService) SendMFAFactorRemoved(
	tenantID uuid.UUID,
	to, username, factorLabel, remainingFactors string,
	evtCtx securityEventContext,
) error {
	subject := fmt.Sprintf("Security alert: %s removed - HexxLock", factorLabel)

	lead := fmt.Sprintf(
		"Hello %s,<br><br>The <strong>%s</strong> on your HexxLock account was just removed. %s",
		template.HTMLEscapeString(username),
		template.HTMLEscapeString(factorLabel),
		template.HTMLEscapeString(remainingFactors),
	)

	body := securityEventShell(
		"#ef4444,#dc2626", // red — security removal
		"Two-factor method removed",
		lead,
		renderEventContext(evtCtx),
		s.accountSecurityCTAURL(),
	)

	return s.sendEmail(context.Background(), tenantID, metrics.EmailTemplateMFAFactorRemoved, to, subject, body, "")
}

// SendDeviceEnrolledViaAuthenticator tells a platform admin that a device
// enrollment was witnessed with their authenticator-app code instead of a
// passkey. Notification only (never carries a code): it is the legitimate
// user's out-of-band signal to detect "wasn't me". Security-critical.
func (s *EmailService) SendDeviceEnrolledViaAuthenticator(
	tenantID uuid.UUID,
	to, username, deviceUUID string,
	evtCtx securityEventContext,
) error {
	subject := "Security alert: device enrolled with authenticator app - HexxLock"

	lead := fmt.Sprintf(
		"Hello %s,<br><br>A device (<code>%s</code>) was just enrolled for secure access and witnessed with your <strong>authenticator-app code</strong>. If this was not you, change your password and contact a HexxLock administrator immediately so the device can be revoked.",
		template.HTMLEscapeString(username),
		template.HTMLEscapeString(deviceUUID),
	)

	body := securityEventShell(
		"#f59e0b,#d97706", // amber — high-trust action with a weaker factor
		"Device enrolled with authenticator app",
		lead,
		renderEventContext(evtCtx),
		s.accountSecurityCTAURL(),
	)

	return s.sendEmail(context.Background(), tenantID, metrics.EmailTemplateDeviceWitnessTOTP, to, subject, body, "")
}

// SendPasswordChanged notifies the user that their password was
// changed. Fires from AuthService.ChangePassword after the DB commit.
// Security-critical — never silenced.
func (s *EmailService) SendPasswordChanged(
	tenantID uuid.UUID,
	to, username string,
	evtCtx securityEventContext,
) error {
	subject := "Security alert: Password changed - HexxLock"

	lead := fmt.Sprintf(
		"Hello %s,<br><br>The password on your HexxLock account was just changed. If you didn't make this change, your account may have been compromised — click below to secure it immediately.",
		template.HTMLEscapeString(username),
	)

	body := securityEventShell(
		"#f59e0b,#d97706", // amber — credentials changed
		"Password changed",
		lead,
		renderEventContext(evtCtx),
		s.accountSecurityCTAURL(),
	)

	return s.sendEmail(context.Background(), tenantID, metrics.EmailTemplatePasswordChanged, to, subject, body, "")
}

// SendRecoveryEmailChanged notifies a user's PRIMARY email that a recovery
// email was added to or removed from their account. Out-of-band by design: an
// attacker who set their own recovery address can't suppress the alert to the
// real owner. action is "added" or "removed".
func (s *EmailService) SendRecoveryEmailChanged(
	tenantID uuid.UUID,
	to, username, action string,
	evtCtx securityEventContext,
) error {
	verb := "added to"
	if action == "removed" {
		verb = "removed from"
	}
	subject := "Security alert: Recovery email changed - HexxLock"

	lead := fmt.Sprintf(
		"Hello %s,<br><br>A recovery email was just %s your HexxLock account. If you didn't make this change, your account may have been compromised — secure it immediately.",
		template.HTMLEscapeString(username),
		template.HTMLEscapeString(verb),
	)

	body := securityEventShell(
		"#f59e0b,#d97706", // amber — recovery method changed
		"Recovery email changed",
		lead,
		renderEventContext(evtCtx),
		s.accountSecurityCTAURL(),
	)

	return s.sendEmail(context.Background(), tenantID, metrics.EmailTemplateRecoveryEmailChange, to, subject, body, "")
}

// SendNewDeviceSignIn notifies the user that a sign-in succeeded from
// a device fingerprint that's never been seen on their account. Fires
// from AuthService.Login when DeviceFingerprintService.IdentifyDevice
// returns isKnown=false. User-optional (defaults to opt-in) — users
// can disable in notification prefs (the only one of the four event
// types that respects opt-out).
func (s *EmailService) SendNewDeviceSignIn(
	tenantID uuid.UUID,
	to, username string,
	evtCtx securityEventContext,
) error {
	subject := "New sign-in to your HexxLock account"

	lead := fmt.Sprintf(
		"Hello %s,<br><br>A successful sign-in to your HexxLock account just happened from a device we don't recognise. If this was you, you can ignore this message. If not, secure your account now.",
		template.HTMLEscapeString(username),
	)

	body := securityEventShell(
		"#0ea5e9,#0284c7", // sky-blue — informational, not alarm
		"New sign-in detected",
		lead,
		renderEventContext(evtCtx),
		s.accountSecurityCTAURL(),
	)

	return s.sendEmail(context.Background(), tenantID, metrics.EmailTemplateNewDeviceSignIn, to, subject, body, "")
}

// SendAccountLocked notifies the user that their account was just
// locked. Fires from AuthService when too many failed login attempts
// trigger the brute-force lock. Security-critical — never silenced;
// the user needs to know an attacker is attempting their account.
//
// unlockAt: when automatic unlock fires; rendered in the body.
// reason: machine-readable reason ("too_many_failed_login_attempts",
// "admin_locked", etc) — rendered as a hint.
func (s *EmailService) SendAccountLocked(
	tenantID uuid.UUID,
	to, username, reason string,
	unlockAt *time.Time,
	evtCtx securityEventContext,
) error {
	subject := "Security alert: Your HexxLock account was locked"

	unlockHint := "Contact support if you need immediate access."
	if unlockAt != nil {
		unlockHint = fmt.Sprintf(
			"Your account will automatically unlock at %s. You can also reset your password to regain access immediately.",
			template.HTMLEscapeString(unlockAt.UTC().Format("Mon, 02 Jan 2026 15:04 MST")),
		)
	}

	reasonHint := ""
	switch reason {
	case "too_many_failed_login_attempts":
		reasonHint = " after too many failed sign-in attempts. Someone may be trying to guess your password."
	case "admin_locked":
		reasonHint = " by an administrator. Contact your organisation's support team for details."
	case "suspicious_activity":
		reasonHint = " after suspicious activity was detected on your account."
	}

	lead := fmt.Sprintf(
		"Hello %s,<br><br>Your HexxLock account was just locked%s<br><br>%s",
		template.HTMLEscapeString(username),
		reasonHint,
		unlockHint,
	)

	body := securityEventShell(
		"#dc2626,#991b1b", // dark red — most severe
		"Account locked",
		lead,
		renderEventContext(evtCtx),
		s.accountSecurityCTAURL(),
	)

	return s.sendEmail(context.Background(), tenantID, metrics.EmailTemplateAccountLocked, to, subject, body, "")
}

// SendSuspiciousLogin notifies the user that the risk engine detected
// anomalous activity on a successful sign-in. Fires from RiskService
// when a policy with action `send_email_notification` matches. Distinct
// from SendNewDeviceSignIn: this fires for elevated-risk signals
// (impossible travel, Tor exit, anonymous proxy, credential-stuffing
// pattern) — not just a fresh device.
//
// riskFactors: array of human-readable strings ("Impossible travel
// from Istanbul to Frankfurt within 1h", "Sign-in from a Tor exit
// node"). At least one should be provided.
func (s *EmailService) SendSuspiciousLogin(
	tenantID uuid.UUID,
	to, username string,
	riskFactors []string,
	evtCtx securityEventContext,
) error {
	subject := "Security alert: Unusual sign-in to your HexxLock account"

	factorsHTML := ""
	if len(riskFactors) > 0 {
		var sb strings.Builder
		sb.WriteString(`<ul style="color:#475569;line-height:1.6;padding-left:20px;margin:8px 0;">`)
		for _, f := range riskFactors {
			sb.WriteString(`<li>` + template.HTMLEscapeString(f) + `</li>`)
		}
		sb.WriteString(`</ul>`)
		factorsHTML = sb.String()
	}

	lead := fmt.Sprintf(
		"Hello %s,<br><br>An unusual sign-in to your HexxLock account was just detected. Our system flagged:%s<br>If this was you, you can ignore this message. If not, secure your account immediately.",
		template.HTMLEscapeString(username),
		factorsHTML,
	)

	body := securityEventShell(
		"#dc2626,#b91c1c", // red — risk-elevated
		"Unusual sign-in detected",
		lead,
		renderEventContext(evtCtx),
		s.accountSecurityCTAURL(),
	)

	return s.sendEmail(context.Background(), tenantID, metrics.EmailTemplateSuspiciousLogin, to, subject, body, "")
}
