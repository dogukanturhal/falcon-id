// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"strings"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/pkg/logger"
)

// SecurityNotificationService is the single entry point for emitting
// user-facing security event emails (MFA factor removed, password
// changed, new device sign-in, account locked, suspicious activity).
// Centralising this serves three goals:
//
//  1. Single decision point for opt-out enforcement. Today only the
//     new-device event respects user preference; the other four are
//     security-critical and never silenced. Routing every send through
//     this service means the opt-out matrix lives in one place
//     instead of being scattered across MFA/auth/risk services.
//
//  2. Single decision point for failure handling. Email infra is
//     external — SMTP outages, dialer errors, rate-limit responses
//     MUST NOT fail the underlying security mutation. This service
//     runs all sends as best-effort: errors are structured-logged
//     for Loki alerting + Prometheus counters but never returned to
//     the caller.
//
//  3. Single decision point for compensating-control story. The
//     /mfa/disable* route's design rationale (cmd/routes.go) cites
//     "email-on-factor-removal" as one of the compensating controls
//     that makes trusting the step-up gate alone safe. This service
//     is where that control lives.
//
// Wired in cmd/services.go via SetSecurityNotificationService on the
// services that need it. Nil-safe — services that haven't been wired
// silently skip the email step.
type SecurityNotificationService struct {
	emailService securityEventMailer
	// optInUser is a closure that returns true when the user has
	// opted-in to a given notification type. Security-critical events
	// (MFA factor removed / password changed / account locked /
	// suspicious login) bypass this gate. Only the new-device event
	// consults it. Wired to a userRepo lookup at composition root.
	optInUser func(ctx context.Context, userID uuid.UUID, prefKey string) bool
}

// securityEventMailer is the narrow surface this service consumes from
// EmailService. Defined as an interface so unit tests can stub it
// without instantiating real SMTP infrastructure.
type securityEventMailer interface {
	IsConfigured() bool
	SendMFAFactorRemoved(tenantID uuid.UUID, to, username, factorLabel, remainingFactors string, evtCtx securityEventContext) error
	SendPasswordChanged(tenantID uuid.UUID, to, username string, evtCtx securityEventContext) error
	SendNewDeviceSignIn(tenantID uuid.UUID, to, username string, evtCtx securityEventContext) error
	SendAccountLocked(tenantID uuid.UUID, to, username, reason string, unlockAt *time.Time, evtCtx securityEventContext) error
	SendSuspiciousLogin(tenantID uuid.UUID, to, username string, riskFactors []string, evtCtx securityEventContext) error
	SendDeviceEnrolledViaAuthenticator(tenantID uuid.UUID, to, username, deviceUUID string, evtCtx securityEventContext) error
}

// NewSecurityNotificationService builds the service. optIn may be nil
// — that path treats every user as opted-in for the only opt-out-able
// event (new-device).
func NewSecurityNotificationService(emailService securityEventMailer, optIn func(ctx context.Context, userID uuid.UUID, prefKey string) bool) *SecurityNotificationService {
	return &SecurityNotificationService{
		emailService: emailService,
		optInUser:    optIn,
	}
}

// notifyContext returns true when we should attempt to send a given
// event. Centralises the "is mailer wired + configured + (for opt-out
// events) user opted in" decision.
func (s *SecurityNotificationService) shouldSend(ctx context.Context, userID uuid.UUID, prefKey string) bool {
	if s == nil || s.emailService == nil || !s.emailService.IsConfigured() {
		return false
	}
	if prefKey == "" {
		// Security-critical event — never silenced.
		return true
	}
	if s.optInUser == nil {
		// No preference lookup configured — default opt-in (industry
		// pattern: users get notified by default, can disable later).
		return true
	}
	return s.optInUser(ctx, userID, prefKey)
}

// fireAndLog runs the send synchronously but treats any error as
// non-fatal — logs structured then swallows. Keeping it synchronous
// (rather than `go func()`) gives operators a deterministic ordering
// in audit logs and avoids the goroutine-cancellation hazards that
// come from passing `ctx` into background sends; if SMTP is slow,
// callers can tune the gomail dialer timeout rather than discover
// orphaned goroutines.
func (s *SecurityNotificationService) fireAndLog(eventName string, fn func() error, fields ...zap.Field) {
	defer func() {
		// Defense against an unexpected panic in the mailer (template
		// formatting bug, etc.) — security notifications must never
		// crash the host process.
		if r := recover(); r != nil {
			logger.Log.Error("SecurityNotificationService: panic during send",
				append(fields,
					zap.String("event", eventName),
					zap.Any("panic", r),
				)...,
			)
		}
	}()
	if err := fn(); err != nil {
		logger.Log.Warn("SecurityNotificationService: email send failed (non-fatal)",
			append(fields,
				zap.String("event", eventName),
				zap.Error(err),
			)...,
		)
		return
	}
	logger.Log.Info("SecurityNotificationService: notification sent",
		append(fields, zap.String("event", eventName))...,
	)
}

// NotifyMFAFactorRemoved fires after MFAService.{DisableMFA,
// DisableTOTPOnly, DisableEmailMFAOnly} succeeds. Security-critical:
// never silenced. factorLabel must be a user-facing string
// ("authenticator app", "email-based two-factor", etc).
func (s *SecurityNotificationService) NotifyMFAFactorRemoved(ctx context.Context, user *models.User, factorLabel, remainingFactors string, evtCtx securityEventContext) {
	if !s.shouldSend(ctx, user.ID, "") || user == nil || user.Email == "" {
		return
	}
	s.fireAndLog(
		"mfa.factor_removed",
		func() error {
			return s.emailService.SendMFAFactorRemoved(user.TenantID, user.Email, user.Username, factorLabel, remainingFactors, evtCtx)
		},
		zap.String("user_id", user.ID.String()),
		zap.String("factor", factorLabel),
	)
}

// NotifyPasswordChanged fires after AuthService.ChangePassword
// succeeds. Security-critical: never silenced.
func (s *SecurityNotificationService) NotifyPasswordChanged(ctx context.Context, user *models.User, evtCtx securityEventContext) {
	if !s.shouldSend(ctx, user.ID, "") || user == nil || user.Email == "" {
		return
	}
	s.fireAndLog(
		"password.changed",
		func() error {
			return s.emailService.SendPasswordChanged(user.TenantID, user.Email, user.Username, evtCtx)
		},
		zap.String("user_id", user.ID.String()),
	)
}

// NotifyNewDeviceSignIn fires after AuthService.Login succeeds AND
// DeviceFingerprintService.IdentifyDevice reports a previously-unseen
// device fingerprint. User-optional: respects notify_new_device pref.
func (s *SecurityNotificationService) NotifyNewDeviceSignIn(ctx context.Context, user *models.User, evtCtx securityEventContext) {
	if !s.shouldSend(ctx, user.ID, "notify_new_device") || user == nil || user.Email == "" {
		return
	}
	s.fireAndLog(
		"login.new_device",
		func() error {
			return s.emailService.SendNewDeviceSignIn(user.TenantID, user.Email, user.Username, evtCtx)
		},
		zap.String("user_id", user.ID.String()),
		zap.String("ip", evtCtx.IPAddress),
	)
}

// NotifyAccountLocked fires when AuthService locks an account after
// too many failed login attempts (or any other lock reason). Security-
// critical: never silenced. unlockAt may be nil for indefinite locks.
func (s *SecurityNotificationService) NotifyAccountLocked(ctx context.Context, user *models.User, reason string, unlockAt *time.Time, evtCtx securityEventContext) {
	if !s.shouldSend(ctx, user.ID, "") || user == nil || user.Email == "" {
		return
	}
	s.fireAndLog(
		"account.locked",
		func() error {
			return s.emailService.SendAccountLocked(user.TenantID, user.Email, user.Username, reason, unlockAt, evtCtx)
		},
		zap.String("user_id", user.ID.String()),
		zap.String("reason", reason),
	)
}

// NotifySuspiciousLogin fires when RiskService applies a policy whose
// `send_email_notification` action is true. riskFactors should be
// human-readable strings ("Impossible travel from X to Y in 1h",
// "Tor exit node detected"). Security-critical: never silenced.
func (s *SecurityNotificationService) NotifySuspiciousLogin(ctx context.Context, user *models.User, riskFactors []string, evtCtx securityEventContext) {
	if !s.shouldSend(ctx, user.ID, "") || user == nil || user.Email == "" {
		return
	}
	s.fireAndLog(
		"login.suspicious",
		func() error {
			return s.emailService.SendSuspiciousLogin(user.TenantID, user.Email, user.Username, riskFactors, evtCtx)
		},
		zap.String("user_id", user.ID.String()),
		zap.Int("risk_factors", len(riskFactors)),
	)
}

// NotifyDeviceEnrolledViaAuthenticator fires after the ZTNA enrollment witness
// was minted from an authenticator-app code. Security-critical: never silenced.
func (s *SecurityNotificationService) NotifyDeviceEnrolledViaAuthenticator(ctx context.Context, user *models.User, deviceUUID string, evtCtx securityEventContext) {
	if user == nil || !s.shouldSend(ctx, user.ID, "") || user.Email == "" {
		return
	}
	s.fireAndLog(
		"device_witness.totp",
		func() error {
			return s.emailService.SendDeviceEnrolledViaAuthenticator(user.TenantID, user.Email, user.Username, deviceUUID, evtCtx)
		},
		zap.String("user_id", user.ID.String()),
		zap.String("device_uuid", deviceUUID),
	)
}

// parseDeviceLabel collapses a raw User-Agent into a short
// "Browser on OS" hint suitable for emails. Pure-substring matching
// — no third-party dependency, OSS-only discipline. Returns empty
// string when the UA cannot be reasonably parsed (the security email
// will fall back to the raw UA in that case).
func parseDeviceLabel(ua string) string {
	if ua == "" {
		return ""
	}
	ua = strings.ToLower(ua)

	browser := ""
	switch {
	case strings.Contains(ua, "edg/"):
		browser = "Edge"
	case strings.Contains(ua, "chrome/") && !strings.Contains(ua, "edg/"):
		browser = "Chrome"
	case strings.Contains(ua, "crios/"):
		// Chrome on iOS uses CriOS user-agent token (Apple webkit policy).
		browser = "Chrome"
	case strings.Contains(ua, "firefox/"):
		browser = "Firefox"
	case strings.Contains(ua, "safari/") && !strings.Contains(ua, "chrome/"):
		browser = "Safari"
	}

	os := ""
	switch {
	case strings.Contains(ua, "iphone") || strings.Contains(ua, "ipad") || strings.Contains(ua, "ipod") || strings.Contains(ua, "iphone os"):
		os = "iOS"
	case strings.Contains(ua, "android"):
		os = "Android"
	case strings.Contains(ua, "mac os x") || strings.Contains(ua, "macintosh"):
		os = "macOS"
	case strings.Contains(ua, "windows"):
		os = "Windows"
	case strings.Contains(ua, "linux"):
		os = "Linux"
	}

	switch {
	case browser != "" && os != "":
		return browser + " on " + os
	case browser != "":
		return browser
	case os != "":
		return os
	}
	return ""
}

// BuildEventContext is a convenience constructor — caller passes IP +
// UA + optional location, gets back a securityEventContext with a
// parsed DeviceLabel and a current-time Timestamp.
func BuildEventContext(ipAddress, userAgent, location string) securityEventContext {
	return securityEventContext{
		Timestamp:   time.Now().UTC(),
		IPAddress:   ipAddress,
		Location:    location,
		DeviceLabel: parseDeviceLabel(userAgent),
		UserAgent:   userAgent,
	}
}
