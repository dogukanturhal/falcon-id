// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"html/template"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"
	"gopkg.in/gomail.v2"

	"github.com/dogukanturhal/falcon-id/internal/metrics"
	"github.com/dogukanturhal/falcon-id/pkg/config"
	"github.com/dogukanturhal/falcon-id/pkg/logger"
)

// generateRandomString generates a random hex string of specified length
func generateRandomString(length int) string {
	bytes := make([]byte, length/2)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

// cachedDialer wraps a gomail.Dialer with creation time for TTL-based eviction.
type cachedDialer struct {
	dialer    *gomail.Dialer
	from      string
	fromName  string
	createdAt time.Time
}

// dialerCacheTTL controls how long a cached dialer is reused before being recreated.
// Matches ConfigProvider Redis TTL so config changes propagate within the same window.
const (
	dialerCacheTTL          = 5 * time.Minute
	emailDefaultDisplayName = "there"
	defaultFrontendURL      = "http://localhost:3000"

	// defaultSenderDisplayName is the From-header display name used for
	// system/security email (signup verification, password reset, MFA,
	// invitations, ...) when the tenant has not configured its own
	// `smtp_from_name`. This is the behaviour every tenant saw before
	// per-tenant sender names existed — an unset override must degrade to
	// exactly this, never to a bare address, so a tenant configuring
	// nothing sees no regression.
	defaultSenderDisplayName = "Hexxlock Technologies Security"

)

// dkimSignableApexes lists the sending domains verified capable of DKIM
// signing at rspamd-dkim-signer, checked live via rspamc against the
// production signer (2026-09-24):
//
//   - example.com — selector "dkim", configured directly in Vault/rspamd.
//     Not a row in hexxlock_domain_management.platform_email_domains; this
//     is the original platform domain, provisioned before that self-serve
//     table existed.
//   - example.com — selector "s1". hexxlock_domain_management
//     .platform_email_domains: dkim_status=verified, spf_status=verified,
//     dmarc_status=verified, is_fully_authenticated=true.
//
// Sending a branded invitation From any OTHER domain would produce an
// UNSIGNED message — worse than today's alignment problem, not better.
// Extending this set requires provisioning a DKIM key + DNS record first
// (an operator/infra step — see hexxlock_domain_management's onboarding
// flow — never assumed here) and adding the domain to this map afterward.
var dkimSignableApexes = map[string]struct{}{
	"example.com": {},
}

// invitationSenderFor picks the From address/display name for a branded
// invitation email so it ALIGNS with emailLinkURL — the exact URL rendered
// as the accept/setup link in the SAME email. Sender/link alignment, not
// SPF/DKIM/DMARC pass/fail, is the anti-phishing signal this exists to
// satisfy (see MR description).
//
// Callers pass the actual link they built (acceptURL / setupLink), not a
// separately-resolved config value, so the sender can never drift from
// what the recipient actually sees in the body — by construction, not by
// convention. That link is itself built from ConfigProvider.FrontendURL,
// resolved per tenant (local cache -> Redis -> DB -> static default, see
// ResolveFrontendURL below), so a tenant — or a future product — that
// configures its own frontend_url gets a correctly-aligned sender without
// another code change here. Nothing product-specific is hardcoded.
//
// This does NOT resolve tenant-management's tenants.domain (a tenant's own
// custom/reseller apex). That was considered and deliberately deferred:
//
//   - falcon-id has no synced, trustworthy copy of that field today. The
//     Kafka tenant projection (tenantprojection/subscriber.go) does not
//     carry domain; iam_tenants.domain is set only via falcon-id's own
//     admin tenant-update endpoint and is never written by the projection,
//     so it can silently drift from tenant-management (the ADR-0029
//     source of truth) — using it here, in a control meant to prevent
//     phishing-signal mismatches, risks introducing exactly the mismatch
//     it exists to prevent.
//   - A live lookup would need a tenant-management HTTP client + scope
//     grant falcon-id does not currently have. payment-gateway hit the
//     identical gap (`GetTenantDomain: unexpected status 403`) — a
//     separate, already-tracked defect.
//   - Even with a trustworthy live value, DKIM is provisioned for exactly
//     the two apexes above, so sending From an arbitrary tenant domain
//     would fail to sign.
//
// Wiring true per-tenant custom-domain sending is a larger, cross-service
// change (tenant-management scope grant, plus DKIM provisioning per
// customer domain via hexxlock_domain_management). This function stops at
// deployment/product-level alignment, which is what the reported defect
// actually requires.
func invitationSenderFor(emailLinkURL string) (from, fromName string) {
	apex := registrableApex(emailLinkURL)
	if _, signable := dkimSignableApexes[apex]; signable {
		return "noreply@" + apex, invitationSenderDisplayName(apex)
	}
	// Unrecognized or unsignable apex (e.g. defaultFrontendURL's
	// "localhost" in local dev, or an apex we don't yet have DKIM for):
	// fall back to the one sender identity guaranteed both configured and
	// signable, rather than emitting mail under a domain that will fail
	// authentication outright.
	return "noreply@example.com", defaultSenderDisplayName
}

// invitationSenderDisplayName maps a signable apex to the brand name shown
// in the From header. Kept separate from invitationSenderFor so adding a
// third signable apex (once DKIM is provisioned for it) is a one-line
// addition here rather than a change to the alignment logic itself.
func invitationSenderDisplayName(apex string) string {
	if apex == "example.com" {
		return "AcmeApp"
	}
	return defaultSenderDisplayName
}

// registrableApex extracts the last two DNS labels of rawURL's host
// ("app.example.com" -> "example.com"). This is intentionally NOT a
// general public-suffix-list implementation — it only needs to work for
// the small, known set of apexes this platform sends invitations under
// (dkimSignableApexes above); a real multi-tenant custom-domain sender
// would need the full PSL treatment, which is part of why that is deferred
// (see invitationSenderFor).
func registrableApex(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil || u.Hostname() == "" {
		return ""
	}
	host := u.Hostname()
	labels := strings.Split(host, ".")
	if len(labels) >= 2 {
		return strings.Join(labels[len(labels)-2:], ".")
	}
	return host
}

// ResolveFrontendURL exposes the per-tenant frontend URL resolution
// (ConfigProvider.FrontendURL — local cache -> Redis -> DB -> static
// default) to callers outside this file, e.g. invitation_service.go's
// sendInvitationEmail, so the accept/setup link and the sender-alignment
// decision are computed from the SAME resolved value instead of two
// separate config reads that could theoretically diverge mid-request.
func (s *EmailService) ResolveFrontendURL(ctx context.Context, tenantID uuid.UUID) string {
	frontendURL := s.config.FrontendURL
	if s.configProvider != nil {
		if resolved := s.configProvider.FrontendURL(ctx, tenantID); resolved != "" {
			frontendURL = resolved
		}
	}
	if frontendURL == "" {
		frontendURL = defaultFrontendURL
	}
	return frontendURL
}

// EmailService is an exported type.
type EmailService struct {
	config         *config.Config
	dialer         *gomail.Dialer // legacy static dialer (fallback)
	configProvider *ConfigProvider
	dialerCache    sync.Map // map[string]*cachedDialer keyed by "host:port:user"
	// outbox, when set, enables durable queueing for NON-CREDENTIAL
	// templates via EnqueueOrSend. Nil means everything is sent
	// synchronously — the pre-outbox behaviour, which is correct, just
	// not durable. Credential mail is never queued regardless; see
	// email_delivery_policy.go and email_outbox_enqueue.go.
	outbox emailOutboxInserter
}

// NewEmailService is an exported function.
func NewEmailService(cfg *config.Config) *EmailService {
	var dialer *gomail.Dialer

	if cfg.SMTPHost != "" {
		dialer = createDialer(cfg.SMTPHost, cfg.SMTPPort, cfg.SMTPUsername, cfg.SMTPPassword, cfg.SMTPUseTLS, cfg.SMTPInsecureSkipVerify)

		logger.Info("Email service configured",
			zap.String("host", cfg.SMTPHost),
			zap.Int("port", cfg.SMTPPort),
			zap.Bool("ssl", dialer.SSL),
			zap.Bool("has_auth", cfg.SMTPUsername != ""),
		)
	}

	return &EmailService{
		config: cfg,
		dialer: dialer,
	}
}

// SetConfigProvider enables per-tenant dynamic SMTP configuration.
// When set, SMTP settings are resolved from the database via the 3-layer cache
// (local LRU → Redis → DB) instead of static env vars.
func (s *EmailService) SetConfigProvider(cp *ConfigProvider) {
	s.configProvider = cp
}

// createDialer builds a gomail.Dialer with the correct TLS settings for the given port.
func createDialer(host string, port int, username, password string, useTLS, insecureSkipVerify bool) *gomail.Dialer {
	dialer := gomail.NewDialer(host, port, username, password)

	// If no username/password, disable authentication (for internal mail relays)
	if username == "" && password == "" {
		dialer.Auth = nil
	}

	// Set a proper HELO hostname (required by some mail servers like Proxmox Mail Gateway)
	dialer.LocalName = "falcon.example.com"

	// Port 587 uses STARTTLS (upgrade connection), not implicit SSL
	// Port 465 uses implicit SSL
	switch {
	case port == 587:
		dialer.SSL = false
		dialer.TLSConfig = &tls.Config{
			ServerName:         host,
			InsecureSkipVerify: insecureSkipVerify, //nolint:gosec // InsecureSkipVerify is user-configurable for internal relay
		}
	case port == 465:
		dialer.SSL = true
		dialer.TLSConfig = &tls.Config{
			ServerName:         host,
			InsecureSkipVerify: insecureSkipVerify, //nolint:gosec // InsecureSkipVerify is user-configurable for internal relay
		}
	case useTLS:
		dialer.TLSConfig = &tls.Config{
			ServerName:         host,
			InsecureSkipVerify: insecureSkipVerify, //nolint:gosec // InsecureSkipVerify is user-configurable for internal relay
		}
	default:
		dialer.SSL = false
		// When TLS is explicitly disabled (e.g. port 25 internal relay), allow
		// opportunistic STARTTLS without strict certificate validation. The server
		// may advertise STARTTLS with a cert that doesn't match the DNS name
		// (e.g. internal hostname vs. external DNS).
		dialer.TLSConfig = &tls.Config{
			ServerName:         host,
			InsecureSkipVerify: true, //nolint:gosec // InsecureSkipVerify intentionally enabled for port 25 relay
		}
	}

	return dialer
}

// resolveSenderDisplayName returns fromName if the tenant configured one, else
// the platform default — never a bare "" that would silently drop the name
// tenants have always seen on system email.
func resolveSenderDisplayName(fromName string) string {
	if fromName == "" {
		return defaultSenderDisplayName
	}
	return fromName
}

// getOrCreateDialer resolves SMTP config for the given tenant and returns a cached dialer,
// the From address, and the From display name (already defaulted — see
// resolveSenderDisplayName).
// Resolution order: ConfigProvider (per-tenant DB config) → static config.Config (env vars).
func (s *EmailService) getOrCreateDialer(ctx context.Context, tenantID uuid.UUID) (*gomail.Dialer, string, string, error) { //nolint:unparam // error return kept for future use when SMTP validation may fail
	// If no ConfigProvider, use legacy static dialer
	if s.configProvider == nil {
		if s.dialer == nil {
			return nil, "", "", nil
		}
		return s.dialer, s.config.SMTPFrom, resolveSenderDisplayName(s.config.SMTPFromName), nil
	}

	// Resolve SMTP config from ConfigProvider (3-layer cache: local → Redis → DB → static fallback)
	host := s.configProvider.SMTPHost(ctx, tenantID)
	port := s.configProvider.SMTPPort(ctx, tenantID)
	from := s.configProvider.SMTPFrom(ctx, tenantID)
	fromName := resolveSenderDisplayName(s.configProvider.SMTPFromName(ctx, tenantID))
	username := s.configProvider.SMTPUsername(ctx, tenantID)
	password := s.configProvider.SMTPPassword(ctx, tenantID)
	useTLS := s.configProvider.SMTPUseTLS(ctx, tenantID)

	// If no SMTP host configured for this tenant, fall back to static config
	if host == "" {
		if s.dialer == nil {
			return nil, "", "", nil
		}
		return s.dialer, s.config.SMTPFrom, resolveSenderDisplayName(s.config.SMTPFromName), nil
	}

	// Cache key: "host:port:username" — shared across tenants using the same SMTP relay
	cacheKey := fmt.Sprintf("%s:%d:%s", host, port, username)

	// Check cache
	if cached, ok := s.dialerCache.Load(cacheKey); ok {
		cd := cached.(*cachedDialer)
		if time.Since(cd.createdAt) < dialerCacheTTL {
			return cd.dialer, from, fromName, nil
		}
		// Expired — fall through to create a new one
		s.dialerCache.Delete(cacheKey)
	}

	// Create new dialer
	dialer := createDialer(host, port, username, password, useTLS, false)

	s.dialerCache.Store(cacheKey, &cachedDialer{
		dialer:    dialer,
		from:      from,
		fromName:  fromName,
		createdAt: time.Now(),
	})

	logger.Info("Created SMTP dialer for tenant",
		zap.String("tenant_id", tenantID.String()),
		zap.String("host", host),
		zap.Int("port", port),
		zap.Bool("has_auth", username != ""),
	)

	return dialer, from, fromName, nil
}

// SendVerificationEmail sends an email verification code (legacy, kept for compatibility)
func (s *EmailService) SendVerificationEmail(tenantID uuid.UUID, to, code, username string) error {
	subject := "Verify Your Email - HexxLock"

	body := fmt.Sprintf(`
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Email Verification</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif; background-color: #f4f4f5; margin: 0; padding: 20px; }
        .container { max-width: 600px; margin: 0 auto; background: white; border-radius: 8px; overflow: hidden; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .header { background: linear-gradient(135deg, #3b82f6, #6366f1); padding: 30px; text-align: center; }
        .header h1 { color: white; margin: 0; font-size: 24px; }
        .content { padding: 30px; }
        .code-box { background: #f8fafc; border: 2px dashed #e2e8f0; border-radius: 8px; padding: 20px; text-align: center; margin: 20px 0; }
        .code { font-size: 32px; font-weight: bold; color: #1e40af; letter-spacing: 8px; font-family: monospace; }
        .footer { padding: 20px 30px; background: #f8fafc; color: #64748b; font-size: 12px; text-align: center; }
        p { color: #475569; line-height: 1.6; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔐 HexxLock</h1>
        </div>
        <div class="content">
            <p>Hello %s,</p>
            <p>Please verify your email address by entering the following code:</p>
            <div class="code-box">
                <div class="code">%s</div>
            </div>
            <p>This code will expire in <strong>10 minutes</strong>.</p>
            <p>If you didn't request this verification, please ignore this email or contact support if you have concerns.</p>
        </div>
        <div class="footer">
            <p>&copy; 2024 HexxLock Corporation. All rights reserved.</p>
            <p>This is an automated message, please do not reply.</p>
        </div>
    </div>
</body>
</html>
`, template.HTMLEscapeString(username), template.HTMLEscapeString(code))

	return s.sendEmail(context.Background(), tenantID, metrics.EmailTemplateVerificationCode, to, subject, body, "")
}

// SendVerificationEmailLink sends an email verification link
func (s *EmailService) SendVerificationEmailLink(tenantID uuid.UUID, to, verificationLink, username string) error {
	subject := "Verify Your Email - HexxLock"

	body := fmt.Sprintf(`
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Email Verification</title>
</head>
<body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif; background-color: #f4f4f5; margin: 0; padding: 20px;">
    <div style="max-width: 600px; margin: 0 auto; background: white; border-radius: 8px; overflow: hidden; box-shadow: 0 2px 4px rgba(0,0,0,0.1);">
        <div style="background: #3b82f6; padding: 30px; text-align: center;">
            <h1 style="color: white; margin: 0; font-size: 24px;">HexxLock</h1>
        </div>
        <div style="padding: 30px;">
            <p style="color: #475569; line-height: 1.6;">Hello %s,</p>
            <p style="color: #475569; line-height: 1.6;">Please verify your email address by clicking the button below:</p>
            <p style="text-align: center; margin: 30px 0;">
                <a href="%s" style="display: inline-block; background-color: #3b82f6; color: white; padding: 14px 28px; text-decoration: none; border-radius: 6px; font-weight: bold;">Verify Email</a>
            </p>
            <p style="color: #475569; line-height: 1.6;">Or copy and paste this link into your browser:</p>
            <p style="word-break: break-all; color: #3b82f6;">%s</p>
            <p style="color: #475569; line-height: 1.6;">This link will expire in <strong>10 minutes</strong>.</p>
            <p style="color: #475569; line-height: 1.6;">If you didn't request this verification, please ignore this email or contact support if you have concerns.</p>
        </div>
        <div style="padding: 20px 30px; background: #f8fafc; color: #64748b; font-size: 12px; text-align: center;">
            <p style="margin: 5px 0;">&copy; 2024 HexxLock Corporation. All rights reserved.</p>
            <p style="margin: 5px 0;">This is an automated message, please do not reply.</p>
        </div>
    </div>
</body>
</html>
`, template.HTMLEscapeString(username), verificationLink, verificationLink)

	return s.sendEmail(context.Background(), tenantID, metrics.EmailTemplateVerificationLink, to, subject, body, "")
}

// SendMFACode sends a one-time MFA code via email
func (s *EmailService) SendMFACode(tenantID uuid.UUID, to, code, username string) error {
	subject := "Your HexxLock Login Code"

	body := fmt.Sprintf(`
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Login Verification Code</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif; background-color: #f4f4f5; margin: 0; padding: 20px; }
        .container { max-width: 600px; margin: 0 auto; background: white; border-radius: 8px; overflow: hidden; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .header { background: linear-gradient(135deg, #3b82f6, #6366f1); padding: 30px; text-align: center; }
        .header h1 { color: white; margin: 0; font-size: 24px; }
        .content { padding: 30px; }
        .code-box { background: #fef3c7; border: 2px solid #f59e0b; border-radius: 8px; padding: 20px; text-align: center; margin: 20px 0; }
        .code { font-size: 36px; font-weight: bold; color: #92400e; letter-spacing: 10px; font-family: monospace; }
        .warning { background: #fef2f2; border-left: 4px solid #ef4444; padding: 12px; margin: 20px 0; color: #991b1b; }
        .footer { padding: 20px 30px; background: #f8fafc; color: #64748b; font-size: 12px; text-align: center; }
        p { color: #475569; line-height: 1.6; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔐 HexxLock</h1>
        </div>
        <div class="content">
            <p>Hello %s,</p>
            <p>Your one-time login verification code is:</p>
            <div class="code-box">
                <div class="code">%s</div>
            </div>
            <p>This code will expire in <strong>10 minutes</strong>.</p>
            <div class="warning">
                <strong>Security Notice:</strong> Never share this code with anyone. HexxLock staff will never ask for your verification code.
            </div>
            <p>If you didn't attempt to log in, please secure your account immediately by changing your password.</p>
        </div>
        <div class="footer">
            <p>&copy; 2024 HexxLock Corporation. All rights reserved.</p>
            <p>This is an automated message, please do not reply.</p>
        </div>
    </div>
</body>
</html>
`, template.HTMLEscapeString(username), template.HTMLEscapeString(code))

	return s.sendEmail(context.Background(), tenantID, metrics.EmailTemplateMFACode, to, subject, body, "")
}

// SendPasswordReset sends a password reset email
func (s *EmailService) SendPasswordReset(tenantID uuid.UUID, to, token, username string) error {
	subject := "Reset Your Password - HexxLock"

	// The reset page lives on the hosted login (IdP host); PASSWORD_RESET_URL_BASE
	// overrides FRONTEND_URL for this link only.
	frontendURL := s.config.PasswordResetURLBase
	if frontendURL == "" {
		frontendURL = s.config.FrontendURL
	}
	if frontendURL == "" {
		frontendURL = defaultFrontendURL
	}
	frontendURL = strings.TrimRight(frontendURL, "/")
	resetLink := fmt.Sprintf("%s/login/reset-password?token=%s", frontendURL, token)

	body := fmt.Sprintf(`
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Password Reset</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif; background-color: #f4f4f5; margin: 0; padding: 20px; }
        .container { max-width: 600px; margin: 0 auto; background: white; border-radius: 8px; overflow: hidden; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .header { background: linear-gradient(135deg, #3b82f6, #6366f1); padding: 30px; text-align: center; }
        .header h1 { color: white; margin: 0; font-size: 24px; }
        .content { padding: 30px; }
        .button { display: inline-block; background: linear-gradient(135deg, #3b82f6, #6366f1); color: white; padding: 14px 28px; text-decoration: none; border-radius: 6px; font-weight: bold; margin: 20px 0; }
        .footer { padding: 20px 30px; background: #f8fafc; color: #64748b; font-size: 12px; text-align: center; }
        p { color: #475569; line-height: 1.6; }
        .link { word-break: break-all; color: #3b82f6; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔐 HexxLock</h1>
        </div>
        <div class="content">
            <p>Hello %s,</p>
            <p>We received a request to reset your password. Click the button below to create a new password:</p>
            <p style="text-align: center;">
                <a href="%s" class="button">Reset Password</a>
            </p>
            <p>Or copy and paste this link into your browser:</p>
            <p class="link">%s</p>
            <p>This link will expire in <strong>1 hour</strong>.</p>
            <p>If you didn't request a password reset, please ignore this email. Your password will remain unchanged.</p>
        </div>
        <div class="footer">
            <p>&copy; 2024 HexxLock Corporation. All rights reserved.</p>
            <p>This is an automated message, please do not reply.</p>
        </div>
    </div>
</body>
</html>
`, template.HTMLEscapeString(username), resetLink, resetLink)

	return s.sendEmail(context.Background(), tenantID, metrics.EmailTemplatePasswordReset, to, subject, body, "")
}

// SendMFAEnabled notifies user that MFA has been enabled
func (s *EmailService) SendMFAEnabled(tenantID uuid.UUID, to, username, mfaType string) error {
	subject := "Two-Factor Authentication Enabled - HexxLock"

	mfaTypeDisplay := "Authenticator App (TOTP)"
	if mfaType == authMethodEmail {
		mfaTypeDisplay = "Email Verification"
	}

	body := fmt.Sprintf(`
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>2FA Enabled</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif; background-color: #f4f4f5; margin: 0; padding: 20px; }
        .container { max-width: 600px; margin: 0 auto; background: white; border-radius: 8px; overflow: hidden; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .header { background: linear-gradient(135deg, #10b981, #059669); padding: 30px; text-align: center; }
        .header h1 { color: white; margin: 0; font-size: 24px; }
        .content { padding: 30px; }
        .success-box { background: #ecfdf5; border: 1px solid #10b981; border-radius: 8px; padding: 20px; text-align: center; margin: 20px 0; }
        .footer { padding: 20px 30px; background: #f8fafc; color: #64748b; font-size: 12px; text-align: center; }
        p { color: #475569; line-height: 1.6; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>✅ 2FA Enabled</h1>
        </div>
        <div class="content">
            <p>Hello %s,</p>
            <div class="success-box">
                <p style="margin: 0; color: #065f46; font-weight: bold;">Two-Factor Authentication has been enabled on your account.</p>
            </div>
            <p><strong>Method:</strong> %s</p>
            <p>From now on, you'll need to provide a verification code in addition to your password when logging in.</p>
            <p><strong>Important:</strong> Keep your backup codes in a safe place. You'll need them if you lose access to your authentication method.</p>
            <p>If you didn't enable 2FA, please contact support immediately.</p>
        </div>
        <div class="footer">
            <p>&copy; 2024 HexxLock Corporation. All rights reserved.</p>
        </div>
    </div>
</body>
</html>
`, template.HTMLEscapeString(username), mfaTypeDisplay)

	return s.sendEmail(context.Background(), tenantID, metrics.EmailTemplateMFAEnabled, to, subject, body, "")
}

// SendMagicLink sends a magic link for passwordless authentication
func (s *EmailService) SendMagicLink(tenantID uuid.UUID, to, magicLink, username string) error {
	subject := "Sign In to HexxLock"

	displayName := username
	if displayName == "" {
		displayName = emailDefaultDisplayName
	}

	body := fmt.Sprintf(`
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Sign In</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif; background-color: #f4f4f5; margin: 0; padding: 20px; }
        .container { max-width: 600px; margin: 0 auto; background: white; border-radius: 8px; overflow: hidden; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .header { background: linear-gradient(135deg, #6366f1, #4f46e5); padding: 30px; text-align: center; }
        .header h1 { color: white; margin: 0; font-size: 24px; }
        .content { padding: 30px; }
        .button { display: inline-block; background: linear-gradient(135deg, #6366f1, #4f46e5); color: white !important; text-decoration: none; padding: 14px 28px; border-radius: 6px; font-weight: bold; margin: 20px 0; }
        .button:hover { opacity: 0.9; }
        .footer { padding: 20px 30px; background: #f8fafc; color: #64748b; font-size: 12px; text-align: center; }
        p { color: #475569; line-height: 1.6; }
        .warning { background: #fef3c7; border: 1px solid #f59e0b; border-radius: 8px; padding: 15px; margin: 20px 0; font-size: 14px; }
        .link { word-break: break-all; color: #6366f1; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔐 Sign In to HexxLock</h1>
        </div>
        <div class="content">
            <p>Hello %s,</p>
            <p>Click the button below to sign in to your account. No password required!</p>
            <p style="text-align: center;">
                <a href="%s" class="button">Sign In Now</a>
            </p>
            <div class="warning">
                <p style="margin: 0;"><strong>⏰ This link expires in 15 minutes.</strong></p>
            </div>
            <p>If the button doesn't work, copy and paste this link into your browser:</p>
            <p class="link">%s</p>
            <p>If you didn't request this link, you can safely ignore this email.</p>
        </div>
        <div class="footer">
            <p>&copy; 2024 HexxLock Corporation. All rights reserved.</p>
            <p>This is an automated message - please do not reply.</p>
        </div>
    </div>
</body>
</html>
`, template.HTMLEscapeString(displayName), magicLink, magicLink)

	return s.sendEmail(context.Background(), tenantID, metrics.EmailTemplateMagicLink, to, subject, body, "")
}

// SendInvitation sends an invitation email for account setup
func (s *EmailService) SendInvitation(tenantID uuid.UUID, to, setupLink, username, tenantName string) error {
	subject := fmt.Sprintf("You've been invited to %s on AcmeApp", tenantName)

	displayName := username
	if displayName == "" {
		displayName = emailDefaultDisplayName
	}

	body := fmt.Sprintf(`
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Account Invitation</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif; background-color: #f4f4f5; margin: 0; padding: 20px; }
        .container { max-width: 600px; margin: 0 auto; background: white; border-radius: 8px; overflow: hidden; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .header { background: linear-gradient(135deg, #4F46E5, #6366f1); padding: 30px; text-align: center; }
        .header h1 { color: white; margin: 0; font-size: 24px; }
        .content { padding: 30px; }
        .button { display: inline-block; background: linear-gradient(135deg, #4F46E5, #6366f1); color: white !important; text-decoration: none; padding: 14px 28px; border-radius: 6px; font-weight: bold; margin: 20px 0; }
        .button:hover { opacity: 0.9; }
        .footer { padding: 20px 30px; background: #f8fafc; color: #64748b; font-size: 12px; text-align: center; }
        p { color: #475569; line-height: 1.6; }
        .warning { background: #fef3c7; border: 1px solid #f59e0b; border-radius: 8px; padding: 15px; margin: 20px 0; font-size: 14px; }
        .link { word-break: break-all; color: #4F46E5; }
        .features { background: #f8fafc; border-radius: 8px; padding: 20px; margin: 20px 0; }
        .features h3 { margin-top: 0; color: #1e293b; }
        .features ul { margin: 0; padding-left: 20px; color: #475569; }
        .features li { margin: 8px 0; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Welcome to AcmeApp</h1>
        </div>
        <div class="content">
            <p>Hello %s,</p>
            <p>You have been invited to be the administrator of <strong>%s</strong> on AcmeApp.</p>
            <p>Click the button below to set up your password and activate your account:</p>
            <p style="text-align: center;">
                <a href="%s" class="button">Set Up Your Account</a>
            </p>
            <div class="warning">
                <p style="margin: 0;"><strong>Important:</strong> This link will expire in 72 hours. If you did not expect this invitation, please ignore this email.</p>
            </div>
            <div class="features">
                <h3>What you can do as an administrator:</h3>
                <ul>
                    <li>Manage users and permissions</li>
                    <li>Configure organization settings</li>
                    <li>Access all enabled modules</li>
                    <li>View reports and analytics</li>
                </ul>
            </div>
            <p>If the button doesn't work, copy and paste this link into your browser:</p>
            <p class="link">%s</p>
        </div>
        <div class="footer">
            <p>&copy; 2024 HexxLock Corporation. All rights reserved.</p>
            <p>This is an automated message - please do not reply.</p>
        </div>
    </div>
</body>
</html>
`, template.HTMLEscapeString(displayName), template.HTMLEscapeString(tenantName), setupLink, setupLink)

	// Branded invitation — align the sender to setupLink itself (the exact
	// URL rendered above), not a hardcoded domain. See invitationSenderFor.
	return s.sendEmail(context.Background(), tenantID, metrics.EmailTemplateInvitation, to, subject, body, setupLink)
}

// SendTeamInvitation hands the credential-bearing invitation directly to the
// relay. The rendered token must never be persisted in the durable outbox.
// existingAccount only adapts the wording ("sign in to accept" instead of
// "create your account"); the link and subject are identical either way.
func (s *EmailService) SendTeamInvitation(ctx context.Context, tenantID uuid.UUID, to, token string, existingAccount bool) error {
	baseURL := strings.TrimRight(s.ResolveFrontendURL(ctx, tenantID), "/")
	acceptURL := baseURL + "/invitations/accept?token=" + url.QueryEscape(token)
	// Branded invitation — align the sender to acceptURL itself (the exact
	// URL rendered below), not a hardcoded domain. See invitationSenderFor.
	return s.sendEmail(ctx, tenantID, TeamInvitationEmailTemplate, to,
		"You've been invited to join a team on AcmeApp",
		teamInvitationHTMLBody(acceptURL, existingAccount), acceptURL)
}

// teamInvitationHTMLBody renders the team-invitation email HTML.
//
// The accept link is deliberately rendered TWICE: once as the <a href>
// button, and once as plain visible text under "Or copy and paste this
// link into your browser" (the same pattern every other templated email in
// this file already follows — see SendVerificationEmailLink,
// SendPasswordReset, SendMagicLink, SendInvitation). That second copy is
// load-bearing, not decorative: sendEmail's htmlToPlainText derives the
// multipart text/plain alternative by stripping HTML TAGS, which discards
// an <a href="..."> attribute entirely and keeps only its link text
// ("Accept invitation"). Without a plain-text copy of the URL, a recipient
// reading the plain-text part of this email (any client that prefers or
// only renders text/plain) sees an invitation with no way to act on it —
// the HTML part remains clickable, but the plain-text part does not
// degrade to a usable link the way it should.
//
// The product name is AcmeApp. "ExampleSuite" is an internal platform name and
// must never reach a customer's inbox.
func teamInvitationHTMLBody(acceptURL string, existingAccount bool) string {
	escapedURL := template.HTMLEscapeString(acceptURL)
	intro := "You have been invited to join a team on AcmeApp."
	if existingAccount {
		intro = "You have been invited to join a team on AcmeApp. You already have a AcmeApp account: sign in with this email address to accept the invitation."
	}
	return fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Team Invitation</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif; background-color: #f4f4f5; margin: 0; padding: 20px; }
        .container { max-width: 600px; margin: 0 auto; background: white; border-radius: 8px; overflow: hidden; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .header { background: linear-gradient(135deg, #3b82f6, #6366f1); padding: 30px; text-align: center; }
        .header h1 { color: white; margin: 0; font-size: 24px; }
        .content { padding: 30px; }
        .button { display: inline-block; background: linear-gradient(135deg, #3b82f6, #6366f1); color: white; padding: 14px 28px; text-decoration: none; border-radius: 6px; font-weight: bold; margin: 20px 0; }
        .footer { padding: 20px 30px; background: #f8fafc; color: #64748b; font-size: 12px; text-align: center; }
        p { color: #475569; line-height: 1.6; }
        .link { word-break: break-all; color: #3b82f6; }
        @media only screen and (max-width: 480px) {
            body { padding: 8px; }
            .content { padding: 20px; }
            .button { display: block; text-align: center; }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>AcmeApp</h1>
        </div>
        <div class="content">
            <p>Hello,</p>
            <p>%s</p>
            <p style="text-align: center;">
                <a href="%s" class="button">Accept invitation</a>
            </p>
            <p>Or copy and paste this link into your browser:</p>
            <p class="link">%s</p>
            <p>This invitation expires in 7 days. If you did not expect this invitation, you can safely ignore this email.</p>
        </div>
        <div class="footer">
            <p>AcmeApp</p>
        </div>
    </div>
</body>
</html>`, template.HTMLEscapeString(intro), escapedURL, escapedURL)
}

// formatSignupCode renders a 6-digit code as "482 913" for readability.
func formatSignupCode(code string) string {
	if len(code) == 6 {
		return code[:3] + " " + code[3:]
	}
	return code
}

// SendSignupVerificationEmail sends the signup email verification message with
// the 6-digit one-time code (valid for 15 minutes). The email is English-only:
// the service has no email i18n mechanism and the signup locale is not passed.
// Because signup happens before a tenant exists, this uses uuid.Nil as the
// tenant ID so the system-level SMTP configuration is used.
func (s *EmailService) SendSignupVerificationEmail(ctx context.Context, email, code, name string) error {
	displayName := name
	if displayName == "" {
		displayName = emailDefaultDisplayName
	}

	// The subject deliberately omits the code: subjects land in lock-screen
	// previews, mail logs and relay traces.
	subject := "Your AcmeApp verification code"

	body := fmt.Sprintf(`
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Your verification code</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif; background-color: #f4f4f5; margin: 0; padding: 20px; }
        .container { max-width: 600px; margin: 0 auto; background: white; border-radius: 8px; overflow: hidden; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .header { background: linear-gradient(135deg, #4F46E5, #6366f1); padding: 30px; text-align: center; }
        .header h1 { color: white; margin: 0; font-size: 24px; }
        .content { padding: 30px; }
        .code-box { background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 8px; padding: 20px; text-align: center; margin: 20px 0; }
        .code { font-family: 'SFMono-Regular', Menlo, Consolas, monospace; font-size: 36px; font-weight: bold; letter-spacing: 6px; color: #4F46E5; margin: 0; }
        .footer { padding: 20px 30px; background: #f8fafc; color: #64748b; font-size: 12px; text-align: center; }
        p { color: #475569; line-height: 1.6; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>AcmeApp</h1>
        </div>
        <div class="content">
            <p>Hello %s,</p>
            <p>Thank you for signing up for AcmeApp. Enter this code to verify your email address:</p>
            <div class="code-box">
                <p class="code">%s</p>
            </div>
            <p>This code expires in 15 minutes. Never share it with anyone. If you did not request it, you can safely ignore this email.</p>
        </div>
        <div class="footer">
            <p>AcmeApp</p>
            <p>This is an automated message - please do not reply.</p>
        </div>
    </div>
</body>
</html>
`, template.HTMLEscapeString(displayName), template.HTMLEscapeString(formatSignupCode(code)))

	// Signup happens before a tenant is known — use uuid.Nil to fall back to
	// the system-level SMTP configuration.
	return s.sendEmail(ctx, uuid.Nil, metrics.EmailTemplateSignupVerification, email, subject, body, "")
}

// sendEmail is the internal method to send emails using per-tenant SMTP config.
//
// `template` is a bounded metrics label from internal/metrics (never a
// subject line or address — those are unbounded and would explode
// cardinality).
//
// FAIL-CLOSED (changed 2026-08-02). This used to `return nil` when SMTP
// was unconfigured, logging a warning and reporting success to the
// caller. On an authentication path that is the worst possible
// behaviour: a login MFA code that was never sent looked, to every
// caller and every dashboard, exactly like one that was delivered. That
// silence is a large part of why the 2026-08-02 OTP delay went
// unnoticed for two days.
//
// Unconfigured SMTP is now an error in production and staging. In
// development it stays non-fatal — otherwise every local signup breaks —
// but it is logged at ERROR and counted, so it can never again pass as
// success.
// alignSenderToLink, when non-empty, is the exact accept/setup link URL
// rendered in htmlBody for a branded invitation template — see
// invitationSenderFor. Every other template passes "" and keeps the
// tenant's normal resolved sender untouched.
func (s *EmailService) sendEmail(ctx context.Context, tenantID uuid.UUID, template, to, subject, htmlBody, alignSenderToLink string) error {
	start := time.Now()
	observe := func(outcome string) {
		metrics.EmailSendDuration.WithLabelValues(template, outcome).Observe(time.Since(start).Seconds())
		metrics.EmailSendTotal.WithLabelValues(template, outcome).Inc()
	}


	dialer, from, fromName, err := s.getOrCreateDialer(ctx, tenantID)
	if err != nil {
		logger.Error("Failed to resolve SMTP config for tenant",
			zap.String("tenant_id", tenantID.String()),
			zap.String("template", template),
			zap.Error(err),
		)
		observe(metrics.EmailOutcomeFailed)
		metrics.EmailSendFailures.WithLabelValues(template, metrics.EmailReasonConfigResolve).Inc()
		return fmt.Errorf("failed to resolve SMTP config: %w", err)
	}

	if dialer == nil || from == "" {
		observe(metrics.EmailOutcomeUnconfigured)
		metrics.EmailSendFailures.WithLabelValues(template, metrics.EmailReasonSMTPUnconfigured).Inc()

		logger.Error("SMTP not configured — email NOT sent",
			zap.String("to", to),
			zap.String("subject", subject),
			zap.String("template", template),
			zap.String("tenant_id", tenantID.String()),
			zap.String("environment", s.config.Environment),
		)

		// Production and staging must never silently swallow this.
		if s.config.Environment == "production" || s.config.Environment == "staging" {
			return fmt.Errorf("smtp not configured for tenant %s: cannot send %s", tenantID, template)
		}
		return nil
	}

	// Align the sender to the invitation's own accept/setup link — but ONLY
	// when `from` is still the system default (config.SMTPFrom). A tenant
	// that configured its own SMTP sender has a legitimate reason for that
	// address, and overriding it here would ship mail under a domain the
	// tenant never chose and may have no authentication set up for.
	if alignSenderToLink != "" && from == s.config.SMTPFrom {
		from, fromName = invitationSenderFor(alignSenderToLink)
	}

	m := gomail.NewMessage()

	// Set required headers to avoid spam filters. fromName is already
	// defaulted (see resolveSenderDisplayName) so a tenant with no
	// smtp_from_name override keeps today's behaviour verbatim.
	// SetAddressHeader RFC 2047-encodes fromName internally (mime.QEncoding
	// via gomail's FormatAddress) when it contains non-ASCII — e.g. a
	// tenant named "Doğukan Turhal" or "Hexxlock Teknoloji" — so no manual
	// encoding is needed or wanted here.
	m.SetAddressHeader("From", from, fromName)
	m.SetHeader("To", to)
	m.SetHeader("Subject", subject)

	// Generate proper Message-ID to avoid spam score penalty. The RHS must
	// match the From domain (rspamd scores MID_RHS_MATCH_FROM as a
	// legitimacy signal, and its absence is one more small mismatch a
	// filter can add up) — a literal "@example.com" here would silently
	// reintroduce that mismatch for mail now sent as example.com (see
	// alignSenderToLink above).
	messageIDDomain := "example.com"
	if idx := strings.LastIndex(from, "@"); idx != -1 && idx+1 < len(from) {
		messageIDDomain = from[idx+1:]
	}
	messageID := fmt.Sprintf("<%d.%s@%s>", time.Now().UnixNano(), generateRandomString(16), messageIDDomain)
	m.SetHeader("Message-ID", messageID)

	// Set other headers that help with spam filtering
	m.SetHeader("X-Mailer", "HexxLock IAM Service")
	m.SetHeader("X-Priority", "3")
	m.SetHeader("Precedence", "bulk")

	m.SetBody("text/html", htmlBody)

	// Also set plain text version
	plainText := s.htmlToPlainText(htmlBody)
	m.AddAlternative("text/plain", plainText)

	if err := dialer.DialAndSend(m); err != nil {
		logger.Error("Failed to send email",
			zap.String("to", to),
			zap.String("subject", subject),
			zap.String("template", template),
			zap.String("tenant_id", tenantID.String()),
			zap.Duration("elapsed", time.Since(start)),
			zap.Error(err),
		)
		observe(metrics.EmailOutcomeFailed)
		metrics.EmailSendFailures.WithLabelValues(template, metrics.EmailReasonSMTPDial).Inc()
		return fmt.Errorf("failed to send email: %w", err)
	}

	// `elapsed` is the field that makes a relay-side stall legible in
	// logs as well as metrics — a healthy handoff is sub-second.
	logger.Info("Email sent successfully",
		zap.String("to", to),
		zap.String("subject", subject),
		zap.String("template", template),
		zap.String("tenant_id", tenantID.String()),
		zap.Duration("elapsed", time.Since(start)),
	)
	observe(metrics.EmailOutcomeSent)

	return nil
}

// SendTestEmail sends a simple test email to verify SMTP connectivity.
func (s *EmailService) SendTestEmail(ctx context.Context, tenantID uuid.UUID, to string) error {
	subject := "SMTP Test - HexxLock Platform"
	body := `<!DOCTYPE html>
<html><head><meta charset="UTF-8"></head>
<body style="font-family:sans-serif;padding:20px;">
<h2>SMTP Configuration Test</h2>
<p>This is a test email from your HexxLock platform to verify SMTP connectivity.</p>
<p>If you received this message, your email settings are correctly configured.</p>
<p style="color:#64748b;font-size:12px;">Sent at: ` + time.Now().UTC().Format(time.RFC3339) + `</p>
</body></html>`
	return s.sendEmail(ctx, tenantID, metrics.EmailTemplateSMTPTest, to, subject, body, "")
}

// htmlToPlainText converts HTML to plain text (basic implementation)
func (s *EmailService) htmlToPlainText(html string) string {
	// Remove style tags and their content
	for {
		start := strings.Index(html, "<style")
		if start == -1 {
			break
		}
		end := strings.Index(html[start:], "</style>")
		if end == -1 {
			break
		}
		html = html[:start] + html[start+end+8:]
	}

	// Remove HTML tags
	var result strings.Builder
	inTag := false
	for _, r := range html {
		if r == '<' {
			inTag = true
			continue
		}
		if r == '>' {
			inTag = false
			result.WriteRune(' ')
			continue
		}
		if !inTag {
			result.WriteRune(r)
		}
	}

	// Clean up whitespace
	text := result.String()
	lines := strings.Split(text, "\n")
	var cleanLines []string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" {
			cleanLines = append(cleanLines, line)
		}
	}

	return strings.Join(cleanLines, "\n")
}

// IsConfigured returns true if SMTP is configured (static fallback check).
func (s *EmailService) IsConfigured() bool {
	// If ConfigProvider is available, we consider it "configured" since
	// per-tenant config may exist in the database even when static config is empty.
	if s.configProvider != nil {
		return true
	}
	return s.config.SMTPHost != "" && s.dialer != nil
}
