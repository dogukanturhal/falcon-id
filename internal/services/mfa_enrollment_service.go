// SPDX-License-Identifier: AGPL-3.0-or-later

package services

// mfa_enrollment_service.go implements the registration-interrupt enrollment
// flow used when risk-based MFA fires for a user without an enrolled
// authenticator. Mirrors Microsoft Entra ID Protection registration interrupt,
// Okta enrollment policies, Auth0 Require MFA Enrollment Action, and Keycloak
// Required Actions (CONFIGURE_TOTP). NIST SP 800-63B-4 §5.1 requires
// authenticators to be bound before AAL2 use, so we never email a code to an
// unenrolled mailbox during the original Login flow — instead we issue an
// ephemeral, ip+ua-bound enrollment_token that gates a separate enrollment UI.
//
// Tier-1 properties:
//   - Token is opaque + Redis-backed (one-time-use on verify; init may be
//     re-called within TTL so the user can switch TOTP↔email).
//   - Bound to user_id + tenant_id + ip + sha256(ua) + client_id; rebind
//     mismatches fail closed and emit auth.mfa.enrollment_token_misuse.
//   - 10-minute TTL (matches Entra reg-interrupt + the §1.5 lockout cliff
//     window — long enough for a real user to complete TOTP setup, short
//     enough that a leaked token can't survive a coffee break).
//   - Never accepted by /oauth/authorize, /oauth/token, or any resource
//     endpoint — the only acceptors are the two enrollment routes.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/pkg/logger"
	"github.com/dogukanturhal/falcon-id/pkg/redis"
)

const (
	// mfaEnrollmentTokenTTL bounds how long a registration-interrupt
	// enrollment_token is valid. 10 minutes matches Entra ID Protection
	// registration-interrupt windows and gives a real user time to install
	// an authenticator app + scan a QR code, while keeping a leaked token's
	// blast radius small.
	mfaEnrollmentTokenTTL = 10 * time.Minute
	// mfaEnrollmentRedisKeyPrefix namespaces the enrollment-session Redis
	// keys away from /api/v1/auth/mfa/complete's mfa:session: keys so a
	// confused-deputy bug can't cross-redeem one for the other.
	mfaEnrollmentRedisKeyPrefix = "iam:mfa_enroll:setup:"
)

// mfaEnrollmentSessionCache is the narrow Redis-cache surface the enrollment
// service depends on — Get/Set/Del. Signatures match *redis.Client exactly so
// callers can pass redis.SessionCache.Client() without any adapter, and tests
// can substitute a miniredis-backed fake.
type mfaEnrollmentSessionCache interface {
	Get(ctx context.Context, key string) (string, error)
	Set(ctx context.Context, key string, value interface{}, expiration time.Duration) error
	Del(ctx context.Context, keys ...string) error
}

// mfaEnrollmentMFAService is the narrow MFAService surface the enrollment
// service needs — TOTP bootstrap + email-code lifecycle + backup-code
// generation + post-enrollment notification. Methods come straight from
// the existing MFAService; we just declare the dependency narrow so unit
// tests don't have to construct a full MFAService.
type mfaEnrollmentMFAService interface {
	GenerateTOTPSecret(ctx context.Context, userID uuid.UUID) (*TOTPSetupResponse, error)
	VerifyAndEnableTOTP(ctx context.Context, userID uuid.UUID, code string) ([]string, error)
	SendEmailMFACode(ctx context.Context, userID uuid.UUID) error
	VerifyEmailMFACode(ctx context.Context, userID uuid.UUID, code string) (bool, error)
	GenerateBackupCodes(ctx context.Context, userID uuid.UUID) ([]string, error)
	// SendMFAEnabledNotification fires the "MFA was just enabled on your
	// account" email — security best practice + OWASP MFA Cheat Sheet
	// 2025 recommendation. Lets the user spot account compromise via a
	// "did you do this?" review path. Best-effort: a failed notification
	// must not roll back the enrollment (the user has already proven
	// factor control by completing verify). Method implemented on
	// MFAService — passes through to EmailService.SendMFAEnabled when
	// the email service is configured.
	SendMFAEnabledNotification(ctx context.Context, userID uuid.UUID, method string) error
}

// mfaEnrollmentUserRepository is the narrow user-repo surface — Get +
// Update + ResetMFAEnrollmentGraceTracking. The reset is invoked after
// VerifyTOTP / VerifyEmail succeed so the user's skip_count zeroes out
// for any future re-enrollment cycle (e.g. realm flips MFA off then
// back on later).
type mfaEnrollmentUserRepository interface {
	GetByID(ctx context.Context, id uuid.UUID) (*models.User, error)
	Update(ctx context.Context, user *models.User) error
	ResetMFAEnrollmentGraceTracking(ctx context.Context, userID uuid.UUID) error
}

// mfaEnrollmentWebAuthnService is the narrow WebAuthnService surface needed
// by the registration-interrupt enrollment flow. Defined as an interface so
// the dependency stays optional — when the WebAuthn service isn't wired,
// the InitWebAuthn / VerifyWebAuthn paths fail closed (HTTP 503 from the
// caller) without breaking TOTP / email enrollment.
type mfaEnrollmentWebAuthnService interface {
	BeginRegistration(ctx context.Context, subject *WebAuthnSubject, friendlyName string) (*RegistrationChallenge, error)
	FinishRegistration(ctx context.Context, subject *WebAuthnSubject, sessionID, friendlyName string, policy models.AttestationPolicy, r *http.Request) (*models.WebAuthnCredential, error)
}

// userToWebAuthnSubject is the in-package converter used when a service
// already holds a *models.User loaded from DB (e.g. MFA enrollment) and
// needs to call the WebAuthn service which accepts the narrow type. The
// explicit conversion at the call boundary keeps the type-narrowing
// contract uniform across paths.
func userToWebAuthnSubject(u *models.User) *WebAuthnSubject {
	if u == nil {
		return nil
	}
	return &WebAuthnSubject{
		ID:       u.ID,
		TenantID: u.TenantID,
		Username: u.Username,
		Email:    u.Email,
	}
}

// MFAEnrollmentService owns the registration-interrupt enrollment lifecycle.
// Stateless aside from its dependencies; all session state lives in Redis.
type MFAEnrollmentService struct {
	cache        mfaEnrollmentSessionCache
	mfa          mfaEnrollmentMFAService
	userRepo     mfaEnrollmentUserRepository
	auditService *AuditService
	webauthn     mfaEnrollmentWebAuthnService // optional — set via SetWebAuthn
}

// NewMFAEnrollmentService is an exported function.
func NewMFAEnrollmentService(
	cache mfaEnrollmentSessionCache,
	mfa mfaEnrollmentMFAService,
	userRepo mfaEnrollmentUserRepository,
	auditService *AuditService,
) *MFAEnrollmentService {
	return &MFAEnrollmentService{
		cache:        cache,
		mfa:          mfa,
		userRepo:     userRepo,
		auditService: auditService,
	}
}

// hashUserAgent returns sha256(ua) hex. Stable, fixed-width, and avoids
// storing the raw UA string on the Redis blob.
func hashUserAgent(ua string) string {
	sum := sha256.Sum256([]byte(ua))
	return hex.EncodeToString(sum[:])
}

func enrollmentRedisKey(token string) string {
	return mfaEnrollmentRedisKeyPrefix + token
}

// CreateSession provisions a fresh enrollment session bound to the originating
// IP + UA hash + client_id, returns the opaque token to surface in the
// LoginResponse, and persists the binding under iam:mfa_enroll:setup:<token>
// with a 10-minute TTL.
//
// Risk score + level are captured from the caller's assessment so the
// downstream verify-side audit log can correlate back to the original signals
// without hitting the scorer again.
func (s *MFAEnrollmentService) CreateSession(
	ctx context.Context,
	userID, tenantID uuid.UUID,
	tenantSlug, ipAddress, userAgent, clientID string,
	riskScore int,
	riskLevel string,
) (token string, expiresIn int64, err error) {
	if s.cache == nil {
		return "", 0, fmt.Errorf("mfa enrollment cache not configured")
	}

	token = uuid.New().String()
	sess := &models.MFAEnrollmentSession{
		UserID:        userID.String(),
		TenantID:      tenantID.String(),
		TenantSlug:    tenantSlug,
		IPAddress:     ipAddress,
		UserAgentHash: hashUserAgent(userAgent),
		ClientID:      clientID,
		RiskScore:     riskScore,
		RiskLevel:     riskLevel,
		CreatedAt:     time.Now().Unix(),
	}

	payload, err := json.Marshal(sess)
	if err != nil {
		return "", 0, fmt.Errorf("marshal enrollment session: %w", err)
	}

	if err := s.cache.Set(ctx, enrollmentRedisKey(token), string(payload), mfaEnrollmentTokenTTL); err != nil {
		return "", 0, fmt.Errorf("persist enrollment session: %w", err)
	}

	return token, int64(mfaEnrollmentTokenTTL.Seconds()), nil
}

// LookupSession fetches an enrollment session from Redis without deleting it.
// Validates the token format + ip/ua rebind. Used by both Init (re-callable
// within TTL) and Verify (which then calls DeleteSession on success).
//
// Rebind mismatches fail closed and emit auth.mfa.enrollment_token_misuse to
// the security audit channel — operators can use this to detect token-theft
// attempts before they cause real harm. We deliberately do NOT delete the
// session on a rebind miss so the legitimate user can still complete from
// their original device.
func (s *MFAEnrollmentService) LookupSession(
	ctx context.Context,
	token, ipAddress, userAgent string,
) (*models.MFAEnrollmentSession, error) {
	if s.cache == nil {
		return nil, fmt.Errorf("mfa enrollment cache not configured")
	}
	if _, err := uuid.Parse(token); err != nil {
		return nil, fmt.Errorf("invalid enrollment token")
	}

	payload, err := s.cache.Get(ctx, enrollmentRedisKey(token))
	if err != nil || payload == "" {
		return nil, fmt.Errorf("enrollment token expired or invalid")
	}

	var sess models.MFAEnrollmentSession
	if jerr := json.Unmarshal([]byte(payload), &sess); jerr != nil {
		return nil, fmt.Errorf("invalid enrollment session payload")
	}

	uaHash := hashUserAgent(userAgent)
	if sess.IPAddress != ipAddress || sess.UserAgentHash != uaHash {
		logger.SecurityAudit.Warn("Security audit: MFA enrollment token rebind mismatch",
			zap.String("event", "auth.mfa.enrollment_token_misuse"),
			zap.String("user_id", sess.UserID),
			zap.String("expected_ip", sess.IPAddress),
			zap.String("seen_ip", ipAddress),
			zap.String("client_id", sess.ClientID),
			zap.Time("timestamp", time.Now().UTC()),
		)
		return nil, fmt.Errorf("enrollment token expired or invalid")
	}

	return &sess, nil
}

// DeleteSession removes the enrollment session — called from VerifyTOTP /
// VerifyEmail after a successful binding so the token cannot be replayed.
func (s *MFAEnrollmentService) DeleteSession(ctx context.Context, token string) {
	if s.cache == nil {
		return
	}
	if err := s.cache.Del(ctx, enrollmentRedisKey(token)); err != nil {
		logger.Warn("Failed to delete MFA enrollment session",
			zap.String("token", token),
			zap.Error(err),
		)
	}
}

// InitTOTP returns the TOTP bootstrap material (secret + QR + manual entry)
// for an enrollment session. Wraps MFAService.GenerateTOTPSecret which
// internally stashes the pending setup keyed on user_id; that pending row is
// what VerifyTOTP will compare against.
func (s *MFAEnrollmentService) InitTOTP(
	ctx context.Context,
	sess *models.MFAEnrollmentSession,
) (*TOTPSetupResponse, error) {
	userID, err := uuid.Parse(sess.UserID)
	if err != nil {
		return nil, fmt.Errorf("invalid enrollment session")
	}
	resp, err := s.mfa.GenerateTOTPSecret(ctx, userID)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

// InitEmail kicks off email enrollment by delivering a one-time code to the
// user's on-file mailbox. The actual code-storage TTL is owned by
// MFAService.SendEmailMFACode (config.MFAEmailCodeTTL). We do NOT mark the
// email verified here — only on successful VerifyEmail, when receipt of the
// code proves mailbox control.
func (s *MFAEnrollmentService) InitEmail(
	ctx context.Context,
	sess *models.MFAEnrollmentSession,
) error {
	userID, err := uuid.Parse(sess.UserID)
	if err != nil {
		return fmt.Errorf("invalid enrollment session")
	}
	return s.mfa.SendEmailMFACode(ctx, userID)
}

// VerifyTOTP validates the user-entered TOTP code against the pending setup
// secret, flips the user's MFA flags via MFAService.VerifyAndEnableTOTP, and
// returns the freshly-generated backup codes. On success the enrollment
// session is deleted (one-time-use). On failure the session is preserved so
// the user can retry without restarting the login flow.
func (s *MFAEnrollmentService) VerifyTOTP(
	ctx context.Context,
	sess *models.MFAEnrollmentSession,
	token, code string,
) ([]string, error) {
	userID, err := uuid.Parse(sess.UserID)
	if err != nil {
		return nil, fmt.Errorf("invalid enrollment session")
	}
	backup, err := s.mfa.VerifyAndEnableTOTP(ctx, userID, code)
	if err != nil {
		return nil, err
	}

	// Reset grace tracking — skip_count zeroes so a future
	// re-enrollment cycle starts fresh. First-prompted-at + deadline
	// remain queryable as "how long did this user take to enrol" for
	// SIEM / compliance.
	if resetErr := s.userRepo.ResetMFAEnrollmentGraceTracking(ctx, userID); resetErr != nil {
		logger.Warn("MFA enrollment: failed to reset grace tracking post-TOTP — non-fatal",
			zap.String("user_id", sess.UserID),
			zap.Error(resetErr),
		)
	}

	s.DeleteSession(ctx, token)
	logger.SecurityAudit.Info("Security audit: MFA enrollment completed",
		zap.String("event", "auth.mfa.enrollment_completed"),
		zap.String("user_id", sess.UserID),
		zap.String("method", authMethodTOTP),
		zap.Int("risk_score", sess.RiskScore),
		zap.String("risk_level", sess.RiskLevel),
		zap.String("client_id", sess.ClientID),
		zap.String("ip", sess.IPAddress),
		zap.Time("timestamp", time.Now().UTC()),
	)
	return backup, nil
}

// VerifyEmail validates the user-entered email code, flips the user's
// mfa_enabled / mfa_email_enabled / is_email_verified flags (the receipt of
// the code is itself proof of mailbox control — same model as Entra/Okta/
// Auth0 email-MFA enrollment), generates backup codes if none exist, and
// returns the codes for one-time display.
func (s *MFAEnrollmentService) VerifyEmail(
	ctx context.Context,
	sess *models.MFAEnrollmentSession,
	token, code string,
) ([]string, error) {
	userID, err := uuid.Parse(sess.UserID)
	if err != nil {
		return nil, fmt.Errorf("invalid enrollment session")
	}

	valid, err := s.mfa.VerifyEmailMFACode(ctx, userID, code)
	if err != nil {
		return nil, fmt.Errorf("verify email code: %w", err)
	}
	if !valid {
		return nil, fmt.Errorf("invalid verification code")
	}

	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("get user: %w", err)
	}
	if user == nil {
		return nil, fmt.Errorf("user not found")
	}

	user.MFAEnabled = true
	user.MFAEmailEnabled = true
	user.IsEmailVerified = true
	emailMethod := authMethodEmail
	user.MFAType = &emailMethod
	if user.MFAPreferredMethod == nil {
		user.MFAPreferredMethod = &emailMethod
	}

	if err := s.userRepo.Update(ctx, user); err != nil {
		return nil, fmt.Errorf("persist enrollment: %w", err)
	}

	if resetErr := s.userRepo.ResetMFAEnrollmentGraceTracking(ctx, userID); resetErr != nil {
		logger.Warn("MFA enrollment: failed to reset grace tracking post-email — non-fatal",
			zap.String("user_id", sess.UserID),
			zap.Error(resetErr),
		)
	}

	// Backup codes prevent a future lockout if the user loses email access —
	// generated only when none exist (TOTP enrollment may have already
	// produced a set; we don't churn them on a re-enrol).
	backup, err := s.mfa.GenerateBackupCodes(ctx, userID)
	if err != nil {
		logger.Warn("Failed to generate backup codes after email enrollment",
			zap.String("user_id", sess.UserID),
			zap.Error(err),
		)
	}

	// Best-effort notification email — "MFA was just enabled on your
	// account". A failure here must not roll back the enrollment (the
	// user has already proven factor control by completing verify;
	// rolling back would leave them locked out with no recovery path).
	// Log + ignore.
	if err := s.mfa.SendMFAEnabledNotification(ctx, userID, authMethodEmail); err != nil {
		logger.Warn("Failed to send MFA-enabled notification after email enrollment",
			zap.String("user_id", sess.UserID),
			zap.Error(err),
		)
	}

	s.DeleteSession(ctx, token)
	logger.SecurityAudit.Info("Security audit: MFA enrollment completed",
		zap.String("event", "auth.mfa.enrollment_completed"),
		zap.String("user_id", sess.UserID),
		zap.String("method", authMethodEmail),
		zap.Int("risk_score", sess.RiskScore),
		zap.String("risk_level", sess.RiskLevel),
		zap.String("client_id", sess.ClientID),
		zap.String("ip", sess.IPAddress),
		zap.Time("timestamp", time.Now().UTC()),
	)
	return backup, nil
}

// SetWebAuthn wires the WebAuthn service into the enrollment flow so
// admin-required-passkey interrupts (require_passkey_for_admin tenant
// flag) can drive the user through a FIDO2 registration ceremony from the
// existing /api/v1/auth/mfa/enrollment surface — no separate authenticated
// session is needed because the enrollment_token is itself an ip+ua-bound
// gate.
func (s *MFAEnrollmentService) SetWebAuthn(svc mfaEnrollmentWebAuthnService) {
	s.webauthn = svc
}

// InitWebAuthn returns the W3C-shaped CredentialCreation challenge for an
// enrollment session whose user lacks a registered passkey. The returned
// RegistrationChallenge is JSON-shaped exactly like the post-login
// /webauthn/register/begin response, so the same frontend code path can
// consume it. The wa_session_id inside the challenge is what the verify
// step matches against (see VerifyWebAuthn).
func (s *MFAEnrollmentService) InitWebAuthn(
	ctx context.Context,
	sess *models.MFAEnrollmentSession,
	friendlyName string,
) (*RegistrationChallenge, error) {
	if s.webauthn == nil {
		return nil, fmt.Errorf("webauthn enrollment unavailable: service not wired")
	}
	user, err := s.loadEnrollmentUser(ctx, sess)
	if err != nil {
		return nil, err
	}
	return s.webauthn.BeginRegistration(ctx, userToWebAuthnSubject(user), friendlyName)
}

// VerifyWebAuthn completes a passkey registration ceremony from an
// enrollment session. On success the credential is persisted, the
// enrollment session is deleted (one-time-use), and the function returns
// the AMR snapshot the caller should record on the issued login session
// (always ["hwk","user"] for WebAuthn UV-required ceremonies).
//
// Unlike VerifyTOTP / VerifyEmail this method does NOT return backup codes
// — the FIDO2 specification doesn't have an analogue. Users who want a
// recovery method should additionally enrol TOTP or email-OTP. Tenant-
// level policy may require this; that's a separate enforcement concern
// out of scope for this method.
func (s *MFAEnrollmentService) VerifyWebAuthn(
	ctx context.Context,
	sess *models.MFAEnrollmentSession,
	enrollmentToken, waSessionID, friendlyName string,
	policy models.AttestationPolicy,
	r *http.Request,
) (amr []string, err error) {
	if s.webauthn == nil {
		return nil, fmt.Errorf("webauthn enrollment unavailable: service not wired")
	}
	user, err := s.loadEnrollmentUser(ctx, sess)
	if err != nil {
		return nil, err
	}
	if _, err := s.webauthn.FinishRegistration(ctx, userToWebAuthnSubject(user), waSessionID, friendlyName, policy, r); err != nil {
		return nil, err
	}
	s.DeleteSession(ctx, enrollmentToken)
	logger.SecurityAudit.Info("Security audit: WebAuthn enrollment completed",
		zap.String("event", "auth.mfa.enrollment_completed"),
		zap.String("user_id", sess.UserID),
		zap.String("method", "webauthn"),
		zap.Int("risk_score", sess.RiskScore),
		zap.String("risk_level", sess.RiskLevel),
		zap.String("client_id", sess.ClientID),
		zap.String("ip", sess.IPAddress),
		zap.Time("timestamp", time.Now().UTC()),
	)
	return []string{AMRValueHardwareKey, AMRValueUserVerification}, nil
}

// loadEnrollmentUser resolves the user record referenced by an enrollment
// session, returning a user-facing error rather than the raw DB error so
// the response surface stays uniform with the TOTP / email paths.
func (s *MFAEnrollmentService) loadEnrollmentUser(ctx context.Context, sess *models.MFAEnrollmentSession) (*models.User, error) {
	userID, err := uuid.Parse(sess.UserID)
	if err != nil {
		return nil, fmt.Errorf("invalid enrollment session")
	}
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil || user == nil {
		return nil, fmt.Errorf("user not found")
	}
	return user, nil
}

// Compile-time assertion that *redis.Client satisfies the cache surface the
// enrollment service depends on. Keeps the dep narrow + tests free of any
// real Redis at the type level.
var _ mfaEnrollmentSessionCache = (*redis.Client)(nil)
