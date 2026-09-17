// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"image/png"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/internal/repositories"
	"github.com/dogukanturhal/falcon-id/pkg/config"
	"github.com/dogukanturhal/falcon-id/pkg/logger"
)

// mfaUserRepository defines the user repository methods needed by MFAService.
type mfaUserRepository interface {
	GetByID(ctx context.Context, id uuid.UUID) (*models.User, error)
	Update(ctx context.Context, user *models.User) error
	HasNonPrimaryMFAFactor(ctx context.Context, userID uuid.UUID) (bool, error)
}

// mfaMFARepository defines the MFA repository methods needed by MFAService.
type mfaMFARepository interface {
	CreateMFAPendingSetup(ctx context.Context, userID uuid.UUID, secret, methodType string, expiresAt time.Time) (*repositories.MFAPendingSetup, error)
	GetMFAPendingSetup(ctx context.Context, userID uuid.UUID) (*repositories.MFAPendingSetup, error)
	DeleteMFAPendingSetup(ctx context.Context, userID uuid.UUID) error
	CreateMFAEmailCode(ctx context.Context, userID uuid.UUID, codeHash string, expiresAt time.Time) (*repositories.MFAEmailCode, error)
	GetActiveMFAEmailCode(ctx context.Context, userID uuid.UUID) (*repositories.MFAEmailCode, error)
	MarkMFAEmailCodeUsed(ctx context.Context, codeID uuid.UUID) error
	CreateRecoveryCodes(ctx context.Context, userID uuid.UUID, codeHashes []string) error
	GetUnusedRecoveryCodes(ctx context.Context, userID uuid.UUID) ([]repositories.RecoveryCode, error)
	GetUnusedRecoveryCodesCount(ctx context.Context, userID uuid.UUID) (int, error)
	UseRecoveryCode(ctx context.Context, codeID uuid.UUID) error
	DeleteAllRecoveryCodes(ctx context.Context, userID uuid.UUID) error
	CreateEmailVerification(ctx context.Context, userID uuid.UUID, email, token string, expiresAt time.Time) (*repositories.EmailVerification, error)
	GetEmailVerification(ctx context.Context, userID uuid.UUID, token string) (*repositories.EmailVerification, error)
	GetEmailVerificationByToken(ctx context.Context, token string) (*repositories.EmailVerification, error)
	MarkEmailVerified(ctx context.Context, verificationID uuid.UUID) error
	GetPendingEmailVerification(ctx context.Context, userID uuid.UUID) (*repositories.EmailVerification, error)
}

// mfaEmailService defines the email service methods needed by MFAService.
type mfaEmailService interface {
	IsConfigured() bool
	SendMFACode(tenantID uuid.UUID, email, code, username string) error
	SendMFAEnabled(tenantID uuid.UUID, email, username, method string) error
	SendVerificationEmailLink(tenantID uuid.UUID, email, link, username string) error
}

// mfaLDAPService defines the LDAP service methods needed by MFAService.
type mfaLDAPService interface {
	GetActiveLDAPProviders(ctx context.Context, tenantID uuid.UUID) ([]*models.IdentityProvider, error)
	Authenticate(ctx context.Context, tenantID, providerID uuid.UUID, username, password string) (*models.User, error)
}

// MFAService is an exported type.
type MFAService struct {
	config       *config.Config
	userRepo     mfaUserRepository
	mfaRepo      mfaMFARepository
	emailService mfaEmailService
	ldapService  mfaLDAPService

	// caeService is optional. When set, DisableMFA and AdminDisableMFA
	// publish CAEMFARevoked so receivers re-evaluate sessions whose
	// authentication context references the now-removed factor (e.g.
	// step-up gates that were satisfied via this factor lose their
	// "recent verification"). Wired in cmd/services.go; nil-safe.
	caeService *CAEService

	// securityNotifier sends user-facing emails on MFA factor
	// mutations (factor removed). Nil-safe — when unset, the email
	// step is skipped but DB writes + CAE event remain authoritative.
	// Phase C, 2026-05-26.
	securityNotifier *SecurityNotificationService
}

// SetCAEService wires the CAEP publisher into MFAService. Safe to
// call with nil; the underlying DB writes (factor removal, audit row)
// remain authoritative.
func (s *MFAService) SetCAEService(svc *CAEService) {
	s.caeService = svc
}

// SetSecurityNotificationService wires the user-facing email notifier
// (Phase C). Nil-safe; DB writes + CAE remain authoritative.
func (s *MFAService) SetSecurityNotificationService(svc *SecurityNotificationService) {
	s.securityNotifier = svc
}

// NewMFAService is an exported function.
func NewMFAService(
	cfg *config.Config,
	userRepo mfaUserRepository,
	mfaRepo mfaMFARepository,
	emailService mfaEmailService,
	ldapService mfaLDAPService,
) *MFAService {
	return &MFAService{
		config:       cfg,
		userRepo:     userRepo,
		mfaRepo:      mfaRepo,
		emailService: emailService,
		ldapService:  ldapService,
	}
}

// TOTPSetupResponse is an exported identifier.
// TOTP is an exported identifier.
// TOTP is an exported identifier.
// TOTP Setup Response
type TOTPSetupResponse struct {
	Secret      string `json:"secret"`
	QRCode      string `json:"qr_code"` // Base64 encoded PNG
	ManualEntry string `json:"manual_entry"`
}

// ErrEmailNotVerified is returned when an MFA enrollment is attempted on a
// user whose email address has not been verified. Tier-1 invariant: a user
// must own a verified recovery channel before they can lock themselves out
// with a second factor — otherwise losing the authenticator is a permanent
// account loss because the email-OTP recovery path can't be trusted.
//
// The handler maps this to HTTP 422 (Unprocessable Entity) with a stable
// error code so the frontend can show a "Verify your email first" inline
// prompt without parsing free-text messages.
var ErrEmailNotVerified = fmt.Errorf("email_not_verified")

// GenerateTOTPSecret creates a new TOTP secret for a user
func (s *MFAService) GenerateTOTPSecret(ctx context.Context, userID uuid.UUID) (*TOTPSetupResponse, error) {
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}
	if user == nil {
		return nil, fmt.Errorf("user not found")
	}

	// Tier-1 MFA/email coupling rule: cannot enroll a second factor without
	// a verified recovery channel. Federated accounts (SSO / SAML) are
	// trusted to have email-verified upstream — skip the check so AD/Okta
	// users aren't blocked. Local-credential users (FederationType == "")
	// must complete email verification first.
	if (user.FederationType == nil || *user.FederationType == "") && !user.IsEmailVerified {
		return nil, ErrEmailNotVerified
	}

	// Generate TOTP key
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      s.config.MFAIssuer,
		AccountName: user.Username,
		Period:      uint(s.config.MFATOTPPeriod), //nolint:gosec // value is bounded by TOTP period config, safe conversion
		Digits:      otp.Digits(s.config.MFATOTPDigits),
		Algorithm:   otp.AlgorithmSHA1,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to generate TOTP key: %w", err)
	}

	// Generate QR code
	var buf bytes.Buffer
	img, err := key.Image(200, 200)
	if err != nil {
		return nil, fmt.Errorf("failed to generate QR code: %w", err)
	}
	if err := png.Encode(&buf, img); err != nil {
		return nil, fmt.Errorf("failed to encode QR code: %w", err)
	}
	qrCodeBase64 := base64.StdEncoding.EncodeToString(buf.Bytes())

	// Store pending setup (expires in 10 minutes)
	expiresAt := time.Now().Add(10 * time.Minute)
	_, err = s.mfaRepo.CreateMFAPendingSetup(ctx, userID, key.Secret(), authMethodTOTP, expiresAt)
	if err != nil {
		return nil, fmt.Errorf("failed to store pending setup: %w", err)
	}

	logger.Info("TOTP secret generated for user",
		zap.String("user_id", userID.String()),
		zap.String("username", user.Username),
	)

	return &TOTPSetupResponse{
		Secret:      key.Secret(),
		QRCode:      qrCodeBase64,
		ManualEntry: fmt.Sprintf("%s (%s)", key.Secret(), s.config.MFAIssuer),
	}, nil
}

// EnsureBackupCodesGenerated generates backup codes ONLY when the
// user has none. Idempotent — safe to call from every factor-
// enrollment completion path (TOTP / Email / WebAuthn / Push) so a
// user who never had any code-based recovery channel gets one
// automatically on first factor activation.
//
// Returns (codes, true) when codes were freshly generated — the
// caller MUST surface them to the user immediately (they are hashed
// before storage and cannot be retrieved again). Returns (nil, false)
// when codes already exist; no rotation, no surface. Errors are
// non-fatal at the call site (factor enrollment must not fail just
// because backup-code generation hit a transient DB issue) — the
// caller logs + degrades.
//
// Why first-enrollment auto-gen is enterprise-canonical: per NIST SP
// 800-63B-4 §5.1.7 and Microsoft Entra / Auth0 / Google reference
// architectures, every MFA-enrolled account needs a recovery factor
// that survives device loss. Platform-bound passkeys + a lone TOTP
// secret can both vanish when a device is lost; backup codes are the
// canonical "out of band" recovery channel. Previously only TOTP
// auto-gen'd them; users who enrolled email-only or passkey-only
// silently had ZERO recovery options. Closed 2026-05-26 (Phase B).
func (s *MFAService) EnsureBackupCodesGenerated(ctx context.Context, userID uuid.UUID) ([]string, bool, error) {
	if s.mfaRepo == nil {
		return nil, false, fmt.Errorf("MFA repository not configured")
	}
	count, err := s.mfaRepo.GetUnusedRecoveryCodesCount(ctx, userID)
	if err != nil {
		return nil, false, fmt.Errorf("EnsureBackupCodesGenerated: count: %w", err)
	}
	if count > 0 {
		return nil, false, nil // already has codes; respect existing set
	}
	codes, err := s.GenerateBackupCodes(ctx, userID)
	if err != nil {
		return nil, false, err
	}
	logger.Info("Backup codes auto-generated on first MFA enrollment",
		zap.String("user_id", userID.String()),
		zap.Int("count", len(codes)),
	)
	return codes, true, nil
}

// VerifyAndEnableTOTP verifies a TOTP code and enables MFA for the user
func (s *MFAService) VerifyAndEnableTOTP(ctx context.Context, userID uuid.UUID, code string) ([]string, error) {
	// Get pending setup
	pendingSetup, err := s.mfaRepo.GetMFAPendingSetup(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get pending setup: %w", err)
	}
	if pendingSetup == nil {
		return nil, fmt.Errorf("no pending MFA setup found - please start setup again")
	}

	// Verify the code
	valid := totp.Validate(code, pendingSetup.Secret)
	if !valid {
		return nil, fmt.Errorf("invalid verification code")
	}

	// Get user
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	// Enable MFA on user
	user.MFAEnabled = true
	user.MFASecret = &pendingSetup.Secret
	mfaType := authMethodTOTP
	user.MFAType = &mfaType
	user.MFATOTPEnabled = true
	// Set as preferred if no preference exists or if this is the only method
	if user.MFAPreferredMethod == nil || !user.MFAEmailEnabled {
		user.MFAPreferredMethod = &mfaType
	}

	if err := s.userRepo.Update(ctx, user); err != nil {
		return nil, fmt.Errorf("failed to enable MFA: %w", err)
	}

	// Auto-generate backup codes ONLY when the user has none yet —
	// preserves any existing recovery set (e.g. user already enrolled
	// email MFA earlier and got codes then). Idempotent across all
	// factor-enrollment paths; see EnsureBackupCodesGenerated doc.
	backupCodes, generated, err := s.EnsureBackupCodesGenerated(ctx, userID)
	if err != nil {
		logger.Error("Failed to ensure backup codes on TOTP enable", zap.Error(err))
		// Don't fail the entire operation — TOTP is enrolled, codes
		// can be regenerated later via POST /mfa/backup-codes.
	}
	_ = generated // surfaced via return value below; logged inside the helper

	// Delete pending setup
	_ = s.mfaRepo.DeleteMFAPendingSetup(ctx, userID)

	// Send notification email
	if s.emailService.IsConfigured() {
		_ = s.emailService.SendMFAEnabled(user.TenantID, user.Email, user.Username, authMethodTOTP)
	}

	logger.Info("TOTP MFA enabled for user",
		zap.String("user_id", userID.String()),
		zap.String("username", user.Username),
	)

	return backupCodes, nil
}

// VerifyTOTPCode verifies a TOTP code for login
func (s *MFAService) VerifyTOTPCode(ctx context.Context, userID uuid.UUID, code string) (bool, error) {
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return false, fmt.Errorf("failed to get user: %w", err)
	}
	if user == nil || !user.MFAEnabled || user.MFASecret == nil {
		return false, fmt.Errorf("MFA not enabled for user")
	}

	valid := totp.Validate(code, *user.MFASecret)
	return valid, nil
}

// SendMFAEnabledNotification fires the "MFA was just enabled on your
// account" email. Used by the registration-interrupt enrollment path
// (MFAEnrollmentService.VerifyEmail) which would otherwise miss the
// notification — the higher-level EnableEmailMFA / VerifyAndEnableTOTP
// paths already wire this for the step-up flow at lines 216 + 345.
//
// Best-effort: returns nil when the email service isn't configured
// (development setups) rather than blocking the enrollment. The
// security audit log captures the enrollment regardless.
func (s *MFAService) SendMFAEnabledNotification(ctx context.Context, userID uuid.UUID, method string) error {
	if s.emailService == nil || !s.emailService.IsConfigured() {
		return nil
	}
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return fmt.Errorf("get user for MFA-enabled notification: %w", err)
	}
	if user == nil {
		return fmt.Errorf("user not found for MFA-enabled notification")
	}
	return s.emailService.SendMFAEnabled(user.TenantID, user.Email, user.Username, method)
}

// Email MFA Methods

// SendEmailMFACode sends a one-time code via email
func (s *MFAService) SendEmailMFACode(ctx context.Context, userID uuid.UUID) error {
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return fmt.Errorf("failed to get user: %w", err)
	}
	if user == nil {
		return fmt.Errorf("user not found")
	}

	// Generate 6-digit code
	code, err := s.generateNumericCode(6)
	if err != nil {
		return fmt.Errorf("failed to generate MFA code: %w", err)
	}

	// Hash the code for storage
	codeHash := s.hashCode(code)

	// Store the code (expires based on config)
	expiresAt := time.Now().Add(s.config.MFAEmailCodeTTL)
	_, err = s.mfaRepo.CreateMFAEmailCode(ctx, userID, codeHash, expiresAt)
	if err != nil {
		return fmt.Errorf("failed to store MFA code: %w", err)
	}

	// Send the code via email
	if err := s.emailService.SendMFACode(user.TenantID, user.Email, code, user.Username); err != nil {
		return fmt.Errorf("failed to send MFA code email: %w", err)
	}

	logger.Info("MFA email code sent",
		zap.String("user_id", userID.String()),
	)

	return nil
}

// VerifyEmailMFACode verifies a code sent via email
func (s *MFAService) VerifyEmailMFACode(ctx context.Context, userID uuid.UUID, code string) (bool, error) {
	emailCode, err := s.mfaRepo.GetActiveMFAEmailCode(ctx, userID)
	if err != nil {
		return false, fmt.Errorf("failed to get MFA code: %w", err)
	}
	if emailCode == nil {
		return false, nil
	}

	// SECURITY: Use constant-time comparison to prevent timing side-channel attacks
	codeHash := s.hashCode(code)
	if subtle.ConstantTimeCompare([]byte(codeHash), []byte(emailCode.CodeHash)) != 1 {
		return false, nil
	}

	// Mark as used
	if err := s.mfaRepo.MarkMFAEmailCodeUsed(ctx, emailCode.ID); err != nil {
		logger.Error("Failed to mark MFA code as used", zap.Error(err))
	}

	return true, nil
}

// EnableEmailMFA enables email-based MFA for a user. Returns any
// freshly-generated backup codes — non-empty ONLY on the user's first
// MFA factor enrollment (idempotent helper). Caller MUST surface
// these to the user since they're hashed at rest and unrecoverable.
func (s *MFAService) EnableEmailMFA(ctx context.Context, userID uuid.UUID) ([]string, error) {
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}
	if user == nil {
		return nil, fmt.Errorf("user not found")
	}

	// Check if email is verified
	if !user.IsEmailVerified {
		return nil, fmt.Errorf("email must be verified before enabling email MFA")
	}

	// Enable MFA
	user.MFAEnabled = true
	mfaType := authMethodEmail
	user.MFAType = &mfaType
	user.MFAEmailEnabled = true
	// Set as preferred if no preference exists or if this is the only method
	if user.MFAPreferredMethod == nil || !user.MFATOTPEnabled {
		user.MFAPreferredMethod = &mfaType
	}

	if err := s.userRepo.Update(ctx, user); err != nil {
		return nil, fmt.Errorf("failed to enable MFA: %w", err)
	}

	// Auto-generate backup codes ONLY when the user has none yet.
	// Idempotent across all factor-enrollment paths.
	backupCodes, _, ensureErr := s.EnsureBackupCodesGenerated(ctx, userID)
	if ensureErr != nil {
		logger.Error("Failed to ensure backup codes on email-MFA enable", zap.Error(ensureErr))
		// Don't fail enrollment — codes can be regenerated later.
	}

	// Send notification
	if s.emailService.IsConfigured() {
		_ = s.emailService.SendMFAEnabled(user.TenantID, user.Email, user.Username, authMethodEmail)
	}

	logger.Info("Email MFA enabled for user",
		zap.String("user_id", userID.String()),
	)

	return backupCodes, nil
}

// DisableMFA disables MFA for a user.
//
// Both password and mfaCode are OPTIONAL — when both are empty, this
// method relies entirely on the RFC 9470 freshAuth middleware that
// gates the /mfa/disable route (see cmd/routes.go) to have proven
// AAL2 within the last 300s. This matches the Auth0 / Okta / Entra
// pattern: step-up alone is the canonical authorization. When either
// is supplied (legacy callers, defense-in-depth) it is still verified
// hard.
//
// Compensating controls outside this method: SSF/CAE event emission,
// 7-year WORM audit log, and email notification on factor removal
// (see publishMFARevoked + the audit middleware).
func (s *MFAService) DisableMFA(ctx context.Context, userID uuid.UUID, password, mfaCode string) error {
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return fmt.Errorf("failed to get user: %w", err)
	}
	if user == nil {
		return fmt.Errorf("user not found")
	}

	if !user.MFAEnabled {
		return fmt.Errorf("MFA is not enabled")
	}

	// Verify password if supplied (defense-in-depth). Empty password is
	// authorized solely by the RFC 9470 freshAuth gate on the route.
	if password != "" {
		if err := s.verifyUserPassword(ctx, user, password); err != nil {
			return err
		}
	}

	// Verify MFA code if supplied (defense-in-depth). Empty code is
	// authorized solely by the RFC 9470 freshAuth gate on the route.
	if mfaCode != "" {
		valid, err := s.VerifyMFACode(ctx, userID, mfaCode)
		if err != nil {
			return fmt.Errorf("failed to verify MFA code: %w", err)
		}
		if !valid {
			return fmt.Errorf("invalid MFA code")
		}
	}

	// Clear primary (TOTP/email) MFA columns. Recompute the consolidated
	// mfa_enabled flag from the residual factor inventory — a user with
	// a WebAuthn passkey or push device still has MFA after this call,
	// so the flag must stay true. Querying the sibling tables BEFORE
	// the Update avoids racing the in-flight write of iam_users.
	hasResidual, err := s.userRepo.HasNonPrimaryMFAFactor(ctx, userID)
	if err != nil {
		return fmt.Errorf("check residual MFA factors: %w", err)
	}
	user.MFASecret = nil
	user.MFAType = nil
	user.MFATOTPEnabled = false
	user.MFAEmailEnabled = false
	user.MFAPreferredMethod = nil
	user.MFAEnabled = hasResidual

	if err := s.userRepo.Update(ctx, user); err != nil {
		return fmt.Errorf("failed to disable MFA: %w", err)
	}

	// Delete all recovery codes
	_ = s.mfaRepo.DeleteAllRecoveryCodes(ctx, userID)

	logger.Info("MFA primary factor disabled for user",
		zap.String("user_id", userID.String()),
		zap.Bool("residual_factor_retained", hasResidual),
	)

	s.publishMFARevoked(ctx, user, "user_disabled")

	// Phase C (2026-05-26): user-facing email notification — gives the
	// legitimate account holder an out-of-band signal that an MFA
	// factor was removed. Critical because the /mfa/disable* freshAuth
	// gate alone is what authorizes the mutation; if a stolen session
	// gets stepped-up via a phished factor, the email is the only
	// out-of-band channel that surfaces the breach to the real user.
	if s.securityNotifier != nil {
		s.securityNotifier.NotifyMFAFactorRemoved(
			ctx, user,
			"all two-factor methods",
			"Your account is no longer protected by multi-factor authentication.",
			BuildEventContext("", "", ""),
		)
	}

	return nil
}

// publishMFARevoked publishes a CAEMFARevoked event so receivers
// re-evaluate sessions whose authentication context referenced the
// now-removed MFA factor. nil-safe (caeService check inside).
func (s *MFAService) publishMFARevoked(ctx context.Context, user *models.User, reason string) {
	if s.caeService == nil || user == nil {
		return
	}
	_ = s.caeService.PublishEvent(ctx, CAEEvent{
		Type:      CAEMFARevoked,
		UserID:    user.ID,
		TenantID:  user.TenantID,
		Timestamp: time.Now().UTC(),
		Metadata: map[string]string{
			"reason": reason,
		},
	})
}

// AdminEnableMFA enables MFA for a user (admin action, no password required)
func (s *MFAService) AdminEnableMFA(ctx context.Context, userID uuid.UUID, method string) error {
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return fmt.Errorf("failed to get user: %w", err)
	}
	if user == nil {
		return fmt.Errorf("user not found")
	}

	if user.MFAEnabled {
		return fmt.Errorf("MFA is already enabled")
	}

	// Default to email MFA if method not specified
	if method == "" {
		method = authMethodEmail
	}

	// Validate method
	if method != authMethodEmail && method != authMethodTOTP {
		return fmt.Errorf("invalid MFA method: must be 'email' or 'totp'")
	}

	// For email MFA, require verified email
	if method == authMethodEmail && !user.IsEmailVerified {
		return fmt.Errorf("email must be verified before enabling email MFA")
	}

	// Enable MFA
	user.MFAEnabled = true
	user.MFAType = &method
	switch method {
	case authMethodEmail:
		user.MFAEmailEnabled = true
	case authMethodTOTP:
		user.MFATOTPEnabled = true
	}
	if user.MFAPreferredMethod == nil {
		user.MFAPreferredMethod = &method
	}

	if err := s.userRepo.Update(ctx, user); err != nil {
		return fmt.Errorf("failed to enable MFA: %w", err)
	}

	// Generate backup codes
	_, err = s.GenerateBackupCodes(ctx, userID)
	if err != nil {
		logger.Error("Failed to generate backup codes", zap.Error(err))
	}

	logger.Info("MFA enabled by admin",
		zap.String("user_id", userID.String()),
		zap.String("method", method),
	)

	return nil
}

// AdminDisableMFA disables MFA for a user (admin action, no password/code required)
func (s *MFAService) AdminDisableMFA(ctx context.Context, userID uuid.UUID) error {
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return fmt.Errorf("failed to get user: %w", err)
	}
	if user == nil {
		return fmt.Errorf("user not found")
	}

	if !user.MFAEnabled {
		return fmt.Errorf("MFA is not enabled")
	}

	// Symmetric with DisableMFA: clear primary (TOTP/email) columns and
	// derive mfa_enabled from any residual WebAuthn/push factors so a
	// user with a passkey isn't silently dropped to single-factor on an
	// admin nuke of their TOTP/email setup.
	hasResidual, err := s.userRepo.HasNonPrimaryMFAFactor(ctx, userID)
	if err != nil {
		return fmt.Errorf("check residual MFA factors: %w", err)
	}
	user.MFASecret = nil
	user.MFAType = nil
	user.MFATOTPEnabled = false
	user.MFAEmailEnabled = false
	user.MFAPreferredMethod = nil
	user.MFAEnabled = hasResidual

	if err := s.userRepo.Update(ctx, user); err != nil {
		return fmt.Errorf("failed to disable MFA: %w", err)
	}

	// Delete all recovery codes
	_ = s.mfaRepo.DeleteAllRecoveryCodes(ctx, userID)

	logger.Info("MFA primary factor disabled by admin",
		zap.String("user_id", userID.String()),
		zap.Bool("residual_factor_retained", hasResidual),
	)

	s.publishMFARevoked(ctx, user, "admin_disabled")

	return nil
}

// VerifyMFACode verifies any type of MFA code (TOTP, email, or backup)
func (s *MFAService) VerifyMFACode(ctx context.Context, userID uuid.UUID, code string) (bool, error) {
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return false, fmt.Errorf("failed to get user: %w", err)
	}
	if user == nil || !user.MFAEnabled {
		return false, fmt.Errorf("MFA not enabled")
	}

	// Normalize code (remove spaces and dashes)
	code = strings.ReplaceAll(code, " ", "")
	code = strings.ReplaceAll(code, "-", "")

	// Check if it's a backup code (typically longer than 6 digits)
	if len(code) > 6 {
		valid, err := s.VerifyBackupCode(ctx, userID, code)
		if err == nil && valid {
			return true, nil
		}
	}

	// Try TOTP if enabled (check new flag first, fallback to old MFAType)
	totpEnabled := user.MFATOTPEnabled || (user.MFAType != nil && *user.MFAType == authMethodTOTP)
	if totpEnabled && user.MFASecret != nil {
		valid, err := s.VerifyTOTPCode(ctx, userID, code)
		if err == nil && valid {
			return true, nil
		}
	}

	// Try email code if enabled (check new flag first, fallback to old MFAType)
	emailEnabled := user.MFAEmailEnabled || (user.MFAType != nil && *user.MFAType == authMethodEmail)
	if emailEnabled {
		valid, err := s.VerifyEmailMFACode(ctx, userID, code)
		if err == nil && valid {
			return true, nil
		}
	}

	// Also try backup code as fallback
	valid, _ := s.VerifyBackupCode(ctx, userID, code)
	return valid, nil
}

// Backup Codes

// GenerateBackupCodes generates new backup codes for a user
func (s *MFAService) GenerateBackupCodes(ctx context.Context, userID uuid.UUID) ([]string, error) {
	codes := make([]string, s.config.MFABackupCodeCount)
	hashes := make([]string, s.config.MFABackupCodeCount)

	for i := 0; i < s.config.MFABackupCodeCount; i++ {
		// Generate random code (8 characters, alphanumeric)
		code, err := s.generateBackupCode()
		if err != nil {
			return nil, fmt.Errorf("failed to generate backup code: %w", err)
		}
		codes[i] = code
		hashes[i] = s.hashCode(code)
	}

	// Store hashes
	if err := s.mfaRepo.CreateRecoveryCodes(ctx, userID, hashes); err != nil {
		return nil, fmt.Errorf("failed to store recovery codes: %w", err)
	}

	logger.Info("Backup codes generated",
		zap.String("user_id", userID.String()),
		zap.Int("count", len(codes)),
	)

	return codes, nil
}

// VerifyBackupCode verifies and consumes a backup code
func (s *MFAService) VerifyBackupCode(ctx context.Context, userID uuid.UUID, code string) (bool, error) {
	codes, err := s.mfaRepo.GetUnusedRecoveryCodes(ctx, userID)
	if err != nil {
		return false, fmt.Errorf("failed to get recovery codes: %w", err)
	}

	codeHash := s.hashCode(strings.ToUpper(code))

	for _, rc := range codes {
		// SECURITY: Use constant-time comparison to prevent timing side-channel attacks
		if subtle.ConstantTimeCompare([]byte(rc.CodeHash), []byte(codeHash)) == 1 {
			// Mark as used
			if err := s.mfaRepo.UseRecoveryCode(ctx, rc.ID); err != nil {
				logger.Error("Failed to mark recovery code as used", zap.Error(err))
			}

			logger.Info("Backup code used",
				zap.String("user_id", userID.String()),
			)

			return true, nil
		}
	}

	return false, nil
}

// GetBackupCodesCount returns the number of remaining backup codes
func (s *MFAService) GetBackupCodesCount(ctx context.Context, userID uuid.UUID) (int, error) {
	return s.mfaRepo.GetUnusedRecoveryCodesCount(ctx, userID)
}

// GetMFAStatus returns the MFA status for a user
func (s *MFAService) GetMFAStatus(ctx context.Context, userID uuid.UUID) (*models.MFAStatusResponse, error) {
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}
	if user == nil {
		return nil, fmt.Errorf("user not found")
	}

	backupCount, _ := s.GetBackupCodesCount(ctx, userID)

	// Build list of available methods
	var availableMethods []string
	if user.MFATOTPEnabled {
		availableMethods = append(availableMethods, authMethodTOTP)
	}
	if user.MFAEmailEnabled {
		availableMethods = append(availableMethods, authMethodEmail)
	}

	// Get preferred method
	preferredMethod := ""
	if user.MFAPreferredMethod != nil {
		preferredMethod = *user.MFAPreferredMethod
	} else if len(availableMethods) > 0 {
		preferredMethod = availableMethods[0] // Default to first available
	}

	// Legacy method field (use preferred or first available)
	method := preferredMethod
	if method == "" && user.MFAType != nil {
		method = *user.MFAType
	}

	return &models.MFAStatusResponse{
		Enabled:          user.MFAEnabled,
		Method:           method,
		TOTPEnabled:      user.MFATOTPEnabled,
		EmailEnabled:     user.MFAEmailEnabled,
		AvailableMethods: availableMethods,
		PreferredMethod:  preferredMethod,
		BackupCodesCount: backupCount,
	}, nil
}

// SetPreferredMFAMethod sets the user's preferred MFA method
func (s *MFAService) SetPreferredMFAMethod(ctx context.Context, userID uuid.UUID, method string) error {
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return fmt.Errorf("failed to get user: %w", err)
	}
	if user == nil {
		return fmt.Errorf("user not found")
	}

	// Validate that the method is enabled
	if method == authMethodTOTP && !user.MFATOTPEnabled {
		return fmt.Errorf("TOTP is not enabled")
	}
	if method == authMethodEmail && !user.MFAEmailEnabled {
		return fmt.Errorf("email MFA is not enabled")
	}

	user.MFAPreferredMethod = &method
	if err := s.userRepo.Update(ctx, user); err != nil {
		return fmt.Errorf("failed to update user: %w", err)
	}

	logger.Info("MFA preferred method updated",
		zap.String("user_id", userID.String()),
		zap.String("method", method),
	)

	return nil
}

// DisableTOTPOnly disables only TOTP MFA while keeping email MFA if enabled.
// Password and mfaCode are both OPTIONAL — same contract as DisableMFA.
func (s *MFAService) DisableTOTPOnly(ctx context.Context, userID uuid.UUID, password, mfaCode string) error {
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return fmt.Errorf("failed to get user: %w", err)
	}
	if user == nil {
		return fmt.Errorf("user not found")
	}

	if !user.MFATOTPEnabled {
		return fmt.Errorf("TOTP MFA is not enabled")
	}

	// Verify password if supplied (defense-in-depth). Empty password is
	// authorized solely by the RFC 9470 freshAuth gate on the route.
	if password != "" {
		if err := s.verifyUserPassword(ctx, user, password); err != nil {
			return fmt.Errorf("DisableTOTPOnly: %w", err)
		}
	}

	// Verify MFA code if supplied (defense-in-depth).
	if mfaCode != "" {
		valid, err := s.VerifyMFACode(ctx, userID, mfaCode)
		if err != nil {
			return fmt.Errorf("failed to verify MFA code: %w", err)
		}
		if !valid {
			return fmt.Errorf("invalid MFA code")
		}
	}

	// Disable TOTP
	user.MFATOTPEnabled = false
	user.MFASecret = nil

	// If email MFA is still enabled, keep MFA enabled and update preferred method
	if user.MFAEmailEnabled {
		emailMethod := authMethodEmail
		user.MFAType = &emailMethod
		user.MFAPreferredMethod = &emailMethod
	} else {
		// No MFA methods left, disable MFA entirely
		user.MFAEnabled = false
		user.MFAType = nil
		user.MFAPreferredMethod = nil
		// Delete recovery codes
		_ = s.mfaRepo.DeleteAllRecoveryCodes(ctx, userID)
	}

	if err := s.userRepo.Update(ctx, user); err != nil {
		return fmt.Errorf("failed to update user: %w", err)
	}

	logger.Info("TOTP MFA disabled for user",
		zap.String("user_id", userID.String()),
		zap.Bool("mfa_still_enabled", user.MFAEnabled),
	)

	// Emit CAE/SSF revocation event so downstream RPs re-evaluate
	// sessions whose authentication context included the removed
	// TOTP factor. This is the compensating control cited by the
	// route's design rationale (step-up = sole authorization +
	// real-time revocation broadcast).
	s.publishMFARevoked(ctx, user, "user_disabled_totp")

	if s.securityNotifier != nil {
		remaining := "You still have multi-factor authentication enabled via another method."
		if !user.MFAEnabled {
			remaining = "Your account is no longer protected by multi-factor authentication."
		}
		s.securityNotifier.NotifyMFAFactorRemoved(
			ctx, user, "authenticator app", remaining, BuildEventContext("", "", ""),
		)
	}

	return nil
}

// DisableEmailMFAOnly disables only email MFA while keeping TOTP if enabled.
// Password and mfaCode are both OPTIONAL — same contract as DisableMFA.
func (s *MFAService) DisableEmailMFAOnly(ctx context.Context, userID uuid.UUID, password, mfaCode string) error {
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return fmt.Errorf("failed to get user: %w", err)
	}
	if user == nil {
		return fmt.Errorf("user not found")
	}

	if !user.MFAEmailEnabled {
		return fmt.Errorf("email MFA is not enabled")
	}

	// Verify password if supplied (defense-in-depth). Empty password is
	// authorized solely by the RFC 9470 freshAuth gate on the route.
	if password != "" {
		if err := s.verifyUserPassword(ctx, user, password); err != nil {
			return fmt.Errorf("DisableEmailMFAOnly: %w", err)
		}
	}

	// Verify MFA code if supplied (defense-in-depth).
	if mfaCode != "" {
		valid, err := s.VerifyMFACode(ctx, userID, mfaCode)
		if err != nil {
			return fmt.Errorf("failed to verify MFA code: %w", err)
		}
		if !valid {
			return fmt.Errorf("invalid MFA code")
		}
	}

	// Disable email MFA
	user.MFAEmailEnabled = false

	// If TOTP is still enabled, keep MFA enabled and update preferred method
	if user.MFATOTPEnabled {
		totpMethod := authMethodTOTP
		user.MFAType = &totpMethod
		user.MFAPreferredMethod = &totpMethod
	} else {
		// No MFA methods left, disable MFA entirely
		user.MFAEnabled = false
		user.MFAType = nil
		user.MFAPreferredMethod = nil
		// Delete recovery codes
		_ = s.mfaRepo.DeleteAllRecoveryCodes(ctx, userID)
	}

	if err := s.userRepo.Update(ctx, user); err != nil {
		return fmt.Errorf("failed to update user: %w", err)
	}

	logger.Info("Email MFA disabled for user",
		zap.String("user_id", userID.String()),
		zap.Bool("mfa_still_enabled", user.MFAEnabled),
	)

	// Emit CAE/SSF revocation event — same rationale as DisableTOTPOnly.
	s.publishMFARevoked(ctx, user, "user_disabled_email")

	if s.securityNotifier != nil {
		remaining := "You still have multi-factor authentication enabled via another method."
		if !user.MFAEnabled {
			remaining = "Your account is no longer protected by multi-factor authentication."
		}
		s.securityNotifier.NotifyMFAFactorRemoved(
			ctx, user, "email-based two-factor", remaining, BuildEventContext("", "", ""),
		)
	}

	return nil
}

// verifyUserPassword verifies password for both local and LDAP users
func (s *MFAService) verifyUserPassword(ctx context.Context, user *models.User, password string) error {
	if user.FederationType != nil && *user.FederationType == federationTypeLDAP {
		return s.verifyLDAPPassword(ctx, user, password)
	}
	if user.PasswordHash == nil || !verifyPassword(password, *user.PasswordHash) {
		return fmt.Errorf("invalid password")
	}
	return nil
}

// verifyLDAPPassword authenticates the user against their configured LDAP provider.
func (s *MFAService) verifyLDAPPassword(ctx context.Context, user *models.User, password string) error {
	if s.ldapService == nil {
		return fmt.Errorf("LDAP service not available")
	}
	providers, err := s.ldapService.GetActiveLDAPProviders(ctx, user.TenantID)
	if err != nil {
		return fmt.Errorf("failed to get LDAP providers: %w", err)
	}
	for _, provider := range providers {
		if user.FederationSource == nil || provider.Name != *user.FederationSource {
			continue
		}
		_, err := s.ldapService.Authenticate(ctx, user.TenantID, provider.ID, user.Username, password)
		if err == nil {
			return nil
		}
		logger.Debug("LDAP authentication failed for password verification",
			zap.String("user_id", user.ID.String()),
			zap.String("provider", provider.Name),
			zap.Error(err),
		)
	}
	return fmt.Errorf("invalid password")
}

// Email verification, helper functions, and password verification
// are in mfa_service_email_verify.go
