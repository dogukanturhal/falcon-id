// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	cryptorand "crypto/rand"
	"encoding/binary"
	"fmt"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/pkg/config"
	"github.com/dogukanturhal/falcon-id/pkg/crypto"
	"github.com/dogukanturhal/falcon-id/pkg/logger"
)

const (
	// PasswordResetTokenExpiry defines how long a password reset token is valid
	PasswordResetTokenExpiry = 1 * time.Hour
)

// passwordResetServiceUserRepo defines the user repository methods needed by PasswordResetService.
type passwordResetServiceUserRepo interface {
	GetByEmail(ctx context.Context, tenantID uuid.UUID, email string) (*models.User, error)
	GetByID(ctx context.Context, id uuid.UUID) (*models.User, error)
	Update(ctx context.Context, user *models.User) error
}

// passwordResetServiceTokenRepo defines the token repository methods needed by PasswordResetService.
type passwordResetServiceTokenRepo interface {
	InvalidateUserPasswordResets(ctx context.Context, userID uuid.UUID) error
	CreatePasswordReset(ctx context.Context, reset *models.PasswordReset) error
	GetPasswordReset(ctx context.Context, tokenHash string) (*models.PasswordReset, error)
	MarkPasswordResetUsed(ctx context.Context, id uuid.UUID) error
}

// passwordResetServiceSessionRepo defines the session repository methods needed by PasswordResetService.
type passwordResetServiceSessionRepo interface {
	EndAllUserSessions(ctx context.Context, userID uuid.UUID, reason string) error
}

// PasswordResetService is an exported type.
type PasswordResetService struct {
	config       *config.Config
	userRepo     passwordResetServiceUserRepo
	tokenRepo    passwordResetServiceTokenRepo
	sessionRepo  passwordResetServiceSessionRepo
	emailService *EmailService
	auditService *AuditService

	// caeService is optional. When set, ResetPassword publishes a
	// CAEPasswordChanged event so receivers (Talon IAP, SSE
	// subscribers) revoke active sessions immediately instead of
	// waiting for the next token refresh. Mirrors the
	// AuthService.ChangePassword publish-site that landed in the
	// tier-1 verification pass; nil-safe.
	caeService *CAEService

	// caepEmitter is the OpenID CAEP 1.0 transmitter — different from
	// caeService (which is an in-process pub/sub for the same node's
	// session listener). caepEmitter pushes signed SETs (RFC 8417) over
	// the wire to registered SSF receivers (Talon, external RPs) so
	// they revoke independently. nil-safe; when nil, behavior is
	// unchanged from pre-tier-1.
	caepEmitter *CAEPEmitter

	// breachChecker is optional. When set, ResetPassword rejects a new
	// password found in the HIBP breach corpus (ASVS V6 / NIST 800-63B).
	// nil-safe: unwired short-circuits to the pre-check behaviour.
	breachChecker breachChecker
}

// SetCAEService wires the CAEP publisher into PasswordResetService.
// Safe to call with nil (DB-layer session revocation in ResetPassword
// remains authoritative).
func (s *PasswordResetService) SetCAEService(svc *CAEService) {
	s.caeService = svc
}

// SetBreachChecker wires the HIBP breach-password check (ASVS V6 / NIST
// 800-63B) into ResetPassword. Optional + nil-safe.
func (s *PasswordResetService) SetBreachChecker(c breachChecker) {
	s.breachChecker = c
}

// SetCAEPEmitter wires the OpenID CAEP 1.0 transmitter into
// PasswordResetService. ResetPassword fires `credential-change`
// (credential_type=password, change_type=update) so every SSF
// receiver hears about the change. Safe to call with nil.
func (s *PasswordResetService) SetCAEPEmitter(em *CAEPEmitter) {
	s.caepEmitter = em
}

// NewPasswordResetService is an exported function.
func NewPasswordResetService(
	cfg *config.Config,
	userRepo passwordResetServiceUserRepo,
	tokenRepo passwordResetServiceTokenRepo,
	emailService *EmailService,
	auditService *AuditService,
) *PasswordResetService {
	return &PasswordResetService{
		config:       cfg,
		userRepo:     userRepo,
		tokenRepo:    tokenRepo,
		emailService: emailService,
		auditService: auditService,
	}
}

// SetSessionRepo sets the session repository for session invalidation on password reset.
func (s *PasswordResetService) SetSessionRepo(sessionRepo passwordResetServiceSessionRepo) {
	s.sessionRepo = sessionRepo
}

// RequestPasswordReset initiates a password reset flow
// Returns nil even if user not found to prevent email enumeration attacks
// SECURITY: Uses constant-time response to prevent timing attacks
func (s *PasswordResetService) RequestPasswordReset(ctx context.Context, tenantID uuid.UUID, email string, ipAddress string) error {
	startTime := time.Now()

	// SECURITY: Ensure minimum response time to prevent timing-based email enumeration
	// This makes the response time similar regardless of whether the user exists
	defer func() {
		elapsed := time.Since(startTime)
		minDuration := 200 * time.Millisecond // Minimum response time
		if elapsed < minDuration {
			time.Sleep(minDuration - elapsed)
		}
	}()

	// Find user by email
	user, err := s.userRepo.GetByEmail(ctx, tenantID, email)
	if err != nil {
		logger.Error("Failed to lookup user for password reset", zap.Error(err))
		// SECURITY: Perform dummy operations to normalize timing
		s.performDummyOperations()
		return nil // Don't reveal if user exists
	}

	if user == nil {
		logger.Info("Password reset requested for non-existent email", zap.String("email", email))
		// SECURITY: Perform dummy operations to normalize timing
		s.performDummyOperations()
		return nil // Don't reveal if user exists
	}

	// Don't allow password reset for federated users
	if user.FederationType != nil && *user.FederationType == federationTypeLDAP {
		logger.Info("Password reset requested for LDAP user", zap.String("email", email))
		// SECURITY: Perform dummy operations to normalize timing
		s.performDummyOperations()
		return nil // Don't reveal user type
	}

	// Invalidate any existing reset tokens for this user
	if err := s.tokenRepo.InvalidateUserPasswordResets(ctx, user.ID); err != nil {
		logger.Error("Failed to invalidate existing password resets", zap.Error(err))
	}

	// Generate reset token (64-byte secure random)
	token, err := crypto.GenerateSecureToken()
	if err != nil {
		logger.Error("Failed to generate password reset token", zap.Error(err))
		return fmt.Errorf("failed to generate reset token")
	}

	// Store token hash in database
	tokenHash, err := crypto.HashToken(token)
	if err != nil {
		logger.Error("Failed to hash password reset token", zap.Error(err))
		return fmt.Errorf("failed to hash token")
	}

	reset := &models.PasswordReset{
		UserID:    user.ID,
		TokenHash: tokenHash,
		IPAddress: &ipAddress,
		ExpiresAt: time.Now().Add(PasswordResetTokenExpiry),
	}

	if err := s.tokenRepo.CreatePasswordReset(ctx, reset); err != nil {
		logger.Error("Failed to create password reset", zap.Error(err))
		return fmt.Errorf("failed to create password reset")
	}

	// Send email with reset link (using raw token, not hash)
	username := user.Username
	if user.DisplayName != nil && *user.DisplayName != "" {
		username = *user.DisplayName
	} else if user.FirstName != nil && *user.FirstName != "" {
		username = *user.FirstName
	}

	if err := s.emailService.SendPasswordReset(user.TenantID, user.Email, token, username); err != nil {
		logger.Error("Failed to send password reset email", zap.Error(err))
		return fmt.Errorf("failed to send password reset email")
	}

	// Log audit event
	s.auditService.LogPasswordResetRequest(ctx, tenantID, user.ID, ipAddress, true, "")

	logger.Info("Password reset email sent",
		zap.String("user_id", user.ID.String()),
		zap.String("email", email),
	)

	return nil
}

// performDummyOperations performs CPU-intensive operations to normalize timing
// SECURITY: This prevents timing attacks by making non-user paths take similar time
func (s *PasswordResetService) performDummyOperations() {
	// Generate and hash a dummy token (same operations as real path)
	dummyToken, err := crypto.GenerateSecureToken()
	if err != nil {
		logger.Warn("performDummyOperations: failed to generate secure token", zap.Error(err))
		return
	}
	if _, err := crypto.HashToken(dummyToken); err != nil {
		logger.Warn("performDummyOperations: failed to hash token", zap.Error(err))
	}

	// SECURITY: Use crypto/rand for unpredictable jitter
	var buf [8]byte
	if _, err := cryptorand.Read(buf[:]); err != nil {
		logger.Warn("performDummyOperations: failed to generate jitter", zap.Error(err))
		return
	}
	jitter := time.Duration(50+binary.LittleEndian.Uint64(buf[:])%100) * time.Millisecond
	time.Sleep(jitter)
}

// ResetPassword completes the password reset flow
func (s *PasswordResetService) ResetPassword(ctx context.Context, token, newPassword, ipAddress string) error {
	// Hash the token to look up in database
	tokenHash, err := crypto.HashToken(token)
	if err != nil {
		return fmt.Errorf("failed to hash token: %w", err)
	}

	// Find the password reset record
	reset, err := s.tokenRepo.GetPasswordReset(ctx, tokenHash)
	if err != nil {
		logger.Error("Failed to lookup password reset", zap.Error(err))
		return fmt.Errorf("invalid or expired reset token")
	}

	if reset == nil {
		logger.Info("Password reset attempted with invalid token")
		return fmt.Errorf("invalid or expired reset token")
	}

	// Check if token is expired
	if time.Now().After(reset.ExpiresAt) {
		logger.Info("Password reset attempted with expired token", zap.String("user_id", reset.UserID.String()))
		return fmt.Errorf("invalid or expired reset token")
	}

	// Check if token is already used
	if reset.UsedAt != nil {
		logger.Info("Password reset attempted with already used token", zap.String("user_id", reset.UserID.String()))
		return fmt.Errorf("invalid or expired reset token")
	}

	// Get the user
	user, err := s.userRepo.GetByID(ctx, reset.UserID)
	if err != nil {
		logger.Error("Failed to get user for password reset", zap.Error(err))
		return fmt.Errorf("failed to reset password")
	}

	if user == nil {
		logger.Error("User not found for password reset", zap.String("user_id", reset.UserID.String()))
		return fmt.Errorf("failed to reset password")
	}

	// Check if user is active
	if !user.IsActive {
		logger.Info("Password reset attempted for inactive user", zap.String("user_id", user.ID.String()))
		return fmt.Errorf("account is disabled")
	}

	// Validate new password
	policy := &crypto.PasswordPolicy{
		MinLength:      s.config.PasswordMinLength,
		RequireUpper:   s.config.PasswordRequireUpper,
		RequireLower:   s.config.PasswordRequireLower,
		RequireDigit:   s.config.PasswordRequireDigit,
		RequireSpecial: s.config.PasswordRequireSpecial,
	}

	if err := crypto.ValidatePassword(newPassword, policy); err != nil {
		return fmt.Errorf("ResetPassword: %w", err)
	}

	// ASVS V6 / NIST 800-63B — reject breached passwords on reset.
	if err := assertPasswordNotBreached(ctx, s.breachChecker, newPassword); err != nil {
		return fmt.Errorf("ResetPassword: %w", err)
	}

	// Hash the new password
	hash, err := crypto.HashPassword(newPassword, nil)
	if err != nil {
		logger.Error("Failed to hash new password", zap.Error(err))
		return fmt.Errorf("failed to reset password")
	}

	// Update user's password
	user.PasswordHash = &hash
	now := time.Now()
	user.PasswordChangedAt = &now
	user.MustChangePassword = false
	user.IsLocked = false
	user.LockReason = nil
	user.LockedAt = nil
	user.LockedUntil = nil
	user.FailedLoginAttempts = 0

	if err := s.userRepo.Update(ctx, user); err != nil {
		logger.Error("Failed to update user password", zap.Error(err))
		return fmt.Errorf("failed to reset password")
	}

	// Mark the reset token as used
	if err := s.tokenRepo.MarkPasswordResetUsed(ctx, reset.ID); err != nil {
		logger.Error("Failed to mark password reset as used", zap.Error(err))
		// Don't return error - password was already changed
	}

	// Invalidate all other reset tokens for this user
	if err := s.tokenRepo.InvalidateUserPasswordResets(ctx, user.ID); err != nil {
		logger.Error("Failed to invalidate other password resets", zap.Error(err))
	}

	// SECURITY: Invalidate all active sessions after password reset
	if s.sessionRepo != nil {
		if err := s.sessionRepo.EndAllUserSessions(ctx, user.ID, "password_reset"); err != nil {
			logger.Error("Failed to invalidate sessions after password reset", zap.Error(err))
		}
	}

	// Log audit event
	s.auditService.LogPasswordReset(ctx, user.TenantID, user.ID, ipAddress, true, "")

	logger.Info("Password reset successful",
		zap.String("user_id", user.ID.String()),
	)

	// Publish CAEPasswordChanged so receivers immediately re-evaluate
	// any other active session for this user. Sibling of the publish-
	// site in AuthService.ChangePassword; the DB-layer EndAllUserSessions
	// above already invalidates sessions, but the push signal removes
	// the up-to-token-TTL window where receivers holding a cached
	// access token would still trust it. nil-safe.
	if s.caeService != nil {
		_ = s.caeService.PublishEvent(ctx, CAEEvent{
			Type:      CAEPasswordChanged,
			UserID:    user.ID,
			TenantID:  user.TenantID,
			Timestamp: time.Now().UTC(),
			Metadata: map[string]string{
				"reason":     "self_service_reset",
				"ip_address": ipAddress,
			},
		})
	}

	// Off-process CAEP 1.0 credential-change SET — pushed to every
	// SSF receiver registered for this tenant. Best-effort
	// background goroutine so the user-facing reset response isn't
	// gated on receiver reachability; the emitter logs per-stream
	// outcomes. context.Background() because the caller's ctx is
	// often the HTTP request — which dies on response flush.
	if s.caepEmitter != nil && user.TenantID != uuid.Nil {
		go func(tid, uid uuid.UUID) { //nolint:gosec // goroutine must outlive request ctx
			_ = s.caepEmitter.EmitCredentialChange(
				context.Background(),
				tid, uid,
				"password",
				"update",
				"self_service_reset",
			)
		}(user.TenantID, user.ID)
	}

	return nil
}
