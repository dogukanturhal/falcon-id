// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/mail"
	"strings"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/internal/repositories"
	"github.com/dogukanturhal/falcon-id/pkg/config"
	"github.com/dogukanturhal/falcon-id/pkg/logger"
	"github.com/dogukanturhal/falcon-id/pkg/redis"
)

const (
	recoveryEmailCodeLength = 6
	recoveryMaxAttempts     = 5
	recoveryDefaultCodeTTL  = 10 * time.Minute
	// Rate limit on code requests (fixed window) — anti email-bombing.
	recoveryMaxCodeRequests = 5
	recoveryRateWindow      = time.Hour
)

// recoveryPending is the transient Redis-stored challenge for a recovery-email
// verification. Only the code HASH is stored — never the code itself.
type recoveryPending struct {
	Email    string `json:"email"`
	CodeHash string `json:"code_hash"`
	Attempts int    `json:"attempts"`
}

// RecoveryService manages a user's account-recovery methods. Verified methods
// are persisted via RecoveryRepository; in-flight verification codes live in
// Redis (ephemeral, brute-force-bounded). Recovery email is fully wired;
// recovery phone is reserved pending SMS delivery.
type RecoveryService struct {
	recoveryRepo *repositories.RecoveryRepository
	userRepo     *repositories.UserRepository
	emailService *EmailService
	redis        *redis.Client
	cfg          *config.Config
	auditService *AuditService
}

// NewRecoveryService wires the recovery service. redisClient must be non-nil;
// the caller (cmd/services.go) only constructs this when Redis is available.
// auditService may be nil (audit is best-effort).
func NewRecoveryService(
	recoveryRepo *repositories.RecoveryRepository,
	userRepo *repositories.UserRepository,
	emailService *EmailService,
	redisClient *redis.Client,
	cfg *config.Config,
	auditService *AuditService,
) *RecoveryService {
	return &RecoveryService{
		recoveryRepo: recoveryRepo,
		userRepo:     userRepo,
		emailService: emailService,
		redis:        redisClient,
		cfg:          cfg,
		auditService: auditService,
	}
}

// checkRateLimit bounds how often a user can request recovery-email codes
// (fixed window), so the endpoint can't be abused to bomb an arbitrary address
// with mail. Fails OPEN on a Redis error — a transient cache outage must not
// lock a legitimate user out; the per-challenge attempt cap still bounds abuse.
func (s *RecoveryService) checkRateLimit(ctx context.Context, userID uuid.UUID) error {
	key := fmt.Sprintf("recovery:email:ratelimit:%s", userID.String())
	n, err := s.redis.Incr(ctx, key)
	if err != nil {
		return nil
	}
	if n == 1 {
		_ = s.redis.Expire(ctx, key, recoveryRateWindow)
	}
	if n > recoveryMaxCodeRequests {
		return fmt.Errorf("too many recovery-email requests — please try again later")
	}
	return nil
}

// audit records a recovery action (best-effort; nil-safe).
func (s *RecoveryService) audit(ctx context.Context, user *models.User, action string, success bool, ipAddress string) {
	if s.auditService == nil || user == nil {
		return
	}
	uid := user.ID
	s.auditService.LogUserAction(ctx, user.TenantID, &uid, &uid, action, success, map[string]interface{}{
		"method":     "recovery_email",
		"ip_address": ipAddress,
	})
}

// notifyPrimary sends an out-of-band security alert to the user's PRIMARY email
// when their recovery email changes (added/removed). Best-effort, non-fatal.
func (s *RecoveryService) notifyPrimary(ctx context.Context, user *models.User, action, ipAddress, userAgent string) {
	if s.emailService == nil || user == nil || user.Email == "" {
		return
	}
	evt := securityEventContext{Timestamp: time.Now().UTC(), IPAddress: ipAddress, UserAgent: userAgent}
	if err := s.emailService.SendRecoveryEmailChanged(user.TenantID, user.Email, user.Username, action, evt); err != nil {
		logger.Warn("recovery: primary-email security notification failed (non-fatal)",
			zap.String("user_id", user.ID.String()), zap.Error(err))
	}
}

func (s *RecoveryService) codeTTL() time.Duration {
	if s.cfg != nil && s.cfg.MFAEmailCodeTTL > 0 {
		return s.cfg.MFAEmailCodeTTL
	}
	return recoveryDefaultCodeTTL
}

func (s *RecoveryService) pendingKey(userID uuid.UUID) string {
	return fmt.Sprintf("recovery:email:pending:%s", userID.String())
}

// SetRecoveryEmail validates a candidate recovery address, generates a one-time
// code, stores the pending challenge in Redis, and emails the code to the
// candidate address. The address is NOT persisted until verified.
func (s *RecoveryService) SetRecoveryEmail(ctx context.Context, userID uuid.UUID, email, ipAddress, userAgent string) error {
	if err := s.checkRateLimit(ctx, userID); err != nil {
		return err
	}
	addr, err := mail.ParseAddress(strings.TrimSpace(email))
	if err != nil {
		return fmt.Errorf("invalid email address")
	}
	email = strings.ToLower(addr.Address)

	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return fmt.Errorf("failed to load user: %w", err)
	}
	if user == nil {
		return fmt.Errorf("user not found")
	}
	if strings.EqualFold(email, user.Email) {
		return fmt.Errorf("recovery email must be different from your account email")
	}

	code, err := generateRecoveryCode(recoveryEmailCodeLength)
	if err != nil {
		return fmt.Errorf("failed to generate code: %w", err)
	}

	pending := recoveryPending{Email: email, CodeHash: hashRecoveryCode(code), Attempts: 0}
	buf, _ := json.Marshal(pending)
	if err := s.redis.Set(ctx, s.pendingKey(userID), string(buf), s.codeTTL()); err != nil {
		return fmt.Errorf("failed to store verification: %w", err)
	}

	// Deliver the code. Always attempt a real send first (so a working
	// local SMTP/mailpit still delivers). If delivery fails, propagate the
	// error in production/staging; in non-production environments fall back
	// to a WARN log of the code so the flow stays testable without SMTP.
	// The dev fallback can NEVER fire in production/staging.
	var sendErr error
	if s.emailService != nil {
		sendErr = s.emailService.SendMFACode(user.TenantID, email, code, user.Username)
	} else {
		sendErr = fmt.Errorf("email service unavailable")
	}
	if sendErr != nil {
		if s.isProdLike() {
			return fmt.Errorf("failed to send verification email: %w", sendErr)
		}
		logger.Warn("Recovery-email code generated but delivery failed — DEV fallback, code logged (non-production only)",
			zap.String("user_id", userID.String()),
			zap.String("recovery_email", email),
			zap.String("dev_code", code),
			zap.Error(sendErr),
		)
	}

	s.audit(ctx, user, "recovery_email_verification_requested", true, ipAddress)
	logger.Info("Recovery-email verification started", zap.String("user_id", userID.String()))
	return nil
}

// isProdLike reports whether code-leaking dev fallbacks must be suppressed.
// Mirrors the production/staging gate used in pkg/config validation.
func (s *RecoveryService) isProdLike() bool {
	if s.cfg == nil {
		return true // fail safe: treat unknown env as production
	}
	return s.cfg.Environment == "production" || s.cfg.Environment == "staging"
}

// VerifyRecoveryEmail checks the supplied code against the pending challenge and,
// on success, persists the recovery email as verified. Brute force is bounded:
// after recoveryMaxAttempts wrong codes the challenge is discarded.
func (s *RecoveryService) VerifyRecoveryEmail(ctx context.Context, userID uuid.UUID, code, ipAddress, userAgent string) error {
	key := s.pendingKey(userID)
	raw, err := s.redis.Get(ctx, key)
	if err != nil || raw == "" {
		return fmt.Errorf("no pending recovery-email verification")
	}
	var pending recoveryPending
	if err := json.Unmarshal([]byte(raw), &pending); err != nil {
		_ = s.redis.Del(ctx, key)
		return fmt.Errorf("no pending recovery-email verification")
	}

	got := hashRecoveryCode(strings.TrimSpace(code))
	if subtle.ConstantTimeCompare([]byte(got), []byte(pending.CodeHash)) != 1 {
		pending.Attempts++
		if pending.Attempts >= recoveryMaxAttempts {
			_ = s.redis.Del(ctx, key)
			return fmt.Errorf("too many incorrect attempts — request a new code")
		}
		buf, _ := json.Marshal(pending)
		_ = s.redis.Set(ctx, key, string(buf), s.codeTTL())
		return fmt.Errorf("incorrect or expired code")
	}

	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil || user == nil {
		return fmt.Errorf("failed to load user")
	}
	if err := s.recoveryRepo.UpsertVerified(ctx, userID, user.TenantID, models.RecoveryMethodEmail, pending.Email); err != nil {
		return fmt.Errorf("failed to save recovery email: %w", err)
	}
	_ = s.redis.Del(ctx, key)

	s.audit(ctx, user, "recovery_email_added", true, ipAddress)
	s.notifyPrimary(ctx, user, "added", ipAddress, userAgent)
	logger.Info("Recovery-email verified", zap.String("user_id", userID.String()))
	return nil
}

// RemoveRecoveryEmail deletes the verified recovery email and any pending one,
// audits it, and notifies the primary email out-of-band.
func (s *RecoveryService) RemoveRecoveryEmail(ctx context.Context, userID uuid.UUID, ipAddress, userAgent string) error {
	_ = s.redis.Del(ctx, s.pendingKey(userID))
	if err := s.recoveryRepo.Delete(ctx, userID, models.RecoveryMethodEmail); err != nil {
		return err
	}
	user, _ := s.userRepo.GetByID(ctx, userID)
	s.audit(ctx, user, "recovery_email_removed", true, ipAddress)
	s.notifyPrimary(ctx, user, "removed", ipAddress, userAgent)
	return nil
}

// GetStatus returns the masked recovery view, including any in-flight pending
// verification (read from Redis).
func (s *RecoveryService) GetStatus(ctx context.Context, userID uuid.UUID) (*models.RecoveryStatus, error) {
	status := &models.RecoveryStatus{}

	method, err := s.recoveryRepo.Get(ctx, userID, models.RecoveryMethodEmail)
	if err != nil {
		return nil, err
	}
	if method != nil {
		status.Email.Configured = method.Verified
		status.Email.MaskedEmail = maskRecoveryEmail(method.Value)
	}

	if raw, err := s.redis.Get(ctx, s.pendingKey(userID)); err == nil && raw != "" {
		var pending recoveryPending
		if json.Unmarshal([]byte(raw), &pending) == nil && pending.Email != "" {
			status.Email.PendingEmail = maskRecoveryEmail(pending.Email)
		}
	}

	return status, nil
}

// --- helpers ---

func generateRecoveryCode(length int) (string, error) {
	const digits = "0123456789"
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	for i := range b {
		b[i] = digits[int(b[i])%len(digits)]
	}
	return string(b), nil
}

func hashRecoveryCode(code string) string {
	h := sha256.Sum256([]byte(strings.TrimSpace(code)))
	return hex.EncodeToString(h[:])
}

// maskRecoveryEmail obscures the local part for display: "john@example.com" ->
// "j•••n@example.com". The domain is shown in full (matches Google's recovery
// UX so the user can still recognise which address it is).
func maskRecoveryEmail(email string) string {
	at := strings.LastIndex(email, "@")
	if at <= 0 {
		return "•••"
	}
	local, domain := email[:at], email[at:]
	switch {
	case len(local) <= 1:
		return local + "•••" + domain
	case len(local) == 2:
		return string(local[0]) + "•••" + domain
	default:
		return string(local[0]) + strings.Repeat("•", 3) + string(local[len(local)-1]) + domain
	}
}
