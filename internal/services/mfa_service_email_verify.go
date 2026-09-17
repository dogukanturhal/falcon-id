// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"
	"golang.org/x/crypto/argon2"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/pkg/logger"
)

// Email Verification

// SendVerificationEmail sends an email verification link
func (s *MFAService) SendVerificationEmail(ctx context.Context, userID uuid.UUID) error {
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return fmt.Errorf("failed to get user: %w", err)
	}
	if user == nil {
		return fmt.Errorf("user not found")
	}

	if user.IsEmailVerified {
		return fmt.Errorf("email is already verified")
	}

	// Generate secure token (32 bytes = 64 hex chars)
	token, err := s.generateSecureToken(32)
	if err != nil {
		return fmt.Errorf("failed to generate verification token: %w", err)
	}

	// Store verification record
	expiresAt := time.Now().Add(s.config.MFAEmailCodeTTL)
	_, err = s.mfaRepo.CreateEmailVerification(ctx, userID, user.Email, token, expiresAt)
	if err != nil {
		return fmt.Errorf("failed to store verification: %w", err)
	}

	// Create verification link
	verificationLink := fmt.Sprintf("%s/verify-email?token=%s", s.config.FrontendURL, token)

	// Send email with link
	if err := s.emailService.SendVerificationEmailLink(user.TenantID, user.Email, verificationLink, user.Username); err != nil {
		return fmt.Errorf("failed to send verification email: %w", err)
	}

	logger.Info("Verification email sent",
		zap.String("user_id", userID.String()),
		zap.String("email", user.Email),
	)

	return nil
}

// VerifyEmail verifies an email with the provided code (requires user context)
func (s *MFAService) VerifyEmail(ctx context.Context, userID uuid.UUID, code string) error {
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return fmt.Errorf("failed to get user: %w", err)
	}
	if user == nil {
		return fmt.Errorf("user not found")
	}

	if user.IsEmailVerified {
		return fmt.Errorf("email is already verified")
	}

	// Get verification record
	verification, err := s.mfaRepo.GetEmailVerification(ctx, userID, code)
	if err != nil {
		return fmt.Errorf("failed to get verification: %w", err)
	}
	if verification == nil {
		return fmt.Errorf("invalid or expired verification code")
	}

	// Mark email as verified
	user.IsEmailVerified = true
	if err := s.userRepo.Update(ctx, user); err != nil {
		return fmt.Errorf("failed to update user: %w", err)
	}

	// Mark verification as used
	_ = s.mfaRepo.MarkEmailVerified(ctx, verification.ID)

	logger.Info("Email verified",
		zap.String("user_id", userID.String()),
		zap.String("email", user.Email),
	)

	return nil
}

// VerifyEmailByToken verifies an email using only the token (for public link verification)
func (s *MFAService) VerifyEmailByToken(ctx context.Context, token string) error {
	// Get verification record by token
	verification, err := s.mfaRepo.GetEmailVerificationByToken(ctx, token)
	if err != nil {
		return fmt.Errorf("failed to get verification: %w", err)
	}
	if verification == nil {
		return fmt.Errorf("invalid or expired verification link")
	}

	// Get user
	user, err := s.userRepo.GetByID(ctx, verification.UserID)
	if err != nil {
		return fmt.Errorf("failed to get user: %w", err)
	}
	if user == nil {
		return fmt.Errorf("user not found")
	}

	if user.IsEmailVerified {
		return fmt.Errorf("email is already verified")
	}

	// Mark email as verified
	user.IsEmailVerified = true
	if err := s.userRepo.Update(ctx, user); err != nil {
		return fmt.Errorf("failed to update user: %w", err)
	}

	// Mark verification as used
	_ = s.mfaRepo.MarkEmailVerified(ctx, verification.ID)

	logger.Info("Email verified via link",
		zap.String("user_id", verification.UserID.String()),
		zap.String("email", user.Email),
	)

	return nil
}

// GetEmailVerificationStatus returns the email verification status
func (s *MFAService) GetEmailVerificationStatus(ctx context.Context, userID uuid.UUID) (*models.EmailVerificationStatus, error) {
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}
	if user == nil {
		return nil, fmt.Errorf("user not found")
	}

	status := &models.EmailVerificationStatus{
		Email:      user.Email,
		IsVerified: user.IsEmailVerified,
	}

	// Check for pending verification
	pending, _ := s.mfaRepo.GetPendingEmailVerification(ctx, userID)
	if pending != nil {
		status.PendingVerification = true
		status.ExpiresAt = &pending.ExpiresAt
	}

	return status, nil
}

// Helper functions

func (s *MFAService) generateNumericCode(length int) (string, error) {
	const digits = "0123456789"
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("crypto/rand.Read failed: %w", err)
	}
	for i := range b {
		b[i] = digits[int(b[i])%len(digits)]
	}
	return string(b), nil
}

func (s *MFAService) generateBackupCode() (string, error) {
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("crypto/rand.Read failed: %w", err)
	}
	// Format: XXXX-XXXX (8 chars total)
	code := strings.ToUpper(base32.StdEncoding.EncodeToString(b)[:8])
	return code[:4] + "-" + code[4:], nil
}

func (s *MFAService) hashCode(code string) string {
	// Normalize
	code = strings.ToUpper(strings.ReplaceAll(code, "-", ""))
	hash := sha256.Sum256([]byte(code))
	return hex.EncodeToString(hash[:])
}

func (s *MFAService) generateSecureToken(length int) (string, error) {
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("crypto/rand.Read failed: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// verifyPassword uses argon2 to verify password
func verifyPassword(password, hash string) bool {
	parts := strings.Split(hash, "$")
	if len(parts) != 6 {
		return false
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false
	}

	expectedHash, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return false
	}

	computedHash := argon2.IDKey([]byte(password), salt, 3, 64*1024, 4, 32)
	// SECURITY: Use constant-time comparison to prevent timing attacks
	return subtle.ConstantTimeCompare(computedHash, expectedHash) == 1
}
