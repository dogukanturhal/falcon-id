// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/pkg/logger"
)

// Onboarding contact verification (EMAIL, not SMS)
//
// The Mearax onboarding wizard mirrors Brevo's UX structure, which has a
// "Add your mobile number" / "Confirm your mobile number" step pair. This
// deployment has NO SMS provider wired (no Twilio/SNS/carrier-webhook
// client anywhere in pkg/config or internal/services) — sending a real
// text message is out of scope and unimplementable honestly here. Rather
// than integrate an SMS vendor (explicitly out of scope) or ship UI copy
// that promises a text the backend never sends, the wizard collects the
// phone number as plain onboarding-profile data and verifies contactability
// by emailing a one-time code to the address already confirmed during
// signup. The frontend step copy says so explicitly ("We'll email you a
// verification code").
//
// This reuses the existing email-MFA primitives (SendEmailMFACode /
// VerifyEmailMFACode: 6-digit numeric code, SHA-256 hashed at rest,
// TTL-bound via config.MFAEmailCodeTTL, constant-time compared) called
// DIRECTLY rather than through the MFAEnabled-gated VerifyMFACode
// dispatcher — a brand-new signup has not enabled MFA and must not be
// forced to in order to finish onboarding. Neither low-level method
// checks the MFAEnabled flag, so this is safe. See
// internal/handlers/onboarding_verify_handler.go for the HTTP layer.

// SendOnboardingVerificationCode emails a one-time code to userID's
// address for the onboarding wizard's contact-verification step.
func (s *MFAService) SendOnboardingVerificationCode(ctx context.Context, userID uuid.UUID) error {
	return s.SendEmailMFACode(ctx, userID)
}

// ConfirmOnboardingVerificationCode verifies a code previously sent by
// SendOnboardingVerificationCode. On success it also best-effort marks the
// user's email as verified — this onboarding step, being delivered by
// email, doubles as proof the user's email address is real and reachable,
// same outcome MFAService.VerifyEmail records for its own (link-based)
// flow. The bookkeeping write is best-effort and logged, not propagated as
// an error: the OTP check itself already succeeded, and onboarding must
// not be blocked by a secondary flag update.
func (s *MFAService) ConfirmOnboardingVerificationCode(ctx context.Context, userID uuid.UUID, code string) (bool, error) {
	valid, err := s.VerifyEmailMFACode(ctx, userID, code)
	if err != nil || !valid {
		return valid, err
	}

	user, getErr := s.userRepo.GetByID(ctx, userID)
	if getErr != nil || user == nil {
		logger.Error("onboarding verification: failed to load user to record email-verified flag",
			zap.String("user_id", userID.String()),
			zap.Error(getErr),
		)
		return true, nil
	}

	if !user.IsEmailVerified {
		user.IsEmailVerified = true
		if updateErr := s.userRepo.Update(ctx, user); updateErr != nil {
			logger.Error("onboarding verification: failed to persist email-verified flag",
				zap.String("user_id", userID.String()),
				zap.Error(updateErr),
			)
		}
	}

	return true, nil
}
