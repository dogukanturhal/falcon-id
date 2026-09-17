// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/internal/repositories"
)

// These tests lock the contract that MFA disable accepts an EMPTY password
// when the call is authorized by the RFC 9470 freshAuth middleware on the
// route. The OTP code remains the canonical anti-takeover signal. Bug
// closed 2026-05-25: passkey-only and social-SSO users were locked out of
// disabling MFA because MFADisableRequest required password as a non-empty
// string, even though /mfa/disable/* is already step-up gated by freshAuth.

func TestDisableMFA_EmptyPasswordSucceeds_RFC9470GateAlreadyPassed(t *testing.T) {
	userID := uuid.New()
	emailType := "email"
	validEmailCode := "555555"
	validEmailCodeHash := hashTestCode(validEmailCode)
	emailCodeID := uuid.New()

	// Passkey-only user: no PasswordHash, but MFA is enabled via email.
	// This mirrors the production breakage where social-SSO + passkey
	// users could not disable MFA at all.
	user := &models.User{
		ID:               userID,
		TenantID:         uuid.New(),
		Username:         "passkey-only",
		Email:            "passkey-only@example.com",
		PasswordHash:     nil,
		MFAEnabled:       true,
		MFAEmailEnabled:  true,
		MFAType:          &emailType,
		IsActive:         true,
	}

	svc, mockUserRepo, mockMFARepo, _, _ := createTestMFAService()
	mockUserRepo.On("GetByID", mock.Anything, userID).Return(user, nil)
	mockMFARepo.On("GetActiveMFAEmailCode", mock.Anything, userID).
		Return(&repositories.MFAEmailCode{
			ID:       emailCodeID,
			UserID:   userID,
			CodeHash: validEmailCodeHash,
		}, nil)
	mockMFARepo.On("MarkMFAEmailCodeUsed", mock.Anything, emailCodeID).Return(nil)
	mockUserRepo.On("HasNonPrimaryMFAFactor", mock.Anything, userID).Return(false, nil)
	mockUserRepo.On("Update", mock.Anything, mock.AnythingOfType("*models.User")).Return(nil)
	mockMFARepo.On("DeleteAllRecoveryCodes", mock.Anything, userID).Return(nil)

	// Empty password — the freshAuth middleware on the route is the gate.
	err := svc.DisableMFA(context.Background(), userID, "", validEmailCode)

	require.NoError(t, err, "empty password MUST succeed when freshAuth has already authorized the call")
}

func TestDisableTOTPOnly_EmptyPasswordSucceeds(t *testing.T) {
	userID := uuid.New()
	secret := "JBSWY3DPEHPK3PXP" // base32; not actually verified — we use the email fallback path

	// User with TOTP enabled + email enabled so VerifyMFACode falls
	// through to the email branch (we control the email code hash).
	emailType := "email"
	validEmailCode := "777777"
	validEmailCodeHash := hashTestCode(validEmailCode)
	emailCodeID := uuid.New()

	user := &models.User{
		ID:              userID,
		TenantID:        uuid.New(),
		Username:        "passkey-only",
		Email:           "passkey-only@example.com",
		PasswordHash:    nil,
		MFAEnabled:      true,
		MFATOTPEnabled:  true,
		MFASecret:       &secret,
		MFAEmailEnabled: true,
		MFAType:         &emailType,
		IsActive:        true,
	}

	svc, mockUserRepo, mockMFARepo, _, _ := createTestMFAService()
	mockUserRepo.On("GetByID", mock.Anything, userID).Return(user, nil)
	mockMFARepo.On("GetActiveMFAEmailCode", mock.Anything, userID).
		Return(&repositories.MFAEmailCode{
			ID:       emailCodeID,
			UserID:   userID,
			CodeHash: validEmailCodeHash,
		}, nil)
	mockMFARepo.On("MarkMFAEmailCodeUsed", mock.Anything, emailCodeID).Return(nil)
	mockUserRepo.On("Update", mock.Anything, mock.AnythingOfType("*models.User")).Return(nil)

	err := svc.DisableTOTPOnly(context.Background(), userID, "", validEmailCode)

	require.NoError(t, err, "DisableTOTPOnly must accept empty password for passkey-only users")
}

func TestDisableEmailMFAOnly_EmptyPasswordSucceeds(t *testing.T) {
	userID := uuid.New()
	emailType := "email"
	validEmailCode := "999999"
	validEmailCodeHash := hashTestCode(validEmailCode)
	emailCodeID := uuid.New()

	user := &models.User{
		ID:              userID,
		TenantID:        uuid.New(),
		Username:        "passkey-only",
		Email:           "passkey-only@example.com",
		PasswordHash:    nil,
		MFAEnabled:      true,
		MFAEmailEnabled: true,
		MFAType:         &emailType,
		IsActive:        true,
	}

	svc, mockUserRepo, mockMFARepo, _, _ := createTestMFAService()
	mockUserRepo.On("GetByID", mock.Anything, userID).Return(user, nil)
	mockMFARepo.On("GetActiveMFAEmailCode", mock.Anything, userID).
		Return(&repositories.MFAEmailCode{
			ID:       emailCodeID,
			UserID:   userID,
			CodeHash: validEmailCodeHash,
		}, nil)
	mockMFARepo.On("MarkMFAEmailCodeUsed", mock.Anything, emailCodeID).Return(nil)
	mockUserRepo.On("Update", mock.Anything, mock.AnythingOfType("*models.User")).Return(nil)
	// Email is the only remaining factor; disabling it triggers full
	// MFA cleanup (DeleteAllRecoveryCodes).
	mockMFARepo.On("DeleteAllRecoveryCodes", mock.Anything, userID).Return(nil)

	err := svc.DisableEmailMFAOnly(context.Background(), userID, "", validEmailCode)

	require.NoError(t, err, "DisableEmailMFAOnly must accept empty password for passkey-only users")
}

// Empty-everything (no password, no code) — relies solely on the
// freshAuth route gate. This is the canonical accounts.hexxlock.com
// flow after the user has just completed step-up via WebAuthn or OTP.
// The frontend passes `disableEmailMfa('')` / `disableTotp('')` —
// empty string for both fields. See apps/accounts/src/components/
// security/mfa-section.tsx.
func TestDisableMFA_EmptyCodeAndPassword_StepUpAlone(t *testing.T) {
	userID := uuid.New()
	emailType := "email"

	user := &models.User{
		ID:              userID,
		TenantID:        uuid.New(),
		Username:        "post-stepup",
		Email:           "post-stepup@example.com",
		PasswordHash:    nil,
		MFAEnabled:      true,
		MFAEmailEnabled: true,
		MFAType:         &emailType,
		IsActive:        true,
	}

	svc, mockUserRepo, mockMFARepo, _, _ := createTestMFAService()
	mockUserRepo.On("GetByID", mock.Anything, userID).Return(user, nil)
	mockUserRepo.On("HasNonPrimaryMFAFactor", mock.Anything, userID).Return(false, nil)
	mockUserRepo.On("Update", mock.Anything, mock.AnythingOfType("*models.User")).Return(nil)
	mockMFARepo.On("DeleteAllRecoveryCodes", mock.Anything, userID).Return(nil)

	err := svc.DisableMFA(context.Background(), userID, "", "")
	require.NoError(t, err, "empty password AND empty code MUST succeed when freshAuth route gate already authorized the call")
}

func TestDisableTOTPOnly_EmptyCodeAndPassword(t *testing.T) {
	userID := uuid.New()
	secret := "JBSWY3DPEHPK3PXP"
	totpType := "totp"

	user := &models.User{
		ID:             userID,
		TenantID:       uuid.New(),
		Username:       "post-stepup",
		Email:          "post-stepup@example.com",
		PasswordHash:   nil,
		MFAEnabled:     true,
		MFATOTPEnabled: true,
		MFASecret:      &secret,
		MFAType:        &totpType,
		IsActive:       true,
	}

	svc, mockUserRepo, mockMFARepo, _, _ := createTestMFAService()
	mockUserRepo.On("GetByID", mock.Anything, userID).Return(user, nil)
	mockUserRepo.On("Update", mock.Anything, mock.AnythingOfType("*models.User")).Return(nil)
	// TOTP is the only factor; disabling triggers full MFA cleanup.
	mockMFARepo.On("DeleteAllRecoveryCodes", mock.Anything, userID).Return(nil)

	err := svc.DisableTOTPOnly(context.Background(), userID, "", "")
	require.NoError(t, err, "DisableTOTPOnly must accept empty everything when step-up gate already authorized")
}

func TestDisableEmailMFAOnly_EmptyCodeAndPassword(t *testing.T) {
	userID := uuid.New()
	emailType := "email"

	user := &models.User{
		ID:              userID,
		TenantID:        uuid.New(),
		Username:        "post-stepup",
		Email:           "post-stepup@example.com",
		PasswordHash:    nil,
		MFAEnabled:      true,
		MFAEmailEnabled: true,
		MFAType:         &emailType,
		IsActive:        true,
	}

	svc, mockUserRepo, mockMFARepo, _, _ := createTestMFAService()
	mockUserRepo.On("GetByID", mock.Anything, userID).Return(user, nil)
	mockUserRepo.On("Update", mock.Anything, mock.AnythingOfType("*models.User")).Return(nil)
	mockMFARepo.On("DeleteAllRecoveryCodes", mock.Anything, userID).Return(nil)

	err := svc.DisableEmailMFAOnly(context.Background(), userID, "", "")
	require.NoError(t, err, "DisableEmailMFAOnly must accept empty everything when step-up gate already authorized")
}

func TestDisableMFA_SuppliedCodeStillVerified(t *testing.T) {
	// Defense-in-depth: when callers DO supply a code (legacy
	// clients), an INVALID one must still fail hard. VerifyMFACode
	// fans out across backup → TOTP → email; for an unknown 6-digit
	// code all three branches return invalid. We mock the negative
	// returns and confirm we surface "invalid MFA code".
	userID := uuid.New()
	emailType := "email"

	user := &models.User{
		ID:              userID,
		TenantID:        uuid.New(),
		Username:        "withcode",
		Email:           "withcode@example.com",
		PasswordHash:    nil,
		MFAEnabled:      true,
		MFAEmailEnabled: true,
		MFAType:         &emailType,
		IsActive:        true,
	}

	svc, mockUserRepo, mockMFARepo, _, _ := createTestMFAService()
	mockUserRepo.On("GetByID", mock.Anything, userID).Return(user, nil)
	// All factor verification paths return "no match" so VerifyMFACode
	// returns false.
	mockMFARepo.On("GetUnusedRecoveryCodes", mock.Anything, userID).
		Return([]repositories.RecoveryCode{}, nil).Maybe()
	mockMFARepo.On("GetActiveMFAEmailCode", mock.Anything, userID).
		Return(nil, nil).Maybe()

	err := svc.DisableMFA(context.Background(), userID, "", "999999")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid MFA code", "supplied wrong code must fail hard")
}

func TestDisableMFA_SuppliedPasswordStillVerified(t *testing.T) {
	// Defense-in-depth: when callers DO supply a password (legacy
	// clients, ops break-glass), it MUST still be verified hard.
	userID := uuid.New()
	correctPassword := "TheRealPassword!1"
	correctHash := makeTestPasswordHash(correctPassword)
	emailType := "email"

	user := &models.User{
		ID:              userID,
		TenantID:        uuid.New(),
		Username:        "withpassword",
		Email:           "withpassword@example.com",
		PasswordHash:    &correctHash,
		MFAEnabled:      true,
		MFAEmailEnabled: true,
		MFAType:         &emailType,
		IsActive:        true,
	}

	svc, mockUserRepo, _, _, _ := createTestMFAService()
	mockUserRepo.On("GetByID", mock.Anything, userID).Return(user, nil)

	// Wrong password supplied — must fail BEFORE OTP verify, before update.
	err := svc.DisableMFA(context.Background(), userID, "WrongPassword!", "123456")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "password", "wrong password must surface as password-related error")
}
