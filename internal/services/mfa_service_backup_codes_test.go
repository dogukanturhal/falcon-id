// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// Tests EnsureBackupCodesGenerated — the idempotent helper that
// auto-generates backup codes on first MFA enrollment across every
// factor type (TOTP / Email / WebAuthn / Push). Locks the contract
// that wired callers can call it unconditionally without rotating an
// existing recovery set.
//
// Bug this guards: pre-Phase-B (2026-05-26) only TOTP enrollment
// auto-generated backup codes. Users who enrolled email-only or
// passkey-only silently had ZERO recovery options. Live trigger:
// dogukanturhal locked out 2026-05-25 after disabling email MFA on
// a passkey-only account with no backup codes.

func TestEnsureBackupCodesGenerated_NoExistingCodes_GeneratesFreshSet(t *testing.T) {
	svc, _, mockMFARepo, _, _ := createTestMFAService()
	userID := uuid.New()

	mockMFARepo.On("GetUnusedRecoveryCodesCount", mock.Anything, userID).Return(0, nil)
	mockMFARepo.On("CreateRecoveryCodes", mock.Anything, userID, mock.AnythingOfType("[]string")).Return(nil)

	codes, generated, err := svc.EnsureBackupCodesGenerated(context.Background(), userID)

	require.NoError(t, err)
	assert.True(t, generated, "first-time enrollment MUST surface generated=true so the caller surfaces codes to the user")
	assert.NotEmpty(t, codes, "freshly-generated codes MUST be returned plaintext — hashed at rest and unrecoverable")
}

func TestEnsureBackupCodesGenerated_ExistingCodes_NoOpRespectsExistingSet(t *testing.T) {
	svc, _, mockMFARepo, _, _ := createTestMFAService()
	userID := uuid.New()

	// User already has 4 unused codes (e.g. from a prior TOTP
	// enrollment). Second factor enrollment (e.g. adding email MFA)
	// must NOT rotate those codes — the user already saved them.
	mockMFARepo.On("GetUnusedRecoveryCodesCount", mock.Anything, userID).Return(4, nil)

	codes, generated, err := svc.EnsureBackupCodesGenerated(context.Background(), userID)

	require.NoError(t, err)
	assert.False(t, generated, "existing recovery set MUST be preserved across factor enrollments")
	assert.Empty(t, codes, "no codes returned when none generated — caller must not surface anything")
	// CreateRecoveryCodes MUST NOT be called.
	mockMFARepo.AssertNotCalled(t, "CreateRecoveryCodes", mock.Anything, mock.Anything, mock.Anything)
}

func TestEnsureBackupCodesGenerated_CountErrorPropagated(t *testing.T) {
	svc, _, mockMFARepo, _, _ := createTestMFAService()
	userID := uuid.New()

	mockMFARepo.On("GetUnusedRecoveryCodesCount", mock.Anything, userID).
		Return(0, errors.New("postgres unavailable"))

	codes, generated, err := svc.EnsureBackupCodesGenerated(context.Background(), userID)

	require.Error(t, err, "DB errors surface to the caller so factor enrollment can decide whether to degrade or fail")
	assert.False(t, generated)
	assert.Nil(t, codes)
}

func TestEnsureBackupCodesGenerated_CreateErrorPropagated(t *testing.T) {
	svc, _, mockMFARepo, _, _ := createTestMFAService()
	userID := uuid.New()

	mockMFARepo.On("GetUnusedRecoveryCodesCount", mock.Anything, userID).Return(0, nil)
	mockMFARepo.On("CreateRecoveryCodes", mock.Anything, userID, mock.AnythingOfType("[]string")).
		Return(errors.New("INSERT failed"))

	codes, generated, err := svc.EnsureBackupCodesGenerated(context.Background(), userID)

	require.Error(t, err)
	assert.False(t, generated)
	assert.Nil(t, codes)
}
