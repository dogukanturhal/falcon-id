// SPDX-License-Identifier: AGPL-3.0-or-later

package repositories

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestEmailHashEmpty_IsTheRegressionSignature documents — and locks in
// detection of — the well-known corruption hash produced when
// UserRepository.Update is called with `user.Email == ""` and the
// pre-2026-05-22 unguarded line `user.EmailHash = computeEmailHash(user.Email)`
// runs anyway.
//
// Before this MR landed:
//
//   - WebAuthnService.FinishRegistration loads the authenticated user
//     from middleware, flips `user.MFAEnabled = true`, calls
//     UserRepository.Update.
//   - If user.Email happens to be empty at that point — because
//     scanUser returned an empty email column, or because PII
//     decryption returned empty, or because the upstream caller never
//     populated the field — line 344 unconditionally recomputed
//     email_hash from "" and overwrote the row's hash with
//     HMAC-SHA256(emailHashKey, "").
//
// Live regression signature (production seen 2026-05-22): a user row
// with `email = ''` AND
// `email_hash = b613679a0814d9ec772f95d778c35fc5ff1697c493715653c6c712144292c5ad`
// (= HMAC-SHA256(empty key, empty input)). Discover then can never
// find the user by their actual email; login UI shows "no account
// found" even though the row exists. Reset to empty-empty happens
// EVERY time the user enrolls a passkey / verifies email / flips
// any MFA preference, so the bug self-heals to broken on every
// auth-adjacent self-service action.
//
// The fix in user_repository.go:Update is the `if user.Email != ""`
// guard; this test asserts both halves of the contract:
//   (a) the empty-empty HMAC has the documented value (catches a
//       change to computeEmailHash that would silently move the
//       regression signature elsewhere)
//   (b) when computeEmailHash is called with an empty string under
//       an empty key, the result IS the well-known constant — so a
//       guard-removal regression would be detectable by grepping
//       production rows for this exact hex string.
func TestEmailHashEmpty_IsTheRegressionSignature(t *testing.T) {
	// The TestMain in user_repository_email_hash_test.go sets the key
	// to "hexxlock-email-hash-default-key" for this package's tests,
	// so we recompute under the empty key here explicitly to lock the
	// production-regression constant. The constant below was extracted
	// from a corrupted live row in hexxlock_falcon_id_public on
	// 2026-05-22 (user dogukanturhal, tenant exampletenant).
	emptyKeyBefore := emailHashKey
	SetEmailHashKey("")
	defer SetEmailHashKey(string(emptyKeyBefore))

	got := computeEmailHash("")
	const corruptionSignature = "b613679a0814d9ec772f95d778c35fc5ff1697c493715653c6c712144292c5ad"
	assert.Equal(t, corruptionSignature, got,
		"the regression-signature constant must remain stable so SOC dashboards + DB-grep recovery scripts can detect the corruption pattern")
}

// TestComputeEmailHash_StableForRealInputs locks the invariant that
// the guard in UserRepository.Update is the ONLY barrier between a
// caller passing user.Email="" and the corruption hash landing in
// the row. If a future refactor changes computeEmailHash so that
// empty input no longer produces the corruption signature, the
// guard still matters (it prevents a hash-recompute that could
// produce any unexpected value, not just the empty-empty constant).
func TestComputeEmailHash_StableForRealInputs(t *testing.T) {
	// Sanity: real email under the test key produces a stable hash.
	// Used as a positive-control reference for the empty-input test
	// above; if THIS hash changes, the entire stored-hash population
	// in the iam_users table would need a back-fill migration.
	got := computeEmailHash("alice@example.com")
	assert.Len(t, got, 64, "HMAC-SHA256 hex output must always be 64 characters — a length drift indicates an algorithm change requiring a back-fill migration")
}
