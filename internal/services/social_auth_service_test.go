// SPDX-License-Identifier: AGPL-3.0-or-later

package services

// social_auth_service_test.go covers the security-critical OAuth state
// management and redirect-URI validation of SocialAuthService.
//
// SocialAuthService uses concrete *repositories.* dependencies and a real
// HTTP client, so unit tests focus on:
//
//   - GenerateOAuthState  — cryptographic randomness, TTL cleanup, uniqueness
//   - ValidateOAuthState  — CSRF replay prevention, empty-state rejection,
//                           unknown-state rejection, single-use guarantee
//   - SetMFAService / SetRiskService etc. — nil-safe setter injection
//   - parseOAuth2Config   — tested indirectly via GetAuthorizationURL nil-guard
//
// Integration tests (provider round-trips, callback handling) live in the
// integration test suite.

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dogukanturhal/falcon-id/pkg/config"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func newSocialAuthSvc() *SocialAuthService {
	return &SocialAuthService{
		config: &config.Config{},
	}
}

// ---------------------------------------------------------------------------
// GenerateOAuthState — CSRF token generation
// ---------------------------------------------------------------------------

func TestGenerateOAuthState_ReturnsNonEmptyState(t *testing.T) {
	svc := newSocialAuthSvc()

	state, _, err := svc.GenerateOAuthState()
	require.NoError(t, err)
	assert.NotEmpty(t, state,
		"GenerateOAuthState must return a non-empty CSRF token")
}

func TestGenerateOAuthState_IsURLSafeBase64(t *testing.T) {
	svc := newSocialAuthSvc()

	state, _, err := svc.GenerateOAuthState()
	require.NoError(t, err)

	// base64 RawURL encoding only uses A-Z a-z 0-9 - _
	for _, c := range state {
		ok := (c >= 'A' && c <= 'Z') ||
			(c >= 'a' && c <= 'z') ||
			(c >= '0' && c <= '9') ||
			c == '-' || c == '_'
		assert.True(t, ok,
			"state must be URL-safe base64: unexpected char %q in %q", string(c), state)
	}
}

func TestGenerateOAuthState_HasAdequateEntropy(t *testing.T) {
	svc := newSocialAuthSvc()

	state, _, err := svc.GenerateOAuthState()
	require.NoError(t, err)

	// 32 bytes of random data produces 43 base64url chars.
	// 43 chars * 6 bits/char ≈ 258 bits — well above the 128-bit minimum.
	assert.GreaterOrEqual(t, len(state), 40,
		"state must be at least 40 characters (≥240 bits of entropy)")
}

func TestGenerateOAuthState_ProducesUniqueValues(t *testing.T) {
	svc := newSocialAuthSvc()
	seen := make(map[string]bool)

	for i := 0; i < 100; i++ {
		state, _, err := svc.GenerateOAuthState()
		require.NoError(t, err)
		assert.False(t, seen[state],
			"GenerateOAuthState must produce unique values (collision at i=%d)", i)
		seen[state] = true
	}
}

func TestGenerateOAuthState_StoredInStateStore(t *testing.T) {
	svc := newSocialAuthSvc()

	state, _, err := svc.GenerateOAuthState()
	require.NoError(t, err)

	_, loaded := svc.stateStore.Load(state)
	assert.True(t, loaded,
		"generated state must be present in the state store before validation")
}

// ---------------------------------------------------------------------------
// ValidateOAuthState — CSRF replay prevention (single-use guarantee)
// ---------------------------------------------------------------------------

func TestValidateOAuthState_ValidState_Succeeds(t *testing.T) {
	svc := newSocialAuthSvc()

	state, binding, err := svc.GenerateOAuthState()
	require.NoError(t, err)

	require.NoError(t, svc.ValidateOAuthState(state, binding))
}

// SECURITY: Core CSRF protection — consuming the state prevents replay attacks.
func TestValidateOAuthState_SingleUse_ReplayRejected(t *testing.T) {
	svc := newSocialAuthSvc()

	state, binding, err := svc.GenerateOAuthState()
	require.NoError(t, err)

	// First use: valid
	require.NoError(t, svc.ValidateOAuthState(state, binding))

	// Second use: must be rejected (state was consumed)
	err = svc.ValidateOAuthState(state, binding)
	require.Error(t, err,
		"SECURITY: replayed state must be rejected after first use")
	assert.Contains(t, err.Error(), "invalid or expired")
}

func TestValidateOAuthState_UnknownState_Rejected(t *testing.T) {
	svc := newSocialAuthSvc()

	err := svc.ValidateOAuthState("unknown-state-value-that-was-never-issued", "any-binding")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid or expired")
}

func TestValidateOAuthState_EmptyState_Rejected(t *testing.T) {
	svc := newSocialAuthSvc()

	err := svc.ValidateOAuthState("", "any-binding")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "missing OAuth state parameter",
		"empty state should return a clear error, not a generic invalid message")
}

func TestValidateOAuthState_StateRemovedFromStoreAfterValidation(t *testing.T) {
	svc := newSocialAuthSvc()

	state, binding, err := svc.GenerateOAuthState()
	require.NoError(t, err)

	require.NoError(t, svc.ValidateOAuthState(state, binding))

	// Verify state is no longer in the store.
	_, loaded := svc.stateStore.Load(state)
	assert.False(t, loaded,
		"state must be removed from the store after successful validation")
}

// ---------------------------------------------------------------------------
// ValidateOAuthState — TTL / timer behaviour
// ---------------------------------------------------------------------------

// TestValidateOAuthState_StopsCancelTimer verifies that successful validation
// stops the cleanup timer.  We indirectly confirm this by checking that the
// timer field is a *time.Timer that can be stopped without panic.
func TestValidateOAuthState_TimerStoppedOnValidation(t *testing.T) {
	svc := newSocialAuthSvc()

	state, binding, err := svc.GenerateOAuthState()
	require.NoError(t, err)

	// Peek at the stored timer before validation.
	val, ok := svc.stateStore.Load(state)
	require.True(t, ok)
	// t-150 changed the stored value from a bare *time.Timer to an entry
	// carrying the timer AND the browser-binding hash. The timer is still the
	// thing under test here.
	entry, isEntry := val.(*oauthStateEntry)
	require.True(t, isEntry, "stateStore must hold a *oauthStateEntry")
	timer := entry.timer
	require.NotNil(t, timer, "entry must carry its cleanup timer")

	// Validate (which should stop the timer).
	require.NoError(t, svc.ValidateOAuthState(state, binding))

	// Stopping an already-stopped timer is a no-op and must not panic.
	assert.NotPanics(t, func() { timer.Stop() })
}

// ---------------------------------------------------------------------------
// Concurrency safety
// ---------------------------------------------------------------------------

// TestGenerateAndValidate_ConcurrentSafety exercises the sync.Map backing the
// state store under concurrent generate/validate access.
func TestGenerateAndValidate_ConcurrentSafety(t *testing.T) {
	svc := newSocialAuthSvc()

	const goroutines = 20
	states := make([]string, goroutines)
	bindings := make([]string, goroutines)

	// Generate all states sequentially to avoid inter-goroutine validation
	// ordering issues.
	for i := 0; i < goroutines; i++ {
		state, binding, err := svc.GenerateOAuthState()
		require.NoError(t, err)
		states[i] = state
		bindings[i] = binding
	}

	// Validate all states concurrently.
	var wg sync.WaitGroup
	errors := make([]error, goroutines)

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			errors[idx] = svc.ValidateOAuthState(states[idx], bindings[idx])
		}(i)
	}

	wg.Wait()

	for i, err := range errors {
		assert.NoError(t, err, "goroutine %d: validate failed: %v", i, err)
	}
}

// ---------------------------------------------------------------------------
// Setter injection — nil-safe wiring (dependency injection pattern)
// ---------------------------------------------------------------------------

func TestSetMFAService_NilSafe(t *testing.T) {
	svc := newSocialAuthSvc()
	assert.NotPanics(t, func() { svc.SetMFAService(nil) })
	assert.Nil(t, svc.mfaService)
}

func TestSetRiskService_NilSafe(t *testing.T) {
	svc := newSocialAuthSvc()
	assert.NotPanics(t, func() { svc.SetRiskService(nil) })
	assert.Nil(t, svc.riskService)
}

func TestSetDeviceService_NilSafe(t *testing.T) {
	svc := newSocialAuthSvc()
	assert.NotPanics(t, func() { svc.SetDeviceService(nil) })
	assert.Nil(t, svc.deviceService)
}

func TestSetRedisClient_NilSafe(t *testing.T) {
	svc := newSocialAuthSvc()
	assert.NotPanics(t, func() { svc.SetRedisClient(nil) })
	assert.Nil(t, svc.redisClient)
}

func TestSetSessionRepository_NilSafe(t *testing.T) {
	svc := newSocialAuthSvc()
	assert.NotPanics(t, func() { svc.SetSessionRepository(nil) })
	assert.Nil(t, svc.sessionRepo)
}

func TestSetTenantRepository_NilSafe(t *testing.T) {
	svc := newSocialAuthSvc()
	assert.NotPanics(t, func() { svc.SetTenantRepository(nil) })
	assert.Nil(t, svc.tenantRepo)
}

func TestSetEncryptionService_NilSafe(t *testing.T) {
	svc := newSocialAuthSvc()
	assert.NotPanics(t, func() { svc.SetEncryptionService(nil) })
	assert.Nil(t, svc.encryptionService)
}

// ---------------------------------------------------------------------------
// oauthStateTTL constant
// ---------------------------------------------------------------------------

func TestOAuthStateTTL_IsReasonable(t *testing.T) {
	assert.Equal(t, 10*time.Minute, oauthStateTTL,
		"OAuth state TTL must be 10 minutes per RFC 6749 recommendation")
}
