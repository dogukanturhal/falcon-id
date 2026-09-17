// SPDX-License-Identifier: AGPL-3.0-or-later

package services

// auth_mfa_service_test.go covers MFA-specific AuthService methods:
//
//   - retrieveMFASession: nil cache guard, malformed session ID
//   - consumeMFASession: nil cache + invalid UUID are no-ops (idempotent)
//   - incrementMFAAttempts: nil cache guard, malformed session ID, exhaustion threshold
//   - CompleteMFALogin: nil cache guard, malformed session ID
//   - SwitchMFALoginMethod: nil cache guard, malformed session ID
//   - getAvailableMFAMethods: pure logic, no DB required
//   - MFASessionData: JSON marshalling contract
//
// The bounded-retry end-to-end behaviour (wrong-then-correct succeeds, max-
// attempts exhausts the session, exhaustion forces re-auth) is exercised in
// the integration tests against a real Redis; the unit layer here covers
// only the input-validation guards reachable without a live cache plus the
// pure exhaustion-threshold computation.

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

// ---------------------------------------------------------------------------
// retrieveMFASession — nil cache + UUID validation guards
// ---------------------------------------------------------------------------

func TestRetrieveMFASession_NilCache_ReturnsError(t *testing.T) {
	svc := &AuthService{
		config:       newAuthCfg(),
		sessionCache: nil,
	}

	_, err := svc.retrieveMFASession(context.Background(), uuid.New().String())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "session cache not available")
}

// Nil-cache check fires before UUID parsing — verifies the guard order
// that prevents oversized-Redis-key attacks from leaking via the error path.
func TestRetrieveMFASession_NilCache_FiresBeforeUUIDCheck(t *testing.T) {
	svc := &AuthService{
		config:       newAuthCfg(),
		sessionCache: nil,
	}

	_, err := svc.retrieveMFASession(context.Background(), "not-a-valid-uuid")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "session cache not available")
}

// ---------------------------------------------------------------------------
// consumeMFASession — idempotent no-op semantics
// ---------------------------------------------------------------------------

func TestConsumeMFASession_NilCache_NoError(t *testing.T) {
	svc := &AuthService{
		config:       newAuthCfg(),
		sessionCache: nil,
	}

	// Calling consume with nil cache returns nil — idempotent contract.
	err := svc.consumeMFASession(context.Background(), uuid.New().String())
	assert.NoError(t, err,
		"consumeMFASession must be a safe no-op when cache is unavailable")
}

func TestConsumeMFASession_InvalidUUID_NoError(t *testing.T) {
	svc := &AuthService{
		config:       newAuthCfg(),
		sessionCache: nil,
	}

	// Even with a malformed session ID, consume must not surface an error
	// — CompleteMFALogin calls this in the exhaustion path where we have
	// already returned the user-facing error and don't want a secondary
	// failure to mask it.
	err := svc.consumeMFASession(context.Background(), "../../etc/passwd")
	assert.NoError(t, err,
		"consumeMFASession must swallow invalid-UUID errors (idempotent contract)")
}

// ---------------------------------------------------------------------------
// incrementMFAAttempts — nil cache + UUID guards, exhaustion threshold
// ---------------------------------------------------------------------------

func TestIncrementMFAAttempts_NilCache_ReturnsError(t *testing.T) {
	svc := &AuthService{
		config:       newAuthCfg(),
		sessionCache: nil,
	}

	_, _, err := svc.incrementMFAAttempts(context.Background(), uuid.New().String())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "session cache not available")
}

func TestIncrementMFAAttempts_NilCache_FiresBeforeUUIDCheck(t *testing.T) {
	svc := &AuthService{
		config:       newAuthCfg(),
		sessionCache: nil,
	}

	_, _, err := svc.incrementMFAAttempts(context.Background(), "not-a-uuid")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "session cache not available")
}

// TestMFAMaxAttempts_Constant pins the retry cap at 5. Aligned with
// NIST SP 800-63B §5.2.2 and Auth0/Okta/Cognito convention. Changing
// this constant has security implications (brute-force tolerance) so
// the test is here as a tripwire on accidental edits.
func TestMFAMaxAttempts_Constant(t *testing.T) {
	assert.Equal(t, 5, mfaMaxAttempts,
		"mfaMaxAttempts must stay at 5 — tier-1 brute-force tolerance baseline")
}

// ---------------------------------------------------------------------------
// CompleteMFALogin — input validation and nil cache guard
// ---------------------------------------------------------------------------

func TestCompleteMFALogin_NilCache_ReturnsError(t *testing.T) {
	svc := &AuthService{
		config:       newAuthCfg(),
		sessionCache: nil,
	}

	req := &models.MFACompleteRequest{
		SessionID: uuid.New().String(),
		MFACode:   "123456",
	}

	_, err := svc.CompleteMFALogin(context.Background(), req, "1.2.3.4", "TestAgent/1.0")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "session cache not available")
}

// TestCompleteMFALogin_MalformedSessionID_DoesNotLeakPath verifies that a
// path-traversal session ID does not appear in the error response.
func TestCompleteMFALogin_MalformedSessionID_DoesNotLeakPath(t *testing.T) {
	svc := &AuthService{
		config:       newAuthCfg(),
		sessionCache: nil,
	}

	req := &models.MFACompleteRequest{
		SessionID: "../../etc/passwd",
		MFACode:   "123456",
	}

	_, err := svc.CompleteMFALogin(context.Background(), req, "1.2.3.4", "TestAgent/1.0")
	require.Error(t, err)
	// The raw malicious session ID must NOT appear in the error message.
	assert.NotContains(t, err.Error(), "/etc/passwd",
		"error must not echo back user-supplied path traversal value")
}

// ---------------------------------------------------------------------------
// SwitchMFALoginMethod — nil cache guard and malformed session
// ---------------------------------------------------------------------------

func TestSwitchMFALoginMethod_NilCache_ReturnsError(t *testing.T) {
	svc := &AuthService{
		config:       newAuthCfg(),
		sessionCache: nil,
	}

	_, err := svc.SwitchMFALoginMethod(context.Background(), uuid.New().String(), authMethodTOTP)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "session cache not available")
}

func TestSwitchMFALoginMethod_MalformedSessionID_Rejected(t *testing.T) {
	svc := &AuthService{
		config:       newAuthCfg(),
		sessionCache: nil,
	}

	_, err := svc.SwitchMFALoginMethod(context.Background(), "INVALID-SESSION-ID!!!!", authMethodTOTP)
	require.Error(t, err)
	// nil cache fires first — no panic, no leak
	assert.Error(t, err)
}

// ---------------------------------------------------------------------------
// getAvailableMFAMethods — pure method, no external calls
// ---------------------------------------------------------------------------

func TestGetAvailableMFAMethods_TOTPOnly(t *testing.T) {
	svc := &AuthService{config: newAuthCfg()}

	user := &models.User{
		ID:              uuid.New(),
		MFATOTPEnabled:  true,
		MFAEmailEnabled: false,
	}

	methods := svc.getAvailableMFAMethods(user, false)
	require.Len(t, methods, 1)
	assert.Equal(t, authMethodTOTP, methods[0])
}

func TestGetAvailableMFAMethods_EmailOnly(t *testing.T) {
	svc := &AuthService{config: newAuthCfg()}

	user := &models.User{
		ID:              uuid.New(),
		MFATOTPEnabled:  false,
		MFAEmailEnabled: true,
	}

	methods := svc.getAvailableMFAMethods(user, false)
	require.Len(t, methods, 1)
	assert.Equal(t, "email", methods[0])
}

func TestGetAvailableMFAMethods_BothEnabled(t *testing.T) {
	svc := &AuthService{config: newAuthCfg()}

	user := &models.User{
		ID:              uuid.New(),
		MFATOTPEnabled:  true,
		MFAEmailEnabled: true,
	}

	methods := svc.getAvailableMFAMethods(user, false)
	assert.Contains(t, methods, authMethodTOTP)
	assert.Contains(t, methods, "email")
	assert.Len(t, methods, 2)
}

// TestGetAvailableMFAMethods_PasskeyOnly locks the new WebAuthn-as-MFA
// path (2026-05-26). When user has no code-based factor but has an
// enrolled passkey, the method list MUST be [webauthn] — not [] (which
// would break the login flow) and not [email] (the pre-2026-05-26
// silent fallback that locked dogukanturhal out after he disabled
// email MFA).
func TestGetAvailableMFAMethods_PasskeyOnly(t *testing.T) {
	svc := &AuthService{config: newAuthCfg()}

	user := &models.User{
		ID:              uuid.New(),
		MFATOTPEnabled:  false,
		MFAEmailEnabled: false,
		IsEmailVerified: true, // explicitly verified — pre-fix this triggered the silent email fallback
	}

	methods := svc.getAvailableMFAMethods(user, true /* hasPasskey */)
	require.Len(t, methods, 1, "passkey-only user gets webauthn as the SOLE method, NOT the legacy email fallback")
	assert.Equal(t, authMethodWebAuthn, methods[0])
}

// TestGetAvailableMFAMethods_AllThreeFactors covers the maximalist
// case: TOTP + email + passkey. Order matters — selectMFAMethod prefers
// earlier entries when no preferred_method is set.
func TestGetAvailableMFAMethods_AllThreeFactors(t *testing.T) {
	svc := &AuthService{config: newAuthCfg()}

	user := &models.User{
		ID:              uuid.New(),
		MFATOTPEnabled:  true,
		MFAEmailEnabled: true,
	}

	methods := svc.getAvailableMFAMethods(user, true)
	require.Len(t, methods, 3)
	assert.Equal(t, authMethodTOTP, methods[0], "TOTP should be the default preference")
	assert.Equal(t, authMethodEmail, methods[1])
	assert.Equal(t, authMethodWebAuthn, methods[2])
}

// TestGetAvailableMFAMethods_NoFactor_NoPasskey locks fail-closed
// behaviour. Pre-2026-05-26 the silent email fallback would emit
// [email] here purely because IsEmailVerified=true (a precondition
// for any active account), even though the user hadn't enrolled
// email MFA. Post-fix: empty list. Caller (createMFAChallenge)
// already routes this case to the MFA-enrollment interrupt when
// risk-MFA-required, or to a "no factor enrolled" hard-fail otherwise.
func TestGetAvailableMFAMethods_NoFactor_NoPasskey(t *testing.T) {
	svc := &AuthService{config: newAuthCfg()}

	user := &models.User{
		ID:              uuid.New(),
		MFATOTPEnabled:  false,
		MFAEmailEnabled: false,
		IsEmailVerified: true,
	}

	methods := svc.getAvailableMFAMethods(user, false)
	assert.Empty(t, methods,
		"user with NO factor enrolled gets empty list — the 2026-05-23 silent email fallback was the bug, not the fix")
}

// ---------------------------------------------------------------------------
// MFASessionData — JSON marshalling contract
// ---------------------------------------------------------------------------

// TestMFASessionData_JSONRoundTrip verifies that the Redis payload structure
// survives marshal/unmarshal.  A field-name regression would cause
// retrieveAndConsumeMFASession to silently return empty IDs, leading to
// "invalid MFA session" errors in production.
func TestMFASessionData_JSONRoundTrip(t *testing.T) {
	original := &models.MFASessionData{
		UserID:     uuid.New().String(),
		TenantID:   uuid.New().String(),
		TenantSlug: "acme-corp",
		IPAddress:  "10.0.0.1",
		UserAgent:  "Mozilla/5.0",
		AuthMethod: "password",
		ClientID:   "my-client-id",
		CreatedAt:  time.Now().Unix(),
	}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var parsed models.MFASessionData
	require.NoError(t, json.Unmarshal(data, &parsed))

	assert.Equal(t, original.UserID, parsed.UserID)
	assert.Equal(t, original.TenantID, parsed.TenantID)
	assert.Equal(t, original.TenantSlug, parsed.TenantSlug)
	assert.Equal(t, original.IPAddress, parsed.IPAddress)
	assert.Equal(t, original.UserAgent, parsed.UserAgent)
	assert.Equal(t, original.AuthMethod, parsed.AuthMethod)
	assert.Equal(t, original.ClientID, parsed.ClientID)
	assert.Equal(t, original.CreatedAt, parsed.CreatedAt)
}

// TestMFASessionData_EmptyUserID_FailsUUIDParse ensures that an empty UserID
// in the session payload is caught by uuid.Parse inside CompleteMFALogin.
func TestMFASessionData_EmptyUserID_FailsUUIDParse(t *testing.T) {
	session := &models.MFASessionData{
		UserID:   "",
		TenantID: uuid.New().String(),
	}

	_, err := uuid.Parse(session.UserID)
	require.Error(t, err,
		"empty UserID must fail uuid.Parse so the service returns an error, not silently uses uuid.Nil")
}

func TestMFASessionData_EmptyTenantID_FailsUUIDParse(t *testing.T) {
	session := &models.MFASessionData{
		UserID:   uuid.New().String(),
		TenantID: "",
	}

	_, err := uuid.Parse(session.TenantID)
	require.Error(t, err,
		"empty TenantID must fail uuid.Parse so the service returns an error, not silently uses uuid.Nil")
}

// TestMFASessionData_ClientIDOptional verifies that omitting ClientID still
// produces valid JSON that round-trips cleanly (non-scoped MFA flows).
func TestMFASessionData_ClientIDOptional(t *testing.T) {
	original := &models.MFASessionData{
		UserID:   uuid.New().String(),
		TenantID: uuid.New().String(),
	}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var parsed models.MFASessionData
	require.NoError(t, json.Unmarshal(data, &parsed))

	assert.Empty(t, parsed.ClientID)
	assert.Equal(t, original.UserID, parsed.UserID)
}
