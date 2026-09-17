// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// stubAuthTimeSource implements idpSessionAuthTimeSource for tests
// without dragging in the real pkg/redis.SessionCache.
type stubAuthTimeSource struct {
	byID map[uuid.UUID]int64
	err  error
}

func (s *stubAuthTimeSource) GetIdpSessionAuthTime(_ context.Context, id uuid.UUID) (int64, bool, error) {
	if s.err != nil {
		return 0, false, s.err
	}
	v, ok := s.byID[id]
	return v, ok, nil
}

// TestGenerateTokens_EmitsAuthTimeFromIdpSession locks the contract
// that /oauth/token-minted access tokens carry the RFC 9470 §6.1 /
// OIDC Core §2 `auth_time` claim sourced from IdpSessionData.AuthTime.
//
// THE bug this guards: pre-fix OAuthProviderService.generateTokens
// emitted NO auth_time claim on any /oauth/token mint path. The
// earlier !242/!243 fixes covered token_service.GenerateAccessTokenV2
// (the /api/v1/auth/login path) but the OAuth /oauth/token path uses
// THIS separate raw-jwt.MapClaims construction. Result: every BFF-
// exchanged access token came out with no auth_time → OptionalAuth
// CurrentUser.AuthTime=0 → RequireFreshAuth failed closed on every
// step-up-protected mutation (passkey delete, mfa/disable/totp,
// mfa/disable/email, password change) EVEN AFTER fresh password+OTP
// re-auth. The 6th layer of the loop, closed 2026-05-25.
func TestGenerateTokens_EmitsAuthTimeFromIdpSession(t *testing.T) {
	svc := newTestOAuthService(t)

	idpSessionID := uuid.New()
	authTime := time.Now().Add(-45 * time.Second).Unix()
	svc.sessionCache = &stubAuthTimeSource{byID: map[uuid.UUID]int64{idpSessionID: authTime}}

	resp, err := svc.generateTokens(
		context.Background(),
		authzCodeClient([]string{"openid"}),
		subjectUser(),
		[]string{"openid", "profile"},
		nil,
		nil,
		[]string{"pwd"},
		&idpSessionID,
	)
	require.NoError(t, err)

	claims := decodeJWTUnverified(t, resp.AccessToken)
	raw, ok := claims["auth_time"]
	require.True(t, ok, "auth_time MUST be present on user-bound /oauth/token output — RFC 9470 §6.1")
	gotF, isNum := raw.(float64)
	require.True(t, isNum, "auth_time must be a JSON number, got %T", raw)
	assert.Equal(t, authTime, int64(gotF), "auth_time should match IdpSessionData.AuthTime")
}

// TestGenerateTokens_FallsBackToNowWhenSessionMissing locks the
// nil-safe / TTL-expired path. Missing IdP session → fall back to
// now() so token issuance doesn't fail. Blocking on session-not-found
// would surface as "OAuth callback fails after successful login" —
// worse UX than slightly-imprecise auth_time.
func TestGenerateTokens_FallsBackToNowWhenSessionMissing(t *testing.T) {
	svc := newTestOAuthService(t)
	svc.sessionCache = &stubAuthTimeSource{byID: map[uuid.UUID]int64{}}

	missingID := uuid.New()
	resp, err := svc.generateTokens(
		context.Background(),
		authzCodeClient([]string{"openid"}),
		subjectUser(),
		[]string{"openid"},
		nil, nil, nil,
		&missingID,
	)
	require.NoError(t, err)

	claims := decodeJWTUnverified(t, resp.AccessToken)
	raw, present := claims["auth_time"]
	require.True(t, present, "auth_time MUST still be present (fallback to now()) when sessionCache misses")
	now := time.Now().Unix()
	got := int64(raw.(float64))
	assert.GreaterOrEqual(t, got, now-5)
	assert.LessOrEqual(t, got, now+5)
}

// TestGenerateTokens_FallsBackToNowOnCacheError — Redis-unavailable
// MUST NOT fail the token mint. Operator visibility via the cache-
// layer error log; token endpoint stays UP.
func TestGenerateTokens_FallsBackToNowOnCacheError(t *testing.T) {
	svc := newTestOAuthService(t)
	svc.sessionCache = &stubAuthTimeSource{err: errors.New("redis unavailable")}

	id := uuid.New()
	resp, err := svc.generateTokens(
		context.Background(),
		authzCodeClient([]string{"openid"}),
		subjectUser(),
		[]string{"openid"},
		nil, nil, nil,
		&id,
	)
	require.NoError(t, err, "generateTokens must not fail on cache error")
	claims := decodeJWTUnverified(t, resp.AccessToken)
	_, present := claims["auth_time"]
	assert.True(t, present, "auth_time MUST be present (now-fallback) on cache error")
}

// TestGenerateTokens_SessionCacheUnwired locks the path where the
// SetSessionCacheAuthTimeSource binding was never called (legacy
// builds, partial deployments, unit tests bootstrapping minimal
// fixtures). Must still emit auth_time via now()-fallback rather
// than panicking or omitting the claim.
func TestGenerateTokens_SessionCacheUnwired(t *testing.T) {
	svc := newTestOAuthService(t)
	svc.sessionCache = nil

	id := uuid.New()
	resp, err := svc.generateTokens(
		context.Background(),
		authzCodeClient([]string{"openid"}),
		subjectUser(),
		[]string{"openid"},
		nil, nil, nil,
		&id,
	)
	require.NoError(t, err)
	claims := decodeJWTUnverified(t, resp.AccessToken)
	_, present := claims["auth_time"]
	assert.True(t, present, "auth_time MUST be present even when sessionCache unwired")
}
