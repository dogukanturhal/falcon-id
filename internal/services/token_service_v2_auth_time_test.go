// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"testing"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

// TestGenerateAccessTokenV2_PropagatesAuthTime locks the contract that
// v2 (SpiceDB) tokens carry the RFC 9470 §6.1 / OIDC Core §2 auth_time
// claim when the caller supplies it.
//
// The bug fixed in this commit had two pieces working together to
// silently strip auth_time on every v2 mint:
//
//  1. SpiceDBClaims had no AuthTime field — even if the value reached
//     the mint function, there was nowhere to put it on the issued
//     JWT.
//  2. GenerateAccessTokenV2 didn't call fillAuthTimeFromSession the
//     way GenerateAccessTokenWithOptions does, so even after #1 was
//     fixed the value never got pulled from session.AuthenticatedAt.
//
// Result: every v2 token shipped with no auth_time claim → every
// downstream RFC 9470 max_age gate misclassified just-minted sessions
// as "infinitely stale" → infinite redirect loop after fresh re-auth.
// Live repro 2026-05-25: dogukanturhal passkey login on iOS Safari
// completed /webauthn/conditional/complete successfully + minted
// fresh v2 JWT, but the very next /oauth/authorize bounced back to
// /oauth/login on its max_age=300 check.
//
// This test verifies both pieces are wired:
//   - Caller-supplied opts.AuthTime → token claim "auth_time"
//   - Zero opts.AuthTime → claim omitted (json:"...,omitempty")
func TestGenerateAccessTokenV2_PropagatesAuthTime(t *testing.T) {
	cfg := createTestConfig()
	svc := NewTokenService(cfg, new(MockTokenRepository), new(MockTokenUserRepository))

	user := createTestUser()
	sessionID := uuid.New()
	authTime := time.Now().Add(-30 * time.Second).Unix()

	token, err := svc.GenerateAccessTokenV2(context.Background(), user, sessionID, []string{"user"}, TokenGenerationOptions{
		RealmID:  models.DefaultRealmID,
		AuthTime: authTime,
	})
	require.NoError(t, err)
	require.NotEmpty(t, token)

	parsed, err := jwt.Parse(token, func(_ *jwt.Token) (interface{}, error) {
		return []byte(cfg.JWTSecret), nil
	})
	require.NoError(t, err)
	require.True(t, parsed.Valid)
	mapClaims, ok := parsed.Claims.(jwt.MapClaims)
	require.True(t, ok)

	raw, present := mapClaims["auth_time"]
	require.True(t, present, "v2 token MUST carry auth_time claim when opts.AuthTime is supplied — RFC 9470 max_age gates depend on it")
	require.IsType(t, float64(0), raw, "auth_time should be a JSON number")
	assert.Equal(t, float64(authTime), raw)
}

// TestGenerateAccessTokenV2_OmitsAuthTimeWhenZero locks the
// json:",omitempty" side: when the caller has no auth_time (and no
// sessionRepo wired to back-fill from session.AuthenticatedAt), the
// claim is absent rather than zero. RFC 9470 §6.1 specifies that
// auth_time when present is a number; absent and zero have different
// semantics for downstream consumers (absent = "unknown", treated as
// "fail closed" by RequireFreshAuth).
func TestGenerateAccessTokenV2_OmitsAuthTimeWhenZero(t *testing.T) {
	cfg := createTestConfig()
	svc := NewTokenService(cfg, new(MockTokenRepository), new(MockTokenUserRepository))

	token, err := svc.GenerateAccessTokenV2(context.Background(), createTestUser(), uuid.New(), []string{"user"}, TokenGenerationOptions{
		RealmID: models.DefaultRealmID,
		// AuthTime omitted; sessionRepo unwired → fillAuthTimeFromSession is a no-op
	})
	require.NoError(t, err)
	parsed, err := jwt.Parse(token, func(_ *jwt.Token) (interface{}, error) {
		return []byte(cfg.JWTSecret), nil
	})
	require.NoError(t, err)
	mapClaims, ok := parsed.Claims.(jwt.MapClaims)
	require.True(t, ok)

	_, present := mapClaims["auth_time"]
	assert.False(t, present, "auth_time MUST be omitted (not 0) when unknown — RFC 9470 §6.1 distinguishes absent from epoch-zero")
}
