// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dogukanturhal/falcon-id/pkg/keys"
)

func signWithService(t *testing.T, svc *OAuthProviderService) (string, string) {
	t.Helper()
	key, kid := svc.signingKey()
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{"sub": "u", "exp": time.Now().Add(time.Hour).Unix()})
	tok.Header["kid"] = kid
	s, err := tok.SignedString(key)
	require.NoError(t, err)
	return s, kid
}

func TestOAuthProviderService_FollowsKeyRotation(t *testing.T) {
	now := time.Now()
	km, err := keys.NewInMemoryKeyManager(keys.Options{
		PublishDelay:      75 * time.Minute,
		RetireAfter:       24 * time.Hour,
		KeyLifetime:       10 * 24 * time.Hour,
		RotationThreshold: 7 * 24 * time.Hour,
	}, func() time.Time { return now })
	require.NoError(t, err)
	ctx := context.Background()
	require.NoError(t, km.Initialize(ctx))

	svc := newTestOAuthProviderService(t, nil, nil)
	svc.SetKeyManager(km)

	oldTok, oldKID := signWithService(t, svc)
	_, err = svc.ValidateAccessToken(oldTok)
	require.NoError(t, err)

	// Enter the rotation window, publish the pending key, then activate it.
	now = now.Add(4 * 24 * time.Hour)
	require.NoError(t, km.Maintain(ctx))
	now = now.Add(76 * time.Minute)
	require.NoError(t, km.Maintain(ctx))

	newTok, newKID := signWithService(t, svc)
	assert.NotEqual(t, oldKID, newKID, "tokens minted after activation must carry the new kid")

	_, err = svc.ValidateAccessToken(newTok)
	assert.NoError(t, err, "token signed by the new key validates")
	_, err = svc.ValidateAccessToken(oldTok)
	assert.NoError(t, err, "token signed by the old (rotated) key still validates")
}

func TestMintAPIKeyToken_FollowsKeyRotation(t *testing.T) {
	now := time.Now()
	km, err := keys.NewInMemoryKeyManager(keys.Options{
		PublishDelay:      75 * time.Minute,
		RetireAfter:       24 * time.Hour,
		KeyLifetime:       10 * 24 * time.Hour,
		RotationThreshold: 7 * 24 * time.Hour,
	}, func() time.Time { return now })
	require.NoError(t, err)
	ctx := context.Background()
	require.NoError(t, km.Initialize(ctx))

	svc := newTestOAuthProviderService(t, nil, nil)
	svc.SetKeyManager(km)

	params := APIKeyTokenParams{
		TenantID: uuid.New(), KeyID: uuid.New(), Access: "read",
		Audience: "https://api.example.test", TTL: time.Minute,
	}
	oldTok, err := svc.MintAPIKeyToken(params)
	require.NoError(t, err)
	_, oldKID := svc.signingKey()

	now = now.Add(4 * 24 * time.Hour)
	require.NoError(t, km.Maintain(ctx))
	now = now.Add(76 * time.Minute)
	require.NoError(t, km.Maintain(ctx))

	newTok, err := svc.MintAPIKeyToken(params)
	require.NoError(t, err)
	_, newKID := svc.signingKey()
	require.NotEqual(t, oldKID, newKID)

	parsed, err := jwt.Parse(newTok, svc.verifyKeyFunc, jwt.WithValidMethods([]string{"RS256"}))
	require.NoError(t, err, "API key token minted after rotation verifies")
	assert.Equal(t, newKID, parsed.Header["kid"], "minted after rotation carries the new kid")

	old, err := jwt.Parse(oldTok, svc.verifyKeyFunc, jwt.WithValidMethods([]string{"RS256"}))
	require.NoError(t, err, "pre-rotation API key token still verifies")
	assert.Equal(t, oldKID, old.Header["kid"])
}
