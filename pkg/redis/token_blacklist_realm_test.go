// SPDX-License-Identifier: AGPL-3.0-or-later

package redis

import (
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// newTestTokenBlacklist creates a TokenBlacklist backed by a fresh miniredis instance.
func newTestTokenBlacklist(t *testing.T) (*TokenBlacklist, *miniredis.Miniredis) {
	t.Helper()

	mr, err := miniredis.Run()
	require.NoError(t, err, "failed to start miniredis")

	cfg := &Config{
		URL:             "redis://" + mr.Addr(),
		MaxRetries:      1,
		MinIdleConns:    1,
		MaxIdleConns:    2,
		ConnMaxLifetime: time.Minute,
		DialTimeout:     2 * time.Second,
		ReadTimeout:     2 * time.Second,
		WriteTimeout:    2 * time.Second,
	}

	client, err := NewClient(cfg, zap.NewNop())
	require.NoError(t, err, "failed to create Redis client")

	bl := NewTokenBlacklist(client, "iam")
	t.Cleanup(func() {
		_ = client.Close()
		mr.Close()
	})

	return bl, mr
}

// ─── realmTokenKey ───────────────────────────────────────────────────────────

func TestRealmTokenKey_IncludesRealmAndJTI(t *testing.T) {
	bl := &TokenBlacklist{prefix: "iam"}
	realmID := uuid.MustParse("11111111-1111-1111-1111-111111111111")
	jti := "tok-abc-123"

	key := bl.realmTokenKey(realmID, jti)

	assert.Equal(t,
		"iam:realm:11111111-1111-1111-1111-111111111111:blacklist:token:tok-abc-123",
		key,
	)
	assert.Contains(t, key, realmID.String())
	assert.Contains(t, key, jti)
}

func TestRealmTokenKey_DifferentRealmsProduceDifferentKeys(t *testing.T) {
	bl := &TokenBlacklist{prefix: "iam"}
	realm1 := uuid.New()
	realm2 := uuid.New()
	jti := "shared-jti"

	key1 := bl.realmTokenKey(realm1, jti)
	key2 := bl.realmTokenKey(realm2, jti)

	assert.NotEqual(t, key1, key2,
		"the same JTI blacklisted in two realms must produce different cache keys")
}

func TestRealmTokenKey_SameInputsProduceSameKey(t *testing.T) {
	bl := &TokenBlacklist{prefix: "iam"}
	realmID := uuid.New()
	jti := "deterministic-jti"

	assert.Equal(t,
		bl.realmTokenKey(realmID, jti),
		bl.realmTokenKey(realmID, jti),
		"realm token key must be deterministic",
	)
}

func TestRealmTokenKey_DoesNotCollideWithFlatKey(t *testing.T) {
	bl := &TokenBlacklist{prefix: "iam"}
	realmID := uuid.New()
	jti := "some-jti"

	realmKey := bl.realmTokenKey(realmID, jti)
	flatKey := bl.tokenKey(jti)

	assert.NotEqual(t, realmKey, flatKey,
		"realm-scoped token key must be distinct from the legacy flat key")
}

func TestRealmTokenKey_PrefixVariants(t *testing.T) {
	tests := []struct {
		prefix string
	}{
		{"iam"},
		{"hexxlock"},
		{"custom:ns"},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.prefix, func(t *testing.T) {
			bl := &TokenBlacklist{prefix: tc.prefix}
			key := bl.realmTokenKey(uuid.New(), "some-jti")
			assert.Contains(t, key, tc.prefix,
				"prefix %q must appear in the realm-scoped token key", tc.prefix)
		})
	}
}

// ─── realmUserTokensKey ──────────────────────────────────────────────────────

func TestRealmUserTokensKey_IncludesRealmAndUserID(t *testing.T) {
	bl := &TokenBlacklist{prefix: "iam"}
	realmID := uuid.MustParse("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
	userID := uuid.MustParse("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb")

	key := bl.realmUserTokensKey(realmID, userID)

	assert.Equal(t,
		"iam:realm:aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa:blacklist:user:bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
		key,
	)
	assert.Contains(t, key, realmID.String())
	assert.Contains(t, key, userID.String())
}

func TestRealmUserTokensKey_DifferentRealmsProduceDifferentKeys(t *testing.T) {
	bl := &TokenBlacklist{prefix: "iam"}
	realm1 := uuid.New()
	realm2 := uuid.New()
	userID := uuid.New()

	key1 := bl.realmUserTokensKey(realm1, userID)
	key2 := bl.realmUserTokensKey(realm2, userID)

	assert.NotEqual(t, key1, key2,
		"same userID in different realms must produce different set keys")
}

func TestRealmUserTokensKey_DoesNotCollideWithFlatKey(t *testing.T) {
	bl := &TokenBlacklist{prefix: "iam"}
	realmID := uuid.New()
	userID := uuid.New()

	realmKey := bl.realmUserTokensKey(realmID, userID)
	flatKey := bl.userTokensKey(userID)

	assert.NotEqual(t, realmKey, flatKey,
		"realm-scoped user tokens key must not collide with the flat key")
}

// ─── Cross-realm isolation (both key types together) ─────────────────────────

func TestTokenBlacklistRealmKeys_NoCrossRealmCollision(t *testing.T) {
	bl := &TokenBlacklist{prefix: "iam"}
	realmA := uuid.New()
	realmB := uuid.New()
	userID := uuid.New()
	jti := "token-id-xyz"

	tokenKeyA := bl.realmTokenKey(realmA, jti)
	tokenKeyB := bl.realmTokenKey(realmB, jti)
	assert.NotEqual(t, tokenKeyA, tokenKeyB)

	userKeyA := bl.realmUserTokensKey(realmA, userID)
	userKeyB := bl.realmUserTokensKey(realmB, userID)
	assert.NotEqual(t, userKeyA, userKeyB)
}

// ─── Integration: realm key exists in Redis after Blacklist call ──────────────
// This test validates that the key format is correct and usable with a real
// Redis client — calling miniredis.Exists with the generated key must return
// true after the value is stored.

func TestRealmTokenKey_RedisRoundTrip(t *testing.T) {
	bl, mr := newTestTokenBlacklist(t)

	realmID := uuid.New()
	jti := "integration-jti"

	// Derive the realm-scoped key manually and store a value directly to
	// simulate what a future realm-aware Blacklist method would do.
	realmKey := bl.realmTokenKey(realmID, jti)
	err := bl.client.Redis().Set(
		t.Context(),
		realmKey,
		"logout",
		5*time.Minute,
	).Err()
	require.NoError(t, err)

	// The key must be visible in miniredis under the exact generated name.
	assert.True(t, mr.Exists(realmKey),
		"realm-scoped token key must be stored and retrievable from Redis")

	// The legacy flat key must remain unaffected.
	flatKey := bl.tokenKey(jti)
	assert.False(t, mr.Exists(flatKey),
		"writing to the realm-scoped key must not pollute the flat key namespace")
}
