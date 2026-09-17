// SPDX-License-Identifier: AGPL-3.0-or-later

package redis

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ─── realmSessionKey ─────────────────────────────────────────────────────────

func TestRealmSessionKey_IncludesRealmAndSessionID(t *testing.T) {
	cache := &SessionCache{prefix: "iam"}
	realmID := uuid.MustParse("11111111-1111-1111-1111-111111111111")
	sessionID := uuid.MustParse("22222222-2222-2222-2222-222222222222")

	key := cache.realmSessionKey(realmID, sessionID)

	assert.Equal(t,
		"iam:realm:11111111-1111-1111-1111-111111111111:session:22222222-2222-2222-2222-222222222222",
		key,
	)
	assert.Contains(t, key, realmID.String())
	assert.Contains(t, key, sessionID.String())
}

func TestRealmSessionKey_DifferentRealmsProduceDifferentKeys(t *testing.T) {
	cache := &SessionCache{prefix: "iam"}
	realm1 := uuid.New()
	realm2 := uuid.New()
	sessionID := uuid.New()

	key1 := cache.realmSessionKey(realm1, sessionID)
	key2 := cache.realmSessionKey(realm2, sessionID)

	assert.NotEqual(t, key1, key2,
		"same sessionID in different realms must produce different cache keys")
}

func TestRealmSessionKey_SameRealmSameSessionProducesSameKey(t *testing.T) {
	cache := &SessionCache{prefix: "iam"}
	realmID := uuid.New()
	sessionID := uuid.New()

	assert.Equal(t,
		cache.realmSessionKey(realmID, sessionID),
		cache.realmSessionKey(realmID, sessionID),
		"identical inputs must produce a deterministic key",
	)
}

func TestRealmSessionKey_DoesNotCollideWithFlatKey(t *testing.T) {
	cache := &SessionCache{prefix: "iam"}
	realmID := uuid.New()
	sessionID := uuid.New()

	realmKey := cache.realmSessionKey(realmID, sessionID)
	flatKey := cache.sessionKey(sessionID)

	assert.NotEqual(t, realmKey, flatKey,
		"realm-scoped key must be distinct from the legacy flat key")
}

// ─── realmUserSessionsKey ────────────────────────────────────────────────────

func TestRealmUserSessionsKey_IncludesRealmAndUserID(t *testing.T) {
	cache := &SessionCache{prefix: "iam"}
	realmID := uuid.MustParse("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
	userID := uuid.MustParse("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb")

	key := cache.realmUserSessionsKey(realmID, userID)

	assert.Equal(t,
		"iam:realm:aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa:user:bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb:sessions",
		key,
	)
	assert.Contains(t, key, realmID.String())
	assert.Contains(t, key, userID.String())
}

func TestRealmUserSessionsKey_DifferentRealmsProduceDifferentKeys(t *testing.T) {
	cache := &SessionCache{prefix: "iam"}
	realm1 := uuid.New()
	realm2 := uuid.New()
	userID := uuid.New()

	key1 := cache.realmUserSessionsKey(realm1, userID)
	key2 := cache.realmUserSessionsKey(realm2, userID)

	assert.NotEqual(t, key1, key2,
		"same userID in different realms must produce different set keys")
}

func TestRealmUserSessionsKey_DoesNotCollideWithFlatKey(t *testing.T) {
	cache := &SessionCache{prefix: "iam"}
	realmID := uuid.New()
	userID := uuid.New()

	realmKey := cache.realmUserSessionsKey(realmID, userID)
	flatKey := cache.userSessionsKey(userID)

	assert.NotEqual(t, realmKey, flatKey,
		"realm-scoped user-sessions key must be distinct from the legacy flat key")
}

// ─── SetSessionData dual-write ───────────────────────────────────────────────

func TestSetSessionData_DualWrite_BothKeysPopulated(t *testing.T) {
	cache, mr := newTestSessionCache(t)
	ctx := context.Background()

	sessionID, data := makeSessionData()
	// makeSessionData already sets a non-zero RealmID.
	require.False(t, data.RealmID == uuid.Nil, "test fixture must have a non-zero RealmID")

	require.NoError(t, cache.SetSessionData(ctx, sessionID, data))

	// Legacy flat key must be readable.
	got, err := cache.GetSessionData(ctx, sessionID)
	require.NoError(t, err)
	require.NotNil(t, got, "legacy flat key must be populated after SetSessionData")
	assert.Equal(t, data.UserID, got.UserID)

	// Realm-scoped key must also exist in Redis.
	realmKey := cache.realmSessionKey(data.RealmID, sessionID)
	exists := mr.Exists(realmKey)
	assert.True(t, exists, "realm-scoped key must be written during SetSessionData")
}

func TestSetSessionData_ZeroRealmID_OnlyFlatKeyWritten(t *testing.T) {
	cache, mr := newTestSessionCache(t)
	ctx := context.Background()

	sessionID, data := makeSessionData()
	data.RealmID = uuid.Nil // suppress realm-scoped write

	require.NoError(t, cache.SetSessionData(ctx, sessionID, data))

	// Legacy flat key must still be present.
	got, err := cache.GetSessionData(ctx, sessionID)
	require.NoError(t, err)
	require.NotNil(t, got)

	// Realm-scoped key must NOT exist because RealmID is the zero UUID.
	realmKey := cache.realmSessionKey(uuid.Nil, sessionID)
	assert.False(t, mr.Exists(realmKey),
		"realm-scoped key must not be written when RealmID is zero")
}

// ─── DeleteSessionData cleans both keys ─────────────────────────────────────

func TestDeleteSessionData_RemovesRealmScopedKey(t *testing.T) {
	cache, mr := newTestSessionCache(t)
	ctx := context.Background()

	sessionID, data := makeSessionData()
	require.False(t, data.RealmID == uuid.Nil)

	require.NoError(t, cache.SetSessionData(ctx, sessionID, data))

	realmKey := cache.realmSessionKey(data.RealmID, sessionID)
	require.True(t, mr.Exists(realmKey), "realm key must exist before delete")

	require.NoError(t, cache.DeleteSessionData(ctx, sessionID, data.UserID))

	// Legacy flat key gone.
	got, err := cache.GetSessionData(ctx, sessionID)
	require.NoError(t, err)
	assert.Nil(t, got, "flat session key must be removed after DeleteSessionData")

	// Realm-scoped key also gone.
	assert.False(t, mr.Exists(realmKey),
		"realm-scoped key must be removed by DeleteSessionData")
}

// ─── Key format stability (prefix variation) ─────────────────────────────────

func TestRealmSessionKey_PrefixIsIncluded(t *testing.T) {
	tests := []struct {
		prefix string
	}{
		{"iam"},
		{"hexxlock"},
		{"custom:prefix"},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.prefix, func(t *testing.T) {
			cache := &SessionCache{prefix: tc.prefix}
			realmID := uuid.New()
			sessionID := uuid.New()

			key := cache.realmSessionKey(realmID, sessionID)
			assert.Contains(t, key, tc.prefix,
				"prefix %q must appear in the realm-scoped key", tc.prefix)
		})
	}
}

// ─── Realm-scoped user-sessions TTL is set ───────────────────────────────────

func TestSetSessionData_RealmUserSessionsKey_HasTTL(t *testing.T) {
	cache, mr := newTestSessionCache(t)
	ctx := context.Background()

	sessionID, data := makeSessionData()

	require.NoError(t, cache.SetSessionData(ctx, sessionID, data))

	realmSetKey := cache.realmUserSessionsKey(data.RealmID, data.UserID)
	ttl := mr.TTL(realmSetKey)
	assert.Greater(t, ttl, time.Duration(0),
		"realm user-sessions set key must have a positive TTL")
}
