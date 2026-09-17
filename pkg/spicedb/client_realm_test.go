// SPDX-License-Identifier: AGPL-3.0-or-later

package spicedb

import (
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

const testCRMModule = "crm_module"

// newTestClient returns a zero-value Client suitable for testing pure key-generation
// helper methods that do not require a live SpiceDB or Redis connection.
func newTestClient() *Client {
	return &Client{}
}

// ─── generateRealmCacheKey ────────────────────────────────────────────────────

func TestGenerateRealmCacheKey_IncludesAllSegments(t *testing.T) {
	c := newTestClient()
	realmID := uuid.MustParse("11111111-1111-1111-1111-111111111111")
	tenantID := uuid.MustParse("22222222-2222-2222-2222-222222222222")
	userID := uuid.MustParse("33333333-3333-3333-3333-333333333333")
	objectType := testCRMModule
	objectID := spicedbObjectDefault
	permission := spicedbPermView

	key := c.generateRealmCacheKey(realmID, tenantID, userID, objectType, objectID, permission)

	assert.Contains(t, key, "spicedb")
	assert.Contains(t, key, "realm")
	assert.Contains(t, key, realmID.String())
	assert.Contains(t, key, tenantID.String())
	assert.Contains(t, key, userID.String())
	assert.Contains(t, key, objectType)
	assert.Contains(t, key, objectID)
	assert.Contains(t, key, permission)
}

func TestGenerateRealmCacheKey_ExactFormat(t *testing.T) {
	c := newTestClient()
	realmID := uuid.MustParse("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
	tenantID := uuid.MustParse("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb")
	userID := uuid.MustParse("cccccccc-cccc-cccc-cccc-cccccccccccc")

	key := c.generateRealmCacheKey(realmID, tenantID, userID, "tenant", spicedbObjectDefault, spicedbPermView)

	expected := "spicedb:realm:aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa:" +
		"check:bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb:" +
		"cccccccc-cccc-cccc-cccc-cccccccccccc:tenant:default:view"
	assert.Equal(t, expected, key)
}

func TestGenerateRealmCacheKey_DifferentRealmsProduceDifferentKeys(t *testing.T) {
	c := newTestClient()
	realm1 := uuid.New()
	realm2 := uuid.New()
	tenantID := uuid.New()
	userID := uuid.New()

	key1 := c.generateRealmCacheKey(realm1, tenantID, userID, "tenant", spicedbObjectDefault, spicedbPermView)
	key2 := c.generateRealmCacheKey(realm2, tenantID, userID, "tenant", spicedbObjectDefault, spicedbPermView)

	assert.NotEqual(t, key1, key2,
		"same check tuple in different realms must produce different cache keys")
}

func TestGenerateRealmCacheKey_DoesNotCollideWithFlatKey(t *testing.T) {
	c := newTestClient()
	realmID := uuid.New()
	tenantID := uuid.New()
	userID := uuid.New()
	objectType := testCRMModule
	objectID := spicedbObjectDefault
	permission := spicedbPermView

	realmKey := c.generateRealmCacheKey(realmID, tenantID, userID, objectType, objectID, permission)
	flatKey := c.generateCacheKey(tenantID, userID, objectType, objectID, permission)

	assert.NotEqual(t, realmKey, flatKey,
		"realm-scoped cache key must not collide with the legacy flat cache key")
}

func TestGenerateRealmCacheKey_Deterministic(t *testing.T) {
	c := newTestClient()
	realmID := uuid.New()
	tenantID := uuid.New()
	userID := uuid.New()

	key1 := c.generateRealmCacheKey(realmID, tenantID, userID, "tenant", "t1", "edit")
	key2 := c.generateRealmCacheKey(realmID, tenantID, userID, "tenant", "t1", "edit")

	assert.Equal(t, key1, key2, "identical inputs must always produce the same key")
}

func TestGenerateRealmCacheKey_DifferentPermissionsProduceDifferentKeys(t *testing.T) {
	c := newTestClient()
	realmID := uuid.New()
	tenantID := uuid.New()
	userID := uuid.New()

	viewKey := c.generateRealmCacheKey(realmID, tenantID, userID, "tenant", spicedbObjectDefault, spicedbPermView)
	editKey := c.generateRealmCacheKey(realmID, tenantID, userID, "tenant", spicedbObjectDefault, "edit")

	assert.NotEqual(t, viewKey, editKey,
		"different permissions within the same realm must produce different keys")
}

func TestGenerateRealmCacheKey_StartsWithSpicedbRealm(t *testing.T) {
	c := newTestClient()
	key := c.generateRealmCacheKey(uuid.New(), uuid.New(), uuid.New(), "obj", "id", "perm")

	assert.True(t,
		strings.HasPrefix(key, "spicedb:realm:"),
		"realm-scoped cache key must start with 'spicedb:realm:'; got: %s", key,
	)
}

// ─── Cross-realm isolation (flat key vs realm key) ───────────────────────────

func TestSpiceDBCacheKeys_NoCrossRealmCollision(t *testing.T) {
	c := newTestClient()
	tenantID := uuid.New()
	userID := uuid.New()
	objectType := testCRMModule
	objectID := spicedbObjectDefault
	permission := spicedbPermView

	// Many realms, same payload — all keys must be distinct.
	realms := []uuid.UUID{uuid.New(), uuid.New(), uuid.New()}
	keys := make(map[string]struct{}, len(realms))
	for _, r := range realms {
		k := c.generateRealmCacheKey(r, tenantID, userID, objectType, objectID, permission)
		_, collision := keys[k]
		assert.False(t, collision, "realm key collision detected for realm %s", r)
		keys[k] = struct{}{}
	}

	// Flat key must also not appear in the realm-key set.
	flatKey := c.generateCacheKey(tenantID, userID, objectType, objectID, permission)
	_, flatCollision := keys[flatKey]
	assert.False(t, flatCollision,
		"flat cache key must not collide with any realm-scoped cache key")
}
