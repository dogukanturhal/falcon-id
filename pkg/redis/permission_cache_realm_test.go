// SPDX-License-Identifier: AGPL-3.0-or-later

package redis

import (
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
)

const (
	testPermCRM   = examplePermCRMContactsRead
	testRoleAdmin = "admin"
)

// newTestPermissionCache creates a PermissionCache using a shared miniredis instance.
// It re-uses newTestSessionCache's miniredis so the whole test binary stays lean.
func newTestPermissionCache(t *testing.T) *PermissionCache {
	t.Helper()

	sessionCache, _ := newTestSessionCache(t)
	pc, err := NewPermissionCache(
		sessionCache.client.Redis(),
		zap.NewNop(),
		DefaultPermissionCacheConfig(),
		"iam",
	)
	if err != nil {
		t.Fatalf("NewPermissionCache: %v", err)
	}
	return pc
}

// ─── realmPermissionCheckKey ─────────────────────────────────────────────────

func TestRealmPermissionCheckKey_IncludesAllSegments(t *testing.T) {
	pc := newTestPermissionCache(t)
	realmID := uuid.MustParse("11111111-1111-1111-1111-111111111111")
	sessionID := uuid.MustParse("22222222-2222-2222-2222-222222222222")
	tenantID := uuid.MustParse("33333333-3333-3333-3333-333333333333")
	permission := testPermCRM

	key := pc.realmPermissionCheckKey(realmID, sessionID, tenantID, permission)

	assert.Contains(t, key, "realm")
	assert.Contains(t, key, realmID.String())
	assert.Contains(t, key, sessionID.String())
	assert.Contains(t, key, tenantID.String())
	// Permission is stored as a hash; verify the key at least contains the perm_check label.
	assert.Contains(t, key, "perm_check")
}

func TestRealmPermissionCheckKey_DifferentRealmsProduceDifferentKeys(t *testing.T) {
	pc := newTestPermissionCache(t)
	realm1 := uuid.New()
	realm2 := uuid.New()
	sessionID := uuid.New()
	tenantID := uuid.New()

	key1 := pc.realmPermissionCheckKey(realm1, sessionID, tenantID, testPermCRM)
	key2 := pc.realmPermissionCheckKey(realm2, sessionID, tenantID, testPermCRM)

	assert.NotEqual(t, key1, key2,
		"identical permission in different realms must produce different cache keys")
}

func TestRealmPermissionCheckKey_DoesNotCollideWithFlatKey(t *testing.T) {
	pc := newTestPermissionCache(t)
	realmID := uuid.New()
	sessionID := uuid.New()
	tenantID := uuid.New()
	permission := testPermCRM

	realmKey := pc.realmPermissionCheckKey(realmID, sessionID, tenantID, permission)
	flatKey := pc.permissionCheckKey(sessionID, tenantID, permission)

	assert.NotEqual(t, realmKey, flatKey,
		"realm-scoped permission check key must not collide with the flat key")
}

func TestRealmPermissionCheckKey_Deterministic(t *testing.T) {
	pc := newTestPermissionCache(t)
	realmID := uuid.New()
	sessionID := uuid.New()
	tenantID := uuid.New()
	permission := "finance:invoices:approve"

	key1 := pc.realmPermissionCheckKey(realmID, sessionID, tenantID, permission)
	key2 := pc.realmPermissionCheckKey(realmID, sessionID, tenantID, permission)

	assert.Equal(t, key1, key2, "same inputs must always produce the same key")
}

// ─── realmRolePermissionsKey ─────────────────────────────────────────────────

func TestRealmRolePermissionsKey_IncludesAllSegments(t *testing.T) {
	pc := newTestPermissionCache(t)
	realmID := uuid.MustParse("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
	tenantID := uuid.MustParse("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb")
	role := testRoleAdmin

	key := pc.realmRolePermissionsKey(realmID, tenantID, role)

	assert.Contains(t, key, "realm")
	assert.Contains(t, key, realmID.String())
	assert.Contains(t, key, tenantID.String())
	assert.Contains(t, key, role)
	assert.Contains(t, key, "permissions")
}

func TestRealmRolePermissionsKey_DifferentRealmsProduceDifferentKeys(t *testing.T) {
	pc := newTestPermissionCache(t)
	realm1 := uuid.New()
	realm2 := uuid.New()
	tenantID := uuid.New()

	key1 := pc.realmRolePermissionsKey(realm1, tenantID, testRoleAdmin)
	key2 := pc.realmRolePermissionsKey(realm2, tenantID, testRoleAdmin)

	assert.NotEqual(t, key1, key2,
		"same role in different realms must produce different keys")
}

func TestRealmRolePermissionsKey_DoesNotCollideWithFlatKey(t *testing.T) {
	pc := newTestPermissionCache(t)
	realmID := uuid.New()
	tenantID := uuid.New()
	role := "editor"

	realmKey := pc.realmRolePermissionsKey(realmID, tenantID, role)
	flatKey := pc.rolePermissionsKey(tenantID, role)

	assert.NotEqual(t, realmKey, flatKey,
		"realm-scoped role permissions key must not collide with the flat key")
}

// ─── realmRoleVersionKey ─────────────────────────────────────────────────────

func TestRealmRoleVersionKey_IncludesAllSegments(t *testing.T) {
	pc := newTestPermissionCache(t)
	realmID := uuid.MustParse("cccccccc-cccc-cccc-cccc-cccccccccccc")
	tenantID := uuid.MustParse("dddddddd-dddd-dddd-dddd-dddddddddddd")

	key := pc.realmRoleVersionKey(realmID, tenantID)

	assert.Contains(t, key, "realm")
	assert.Contains(t, key, realmID.String())
	assert.Contains(t, key, tenantID.String())
	assert.Contains(t, key, "version")
}

func TestRealmRoleVersionKey_DifferentRealmsProduceDifferentKeys(t *testing.T) {
	pc := newTestPermissionCache(t)
	realm1 := uuid.New()
	realm2 := uuid.New()
	tenantID := uuid.New()

	key1 := pc.realmRoleVersionKey(realm1, tenantID)
	key2 := pc.realmRoleVersionKey(realm2, tenantID)

	assert.NotEqual(t, key1, key2,
		"same tenantID in different realms must produce different version keys")
}

func TestRealmRoleVersionKey_DoesNotCollideWithFlatKey(t *testing.T) {
	pc := newTestPermissionCache(t)
	realmID := uuid.New()
	tenantID := uuid.New()

	realmKey := pc.realmRoleVersionKey(realmID, tenantID)
	flatKey := pc.roleVersionKey(tenantID)

	assert.NotEqual(t, realmKey, flatKey,
		"realm-scoped version key must not collide with the flat key")
}

// ─── Cross-realm isolation (all three key types) ─────────────────────────────

func TestPermissionCacheRealmKeys_NoCrossRealmCollision(t *testing.T) {
	pc := newTestPermissionCache(t)

	realmA := uuid.New()
	realmB := uuid.New()
	sessionID := uuid.New()
	tenantID := uuid.New()
	userID := uuid.New()
	_ = userID // present for symmetry with session-cache tests

	checkKeyA := pc.realmPermissionCheckKey(realmA, sessionID, tenantID, testPermCRM)
	checkKeyB := pc.realmPermissionCheckKey(realmB, sessionID, tenantID, testPermCRM)
	assert.NotEqual(t, checkKeyA, checkKeyB)

	roleKeyA := pc.realmRolePermissionsKey(realmA, tenantID, "superuser")
	roleKeyB := pc.realmRolePermissionsKey(realmB, tenantID, "superuser")
	assert.NotEqual(t, roleKeyA, roleKeyB)

	versionKeyA := pc.realmRoleVersionKey(realmA, tenantID)
	versionKeyB := pc.realmRoleVersionKey(realmB, tenantID)
	assert.NotEqual(t, versionKeyA, versionKeyB)
}
