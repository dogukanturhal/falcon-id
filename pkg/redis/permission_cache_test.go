// SPDX-License-Identifier: AGPL-3.0-or-later

package redis

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func setupPermissionCacheTest(t *testing.T) (*PermissionCache, *miniredis.Miniredis, func()) {
	// Start miniredis
	mr, err := miniredis.Run()
	require.NoError(t, err)

	// Create Redis client
	rdb := redis.NewClient(&redis.Options{
		Addr: mr.Addr(),
	})

	// Create permission cache
	config := &PermissionCacheConfig{
		LocalSize:      100,
		LocalTTL:       1 * time.Second,
		CheckTTL:       2 * time.Second,
		RoleMappingTTL: 5 * time.Second,
	}

	logger := zap.NewNop()
	cache, err := NewPermissionCache(rdb, logger, config, "test")
	require.NoError(t, err)

	cleanup := func() {
		rdb.Close() //nolint:errcheck,gosec
		mr.Close()
	}

	return cache, mr, cleanup
}

func TestNewPermissionCache(t *testing.T) {
	tests := []struct {
		name        string
		config      *PermissionCacheConfig
		prefix      string
		expectError bool
	}{
		{
			name:        "default config",
			config:      nil,
			prefix:      "",
			expectError: false,
		},
		{
			name:        "custom config",
			config:      DefaultPermissionCacheConfig(),
			prefix:      "custom",
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mr, err := miniredis.Run()
			require.NoError(t, err)
			defer mr.Close()

			rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
			defer rdb.Close() //nolint:errcheck

			cache, err := NewPermissionCache(rdb, zap.NewNop(), tt.config, tt.prefix)

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, cache)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, cache)
			}
		})
	}
}

func TestPermissionCache_CacheAndCheckPermission(t *testing.T) {
	cache, _, cleanup := setupPermissionCacheTest(t)
	defer cleanup()

	ctx := context.Background()
	sessionID := uuid.New()
	tenantID := uuid.New()
	permission := examplePermCRMContactsRead

	// Initially not cached - should return ErrPermissionNotCached
	allowed, err := cache.CheckPermission(ctx, sessionID, tenantID, permission)
	assert.Equal(t, ErrPermissionNotCached, err)
	assert.False(t, allowed)

	// Cache the permission (allowed)
	err = cache.CachePermissionCheck(ctx, sessionID, tenantID, permission, true)
	require.NoError(t, err)

	// Should now be cached and return true
	allowed, err = cache.CheckPermission(ctx, sessionID, tenantID, permission)
	assert.NoError(t, err)
	assert.True(t, allowed)

	// Cache a denied permission
	deniedPermission := "crm:contacts:delete"
	err = cache.CachePermissionCheck(ctx, sessionID, tenantID, deniedPermission, false)
	require.NoError(t, err)

	allowed, err = cache.CheckPermission(ctx, sessionID, tenantID, deniedPermission)
	assert.NoError(t, err)
	assert.False(t, allowed)
}

func TestPermissionCache_LocalCacheLayer(t *testing.T) {
	cache, mr, cleanup := setupPermissionCacheTest(t)
	defer cleanup()

	ctx := context.Background()
	sessionID := uuid.New()
	tenantID := uuid.New()
	permission := examplePermCRMContactsRead

	// Cache the permission
	err := cache.CachePermissionCheck(ctx, sessionID, tenantID, permission, true)
	require.NoError(t, err)

	// First check - hits Redis
	allowed, err := cache.CheckPermission(ctx, sessionID, tenantID, permission)
	assert.NoError(t, err)
	assert.True(t, allowed)

	// Second check - should hit local cache (even if Redis is down)
	mr.Close() // Simulate Redis failure

	allowed, err = cache.CheckPermission(ctx, sessionID, tenantID, permission)
	assert.NoError(t, err) // Should succeed from local cache
	assert.True(t, allowed)
}

func TestPermissionCache_LocalCacheExpiration(t *testing.T) {
	cache, _, cleanup := setupPermissionCacheTest(t)
	defer cleanup()

	ctx := context.Background()
	sessionID := uuid.New()
	tenantID := uuid.New()
	permission := examplePermCRMContactsRead

	// Cache the permission
	err := cache.CachePermissionCheck(ctx, sessionID, tenantID, permission, true)
	require.NoError(t, err)

	// Check immediately - should be cached
	allowed, err := cache.CheckPermission(ctx, sessionID, tenantID, permission)
	assert.NoError(t, err)
	assert.True(t, allowed)

	// Wait for local cache to expire (1 second in test config)
	time.Sleep(1200 * time.Millisecond)

	// Check again - local cache expired, but Redis still has it
	allowed, err = cache.CheckPermission(ctx, sessionID, tenantID, permission)
	assert.NoError(t, err)
	assert.True(t, allowed)
}

func TestPermissionCache_RolePermissions(t *testing.T) {
	cache, _, cleanup := setupPermissionCacheTest(t)
	defer cleanup()

	ctx := context.Background()
	tenantID := uuid.New()
	role := "admin"
	permissions := []string{
		examplePermCRMContactsRead,
		"crm:contacts:write",
		"crm:companies:read",
		"invoicing:*",
	}

	// Initially not cached
	perms, err := cache.GetRolePermissions(ctx, tenantID, role)
	assert.Equal(t, ErrRolePermissionsNotCached, err)
	assert.Nil(t, perms)

	// Cache role permissions
	err = cache.CacheRolePermissions(ctx, tenantID, role, permissions)
	require.NoError(t, err)

	// Retrieve cached permissions
	perms, err = cache.GetRolePermissions(ctx, tenantID, role)
	assert.NoError(t, err)
	assert.ElementsMatch(t, permissions, perms)
}

func TestPermissionCache_GetUserEffectivePermissions(t *testing.T) {
	cache, _, cleanup := setupPermissionCacheTest(t)
	defer cleanup()

	ctx := context.Background()
	tenantID := uuid.New()

	// Set up role permissions
	adminPerms := []string{"crm:*", "invoicing:*"}
	userPerms := []string{examplePermCRMContactsRead, "crm:companies:read"}

	err := cache.CacheRolePermissions(ctx, tenantID, "admin", adminPerms)
	require.NoError(t, err)

	err = cache.CacheRolePermissions(ctx, tenantID, "user", userPerms)
	require.NoError(t, err)

	// Get effective permissions for user with both roles
	effective, err := cache.GetUserEffectivePermissions(ctx, tenantID, []string{"admin", "user"})
	require.NoError(t, err)

	// Should contain all unique permissions
	assert.Contains(t, effective, "crm:*")
	assert.Contains(t, effective, "invoicing:*")
	assert.Contains(t, effective, examplePermCRMContactsRead)
	assert.Contains(t, effective, "crm:companies:read")
}

func TestPermissionCache_WildcardMatching(t *testing.T) {
	cache, _, cleanup := setupPermissionCacheTest(t)
	defer cleanup()

	tests := []struct {
		name               string
		userPermissions    []string
		requiredPermission string
		expected           bool
	}{
		{
			name:               "exact match",
			userPermissions:    []string{examplePermCRMContactsRead},
			requiredPermission: examplePermCRMContactsRead,
			expected:           true,
		},
		{
			name:               "no match",
			userPermissions:    []string{examplePermCRMContactsRead},
			requiredPermission: "crm:contacts:write",
			expected:           false,
		},
		{
			name:               "wildcard module match",
			userPermissions:    []string{"crm:*"},
			requiredPermission: examplePermCRMContactsRead,
			expected:           true,
		},
		{
			name:               "wildcard resource match",
			userPermissions:    []string{"crm:contacts:*"},
			requiredPermission: "crm:contacts:delete",
			expected:           true,
		},
		{
			name:               "universal wildcard",
			userPermissions:    []string{"*"},
			requiredPermission: "anything:here:works",
			expected:           true,
		},
		{
			name:               "wildcard no match different module",
			userPermissions:    []string{"crm:*"},
			requiredPermission: "invoicing:invoices:read",
			expected:           false,
		},
		{
			name:               "wildcard no match different resource",
			userPermissions:    []string{"crm:contacts:*"},
			requiredPermission: "crm:companies:read",
			expected:           false,
		},
		{
			name:               "multiple permissions with wildcard",
			userPermissions:    []string{examplePermCRMContactsRead, "invoicing:*"},
			requiredPermission: "invoicing:invoices:write",
			expected:           true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := cache.CheckPermissionWithWildcard(tt.userPermissions, tt.requiredPermission)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestPermissionCache_InvalidateRolePermissions(t *testing.T) {
	cache, _, cleanup := setupPermissionCacheTest(t)
	defer cleanup()

	ctx := context.Background()
	tenantID := uuid.New()
	role := "admin"
	permissions := []string{"crm:*", "invoicing:*"}

	// Cache permissions
	err := cache.CacheRolePermissions(ctx, tenantID, role, permissions)
	require.NoError(t, err)

	// Verify cached
	perms, err := cache.GetRolePermissions(ctx, tenantID, role)
	assert.NoError(t, err)
	assert.ElementsMatch(t, permissions, perms)

	// Get initial version
	version1, err := cache.GetRoleVersion(ctx, tenantID)
	require.NoError(t, err)

	// Invalidate
	err = cache.InvalidateRolePermissions(ctx, tenantID, role)
	require.NoError(t, err)

	// Should no longer be cached
	perms, err = cache.GetRolePermissions(ctx, tenantID, role)
	assert.Equal(t, ErrRolePermissionsNotCached, err)
	assert.Nil(t, perms)

	// Version should be incremented
	version2, err := cache.GetRoleVersion(ctx, tenantID)
	require.NoError(t, err)
	assert.Greater(t, version2, version1)
}

func TestPermissionCache_InvalidateTenantPermissions(t *testing.T) {
	cache, _, cleanup := setupPermissionCacheTest(t)
	defer cleanup()

	ctx := context.Background()
	tenantID := uuid.New()

	// Cache multiple role permissions
	roles := map[string][]string{
		"admin":   {"crm:*", "invoicing:*"},
		"user":    {examplePermCRMContactsRead},
		"manager": {"crm:*", "hr:employees:read"},
	}

	for role, perms := range roles {
		err := cache.CacheRolePermissions(ctx, tenantID, role, perms)
		require.NoError(t, err)
	}

	// Verify all cached
	for role := range roles {
		_, err := cache.GetRolePermissions(ctx, tenantID, role)
		assert.NoError(t, err)
	}

	// Invalidate all tenant permissions
	err := cache.InvalidateTenantPermissions(ctx, tenantID)
	require.NoError(t, err)

	// All should be invalidated
	for role := range roles {
		_, err := cache.GetRolePermissions(ctx, tenantID, role)
		assert.Equal(t, ErrRolePermissionsNotCached, err)
	}
}

func TestPermissionCache_InvalidateSessionPermissions(t *testing.T) {
	cache, _, cleanup := setupPermissionCacheTest(t)
	defer cleanup()

	ctx := context.Background()
	sessionID := uuid.New()
	tenantID := uuid.New()

	// Cache multiple permission checks
	permissions := []string{
		examplePermCRMContactsRead,
		"crm:contacts:write",
		"invoicing:invoices:read",
	}

	for _, perm := range permissions {
		err := cache.CachePermissionCheck(ctx, sessionID, tenantID, perm, true)
		require.NoError(t, err)
	}

	// Verify all cached in Redis (don't populate local cache yet)
	// We need to clear local cache first to test Redis invalidation properly
	cache.localCache.Purge()

	// Invalidate session permissions in Redis
	err := cache.InvalidateSessionPermissions(ctx, sessionID, tenantID)
	require.NoError(t, err)

	// All should be invalidated from Redis (will return ErrPermissionNotCached)
	// Local cache is already cleared, so this tests Redis layer
	for _, perm := range permissions {
		_, err := cache.CheckPermission(ctx, sessionID, tenantID, perm)
		assert.Equal(t, ErrPermissionNotCached, err)
	}
}

func TestPermissionCache_Metrics(t *testing.T) {
	cache, _, cleanup := setupPermissionCacheTest(t)
	defer cleanup()

	ctx := context.Background()
	sessionID := uuid.New()
	tenantID := uuid.New()

	// Reset metrics to start fresh
	cache.ResetMetrics()

	// Perform various operations
	_, _ = cache.CheckPermission(ctx, sessionID, tenantID, examplePermCRMContactsRead)         // Miss (local + redis)
	_ = cache.CachePermissionCheck(ctx, sessionID, tenantID, examplePermCRMContactsRead, true) // Cache it

	// Clear local cache to ensure next check hits Redis
	cache.localCache.Purge()

	_, _ = cache.CheckPermission(ctx, sessionID, tenantID, examplePermCRMContactsRead) // Hit (Redis) + populates local
	_, _ = cache.CheckPermission(ctx, sessionID, tenantID, examplePermCRMContactsRead) // Hit (local)
	_, _ = cache.GetUserEffectivePermissions(ctx, tenantID, []string{"admin"})         // Role resolution (will miss)
	_ = cache.InvalidateRolePermissions(ctx, tenantID, "admin")                        // Invalidation

	metrics := cache.GetMetrics()

	assert.Equal(t, int64(3), metrics.TotalChecks)       // 3 CheckPermission calls
	assert.Equal(t, int64(1), metrics.LocalHits)         // 1 local cache hit
	assert.Equal(t, int64(2), metrics.LocalMisses)       // 2 local cache misses
	assert.Equal(t, int64(1), metrics.RedisHits)         // 1 redis hit
	assert.Equal(t, int64(1), metrics.RedisMisses)       // 1 redis miss
	assert.Equal(t, int64(1), metrics.RoleResolutions)   // 1 GetUserEffectivePermissions call
	assert.Equal(t, int64(1), metrics.InvalidationCount) // 1 invalidation

	// Reset metrics
	cache.ResetMetrics()
	metrics = cache.GetMetrics()
	assert.Equal(t, int64(0), metrics.TotalChecks)
}

func TestPermissionCache_ValidatePermission(t *testing.T) {
	tests := []struct {
		name        string
		permission  string
		expectError bool
	}{
		{"valid module:resource:action", examplePermCRMContactsRead, false},
		{"valid module:*", "crm:*", false},
		{"valid universal wildcard", "*", false},
		{"valid four parts", "crm:contacts:custom:read", false},
		{"empty permission", "", true},
		{"single part", "crm", true},
		{"too many parts", "a:b:c:d:e", true},
		{"empty part", "crm::read", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validatePermission(tt.permission)
			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestPermissionCache_EmptyRolePermissions(t *testing.T) {
	cache, _, cleanup := setupPermissionCacheTest(t)
	defer cleanup()

	ctx := context.Background()
	tenantID := uuid.New()
	role := "empty-role"

	// Cache empty permissions
	err := cache.CacheRolePermissions(ctx, tenantID, role, []string{})
	require.NoError(t, err)

	// Should return ErrRolePermissionsNotCached for empty set
	perms, err := cache.GetRolePermissions(ctx, tenantID, role)
	assert.Equal(t, ErrRolePermissionsNotCached, err)
	assert.Nil(t, perms)
}

func TestPermissionCache_ConcurrentAccess(t *testing.T) {
	cache, _, cleanup := setupPermissionCacheTest(t)
	defer cleanup()

	ctx := context.Background()
	tenantID := uuid.New()

	// Concurrent writes and reads
	done := make(chan bool)

	// Writer goroutines
	for i := 0; i < 10; i++ {
		go func(idx int) {
			role := "role-" + string(rune(idx)) //nolint:gosec // rune is always within Unicode range in this context
			perms := []string{"perm1", "perm2"}
			_ = cache.CacheRolePermissions(ctx, tenantID, role, perms)
			done <- true
		}(i)
	}

	// Reader goroutines
	for i := 0; i < 10; i++ {
		go func(idx int) {
			role := "role-" + string(rune(idx)) //nolint:gosec // rune is always within Unicode range in this context
			_, _ = cache.GetRolePermissions(ctx, tenantID, role)
			done <- true
		}(i)
	}

	// Wait for all
	for i := 0; i < 20; i++ {
		<-done
	}

	// Should not crash - verify metrics are thread-safe
	metrics := cache.GetMetrics()
	assert.NotNil(t, metrics)
}

func TestPermissionCache_HashPermission(t *testing.T) {
	// Test that hashing is consistent
	perm := examplePermCRMContactsRead
	hash1 := hashPermission(perm)
	hash2 := hashPermission(perm)

	assert.Equal(t, hash1, hash2)
	assert.Len(t, hash1, 16) // Should be 16 chars

	// Different permissions should have different hashes
	hash3 := hashPermission("crm:contacts:write")
	assert.NotEqual(t, hash1, hash3)
}

func TestMatchPermission(t *testing.T) {
	tests := []struct {
		name       string
		pattern    string
		permission string
		expected   bool
	}{
		{"universal wildcard", "*", "anything", true},
		{"exact match", examplePermCRMContactsRead, examplePermCRMContactsRead, true},
		{"module wildcard match", "crm:*", examplePermCRMContactsRead, true},
		{"module wildcard no match", "crm:*", "invoicing:invoices:read", false},
		{"resource wildcard match", "crm:contacts:*", "crm:contacts:delete", true},
		{"resource wildcard no match", "crm:contacts:*", "crm:companies:read", false},
		{"no wildcard exact match", examplePermCRMContactsRead, examplePermCRMContactsRead, true},
		{"no wildcard no match", examplePermCRMContactsRead, "crm:contacts:write", false},
		{"longer pattern", "crm:contacts:custom:read", "crm:contacts:custom:read", true},
		{"pattern longer than permission", examplePermCRMContactsRead, "crm:contacts", false},
		{"permission longer than pattern", "crm:*", "crm:contacts:custom:read", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := matchPermission(tt.pattern, tt.permission)
			assert.Equal(t, tt.expected, result, "pattern: %s, permission: %s", tt.pattern, tt.permission)
		})
	}
}

func BenchmarkPermissionCache_LocalHit(b *testing.B) {
	cache, _, cleanup := setupPermissionCacheTest(&testing.T{})
	defer cleanup()

	ctx := context.Background()
	sessionID := uuid.New()
	tenantID := uuid.New()
	permission := examplePermCRMContactsRead

	// Warm up cache
	_ = cache.CachePermissionCheck(ctx, sessionID, tenantID, permission, true)
	_, _ = cache.CheckPermission(ctx, sessionID, tenantID, permission)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = cache.CheckPermission(ctx, sessionID, tenantID, permission)
	}
}

func BenchmarkPermissionCache_WildcardMatch(b *testing.B) {
	cache, _, cleanup := setupPermissionCacheTest(&testing.T{})
	defer cleanup()

	userPerms := []string{"crm:*", "invoicing:*", "hr:employees:read"}
	requiredPerm := examplePermCRMContactsRead

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cache.CheckPermissionWithWildcard(userPerms, requiredPerm)
	}
}
