// SPDX-License-Identifier: AGPL-3.0-or-later

package redis

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
)

const examplePermCRMContactsRead = "crm:contacts:read"

// ExamplePermissionCache demonstrates how to use the permission cache in production
func ExamplePermissionCache() {
	// 1. Setup Redis client
	rdb := redis.NewClient(&redis.Options{
		Addr: "localhost:6379",
	})
	defer rdb.Close() //nolint:errcheck

	// 2. Create logger
	logger, _ := zap.NewProduction()
	defer logger.Sync() //nolint:errcheck

	// 3. Configure permission cache
	config := &PermissionCacheConfig{
		LocalSize:      10000,            // 10k entries in local LRU
		LocalTTL:       30 * time.Second, // Local cache refreshes every 30s
		CheckTTL:       1 * time.Minute,  // Permission checks cached for 1 minute
		RoleMappingTTL: 15 * time.Minute, // Role mappings cached for 15 minutes
	}

	// 4. Create permission cache
	permCache, err := NewPermissionCache(rdb, logger, config, "hexxlock")
	if err != nil {
		logger.Fatal("failed to create permission cache", zap.Error(err))
		return
	}

	ctx := context.Background()

	// Example tenant and user
	tenantID := uuid.New()
	sessionID := uuid.New()

	// === SCENARIO 1: Cache role permissions (called when roles are loaded/updated) ===
	adminPermissions := []string{
		"crm:*",             // Full CRM access
		"invoicing:*",       // Full invoicing access
		"hr:employees:read", // Read-only HR employee access
	}

	if err := permCache.CacheRolePermissions(ctx, tenantID, "admin", adminPermissions); err != nil {
		logger.Error("failed to cache role permissions", zap.Error(err))
	}

	userPermissions := []string{
		examplePermCRMContactsRead,
		"crm:contacts:write",
		"crm:companies:read",
	}

	if err := permCache.CacheRolePermissions(ctx, tenantID, "user", userPermissions); err != nil {
		logger.Error("failed to cache role permissions", zap.Error(err))
	}

	// === SCENARIO 2: Resolve user effective permissions (on login) ===
	userRoles := []string{"admin", "user"}
	effectivePerms, err := permCache.GetUserEffectivePermissions(ctx, tenantID, userRoles)
	if err != nil {
		logger.Error("failed to get effective permissions", zap.Error(err))
		return
	}

	logger.Info("user effective permissions",
		zap.Int("count", len(effectivePerms)),
		zap.Strings("permissions", effectivePerms))

	// === SCENARIO 3: Cache individual permission checks (for fast lookups) ===
	// After resolving that user has a permission, cache it for this session
	for _, perm := range effectivePerms {
		if err := permCache.CachePermissionCheck(ctx, sessionID, tenantID, perm, true); err != nil {
			logger.Error("failed to cache permission check", zap.Error(err))
		}
	}

	// === SCENARIO 4: Check permission (in middleware/authorization) ===
	requiredPermission := examplePermCRMContactsRead
	allowed, err := permCache.CheckPermission(ctx, sessionID, tenantID, requiredPermission)

	if errors.Is(err, ErrPermissionNotCached) {
		// Permission not cached - resolve it
		logger.Debug("permission not cached, resolving from user roles")

		// Get user's effective permissions
		effectivePerms, err := permCache.GetUserEffectivePermissions(ctx, tenantID, userRoles)
		if err != nil {
			logger.Error("failed to resolve permissions", zap.Error(err))
			return
		}

		// Check with wildcard matching
		allowed = permCache.CheckPermissionWithWildcard(effectivePerms, requiredPermission)

		// Cache the result
		if err := permCache.CachePermissionCheck(ctx, sessionID, tenantID, requiredPermission, allowed); err != nil {
			logger.Error("failed to cache permission result", zap.Error(err))
		}
	} else if err != nil {
		logger.Error("permission check failed", zap.Error(err))
		return
	}

	if allowed {
		logger.Info("permission granted", zap.String("permission", requiredPermission))
	} else {
		logger.Warn("permission denied", zap.String("permission", requiredPermission))
	}

	// === SCENARIO 5: Invalidate when roles change ===
	// When role permissions are updated, invalidate the cache
	if err := permCache.InvalidateRolePermissions(ctx, tenantID, "admin"); err != nil {
		logger.Error("failed to invalidate role permissions", zap.Error(err))
	}

	// When a user's roles change, invalidate their session permissions
	if err := permCache.InvalidateSessionPermissions(ctx, sessionID, tenantID); err != nil {
		logger.Error("failed to invalidate session permissions", zap.Error(err))
	}

	// When tenant's entire permission structure changes
	if err := permCache.InvalidateTenantPermissions(ctx, tenantID); err != nil {
		logger.Error("failed to invalidate tenant permissions", zap.Error(err))
	}

	// === SCENARIO 6: Monitor cache performance ===
	metrics := permCache.GetMetrics()
	logger.Info("cache metrics",
		zap.Int64("total_checks", metrics.TotalChecks),
		zap.Int64("local_hits", metrics.LocalHits),
		zap.Int64("redis_hits", metrics.RedisHits),
		zap.Int64("local_misses", metrics.LocalMisses),
		zap.Int64("redis_misses", metrics.RedisMisses),
		zap.Float64("local_hit_rate", float64(metrics.LocalHits)/float64(metrics.TotalChecks)*100),
	)
}

// ExampleMiddlewareIntegration shows how to use permission cache in HTTP middleware
func ExampleMiddlewareIntegration(permCache *PermissionCache) func(next func()) {
	return func(next func()) {
		ctx := context.Background()

		// Extract from request context (pseudo-code)
		var sessionID, tenantID uuid.UUID
		var requiredPermission string

		// Try cache first (ultra-fast path)
		allowed, err := permCache.CheckPermission(ctx, sessionID, tenantID, requiredPermission)

		if errors.Is(err, ErrPermissionNotCached) {
			// Slow path: resolve from database
			// In real implementation, get user's roles from session/database
			userRoles := []string{"admin"} // from session

			effectivePerms, err := permCache.GetUserEffectivePermissions(ctx, tenantID, userRoles)
			if errors.Is(err, ErrRolePermissionsNotCached) {
				// Even slower path: load role permissions from database
				// loadAndCacheRolePermissionsFromDB(...)
				return
			}

			// Check with wildcard matching
			allowed = permCache.CheckPermissionWithWildcard(effectivePerms, requiredPermission)

			// Cache for next time
			_ = permCache.CachePermissionCheck(ctx, sessionID, tenantID, requiredPermission, allowed)
		}

		if !allowed {
			// Return 403 Forbidden
			return
		}

		// Permission granted - continue
		next()
	}
}

// ExampleBulkPermissionCheck demonstrates checking multiple permissions efficiently
func ExampleBulkPermissionCheck(permCache *PermissionCache) {
	ctx := context.Background()
	tenantID := uuid.New()
	sessionID := uuid.New()

	// Permissions to check
	requiredPermissions := []string{
		examplePermCRMContactsRead,
		"crm:contacts:write",
		"crm:companies:read",
		"invoicing:invoices:read",
	}

	// Get user's roles (from session or database)
	userRoles := []string{"admin", "user"}

	// Get effective permissions once
	effectivePerms, err := permCache.GetUserEffectivePermissions(ctx, tenantID, userRoles)
	if err != nil {
		fmt.Printf("Failed to get effective permissions: %v\n", err)
		return
	}

	// Check all required permissions
	results := make(map[string]bool)
	for _, perm := range requiredPermissions {
		// Check from cache first
		allowed, err := permCache.CheckPermission(ctx, sessionID, tenantID, perm)

		if errors.Is(err, ErrPermissionNotCached) {
			// Not cached - check with wildcard matching
			allowed = permCache.CheckPermissionWithWildcard(effectivePerms, perm)

			// Cache the result
			_ = permCache.CachePermissionCheck(ctx, sessionID, tenantID, perm, allowed)
		}

		results[perm] = allowed
	}

	// Process results
	for perm, allowed := range results {
		fmt.Printf("Permission %s: %v\n", perm, allowed)
	}
}

// ExampleRoleVersioning demonstrates how role versioning works for cache invalidation
func ExampleRoleVersioning(permCache *PermissionCache) {
	ctx := context.Background()
	tenantID := uuid.New()

	// Get current version
	version1, _ := permCache.GetRoleVersion(ctx, tenantID)
	fmt.Printf("Initial version: %d\n", version1)

	// When role permissions are updated
	_ = permCache.InvalidateRolePermissions(ctx, tenantID, "admin")

	// Version is incremented
	version2, _ := permCache.GetRoleVersion(ctx, tenantID)
	fmt.Printf("After invalidation: %d\n", version2)

	// All session-level permission checks are implicitly invalidated
	// because they can check the version and see it changed
}

// ExampleWildcardPermissions demonstrates wildcard permission usage
func ExampleWildcardPermissions(permCache *PermissionCache) {
	// User has these permissions
	userPermissions := []string{
		"crm:*",                // Full CRM access
		"invoicing:invoices:*", // All invoice operations
		"hr:employees:read",    // Specific read access
	}

	// Test various required permissions
	tests := []string{
		examplePermCRMContactsRead, // Matches crm:*
		"crm:companies:delete",     // Matches crm:*
		"invoicing:invoices:read",  // Matches invoicing:invoices:*
		"invoicing:payments:read",  // No match
		"hr:employees:read",        // Exact match
		"hr:employees:write",       // No match
	}

	for _, required := range tests {
		allowed := permCache.CheckPermissionWithWildcard(userPermissions, required)
		fmt.Printf("Permission %s: %v\n", required, allowed)
	}

	// Output:
	// Permission crm:contacts:read: true
	// Permission crm:companies:delete: true
	// Permission invoicing:invoices:read: true
	// Permission invoicing:payments:read: false
	// Permission hr:employees:read: true
	// Permission hr:employees:write: false
}
