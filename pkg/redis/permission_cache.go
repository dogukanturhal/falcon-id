// SPDX-License-Identifier: AGPL-3.0-or-later

package redis

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
)

var (
	// ErrPermissionNotCached indicates permission check is not cached and requires resolution
	ErrPermissionNotCached = errors.New("permission not cached, requires resolution")

	// ErrRolePermissionsNotCached indicates role permissions are not cached
	ErrRolePermissionsNotCached = errors.New("role permissions not cached")

	// ErrInvalidPermissionFormat indicates the permission string is malformed
	ErrInvalidPermissionFormat = errors.New("invalid permission format")
)

// PermissionCacheConfig holds configuration for the permission cache
type PermissionCacheConfig struct {
	LocalSize      int           // Local LRU cache size (default: 10000)
	LocalTTL       time.Duration // Local cache TTL (default: 30s)
	CheckTTL       time.Duration // Redis permission check TTL (default: 1m)
	RoleMappingTTL time.Duration // Role->permissions mapping TTL (default: 15m)
}

// DefaultPermissionCacheConfig returns sensible defaults
func DefaultPermissionCacheConfig() *PermissionCacheConfig {
	return &PermissionCacheConfig{
		LocalSize:      10000,
		LocalTTL:       30 * time.Second,
		CheckTTL:       1 * time.Minute,
		RoleMappingTTL: 15 * time.Minute,
	}
}

// PermissionCache handles permission resolution with multi-layer caching
// Layer 1: Local LRU cache (per-instance, ultra-fast, 30s TTL)
// Layer 2: Redis permission check cache (distributed, 1m TTL)
// Layer 3: Redis role->permissions mapping cache (15m TTL)
type PermissionCache struct {
	redis  *redis.Client
	logger *zap.Logger
	config *PermissionCacheConfig
	prefix string

	// Local LRU cache for permission checks
	// Key: "sessionID:tenantID:permission"
	// Value: cacheEntry (contains result and expiration)
	localCache *lru.Cache[string, *cacheEntry]

	// Mutex for metrics (optional - can be extended)
	metricsMu sync.RWMutex
	metrics   *CacheMetrics
}

// cacheEntry represents a cached permission check result with expiration
type cacheEntry struct {
	Allowed   bool
	ExpiresAt time.Time
}

// CacheMetrics tracks cache performance
type CacheMetrics struct {
	LocalHits         int64
	LocalMisses       int64
	RedisHits         int64
	RedisMisses       int64
	TotalChecks       int64
	RoleResolutions   int64
	InvalidationCount int64
}

// NewPermissionCache creates a new permission cache
func NewPermissionCache(redisClient *redis.Client, logger *zap.Logger, config *PermissionCacheConfig, prefix string) (*PermissionCache, error) {
	if config == nil {
		config = DefaultPermissionCacheConfig()
	}

	if prefix == "" {
		prefix = "hexxlock"
	}

	// Create local LRU cache
	localCache, err := lru.New[string, *cacheEntry](config.LocalSize)
	if err != nil {
		return nil, fmt.Errorf("failed to create local LRU cache: %w", err)
	}

	return &PermissionCache{
		redis:      redisClient,
		logger:     logger,
		config:     config,
		prefix:     prefix,
		localCache: localCache,
		metrics:    &CacheMetrics{},
	}, nil
}

// CheckPermission checks if a user session has a specific permission
// Returns (allowed, error). If ErrPermissionNotCached is returned, caller must resolve permissions.
func (c *PermissionCache) CheckPermission(ctx context.Context, sessionID, tenantID uuid.UUID, permission string) (bool, error) {
	c.incrementMetric(&c.metrics.TotalChecks)

	if err := validatePermission(permission); err != nil {
		return false, fmt.Errorf("CheckPermission: %w", err)
	}

	cacheKey := c.localCacheKey(sessionID, tenantID, permission)

	// Layer 1: Check local LRU cache
	if entry, ok := c.localCache.Get(cacheKey); ok {
		// Check if entry is still valid
		if time.Now().Before(entry.ExpiresAt) {
			c.incrementMetric(&c.metrics.LocalHits)
			c.logger.Debug("permission check: local cache hit",
				zap.String("session_id", sessionID.String()),
				zap.String("tenant_id", tenantID.String()),
				zap.String("permission", permission),
				zap.Bool("allowed", entry.Allowed))
			return entry.Allowed, nil
		}
		// Expired - evict
		c.localCache.Remove(cacheKey)
	}
	c.incrementMetric(&c.metrics.LocalMisses)

	// Layer 2: Check Redis permission check cache
	redisKey := c.permissionCheckKey(sessionID, tenantID, permission)
	cached, err := c.redis.Get(ctx, redisKey).Result()
	if err == nil {
		allowed := cached == "1"

		// Store in local cache
		c.localCache.Add(cacheKey, &cacheEntry{
			Allowed:   allowed,
			ExpiresAt: time.Now().Add(c.config.LocalTTL),
		})

		c.incrementMetric(&c.metrics.RedisHits)
		c.logger.Debug("permission check: redis cache hit",
			zap.String("session_id", sessionID.String()),
			zap.String("tenant_id", tenantID.String()),
			zap.String("permission", permission),
			zap.Bool("allowed", allowed))
		return allowed, nil
	}

	if !errors.Is(err, redis.Nil) {
		c.logger.Error("failed to check Redis permission cache",
			zap.Error(err),
			zap.String("key", redisKey))
		// Don't fail - return ErrPermissionNotCached to trigger resolution
	}

	c.incrementMetric(&c.metrics.RedisMisses)

	// Layer 3: Permission not cached - caller must resolve from role permissions
	c.logger.Debug("permission check: cache miss, requires resolution",
		zap.String("session_id", sessionID.String()),
		zap.String("tenant_id", tenantID.String()),
		zap.String("permission", permission))
	return false, ErrPermissionNotCached
}

// CachePermissionCheck stores a permission check result in both Redis and local cache
func (c *PermissionCache) CachePermissionCheck(ctx context.Context, sessionID, tenantID uuid.UUID, permission string, allowed bool) error {
	if err := validatePermission(permission); err != nil {
		return fmt.Errorf("CachePermissionCheck: %w", err)
	}

	// Store in Redis
	redisKey := c.permissionCheckKey(sessionID, tenantID, permission)
	value := "0"
	if allowed {
		value = "1"
	}

	if err := c.redis.Set(ctx, redisKey, value, c.config.CheckTTL).Err(); err != nil {
		c.logger.Error("failed to cache permission check in Redis",
			zap.Error(err),
			zap.String("key", redisKey))
		return fmt.Errorf("failed to cache permission check: %w", err)
	}

	// Store in local cache
	localKey := c.localCacheKey(sessionID, tenantID, permission)
	c.localCache.Add(localKey, &cacheEntry{
		Allowed:   allowed,
		ExpiresAt: time.Now().Add(c.config.LocalTTL),
	})

	c.logger.Debug("cached permission check",
		zap.String("session_id", sessionID.String()),
		zap.String("tenant_id", tenantID.String()),
		zap.String("permission", permission),
		zap.Bool("allowed", allowed))

	return nil
}

// GetRolePermissions retrieves permissions for a role from cache
func (c *PermissionCache) GetRolePermissions(ctx context.Context, tenantID uuid.UUID, role string) ([]string, error) {
	if role == "" {
		return nil, fmt.Errorf("role cannot be empty")
	}

	key := c.rolePermissionsKey(tenantID, role)

	perms, err := c.redis.SMembers(ctx, key).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			c.logger.Debug("role permissions not cached",
				zap.String("tenant_id", tenantID.String()),
				zap.String("role", role))
			return nil, ErrRolePermissionsNotCached
		}
		return nil, fmt.Errorf("failed to get role permissions: %w", err)
	}

	if len(perms) == 0 {
		c.logger.Debug("role permissions cache empty",
			zap.String("tenant_id", tenantID.String()),
			zap.String("role", role))
		return nil, ErrRolePermissionsNotCached
	}

	c.logger.Debug("retrieved role permissions from cache",
		zap.String("tenant_id", tenantID.String()),
		zap.String("role", role),
		zap.Int("permission_count", len(perms)))

	return perms, nil
}

// CacheRolePermissions stores permissions for a role
func (c *PermissionCache) CacheRolePermissions(ctx context.Context, tenantID uuid.UUID, role string, permissions []string) error {
	if role == "" {
		return fmt.Errorf("role cannot be empty")
	}

	key := c.rolePermissionsKey(tenantID, role)

	// Use pipeline for atomic operation
	pipe := c.redis.Pipeline()

	// Delete existing permissions
	pipe.Del(ctx, key)

	// Add new permissions (only if non-empty)
	if len(permissions) > 0 {
		// Convert []string to []interface{} for SAdd
		permsInterface := make([]interface{}, len(permissions))
		for i, p := range permissions {
			permsInterface[i] = p
		}
		pipe.SAdd(ctx, key, permsInterface...)
	}

	// Set expiration
	pipe.Expire(ctx, key, c.config.RoleMappingTTL)

	if _, err := pipe.Exec(ctx); err != nil {
		c.logger.Error("failed to cache role permissions",
			zap.Error(err),
			zap.String("tenant_id", tenantID.String()),
			zap.String("role", role))
		return fmt.Errorf("failed to cache role permissions: %w", err)
	}

	c.logger.Info("cached role permissions",
		zap.String("tenant_id", tenantID.String()),
		zap.String("role", role),
		zap.Int("permission_count", len(permissions)))

	return nil
}

// GetUserEffectivePermissions resolves all permissions for a user based on their roles
// This method checks role permissions cache and merges them, handling wildcards
func (c *PermissionCache) GetUserEffectivePermissions(ctx context.Context, tenantID uuid.UUID, roles []string) ([]string, error) {
	c.incrementMetric(&c.metrics.RoleResolutions)

	if len(roles) == 0 {
		return []string{}, nil
	}

	permissionSet := make(map[string]bool)

	for _, role := range roles {
		rolePerms, err := c.GetRolePermissions(ctx, tenantID, role)
		if err != nil {
			if errors.Is(err, ErrRolePermissionsNotCached) {
				// Role not cached - caller must populate
				c.logger.Debug("role permissions not cached during effective permission resolution",
					zap.String("tenant_id", tenantID.String()),
					zap.String("role", role))
				return nil, ErrRolePermissionsNotCached
			}
			return nil, fmt.Errorf("GetUserEffectivePermissions: %w", err)
		}

		// Add all permissions from this role
		for _, perm := range rolePerms {
			permissionSet[perm] = true
		}
	}

	// Convert set to slice
	permissions := make([]string, 0, len(permissionSet))
	for perm := range permissionSet {
		permissions = append(permissions, perm)
	}

	c.logger.Debug("resolved user effective permissions",
		zap.String("tenant_id", tenantID.String()),
		zap.Strings("roles", roles),
		zap.Int("permission_count", len(permissions)))

	return permissions, nil
}

// CheckPermissionWithWildcard checks if user has permission, supporting wildcard matching
// e.g., "crm:*" matches "crm:contacts:read"
// e.g., "crm:contacts:*" matches "crm:contacts:delete"
func (c *PermissionCache) CheckPermissionWithWildcard(userPermissions []string, requiredPermission string) bool {
	// Exact match first
	for _, perm := range userPermissions {
		if perm == requiredPermission {
			return true
		}
	}

	// Wildcard matching
	for _, perm := range userPermissions {
		if matchPermission(perm, requiredPermission) {
			return true
		}
	}

	return false
}

// InvalidateRolePermissions invalidates cache for a specific role
func (c *PermissionCache) InvalidateRolePermissions(ctx context.Context, tenantID uuid.UUID, role string) error {
	c.incrementMetric(&c.metrics.InvalidationCount)

	// Delete role permissions cache
	key := c.rolePermissionsKey(tenantID, role)
	if err := c.redis.Del(ctx, key).Err(); err != nil {
		c.logger.Error("failed to invalidate role permissions",
			zap.Error(err),
			zap.String("tenant_id", tenantID.String()),
			zap.String("role", role))
		return fmt.Errorf("failed to invalidate role permissions: %w", err)
	}

	// Increment role version to invalidate all session permission caches
	if err := c.IncrementRoleVersion(ctx, tenantID); err != nil {
		c.logger.Error("failed to increment role version",
			zap.Error(err),
			zap.String("tenant_id", tenantID.String()))
		return fmt.Errorf("InvalidateRolePermissions: %w", err)
	}

	c.logger.Info("invalidated role permissions",
		zap.String("tenant_id", tenantID.String()),
		zap.String("role", role))

	return nil
}

// InvalidateTenantPermissions invalidates all permission caches for a tenant
func (c *PermissionCache) InvalidateTenantPermissions(ctx context.Context, tenantID uuid.UUID) error {
	c.incrementMetric(&c.metrics.InvalidationCount)

	// Pattern for all tenant role permissions
	pattern := c.rolePermissionsKeyPattern(tenantID)

	// Scan and delete all matching keys
	var cursor uint64
	deletedCount := 0

	for {
		var keys []string
		var err error

		keys, cursor, err = c.redis.Scan(ctx, cursor, pattern, 100).Result()
		if err != nil {
			return fmt.Errorf("failed to scan tenant permission keys: %w", err)
		}

		if len(keys) > 0 {
			if err := c.redis.Del(ctx, keys...).Err(); err != nil {
				return fmt.Errorf("failed to delete tenant permission keys: %w", err)
			}
			deletedCount += len(keys)
		}

		if cursor == 0 {
			break
		}
	}

	// Increment role version
	if err := c.IncrementRoleVersion(ctx, tenantID); err != nil {
		return fmt.Errorf("InvalidateTenantPermissions: %w", err)
	}

	c.logger.Info("invalidated all tenant permissions",
		zap.String("tenant_id", tenantID.String()),
		zap.Int("keys_deleted", deletedCount))

	return nil
}

// IncrementRoleVersion increments the role version to invalidate session permission caches
// This is a lightweight way to invalidate all session-level permission checks without
// scanning and deleting individual keys
func (c *PermissionCache) IncrementRoleVersion(ctx context.Context, tenantID uuid.UUID) error {
	key := c.roleVersionKey(tenantID)
	version, err := c.redis.Incr(ctx, key).Result()
	if err != nil {
		return fmt.Errorf("failed to increment role version: %w", err)
	}

	c.logger.Debug("incremented role version",
		zap.String("tenant_id", tenantID.String()),
		zap.Int64("version", version))

	return nil
}

// GetRoleVersion returns the current role version for a tenant
func (c *PermissionCache) GetRoleVersion(ctx context.Context, tenantID uuid.UUID) (int64, error) {
	key := c.roleVersionKey(tenantID)
	version, err := c.redis.Get(ctx, key).Int64()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return 0, nil
		}
		return 0, fmt.Errorf("failed to get role version: %w", err)
	}
	return version, nil
}

// InvalidateSessionPermissions invalidates all permission checks for a specific session
func (c *PermissionCache) InvalidateSessionPermissions(ctx context.Context, sessionID, tenantID uuid.UUID) error {
	c.incrementMetric(&c.metrics.InvalidationCount)

	// Pattern for all session permission checks
	pattern := c.sessionPermissionsPattern(sessionID, tenantID)

	var cursor uint64
	deletedCount := 0

	for {
		var keys []string
		var err error

		keys, cursor, err = c.redis.Scan(ctx, cursor, pattern, 100).Result()
		if err != nil {
			c.logger.Error("failed to scan session permission keys",
				zap.Error(err),
				zap.String("pattern", pattern))
			return fmt.Errorf("failed to scan session permission keys: %w", err)
		}

		if len(keys) > 0 {
			if err := c.redis.Del(ctx, keys...).Err(); err != nil {
				c.logger.Error("failed to delete session permission keys",
					zap.Error(err))
				return fmt.Errorf("failed to delete session permission keys: %w", err)
			}
			deletedCount += len(keys)
		}

		if cursor == 0 {
			break
		}
	}

	// Clear local cache entries for this session
	// Note: LRU doesn't support pattern deletion, but entries will expire naturally

	c.logger.Info("invalidated session permissions",
		zap.String("session_id", sessionID.String()),
		zap.String("tenant_id", tenantID.String()),
		zap.Int("keys_deleted", deletedCount))

	return nil
}

// GetMetrics returns current cache metrics
func (c *PermissionCache) GetMetrics() CacheMetrics {
	c.metricsMu.RLock()
	defer c.metricsMu.RUnlock()
	return *c.metrics
}

// ResetMetrics resets cache metrics
func (c *PermissionCache) ResetMetrics() {
	c.metricsMu.Lock()
	defer c.metricsMu.Unlock()
	c.metrics = &CacheMetrics{}
}

// Key generation methods

func (c *PermissionCache) localCacheKey(sessionID, tenantID uuid.UUID, permission string) string {
	return fmt.Sprintf("%s:%s:%s", sessionID.String(), tenantID.String(), permission)
}

func (c *PermissionCache) permissionCheckKey(sessionID, tenantID uuid.UUID, permission string) string {
	permHash := hashPermission(permission)
	return fmt.Sprintf("%s:session:%s:tenant:%s:perm_check:%s", c.prefix, sessionID.String(), tenantID.String(), permHash)
}

// realmPermissionCheckKey returns the realm-scoped Redis key for a single permission
// check result.  The realm dimension prevents cross-realm key collisions when the
// same (sessionID, tenantID, permission) triple exists in multiple realms.
func (c *PermissionCache) realmPermissionCheckKey(realmID, sessionID, tenantID uuid.UUID, permission string) string {
	permHash := hashPermission(permission)
	return fmt.Sprintf("%s:realm:%s:session:%s:tenant:%s:perm_check:%s",
		c.prefix, realmID.String(), sessionID.String(), tenantID.String(), permHash)
}

func (c *PermissionCache) rolePermissionsKey(tenantID uuid.UUID, role string) string {
	return fmt.Sprintf("%s:tenant:%s:role:%s:permissions", c.prefix, tenantID.String(), role)
}

// realmRolePermissionsKey returns the realm-scoped Redis key for a role's permission
// set.  Using a realm prefix keeps role caches from different realms isolated even
// when role names collide across realms.
func (c *PermissionCache) realmRolePermissionsKey(realmID, tenantID uuid.UUID, role string) string {
	return fmt.Sprintf("%s:realm:%s:tenant:%s:role:%s:permissions",
		c.prefix, realmID.String(), tenantID.String(), role)
}

func (c *PermissionCache) rolePermissionsKeyPattern(tenantID uuid.UUID) string {
	return fmt.Sprintf("%s:tenant:%s:role:*:permissions", c.prefix, tenantID.String())
}

func (c *PermissionCache) roleVersionKey(tenantID uuid.UUID) string {
	return fmt.Sprintf("%s:tenant:%s:roles:version", c.prefix, tenantID.String())
}

// realmRoleVersionKey returns the realm-scoped Redis key for a tenant's role
// version counter.  Incrementing this key invalidates all realm-scoped session
// permission checks for the tenant without touching other realms.
func (c *PermissionCache) realmRoleVersionKey(realmID, tenantID uuid.UUID) string {
	return fmt.Sprintf("%s:realm:%s:tenant:%s:roles:version", c.prefix, realmID.String(), tenantID.String())
}

func (c *PermissionCache) sessionPermissionsPattern(sessionID, tenantID uuid.UUID) string {
	return fmt.Sprintf("%s:session:%s:tenant:%s:perm_check:*", c.prefix, sessionID.String(), tenantID.String())
}

// Helper functions

// hashPermission creates a consistent hash of a permission string
func hashPermission(permission string) string {
	h := sha256.New()
	h.Write([]byte(permission))
	return hex.EncodeToString(h.Sum(nil))[:16] // Use first 16 chars for brevity
}

// matchPermission handles wildcard permission matching
// Pattern examples:
// - "*" matches everything
// - "crm:*" matches "crm:contacts:read", "crm:companies:write", etc.
// - "crm:contacts:*" matches "crm:contacts:read", "crm:contacts:write", etc.
// - "crm:contacts:read" matches exactly "crm:contacts:read"
func matchPermission(pattern, permission string) bool {
	// Universal wildcard
	if pattern == "*" {
		return true
	}

	// Exact match
	if pattern == permission {
		return true
	}

	// No wildcard in pattern
	if !strings.Contains(pattern, "*") {
		return false
	}

	// Split by colon
	patternParts := strings.Split(pattern, ":")
	permParts := strings.Split(permission, ":")

	// Check each part
	for i, pp := range patternParts {
		if pp == "*" {
			// Wildcard matches rest
			return true
		}

		// Not enough parts in permission
		if i >= len(permParts) {
			return false
		}

		// Part doesn't match
		if pp != permParts[i] {
			return false
		}
	}

	// All parts matched - ensure same length
	return len(patternParts) == len(permParts)
}

// validatePermission validates permission string format
// Valid format: "module:resource:action" or "module:*" or "*"
func validatePermission(permission string) error {
	if permission == "" {
		return ErrInvalidPermissionFormat
	}

	if permission == "*" {
		return nil
	}

	parts := strings.Split(permission, ":")
	if len(parts) < 2 || len(parts) > 4 {
		return fmt.Errorf("%w: must be in format 'module:resource:action' or 'module:*'", ErrInvalidPermissionFormat)
	}

	for _, part := range parts {
		if part == "" && part != "*" {
			return fmt.Errorf("%w: empty parts not allowed", ErrInvalidPermissionFormat)
		}
	}

	return nil
}

// incrementMetric safely increments a metric counter
func (c *PermissionCache) incrementMetric(counter *int64) {
	c.metricsMu.Lock()
	*counter++
	c.metricsMu.Unlock()
}
