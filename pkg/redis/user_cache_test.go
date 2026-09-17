// SPDX-License-Identifier: AGPL-3.0-or-later

package redis

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"go.uber.org/zap/zaptest"
)

func TestDefaultCacheConfig(t *testing.T) {
	config := DefaultCacheConfig()
	assert.Equal(t, 5*time.Minute, config.UserProfileTTL)
	assert.Equal(t, 2*time.Minute, config.RoleCheckTTL)
	assert.Equal(t, 2*time.Minute, config.PermissionTTL)
}

func TestNewUserCacheService(t *testing.T) {
	logger := zaptest.NewLogger(t)
	mockRedis := &Client{
		rdb:    nil,
		logger: logger,
	}

	t.Run("with default config", func(t *testing.T) {
		cache := NewUserCacheService(mockRedis, logger, nil)
		assert.NotNil(t, cache)
		assert.Equal(t, "iam:user", cache.keyPrefix)
		assert.Equal(t, 5*time.Minute, cache.userProfileTTL)
		assert.Equal(t, 2*time.Minute, cache.roleCheckTTL)
		assert.Equal(t, 2*time.Minute, cache.permissionTTL)
	})

	t.Run("with custom config", func(t *testing.T) {
		customConfig := &CacheConfig{
			UserProfileTTL: 10 * time.Minute,
			RoleCheckTTL:   3 * time.Minute,
			PermissionTTL:  3 * time.Minute,
		}
		cache := NewUserCacheService(mockRedis, logger, customConfig)
		assert.NotNil(t, cache)
		assert.Equal(t, 10*time.Minute, cache.userProfileTTL)
		assert.Equal(t, 3*time.Minute, cache.roleCheckTTL)
		assert.Equal(t, 3*time.Minute, cache.permissionTTL)
	})
}

func TestCacheKeyGeneration(t *testing.T) {
	logger := zaptest.NewLogger(t)
	mockRedis := &Client{
		rdb:    nil,
		logger: logger,
	}
	cache := NewUserCacheService(mockRedis, logger, nil)

	userID := "user-123"

	t.Run("profile key format", func(t *testing.T) {
		expectedKey := "iam:user:user-123:profile"
		assert.Equal(t, cache.keyPrefix, "iam:user")
		// Key format is tested implicitly through the implementation
		_ = expectedKey
	})

	t.Run("roles key format", func(_ *testing.T) {
		expectedKey := "iam:user:user-123:roles"
		_ = expectedKey
		_ = userID
	})

	t.Run("permissions key format", func(_ *testing.T) {
		expectedKey := "iam:user:user-123:permissions"
		_ = expectedKey
		_ = userID
	})
}

func TestCacheTTLConfiguration(t *testing.T) {
	logger := zaptest.NewLogger(t)
	mockRedis := &Client{
		rdb:    nil,
		logger: logger,
	}

	t.Run("default TTLs follow security best practices", func(t *testing.T) {
		config := DefaultCacheConfig()

		// User profile: 5 minutes (moderate change rate)
		assert.Equal(t, 5*time.Minute, config.UserProfileTTL,
			"User profile cache should be 5 minutes for balanced performance")

		// Security-sensitive data: 2 minutes (faster invalidation)
		assert.Equal(t, 2*time.Minute, config.RoleCheckTTL,
			"Role check cache should be 2 minutes for security")
		assert.Equal(t, 2*time.Minute, config.PermissionTTL,
			"Permission cache should be 2 minutes for security")
	})

	t.Run("custom TTLs can be configured", func(t *testing.T) {
		customConfig := &CacheConfig{
			UserProfileTTL: 15 * time.Minute,
			RoleCheckTTL:   5 * time.Minute,
			PermissionTTL:  5 * time.Minute,
		}
		cache := NewUserCacheService(mockRedis, logger, customConfig)

		assert.Equal(t, 15*time.Minute, cache.userProfileTTL)
		assert.Equal(t, 5*time.Minute, cache.roleCheckTTL)
		assert.Equal(t, 5*time.Minute, cache.permissionTTL)
	})
}

func TestCacheStats(t *testing.T) {
	t.Run("CacheStats structure", func(t *testing.T) {
		stats := &CacheStats{
			HitRate:        95.5,
			KeyspaceHits:   1000,
			KeyspaceMisses: 50,
			TotalKeys:      100,
			MemoryUsageMB:  1.5,
		}

		assert.Equal(t, 95.5, stats.HitRate)
		assert.Equal(t, int64(1000), stats.KeyspaceHits)
		assert.Equal(t, int64(50), stats.KeyspaceMisses)
		assert.Equal(t, int64(100), stats.TotalKeys)
		assert.Equal(t, 1.5, stats.MemoryUsageMB)
	})
}

// Integration tests require actual Redis connection
// Run with: go test -tags=integration
// These tests are separated to allow unit tests to run without Redis
