// SPDX-License-Identifier: AGPL-3.0-or-later

package redis

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
)

// UserCacheService provides Redis caching for IAM user lookups.
// Pattern: Write-through cache with TTL-based expiration
// Follows Customer360CacheService pattern from CRM module
type UserCacheService struct {
	client    *Client
	logger    *zap.Logger
	keyPrefix string
	// Cache TTLs (configurable)
	userProfileTTL time.Duration
	roleCheckTTL   time.Duration
	permissionTTL  time.Duration
}

// CacheConfig holds configurable cache TTLs
type CacheConfig struct {
	UserProfileTTL time.Duration
	RoleCheckTTL   time.Duration
	PermissionTTL  time.Duration
}

// DefaultCacheConfig returns sensible defaults
func DefaultCacheConfig() *CacheConfig {
	return &CacheConfig{
		UserProfileTTL: 5 * time.Minute,
		RoleCheckTTL:   2 * time.Minute,
		PermissionTTL:  2 * time.Minute,
	}
}

// NewUserCacheService creates a new user cache service
func NewUserCacheService(client *Client, logger *zap.Logger, config *CacheConfig) *UserCacheService {
	if config == nil {
		config = DefaultCacheConfig()
	}

	return &UserCacheService{
		client:         client,
		logger:         logger,
		keyPrefix:      "iam:user",
		userProfileTTL: config.UserProfileTTL,
		roleCheckTTL:   config.RoleCheckTTL,
		permissionTTL:  config.PermissionTTL,
	}
}

// GetJSON retrieves and unmarshals a cached JSON value
func (s *UserCacheService) GetJSON(ctx context.Context, key string) (interface{}, error) {
	val, err := s.client.Get(ctx, key)
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return nil, nil
		}
		s.logger.Warn("Cache get failed",
			zap.String("key", key),
			zap.Error(err),
		)
		return nil, fmt.Errorf("GetJSON: %w", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal([]byte(val), &result); err != nil {
		s.logger.Warn("Cache unmarshal failed",
			zap.String("key", key),
			zap.Error(err),
		)
		return nil, fmt.Errorf("GetJSON: %w", err)
	}

	return result, nil
}

// SetJSON marshals and caches a JSON value with TTL
func (s *UserCacheService) SetJSON(ctx context.Context, key string, value interface{}, ttl time.Duration) error {
	data, err := json.Marshal(value)
	if err != nil {
		s.logger.Warn("Cache marshal failed",
			zap.String("key", key),
			zap.Error(err),
		)
		return fmt.Errorf("SetJSON: %w", err)
	}

	if err := s.client.Set(ctx, key, data, ttl); err != nil {
		s.logger.Warn("Cache set failed",
			zap.String("key", key),
			zap.Error(err),
		)
		return fmt.Errorf("SetJSON: %w", err)
	}

	return nil
}

// Delete removes a key from cache
func (s *UserCacheService) Delete(ctx context.Context, key string) error {
	if err := s.client.Del(ctx, key); err != nil {
		s.logger.Warn("Cache delete failed",
			zap.String("key", key),
			zap.Error(err),
		)
		return fmt.Errorf("Delete: %w", err)
	}
	return nil
}

// GetUserProfile retrieves cached user profile
func (s *UserCacheService) GetUserProfile(ctx context.Context, userID string) (map[string]interface{}, error) {
	key := fmt.Sprintf("%s:%s:profile", s.keyPrefix, userID)
	val, err := s.GetJSON(ctx, key)
	if err != nil || val == nil {
		return nil, fmt.Errorf("GetUserProfile: GetJSON failed: %w", err)
	}

	if result, ok := val.(map[string]interface{}); ok {
		return result, nil
	}
	return nil, nil
}

// SetUserProfile caches user profile data
func (s *UserCacheService) SetUserProfile(ctx context.Context, userID string, profile interface{}) error {
	key := fmt.Sprintf("%s:%s:profile", s.keyPrefix, userID)
	return s.SetJSON(ctx, key, profile, s.userProfileTTL)
}

// InvalidateUserProfile removes cached user profile
func (s *UserCacheService) InvalidateUserProfile(ctx context.Context, userID string) error {
	key := fmt.Sprintf("%s:%s:profile", s.keyPrefix, userID)
	return s.Delete(ctx, key)
}

// GetUserRoles retrieves cached user roles
func (s *UserCacheService) GetUserRoles(ctx context.Context, userID string) ([]string, error) {
	key := fmt.Sprintf("%s:%s:roles", s.keyPrefix, userID)
	val, err := s.GetJSON(ctx, key)
	if err != nil || val == nil {
		return nil, fmt.Errorf("GetUserRoles: GetJSON failed: %w", err)
	}

	if rolesMap, ok := val.(map[string]interface{}); ok {
		if rolesList, ok := rolesMap["roles"].([]interface{}); ok {
			roles := make([]string, 0, len(rolesList))
			for _, r := range rolesList {
				if roleStr, ok := r.(string); ok {
					roles = append(roles, roleStr)
				}
			}
			return roles, nil
		}
	}
	return nil, nil
}

// SetUserRoles caches user roles
func (s *UserCacheService) SetUserRoles(ctx context.Context, userID string, roles []string) error {
	key := fmt.Sprintf("%s:%s:roles", s.keyPrefix, userID)
	data := map[string]interface{}{"roles": roles}
	return s.SetJSON(ctx, key, data, s.roleCheckTTL)
}

// InvalidateUserRoles removes cached user roles
func (s *UserCacheService) InvalidateUserRoles(ctx context.Context, userID string) error {
	key := fmt.Sprintf("%s:%s:roles", s.keyPrefix, userID)
	return s.Delete(ctx, key)
}

// GetUserPermissions retrieves cached user permissions
func (s *UserCacheService) GetUserPermissions(ctx context.Context, userID string) ([]string, error) {
	key := fmt.Sprintf("%s:%s:permissions", s.keyPrefix, userID)
	val, err := s.GetJSON(ctx, key)
	if err != nil || val == nil {
		return nil, fmt.Errorf("GetUserPermissions: GetJSON failed: %w", err)
	}

	if permsMap, ok := val.(map[string]interface{}); ok {
		if permsList, ok := permsMap["permissions"].([]interface{}); ok {
			perms := make([]string, 0, len(permsList))
			for _, p := range permsList {
				if permStr, ok := p.(string); ok {
					perms = append(perms, permStr)
				}
			}
			return perms, nil
		}
	}
	return nil, nil
}

// SetUserPermissions caches user permissions
func (s *UserCacheService) SetUserPermissions(ctx context.Context, userID string, permissions []string) error {
	key := fmt.Sprintf("%s:%s:permissions", s.keyPrefix, userID)
	data := map[string]interface{}{"permissions": permissions}
	return s.SetJSON(ctx, key, data, s.permissionTTL)
}

// InvalidateUserPermissions removes cached user permissions
func (s *UserCacheService) InvalidateUserPermissions(ctx context.Context, userID string) error {
	key := fmt.Sprintf("%s:%s:permissions", s.keyPrefix, userID)
	return s.Delete(ctx, key)
}

// InvalidateAllUserCache removes all cached data for a user
func (s *UserCacheService) InvalidateAllUserCache(ctx context.Context, userID string) error {
	keys := []string{
		fmt.Sprintf("%s:%s:profile", s.keyPrefix, userID),
		fmt.Sprintf("%s:%s:roles", s.keyPrefix, userID),
		fmt.Sprintf("%s:%s:permissions", s.keyPrefix, userID),
	}

	for _, key := range keys {
		if err := s.Delete(ctx, key); err != nil {
			s.logger.Warn("Failed to invalidate cache entry",
				zap.String("key", key),
				zap.Error(err),
			)
		}
	}

	return nil
}

// BatchGetUserProfiles retrieves multiple user profiles in a single pipeline
func (s *UserCacheService) BatchGetUserProfiles(ctx context.Context, userIDs []string) (map[string]map[string]interface{}, error) {
	if len(userIDs) == 0 {
		return make(map[string]map[string]interface{}), nil
	}

	pipe := s.client.Pipeline()
	cmds := make(map[string]*redis.StringCmd, len(userIDs))

	for _, userID := range userIDs {
		key := fmt.Sprintf("%s:%s:profile", s.keyPrefix, userID)
		cmds[userID] = pipe.Get(ctx, key)
	}

	if _, err := pipe.Exec(ctx); err != nil && !errors.Is(err, redis.Nil) {
		s.logger.Warn("Batch cache get failed", zap.Error(err))
		return nil, fmt.Errorf("BatchGetUserProfiles: %w", err)
	}

	results := make(map[string]map[string]interface{})
	for userID, cmd := range cmds {
		val, err := cmd.Result()
		if errors.Is(err, redis.Nil) {
			continue
		}
		if err != nil {
			s.logger.Warn("Failed to get cached profile",
				zap.String("user_id", userID),
				zap.Error(err),
			)
			continue
		}

		var profile map[string]interface{}
		if err := json.Unmarshal([]byte(val), &profile); err != nil {
			s.logger.Warn("Failed to unmarshal cached profile",
				zap.String("user_id", userID),
				zap.Error(err),
			)
			continue
		}

		results[userID] = profile
	}

	return results, nil
}

// BatchSetUserProfiles caches multiple user profiles in a single pipeline
func (s *UserCacheService) BatchSetUserProfiles(ctx context.Context, profiles map[string]interface{}) error {
	if len(profiles) == 0 {
		return nil
	}

	pipe := s.client.Pipeline()

	for userID, profile := range profiles {
		key := fmt.Sprintf("%s:%s:profile", s.keyPrefix, userID)
		data, err := json.Marshal(profile)
		if err != nil {
			s.logger.Warn("Failed to marshal profile for batch set",
				zap.String("user_id", userID),
				zap.Error(err),
			)
			continue
		}
		pipe.Set(ctx, key, data, s.userProfileTTL)
	}

	if _, err := pipe.Exec(ctx); err != nil {
		s.logger.Warn("Batch cache set failed", zap.Error(err))
		return fmt.Errorf("BatchSetUserProfiles: %w", err)
	}

	return nil
}

// GetCacheStats returns cache hit/miss statistics
func (s *UserCacheService) GetCacheStats(ctx context.Context) (*CacheStats, error) {
	stats, err := s.client.Stats(ctx)
	if err != nil {
		return nil, fmt.Errorf("GetCacheStats: %w", err)
	}

	return &CacheStats{
		HitRate:        stats.HitRate,
		KeyspaceHits:   stats.KeyspaceHits,
		KeyspaceMisses: stats.KeyspaceMisses,
		TotalKeys:      stats.TotalKeys,
		MemoryUsageMB:  stats.UsedMemoryMB,
	}, nil
}

// CacheStats contains cache performance metrics
type CacheStats struct {
	HitRate        float64
	KeyspaceHits   int64
	KeyspaceMisses int64
	TotalKeys      int64
	MemoryUsageMB  float64
}
