// SPDX-License-Identifier: AGPL-3.0-or-later

package redis

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
)

// TenantCacheService provides Redis caching for tenant lookups.
// Pattern: Write-through cache with TTL-based expiration
type TenantCacheService struct {
	client    *Client
	logger    *zap.Logger
	keyPrefix string
	ttl       time.Duration
}

// NewTenantCacheService creates a new tenant cache service
func NewTenantCacheService(client *Client, logger *zap.Logger, keyPrefix string, ttl time.Duration) *TenantCacheService {
	if keyPrefix == "" {
		keyPrefix = "iam:tenant"
	}
	if ttl == 0 {
		ttl = 5 * time.Minute // Default 5 minute TTL for tenant data
	}

	return &TenantCacheService{
		client:    client,
		logger:    logger,
		keyPrefix: keyPrefix,
		ttl:       ttl,
	}
}

// Get retrieves a cached value
func (s *TenantCacheService) Get(ctx context.Context, key string) (string, error) {
	fullKey := fmt.Sprintf("%s:%s", s.keyPrefix, key)
	val, err := s.client.Get(ctx, fullKey)
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return "", nil
		}
		s.logger.Warn("Tenant cache get failed",
			zap.String("key", fullKey),
			zap.Error(err),
		)
		return "", fmt.Errorf("Get: %w", err)
	}
	return val, nil
}

// Set caches a value with TTL
func (s *TenantCacheService) Set(ctx context.Context, key string, value string, ttl time.Duration) error {
	fullKey := fmt.Sprintf("%s:%s", s.keyPrefix, key)
	if ttl == 0 {
		ttl = s.ttl
	}

	if err := s.client.Set(ctx, fullKey, value, ttl); err != nil {
		s.logger.Warn("Tenant cache set failed",
			zap.String("key", fullKey),
			zap.Error(err),
		)
		return fmt.Errorf("Set: %w", err)
	}
	return nil
}

// Del removes a key from cache
func (s *TenantCacheService) Del(ctx context.Context, key string) error {
	fullKey := fmt.Sprintf("%s:%s", s.keyPrefix, key)
	if err := s.client.Del(ctx, fullKey); err != nil {
		s.logger.Warn("Tenant cache delete failed",
			zap.String("key", fullKey),
			zap.Error(err),
		)
		return fmt.Errorf("Del: %w", err)
	}
	return nil
}

// InvalidateTenant removes all cached data for a tenant
func (s *TenantCacheService) InvalidateTenant(ctx context.Context, tenantID string) error {
	// Common cache keys for a tenant
	keys := []string{
		fmt.Sprintf("%s:id:%s", s.keyPrefix, tenantID),
		fmt.Sprintf("%s:slug:%s", s.keyPrefix, tenantID),
	}

	for _, key := range keys {
		if err := s.client.Del(ctx, key); err != nil {
			s.logger.Warn("Failed to invalidate tenant cache entry",
				zap.String("key", key),
				zap.Error(err),
			)
		}
	}

	return nil
}
