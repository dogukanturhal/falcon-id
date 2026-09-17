// SPDX-License-Identifier: AGPL-3.0-or-later

package middleware

// distributed_rate_limiter.go implements a Redis-backed per-tenant sliding
// window rate limiter shared across all Falcon-ID instances.
//
// Design:
//   - Each tenant has one Redis sorted set keyed "ratelimit:<tenant_id>".
//   - Every request adds the current millisecond timestamp as both score and member.
//   - A pipeline atomically: removes expired entries (outside 1-hour window),
//     adds the current entry, counts the window size, and refreshes the key TTL.
//   - Rate limits are derived from the tenant's subscription plan (from JWT claim
//     or a Redis-cached lookup).
//   - A nil Redis client causes the limiter to fail open — all requests are allowed
//     (suitable for development environments without Redis).
//
// Limits per plan:
//   starter:      1,000 req/hour
//   professional: 10,000 req/hour
//   enterprise:   100,000 req/hour
//   unlimited:    1,000,000 req/hour (effectively uncapped)

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
)

const (
	// windowDuration is the sliding window length for rate limiting.
	windowDuration = time.Hour

	// windowMs is the window in milliseconds — used for sorted set score arithmetic.
	windowMs = int64(windowDuration / time.Millisecond)

	// keyTTL is the Redis key expiry. Two windows ensures entries are not
	// evicted before the window slides past them.
	keyTTL = 2 * windowDuration

	// planCacheKeyPrefix is the Redis key prefix for plan lookups.
	// Format: "ratelimit:plan:<tenant_id>"
	planCacheKeyPrefix = "ratelimit:plan:"

	// planCacheTTL is how long to cache a tenant's plan in Redis.
	planCacheTTL = 10 * time.Minute

	// defaultPlan is used when the plan cannot be resolved.
	defaultPlan = "starter"
)

// planLimits maps subscription plan names to requests-per-hour ceilings.
var planLimits = map[string]int64{
	"starter":      1_000,
	"professional": 10_000,
	"enterprise":   100_000,
	"unlimited":    1_000_000,
}

// DistributedRateLimiter enforces per-tenant rate limits using Redis sorted
// sets implementing a sliding window algorithm. One instance is safe to use
// from multiple goroutines.
type DistributedRateLimiter struct {
	redis  redis.Cmdable
	limits map[string]int64
	log    *zap.SugaredLogger
}

// NewDistributedRateLimiter creates a DistributedRateLimiter backed by the
// provided Redis client. A nil client causes the limiter to fail open.
func NewDistributedRateLimiter(redisClient redis.Cmdable, log *zap.SugaredLogger) *DistributedRateLimiter {
	return &DistributedRateLimiter{
		redis:  redisClient,
		limits: planLimits,
		log:    log,
	}
}

// Middleware returns a Gin handler that enforces per-tenant rate limits.
//
// Response headers set on every non-blocked request:
//
//	X-RateLimit-Limit     — the plan ceiling (req/hour)
//	X-RateLimit-Remaining — remaining requests in the current window
//	X-RateLimit-Reset     — Unix timestamp (seconds) when the window resets
//
// When the limit is exceeded the handler aborts with 429 and a JSON body:
//
//	{"error":"rate_limit_exceeded","retry_after":seconds}
func (rl *DistributedRateLimiter) Middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Resolve tenant ID from the authenticated user context (set by AuthMiddleware).
		tenantID := rl.extractTenantID(c)
		if tenantID == "" {
			// No tenant context — unauthenticated or platform-internal requests.
			// Pass through without rate limiting.
			c.Next()
			return
		}

		// Resolve the tenant's plan. Start from JWT claim, fall back to cached
		// DB lookup, then use the conservative default.
		plan := rl.extractPlan(c, tenantID)

		ctx := c.Request.Context()
		allowed, remaining, err := rl.isAllowed(ctx, tenantID, plan)
		if err != nil {
			// Fail open: log the error and let the request through.
			rl.log.Warnw("DistributedRateLimiter: Redis error, failing open",
				"tenant_id", tenantID,
				"plan", plan,
				"err", err,
			)
			c.Next()
			return
		}

		limit := rl.limitForPlan(plan)
		resetAt := time.Now().Add(windowDuration).Unix()

		c.Header("X-RateLimit-Limit", strconv.FormatInt(limit, 10))
		c.Header("X-RateLimit-Remaining", strconv.FormatInt(remaining, 10))
		c.Header("X-RateLimit-Reset", strconv.FormatInt(resetAt, 10))

		if !allowed {
			retryAfter := int64(windowDuration.Seconds())

			rl.log.Warnw("DistributedRateLimiter: tenant rate limit exceeded",
				"tenant_id", tenantID,
				"plan", plan,
				"limit", limit,
			)

			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{
				"error":       "rate_limit_exceeded",
				"retry_after": retryAfter,
			})
			return
		}

		c.Next()
	}
}

// isAllowed checks whether the tenant has remaining quota in the sliding window.
// Returns (allowed, remaining, error). On Redis error the caller should fail open.
//
// Implementation detail:
//
//	The pipeline is NOT atomic by default (multiple round-trips), but the
//	combination of ZREMRANGEBYSCORE + ZADD + ZCARD + EXPIRE is atomic enough
//	for rate limiting purposes: a small race between ZADD and ZCARD on
//	concurrent instances results in at most a few requests over the limit,
//	not a security breach. Use a Lua script if hard-atomic enforcement is needed.
func (rl *DistributedRateLimiter) isAllowed(ctx context.Context, tenantID string, plan string) (bool, int64, error) {
	if rl.redis == nil {
		// No Redis configured — fail open.
		limit := rl.limitForPlan(plan)
		return true, limit, nil
	}

	limit := rl.limitForPlan(plan)
	key := fmt.Sprintf("ratelimit:%s", tenantID)
	now := time.Now().UnixMilli()
	windowStart := now - windowMs

	pipe := rl.redis.Pipeline()
	// Remove expired entries from the sorted set.
	pipe.ZRemRangeByScore(ctx, key, "0", strconv.FormatInt(windowStart, 10))
	// Add the current request timestamp (member = score = now to ensure uniqueness).
	pipe.ZAdd(ctx, key, redis.Z{Score: float64(now), Member: strconv.FormatInt(now, 10)})
	// Count all entries in the window.
	countCmd := pipe.ZCard(ctx, key)
	// Extend the key TTL so idle tenants' keys are eventually evicted.
	pipe.Expire(ctx, key, keyTTL)

	if _, err := pipe.Exec(ctx); err != nil {
		return false, 0, fmt.Errorf("isAllowed pipeline: %w", err)
	}

	count := countCmd.Val()
	remaining := limit - count
	if remaining < 0 {
		remaining = 0
	}

	return count <= limit, remaining, nil
}

// limitForPlan returns the requests-per-hour limit for the given plan name.
// Falls back to the starter limit for unrecognised plan names.
func (rl *DistributedRateLimiter) limitForPlan(plan string) int64 {
	if l, ok := rl.limits[plan]; ok {
		return l
	}
	return rl.limits[defaultPlan]
}

// extractTenantID reads the tenant_id set in the Gin context by AuthMiddleware.
// Returns an empty string when no tenant context is present.
func (rl *DistributedRateLimiter) extractTenantID(c *gin.Context) string {
	// AuthMiddleware stores tenant_id as a string representation of uuid.UUID.
	if raw, exists := c.Get("tenant_id"); exists {
		switch v := raw.(type) {
		case string:
			return v
		case uuid.UUID:
			return v.String()
		}
	}
	return ""
}

// extractPlan resolves the tenant's subscription plan in order of preference:
//  1. JWT claim "plan" (set by token service from subscription resolver).
//  2. Redis plan cache (warm from previous request).
//  3. Conservative default ("starter").
//
// The plan cache is intentionally write-through: when a new plan is read from
// the JWT it is written back to Redis so subsequent requests in the same
// window reuse it without another DB round-trip.
func (rl *DistributedRateLimiter) extractPlan(c *gin.Context, tenantID string) string {
	// 1. JWT claim — set by AuthMiddleware when the token carries a "plan" claim.
	if raw, exists := c.Get("plan"); exists {
		if plan, ok := raw.(string); ok && plan != "" {
			rl.cachePlan(c.Request.Context(), tenantID, plan)
			return plan
		}
	}

	// 2. Redis plan cache.
	if rl.redis != nil {
		cacheKey := planCacheKeyPrefix + tenantID
		if cached, err := rl.redis.Get(c.Request.Context(), cacheKey).Result(); err == nil && cached != "" {
			return cached
		}
	}

	// 3. Default.
	return defaultPlan
}

// cachePlan writes the plan into Redis with a short TTL. Best-effort — errors
// are silently discarded so a Redis hiccup never blocks a request.
func (rl *DistributedRateLimiter) cachePlan(ctx context.Context, tenantID, plan string) {
	if rl.redis == nil {
		return
	}
	cacheKey := planCacheKeyPrefix + tenantID
	_ = rl.redis.Set(ctx, cacheKey, plan, planCacheTTL).Err()
}
