// SPDX-License-Identifier: AGPL-3.0-or-later

package redis

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// RateLimiter implements a Redis-based sliding window rate limiter
type RateLimiter struct {
	client *Client
	prefix string
}

// RateLimitResult contains the result of a rate limit check
type RateLimitResult struct {
	Allowed    bool
	Remaining  int
	ResetAt    time.Time
	RetryAfter time.Duration
	TotalHits  int64
}

// NewRateLimiter creates a new Redis-based rate limiter
func NewRateLimiter(client *Client, prefix string) *RateLimiter {
	return &RateLimiter{
		client: client,
		prefix: prefix,
	}
}

// slidingWindowScript is a Lua script for atomic sliding window rate limiting
var slidingWindowScript = redis.NewScript(`
local key = KEYS[1]
local now = tonumber(ARGV[1])
local window = tonumber(ARGV[2])
local limit = tonumber(ARGV[3])
local block_duration = tonumber(ARGV[4])

-- Check if blocked
local blocked_key = key .. ":blocked"
local blocked_until = redis.call('GET', blocked_key)
if blocked_until then
    local blocked_ts = tonumber(blocked_until)
    if now < blocked_ts then
        return {0, 0, blocked_ts, -1}
    else
        redis.call('DEL', blocked_key)
    end
end

-- Remove old entries outside the window
local window_start = now - window
redis.call('ZREMRANGEBYSCORE', key, '-inf', window_start)

-- Count current requests in window
local count = redis.call('ZCARD', key)

if count >= limit then
    -- Block the client
    local block_until = now + block_duration
    redis.call('SET', blocked_key, block_until, 'EX', math.ceil(block_duration / 1000))
    return {0, 0, block_until, count}
end

-- Add current request with unique member
local member = now .. ':' .. math.random(1000000)
redis.call('ZADD', key, now, member)
redis.call('EXPIRE', key, math.ceil(window / 1000) + 1)

local remaining = limit - count - 1
local reset_at = now + window

return {1, remaining, reset_at, count + 1}
`)

// Check performs a rate limit check using sliding window algorithm
func (r *RateLimiter) Check(ctx context.Context, key string, limit int, window time.Duration, blockDuration time.Duration) (*RateLimitResult, error) {
	fullKey := fmt.Sprintf("%s:ratelimit:%s", r.prefix, key)
	now := time.Now().UnixMilli()
	windowMs := window.Milliseconds()
	blockMs := blockDuration.Milliseconds()

	result, err := slidingWindowScript.Run(ctx, r.client.Redis(), []string{fullKey}, now, windowMs, limit, blockMs).Slice()
	if err != nil {
		return nil, fmt.Errorf("rate limit script error: %w", err)
	}

	allowed := result[0].(int64) == 1
	remaining := int(result[1].(int64))
	resetTs := result[2].(int64)
	totalHits := result[3].(int64)

	resetAt := time.UnixMilli(resetTs)
	var retryAfter time.Duration
	if !allowed {
		retryAfter = time.Until(resetAt)
		if retryAfter < 0 {
			retryAfter = 0
		}
	}

	return &RateLimitResult{
		Allowed:    allowed,
		Remaining:  remaining,
		ResetAt:    resetAt,
		RetryAfter: retryAfter,
		TotalHits:  totalHits,
	}, nil
}

// Reset clears the rate limit for a key
func (r *RateLimiter) Reset(ctx context.Context, key string) error {
	fullKey := fmt.Sprintf("%s:ratelimit:%s", r.prefix, key)
	blockedKey := fullKey + ":blocked"

	pipe := r.client.Redis().Pipeline()
	pipe.Del(ctx, fullKey)
	pipe.Del(ctx, blockedKey)
	_, err := pipe.Exec(ctx)
	if err != nil {
		return fmt.Errorf("Reset: Exec failed: %w", err)
	}
	return nil
}

// GetStatus returns the current rate limit status for a key without incrementing
func (r *RateLimiter) GetStatus(ctx context.Context, key string, limit int, window time.Duration) (*RateLimitResult, error) {
	fullKey := fmt.Sprintf("%s:ratelimit:%s", r.prefix, key)
	now := time.Now().UnixMilli()
	windowStart := now - window.Milliseconds()

	// Check if blocked
	blockedKey := fullKey + ":blocked"
	blockedUntil, err := r.client.Redis().Get(ctx, blockedKey).Int64()
	if err == nil && now < blockedUntil {
		return &RateLimitResult{
			Allowed:    false,
			Remaining:  0,
			ResetAt:    time.UnixMilli(blockedUntil),
			RetryAfter: time.Until(time.UnixMilli(blockedUntil)),
			TotalHits:  int64(limit),
		}, nil
	}

	// Count current requests in window
	count, err := r.client.Redis().ZCount(ctx, fullKey, fmt.Sprint(windowStart), fmt.Sprint(now)).Result()
	if err != nil && !errors.Is(err, redis.Nil) {
		return nil, fmt.Errorf("GetStatus: %w", err)
	}

	remaining := limit - int(count)
	if remaining < 0 {
		remaining = 0
	}

	return &RateLimitResult{
		Allowed:   remaining > 0,
		Remaining: remaining,
		ResetAt:   time.Now().Add(window),
		TotalHits: count,
	}, nil
}
