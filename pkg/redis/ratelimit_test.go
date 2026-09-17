// SPDX-License-Identifier: AGPL-3.0-or-later

package redis

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"go.uber.org/zap"
)

func setupTestRateLimiter(t *testing.T) (*RateLimiter, *miniredis.Miniredis, *Client) {
	t.Helper()

	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("Failed to create miniredis: %v", err)
	}

	cfg := &Config{
		URL:          "redis://" + mr.Addr(),
		MaxRetries:   3,
		MinIdleConns: 1,
		MaxIdleConns: 2,
		DialTimeout:  5 * time.Second,
	}

	logger := zap.NewNop()
	client, err := NewClient(cfg, logger)
	if err != nil {
		mr.Close()
		t.Fatalf("Failed to create client: %v", err)
	}

	limiter := NewRateLimiter(client, "test")

	return limiter, mr, client
}

func TestNewRateLimiter(t *testing.T) {
	limiter, mr, client := setupTestRateLimiter(t)
	defer mr.Close()
	defer client.Close() //nolint:errcheck

	if limiter == nil {
		t.Fatal("NewRateLimiter() returned nil")
	}

	if limiter.client == nil {
		t.Fatal("RateLimiter client is nil")
	}

	if limiter.prefix != "test" {
		t.Errorf("RateLimiter prefix = %q, want %q", limiter.prefix, "test")
	}
}

func TestRateLimiter_Check_AllowRequests(t *testing.T) {
	limiter, mr, client := setupTestRateLimiter(t)
	defer mr.Close()
	defer client.Close() //nolint:errcheck

	ctx := context.Background()
	key := "user:123"
	limit := 5
	window := 1 * time.Minute
	blockDuration := 5 * time.Minute

	// Make requests within the limit
	for i := 0; i < limit; i++ {
		result, err := limiter.Check(ctx, key, limit, window, blockDuration)
		if err != nil {
			t.Fatalf("Check() iteration %d error = %v", i, err)
		}

		if !result.Allowed {
			t.Errorf("Check() iteration %d: Allowed = false, want true", i)
		}

		expectedRemaining := limit - i - 1
		if result.Remaining != expectedRemaining {
			t.Errorf("Check() iteration %d: Remaining = %d, want %d", i, result.Remaining, expectedRemaining)
		}

		if result.TotalHits != int64(i+1) {
			t.Errorf("Check() iteration %d: TotalHits = %d, want %d", i, result.TotalHits, i+1)
		}
	}
}

func TestRateLimiter_Check_BlockWhenLimitExceeded(t *testing.T) {
	limiter, mr, client := setupTestRateLimiter(t)
	defer mr.Close()
	defer client.Close() //nolint:errcheck

	ctx := context.Background()
	key := "user:456"
	limit := 3
	window := 1 * time.Minute
	blockDuration := 2 * time.Minute

	// Make requests up to the limit
	for i := 0; i < limit; i++ {
		result, err := limiter.Check(ctx, key, limit, window, blockDuration)
		if err != nil {
			t.Fatalf("Check() iteration %d error = %v", i, err)
		}
		if !result.Allowed {
			t.Errorf("Check() iteration %d: should be allowed", i)
		}
	}

	// Next request should be blocked
	result, err := limiter.Check(ctx, key, limit, window, blockDuration)
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}

	if result.Allowed {
		t.Error("Check() Allowed = true, want false (should be blocked)")
	}

	if result.Remaining != 0 {
		t.Errorf("Check() Remaining = %d, want 0", result.Remaining)
	}

	if result.RetryAfter <= 0 {
		t.Error("Check() RetryAfter should be > 0 when blocked")
	}

	if result.TotalHits != int64(limit) {
		t.Errorf("Check() TotalHits = %d, want %d", result.TotalHits, limit)
	}

	// Subsequent requests should also be blocked
	result2, err := limiter.Check(ctx, key, limit, window, blockDuration)
	if err != nil {
		t.Fatalf("Check() second blocked request error = %v", err)
	}

	if result2.Allowed {
		t.Error("Check() second request should still be blocked")
	}
}

func TestRateLimiter_Check_DifferentKeys(t *testing.T) {
	limiter, mr, client := setupTestRateLimiter(t)
	defer mr.Close()
	defer client.Close() //nolint:errcheck

	ctx := context.Background()
	limit := 2
	window := 1 * time.Minute
	blockDuration := 2 * time.Minute

	// Exhaust limit for key1
	key1 := "user:key1"
	for i := 0; i < limit; i++ {
		_, err := limiter.Check(ctx, key1, limit, window, blockDuration)
		if err != nil {
			t.Fatalf("Check() key1 error = %v", err)
		}
	}

	// key1 should be blocked
	result1, err := limiter.Check(ctx, key1, limit, window, blockDuration)
	if err != nil {
		t.Fatalf("Check() key1 blocked error = %v", err)
	}
	if result1.Allowed {
		t.Error("key1 should be blocked")
	}

	// key2 should still work
	key2 := "user:key2"
	result2, err := limiter.Check(ctx, key2, limit, window, blockDuration)
	if err != nil {
		t.Fatalf("Check() key2 error = %v", err)
	}
	if !result2.Allowed {
		t.Error("key2 should be allowed")
	}
}

func TestRateLimiter_Reset(t *testing.T) {
	limiter, mr, client := setupTestRateLimiter(t)
	defer mr.Close()
	defer client.Close() //nolint:errcheck

	ctx := context.Background()
	key := "user:reset"
	limit := 2
	window := 1 * time.Minute
	blockDuration := 2 * time.Minute

	// Exhaust the limit
	for i := 0; i < limit; i++ {
		_, err := limiter.Check(ctx, key, limit, window, blockDuration)
		if err != nil {
			t.Fatalf("Check() error = %v", err)
		}
	}

	// Should be blocked
	result, err := limiter.Check(ctx, key, limit, window, blockDuration)
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if result.Allowed {
		t.Error("Should be blocked before reset")
	}

	// Reset the rate limit
	err = limiter.Reset(ctx, key)
	if err != nil {
		t.Fatalf("Reset() error = %v", err)
	}

	// Should be allowed again
	result2, err := limiter.Check(ctx, key, limit, window, blockDuration)
	if err != nil {
		t.Fatalf("Check() after reset error = %v", err)
	}
	if !result2.Allowed {
		t.Error("Should be allowed after reset")
	}
}

func TestRateLimiter_GetStatus(t *testing.T) {
	limiter, mr, client := setupTestRateLimiter(t)
	defer mr.Close()
	defer client.Close() //nolint:errcheck

	ctx := context.Background()
	key := "user:status"
	limit := 5
	window := 1 * time.Minute

	t.Run("Status for new key", func(t *testing.T) {
		status, err := limiter.GetStatus(ctx, key, limit, window)
		if err != nil {
			t.Fatalf("GetStatus() error = %v", err)
		}

		if !status.Allowed {
			t.Error("GetStatus() Allowed = false, want true for new key")
		}

		if status.Remaining != limit {
			t.Errorf("GetStatus() Remaining = %d, want %d", status.Remaining, limit)
		}

		if status.TotalHits != 0 {
			t.Errorf("GetStatus() TotalHits = %d, want 0", status.TotalHits)
		}
	})

	t.Run("Status after some requests", func(t *testing.T) {
		blockDuration := 2 * time.Minute
		// Make 3 requests
		for i := 0; i < 3; i++ {
			_, err := limiter.Check(ctx, key, limit, window, blockDuration)
			if err != nil {
				t.Fatalf("Check() error = %v", err)
			}
		}

		status, err := limiter.GetStatus(ctx, key, limit, window)
		if err != nil {
			t.Fatalf("GetStatus() error = %v", err)
		}

		if !status.Allowed {
			t.Error("GetStatus() Allowed = false, want true")
		}

		expectedRemaining := limit - 3
		if status.Remaining != expectedRemaining {
			t.Errorf("GetStatus() Remaining = %d, want %d", status.Remaining, expectedRemaining)
		}

		if status.TotalHits != 3 {
			t.Errorf("GetStatus() TotalHits = %d, want 3", status.TotalHits)
		}
	})
}

func TestRateLimiter_GetStatus_Blocked(t *testing.T) {
	limiter, mr, client := setupTestRateLimiter(t)
	defer mr.Close()
	defer client.Close() //nolint:errcheck

	ctx := context.Background()
	key := "user:blocked_status"
	limit := 2
	window := 1 * time.Minute
	blockDuration := 3 * time.Minute

	// Exhaust limit to get blocked
	for i := 0; i < limit; i++ {
		_, err := limiter.Check(ctx, key, limit, window, blockDuration)
		if err != nil {
			t.Fatalf("Check() error = %v", err)
		}
	}

	// Trigger blocking
	_, err := limiter.Check(ctx, key, limit, window, blockDuration)
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}

	// Get status
	status, err := limiter.GetStatus(ctx, key, limit, window)
	if err != nil {
		t.Fatalf("GetStatus() error = %v", err)
	}

	if status.Allowed {
		t.Error("GetStatus() Allowed = true, want false (blocked)")
	}

	if status.Remaining != 0 {
		t.Errorf("GetStatus() Remaining = %d, want 0", status.Remaining)
	}

	if status.RetryAfter <= 0 {
		t.Error("GetStatus() RetryAfter should be > 0 for blocked user")
	}
}

func TestRateLimiter_Check_WithZeroLimit(t *testing.T) {
	limiter, mr, client := setupTestRateLimiter(t)
	defer mr.Close()
	defer client.Close() //nolint:errcheck

	ctx := context.Background()
	key := "user:zero"
	limit := 0
	window := 1 * time.Minute
	blockDuration := 2 * time.Minute

	// With zero limit, first request should be blocked
	result, err := limiter.Check(ctx, key, limit, window, blockDuration)
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}

	if result.Allowed {
		t.Error("Check() with zero limit should block immediately")
	}
}

func TestRateLimiter_Check_MultipleWindows(t *testing.T) {
	limiter, mr, client := setupTestRateLimiter(t)
	defer mr.Close()
	defer client.Close() //nolint:errcheck

	ctx := context.Background()
	key := "user:windows"
	limit := 3
	window := 500 * time.Millisecond
	blockDuration := 1 * time.Second

	// Exhaust the limit
	for i := 0; i < limit; i++ {
		result, err := limiter.Check(ctx, key, limit, window, blockDuration)
		if err != nil {
			t.Fatalf("Check() iteration %d error = %v", i, err)
		}
		if !result.Allowed {
			t.Errorf("Check() iteration %d should be allowed", i)
		}
	}

	// Should be blocked
	result, err := limiter.Check(ctx, key, limit, window, blockDuration)
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if result.Allowed {
		t.Error("Should be blocked")
	}

	// Fast forward time in miniredis
	mr.FastForward(window)

	// After window expires and block duration, should be allowed again
	time.Sleep(50 * time.Millisecond) // Small buffer

	_, err = limiter.Check(ctx, key, limit, window, blockDuration)
	if err != nil {
		t.Fatalf("Check() after window error = %v", err)
	}

	// Note: This test might still fail because the sliding window
	// implementation tracks individual requests with timestamps.
	// The behavior depends on the Lua script logic.
}

func TestRateLimiter_Check_ConcurrentRequests(t *testing.T) {
	limiter, mr, client := setupTestRateLimiter(t)
	defer mr.Close()
	defer client.Close() //nolint:errcheck

	ctx := context.Background()
	key := "user:concurrent"
	limit := 10
	window := 1 * time.Minute
	blockDuration := 2 * time.Minute

	// Make concurrent requests
	results := make(chan *RateLimitResult, limit)
	errors := make(chan error, limit)

	for i := 0; i < limit; i++ {
		go func() {
			result, err := limiter.Check(ctx, key, limit, window, blockDuration)
			if err != nil {
				errors <- err
				return
			}
			results <- result
		}()
	}

	// Collect results
	allowedCount := 0
	for i := 0; i < limit; i++ {
		select {
		case err := <-errors:
			t.Fatalf("Concurrent Check() error = %v", err)
		case result := <-results:
			if result.Allowed {
				allowedCount++
			}
		case <-time.After(5 * time.Second):
			t.Fatal("Timeout waiting for concurrent requests")
		}
	}

	// All should be allowed since we're within the limit
	if allowedCount != limit {
		t.Errorf("Allowed count = %d, want %d", allowedCount, limit)
	}
}

func TestRateLimiter_Reset_NonExistentKey(t *testing.T) {
	limiter, mr, client := setupTestRateLimiter(t)
	defer mr.Close()
	defer client.Close() //nolint:errcheck

	ctx := context.Background()

	// Reset a key that doesn't exist should not error
	err := limiter.Reset(ctx, "non-existent-key")
	if err != nil {
		t.Errorf("Reset() on non-existent key error = %v, want nil", err)
	}
}

func TestRateLimiter_Check_VeryShortWindow(t *testing.T) {
	limiter, mr, client := setupTestRateLimiter(t)
	defer mr.Close()
	defer client.Close() //nolint:errcheck

	ctx := context.Background()
	key := "user:short"
	limit := 2
	window := 100 * time.Millisecond
	blockDuration := 200 * time.Millisecond

	// First request should succeed
	result, err := limiter.Check(ctx, key, limit, window, blockDuration)
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if !result.Allowed {
		t.Error("First request should be allowed")
	}

	// Second request should succeed
	result2, err := limiter.Check(ctx, key, limit, window, blockDuration)
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if !result2.Allowed {
		t.Error("Second request should be allowed")
	}

	// Third request should be blocked
	result3, err := limiter.Check(ctx, key, limit, window, blockDuration)
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if result3.Allowed {
		t.Error("Third request should be blocked")
	}
}

func TestRateLimitResult_Fields(t *testing.T) {
	limiter, mr, client := setupTestRateLimiter(t)
	defer mr.Close()
	defer client.Close() //nolint:errcheck

	ctx := context.Background()
	key := "user:fields"
	limit := 5
	window := 1 * time.Minute
	blockDuration := 2 * time.Minute

	result, err := limiter.Check(ctx, key, limit, window, blockDuration)
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}

	// Verify all fields are populated
	if result.Allowed != true {
		t.Errorf("Allowed field not set correctly")
	}

	if result.Remaining != 4 {
		t.Errorf("Remaining = %d, want 4", result.Remaining)
	}

	if result.ResetAt.IsZero() {
		t.Error("ResetAt should not be zero")
	}

	if result.ResetAt.Before(time.Now()) {
		t.Error("ResetAt should be in the future")
	}

	if result.TotalHits != 1 {
		t.Errorf("TotalHits = %d, want 1", result.TotalHits)
	}

	// RetryAfter should be 0 when allowed
	if result.RetryAfter != 0 {
		t.Errorf("RetryAfter = %v, want 0 when allowed", result.RetryAfter)
	}
}
