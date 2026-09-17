// SPDX-License-Identifier: AGPL-3.0-or-later

package redis

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"go.uber.org/zap"
)

const testRedisVal1 = "value1"

// setupTestRedis creates a test Redis server using miniredis
func setupTestRedis(t *testing.T) (*Client, *miniredis.Miniredis) {
	t.Helper()

	// Create a miniredis server
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("Failed to create miniredis: %v", err)
	}

	// Create a test config
	cfg := &Config{
		URL:             "redis://" + mr.Addr(),
		MaxRetries:      3,
		MinIdleConns:    1,
		MaxIdleConns:    2,
		ConnMaxLifetime: 30 * time.Minute,
		DialTimeout:     5 * time.Second,
		ReadTimeout:     3 * time.Second,
		WriteTimeout:    3 * time.Second,
	}

	logger := zap.NewNop()
	client, err := NewClient(cfg, logger)
	if err != nil {
		mr.Close()
		t.Fatalf("Failed to create client: %v", err)
	}

	return client, mr
}

func TestNewClient(t *testing.T) {
	t.Run("Successful connection", func(t *testing.T) {
		client, mr := setupTestRedis(t)
		defer mr.Close()
		defer client.Close() //nolint:errcheck

		if client == nil {
			t.Fatal("Expected client to be non-nil")
		}

		if client.rdb == nil {
			t.Error("Expected underlying Redis client to be non-nil")
		}
	})

	t.Run("Invalid Redis URL", func(t *testing.T) {
		cfg := &Config{
			URL:          "invalid-url",
			MaxRetries:   3,
			MinIdleConns: 1,
		}

		logger := zap.NewNop()
		_, err := NewClient(cfg, logger)
		if err == nil {
			t.Error("Expected error for invalid URL")
		}
	})

	t.Run("Connection failure", func(t *testing.T) {
		cfg := &Config{
			URL:          "redis://localhost:9999", // Non-existent Redis
			MaxRetries:   1,
			MinIdleConns: 1,
			DialTimeout:  100 * time.Millisecond,
		}

		logger := zap.NewNop()
		_, err := NewClient(cfg, logger)
		if err == nil {
			t.Error("Expected error for failed connection")
		}
	})
}

func TestDefaultConfig(t *testing.T) {
	url := "redis://localhost:6379"
	cfg := DefaultConfig(url)

	if cfg.URL != url {
		t.Errorf("URL = %s, want %s", cfg.URL, url)
	}

	if cfg.MaxRetries != 3 {
		t.Errorf("MaxRetries = %d, want 3", cfg.MaxRetries)
	}

	if cfg.MinIdleConns != 5 {
		t.Errorf("MinIdleConns = %d, want 5", cfg.MinIdleConns)
	}

	if cfg.MaxIdleConns != 10 {
		t.Errorf("MaxIdleConns = %d, want 10", cfg.MaxIdleConns)
	}

	if cfg.ConnMaxLifetime != 30*time.Minute {
		t.Errorf("ConnMaxLifetime = %v, want 30m", cfg.ConnMaxLifetime)
	}
}

func TestClient_SetAndGet(t *testing.T) {
	client, mr := setupTestRedis(t)
	defer mr.Close()
	defer client.Close() //nolint:errcheck

	ctx := context.Background()

	tests := []struct {
		name       string
		key        string
		value      string
		expiration time.Duration
	}{
		{
			name:       "Simple string",
			key:        "test:key1",
			value:      "test value",
			expiration: 5 * time.Minute,
		},
		{
			name:       "Empty value",
			key:        "test:key2",
			value:      "",
			expiration: 5 * time.Minute,
		},
		{
			name:       "No expiration",
			key:        "test:key3",
			value:      "permanent value",
			expiration: 0,
		},
		{
			name:       "Unicode value",
			key:        "test:key4",
			value:      "Hello 世界 🔐",
			expiration: 5 * time.Minute,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set the value
			err := client.Set(ctx, tt.key, tt.value, tt.expiration)
			if err != nil {
				t.Fatalf("Set() error = %v", err)
			}

			// Get the value
			got, err := client.Get(ctx, tt.key)
			if err != nil {
				t.Fatalf("Get() error = %v", err)
			}

			if got != tt.value {
				t.Errorf("Get() = %q, want %q", got, tt.value)
			}
		})
	}
}

func TestClient_GetNonExistent(t *testing.T) {
	client, mr := setupTestRedis(t)
	defer mr.Close()
	defer client.Close() //nolint:errcheck

	ctx := context.Background()

	_, err := client.Get(ctx, "non-existent-key")
	if err == nil {
		t.Error("Expected error when getting non-existent key")
	}
}

func TestClient_Del(t *testing.T) {
	client, mr := setupTestRedis(t)
	defer mr.Close()
	defer client.Close() //nolint:errcheck

	ctx := context.Background()

	t.Run("Delete single key", func(t *testing.T) {
		key := "test:delete1"
		err := client.Set(ctx, key, "value", 0)
		if err != nil {
			t.Fatalf("Set() error = %v", err)
		}

		err = client.Del(ctx, key)
		if err != nil {
			t.Fatalf("Del() error = %v", err)
		}

		_, err = client.Get(ctx, key)
		if err == nil {
			t.Error("Key should not exist after deletion")
		}
	})

	t.Run("Delete multiple keys", func(t *testing.T) {
		keys := []string{"test:delete2", "test:delete3", "test:delete4"}
		for _, key := range keys {
			err := client.Set(ctx, key, "value", 0)
			if err != nil {
				t.Fatalf("Set() error = %v", err)
			}
		}

		err := client.Del(ctx, keys...)
		if err != nil {
			t.Fatalf("Del() error = %v", err)
		}

		for _, key := range keys {
			_, err = client.Get(ctx, key)
			if err == nil {
				t.Errorf("Key %s should not exist after deletion", key)
			}
		}
	})

	t.Run("Delete non-existent key", func(t *testing.T) {
		err := client.Del(ctx, "non-existent-key")
		if err != nil {
			t.Errorf("Del() error = %v, want nil", err)
		}
	})
}

func TestClient_Exists(t *testing.T) {
	client, mr := setupTestRedis(t)
	defer mr.Close()
	defer client.Close() //nolint:errcheck

	ctx := context.Background()

	t.Run("Check existing key", func(t *testing.T) {
		key := "test:exists1"
		err := client.Set(ctx, key, "value", 0)
		if err != nil {
			t.Fatalf("Set() error = %v", err)
		}

		count, err := client.Exists(ctx, key)
		if err != nil {
			t.Fatalf("Exists() error = %v", err)
		}

		if count != 1 {
			t.Errorf("Exists() = %d, want 1", count)
		}
	})

	t.Run("Check non-existent key", func(t *testing.T) {
		count, err := client.Exists(ctx, "non-existent-key")
		if err != nil {
			t.Fatalf("Exists() error = %v", err)
		}

		if count != 0 {
			t.Errorf("Exists() = %d, want 0", count)
		}
	})

	t.Run("Check multiple keys", func(t *testing.T) {
		keys := []string{"test:exists2", "test:exists3"}
		for _, key := range keys {
			err := client.Set(ctx, key, "value", 0)
			if err != nil {
				t.Fatalf("Set() error = %v", err)
			}
		}

		count, err := client.Exists(ctx, keys...)
		if err != nil {
			t.Fatalf("Exists() error = %v", err)
		}

		if count != 2 {
			t.Errorf("Exists() = %d, want 2", count)
		}
	})
}

func TestClient_Expire(t *testing.T) {
	client, mr := setupTestRedis(t)
	defer mr.Close()
	defer client.Close() //nolint:errcheck

	ctx := context.Background()

	key := "test:expire"
	err := client.Set(ctx, key, "value", 0)
	if err != nil {
		t.Fatalf("Set() error = %v", err)
	}

	err = client.Expire(ctx, key, 10*time.Second)
	if err != nil {
		t.Fatalf("Expire() error = %v", err)
	}

	ttl, err := client.TTL(ctx, key)
	if err != nil {
		t.Fatalf("TTL() error = %v", err)
	}

	if ttl <= 0 || ttl > 10*time.Second {
		t.Errorf("TTL() = %v, want between 0 and 10s", ttl)
	}
}

func TestClient_TTL(t *testing.T) {
	client, mr := setupTestRedis(t)
	defer mr.Close()
	defer client.Close() //nolint:errcheck

	ctx := context.Background()

	t.Run("Key with TTL", func(t *testing.T) {
		key := "test:ttl1"
		err := client.Set(ctx, key, "value", 10*time.Second)
		if err != nil {
			t.Fatalf("Set() error = %v", err)
		}

		ttl, err := client.TTL(ctx, key)
		if err != nil {
			t.Fatalf("TTL() error = %v", err)
		}

		if ttl <= 0 || ttl > 10*time.Second {
			t.Errorf("TTL() = %v, want between 0 and 10s", ttl)
		}
	})

	t.Run("Key without TTL", func(t *testing.T) {
		key := "test:ttl2"
		err := client.Set(ctx, key, "value", 0)
		if err != nil {
			t.Fatalf("Set() error = %v", err)
		}

		ttl, err := client.TTL(ctx, key)
		if err != nil {
			t.Fatalf("TTL() error = %v", err)
		}

		// In Redis, -1 means no expiration
		if ttl != -1 {
			t.Errorf("TTL() = %v, want -1 (no expiration)", ttl)
		}
	})
}

func TestClient_Incr(t *testing.T) {
	client, mr := setupTestRedis(t)
	defer mr.Close()
	defer client.Close() //nolint:errcheck

	ctx := context.Background()

	key := "test:counter"

	// First increment
	val, err := client.Incr(ctx, key)
	if err != nil {
		t.Fatalf("Incr() error = %v", err)
	}
	if val != 1 {
		t.Errorf("Incr() = %d, want 1", val)
	}

	// Second increment
	val, err = client.Incr(ctx, key)
	if err != nil {
		t.Fatalf("Incr() error = %v", err)
	}
	if val != 2 {
		t.Errorf("Incr() = %d, want 2", val)
	}
}

func TestClient_IncrBy(t *testing.T) {
	client, mr := setupTestRedis(t)
	defer mr.Close()
	defer client.Close() //nolint:errcheck

	ctx := context.Background()

	key := "test:counter2"

	tests := []struct {
		name      string
		increment int64
		expected  int64
	}{
		{"Increment by 5", 5, 5},
		{"Increment by 10", 10, 15},
		{"Increment by 1", 1, 16},
		{"Increment by -3", -3, 13},
	}

	currentVal := int64(0)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			val, err := client.IncrBy(ctx, key, tt.increment)
			if err != nil {
				t.Fatalf("IncrBy() error = %v", err)
			}

			currentVal += tt.increment
			if val != currentVal {
				t.Errorf("IncrBy() = %d, want %d", val, currentVal)
			}

			if val != tt.expected {
				t.Errorf("IncrBy() = %d, want %d", val, tt.expected)
			}
		})
	}
}

func TestClient_SetNX(t *testing.T) {
	client, mr := setupTestRedis(t)
	defer mr.Close()
	defer client.Close() //nolint:errcheck

	ctx := context.Background()

	key := "test:setnx"

	t.Run("Set when key doesn't exist", func(t *testing.T) {
		success, err := client.SetNX(ctx, key, testRedisVal1, 10*time.Second)
		if err != nil {
			t.Fatalf("SetNX() error = %v", err)
		}

		if !success {
			t.Error("SetNX() = false, want true (key didn't exist)")
		}

		val, err := client.Get(ctx, key)
		if err != nil {
			t.Fatalf("Get() error = %v", err)
		}

		if val != testRedisVal1 {
			t.Errorf("Get() = %q, want %q", val, testRedisVal1)
		}
	})

	t.Run("Set when key already exists", func(t *testing.T) {
		success, err := client.SetNX(ctx, key, "value2", 10*time.Second)
		if err != nil {
			t.Fatalf("SetNX() error = %v", err)
		}

		if success {
			t.Error("SetNX() = true, want false (key already exists)")
		}

		// Value should remain unchanged
		val, err := client.Get(ctx, key)
		if err != nil {
			t.Fatalf("Get() error = %v", err)
		}

		if val != testRedisVal1 {
			t.Errorf("Get() = %q, want %q (value should not change)", val, testRedisVal1)
		}
	})
}

func TestClient_Health(t *testing.T) {
	client, mr := setupTestRedis(t)
	defer mr.Close()
	defer client.Close() //nolint:errcheck

	ctx := context.Background()

	err := client.Health(ctx)
	if err != nil {
		t.Errorf("Health() error = %v, want nil", err)
	}
}

func TestClient_Redis(t *testing.T) {
	client, mr := setupTestRedis(t)
	defer mr.Close()
	defer client.Close() //nolint:errcheck

	rdb := client.Redis()
	if rdb == nil {
		t.Fatal("Redis() returned nil")
	}

	// Verify we can use the underlying client
	ctx := context.Background()
	err := rdb.Set(ctx, "test:direct", "value", 0).Err()
	if err != nil {
		t.Errorf("Direct Redis access failed: %v", err)
	}
}

func TestClient_Pipeline(t *testing.T) {
	client, mr := setupTestRedis(t)
	defer mr.Close()
	defer client.Close() //nolint:errcheck

	ctx := context.Background()

	pipe := client.Pipeline()
	if pipe == nil {
		t.Fatal("Pipeline() returned nil")
	}

	// Use pipeline to batch commands
	pipe.Set(ctx, "test:pipe1", testRedisVal1, 0)
	pipe.Set(ctx, "test:pipe2", "value2", 0)
	pipe.Set(ctx, "test:pipe3", "value3", 0)

	_, err := pipe.Exec(ctx)
	if err != nil {
		t.Fatalf("Pipeline Exec() error = %v", err)
	}

	// Verify values were set
	val, err := client.Get(ctx, "test:pipe1")
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if val != testRedisVal1 {
		t.Errorf("Get() = %q, want %q", val, testRedisVal1)
	}
}

func TestClient_TxPipeline(t *testing.T) {
	client, mr := setupTestRedis(t)
	defer mr.Close()
	defer client.Close() //nolint:errcheck

	ctx := context.Background()

	pipe := client.TxPipeline()
	if pipe == nil {
		t.Fatal("TxPipeline() returned nil")
	}

	// Use transaction pipeline
	pipe.Set(ctx, "test:tx1", testRedisVal1, 0)
	pipe.Set(ctx, "test:tx2", "value2", 0)

	_, err := pipe.Exec(ctx)
	if err != nil {
		t.Fatalf("TxPipeline Exec() error = %v", err)
	}

	// Verify values were set
	val, err := client.Get(ctx, "test:tx1")
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if val != testRedisVal1 {
		t.Errorf("Get() = %q, want %q", val, testRedisVal1)
	}
}

func TestClient_Close(t *testing.T) {
	client, mr := setupTestRedis(t)
	defer mr.Close()

	err := client.Close()
	if err != nil {
		t.Errorf("Close() error = %v", err)
	}
}
