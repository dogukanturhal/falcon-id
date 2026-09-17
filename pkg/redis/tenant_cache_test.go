// SPDX-License-Identifier: AGPL-3.0-or-later

package redis

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// newTestTenantCache creates a TenantCacheService backed by a fresh miniredis instance.
func newTestTenantCache(t *testing.T, keyPrefix string, ttl time.Duration) (*TenantCacheService, *miniredis.Miniredis) { //nolint:unparam // Miniredis is returned for potential future use in tests
	t.Helper()

	mr, err := miniredis.Run()
	require.NoError(t, err, "failed to start miniredis")

	cfg := &Config{
		URL:             "redis://" + mr.Addr(),
		MaxRetries:      1,
		MinIdleConns:    1,
		MaxIdleConns:    2,
		ConnMaxLifetime: time.Minute,
		DialTimeout:     2 * time.Second,
		ReadTimeout:     2 * time.Second,
		WriteTimeout:    2 * time.Second,
	}

	client, err := NewClient(cfg, zap.NewNop())
	require.NoError(t, err, "failed to create Redis client")

	svc := NewTenantCacheService(client, zap.NewNop(), keyPrefix, ttl)
	t.Cleanup(func() {
		_ = client.Close()
		mr.Close()
	})

	return svc, mr
}

// ─── NewTenantCacheService ────────────────────────────────────────────────────

func TestNewTenantCacheService_DefaultValues(t *testing.T) {
	mr, err := miniredis.Run()
	require.NoError(t, err)
	defer mr.Close()

	cfg := &Config{
		URL:         "redis://" + mr.Addr(),
		MaxRetries:  1,
		DialTimeout: 2 * time.Second,
	}
	client, err := NewClient(cfg, zap.NewNop())
	require.NoError(t, err)
	defer client.Close() //nolint:errcheck

	// Empty prefix and zero TTL should use defaults.
	svc := NewTenantCacheService(client, zap.NewNop(), "", 0)
	assert.Equal(t, "iam:tenant", svc.keyPrefix)
	assert.Equal(t, 5*time.Minute, svc.ttl)
}

func TestNewTenantCacheService_CustomValues(t *testing.T) {
	svc, _ := newTestTenantCache(t, "myprefix", 10*time.Minute)
	assert.Equal(t, "myprefix", svc.keyPrefix)
	assert.Equal(t, 10*time.Minute, svc.ttl)
}

// ─── Set / Get ────────────────────────────────────────────────────────────────

func TestTenantCache_Set_Get_RoundTrip(t *testing.T) {
	svc, _ := newTestTenantCache(t, "iam:tenant", 5*time.Minute)
	ctx := context.Background()

	err := svc.Set(ctx, "id:tenant-123", `{"id":"tenant-123","name":"Acme"}`, 0)
	require.NoError(t, err)

	got, err := svc.Get(ctx, "id:tenant-123")
	require.NoError(t, err)
	assert.Equal(t, `{"id":"tenant-123","name":"Acme"}`, got)
}

func TestTenantCache_Get_Miss(t *testing.T) {
	svc, _ := newTestTenantCache(t, "iam:tenant", 5*time.Minute)
	ctx := context.Background()

	got, err := svc.Get(ctx, "nonexistent")
	require.NoError(t, err, "cache miss should not error")
	assert.Empty(t, got, "cache miss should return empty string")
}

func TestTenantCache_Set_OverridesExistingValue(t *testing.T) {
	svc, _ := newTestTenantCache(t, "iam:tenant", 5*time.Minute)
	ctx := context.Background()

	require.NoError(t, svc.Set(ctx, "k", "v1", 0))
	require.NoError(t, svc.Set(ctx, "k", "v2", 0))

	got, err := svc.Get(ctx, "k")
	require.NoError(t, err)
	assert.Equal(t, "v2", got)
}

// ─── Del ──────────────────────────────────────────────────────────────────────

func TestTenantCache_Del_ExistingKey(t *testing.T) {
	svc, _ := newTestTenantCache(t, "iam:tenant", 5*time.Minute)
	ctx := context.Background()

	require.NoError(t, svc.Set(ctx, "todelete", "value", 0))
	require.NoError(t, svc.Del(ctx, "todelete"))

	got, err := svc.Get(ctx, "todelete")
	require.NoError(t, err)
	assert.Empty(t, got, "key should be gone after Del")
}

func TestTenantCache_Del_NonExistentKey(t *testing.T) {
	svc, _ := newTestTenantCache(t, "iam:tenant", 5*time.Minute)
	ctx := context.Background()

	// Deleting a missing key should not error.
	err := svc.Del(ctx, "missing")
	require.NoError(t, err)
}

// ─── InvalidateTenant ─────────────────────────────────────────────────────────

func TestTenantCache_InvalidateTenant_RemovesIdAndSlugKeys(t *testing.T) {
	svc, _ := newTestTenantCache(t, "iam:tenant", 5*time.Minute)
	ctx := context.Background()

	tenantID := "tenant-abc"

	// Populate both expected cache keys.
	idKey := "id:" + tenantID
	slugKey := "slug:" + tenantID

	require.NoError(t, svc.Set(ctx, idKey, `{"id":"tenant-abc"}`, 0))
	require.NoError(t, svc.Set(ctx, slugKey, `{"slug":"acme"}`, 0))

	require.NoError(t, svc.InvalidateTenant(ctx, tenantID))

	got, err := svc.Get(ctx, idKey)
	require.NoError(t, err)
	assert.Empty(t, got, "id key should be removed after InvalidateTenant")

	got, err = svc.Get(ctx, slugKey)
	require.NoError(t, err)
	assert.Empty(t, got, "slug key should be removed after InvalidateTenant")
}

func TestTenantCache_InvalidateTenant_NoKeysPresent(t *testing.T) {
	svc, _ := newTestTenantCache(t, "iam:tenant", 5*time.Minute)
	ctx := context.Background()

	// Should not error even when nothing is cached.
	err := svc.InvalidateTenant(ctx, "nonexistent-tenant")
	require.NoError(t, err)
}

// ─── TTL behaviour ────────────────────────────────────────────────────────────

func TestTenantCache_TTL_DefaultFromService(t *testing.T) {
	// When Set is called with ttl==0 it should use the service-level TTL.
	mr, err := miniredis.Run()
	require.NoError(t, err)
	defer mr.Close()

	cfg := &Config{
		URL:         "redis://" + mr.Addr(),
		MaxRetries:  1,
		DialTimeout: 2 * time.Second,
	}
	client, err := NewClient(cfg, zap.NewNop())
	require.NoError(t, err)
	defer client.Close() //nolint:errcheck

	serviceTTL := 2 * time.Second
	svc := NewTenantCacheService(client, zap.NewNop(), "iam:tenant", serviceTTL)
	ctx := context.Background()

	require.NoError(t, svc.Set(ctx, "k", "v", 0)) // zero TTL → use serviceTTL

	// Present immediately.
	got, err := svc.Get(ctx, "k")
	require.NoError(t, err)
	assert.Equal(t, "v", got)

	// Expire via miniredis fast-forward.
	mr.FastForward(serviceTTL + time.Second)

	got, err = svc.Get(ctx, "k")
	require.NoError(t, err)
	assert.Empty(t, got, "key should have expired")
}

func TestTenantCache_TTL_CustomPerSet(t *testing.T) {
	mr, err := miniredis.Run()
	require.NoError(t, err)
	defer mr.Close()

	cfg := &Config{
		URL:         "redis://" + mr.Addr(),
		MaxRetries:  1,
		DialTimeout: 2 * time.Second,
	}
	client, err := NewClient(cfg, zap.NewNop())
	require.NoError(t, err)
	defer client.Close() //nolint:errcheck

	svc := NewTenantCacheService(client, zap.NewNop(), "iam:tenant", 10*time.Minute)
	ctx := context.Background()

	// Provide a very short TTL on this specific Set call.
	shortTTL := 1 * time.Second
	require.NoError(t, svc.Set(ctx, "short", "value", shortTTL))

	got, err := svc.Get(ctx, "short")
	require.NoError(t, err)
	assert.Equal(t, "value", got)

	mr.FastForward(shortTTL + time.Second)

	got, err = svc.Get(ctx, "short")
	require.NoError(t, err)
	assert.Empty(t, got, "key should have expired with custom TTL")
}

// ─── Key prefix isolation ─────────────────────────────────────────────────────

func TestTenantCache_KeyPrefix_Isolation(t *testing.T) {
	// Two caches with different prefixes should not share data.
	mr, err := miniredis.Run()
	require.NoError(t, err)
	defer mr.Close()

	cfg := &Config{
		URL:         "redis://" + mr.Addr(),
		MaxRetries:  1,
		DialTimeout: 2 * time.Second,
	}
	client, err := NewClient(cfg, zap.NewNop())
	require.NoError(t, err)
	defer client.Close() //nolint:errcheck

	svc1 := NewTenantCacheService(client, zap.NewNop(), "ns1", time.Minute)
	svc2 := NewTenantCacheService(client, zap.NewNop(), "ns2", time.Minute)
	ctx := context.Background()

	require.NoError(t, svc1.Set(ctx, "k", "svc1-value", 0))

	// svc2 should not see svc1's data.
	got, err := svc2.Get(ctx, "k")
	require.NoError(t, err)
	assert.Empty(t, got)
}

// ─── Multiple key operations ──────────────────────────────────────────────────

func TestTenantCache_MultipleKeys(t *testing.T) {
	svc, _ := newTestTenantCache(t, "iam:tenant", 5*time.Minute)
	ctx := context.Background()

	entries := map[string]string{
		"id:t1":   `{"id":"t1"}`,
		"id:t2":   `{"id":"t2"}`,
		"slug:s1": `{"slug":"s1"}`,
	}

	for k, v := range entries {
		require.NoError(t, svc.Set(ctx, k, v, 0))
	}

	for k, want := range entries {
		got, err := svc.Get(ctx, k)
		require.NoError(t, err)
		assert.Equal(t, want, got, "key %s should match", k)
	}
}

func TestTenantCache_Del_DoesNotAffectOtherKeys(t *testing.T) {
	svc, _ := newTestTenantCache(t, "iam:tenant", 5*time.Minute)
	ctx := context.Background()

	require.NoError(t, svc.Set(ctx, "keep", "keep-me", 0))
	require.NoError(t, svc.Set(ctx, "remove", "remove-me", 0))

	require.NoError(t, svc.Del(ctx, "remove"))

	got, err := svc.Get(ctx, "keep")
	require.NoError(t, err)
	assert.Equal(t, "keep-me", got, "undeleted key should still be present")
}
