// SPDX-License-Identifier: AGPL-3.0-or-later

package security

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	goredis "github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newTestRedisStore starts a miniredis server and returns a RedisReplayStore
// backed by it.  The caller must call cleanup() when done.
func newTestRedisStore(t *testing.T, failOpen bool) (*RedisReplayStore, func()) {
	t.Helper()
	mr, err := miniredis.Run()
	require.NoError(t, err, "start miniredis")

	client := goredis.NewClient(&goredis.Options{Addr: mr.Addr()})
	store := NewRedisReplayStore(client, failOpen)

	return store, func() {
		_ = client.Close()
		mr.Close()
	}
}

func TestRedisReplayStore_FirstConsumption_ReturnsTrue(t *testing.T) {
	store, cleanup := newTestRedisStore(t, false)
	defer cleanup()

	ok, err := store.MarkAssertionConsumed(context.Background(), "assertion-id-1", 5*time.Minute)
	require.NoError(t, err)
	assert.True(t, ok, "first consumption must return true")
}

func TestRedisReplayStore_SecondConsumption_ReturnsFalse(t *testing.T) {
	store, cleanup := newTestRedisStore(t, false)
	defer cleanup()

	id := "assertion-id-2"
	ok1, err1 := store.MarkAssertionConsumed(context.Background(), id, 5*time.Minute)
	require.NoError(t, err1)
	require.True(t, ok1, "first consumption must succeed")

	ok2, err2 := store.MarkAssertionConsumed(context.Background(), id, 5*time.Minute)
	require.NoError(t, err2)
	assert.False(t, ok2, "second consumption must return false (replay detected)")
}

func TestRedisReplayStore_DifferentIDs_Independent(t *testing.T) {
	store, cleanup := newTestRedisStore(t, false)
	defer cleanup()

	ok1, err := store.MarkAssertionConsumed(context.Background(), "id-A", 5*time.Minute)
	require.NoError(t, err)
	assert.True(t, ok1)

	ok2, err := store.MarkAssertionConsumed(context.Background(), "id-B", 5*time.Minute)
	require.NoError(t, err)
	assert.True(t, ok2, "a distinct ID must be treated as a fresh consumption")
}

func TestRedisReplayStore_NilClient_FailClosed(t *testing.T) {
	// FailOpen = false (the default): nil client must reject the assertion.
	store := NewRedisReplayStore(nil, false)

	ok, err := store.MarkAssertionConsumed(context.Background(), "some-id", 5*time.Minute)
	require.Error(t, err, "nil client must return an error in fail-closed mode")
	assert.False(t, ok, "nil client must return false in fail-closed mode")
}

func TestRedisReplayStore_NilClient_FailOpen(t *testing.T) {
	// FailOpen = true: nil client still returns an error (degraded warning) but
	// allows the assertion through (returns true).
	store := NewRedisReplayStore(nil, true)

	ok, err := store.MarkAssertionConsumed(context.Background(), "some-id", 5*time.Minute)
	require.Error(t, err, "nil client must still return an error in fail-open mode")
	assert.True(t, ok, "nil client must return true in fail-open mode")
}

func TestRedisReplayStore_KeyPrefix(t *testing.T) {
	// Confirm that keys stored in Redis carry the expected prefix so they can
	// be identified and expired correctly without colliding with other keys.
	mr, err := miniredis.Run()
	require.NoError(t, err)
	defer mr.Close()

	client := goredis.NewClient(&goredis.Options{Addr: mr.Addr()})
	defer client.Close() //nolint:errcheck

	store := NewRedisReplayStore(client, false)
	_, err = store.MarkAssertionConsumed(context.Background(), "test-assertion", 5*time.Minute)
	require.NoError(t, err)

	// Verify the key exists in miniredis with the expected prefix.
	assert.True(t, mr.Exists("saml:assertion:replay:test-assertion"),
		"Redis key must include the 'saml:assertion:replay:' prefix")
}

func TestRedisReplayStore_TTL_IsSet(t *testing.T) {
	mr, err := miniredis.Run()
	require.NoError(t, err)
	defer mr.Close()

	client := goredis.NewClient(&goredis.Options{Addr: mr.Addr()})
	defer client.Close() //nolint:errcheck

	store := NewRedisReplayStore(client, false)
	ttl := 30 * time.Minute
	_, err = store.MarkAssertionConsumed(context.Background(), "ttl-test", ttl)
	require.NoError(t, err)

	// miniredis tracks TTLs.
	remaining := mr.TTL("saml:assertion:replay:ttl-test")
	assert.Greater(t, remaining, time.Duration(0), "key must have a positive TTL set")
	// Should be approximately 30 minutes (allow small delta).
	assert.LessOrEqual(t, remaining, ttl)
}
