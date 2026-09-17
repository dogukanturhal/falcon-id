// SPDX-License-Identifier: AGPL-3.0-or-later

package security

import (
	"context"
	"fmt"
	"time"

	goredis "github.com/redis/go-redis/v9"
)

// RedisReplayStore implements AssertionReplayStore using Redis SET NX.
// Each assertion ID is stored with a TTL matching the assertion's validity
// window. Duplicate attempts (replays) are rejected.
//
// By default the store is fail-closed: if the Redis client is nil,
// MarkAssertionConsumed returns false with an error. Set FailOpen to true
// only when availability must take precedence over replay protection.
type RedisReplayStore struct {
	client   *goredis.Client
	prefix   string
	FailOpen bool
}

// NewRedisReplayStore creates a new RedisReplayStore.
// When failOpen is false (the default recommendation), a nil Redis client
// causes MarkAssertionConsumed to reject every assertion rather than
// silently accepting replays.
func NewRedisReplayStore(client *goredis.Client, failOpen bool) *RedisReplayStore {
	return &RedisReplayStore{
		client:   client,
		prefix:   "saml:assertion:replay:",
		FailOpen: failOpen,
	}
}

// MarkAssertionConsumed attempts to mark an assertion ID as consumed.
// Returns true if this is the first time the ID was seen (accepted),
// false if it was already consumed (replay attack).
func (s *RedisReplayStore) MarkAssertionConsumed(ctx context.Context, assertionID string, ttl time.Duration) (bool, error) {
	if s.client == nil {
		if s.FailOpen {
			return true, fmt.Errorf("replay store: Redis client unavailable (fail-open; replay protection degraded)")
		}
		return false, fmt.Errorf("replay store: Redis client unavailable")
	}

	key := s.prefix + assertionID
	err := s.client.SetArgs(ctx, key, "1", goredis.SetArgs{Mode: "NX", TTL: ttl}).Err()
	if err == goredis.Nil {
		return false, nil // key already existed → replay
	}
	if err != nil {
		return false, fmt.Errorf("redis SETNX for assertion replay check: %w", err)
	}
	return true, nil // first time (accepted)
}
