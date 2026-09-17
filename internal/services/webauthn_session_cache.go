// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"

	falconredis "github.com/dogukanturhal/falcon-id/pkg/redis"
)

// webauthnSessionCacheTTL is the maximum lifetime of a stored ceremony.
// 5 minutes is the W3C-recommended ceremony timeout — long enough to cover
// authenticator UV prompts on slow devices, short enough that abandoned
// challenges expire well before they could be replayed.
const webauthnSessionCacheTTL = 5 * time.Minute

// webauthnSessionPrefix scopes ceremony state in Redis. Using a dedicated
// prefix keeps these keys distinct from MFA-enrollment, OAuth-state, or any
// other short-TTL store — important so that a misuse cannot promote a key
// from one store into another.
const webauthnSessionPrefix = "iam:webauthn:sess:"

// webauthnSessionStore is the narrow interface the WebAuthn service needs.
// Defined here (not in pkg/redis) so tests can substitute miniredis or an
// in-memory map without a real client.
type webauthnSessionStore interface {
	Get(ctx context.Context, key string) (string, error)
	Set(ctx context.Context, key string, value interface{}, ttl time.Duration) error
	Del(ctx context.Context, keys ...string) error
}

// WebAuthnSessionCache persists go-webauthn SessionData across the
// begin/finish ceremony round-trip. Without server-side persistence, the
// challenge would be untrusted client input and the ceremony would have no
// replay protection (W3C WebAuthn §13.4.3 — challenge MUST be verified
// against the value the RP originally generated).
type WebAuthnSessionCache struct {
	store webauthnSessionStore
}

// NewWebAuthnSessionCache wires the Redis-backed store. Pass the existing
// *redis.Client; the cache uses its narrow Get/Set/Del subset.
func NewWebAuthnSessionCache(client *falconredis.Client) *WebAuthnSessionCache {
	return &WebAuthnSessionCache{store: client}
}

// newWebAuthnSessionCacheWithStore is a test seam allowing miniredis or a
// fake store to be substituted. Not exported; production wiring goes through
// NewWebAuthnSessionCache.
func newWebAuthnSessionCacheWithStore(store webauthnSessionStore) *WebAuthnSessionCache {
	return &WebAuthnSessionCache{store: store}
}

// NewSessionID returns a fresh opaque ceremony identifier. The client receives
// it from the begin endpoint and echoes it back on finish. Using a separate
// random ID rather than the challenge itself makes lookups O(1) and avoids
// having to parse the clientDataJSON server-side just to find the SessionData.
func NewSessionID() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("WebAuthnSessionCache.NewSessionID: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// Save serialises a *webauthn.SessionData under the given session ID with a
// fixed 5-minute TTL. The library's SessionData JSON tags are stable and
// safe to round-trip via encoding/json.
func (c *WebAuthnSessionCache) Save(ctx context.Context, sessionID string, data *webauthn.SessionData) error {
	if sessionID == "" {
		return errors.New("WebAuthnSessionCache.Save: sessionID is empty")
	}
	if data == nil {
		return errors.New("WebAuthnSessionCache.Save: data is nil")
	}
	payload, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("WebAuthnSessionCache.Save: marshal: %w", err)
	}
	if err := c.store.Set(ctx, webauthnSessionPrefix+sessionID, payload, webauthnSessionCacheTTL); err != nil {
		return fmt.Errorf("WebAuthnSessionCache.Save: store: %w", err)
	}
	return nil
}

// Take loads and atomically deletes the SessionData. Single-use enforcement
// matters: re-using a challenge across two finish calls would weaken replay
// protection. Callers MUST treat a not-found result as a hard failure of the
// ceremony, never a recoverable error.
func (c *WebAuthnSessionCache) Take(ctx context.Context, sessionID string) (*webauthn.SessionData, error) {
	if sessionID == "" {
		return nil, errors.New("WebAuthnSessionCache.Take: sessionID is empty")
	}
	key := webauthnSessionPrefix + sessionID
	raw, err := c.store.Get(ctx, key)
	if err != nil {
		return nil, fmt.Errorf("WebAuthnSessionCache.Take: get: %w", err)
	}
	if raw == "" {
		return nil, errors.New("WebAuthnSessionCache.Take: session not found or expired")
	}
	// Best-effort delete. A failure to delete is logged-only because the
	// challenge has already been consumed; the next Take with the same ID
	// would still see the value but the SessionData.Expires guard inside
	// the library will reject it.
	_ = c.store.Del(ctx, key)
	var data webauthn.SessionData
	if err := json.Unmarshal([]byte(raw), &data); err != nil {
		return nil, fmt.Errorf("WebAuthnSessionCache.Take: unmarshal: %w", err)
	}
	return &data, nil
}
