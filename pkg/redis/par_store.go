// SPDX-License-Identifier: AGPL-3.0-or-later

package redis

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	goredis "github.com/redis/go-redis/v9"
)

const (
	// PARDefaultTTL is the default lifetime of a pushed authorization request (RFC 9126 §2.1).
	// The spec recommends between 5 and 600 seconds; 60 seconds is a common default.
	PARDefaultTTL = 60 * time.Second
)

// PAREntry mirrors services.PAREntry for JSON serialisation in Redis.
// It is defined independently here to avoid an import cycle between pkg/redis and
// internal/services. The adapter in cmd/services.go maps between the two types.
type PAREntry struct {
	Reference           string `json:"reference"`
	ClientID            string `json:"client_id"`
	ResponseType        string `json:"response_type"`
	RedirectURI         string `json:"redirect_uri"`
	Scope               string `json:"scope"`
	State               string `json:"state,omitempty"`
	Nonce               string `json:"nonce,omitempty"`
	CodeChallenge       string `json:"code_challenge,omitempty"`
	CodeChallengeMethod string `json:"code_challenge_method,omitempty"`
	Display             string `json:"display,omitempty"`
	Prompt              string `json:"prompt,omitempty"`
	// AcrValues / MaxAge propagate the OIDC step-up + freshness params
	// through PAR; missing fields silently downgrade the security gate
	// at /oauth/authorize (the handler enforces both off the resolved
	// OAuthAuthorizeRequest). Pointer-typed MaxAge to distinguish "not
	// requested" (nil) from "always re-auth" (0).
	AcrValues string `json:"acr_values,omitempty"`
	MaxAge    *int   `json:"max_age,omitempty"`
	// LoginHint / LoginContext — see services.PAREntry for why these must
	// round-trip through PAR identically to a bare-query authorize call.
	LoginHint    string `json:"login_hint,omitempty"`
	LoginContext string `json:"login_context,omitempty"`
	ExpiresAt    int64  `json:"expires_at"` // Unix timestamp
}

// PARStore stores and retrieves pushed authorization requests in Redis.
// Keys follow the pattern: <prefix>:par:<reference>
// Each key is written with an absolute TTL equal to the PAR expiry window
// so Redis evicts stale entries automatically.
type PARStore struct {
	client *Client
	prefix string
	ttl    time.Duration
}

// NewPARStore creates a new PARStore.
func NewPARStore(client *Client, prefix string, ttl time.Duration) *PARStore {
	if ttl == 0 {
		ttl = PARDefaultTTL
	}
	return &PARStore{
		client: client,
		prefix: prefix,
		ttl:    ttl,
	}
}

func (s *PARStore) key(reference string) string {
	return fmt.Sprintf("%s:par:%s", s.prefix, reference)
}

// SetPAR stores a PAR entry in Redis. The TTL is derived from entry.ExpiresAt;
// if that yields a non-positive duration the configured default TTL is used.
func (s *PARStore) SetPAR(ctx context.Context, entry *PAREntry) error {
	data, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("PARStore.SetPAR: marshal: %w", err)
	}
	ttl := time.Until(time.Unix(entry.ExpiresAt, 0))
	if ttl <= 0 {
		ttl = s.ttl
	}
	if err := s.client.Redis().Set(ctx, s.key(entry.Reference), data, ttl).Err(); err != nil {
		return fmt.Errorf("PARStore.SetPAR: redis: %w", err)
	}
	return nil
}

// GetPAR retrieves a PAR entry by its reference token.
// Returns (nil, nil) when the key does not exist (already consumed or expired).
func (s *PARStore) GetPAR(ctx context.Context, reference string) (*PAREntry, error) {
	data, err := s.client.Redis().Get(ctx, s.key(reference)).Bytes()
	if err != nil {
		if errors.Is(err, goredis.Nil) {
			return nil, nil
		}
		return nil, fmt.Errorf("PARStore.GetPAR: redis: %w", err)
	}
	var entry PAREntry
	if err := json.Unmarshal(data, &entry); err != nil {
		return nil, fmt.Errorf("PARStore.GetPAR: unmarshal: %w", err)
	}
	return &entry, nil
}

// DeletePAR removes a PAR entry from Redis.
// Called after the authorization endpoint has consumed the request_uri.
func (s *PARStore) DeletePAR(ctx context.Context, reference string) error {
	if err := s.client.Redis().Del(ctx, s.key(reference)).Err(); err != nil && !errors.Is(err, goredis.Nil) {
		return fmt.Errorf("PARStore.DeletePAR: redis: %w", err)
	}
	return nil
}
