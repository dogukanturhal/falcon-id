// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"slices"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// bclEventBackchannelLogout is the spec §2.4 "events" claim URN that
// every legitimate logout_token MUST carry.
const bclEventBackchannelLogout = "http://schemas.openid.net/event/backchannel-logout"

// bclReceiverHTTPTimeout caps the JWKS / discovery-doc fetch to avoid
// the receiver hot path stalling on a slow upstream IdP.
const bclReceiverHTTPTimeout = 10 * time.Second

// receiverJWKSCache holds RSA public keys fetched from upstream IdP
// JWKS endpoints, keyed by issuer. Each entry's keys map is keyed by
// JWT `kid` header so signature verification can pick the right key
// without re-fetching the JWKS document on every Receive() call.
//
// Concurrency: Get takes RLock for the cache hit fast path; cache
// misses upgrade to Lock for the populate. The fetch itself uses
// singleflight-style deduplication via the per-issuer fetch goroutine
// being held under the write lock — at most one in-flight fetch per
// issuer at a time.
type receiverJWKSCache struct {
	mu      sync.RWMutex
	entries map[string]*receiverJWKSEntry // keyed by issuer URL
	httpC   *http.Client
	ttl     time.Duration
}

type receiverJWKSEntry struct {
	keys      map[string]*rsa.PublicKey // keyed by kid
	expiresAt time.Time
}

func newReceiverJWKSCache(ttl time.Duration) *receiverJWKSCache {
	return &receiverJWKSCache{
		entries: make(map[string]*receiverJWKSEntry),
		httpC:   &http.Client{Timeout: bclReceiverHTTPTimeout},
		ttl:     ttl,
	}
}

// Get returns the *rsa.PublicKey for (issuer, kid). On cache miss or
// expired entry, it fetches the issuer's openid-configuration discovery
// document, dereferences the jwks_uri, parses every RSA key, caches
// the lot, and returns the requested kid. Returns an error if the kid
// is absent from the fetched JWKS — the caller should NOT retry, as
// the upstream IdP either rotated to a kid we don't know yet (will
// expire from cache) or the token is forged.
func (c *receiverJWKSCache) Get(ctx context.Context, issuer, kid string) (*rsa.PublicKey, error) {
	c.mu.RLock()
	entry, ok := c.entries[issuer]
	c.mu.RUnlock()
	if ok && time.Now().Before(entry.expiresAt) {
		if k, ok := entry.keys[kid]; ok {
			return k, nil
		}
		// Cache hit but unknown kid — could be a key rotation we
		// haven't observed yet. Force-refresh.
	}
	return c.fetchAndCache(ctx, issuer, kid)
}

func (c *receiverJWKSCache) fetchAndCache(ctx context.Context, issuer, kid string) (*rsa.PublicKey, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Double-check after acquiring write lock.
	if entry, ok := c.entries[issuer]; ok && time.Now().Before(entry.expiresAt) {
		if k, ok := entry.keys[kid]; ok {
			return k, nil
		}
	}

	jwksURI, err := c.discoverJWKSURI(ctx, issuer)
	if err != nil {
		return nil, fmt.Errorf("discover jwks_uri for %s: %w", issuer, err)
	}
	keys, err := c.fetchJWKS(ctx, jwksURI)
	if err != nil {
		return nil, fmt.Errorf("fetch JWKS for %s: %w", issuer, err)
	}
	c.entries[issuer] = &receiverJWKSEntry{
		keys:      keys,
		expiresAt: time.Now().Add(c.ttl),
	}

	k, ok := keys[kid]
	if !ok {
		return nil, fmt.Errorf("kid %q not in JWKS for issuer %s", kid, issuer)
	}
	return k, nil
}

// discoverJWKSURI fetches <issuer>/.well-known/openid-configuration
// and extracts the jwks_uri field. Required by RFC 8414 §5: every OP
// publishes its JWKS location through discovery, never hard-codes.
func (c *receiverJWKSCache) discoverJWKSURI(ctx context.Context, issuer string) (string, error) {
	url := issuer + "/.well-known/openid-configuration"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", fmt.Errorf("build request: %w", err)
	}
	resp, err := c.httpC.Do(req)
	if err != nil {
		return "", fmt.Errorf("http get: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck,gosec
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("status %d", resp.StatusCode)
	}
	var disc struct {
		JWKSURI string `json:"jwks_uri"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&disc); err != nil {
		return "", fmt.Errorf("decode discovery: %w", err)
	}
	if disc.JWKSURI == "" {
		return "", errors.New("discovery doc missing jwks_uri")
	}
	return disc.JWKSURI, nil
}

// fetchJWKS GETs the JWKS document and parses each RSA key. Non-RSA
// keys (EC, OKP, etc.) are silently skipped — F2 only supports RS256
// signature verification, matching what every BCL-emitting OP we'd
// federate with actually uses. Add EC support via a switch-on-`kty`
// when an OP requires it.
func (c *receiverJWKSCache) fetchJWKS(ctx context.Context, url string) (map[string]*rsa.PublicKey, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	resp, err := c.httpC.Do(req)
	if err != nil {
		return nil, fmt.Errorf("http get: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck,gosec
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}
	var doc struct {
		Keys []struct {
			Kty string `json:"kty"`
			Kid string `json:"kid"`
			Alg string `json:"alg"`
			Use string `json:"use"`
			N   string `json:"n"`
			E   string `json:"e"`
		} `json:"keys"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return nil, fmt.Errorf("decode JWKS: %w", err)
	}
	out := make(map[string]*rsa.PublicKey)
	for _, k := range doc.Keys {
		if k.Kty != "RSA" {
			continue
		}
		nBytes, err := base64.RawURLEncoding.DecodeString(k.N)
		if err != nil {
			continue
		}
		eBytes, err := base64.RawURLEncoding.DecodeString(k.E)
		if err != nil {
			continue
		}
		n := new(big.Int).SetBytes(nBytes)
		var e int
		for _, b := range eBytes {
			e = e<<8 | int(b)
		}
		out[k.Kid] = &rsa.PublicKey{N: n, E: e}
	}
	if len(out) == 0 {
		return nil, errors.New("JWKS has no usable RSA keys")
	}
	return out, nil
}

// receiveJWKSVerify executes the full §2.6 verification pipeline on a
// candidate logout_token. Returns the `sub` claim (or empty string +
// nil error if only `sid` was supplied — caller decides what to do).
//
// Validation order matches spec §2.6:
//
//  1. Parse JWT, signature verify against issuer's JWKS (kid lookup).
//  2. iss in TrustedIssuers allow-list.
//  3. aud equals configured Audience.
//  4. iat within ±MaxSkew of now.
//  5. exp not pathologically distant (≤ now + 5min) — defense in depth
//     against an attacker re-using a stolen-but-not-yet-used token
//     against the receiver after the OP-side outbox has TTL'd it.
//  6. events claim contains spec URN.
//  7. nonce claim ABSENT (spec §2.4 forbids it).
//  8. sub OR sid present.
//
// Any single failure → error. Caller maps to HTTP 400.
func (s *BackchannelLogoutService) receiveJWKSVerify(ctx context.Context, logoutToken string) (string, error) {
	if s.jwksCache == nil {
		s.jwksCache = newReceiverJWKSCache(s.receiverCfg.JWKSCacheTTL)
	}

	// Stage 1 + 2: parse with signature verify, picking the key by
	// (iss, kid). The KeyFunc closure has access to the parsed token
	// header but we read iss from the claims (set on the token by the
	// parser before KeyFunc fires).
	claims := jwt.MapClaims{}
	parser := jwt.NewParser(jwt.WithValidMethods([]string{"RS256"}))
	tok, err := parser.ParseWithClaims(logoutToken, claims, func(t *jwt.Token) (interface{}, error) {
		// At this point claims is populated. Read iss to dispatch JWKS.
		iss, _ := claims["iss"].(string)
		if iss == "" {
			return nil, errors.New("missing iss claim")
		}
		if !slices.Contains(s.receiverCfg.TrustedIssuers, iss) {
			return nil, fmt.Errorf("untrusted issuer: %s", iss)
		}
		kid, _ := t.Header["kid"].(string)
		if kid == "" {
			return nil, errors.New("missing kid header")
		}
		return s.jwksCache.Get(ctx, iss, kid)
	})
	if err != nil {
		return "", fmt.Errorf("jwt parse: %w", err)
	}
	if !tok.Valid {
		return "", errors.New("token signature invalid")
	}

	// Stage 3: aud check. Must include exactly the configured audience.
	if !claimsAudContains(claims, s.receiverCfg.Audience) {
		return "", fmt.Errorf("aud mismatch: expected %q", s.receiverCfg.Audience)
	}

	// Stage 4: iat skew. Tokens older than MaxSkew or from the future
	// (re: clock drift) are rejected.
	iatRaw, ok := claims["iat"].(float64)
	if !ok {
		return "", errors.New("missing or non-numeric iat")
	}
	iat := time.Unix(int64(iatRaw), 0)
	skew := s.receiverCfg.MaxSkew
	now := time.Now()
	if iat.Before(now.Add(-skew)) || iat.After(now.Add(skew)) {
		return "", fmt.Errorf("iat outside skew window (skew=%s)", skew)
	}

	// Stage 5: exp sanity (defense in depth — jwt.Parse already
	// enforces exp). 5min ceiling beyond now to flag obviously stale-
	// future tokens.
	if expRaw, ok := claims["exp"].(float64); ok {
		exp := time.Unix(int64(expRaw), 0)
		if exp.After(now.Add(5 * time.Minute)) {
			return "", errors.New("exp implausibly far in future")
		}
	}

	// Stage 6: events claim MUST carry the BCL URN.
	events, _ := claims["events"].(map[string]interface{})
	if _, hasEvent := events[bclEventBackchannelLogout]; !hasEvent {
		return "", errors.New("missing events.backchannel-logout")
	}

	// Stage 7: nonce ABSENT per spec §2.4.
	if _, hasNonce := claims["nonce"]; hasNonce {
		return "", errors.New("nonce claim is forbidden in logout_token")
	}

	// Stage 8: sub OR sid present.
	sub, _ := claims["sub"].(string)
	sid, _ := claims["sid"].(string)
	if sub == "" && sid == "" {
		return "", errors.New("logout_token must carry sub or sid")
	}

	// jti SETNX replay defense intentionally NOT implemented in F2.
	// Requires Redis client wiring; HexxLock's current topology has
	// Falcon-ID as the OP not an RP so this path is dormant. Add the
	// SETNX in a follow-up MR alongside the integration that needs
	// the receive path.

	return sub, nil
}

// claimsAudContains returns true if the JWT `aud` claim — which can
// be either a string or []string per spec — contains the supplied
// audience value.
func claimsAudContains(claims jwt.MapClaims, want string) bool {
	switch v := claims["aud"].(type) {
	case string:
		return v == want
	case []interface{}:
		for _, item := range v {
			if s, ok := item.(string); ok && s == want {
				return true
			}
		}
	}
	return false
}
