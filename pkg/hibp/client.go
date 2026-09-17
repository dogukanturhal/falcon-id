// SPDX-License-Identifier: AGPL-3.0-or-later

// Package hibp provides a k-anonymity client for the Have I Been Pwned
// Pwned Passwords API (https://haveibeenpwned.com/API/v3#PwnedPasswords).
//
// The k-anonymity model ensures that no complete password hash is ever
// sent over the wire. Only the first 5 hex characters of the SHA-1 hash
// are transmitted, and the API returns all matching hash suffixes along
// with breach counts. The caller then performs the final match locally.
package hibp

import (
	"context"
	"crypto/sha1" //nolint:gosec // SHA1 is required by HIBP k-anonymity protocol
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	resilient "github.com/dogukanturhal/hexx-pep-core/pkg/resilient"
)

// Client is a thread-safe HIBP Pwned Passwords client with an in-memory
// response cache. Cache entries are keyed by the 5-character SHA-1 prefix
// and expire after cacheTTL (default 24 hours), matching the recommended
// HIBP CDN cache lifetime.
type Client struct {
	httpClient *http.Client
	baseURL    string // configurable for testing; default https://api.pwnedpasswords.com/range/
	cache      map[string]cacheEntry
	cacheMu    sync.RWMutex
	cacheTTL   time.Duration

	// DDIL P3.11 resilience around the outbound range fetch. resilienceOn=false
	// ⇒ direct passthrough (pre-DDIL behaviour). The GET is idempotent, so the
	// full envelope (shared breaker + backoff-with-jitter + retry) is safe; when
	// the breaker opens the fetch fails fast and the caller's breach-guard policy
	// decides fail-open/closed as before.
	resilienceOn bool
	fetchCfg     resilient.Config
}

// Option configures a Client.
type Option func(*Client)

// WithResilience wraps the outbound HIBP range fetch in a shared circuit
// breaker (breaker), exponential backoff with jitter, and up to maxAttempts
// attempts. The per-request HTTP timeout on the client still bounds each
// attempt. Pass a breaker shared across the process so shedding is coordinated.
func WithResilience(breaker *resilient.Breaker, maxAttempts int) Option {
	return func(c *Client) {
		c.resilienceOn = true
		c.fetchCfg = resilient.Config{
			MaxAttempts: maxAttempts,
			Breaker:     breaker,
		}
	}
}

// WithHTTPClient overrides the HTTP client (e.g. custom timeout or transport).
func WithHTTPClient(hc *http.Client) Option {
	return func(c *Client) {
		if hc != nil {
			c.httpClient = hc
		}
	}
}

type cacheEntry struct {
	suffixes  string
	expiresAt time.Time
}

// defaultBaseURL is the production HIBP k-anonymity range endpoint.
const defaultBaseURL = "https://api.pwnedpasswords.com/range/"

// NewClient constructs a Client with production defaults:
//   - 5-second HTTP timeout
//   - 24-hour cache TTL
//
// Pass options (e.g. WithResilience) to opt into the DDIL resilience envelope.
func NewClient(opts ...Option) *Client {
	c := &Client{
		httpClient: &http.Client{Timeout: 5 * time.Second},
		baseURL:    defaultBaseURL,
		cache:      make(map[string]cacheEntry),
		cacheTTL:   24 * time.Hour,
	}
	for _, o := range opts {
		o(c)
	}
	return c
}

// IsCompromised reports whether password has appeared in a known data breach.
//
// It implements the HIBP k-anonymity protocol:
//  1. Compute SHA-1(password) and upper-case it.
//  2. Send only the first 5 hex characters to the API.
//  3. Search the returned suffix list locally for a match.
//
// Returns (true, count, nil) when a match is found, where count is the number
// of times the password appeared across all indexed breaches. Returns
// (false, 0, nil) when the password is not found. A non-nil error indicates
// a network or API failure; callers should decide whether to fail open or
// closed based on their security requirements.
func (c *Client) IsCompromised(ctx context.Context, password string) (bool, int, error) {
	// SHA-1 is intentionally used here: it is mandated by the HIBP API
	// specification and is not used for any security-sensitive purpose.
	hash := fmt.Sprintf("%X", sha1.Sum([]byte(password))) //nolint:gosec // SHA1 is required by HIBP k-anonymity protocol
	prefix := hash[:5]
	suffix := hash[5:]

	suffixes, err := c.getRangeSuffixes(ctx, prefix)
	if err != nil {
		return false, 0, err
	}

	for _, line := range strings.Split(suffixes, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		if strings.EqualFold(parts[0], suffix) {
			count := 0
			_, _ = fmt.Sscanf(parts[1], "%d", &count)
			// count==0 rows are HIBP padding (Add-Padding mode) and MUST be
			// treated as "not found" — they are decoy suffixes the API mixes
			// in to hide the real response size, never a genuine breach hit.
			if count == 0 {
				return false, 0, nil
			}
			return true, count, nil
		}
	}

	return false, 0, nil
}

// getRangeSuffixes fetches (or returns a cached copy of) the HIBP suffix list
// for the given 5-character prefix. The response body is a CRLF-delimited
// text file of "SUFFIX:COUNT" pairs.
func (c *Client) getRangeSuffixes(ctx context.Context, prefix string) (string, error) {
	// Fast path: serve from cache under a read lock.
	c.cacheMu.RLock()
	entry, hit := c.cache[prefix]
	c.cacheMu.RUnlock()

	if hit && time.Now().Before(entry.expiresAt) {
		return entry.suffixes, nil
	}

	// Slow path: fetch from the API, under the DDIL resilience envelope when
	// enabled (shared breaker + backoff-with-jitter + retry). The GET is
	// idempotent so retries are safe; a shed (ErrBreakerOpen) surfaces as an
	// error the caller's breach-guard policy already handles.
	var suffixes string
	fetch := func(ctx context.Context) error {
		s, ferr := c.doRangeFetch(ctx, prefix)
		if ferr != nil {
			return ferr
		}
		suffixes = s
		return nil
	}
	var err error
	if c.resilienceOn {
		err = resilient.Do(ctx, c.fetchCfg, fetch)
	} else {
		err = fetch(ctx)
	}
	if err != nil {
		return "", err
	}

	// Write the result into the cache.
	c.cacheMu.Lock()
	c.cache[prefix] = cacheEntry{
		suffixes:  suffixes,
		expiresAt: time.Now().Add(c.cacheTTL),
	}
	c.cacheMu.Unlock()

	return suffixes, nil
}

// doRangeFetch performs a single HIBP range request for the given prefix and
// returns the raw suffix body. It is the unit wrapped by the resilience
// envelope in getRangeSuffixes.
func (c *Client) doRangeFetch(ctx context.Context, prefix string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+prefix, nil)
	if err != nil {
		return "", fmt.Errorf("hibp: failed to build request: %w", err)
	}
	// Add-Padding mode: HIBP mixes decoy (count 0) suffixes into every range
	// response so all responses are ~similar size, defeating traffic-analysis
	// correlation of which prefix was queried. Decoys are filtered in
	// IsCompromised by their zero count.
	req.Header.Set("Add-Padding", "true")
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("hibp: API request failed: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("hibp: API returned unexpected status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("hibp: failed to read response body: %w", err)
	}
	return string(body), nil
}
