// SPDX-License-Identifier: AGPL-3.0-or-later

package hibp

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newTestClient returns a Client wired to the provided test server URL.
// cacheTTL is set to 1 hour so cache-hit tests are reliable.
func newTestClient(serverURL string) *Client {
	return &Client{
		httpClient: &http.Client{Timeout: 5 * time.Second},
		baseURL:    serverURL + "/range/",
		cache:      make(map[string]cacheEntry),
		cacheTTL:   time.Hour,
	}
}

// hibpHandler returns an http.HandlerFunc that simulates the HIBP range
// endpoint. The handler accepts the 5-char prefix as the last path segment
// and returns a synthetic suffix list in the HIBP wire format.
//
// Hardcoded test data (SHA-1 of "password" = 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8):
//
//	prefix = "5BAA6", suffix = "1E4C9B93F3F0682250B6CF8331B7EE68FD8"
//
// This lets us assert the compromised path without a real network call.
func hibpHandler(requestCount *atomic.Int64) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if requestCount != nil {
			requestCount.Add(1)
		}

		// Extract the 5-char prefix from the URL path (last segment).
		parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/range/"), "/")
		prefix := strings.ToUpper(parts[0])

		// Build a response that always contains the suffix for "password"
		// when the correct prefix is requested.
		var lines []string
		if prefix == "5BAA6" {
			// "password" hash suffix + a few synthetic neighbours.
			lines = []string{
				"1E4C9B93F3F0682250B6CF8331B7EE68FD8:9659365",
				"1E4C9B93F3F0682250B6CF8331B7EE68FD9:1",
				"0000000000000000000000000000000AAAAA:5",
			}
		} else {
			// Return only synthetic neighbours — the queried password is NOT found.
			lines = []string{
				"AABBCCDD0011223344556677889900AABBCC:3",
				"FFEEDDCC0011223344556677889900FFEEDD:1",
			}
		}

		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintln(w, strings.Join(lines, "\r\n"))
	}
}

// TestHIBP_IsCompromised_Found verifies that a password whose SHA-1 hash
// appears in the mocked range response is reported as compromised with the
// correct breach count.
func TestHIBP_IsCompromised_Found(t *testing.T) {
	srv := httptest.NewServer(hibpHandler(nil))
	defer srv.Close()

	client := newTestClient(srv.URL)

	// "password" → SHA-1 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8
	found, count, err := client.IsCompromised(context.Background(), "password")

	require.NoError(t, err)
	assert.True(t, found, "expected 'password' to be reported as compromised")
	assert.Equal(t, 9659365, count, "expected breach count to match mock response")
}

// TestHIBP_IsCompromised_NotFound verifies that a password whose SHA-1 hash
// prefix does not match any entry in the range response is reported as clean.
func TestHIBP_IsCompromised_NotFound(t *testing.T) {
	srv := httptest.NewServer(hibpHandler(nil))
	defer srv.Close()

	client := newTestClient(srv.URL)

	// This password hashes to a prefix other than "5BAA6", so the mock
	// server returns a list that will not contain its suffix.
	found, count, err := client.IsCompromised(context.Background(), "this-is-a-very-unique-test-password-xyz-9182736450")

	require.NoError(t, err)
	assert.False(t, found, "expected an uncommon password to NOT be reported as compromised")
	assert.Equal(t, 0, count, "expected count to be 0 for a clean password")
}

// TestHIBP_CacheHit verifies that a second call with the same password uses
// the in-memory cache and does not issue an additional HTTP request.
func TestHIBP_CacheHit(t *testing.T) {
	var requestCount atomic.Int64

	srv := httptest.NewServer(hibpHandler(&requestCount))
	defer srv.Close()

	client := newTestClient(srv.URL)

	// First call: expect one HTTP request.
	found1, count1, err := client.IsCompromised(context.Background(), "password")
	require.NoError(t, err)
	assert.True(t, found1)
	assert.Equal(t, int64(1), requestCount.Load(), "expected exactly one HTTP request on first call")

	// Second call with the same password: the prefix is already cached.
	found2, count2, err := client.IsCompromised(context.Background(), "password")
	require.NoError(t, err)
	assert.True(t, found2)
	assert.Equal(t, count1, count2, "cached and live results should match")
	assert.Equal(t, int64(1), requestCount.Load(), "expected no additional HTTP requests due to cache hit")
}

// TestHIBP_CacheExpiry verifies that an expired cache entry triggers a fresh
// HTTP request rather than returning stale data.
func TestHIBP_CacheExpiry(t *testing.T) {
	var requestCount atomic.Int64

	srv := httptest.NewServer(hibpHandler(&requestCount))
	defer srv.Close()

	// Use a TTL that has already elapsed so every call hits the server.
	client := &Client{
		httpClient: &http.Client{Timeout: 5 * time.Second},
		baseURL:    srv.URL + "/range/",
		cache:      make(map[string]cacheEntry),
		cacheTTL:   -1 * time.Second, // negative TTL: entries expire immediately
	}

	_, _, err := client.IsCompromised(context.Background(), "password")
	require.NoError(t, err)

	_, _, err = client.IsCompromised(context.Background(), "password")
	require.NoError(t, err)

	assert.Equal(t, int64(2), requestCount.Load(), "expected two HTTP requests when cache is expired")
}

// TestHIBP_APIError verifies that a non-200 HTTP response from the HIBP API
// is propagated as a descriptive error.
func TestHIBP_APIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "service unavailable", http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	client := newTestClient(srv.URL)

	found, count, err := client.IsCompromised(context.Background(), "password")

	require.Error(t, err, "expected an error when the API returns a non-200 status")
	assert.Contains(t, err.Error(), "503", "error should include the HTTP status code")
	assert.False(t, found)
	assert.Equal(t, 0, count)
}

// TestHIBP_NetworkError verifies that a connection failure (server unreachable)
// is surfaced as an error rather than silently returning a clean result.
func TestHIBP_NetworkError(t *testing.T) {
	// Use a URL that is guaranteed to be unreachable.
	client := newTestClient("http://127.0.0.1:0")

	found, count, err := client.IsCompromised(context.Background(), "password")

	require.Error(t, err, "expected an error when the server is unreachable")
	assert.False(t, found)
	assert.Equal(t, 0, count)
}

// TestHIBP_IsCompromised_CaseInsensitiveSuffixMatch verifies that the suffix
// comparison is case-insensitive, since the HIBP API returns upper-case
// suffixes but our SHA-1 is also upper-cased.
func TestHIBP_IsCompromised_CaseInsensitiveSuffixMatch(t *testing.T) {
	// Serve a response whose suffix is lower-cased to test EqualFold.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// Lower-case version of the "password" suffix.
		_, _ = fmt.Fprintln(w, "1e4c9b93f3f0682250b6cf8331b7ee68fd8:9659365")
	}))
	defer srv.Close()

	client := newTestClient(srv.URL)

	found, count, err := client.IsCompromised(context.Background(), "password")

	require.NoError(t, err)
	assert.True(t, found, "suffix comparison must be case-insensitive")
	assert.Equal(t, 9659365, count)
}

// TestHIBP_ConcurrentAccess verifies that concurrent calls from multiple
// goroutines do not trigger data races on the cache map. Run with -race.
func TestHIBP_ConcurrentAccess(_ *testing.T) {
	srv := httptest.NewServer(hibpHandler(nil))
	defer srv.Close()

	client := newTestClient(srv.URL)

	const goroutines = 20
	done := make(chan struct{}, goroutines)

	for i := 0; i < goroutines; i++ {
		go func() {
			defer func() { done <- struct{}{} }()
			_, _, _ = client.IsCompromised(context.Background(), "password")
		}()
	}

	for i := 0; i < goroutines; i++ {
		<-done
	}
}
