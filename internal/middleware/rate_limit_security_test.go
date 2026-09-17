// SPDX-License-Identifier: AGPL-3.0-or-later

package middleware

import (
	"container/list"
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"

	"github.com/dogukanturhal/falcon-id/internal/services"
)

// TestIPv6AddressParsing tests that IPv6 addresses are correctly parsed
func TestIPv6AddressParsing(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name           string
		remoteAddr     string
		trustedProxies []string
		xForwardedFor  string
		expectedIP     string
	}{
		{
			name:           "IPv4 with port",
			remoteAddr:     "192.168.1.1:8080",
			trustedProxies: []string{},
			expectedIP:     "192.168.1.1",
		},
		{
			name:           "IPv6 with port and brackets",
			remoteAddr:     "[::1]:8080",
			trustedProxies: []string{},
			expectedIP:     "::1",
		},
		{
			name:           "IPv6 full address with port",
			remoteAddr:     "[2001:db8::1]:8080",
			trustedProxies: []string{},
			expectedIP:     "2001:db8::1",
		},
		{
			name:           "IPv6 in X-Forwarded-For from trusted proxy",
			remoteAddr:     "10.0.30.20:8080",
			trustedProxies: []string{"10.0.30.20"},
			xForwardedFor:  "2001:db8::1, 10.0.30.20",
			expectedIP:     "2001:db8::1",
		},
		{
			name:           "IPv6 with port in X-Forwarded-For",
			remoteAddr:     "10.0.30.20:8080",
			trustedProxies: []string{"10.0.30.20"},
			xForwardedFor:  "[2001:db8::1]:8080, 10.0.30.20",
			expectedIP:     "2001:db8::1",
		},
		{
			name:           "Mixed IPv4 and IPv6 in X-Forwarded-For",
			remoteAddr:     "10.0.30.30:8080",
			trustedProxies: []string{"10.0.30.30", "10.0.30.20"},
			xForwardedFor:  "192.168.1.1, 2001:db8::1, 10.0.30.20, 10.0.30.30",
			expectedIP:     "2001:db8::1",
		},
		{
			name:           "Untrusted proxy with IPv6",
			remoteAddr:     "[2001:db8::bad]:8080",
			trustedProxies: []string{"10.0.30.20"},
			xForwardedFor:  "192.168.1.1",
			expectedIP:     "2001:db8::bad",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			middleware := NewRateLimitMiddleware(&services.RateLimitService{})
			middleware.SetTrustedProxies(tt.trustedProxies)

			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)

			// Create a mock request with the specified remote address
			req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/test", nil)
			req.RemoteAddr = tt.remoteAddr
			if tt.xForwardedFor != "" {
				req.Header.Set("X-Forwarded-For", tt.xForwardedFor)
			}
			c.Request = req

			// Test the IP extraction
			ip := middleware.getClientIP(c)
			assert.Equal(t, tt.expectedIP, ip, "IP should be correctly extracted")
		})
	}
}

// TestSetTrustedProxiesIPv6 tests that trusted proxies with IPv6 are correctly normalized
func TestSetTrustedProxiesIPv6(t *testing.T) {
	tests := []struct {
		name          string
		proxies       []string
		expectedCount int
		shouldContain []string
	}{
		{
			name:          "IPv4 proxies with ports",
			proxies:       []string{"10.0.30.20:8080", "10.0.30.30:9090"},
			expectedCount: 2,
			shouldContain: []string{"10.0.30.20", "10.0.30.30"},
		},
		{
			name:          "IPv6 proxies with ports",
			proxies:       []string{"[::1]:8080", "[2001:db8::1]:9090"},
			expectedCount: 2,
			shouldContain: []string{"::1", "2001:db8::1"},
		},
		{
			name:          "Mixed IPv4 and IPv6",
			proxies:       []string{"10.0.30.20:8080", "[::1]:9090"},
			expectedCount: 2,
			shouldContain: []string{"10.0.30.20", "::1"},
		},
		{
			name:          "IPs without ports",
			proxies:       []string{"10.0.30.20", "2001:db8::1"},
			expectedCount: 2,
			shouldContain: []string{"10.0.30.20", "2001:db8::1"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			middleware := NewRateLimitMiddleware(&services.RateLimitService{})
			middleware.SetTrustedProxies(tt.proxies)

			assert.Equal(t, tt.expectedCount, len(middleware.trustedProxies), "Should have correct number of trusted proxies")

			for _, expectedIP := range tt.shouldContain {
				assert.True(t, middleware.trustedProxies[expectedIP], "Should contain normalized IP: %s", expectedIP)
			}
		})
	}
}

// TestLRUEviction tests that the LRU store correctly evicts old entries
func TestLRUEviction(t *testing.T) {
	// Create a small store for testing
	store := &rateLimitStore{
		store:      make(map[string]*lruEntry),
		lruList:    list.New(),
		maxEntries: 3,
	}

	// Add 3 entries
	entry1 := &authRateLimitEntry{requests: []time.Time{time.Now()}}
	entry2 := &authRateLimitEntry{requests: []time.Time{time.Now()}}
	entry3 := &authRateLimitEntry{requests: []time.Time{time.Now()}}

	store.LoadOrStore("key1", entry1)
	store.LoadOrStore("key2", entry2)
	store.LoadOrStore("key3", entry3)

	assert.Equal(t, 3, store.GetEntryCount(), "Should have 3 entries")

	// Add 4th entry - should evict key1 (least recently used)
	entry4 := &authRateLimitEntry{requests: []time.Time{time.Now()}}
	store.LoadOrStore("key4", entry4)

	assert.Equal(t, 3, store.GetEntryCount(), "Should still have 3 entries after eviction")

	// Access key2 to make it recently used
	store.LoadOrStore("key2", entry2)

	// Add 5th entry - should evict key3 (now least recently used)
	entry5 := &authRateLimitEntry{requests: []time.Time{time.Now()}}
	store.LoadOrStore("key5", entry5)

	assert.Equal(t, 3, store.GetEntryCount(), "Should still have 3 entries after second eviction")

	// Verify key2 and key4 still exist
	_, exists := store.store["key2"]
	assert.True(t, exists, "key2 should still exist (was accessed recently)")

	_, exists = store.store["key4"]
	assert.True(t, exists, "key4 should still exist")

	// Verify key1 and key3 were evicted
	_, exists = store.store["key1"]
	assert.False(t, exists, "key1 should be evicted (oldest)")

	_, exists = store.store["key3"]
	assert.False(t, exists, "key3 should be evicted")
}

// TestRateLimitStoreMemoryBounds tests that the store respects maximum entry limits
func TestRateLimitStoreMemoryBounds(t *testing.T) {
	store := &rateLimitStore{
		store:      make(map[string]*lruEntry),
		lruList:    list.New(),
		maxEntries: 100,
	}

	// Add 150 entries
	for i := 0; i < 150; i++ {
		key := string(rune('a' + i))
		entry := &authRateLimitEntry{requests: []time.Time{time.Now()}}
		store.LoadOrStore(key, entry)
	}

	// Should never exceed maxEntries
	assert.LessOrEqual(t, store.GetEntryCount(), 100, "Entry count should not exceed maxEntries")
	assert.Equal(t, 100, store.GetEntryCount(), "Should have exactly maxEntries")
}

// TestAuthRateLimitWithIPv6 tests rate limiting with IPv6 client IPs
func TestAuthRateLimitWithIPv6(t *testing.T) {
	gin.SetMode(gin.TestMode)

	// Reset the global store for this test
	oldStore := authRateLimitStore
	authRateLimitStore = &rateLimitStore{
		store:      make(map[string]*lruEntry),
		lruList:    list.New(),
		maxEntries: 100000,
	}
	defer func() { authRateLimitStore = oldStore }()

	middleware := NewRateLimitMiddleware(&services.RateLimitService{})
	middleware.SetTrustedProxies([]string{})

	// Test IPv6 rate limiting
	// /api/auth/login has MaxRequests: 15
	loginLimit := authEndpointLimits["/api/auth/login"].MaxRequests
	for i := 0; i < loginLimit+1; i++ {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)

		req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/auth/login", nil)
		req.RemoteAddr = "[2001:db8::1]:8080"
		c.Request = req

		blocked, remaining, _ := middleware.checkAuthRateLimit(c)

		if i < loginLimit {
			assert.False(t, blocked, "Should not be blocked for request %d", i+1)
			assert.Equal(t, loginLimit-(i+1), remaining, "Should have correct remaining count")
		} else {
			assert.True(t, blocked, "Should be blocked on request %d", i+1)
			assert.Equal(t, 0, remaining, "Should have 0 remaining")
		}
	}
}

// TestCleanupDoesNotLeakMemory tests that cleanup properly removes old entries
func TestCleanupDoesNotLeakMemory(t *testing.T) {
	store := &rateLimitStore{
		store:      make(map[string]*lruEntry),
		lruList:    list.New(),
		maxEntries: 100000,
	}

	// Add entries with old timestamps
	oldTime := time.Now().Add(-1 * time.Hour)
	for i := 0; i < 100; i++ {
		key := string(rune('a' + i))
		entry := &authRateLimitEntry{
			requests:     []time.Time{oldTime},
			blockedUntil: oldTime,
		}
		store.LoadOrStore(key, entry)
	}

	assert.Equal(t, 100, store.GetEntryCount(), "Should have 100 entries before cleanup")

	// Simulate cleanup
	now := time.Now()
	cutoff := now.Add(-30 * time.Minute)
	toDelete := make([]string, 0)

	store.Range(func(key string, entry *authRateLimitEntry) bool {
		entry.mu.Lock()
		shouldDelete := false

		if len(entry.requests) == 0 && entry.blockedUntil.Before(now) {
			shouldDelete = true
		} else if len(entry.requests) > 0 {
			if entry.requests[len(entry.requests)-1].Before(cutoff) {
				shouldDelete = true
			}
		}

		entry.mu.Unlock()

		if shouldDelete {
			toDelete = append(toDelete, key)
		}
		return true
	})

	for _, key := range toDelete {
		store.Delete(key)
	}

	assert.Equal(t, 0, store.GetEntryCount(), "All old entries should be cleaned up")
}

// TestNetSplitHostPortEdgeCases tests edge cases in IP parsing
func TestNetSplitHostPortEdgeCases(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		expectedIP  string
		shouldError bool
	}{
		{
			name:       "IPv4 with port",
			input:      "192.168.1.1:8080",
			expectedIP: "192.168.1.1",
		},
		{
			name:       "IPv4 without port",
			input:      "192.168.1.1",
			expectedIP: "192.168.1.1",
		},
		{
			name:       "IPv6 with brackets and port",
			input:      "[::1]:8080",
			expectedIP: "::1",
		},
		{
			name:       "IPv6 without brackets (no port)",
			input:      "::1",
			expectedIP: "::1",
		},
		{
			name:       "IPv6 full address",
			input:      "[2001:db8:85a3::8a2e:370:7334]:443",
			expectedIP: "2001:db8:85a3::8a2e:370:7334",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var resultIP string
			if host, _, err := net.SplitHostPort(tt.input); err == nil {
				resultIP = host
			} else {
				resultIP = tt.input
			}

			assert.Equal(t, tt.expectedIP, resultIP, "IP should be correctly parsed")
		})
	}
}

// BenchmarkLRUStoreLoadOrStore benchmarks the LRU store performance
func BenchmarkLRUStoreLoadOrStore(b *testing.B) {
	store := &rateLimitStore{
		store:      make(map[string]*lruEntry),
		lruList:    list.New(),
		maxEntries: 100000,
	}

	entry := &authRateLimitEntry{
		requests: []time.Time{time.Now()},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		key := string(rune('a' + (i % 26)))
		store.LoadOrStore(key, entry)
	}
}

// BenchmarkIPv6Parsing benchmarks IPv6 address parsing
func BenchmarkIPv6Parsing(b *testing.B) {
	testAddr := "[2001:db8::1]:8080"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if host, _, err := net.SplitHostPort(testAddr); err == nil {
			_ = host
		}
	}
}
