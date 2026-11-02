// SPDX-License-Identifier: AGPL-3.0-or-later

package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testRemoteAddr1  = "10.0.0.1:12345"
	testRemoteAddr50 = "10.0.0.50:12345"
)

func init() {
	gin.SetMode(gin.TestMode)
}

// TestDefaultAuthRateLimiterConfig verifies the default configuration values.
func TestDefaultAuthRateLimiterConfig(t *testing.T) {
	cfg := DefaultAuthRateLimiterConfig()

	assert.Equal(t, 5, cfg.PerIP.MaxRequests)
	assert.Equal(t, 1*time.Minute, cfg.PerIP.Window)
	assert.Equal(t, 5*time.Minute, cfg.PerIP.BlockDuration)

	assert.Equal(t, 10, cfg.PerAccount.MaxRequests)
	assert.Equal(t, 1*time.Hour, cfg.PerAccount.Window)
	assert.Equal(t, 30*time.Minute, cfg.PerAccount.BlockDuration)

	assert.Equal(t, 1000, cfg.Global.MaxRequests)
	assert.Equal(t, 1*time.Minute, cfg.Global.Window)
	assert.Equal(t, 1*time.Minute, cfg.Global.BlockDuration)
}

// TestPerIPRateLimiting verifies that per-IP rate limiting blocks after threshold.
func TestPerIPRateLimiting(t *testing.T) {
	cfg := AuthRateLimiterConfig{
		PerIP: TierConfig{
			MaxRequests:   3,
			Window:        1 * time.Minute,
			BlockDuration: 5 * time.Minute,
		},
		PerAccount: TierConfig{
			MaxRequests:   100,
			Window:        1 * time.Hour,
			BlockDuration: 30 * time.Minute,
		},
		Global: TierConfig{
			MaxRequests:   10000,
			Window:        1 * time.Minute,
			BlockDuration: 1 * time.Minute,
		},
	}

	limiter := NewAuthRateLimiter(cfg, nil)

	for i := 0; i < 3; i++ {
		w := httptest.NewRecorder()
		c, router := gin.CreateTestContext(w)

		router.POST("/api/auth/login", limiter.Middleware(), func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"status": "ok"})
		})

		req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/auth/login", nil)
		req.RemoteAddr = "192.168.1.100:12345"
		c.Request = req
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code, "Request %d should be allowed", i+1)
	}

	// 4th request should be blocked
	w := httptest.NewRecorder()
	_, router := gin.CreateTestContext(w)

	router.POST("/api/auth/login", limiter.Middleware(), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/auth/login", nil)
	req.RemoteAddr = "192.168.1.100:12345"
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusTooManyRequests, w.Code, "4th request should be rate limited")
	assert.NotEmpty(t, w.Header().Get("Retry-After"), "Should have Retry-After header")
	assert.Equal(t, "per_ip", w.Header().Get("X-RateLimit-Tier"), "Should indicate per_ip tier")
}

// TestDifferentIPsAreIndependent verifies that rate limits are tracked per-IP.
func TestDifferentIPsAreIndependent(t *testing.T) {
	cfg := AuthRateLimiterConfig{
		PerIP: TierConfig{
			MaxRequests:   2,
			Window:        1 * time.Minute,
			BlockDuration: 5 * time.Minute,
		},
		PerAccount: TierConfig{
			MaxRequests:   100,
			Window:        1 * time.Hour,
			BlockDuration: 30 * time.Minute,
		},
		Global: TierConfig{
			MaxRequests:   10000,
			Window:        1 * time.Minute,
			BlockDuration: 1 * time.Minute,
		},
	}

	limiter := NewAuthRateLimiter(cfg, nil)

	// Exhaust limit for IP1
	for i := 0; i < 2; i++ {
		w := httptest.NewRecorder()
		_, router := gin.CreateTestContext(w)
		router.POST("/api/auth/login", limiter.Middleware(), func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"status": "ok"})
		})

		req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/auth/login", nil)
		req.RemoteAddr = testRemoteAddr1
		router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code)
	}

	// IP1 should be blocked
	w := httptest.NewRecorder()
	_, router := gin.CreateTestContext(w)
	router.POST("/api/auth/login", limiter.Middleware(), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/auth/login", nil)
	req.RemoteAddr = testRemoteAddr1
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusTooManyRequests, w.Code, "IP1 should be blocked")

	// IP2 should still be allowed
	w2 := httptest.NewRecorder()
	_, router2 := gin.CreateTestContext(w2)
	router2.POST("/api/auth/login", limiter.Middleware(), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})
	req2 := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/auth/login", nil)
	req2.RemoteAddr = "10.0.0.2:12345"
	router2.ServeHTTP(w2, req2)
	assert.Equal(t, http.StatusOK, w2.Code, "IP2 should still be allowed")
}

// TestGlobalRateLimiting verifies that the global tier blocks when total
// requests across all IPs exceed the threshold.
func TestGlobalRateLimiting(t *testing.T) {
	cfg := AuthRateLimiterConfig{
		PerIP: TierConfig{
			MaxRequests:   100,
			Window:        1 * time.Minute,
			BlockDuration: 5 * time.Minute,
		},
		PerAccount: TierConfig{
			MaxRequests:   100,
			Window:        1 * time.Hour,
			BlockDuration: 30 * time.Minute,
		},
		Global: TierConfig{
			MaxRequests:   5,
			Window:        1 * time.Minute,
			BlockDuration: 1 * time.Minute,
		},
	}

	limiter := NewAuthRateLimiter(cfg, nil)

	// Make 5 requests from different IPs
	for i := 0; i < 5; i++ {
		w := httptest.NewRecorder()
		_, router := gin.CreateTestContext(w)
		router.POST("/api/auth/login", limiter.Middleware(), func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"status": "ok"})
		})

		req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/auth/login", nil)
		req.RemoteAddr = "10.0.0." + string(rune('1'+i)) + ":12345"
		router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code, "Request %d should be allowed", i+1)
	}

	// 6th request from a new IP should be blocked by global limit
	w := httptest.NewRecorder()
	_, router := gin.CreateTestContext(w)
	router.POST("/api/auth/login", limiter.Middleware(), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/auth/login", nil)
	req.RemoteAddr = "10.0.0.99:12345"
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusTooManyRequests, w.Code, "Should be blocked by global limit")
	assert.Equal(t, "global", w.Header().Get("X-RateLimit-Tier"), "Should indicate global tier")
}

// TestNormalizeEndpoint verifies that endpoint normalization groups related paths.
func TestNormalizeEndpoint(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"/api/auth/login", "auth_login"},
		{"/api/v1/auth/login", "auth_login"},
		{"/api/auth/register", "auth_register"},
		// auth_mfa was split 2026-05-19 into _credential (code-verifying,
		// brute-force-prone) and _mgmt (post-auth user-management
		// actions). isMFACredentialPath enumerates the credential set
		// explicitly; everything else under /auth/mfa is mgmt.
		{"/api/auth/mfa/complete", "auth_mfa_credential"},
		{"/api/auth/mfa/verify", "auth_mfa_credential"},
		{"/api/auth/mfa/send-code", "auth_mfa_credential"},
		{"/api/auth/mfa/step-up/verify", "auth_mfa_credential"},
		{"/api/v1/auth/mfa/setup/totp/verify", "auth_mfa_credential"},
		{"/api/v1/auth/mfa/enrollment/verify", "auth_mfa_credential"},
		{"/api/auth/mfa/switch-method", "auth_mfa_mgmt"},
		{"/api/v1/auth/mfa/setup/totp", "auth_mfa_mgmt"},
		{"/api/v1/auth/mfa/setup/email", "auth_mfa_mgmt"},
		{"/api/v1/auth/mfa/disable", "auth_mfa_mgmt"},
		{"/api/v1/auth/mfa/disable/email", "auth_mfa_mgmt"},
		{"/api/v1/auth/mfa/disable/totp", "auth_mfa_mgmt"},
		{"/api/v1/auth/mfa/backup-codes", "auth_mfa_mgmt"},
		{"/api/v1/auth/mfa/enrollment/init", "auth_mfa_mgmt"},
		{"/api/auth/magic-link/request", "auth_magic_link"},
		{"/api/auth/magic-link/verify", "auth_magic_link"},
		{"/api/v1/auth/magic-link/request", "auth_magic_link"},
		{"/api/auth/password/forgot", "auth_password"},
		{"/api/auth/password/reset", "auth_password"},
		{"/api/v1/auth/password/reset", "auth_password"},
		// Signup (3-call flow) — all sub-endpoints share one bucket per
		// the consumer-tenant abuse-prevention design (ENT-5). A 5/min/IP
		// override caps signup ATTEMPTS, not sub-calls.
		{"/api/v1/auth/signup", "auth_signup"},
		{"/api/v1/auth/signup/verify-email", "auth_signup_verify"},
		{"/api/v1/auth/signup/complete", "auth_signup"},
		{"/api/auth/signup", "auth_signup"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := normalizeEndpoint(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestRateLimitMessage verifies the user-facing messages for each tier.
func TestRateLimitMessage(t *testing.T) {
	tests := []struct {
		tier     RateLimitTier
		contains string
	}{
		{TierPerIP, "IP address"},
		{TierPerAccount, "account"},
		{TierGlobal, "high demand"},
	}

	for _, tt := range tests {
		t.Run(string(tt.tier), func(t *testing.T) {
			msg := rateLimitMessage(tt.tier)
			assert.Contains(t, msg, tt.contains)
		})
	}
}

// TestExtractClientIPWithTrustedProxies verifies IP extraction with proxy chains.
func TestExtractClientIPWithTrustedProxies(t *testing.T) {
	limiter := NewAuthRateLimiter(DefaultAuthRateLimiterConfig(), nil)
	limiter.SetTrustedProxies([]string{"10.0.0.1", "[::1]:8080"})

	tests := []struct {
		name          string
		remoteAddr    string
		xForwardedFor string
		expectedIP    string
	}{
		{
			name:       "Direct connection (no proxy)",
			remoteAddr: "192.168.1.1:8080",
			expectedIP: "192.168.1.1",
		},
		{
			name:          "Through trusted proxy",
			remoteAddr:    "10.0.0.1:8080",
			xForwardedFor: "203.0.113.50, 10.0.0.1",
			expectedIP:    "203.0.113.50",
		},
		{
			name:          "Through untrusted proxy",
			remoteAddr:    "192.168.1.99:8080",
			xForwardedFor: "203.0.113.50",
			expectedIP:    "192.168.1.99",
		},
		{
			name:          "IPv6 trusted proxy",
			remoteAddr:    "[::1]:8080",
			xForwardedFor: "2001:db8::1, ::1",
			expectedIP:    "2001:db8::1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)

			req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/auth/login", nil)
			req.RemoteAddr = tt.remoteAddr
			if tt.xForwardedFor != "" {
				req.Header.Set("X-Forwarded-For", tt.xForwardedFor)
			}
			c.Request = req

			ip := limiter.extractClientIP(c)
			assert.Equal(t, tt.expectedIP, ip)
		})
	}
}

// TestInMemoryStoreEviction verifies that the in-memory store evicts old entries.
func TestInMemoryStoreEviction(t *testing.T) {
	store := &inMemoryTieredStore{
		entries:    make(map[string]*tieredEntry),
		maxEntries: 3,
	}

	// Fill to capacity
	for i := 0; i < 3; i++ {
		key := "key" + string(rune('a'+i))
		entry := store.getOrCreate(key)
		entry.lastAccess = time.Now().Add(-time.Duration(3-i) * time.Minute)
	}

	require.Equal(t, 3, len(store.entries))

	// Adding a 4th entry should evict the oldest
	store.getOrCreate("keyd")
	assert.Equal(t, 3, len(store.entries), "Should evict to stay at maxEntries")
}

// TestInMemoryStoreCleanup verifies that expired entries are cleaned up.
func TestInMemoryStoreCleanup(t *testing.T) {
	store := &inMemoryTieredStore{
		entries:    make(map[string]*tieredEntry),
		maxEntries: 100,
	}

	// Add entries with old access times
	for i := 0; i < 10; i++ {
		key := "old" + string(rune('a'+i))
		entry := store.getOrCreate(key)
		entry.lastAccess = time.Now().Add(-1 * time.Hour)
	}

	// Add entries with recent access times
	for i := 0; i < 5; i++ {
		key := "new" + string(rune('a'+i))
		store.getOrCreate(key)
	}

	require.Equal(t, 15, len(store.entries))

	store.cleanup()

	assert.Equal(t, 5, len(store.entries), "Old entries should be cleaned up")
}

// TestBlockedEntryRemainsBlocked verifies that blocked entries stay blocked
// until the block duration expires.
func TestBlockedEntryRemainsBlocked(t *testing.T) {
	cfg := AuthRateLimiterConfig{
		PerIP: TierConfig{
			MaxRequests:   1,
			Window:        1 * time.Minute,
			BlockDuration: 10 * time.Minute,
		},
		PerAccount: TierConfig{
			MaxRequests:   100,
			Window:        1 * time.Hour,
			BlockDuration: 30 * time.Minute,
		},
		Global: TierConfig{
			MaxRequests:   10000,
			Window:        1 * time.Minute,
			BlockDuration: 1 * time.Minute,
		},
	}

	limiter := NewAuthRateLimiter(cfg, nil)

	// First request should pass
	w := httptest.NewRecorder()
	_, router := gin.CreateTestContext(w)
	router.POST("/api/auth/login", limiter.Middleware(), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/auth/login", nil)
	req.RemoteAddr = testRemoteAddr50
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)

	// Second request should be blocked
	w2 := httptest.NewRecorder()
	_, router2 := gin.CreateTestContext(w2)
	router2.POST("/api/auth/login", limiter.Middleware(), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})
	req2 := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/auth/login", nil)
	req2.RemoteAddr = testRemoteAddr50
	router2.ServeHTTP(w2, req2)
	assert.Equal(t, http.StatusTooManyRequests, w2.Code)

	// Third request should still be blocked (block duration hasn't expired)
	w3 := httptest.NewRecorder()
	_, router3 := gin.CreateTestContext(w3)
	router3.POST("/api/auth/login", limiter.Middleware(), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})
	req3 := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/auth/login", nil)
	req3.RemoteAddr = testRemoteAddr50
	router3.ServeHTTP(w3, req3)
	assert.Equal(t, http.StatusTooManyRequests, w3.Code)
}

// TestResponseHeaders verifies the rate limit response headers.
func TestResponseHeaders(t *testing.T) {
	cfg := AuthRateLimiterConfig{
		PerIP: TierConfig{
			MaxRequests:   1,
			Window:        1 * time.Minute,
			BlockDuration: 5 * time.Minute,
		},
		PerAccount: TierConfig{
			MaxRequests:   100,
			Window:        1 * time.Hour,
			BlockDuration: 30 * time.Minute,
		},
		Global: TierConfig{
			MaxRequests:   10000,
			Window:        1 * time.Minute,
			BlockDuration: 1 * time.Minute,
		},
	}

	limiter := NewAuthRateLimiter(cfg, nil)

	// First request passes
	w := httptest.NewRecorder()
	_, router := gin.CreateTestContext(w)
	router.POST("/api/auth/login", limiter.Middleware(), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/auth/login", nil)
	req.RemoteAddr = "10.99.99.99:12345"
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)

	// Second request should be blocked with proper headers
	w2 := httptest.NewRecorder()
	_, router2 := gin.CreateTestContext(w2)
	router2.POST("/api/auth/login", limiter.Middleware(), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})
	req2 := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/auth/login", nil)
	req2.RemoteAddr = "10.99.99.99:12345"
	router2.ServeHTTP(w2, req2)

	assert.Equal(t, http.StatusTooManyRequests, w2.Code)
	assert.NotEmpty(t, w2.Header().Get("Retry-After"))
	assert.Equal(t, "0", w2.Header().Get("X-RateLimit-Remaining"))
	assert.NotEmpty(t, w2.Header().Get("X-RateLimit-Reset"))
	assert.Equal(t, "per_ip", w2.Header().Get("X-RateLimit-Tier"))
}

// TestSetTrustedProxiesNormalizesAddresses verifies proxy address normalization.
func TestSetTrustedProxiesNormalizesAddresses(t *testing.T) {
	limiter := NewAuthRateLimiter(DefaultAuthRateLimiterConfig(), nil)

	limiter.SetTrustedProxies([]string{
		"10.0.0.1:8080",
		"[::1]:9090",
		"192.168.1.1",
	})

	limiter.mu.RLock()
	defer limiter.mu.RUnlock()

	assert.True(t, limiter.trustedProxies["10.0.0.1"])
	assert.True(t, limiter.trustedProxies["::1"])
	assert.True(t, limiter.trustedProxies["192.168.1.1"])
	assert.Equal(t, 3, len(limiter.trustedProxies))
}

// TestNewAuthRateLimiterWithNilRedis verifies that the limiter works with
// nil Redis (in-memory fallback mode).
func TestNewAuthRateLimiterWithNilRedis(t *testing.T) {
	limiter := NewAuthRateLimiter(DefaultAuthRateLimiterConfig(), nil)

	assert.NotNil(t, limiter)
	assert.Nil(t, limiter.redisLimiter)
	assert.NotNil(t, limiter.fallbackStore)
}

// TestEndpointIsolation verifies that different endpoints have separate rate limits.
func TestEndpointIsolation(t *testing.T) {
	cfg := AuthRateLimiterConfig{
		PerIP: TierConfig{
			MaxRequests:   2,
			Window:        1 * time.Minute,
			BlockDuration: 5 * time.Minute,
		},
		PerAccount: TierConfig{
			MaxRequests:   100,
			Window:        1 * time.Hour,
			BlockDuration: 30 * time.Minute,
		},
		Global: TierConfig{
			MaxRequests:   10000,
			Window:        1 * time.Minute,
			BlockDuration: 1 * time.Minute,
		},
	}

	limiter := NewAuthRateLimiter(cfg, nil)

	// Exhaust limit for /auth/login
	for i := 0; i < 2; i++ {
		w := httptest.NewRecorder()
		_, router := gin.CreateTestContext(w)
		router.POST("/api/auth/login", limiter.Middleware(), func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"status": "ok"})
		})
		req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/auth/login", nil)
		req.RemoteAddr = testRemoteAddr1
		router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code)
	}

	// /auth/login should now be blocked
	w := httptest.NewRecorder()
	_, router := gin.CreateTestContext(w)
	router.POST("/api/auth/login", limiter.Middleware(), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/auth/login", nil)
	req.RemoteAddr = testRemoteAddr1
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusTooManyRequests, w.Code)

	// /auth/password/reset should still work for the same IP
	// (different normalized endpoint = "auth_password" vs "auth_login")
	w2 := httptest.NewRecorder()
	_, router2 := gin.CreateTestContext(w2)
	router2.POST("/api/auth/password/reset", limiter.Middleware(), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})
	req2 := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/auth/password/reset", nil)
	req2.RemoteAddr = testRemoteAddr1
	router2.ServeHTTP(w2, req2)
	assert.Equal(t, http.StatusOK, w2.Code, "Different endpoint should have separate rate limit")
}

// TestExtractClientIPTrustedProxyCIDRAndExact verifies that both a CIDR range
// and an exact IP are honoured as trusted proxies, and that an untrusted peer
// cannot spoof X-Forwarded-For.
func TestExtractClientIPTrustedProxyCIDRAndExact(t *testing.T) {
	limiter := NewAuthRateLimiter(DefaultAuthRateLimiterConfig(), nil)
	limiter.SetTrustedProxies([]string{"10.42.0.0/16", "192.168.1.1"})

	tests := []struct {
		name       string
		remoteAddr string
		xff        string
		want       string
	}{
		{"cidr peer trusted", "10.42.7.9:1234", "203.0.113.5", "203.0.113.5"},
		{"exact peer trusted", "192.168.1.1:1234", "203.0.113.6", "203.0.113.6"},
		{"untrusted peer ignores XFF", "172.16.0.1:1234", "203.0.113.7", "172.16.0.1"},
		{"just outside cidr ignores XFF", "10.43.0.1:1234", "203.0.113.8", "10.43.0.1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, _ := gin.CreateTestContext(httptest.NewRecorder())
			c.Request = httptest.NewRequest(http.MethodPost, "/", nil)
			c.Request.RemoteAddr = tt.remoteAddr
			c.Request.Header.Set("X-Forwarded-For", tt.xff)
			assert.Equal(t, tt.want, limiter.extractClientIP(c))
		})
	}
}

func TestDefaultAuthRateLimiterConfig_OAuthLoginPerAccountLoose(t *testing.T) {
	cfg := DefaultAuthRateLimiterConfig()
	ov, ok := cfg.EndpointOverrides[normalizeEndpoint("/oauth/login")]
	require.True(t, ok, "oauth_login override missing")
	assert.GreaterOrEqual(t, ov.PerAccount.MaxRequests, 100)
	assert.Equal(t, 5, cfg.PerIP.MaxRequests, "per-IP stays strict")
}
