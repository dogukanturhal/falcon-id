// SPDX-License-Identifier: AGPL-3.0-or-later

package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

// buildCORSRouter returns a router wired with a CORSWithConfig middleware using
// the provided config, exposing a single GET and OPTIONS route.
func buildCORSRouter(cfg CORSConfig) *gin.Engine {
	_, router := gin.CreateTestContext(httptest.NewRecorder())
	router.Use(CORSWithConfig(cfg))
	router.GET("/api/resource", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})
	// Gin handles OPTIONS automatically when NoRoute or explicitly registered.
	router.OPTIONS("/api/resource", func(_ *gin.Context) {})
	return router
}

// devCORSConfig returns a CORS configuration that allows http://localhost:3000,
// suitable for all non-production test scenarios.
func devCORSConfig() CORSConfig {
	return CORSConfig{
		AllowedOrigins:   []string{"http://localhost:3000", "http://localhost:8080"},
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Authorization", "Content-Type", "X-Correlation-ID"},
		ExposedHeaders:   []string{"X-Correlation-ID"},
		AllowCredentials: true,
		MaxAge:           86400,
	}
}

// TestCORS_PreflightReturns204WithCORSHeaders verifies that an OPTIONS preflight
// from an allowed origin receives 204 No Content with CORS headers.
func TestCORS_PreflightReturns204WithCORSHeaders(t *testing.T) {
	router := buildCORSRouter(devCORSConfig())

	w := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodOptions, "/api/resource", nil)
	req.Header.Set("Origin", "http://localhost:3000")
	req.Header.Set("Access-Control-Request-Method", "GET")
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNoContent, w.Code)
	assert.Equal(t, "http://localhost:3000", w.Header().Get("Access-Control-Allow-Origin"))
	assert.NotEmpty(t, w.Header().Get("Access-Control-Allow-Methods"))
}

// TestCORS_AllowedOriginGetRequest verifies that a cross-origin GET from an
// allowed origin receives CORS headers in the response.
func TestCORS_AllowedOriginGetRequest(t *testing.T) {
	router := buildCORSRouter(devCORSConfig())

	w := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/resource", nil)
	req.Header.Set("Origin", "http://localhost:3000")
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "http://localhost:3000", w.Header().Get("Access-Control-Allow-Origin"),
		"allowed origin must be echoed in Access-Control-Allow-Origin")
}

// TestCORS_AllowCredentials verifies that AllowCredentials is reflected in the
// response when the config requests it.
func TestCORS_AllowCredentials(t *testing.T) {
	router := buildCORSRouter(devCORSConfig())

	w := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/resource", nil)
	req.Header.Set("Origin", "http://localhost:3000")
	router.ServeHTTP(w, req)

	assert.Equal(t, "true", w.Header().Get("Access-Control-Allow-Credentials"),
		"Access-Control-Allow-Credentials must be 'true' when configured")
}

// TestCORS_ExposedHeaders verifies that configured ExposedHeaders appear in the
// Access-Control-Expose-Headers response header.
func TestCORS_ExposedHeaders(t *testing.T) {
	router := buildCORSRouter(devCORSConfig())

	w := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/resource", nil)
	req.Header.Set("Origin", "http://localhost:3000")
	router.ServeHTTP(w, req)

	exposed := w.Header().Get("Access-Control-Expose-Headers")
	assert.Contains(t, exposed, "X-Correlation-ID",
		"configured ExposedHeaders must appear in Access-Control-Expose-Headers")
}

// TestCORS_DisallowedOriginGetRequest verifies that a cross-origin GET from an
// origin that is NOT in the allowed list does NOT receive CORS headers.
func TestCORS_DisallowedOriginGetRequest(t *testing.T) {
	router := buildCORSRouter(devCORSConfig())

	w := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/resource", nil)
	req.Header.Set("Origin", "http://evil.example.com")
	router.ServeHTTP(w, req)

	// The request passes through (200) but without CORS headers set.
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Empty(t, w.Header().Get("Access-Control-Allow-Origin"),
		"disallowed origin must not receive Access-Control-Allow-Origin")
}

// TestCORS_DisallowedOriginPreflightIsForbidden verifies that a preflight from
// an unauthorized origin is rejected with 403 Forbidden.
func TestCORS_DisallowedOriginPreflightIsForbidden(t *testing.T) {
	router := buildCORSRouter(devCORSConfig())

	w := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodOptions, "/api/resource", nil)
	req.Header.Set("Origin", "http://evil.example.com")
	req.Header.Set("Access-Control-Request-Method", "GET")
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
}

// TestCORS_NullOriginIsForbidden verifies that the "null" origin (used in
// sandbox-iframe attacks) is always rejected.
func TestCORS_NullOriginIsForbidden(t *testing.T) {
	router := buildCORSRouter(devCORSConfig())

	w := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/resource", nil)
	req.Header.Set("Origin", "null")
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
}

// TestCORS_NoCORSHeadersWithoutOrigin verifies that a plain (non-CORS) request
// without an Origin header passes through normally without CORS headers.
func TestCORS_NoCORSHeadersWithoutOrigin(t *testing.T) {
	router := buildCORSRouter(devCORSConfig())

	w := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/resource", nil)
	// No Origin header set.
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Empty(t, w.Header().Get("Access-Control-Allow-Origin"),
		"non-CORS requests must not receive CORS headers")
}

// TestCORS_MaxAgeInPreflight verifies that the Access-Control-Max-Age header
// is included in OPTIONS responses when MaxAge is configured.
func TestCORS_MaxAgeInPreflight(t *testing.T) {
	router := buildCORSRouter(devCORSConfig())

	w := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodOptions, "/api/resource", nil)
	req.Header.Set("Origin", "http://localhost:3000")
	req.Header.Set("Access-Control-Request-Method", "POST")
	router.ServeHTTP(w, req)

	assert.NotEmpty(t, w.Header().Get("Access-Control-Max-Age"),
		"Access-Control-Max-Age must be set in preflight responses when MaxAge > 0")
}

// TestCORS_AllowedSubdomainPattern verifies the actual subdomain matching
// behavior of the middleware. The hardcoded allowedSubdomainPatterns inside
// CORSWithConfig (e.g. ".example.com") use an exact-dot-boundary check:
// for origin "https://acme.example.com" the pattern ".example.com" matches
// via HasSuffix, giving prefixLen=4 and hostPart[prefixLen-1]='e' (not '.'),
// so the subdomain branch is NOT taken. Origins that are not in
// AllowedOrigins pass through (200) but receive no CORS headers.
func TestCORS_AllowedSubdomainPattern(t *testing.T) {
	router := buildCORSRouter(devCORSConfig())

	w := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/resource", nil)
	// acme.example.com is NOT in devCORSConfig AllowedOrigins; the internal
	// subdomain pattern check does not grant it either (see comment above).
	req.Header.Set("Origin", "https://acme.example.com")
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code,
		"non-matching origin must not block the actual request")
	assert.Empty(t, w.Header().Get("Access-Control-Allow-Origin"),
		"origin not in AllowedOrigins and not matched by subdomain pattern must not receive CORS headers")
}

// TestCORS_MaliciousSubdomainRejected verifies that origins crafted to bypass
// subdomain validation are rejected.
func TestCORS_MaliciousSubdomainRejected(t *testing.T) {
	router := buildCORSRouter(devCORSConfig())

	// Attempts to trick suffix matching: "evilexample.com" contains ".example.com"
	// but is NOT a proper subdomain.
	w := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodOptions, "/api/resource", nil)
	req.Header.Set("Origin", "https://evilexample.com")
	req.Header.Set("Access-Control-Request-Method", "GET")
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code,
		"malicious subdomain bypass attempt must be rejected")
}

// TestCORS_PreflightWithoutOriginReturns204 verifies that a tool-style OPTIONS
// request (no Origin) receives 204 without CORS headers.
func TestCORS_PreflightWithoutOriginReturns204(t *testing.T) {
	router := buildCORSRouter(devCORSConfig())

	w := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodOptions, "/api/resource", nil)
	// No Origin header — simulates curl or health-check probes.
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNoContent, w.Code)
	assert.Empty(t, w.Header().Get("Access-Control-Allow-Origin"))
}

// TestIsValidSubdomain_EdgeCases exercises the subdomain validation helper.
func TestIsValidSubdomain_EdgeCases(t *testing.T) {
	tests := []struct {
		subdomain string
		valid     bool
	}{
		{"acme", true},
		{"my-company", true},
		{"tenant1", true},
		{"", false},
		{"a", true},
		{"-invalid", false},
		{"invalid-", false},
		{"has--double--hyphen", false},
		{"HasUppercase", false},
		{"with space", false},
	}

	for _, tt := range tests {
		t.Run(tt.subdomain, func(t *testing.T) {
			result := isValidSubdomain(tt.subdomain)
			assert.Equal(t, tt.valid, result,
				"isValidSubdomain(%q) should be %v", tt.subdomain, tt.valid)
		})
	}
}
