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

// buildSecurityHeadersRouter returns a router with SecurityHeadersWithConfig applied
// so tests can supply an explicit config rather than relying on the ENVIRONMENT variable.
func buildSecurityHeadersRouter(cfg SecurityHeadersConfig) *gin.Engine {
	w := httptest.NewRecorder()
	_, router := gin.CreateTestContext(w)
	router.Use(SecurityHeadersWithConfig(cfg))
	router.GET("/test", func(c *gin.Context) {
		c.Status(http.StatusOK)
	})
	router.GET("/api/data", func(c *gin.Context) {
		c.Status(http.StatusOK)
	})
	return router
}

// fullSecurityConfig returns a SecurityHeadersConfig with all fields populated so
// every header assertion can be exercised without relying on the environment.
func fullSecurityConfig() SecurityHeadersConfig {
	return SecurityHeadersConfig{
		XFrameOptions:             "DENY",
		XContentTypeOptions:       "nosniff",
		XSSProtection:             "1; mode=block",
		StrictTransportSecurity:   "max-age=31536000; includeSubDomains; preload",
		ReferrerPolicy:            "strict-origin-when-cross-origin",
		PermissionsPolicy:         "accelerometer=(), camera=()",
		ContentSecurityPolicy:     "default-src 'self'",
		CacheControl:              "no-store, no-cache, must-revalidate, proxy-revalidate",
		CrossOriginEmbedderPolicy: "require-corp",
		CrossOriginOpenerPolicy:   "same-origin-allow-popups",
		CrossOriginResourcePolicy: "same-origin",
	}
}

// TestSecurityHeaders_XFrameOptions verifies the X-Frame-Options header is set.
func TestSecurityHeaders_XFrameOptions(t *testing.T) {
	router := buildSecurityHeadersRouter(fullSecurityConfig())

	w := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/test", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "DENY", w.Header().Get("X-Frame-Options"),
		"X-Frame-Options must be set to prevent clickjacking")
}

// TestSecurityHeaders_XContentTypeOptions verifies the X-Content-Type-Options header is set.
func TestSecurityHeaders_XContentTypeOptions(t *testing.T) {
	router := buildSecurityHeadersRouter(fullSecurityConfig())

	w := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/test", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, "nosniff", w.Header().Get("X-Content-Type-Options"),
		"X-Content-Type-Options must prevent MIME sniffing")
}

// TestSecurityHeaders_ContentSecurityPolicy verifies the Content-Security-Policy header is set.
func TestSecurityHeaders_ContentSecurityPolicy(t *testing.T) {
	router := buildSecurityHeadersRouter(fullSecurityConfig())

	w := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/test", nil)
	router.ServeHTTP(w, req)

	csp := w.Header().Get("Content-Security-Policy")
	assert.NotEmpty(t, csp, "Content-Security-Policy must be set")
	assert.Contains(t, csp, "default-src", "CSP must have a default-src directive")
}

// TestSecurityHeaders_StrictTransportSecurity verifies the HSTS header is present.
func TestSecurityHeaders_StrictTransportSecurity(t *testing.T) {
	router := buildSecurityHeadersRouter(fullSecurityConfig())

	w := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/test", nil)
	router.ServeHTTP(w, req)

	hsts := w.Header().Get("Strict-Transport-Security")
	assert.NotEmpty(t, hsts, "Strict-Transport-Security (HSTS) must be set")
	assert.Contains(t, hsts, "max-age=", "HSTS must contain max-age directive")
}

// TestSecurityHeaders_ReferrerPolicy verifies the Referrer-Policy header is set.
func TestSecurityHeaders_ReferrerPolicy(t *testing.T) {
	router := buildSecurityHeadersRouter(fullSecurityConfig())

	w := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/test", nil)
	router.ServeHTTP(w, req)

	assert.NotEmpty(t, w.Header().Get("Referrer-Policy"),
		"Referrer-Policy must be set")
}

// TestSecurityHeaders_PermissionsPolicy verifies the Permissions-Policy header is set.
func TestSecurityHeaders_PermissionsPolicy(t *testing.T) {
	router := buildSecurityHeadersRouter(fullSecurityConfig())

	w := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/test", nil)
	router.ServeHTTP(w, req)

	assert.NotEmpty(t, w.Header().Get("Permissions-Policy"),
		"Permissions-Policy must be set")
}

// TestSecurityHeaders_CrossOriginPolicies verifies cross-origin isolation headers are set.
func TestSecurityHeaders_CrossOriginPolicies(t *testing.T) {
	router := buildSecurityHeadersRouter(fullSecurityConfig())

	w := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/test", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, "require-corp", w.Header().Get("Cross-Origin-Embedder-Policy"))
	assert.Equal(t, "same-origin-allow-popups", w.Header().Get("Cross-Origin-Opener-Policy"))
	assert.Equal(t, "same-origin", w.Header().Get("Cross-Origin-Resource-Policy"))
}

// TestSecurityHeaders_CacheControlOnAPIPath verifies that Cache-Control headers
// are added for /api/ paths.
func TestSecurityHeaders_CacheControlOnAPIPath(t *testing.T) {
	router := buildSecurityHeadersRouter(fullSecurityConfig())

	w := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/data", nil)
	router.ServeHTTP(w, req)

	assert.NotEmpty(t, w.Header().Get("Cache-Control"),
		"Cache-Control must be set for /api/ paths")
	assert.Equal(t, "no-cache", w.Header().Get("Pragma"))
	assert.Equal(t, "0", w.Header().Get("Expires"))
}

// TestSecurityHeaders_NoCacheControlOnNonAPIPath verifies that Cache-Control is
// NOT injected for non-/api/ paths.
func TestSecurityHeaders_NoCacheControlOnNonAPIPath(t *testing.T) {
	router := buildSecurityHeadersRouter(fullSecurityConfig())

	w := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/test", nil)
	router.ServeHTTP(w, req)

	assert.Empty(t, w.Header().Get("Cache-Control"),
		"Cache-Control must NOT be set for non-API paths")
}

// TestSecurityHeaders_EmptyConfigSetsNoHeaders verifies that an empty config
// leaves all security headers unset.
func TestSecurityHeaders_EmptyConfigSetsNoHeaders(t *testing.T) {
	router := buildSecurityHeadersRouter(SecurityHeadersConfig{})

	w := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/test", nil)
	router.ServeHTTP(w, req)

	assert.Empty(t, w.Header().Get("X-Frame-Options"))
	assert.Empty(t, w.Header().Get("X-Content-Type-Options"))
	assert.Empty(t, w.Header().Get("Content-Security-Policy"))
}

// TestSecurityHeaders_DoesNotBlockRequest confirms the middleware passes through
// to the downstream handler.
func TestSecurityHeaders_DoesNotBlockRequest(t *testing.T) {
	router := buildSecurityHeadersRouter(fullSecurityConfig())

	w := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/test", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

// TestDefaultSecurityHeadersConfig verifies that the default config has the
// expected base values set regardless of environment.
func TestDefaultSecurityHeadersConfig(t *testing.T) {
	cfg := DefaultSecurityHeadersConfig()

	assert.Equal(t, "DENY", cfg.XFrameOptions)
	assert.Equal(t, "nosniff", cfg.XContentTypeOptions)
	assert.NotEmpty(t, cfg.ContentSecurityPolicy)
	assert.NotEmpty(t, cfg.ReferrerPolicy)
}

// TestAPISecurityHeaders_SetsRequiredHeaders verifies that APISecurityHeaders
// middleware sets the core security headers on API responses.
func TestAPISecurityHeaders_SetsRequiredHeaders(t *testing.T) {
	w := httptest.NewRecorder()
	_, router := gin.CreateTestContext(w)
	router.Use(APISecurityHeaders())
	router.GET("/test", func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/test", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "nosniff", w.Header().Get("X-Content-Type-Options"))
	assert.Equal(t, "DENY", w.Header().Get("X-Frame-Options"))
	assert.NotEmpty(t, w.Header().Get("Cache-Control"))
}
