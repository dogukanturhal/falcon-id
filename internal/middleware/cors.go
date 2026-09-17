// SPDX-License-Identifier: AGPL-3.0-or-later

package middleware

import (
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
)

// CORSConfig holds CORS middleware configuration
type CORSConfig struct {
	// AllowedOrigins is the list of allowed origins
	AllowedOrigins []string
	// AllowedMethods is the list of allowed HTTP methods
	AllowedMethods []string
	// AllowedHeaders is the list of allowed headers
	AllowedHeaders []string
	// ExposedHeaders is the list of headers that are safe to expose to the API
	ExposedHeaders []string
	// AllowCredentials indicates whether the request can include user credentials
	AllowCredentials bool
	// MaxAge indicates how long (in seconds) the results of a preflight request can be cached
	MaxAge int
}

// DefaultCORSConfig returns environment-aware CORS configuration
func DefaultCORSConfig() CORSConfig {
	env := os.Getenv("ENVIRONMENT")

	var allowedOrigins []string

	switch env {
	case envProductionName:
		// SECURITY: Strict production origins only.
		//
		// Includes every public HexxLock product subdomain that mounts a
		// browser SPA which talks to Falcon-ID (OIDC silent-SSO probe via
		// /oauth/authorize, RP-initiated logout, token refresh via /oauth/token,
		// JWKS fetch). When a new product subdomain ships, add it here OR
		// the browser will fail CORS preflight with 403 and silent-SSO
		// will silently fall back to full redirect (visible to users as an
		// extra page bounce on every navigation).
		//
		// 2026-05-30 — added mearax.hexxlock.com + accounts.hexxlock.com
		// after iPhone Mearax dashboard surfaced preflight 403 on
		// /oauth/authorize?response_type=code&client_id=mearax-bff... .
		// Pre-existing dashboard.hexxlock.com / app.hexxlock.com / admin
		// entries kept; those mount distinct product SPAs.
		allowedOrigins = []string{
			"https://hexxlock.com",
			"https://www.hexxlock.com",
			"https://app.hexxlock.com",
			"https://dashboard.hexxlock.com",
			"https://admin.hexxlock.com",
			"https://accounts.hexxlock.com",
			"https://mearax.hexxlock.com",
			"https://example.com",
			"https://www.example.com",
			"https://app.example.com",
			"https://dashboard.example.com",
		}
	case envStagingName:
		allowedOrigins = []string{
			"https://staging.hexxlock.com",
			"https://staging-app.hexxlock.com",
			"https://staging-dashboard.hexxlock.com",
			"https://staging-accounts.hexxlock.com",
			"https://staging-mearax.hexxlock.com",
			"https://staging.example.com",
			"https://staging-app.example.com",
		}
	default: // development, test, or unset
		allowedOrigins = []string{
			"http://localhost:3000",
			"http://localhost:8080",
			"http://127.0.0.1:3000",
		}
	}

	return CORSConfig{
		AllowedOrigins: allowedOrigins,
		AllowedMethods: []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"},
		AllowedHeaders: []string{
			"Accept",
			"Authorization",
			"Content-Type",
			"Content-Length",
			"Accept-Encoding",
			"Cache-Control",
			"Origin",
			"X-Requested-With",
			"X-Tenant-ID",
			"X-Tenant-Slug",
			"X-Realm-ID",
			"X-Realm-Slug",
			"X-Realm-Type",
			"X-CSRF-Token",
			"X-Request-ID",
			"X-Correlation-ID",
			// Session-related headers (minimal JWT architecture)
			"X-Session-ID",
			"X-Role-Version",
		},
		ExposedHeaders: []string{
			"X-Request-ID",
			"X-Correlation-ID",
			"X-Session-ID",
		},
		AllowCredentials: true,
		MaxAge:           86400, // 24 hours
	}
}

// CORS middleware for handling cross-origin requests with security hardening
func CORS() gin.HandlerFunc {
	config := DefaultCORSConfig()
	return CORSWithConfig(config)
}

// CORSWithConfig returns a CORS middleware with custom configuration
func CORSWithConfig(config CORSConfig) gin.HandlerFunc {
	// Pre-compute lowercase origins for faster lookup
	allowedOriginsMap := make(map[string]bool)
	for _, origin := range config.AllowedOrigins {
		allowedOriginsMap[strings.ToLower(origin)] = true
	}

	// Allowed subdomain patterns for multi-tenant support
	allowedSubdomainPatterns := []string{
		".example.app",
		".hexxlock.com",
		".example.com",
	}

	return func(c *gin.Context) {
		origin := c.Request.Header.Get("Origin")

		// SECURITY: Reject null origin (can be used in attacks)
		if origin == "null" {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error":   "cors_invalid_origin",
				"message": "Null origin not allowed",
			})
			return
		}

		allowed := isOriginAllowed(origin, allowedOriginsMap, allowedSubdomainPatterns)

		if c.Request.Method == "OPTIONS" {
			handlePreflightRequest(c, origin, allowed, config)
			return
		}

		if allowed {
			setCorSHeaders(c, origin, config)
		}
		// SECURITY: Don't set CORS headers for unauthorized origins — browser will block.

		c.Next()
	}
}

// isOriginAllowed checks whether origin is permitted by exact map lookup or subdomain pattern.
func isOriginAllowed(origin string, allowedOriginsMap map[string]bool, allowedSubdomainPatterns []string) bool {
	if origin == "" {
		return false
	}
	if allowedOriginsMap[strings.ToLower(origin)] {
		return true
	}
	return isAllowedSubdomainOrigin(origin, allowedSubdomainPatterns)
}

// isAllowedSubdomainOrigin checks HTTPS origins against the allowed subdomain suffix patterns.
func isAllowedSubdomainOrigin(origin string, allowedSubdomainPatterns []string) bool {
	lowerOrigin := strings.ToLower(origin)
	if !strings.HasPrefix(lowerOrigin, "https://") {
		return false
	}
	domainPart := strings.TrimPrefix(lowerOrigin, "https://")
	hostPart := domainPart
	if idx := strings.IndexByte(domainPart, ':'); idx != -1 {
		hostPart = domainPart[:idx]
	}
	for _, pattern := range allowedSubdomainPatterns {
		if isValidSubdomainMatch(hostPart, pattern) {
			return true
		}
	}
	return false
}

// isValidSubdomainMatch returns true when hostPart matches the suffix pattern at a domain boundary.
// SECURITY: prevents "evilexample.app" from matching ".example.app".
func isValidSubdomainMatch(hostPart, pattern string) bool {
	if !strings.HasSuffix(hostPart, pattern) {
		return false
	}
	prefixLen := len(hostPart) - len(pattern)
	if prefixLen == 0 {
		return true // exact match
	}
	if hostPart[prefixLen-1] != '.' {
		return false
	}
	subdomain := hostPart[:prefixLen-1]
	return isValidSubdomain(subdomain)
}

// handlePreflightRequest responds to an OPTIONS preflight request.
func handlePreflightRequest(c *gin.Context, origin string, allowed bool, config CORSConfig) {
	if allowed {
		setCorSHeaders(c, origin, config)
		c.AbortWithStatus(http.StatusNoContent)
		return
	}
	if origin == "" {
		// Allow OPTIONS without origin for tools like curl
		c.AbortWithStatus(http.StatusNoContent)
		return
	}
	// SECURITY: Reject preflight from unauthorized origins
	c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
		"error":   "cors_origin_not_allowed",
		"message": "Origin not allowed",
	})
}

// setCorSHeaders sets the CORS response headers
func setCorSHeaders(c *gin.Context, origin string, config CORSConfig) {
	c.Writer.Header().Set("Access-Control-Allow-Origin", origin)

	if config.AllowCredentials {
		c.Writer.Header().Set("Access-Control-Allow-Credentials", "true")
	}

	if len(config.AllowedMethods) > 0 {
		c.Writer.Header().Set("Access-Control-Allow-Methods", strings.Join(config.AllowedMethods, ", "))
	}

	if len(config.AllowedHeaders) > 0 {
		c.Writer.Header().Set("Access-Control-Allow-Headers", strings.Join(config.AllowedHeaders, ", "))
	}

	if len(config.ExposedHeaders) > 0 {
		c.Writer.Header().Set("Access-Control-Expose-Headers", strings.Join(config.ExposedHeaders, ", "))
	}

	if config.MaxAge > 0 {
		c.Writer.Header().Set("Access-Control-Max-Age", strconv.Itoa(config.MaxAge))
	}

	// SECURITY: Prevent browsers from trying to guess content types
	c.Writer.Header().Set("X-Content-Type-Options", "nosniff")
}

// isValidSubdomain validates that a subdomain is well-formed
// SECURITY: Prevents subdomain injection attacks
func isValidSubdomain(subdomain string) bool {
	if subdomain == "" {
		return false
	}

	// Length check (DNS limit)
	if len(subdomain) > 63 {
		return false
	}

	// Must start and end with alphanumeric
	if !isAlphanumeric(subdomain[0]) || !isAlphanumeric(subdomain[len(subdomain)-1]) {
		return false
	}

	// Only allow lowercase alphanumeric and hyphens
	for _, c := range subdomain {
		if !isAlphanumeric(byte(c)) && c != '-' { //nolint:gosec // rune is always ASCII in this context, safe conversion
			return false
		}
	}

	// No consecutive hyphens
	if strings.Contains(subdomain, "--") {
		return false
	}

	return true
}

// isAlphanumeric checks if a character is a lowercase letter or digit
func isAlphanumeric(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
}
