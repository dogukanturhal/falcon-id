// SPDX-License-Identifier: AGPL-3.0-or-later

// Package middleware provides HTTP middleware for the IAM service.
package middleware

import (
	"os"
	"strings"

	"github.com/gin-gonic/gin"
)

const (
	envProductionName = "production"
	envStagingName    = "staging"
)

// SecurityHeadersConfig holds security headers middleware configuration
type SecurityHeadersConfig struct {
	// ContentSecurityPolicy is the Content-Security-Policy header value
	ContentSecurityPolicy string
	// XFrameOptions is the X-Frame-Options header value
	XFrameOptions string
	// XContentTypeOptions is the X-Content-Type-Options header value
	XContentTypeOptions string
	// XSSProtection is the X-XSS-Protection header value
	XSSProtection string
	// StrictTransportSecurity is the Strict-Transport-Security header value (HSTS)
	StrictTransportSecurity string
	// ReferrerPolicy is the Referrer-Policy header value
	ReferrerPolicy string
	// PermissionsPolicy is the Permissions-Policy header value
	PermissionsPolicy string
	// CacheControl is the Cache-Control header value for API responses
	CacheControl string
	// CrossOriginEmbedderPolicy is the Cross-Origin-Embedder-Policy header value
	CrossOriginEmbedderPolicy string
	// CrossOriginOpenerPolicy is the Cross-Origin-Opener-Policy header value
	CrossOriginOpenerPolicy string
	// CrossOriginResourcePolicy is the Cross-Origin-Resource-Policy header value
	CrossOriginResourcePolicy string
}

// DefaultSecurityHeadersConfig returns environment-aware security headers configuration
func DefaultSecurityHeadersConfig() SecurityHeadersConfig {
	env := os.Getenv("ENVIRONMENT")
	isProduction := env == envProductionName || env == envStagingName

	config := SecurityHeadersConfig{
		// SECURITY: Prevent clickjacking attacks
		XFrameOptions: "DENY",

		// SECURITY: Prevent MIME-type sniffing
		XContentTypeOptions: "nosniff",

		// SECURITY: Enable browser XSS filtering (legacy, but still useful)
		XSSProtection: "1; mode=block",

		// SECURITY: Control referrer information
		ReferrerPolicy: "strict-origin-when-cross-origin",

		// SECURITY: Restrict browser features
		PermissionsPolicy: "accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()",

		// SECURITY: Prevent caching of sensitive API responses
		CacheControl: "no-store, no-cache, must-revalidate, proxy-revalidate",

		// SECURITY: Cross-origin isolation policies
		CrossOriginEmbedderPolicy: "require-corp",
		// `same-origin-allow-popups` instead of strict `same-origin` —
		// preserves the popup-mode OIDC flow that Vault (and any
		// other RP that uses `window.open` + popup → callback →
		// `window.opener.postMessage`) relies on.
		//
		// Under strict `same-origin`, when a same-origin popup
		// navigates to Falcon-ID (cross-origin from the RP's view)
		// and then back to the RP, `window.opener` is severed by the
		// browser — the popup's callback page throws
		// `Cannot read properties of null (reading 'postMessage')`
		// and the OIDC sign-in dead-ends. Caught live 2026-06-14 on
		// vault.ops popup.
		//
		// `same-origin-allow-popups` keeps the COOP+COEP top-level
		// isolation benefits (Spectre/Meltdown, SharedArrayBuffer
		// gating) but allows popups opened by trusted same-origin
		// parents to retain the opener relationship across cross-
		// origin navigation. The risk delta is bounded because:
		//   * iframe embed is still blocked by CSP frame-ancestors
		//   * form submission is still gated by CSP form-action 'self'
		//   * Falcon-ID exposes no postMessage handler that leaks data
		//   * CSRF tokens still protect mutations
		CrossOriginOpenerPolicy:   "same-origin-allow-popups",
		CrossOriginResourcePolicy: "same-origin",
	}

	if isProduction {
		// SECURITY: HSTS - Force HTTPS for 1 year, include subdomains, preload
		config.StrictTransportSecurity = "max-age=31536000; includeSubDomains; preload"

		// SECURITY: Strict CSP for production
		config.ContentSecurityPolicy = strings.Join([]string{
			"default-src 'self'",
			"script-src 'self'",
			"style-src 'self' 'unsafe-inline'", // Some inline styles may be needed
			"img-src 'self' data: https:",
			"font-src 'self'",
			"connect-src 'self'",
			"frame-ancestors 'none'",
			"form-action 'self'",
			"base-uri 'self'",
			"object-src 'none'",
			"upgrade-insecure-requests",
		}, "; ")
	} else {
		// Development: Relaxed HSTS
		config.StrictTransportSecurity = "max-age=0"

		// Development: Relaxed CSP to allow debugging tools
		config.ContentSecurityPolicy = strings.Join([]string{
			"default-src 'self'",
			"script-src 'self' 'unsafe-inline' 'unsafe-eval'", // Allow inline for dev tools
			"style-src 'self' 'unsafe-inline'",
			"img-src 'self' data: https: http:",
			"font-src 'self' data:",
			"connect-src 'self' ws: wss: http: https:", // Allow all connections in dev
			"frame-ancestors 'self'",
			"form-action 'self'",
		}, "; ")

		// Relax cross-origin policies in development
		config.CrossOriginEmbedderPolicy = ""
		config.CrossOriginOpenerPolicy = ""
		config.CrossOriginResourcePolicy = ""
	}

	return config
}

// SecurityHeaders returns a middleware that sets comprehensive security headers
func SecurityHeaders() gin.HandlerFunc {
	config := DefaultSecurityHeadersConfig()
	return SecurityHeadersWithConfig(config)
}

// SecurityHeadersWithConfig returns a security headers middleware with custom configuration
func SecurityHeadersWithConfig(config SecurityHeadersConfig) gin.HandlerFunc {
	return func(c *gin.Context) {
		setSecurityHeaders(c, config)
		c.Next()
	}
}

// setSecurityHeaders applies all configured security headers to the response.
func setSecurityHeaders(c *gin.Context, config SecurityHeadersConfig) {
	isAPIPath := strings.HasPrefix(c.Request.URL.Path, "/api/")

	setHeaderIfNonEmpty(c, "X-Frame-Options", config.XFrameOptions)
	setHeaderIfNonEmpty(c, "X-Content-Type-Options", config.XContentTypeOptions)
	setHeaderIfNonEmpty(c, "X-XSS-Protection", config.XSSProtection)
	setHeaderIfNonEmpty(c, "Strict-Transport-Security", config.StrictTransportSecurity)
	setHeaderIfNonEmpty(c, "Referrer-Policy", config.ReferrerPolicy)
	setHeaderIfNonEmpty(c, "Permissions-Policy", config.PermissionsPolicy)
	setHeaderIfNonEmpty(c, "Cross-Origin-Embedder-Policy", config.CrossOriginEmbedderPolicy)
	setHeaderIfNonEmpty(c, "Cross-Origin-Opener-Policy", config.CrossOriginOpenerPolicy)
	setHeaderIfNonEmpty(c, "Cross-Origin-Resource-Policy", config.CrossOriginResourcePolicy)

	// CSP is only meaningful for HTML pages rendered in a browser.
	// Setting it on JSON API responses causes browsers to block cross-origin
	// fetch calls from frontend apps (e.g. localhost:3003 → localhost:8005).
	if config.ContentSecurityPolicy != "" && !isAPIPath {
		c.Header("Content-Security-Policy", config.ContentSecurityPolicy)
	}

	if config.CacheControl != "" && isAPIPath {
		c.Header("Cache-Control", config.CacheControl)
		c.Header("Pragma", "no-cache")
		c.Header("Expires", "0")
	}
}

// setHeaderIfNonEmpty sets a response header only when the value is non-empty.
func setHeaderIfNonEmpty(c *gin.Context, name, value string) {
	if value != "" {
		c.Header(name, value)
	}
}

// APISecurityHeaders returns security headers optimized for API endpoints
// This is a lighter version that doesn't include CSP (which is more relevant for HTML pages)
func APISecurityHeaders() gin.HandlerFunc {
	return func(c *gin.Context) {
		env := os.Getenv("ENVIRONMENT")
		isProduction := env == envProductionName || env == envStagingName

		// Core security headers for APIs
		c.Header("X-Content-Type-Options", "nosniff")
		c.Header("X-Frame-Options", "DENY")
		c.Header("Cache-Control", "no-store, no-cache, must-revalidate")
		c.Header("Pragma", "no-cache")
		c.Header("Expires", "0")

		if isProduction {
			c.Header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}

		c.Next()
	}
}
