// SPDX-License-Identifier: AGPL-3.0-or-later

// Package middleware provides HTTP middleware for the IAM service.
package middleware

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	goredis "github.com/redis/go-redis/v9"

	"github.com/dogukanturhal/falcon-id/pkg/redis"
)

const (
	// CSRFTokenHeader is the header name for CSRF token
	CSRFTokenHeader = "X-CSRF-Token" //nolint:gosec // not a credential, this is a header name constant
	// CSRFCookieName is the cookie name for CSRF token
	CSRFCookieName = "hexxlock_csrf"
	// CSRFTokenLength is the length of the CSRF token in bytes
	CSRFTokenLength = 32
	// CSRFCookieMaxAge is the max age of the CSRF cookie
	CSRFCookieMaxAge = 12 * 60 * 60 // 12 hours
	// CSRFRedisKeyPrefix is the prefix for CSRF tokens in Redis
	CSRFRedisKeyPrefix = "csrf:token:"
)

// CSRFConfig holds CSRF middleware configuration
type CSRFConfig struct {
	// TokenLength is the length of the CSRF token in bytes
	TokenLength int
	// CookieName is the name of the CSRF cookie
	CookieName string
	// CookieMaxAge is the max age of the CSRF cookie in seconds
	CookieMaxAge int
	// CookiePath is the path for the CSRF cookie
	CookiePath string
	// CookieDomain is the domain for the CSRF cookie
	CookieDomain string
	// CookieSecure indicates if the cookie should only be sent over HTTPS
	CookieSecure bool
	// CookieHTTPOnly indicates if the cookie should be HTTP only
	CookieHTTPOnly bool
	// CookieSameSite sets the SameSite attribute for the cookie
	CookieSameSite http.SameSite
	// HeaderName is the name of the header to check for the token
	HeaderName string
	// SkipMethods are HTTP methods to skip CSRF check
	SkipMethods []string
	// SkipPaths are paths to skip CSRF check (useful for API key authenticated endpoints)
	SkipPaths []string
	// ErrorHandler is called when CSRF validation fails
	ErrorHandler gin.HandlerFunc
	// RedisClient is the Redis client for storing CSRF tokens per session
	RedisClient *redis.Client
}

// DefaultCSRFConfig returns a default CSRF configuration
func DefaultCSRFConfig() CSRFConfig {
	env := os.Getenv("ENVIRONMENT")
	isProduction := env == envProductionName || env == envStagingName

	return CSRFConfig{
		TokenLength:    CSRFTokenLength,
		CookieName:     CSRFCookieName,
		CookieMaxAge:   CSRFCookieMaxAge,
		CookiePath:     "/",
		CookieDomain:   "",
		CookieSecure:   isProduction,
		CookieHTTPOnly: false, // Must be false so JavaScript can read it for double-submit
		CookieSameSite: http.SameSiteStrictMode,
		HeaderName:     CSRFTokenHeader,
		SkipMethods:    []string{"GET", "HEAD", "OPTIONS", "TRACE"},
		SkipPaths: []string{
			"/health",
			"/metrics",
			"/internal/",                    // Internal API uses API key auth
			"/api/v1/permissions/internal/", // Service-to-service permission registration (X-Internal-Key)
			"/scim/v2/",                     // SCIM uses bearer token auth
			"/oauth/token",                  // OAuth token endpoint uses client credentials
			"/oauth/introspect",             // RFC 7662 §2.1 — confidential-client auth (client_secret_basic / _post) IS the anti-CSRF; CSRF middleware would block every legitimate s2s introspection call
			"/oauth/revoke",                 // RFC 7009 §2.1 — same reasoning as /oauth/introspect; client credentials authenticate the request, no browser-form attack surface
			"/oauth/par",                    // RFC 9126 §2.2 — Pushed Authorization Request; confidential-client auth at the endpoint, called server-side by RPs
			"/oauth/login",                  // Pre-auth: credentials serve as anti-CSRF (OIDC login form)
			"/oauth/consent",                // Handler-level double-submit (falcon_oauth_csrf cookie + csrf_token form field); middleware uses X-CSRF-Token / _csrf which the OIDC consent form does not carry
			"/.well-known/",
			"/api/auth/login",           // Pre-auth: credentials serve as anti-CSRF
			"/api/v1/auth/login",        // Pre-auth: v1 route
			"/api/auth/register",        // Pre-auth: no session to exploit
			"/api/v1/auth/register",     // Pre-auth: v1 route
			"/api/auth/password/forgot", // Pre-auth: only sends email, no state change
			"/api/v1/auth/password/forgot",
			"/api/auth/password/reset", // Pre-auth: requires one-time reset token
			"/api/v1/auth/password/reset",
			"/api/auth/magic-link", // Pre-auth: only sends email
			"/api/v1/auth/magic-link",
			"/api/auth/mfa/verify", // Pre-auth: requires MFA session + OTP code
			"/api/v1/auth/mfa/verify",
			"/api/auth/mfa/complete", // Pre-auth: session-based MFA completion (no password)
			"/api/v1/auth/mfa/complete",
			"/api/auth/mfa/switch-method", // Pre-auth: switch MFA method during login
			"/api/v1/auth/mfa/switch-method",
			// Risk-MFA enrollment-interrupt routes — pre-auth, no IdP session yet.
			//
			// These fire when /api/v1/auth/login returns
			// {requires_mfa_enrollment:true, enrollment_token:"..."} due to
			// high-risk-score login (new device, no MFA enrolled). The
			// browser is mid-login: it has password-validated the user but
			// no IdP session cookie yet, so the standard CSRF middleware's
			// session-bound double-submit token cannot exist (Redis
			// CSRFRedisKeyPrefix:<sessionID> has no entry — there is no
			// sessionID).
			//
			// Anti-CSRF for these endpoints is the enrollment_token itself:
			// IP+UA-bound and single-use, returned only to the originating
			// browser by /auth/login (memory:
			// internal engineering notes). An
			// attacker on a different IP+UA cannot replay the token, so
			// the cross-site forgery surface is closed at the application
			// layer rather than the middleware layer.
			//
			// OWASP Cross-Site Request Forgery Prevention Cheat Sheet
			// allows alternative anti-CSRF mechanisms; the enrollment_token
			// is one (functionally equivalent to the MFA session in
			// /api/v1/auth/mfa/verify, which is also skipped here for the
			// same reason).
			//
			// Without this skip, every iPhone/Chrome user hitting risk-MFA
			// enrollment gets HTTP 403 csrf_validation_failed and cannot
			// complete the MFA setup that the same login flow demanded
			// (observed live 2026-05-07: dogukanturhal@example.com from
			// CriOS/147.0 Mobile/15E148 Safari/604.1, 4 consecutive
			// /api/v1/auth/mfa/enrollment/init POSTs all 403'd).
			"/api/auth/mfa/enrollment/init",
			"/api/v1/auth/mfa/enrollment/init",
			"/api/auth/mfa/enrollment/verify",
			"/api/v1/auth/mfa/enrollment/verify",
			"/api/auth/mfa/enrollment/skip",    // Pre-auth: grace-period "Remind me later"
			"/api/v1/auth/mfa/enrollment/skip", // Pre-auth: v1 route, same enrollment_token gate
			"/api/auth/mfa/enrollment/webauthn/begin",
			"/api/v1/auth/mfa/enrollment/webauthn/begin",
			"/api/auth/mfa/enrollment/webauthn/finish",
			"/api/v1/auth/mfa/enrollment/webauthn/finish",
			// MFA-as-WebAuthn VERIFICATION ceremony (Phase A.2, 2026-05-26) —
			// the login-time counterpart to the enrollment pair above. Pre-auth:
			// the user is mid-login MFA challenge, gated by the temp MFA
			// session_id (resolved from Redis), so no IdP session / session-bound
			// CSRF token exists yet. Anti-CSRF is the WebAuthn assertion itself
			// (same rationale as the conditional/login ceremonies below). These
			// were overlooked when passkey-as-MFA shipped, so after switching the
			// MFA method to passkey the ceremony POST /mfa/webauthn/begin 403'd
			// with csrf_validation_failed (live repro 2026-06-22).
			"/api/auth/mfa/webauthn/begin",
			"/api/v1/auth/mfa/webauthn/begin",
			"/api/auth/mfa/webauthn/finish",
			"/api/v1/auth/mfa/webauthn/finish",
			// Primary-login WebAuthn ceremonies — pre-auth, no IdP session
			// yet. The session-bound CSRF token cannot exist (no sessionID
			// to key Redis on). Anti-CSRF for these endpoints is the
			// WebAuthn assertion itself: hardware-key-signed + origin-
			// bound + non-replayable per W3C WebAuthn L3 §5.1.4. An
			// attacker without physical possession of the authenticator
			// AND control of the matching origin cannot forge the
			// assertion, so the cross-site forgery surface is closed at
			// the protocol layer rather than the middleware layer —
			// strictly stronger than the session-bound token (which
			// merely proves the request came from the same browser
			// holding the session, whereas the assertion proves the
			// request came from the user touching their hardware key
			// inside the right origin).
			//
			// Without this skip the new primary-login button at
			// id.hexxlock.com/login surfaces "csrf_validation_failed"
			// on every passkey ceremony attempt (live repro 2026-05-24:
			// dogukanturhal Chrome/148 first POST after frontend!92
			// deploy → POST /webauthn/conditional/begin → 403 size:75
			// latency:100us — fast 403 is the middleware signature).
			//
			// Mirrors the /api/v1/auth/login exemption + the
			// /webauthn/mfa/enrollment exemption above — same root cause
			// (pre-auth state → no session-bound token possible) and
			// same replacement defense (cryptographic credential at the
			// endpoint level).
			"/api/auth/webauthn/conditional/begin",
			"/api/v1/auth/webauthn/conditional/begin",
			"/api/auth/webauthn/conditional/complete",
			"/api/v1/auth/webauthn/conditional/complete",
			"/api/auth/webauthn/login/begin",
			"/api/v1/auth/webauthn/login/begin",
			"/api/auth/webauthn/login/finish",
			"/api/v1/auth/webauthn/login/finish",
			// ZTNA Path-B device-enrollment witness ceremony (ADR 0043 §3.c.0).
			// Same class as the WebAuthn ceremony endpoints above and exempt for
			// the same reasons — the session-bound synchronizer token does NOT
			// fit this flow, and stronger protections already apply:
			//
			//  1. The witness page is launched by the device-agent DESKTOP
			//     app into the system browser (a cross-context, app-initiated
			//     navigation). The single-slot per-session synchronizer token
			//     (Redis CSRFRedisKeyPrefix:<sessionID> + the shared
			//     hexxlock_csrf cookie) is clobbered across concurrent
			//     renders/retries, so the page-embedded X-CSRF-Token reliably
			//     mismatches the stored slot at /witness/begin → deterministic
			//     csrf_validation_failed (live repro 2026-06-16:
			//     dogukanturhal@example.com, every begin POST 403'd while the
			//     GET rendered 200).
			//  2. The real anti-CSRF here is the SameSite=Strict
			//     falcon_idp_session cookie: a cross-site request cannot carry
			//     it, so an attacker cannot drive these endpoints with the
			//     victim's session at all. Plus both handlers re-check
			//     platform_admin, and /witness/finish verifies a hardware-key
			//     WebAuthn assertion (origin-bound + non-replayable, W3C
			//     WebAuthn L3 §5.1.4) — strictly stronger than a synchronizer
			//     token. Identical rationale to the login/conditional ceremony
			//     exemptions above.
			"/api/auth/webauthn/witness/begin",
			"/api/v1/auth/webauthn/witness/begin",
			"/api/auth/webauthn/witness/finish",
			"/api/v1/auth/webauthn/witness/finish",
			"/api/auth/discover",           // Pre-auth: email discovery for adaptive login (no state change)
			"/api/v1/auth/discover",        // Pre-auth: v1 route
			"/api/auth/realm-discovery",    // Pre-auth: identifier-first realm lookup (no state change)
			"/api/v1/auth/realm-discovery", // Pre-auth: v1 route
			"/api/auth/signup",             // Pre-auth: self-service signup (no session)
			"/api/v1/auth/signup",          // Pre-auth: v1 route
			"/api/v1/auth/signup/",         // Pre-auth: signup sub-routes (verify, complete)
			// Pre-auth: invitation onboarding creates the account from a single-use
			// invitation token (the credential); no session, so no synchronizer token
			// can exist. Without this every invited-member signup 403s (csrf_validation_failed).
			"/api/auth/invitations/register",
			"/api/v1/auth/invitations/register",
			"/api/auth/social/",            // Pre-auth: social auth callbacks (Apple POST uses form_post)
			"/api/v1/auth/social/",         // Pre-auth: v1 social routes
			"/api/auth/heartbeat",          // Session keepalive: protected by Bearer token auth
			"/api/v1/auth/heartbeat",
			"/api/auth/refresh",        // Refresh token is a bearer credential (httpOnly cookie); CSRF not needed
			"/api/v1/auth/refresh",     // v1 route
			"/api/platform/auth/login", // Pre-auth: credentials serve as anti-CSRF (platform admin)
			"/api/v1/platform/auth/login",
			"/saml/sp/",                          // SAML SP endpoints: cross-origin IdP POSTs use protocol-level replay/signature protection
			"/api/v1/platform/autoscale/webhook", // AlertManager webhook: internal-only, network-isolated
			"/api/v1/internal/",                  // All internal service-to-service endpoints (X-Internal-Key auth)
		},
		ErrorHandler: nil,
	}
}

// CSRFMiddleware creates a new CSRF protection middleware
type CSRFMiddleware struct {
	config CSRFConfig
	// originRegistry is the Stage 3 tenant-registry-derived origin set
	// consulted (in-memory, no per-request network call) alongside
	// getAllowedCSRFOrigins()'s static patterns in validateOrigin. Nil
	// (unset via SetOriginRegistry) behaves exactly as before Stage 3 —
	// (*DynamicOriginRegistry)(nil).Contains is always false.
	originRegistry *DynamicOriginRegistry
}

// NewCSRFMiddleware creates a new CSRF middleware with default config
func NewCSRFMiddleware(redisClient *redis.Client) *CSRFMiddleware {
	config := DefaultCSRFConfig()
	config.RedisClient = redisClient
	return &CSRFMiddleware{
		config: config,
	}
}

// SetOriginRegistry wires the Stage 3 dynamic tenant-origin registry into
// origin validation. Safe to call with nil (no-op — validateOrigin already
// tolerates a nil registry).
func (m *CSRFMiddleware) SetOriginRegistry(registry *DynamicOriginRegistry) {
	m.originRegistry = registry
}

// NewCSRFMiddlewareWithConfig creates a new CSRF middleware with custom config
func NewCSRFMiddlewareWithConfig(config CSRFConfig) *CSRFMiddleware {
	return &CSRFMiddleware{
		config: config,
	}
}

func (m *CSRFMiddleware) getRedisKey(sessionID uuid.UUID) string {
	return fmt.Sprintf("%s%s", CSRFRedisKeyPrefix, sessionID.String())
}

func (m *CSRFMiddleware) storeTokenInRedis(ctx context.Context, sessionID uuid.UUID, token string) error {
	if m.config.RedisClient == nil {
		return nil
	}
	key := m.getRedisKey(sessionID)
	ttl := time.Duration(m.config.CookieMaxAge) * time.Second
	return m.config.RedisClient.Set(ctx, key, token, ttl)
}

func (m *CSRFMiddleware) getTokenFromRedis(ctx context.Context, sessionID uuid.UUID) (string, error) {
	if m.config.RedisClient == nil {
		return "", nil
	}
	key := m.getRedisKey(sessionID)
	token, err := m.config.RedisClient.Get(ctx, key)
	if err != nil {
		if errors.Is(err, goredis.Nil) {
			return "", nil
		}
		return "", err
	}
	return token, nil
}

// CSRF returns the CSRF protection middleware handler
func (m *CSRFMiddleware) CSRF() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Skip CSRF for exempt methods
		if m.isExemptMethod(c.Request.Method) {
			c.Next()
			return
		}

		// Skip CSRF for exempt paths
		if m.isExemptPath(c.Request.URL.Path) {
			c.Next()
			return
		}

		// Check if request is authenticated with API key (skip CSRF for API key auth)
		if c.GetBool("api_key_authenticated") {
			c.Next()
			return
		}

		// SECURITY: Skip CSRF for explicit Authorization header auth.
		// CSRF attacks exploit automatic cookie inclusion by the browser.
		// An Authorization header requires JavaScript to set, which triggers
		// a CORS preflight (OPTIONS) for cross-origin requests — the browser
		// blocks the request unless the server explicitly allows the origin.
		// Cookie-based auth (fallback) still requires CSRF validation.
		if authHeader := c.GetHeader("Authorization"); strings.HasPrefix(authHeader, "Bearer ") {
			c.Next()
			return
		}

		// SECURITY: Validate Origin/Referer header first (defense in depth)
		if !m.validateOrigin(c) {
			if m.config.ErrorHandler != nil {
				m.config.ErrorHandler(c)
				return
			}
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error":   "origin_validation_failed",
				"message": "Request origin validation failed",
			})
			return
		}

		// Validate CSRF token (Redis-based if session exists, cookie-based fallback)
		if !m.validateToken(c) {
			if m.config.ErrorHandler != nil {
				m.config.ErrorHandler(c)
				return
			}
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error":   "csrf_validation_failed",
				"message": "CSRF token validation failed",
			})
			return
		}

		c.Next()
	}
}

// generateToken generates a new CSRF token
func (m *CSRFMiddleware) generateToken() (string, error) {
	bytes := make([]byte, m.config.TokenLength)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("generateToken: %w", err)
	}
	return base64.URLEncoding.EncodeToString(bytes), nil
}

// GenerateTokenForSession generates a CSRF token for a session and stores it in Redis
func (m *CSRFMiddleware) GenerateTokenForSession(c *gin.Context, sessionID uuid.UUID) (string, error) {
	token, err := m.generateToken()
	if err != nil {
		return "", fmt.Errorf("GenerateTokenForSession: generateToken failed: %w", err)
	}

	if err := m.storeTokenInRedis(c.Request.Context(), sessionID, token); err != nil {
		log.Printf("ERROR: Failed to store CSRF token in Redis: %v", err)
	}

	return token, nil
}

// WriteCookie sets the hexxlock_csrf cookie on the current response
// with the configured attributes (SameSite, Secure, MaxAge, Path,
// HttpOnly=false). Idempotent. Callers that just generated a token
// for the user should invoke this so the cookie double-submit
// fallback in validateToken has a cookie to compare against — closes
// the gap that left the cookie path as dead code (no code ever set
// the cookie despite validateToken referencing it).
//
// HttpOnly is intentionally false here: per OWASP CSRF Prevention
// Cheat Sheet 2025, the double-submit pattern requires browser JS
// to read the cookie value and mirror it into the X-CSRF-Token
// header. SameSite=Strict (prod) + Origin/Referer validation
// (validateOrigin) keep the cookie unreadable to attacker-controlled
// origins.
func (m *CSRFMiddleware) WriteCookie(c *gin.Context, token string) {
	c.SetSameSite(m.config.CookieSameSite)
	c.SetCookie(
		m.config.CookieName,
		token,
		m.config.CookieMaxAge,
		m.config.CookiePath,
		m.config.CookieDomain,
		m.config.CookieSecure,
		m.config.CookieHTTPOnly,
	)
}

// validateOrigin validates the Origin or Referer header against allowed origins
// SECURITY: This provides defense in depth against CSRF attacks
func (m *CSRFMiddleware) validateOrigin(c *gin.Context) bool {
	origin := resolveCSRFOrigin(c)
	if origin == "" {
		return true // no origin header — allow (CSRF token check still enforced)
	}
	if origin == "null" {
		log.Printf("WARN: CSRF rejected null origin")
		return false
	}

	requestHost := stripCSRFPort(c.Request.Host)

	originHost := extractHostFromOrigin(origin)
	if originHost == "" {
		log.Printf("WARN: CSRF could not extract host from origin: %s", origin)
		return false
	}

	if originHost == requestHost {
		return true
	}

	for _, allowed := range getAllowedCSRFOrigins() {
		if matchesOriginPattern(origin, allowed) {
			return true
		}
	}

	// Stage 3: tenant-registry-derived origins, on top of the static
	// patterns above. m.originRegistry.Contains is an in-memory lookup
	// against the last successfully cached set (see
	// DynamicOriginRegistry's fail-closed contract) — a nil registry, or
	// one that has never refreshed successfully, contributes nothing
	// here, so this can only ever ADD trusted origins on top of the
	// static list, never substitute for it.
	if m.originRegistry.Contains(origin) {
		return true
	}

	log.Printf("WARN: CSRF origin mismatch - origin: %s, host: %s", origin, requestHost)
	return false
}

// resolveCSRFOrigin returns the Origin header value, falling back to extracting the origin from Referer.
func resolveCSRFOrigin(c *gin.Context) string {
	if origin := c.GetHeader("Origin"); origin != "" {
		return origin
	}
	if referer := c.GetHeader("Referer"); referer != "" {
		return extractOriginFromURL(referer)
	}
	return ""
}

// stripCSRFPort removes the port from a host string (e.g., "example.com:8080" → "example.com").
func stripCSRFPort(host string) string {
	if idx := strings.Index(host, ":"); idx != -1 {
		return host[:idx]
	}
	return host
}

// extractOriginFromURL extracts the origin (scheme://host:port) from a URL
func extractOriginFromURL(urlStr string) string {
	// Find the scheme
	schemeEnd := strings.Index(urlStr, "://")
	if schemeEnd == -1 {
		return ""
	}

	// Find the path start (after scheme://host)
	pathStart := strings.Index(urlStr[schemeEnd+3:], "/")
	if pathStart == -1 {
		return urlStr // No path, return as-is
	}

	return urlStr[:schemeEnd+3+pathStart]
}

// extractHostFromOrigin extracts the host from an origin URL
func extractHostFromOrigin(origin string) string {
	// Remove scheme
	host := origin
	if strings.HasPrefix(host, "https://") {
		host = host[8:]
	} else if strings.HasPrefix(host, "http://") {
		host = host[7:]
	}

	// Remove port
	if idx := strings.Index(host, ":"); idx != -1 {
		host = host[:idx]
	}

	// Remove path (shouldn't be in origin, but just in case)
	if idx := strings.Index(host, "/"); idx != -1 {
		host = host[:idx]
	}

	return host
}

// getAllowedCSRFOrigins returns the list of allowed origins for CSRF validation
func getAllowedCSRFOrigins() []string {
	env := os.Getenv("ENVIRONMENT")

	switch env {
	case envProductionName:
		return []string{
			"https://hexxlock.com",
			"https://www.hexxlock.com",
			"https://app.hexxlock.com",
			"https://dashboard.hexxlock.com",
			"https://admin.hexxlock.com",
			"https://*.hexxlock.com",
			// AcmeWeb serves example.com (acmeweb-prod HTTPRoute), including
			// its wildcard for tenant subdomains. Absent here, a
			// state-changing request from the live customer app is rejected
			// as a cross-origin CSRF attempt.
			//
			// hexxlock.io was a legacy test apex retired 2026-09-24: the
			// acmeweb-prod HTTPRoute now only 301-redirects it to example.com,
			// it is never served as a first-class origin, so no browser ever
			// submits a state-changing request with Origin: https://hexxlock.io.
			// Removed here.
			"https://example.com",
			"https://www.example.com",
			"https://*.example.com",
			"https://example.com",
			"https://www.example.com",
			"https://app.example.com",
			"https://dashboard.example.com",
			"https://*.example.com",
			"https://*.example.app",
		}
	case envStagingName:
		return []string{
			"https://staging.hexxlock.com",
			"https://staging-app.hexxlock.com",
			"https://staging-dashboard.hexxlock.com",
			"https://*.staging.hexxlock.com",
			"https://staging.example.com",
			"https://*.staging.example.com",
		}
	default: // development
		return []string{
			"http://localhost:3000",
			"http://localhost:3001",
			"http://localhost:3003",
			"http://localhost:8080",
			"http://localhost:9080",
			"http://127.0.0.1:3000",
			"http://127.0.0.1:3001",
			"http://127.0.0.1:3003",
		}
	}
}

// matchesOriginPattern checks if an origin matches an allowed pattern
// Supports wildcard subdomain patterns like "https://*.hexxlock.com"
func matchesOriginPattern(origin, pattern string) bool {
	if origin == pattern {
		return true
	}
	if !strings.Contains(pattern, "*") {
		return false
	}

	patternScheme, patternDomain := splitOriginScheme(pattern)
	originScheme, originDomain := splitOriginScheme(origin)

	if patternScheme != originScheme {
		return false
	}

	if strings.HasPrefix(patternDomain, "*.") {
		baseDomain := patternDomain[2:]
		return originDomain == baseDomain || strings.HasSuffix(originDomain, "."+baseDomain)
	}

	return false
}

// splitOriginScheme splits a URL into (scheme+"://", rest) for http:// and https:// URLs.
func splitOriginScheme(url string) (scheme, domain string) {
	switch {
	case strings.HasPrefix(url, "https://"):
		return "https://", url[8:]
	case strings.HasPrefix(url, "http://"):
		return "http://", url[7:]
	default:
		return "", url
	}
}

// validateToken validates the CSRF token. Tries (in order):
//
//  1. Synchronizer-token (server-stored): when an authenticated user
//     is in context (set by AuthMiddleware.OptionalAuth running
//     earlier in the global chain — see cmd/routes.go applyGlobalMiddleware),
//     look up the per-session token from Redis and constant-time
//     compare it against the supplied header.
//
//  2. Double-submit cookie fallback: compare the supplied header
//     token against the hexxlock_csrf cookie (issued by the
//     GetCSRFToken handler alongside the JSON response).
//
// OWASP CSRF Prevention Cheat Sheet 2025 endorses BOTH paths;
// Path 1 (synchronizer token) is the primary, Path 2 covers the
// pre-auth window where no session exists yet.
func (m *CSRFMiddleware) validateToken(c *gin.Context) bool {
	headerToken := c.GetHeader(m.config.HeaderName)
	if headerToken == "" {
		headerToken = c.PostForm("_csrf")
	}

	if headerToken == "" {
		return false
	}

	// Path 1: synchronizer token, keyed by the session ID set in
	// context by OptionalAuth (or RequireAuth for routes that mount
	// it). Tier-1 industry-standard CSRF defense per OWASP.
	user := GetCurrentUser(c)
	if user != nil && m.config.RedisClient != nil {
		storedToken, err := m.getTokenFromRedis(c.Request.Context(), user.SessionID)
		if err == nil && storedToken != "" {
			if subtle.ConstantTimeCompare([]byte(storedToken), []byte(headerToken)) == 1 {
				return true
			}
			// Synchronizer token present but mismatched. Do NOT short-circuit
			// to false — fall through to the double-submit cookie path below.
			// The per-session slot is single-valued, so it can be legitimately
			// overwritten between a server-rendered page's render and its POST
			// (a second render in another tab/retry, or a different auth path
			// resolving a different session_id for the same request). When the
			// page also sets the hexxlock_csrf cookie to the SAME token it
			// embedded (see WebAuthnHandler.generateWitnessCSRFToken /
			// auth_handler_profile), the cookie + X-CSRF-Token always agree for
			// that render even if Redis was overwritten. The double-submit
			// cookie is an independent, OWASP-recognised CSRF proof and Origin
			// is already validated above, so accepting it here is safe and makes
			// server-rendered flows (the ZTNA witness-enrollment page) robust.
		}
	}

	// Path 2: double-submit cookie fallback. The hexxlock_csrf cookie
	// is set by GetCSRFToken (and the witness-enrollment page) alongside
	// the token so this path is functional even before a session exists
	// OR when the synchronizer slot above was overwritten.
	cookieToken, err := c.Cookie(m.config.CookieName)
	if err != nil || cookieToken == "" {
		return false
	}

	return subtle.ConstantTimeCompare([]byte(cookieToken), []byte(headerToken)) == 1
}

// isExemptMethod checks if the HTTP method is exempt from CSRF check
func (m *CSRFMiddleware) isExemptMethod(method string) bool {
	for _, exemptMethod := range m.config.SkipMethods {
		if method == exemptMethod {
			return true
		}
	}
	return false
}

// isExemptPath checks if the path is exempt from CSRF check.
// Paths ending with "/" use prefix matching (for route groups like /internal/, /scim/v2/).
// All other paths use exact matching to prevent unintended exemptions.
func (m *CSRFMiddleware) isExemptPath(path string) bool {
	for _, exemptPath := range m.config.SkipPaths {
		if strings.HasSuffix(exemptPath, "/") {
			// Prefix match for route groups (e.g., /internal/, /scim/v2/)
			if strings.HasPrefix(path, exemptPath) {
				return true
			}
		} else {
			// Exact match for specific endpoints
			if path == exemptPath {
				return true
			}
		}
	}
	return false
}

// GetCSRFToken returns the CSRF token from the context
func GetCSRFToken(c *gin.Context) string {
	token, exists := c.Get("csrf_token")
	if !exists {
		return ""
	}
	// Safe type assertion with check
	str, ok := token.(string)
	if !ok {
		log.Printf("ERROR: CSRF token in context is not a string: %T", token)
		return ""
	}
	return str
}

// CSRFTokenEndpoint is a handler that returns the current CSRF token.
// This can be used by SPAs to get a token on initial load.
//
// Deprecated: Use RateLimitedCSRFTokenEndpoint instead for production.
func CSRFTokenEndpoint() gin.HandlerFunc {
	return func(c *gin.Context) {
		token := GetCSRFToken(c)
		c.JSON(http.StatusOK, gin.H{
			"csrf_token": token,
			"expires_at": time.Now().Add(time.Duration(CSRFCookieMaxAge) * time.Second).Unix(),
		})
	}
}

// csrfRateLimitMaxEntries bounds the in-memory CSRF rate limit store to
// prevent unbounded memory growth under DDoS from many distinct IPs.
const csrfRateLimitMaxEntries = 50000

// csrfTokenRateLimiter stores rate limit state for CSRF token requests
var csrfTokenRateLimiter = &csrfRateLimitStore{
	store: make(map[string]*csrfRateLimitEntry),
}

type csrfRateLimitEntry struct {
	count     int
	windowEnd time.Time
}

type csrfRateLimitStore struct {
	mu    sync.Mutex
	store map[string]*csrfRateLimitEntry
}

// CSRFTokenRateLimitConfig defines rate limits for CSRF token endpoint
type CSRFTokenRateLimitConfig struct {
	MaxRequests   int           // Maximum requests per window
	WindowSeconds int           // Time window in seconds
	BlockDuration time.Duration // How long to block after exceeding limit
}

// DefaultCSRFTokenRateLimitConfig returns secure default rate limits
func DefaultCSRFTokenRateLimitConfig() CSRFTokenRateLimitConfig {
	return CSRFTokenRateLimitConfig{
		MaxRequests:   10,              // 10 requests per window
		WindowSeconds: 60,              // Per minute
		BlockDuration: 5 * time.Minute, // Block for 5 minutes if exceeded
	}
}

// RateLimitedCSRFTokenEndpoint returns a rate-limited CSRF token endpoint
// SECURITY: Prevents abuse of CSRF token generation
func RateLimitedCSRFTokenEndpoint(config CSRFTokenRateLimitConfig) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Rate-limit by the real client public IP (X-Real-IP, APISIX-stamped
		// from CF-Connecting-IP). The TCP peer is the APISIX pod IP — keying
		// rate limits on it would lump every client into one bucket and
		// effectively rate-limit the gateway itself, not individual abusers.
		clientIP := ClientIP(c.Request)

		// Check rate limit
		if blocked, retryAfter := checkCSRFTokenRateLimit(clientIP, config); blocked {
			c.Header("Retry-After", fmt.Sprintf("%d", int(retryAfter.Seconds())))
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{
				"error":       "rate_limit_exceeded",
				"message":     "Too many CSRF token requests. Please try again later.",
				"retry_after": int(retryAfter.Seconds()),
			})
			return
		}

		token := GetCSRFToken(c)
		c.JSON(http.StatusOK, gin.H{
			"csrf_token": token,
			"expires_at": time.Now().Add(time.Duration(CSRFCookieMaxAge) * time.Second).Unix(),
		})
	}
}

// checkCSRFTokenRateLimit checks if the client has exceeded the rate limit
func checkCSRFTokenRateLimit(clientIP string, config CSRFTokenRateLimitConfig) (blocked bool, retryAfter time.Duration) {
	csrfTokenRateLimiter.mu.Lock()
	defer csrfTokenRateLimiter.mu.Unlock()

	now := time.Now()
	key := "csrf_token:" + clientIP

	entry, exists := csrfTokenRateLimiter.store[key]
	if exists {
		return updateExistingCSRFEntry(entry, now, config)
	}

	evictExpiredCSRFEntries(now)
	if len(csrfTokenRateLimiter.store) >= csrfRateLimitMaxEntries {
		return true, 1 * time.Minute
	}

	createNewCSRFEntry(key, now, config)
	return false, 0
}

// updateExistingCSRFEntry updates an existing rate limit entry and returns blocked status.
func updateExistingCSRFEntry(entry *csrfRateLimitEntry, now time.Time, config CSRFTokenRateLimitConfig) (bool, time.Duration) {
	if now.Before(entry.windowEnd) {
		entry.count++
		if entry.count > config.MaxRequests {
			entry.windowEnd = now.Add(config.BlockDuration)
			return true, entry.windowEnd.Sub(now)
		}
		return false, 0
	}
	// Window expired — reset
	entry.count = 1
	entry.windowEnd = now.Add(time.Duration(config.WindowSeconds) * time.Second)
	return false, 0
}

// createNewCSRFEntry inserts a fresh rate limit entry into the store.
func createNewCSRFEntry(key string, now time.Time, config CSRFTokenRateLimitConfig) {
	csrfTokenRateLimiter.store[key] = &csrfRateLimitEntry{
		count:     1,
		windowEnd: now.Add(time.Duration(config.WindowSeconds) * time.Second),
	}
}

// evictExpiredCSRFEntries removes entries whose window has elapsed to bound memory usage.
func evictExpiredCSRFEntries(now time.Time) {
	if len(csrfTokenRateLimiter.store) < csrfRateLimitMaxEntries {
		return
	}
	for k, e := range csrfTokenRateLimiter.store {
		if now.After(e.windowEnd) {
			delete(csrfTokenRateLimiter.store, k)
		}
	}
}

// csrfCleanupStopCh is used to stop the CSRF rate limit cleanup goroutine.
var (
	csrfCleanupStopCh   = make(chan struct{})
	csrfCleanupStopOnce sync.Once
)

// StopCSRFCleanup stops the background CSRF rate limit cleanup goroutine.
// Safe to call multiple times.
func StopCSRFCleanup() {
	csrfCleanupStopOnce.Do(func() { close(csrfCleanupStopCh) })
}

// init starts the CSRF rate limit cleanup goroutine.
// Call StopCSRFCleanup() during shutdown to stop it.
func init() {
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				cleanupCSRFRateLimitStore()
			case <-csrfCleanupStopCh:
				return
			}
		}
	}()
}

func cleanupCSRFRateLimitStore() {
	csrfTokenRateLimiter.mu.Lock()
	defer csrfTokenRateLimiter.mu.Unlock()

	now := time.Now()
	for key, entry := range csrfTokenRateLimiter.store {
		if now.After(entry.windowEnd) {
			delete(csrfTokenRateLimiter.store, key)
		}
	}
}
