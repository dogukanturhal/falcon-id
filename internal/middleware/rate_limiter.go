// SPDX-License-Identifier: AGPL-3.0-or-later

package middleware

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/pkg/logger"
	pkgredis "github.com/dogukanturhal/falcon-id/pkg/redis"
)

// RateLimitTier identifies which tier of rate limiting was triggered.
type RateLimitTier string

const (
	// TierPerIP limits requests from a single IP address.
	// Prevents brute force attacks from a single source.
	TierPerIP RateLimitTier = "per_ip"

	// TierPerAccount limits requests targeting a specific account.
	// Prevents credential stuffing across multiple IPs.
	TierPerAccount RateLimitTier = "per_account"

	// TierGlobal limits total requests across all sources.
	// Prevents DDoS on authentication endpoints.
	TierGlobal RateLimitTier = "global"
)

// TierConfig defines the rate limit parameters for a single tier.
type TierConfig struct {
	MaxRequests   int
	Window        time.Duration
	BlockDuration time.Duration
}

// AuthRateLimiterConfig defines the tiered rate limiting configuration
// for authentication endpoints.
type AuthRateLimiterConfig struct {
	// PerIP limits requests from a single IP address.
	// Default: 5 requests per minute, block for 5 minutes.
	PerIP TierConfig

	// PerAccount limits requests targeting a specific account (email/username).
	// Default: 10 requests per hour, block for 30 minutes.
	PerAccount TierConfig

	// Global limits total requests to auth endpoints across all sources.
	// Default: 1000 requests per minute, block for 1 minute.
	Global TierConfig

	// EndpointOverrides maps a normalized endpoint name (the value returned
	// by normalizeEndpoint) to per-tier overrides. When an entry is
	// present, those tiers are consulted INSTEAD of the global PerIP /
	// PerAccount defaults for that endpoint's bucket. Missing tier (zero
	// MaxRequests) falls back to the default for that tier.
	//
	// Motivation: post-auth MFA management actions (disable, setup,
	// backup-code regenerate) belong in a relaxed bucket vs the strict
	// 5/min/IP designed for /login + /mfa/verify credential checks. The
	// auth_mfa bucket was split into auth_mfa_credential (strict) and
	// auth_mfa_mgmt (relaxed) by normalizeEndpoint 2026-05-19; this map
	// gives the relaxed bucket its own tier sizing without weakening the
	// brute-force protection on credential surfaces.
	//
	// Industry pattern: Auth0 "Management API" vs "Authentication API"
	// tiers; Okta "User Lifecycle" vs "Authentication" buckets.
	EndpointOverrides map[string]EndpointTierOverride
}

// EndpointTierOverride lets a specific endpoint bucket override the
// default PerIP / PerAccount tier sizings. Zero-value tier (MaxRequests
// == 0) means "fall back to the global default" — partial overrides are
// allowed.
type EndpointTierOverride struct {
	PerIP      TierConfig
	PerAccount TierConfig
}

// DefaultAuthRateLimiterConfig returns the default tiered rate limiting configuration.
// SECURITY: These defaults are deliberately restrictive to protect auth endpoints
// against brute-force and credential-stuffing attacks.
func DefaultAuthRateLimiterConfig() AuthRateLimiterConfig {
	return AuthRateLimiterConfig{
		PerIP: TierConfig{
			MaxRequests:   5,
			Window:        1 * time.Minute,
			BlockDuration: 5 * time.Minute,
		},
		PerAccount: TierConfig{
			MaxRequests:   10,
			Window:        1 * time.Hour,
			BlockDuration: 30 * time.Minute,
		},
		Global: TierConfig{
			MaxRequests:   1000,
			Window:        1 * time.Minute,
			BlockDuration: 1 * time.Minute,
		},
		EndpointOverrides: map[string]EndpointTierOverride{
			// MFA MANAGEMENT — relaxed for already-authenticated user
			// actions. RequireFreshAuth(5min) is the proper auth-time
			// gate per RFC 9470; the rate limit just bounds rapid abuse.
			// Settings sized for a user managing factors across an
			// enrollment flow (setup TOTP → verify → enable email →
			// generate backup codes → disable one factor → re-enable) —
			// easily 8-10 distinct calls in 30 seconds.
			"auth_mfa_mgmt": {
				PerIP: TierConfig{
					MaxRequests:   30,
					Window:        1 * time.Minute,
					BlockDuration: 1 * time.Minute,
				},
				PerAccount: TierConfig{
					MaxRequests:   100,
					Window:        1 * time.Hour,
					BlockDuration: 5 * time.Minute,
				},
			},
			// HOME-REALM DISCOVERY — looser than the credential-checking
			// strict default (5/min/IP) because the login UI calls this
			// once per user keystroke-debounce on the email field, but
			// still bounded so an attacker can't iterate the email space
			// observing email_known:true/false. Threat model is
			// enumeration of registered emails, NOT credential brute-force,
			// so the per-IP budget can be ~6x the login bucket while
			// staying well below what enumeration-at-scale requires
			// (millions of probes). Industry pattern: Okta /api/v1/users
			// lookup is rate-limited at 60/min per org/IP for the same
			// reason. Pair with the negative-cache + timing-smoothing in
			// services/discover_service.go for full RFC-aligned mitigation.
			"auth_discover": {
				PerIP: TierConfig{
					MaxRequests:   30,
					Window:        1 * time.Minute,
					BlockDuration: 5 * time.Minute,
				},
				PerAccount: TierConfig{
					MaxRequests:   60,
					Window:        1 * time.Hour,
					BlockDuration: 30 * time.Minute,
				},
			},
			// SIGNUP — stricter than the 5/min/IP login default would
			// imply, because the shared `hexxlock-consumer` tenant
			// receives every personal-account signup. A flooder could
			// inflate the consumer-tenant member list with throwaway
			// gmail addresses if signup were limited only by the
			// global tier (1000/min). Tier here is sized for an honest
			// 3-call flow (initiate → verify-email → complete) which
			// the normalizeEndpoint prefix-match groups under one
			// shared bucket — so 5/min/IP = 5 distinct signup attempts
			// per IP per minute, not 15 sub-calls.
			//
			// No PerAccount tier: at signup time there's no
			// authenticated user-account, so the per-account budget
			// is N/A and falls through to the global cap.
			//
			// Pair with frontend CAPTCHA + the existing
			// EMAIL_HASH_KEY-backed normalized-email-uniqueness check
			// in signup_service for full abuse coverage.
			"auth_signup": {
				PerIP: TierConfig{
					MaxRequests:   5,
					Window:        1 * time.Minute,
					BlockDuration: 30 * time.Minute,
				},
			},
			// MFA CREDENTIAL surfaces keep the strict default (5/min/IP,
			// 10/hour/account, 5-30 min blocks). No override needed —
			// absence in this map = use the global tier values.
		},
	}
}

// DevAuthRateLimiterConfig returns relaxed rate limits suitable for development/testing.
// Allows rapid iteration without hitting rate limit blocks.
func DevAuthRateLimiterConfig() AuthRateLimiterConfig {
	return AuthRateLimiterConfig{
		PerIP: TierConfig{
			MaxRequests:   1000,
			Window:        1 * time.Minute,
			BlockDuration: 1 * time.Second,
		},
		PerAccount: TierConfig{
			MaxRequests:   2000,
			Window:        1 * time.Hour,
			BlockDuration: 1 * time.Second,
		},
		Global: TierConfig{
			MaxRequests:   10000,
			Window:        1 * time.Minute,
			BlockDuration: 10 * time.Second,
		},
	}
}

// rateLimitDenial captures the details of a rate limit rejection.
type rateLimitDenial struct {
	Tier       RateLimitTier
	RetryAfter time.Duration
	ResetAt    time.Time
}

// AuthRateLimiter provides tiered rate limiting for authentication endpoints.
// It supports both Redis-based distributed limiting and in-memory fallback.
type AuthRateLimiter struct {
	config         AuthRateLimiterConfig
	redisLimiter   *pkgredis.RateLimiter
	fallbackStore  *inMemoryTieredStore
	trustedProxies map[string]bool
	mu             sync.RWMutex
}

// NewAuthRateLimiter creates a new tiered rate limiter for authentication endpoints.
// If redisLimiter is nil, an in-memory fallback store is used instead.
// Call Stop() to release resources when the rate limiter is no longer needed.
func NewAuthRateLimiter(config AuthRateLimiterConfig, redisLimiter *pkgredis.RateLimiter) *AuthRateLimiter {
	return &AuthRateLimiter{
		config:         config,
		redisLimiter:   redisLimiter,
		fallbackStore:  newInMemoryTieredStore(),
		trustedProxies: make(map[string]bool),
	}
}

// Stop releases resources held by the rate limiter, including cleanup goroutines.
func (rl *AuthRateLimiter) Stop() {
	if rl.fallbackStore != nil {
		rl.fallbackStore.Stop()
	}
}

// SetTrustedProxies configures the list of trusted proxy IPs for secure
// client IP extraction. Only IPs in this list are trusted for X-Forwarded-For.
func (rl *AuthRateLimiter) SetTrustedProxies(proxies []string) {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	newProxies := make(map[string]bool, len(proxies))
	for _, proxy := range proxies {
		ip := proxy
		if host, _, err := net.SplitHostPort(proxy); err == nil {
			ip = host
		}
		newProxies[ip] = true
	}
	rl.trustedProxies = newProxies
}

// Middleware returns a Gin middleware handler that enforces tiered rate limiting.
// It checks all three tiers (per-IP, per-account, global) and rejects the request
// if any tier is exceeded. The most restrictive tier takes precedence.
func (rl *AuthRateLimiter) Middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		clientIP := rl.extractClientIP(c)
		accountID := rl.extractAccountIdentifier(c)
		endpoint := c.Request.URL.Path

		denial, err := rl.checkAllTiers(c.Request.Context(), clientIP, accountID, endpoint)
		if err != nil {
			logger.Log.Error("Rate limiter check failed - denying request (fail-closed for auth security)",
				zap.Error(err),
				zap.String("client_ip", clientIP),
				zap.String("endpoint", endpoint),
			)
			c.AbortWithStatusJSON(http.StatusServiceUnavailable, gin.H{
				"error":   "Service temporarily unavailable",
				"message": "Please try again in a few moments.",
			})
			return
		}

		if denial != nil {
			retryAfterSec := int64(denial.RetryAfter.Seconds())
			if retryAfterSec < 1 {
				retryAfterSec = 1
			}

			c.Header("Retry-After", strconv.FormatInt(retryAfterSec, 10))
			c.Header("X-RateLimit-Remaining", "0")
			c.Header("X-RateLimit-Reset", strconv.FormatInt(denial.ResetAt.Unix(), 10))
			c.Header("X-RateLimit-Tier", string(denial.Tier))

			logger.Log.Warn("Auth rate limit exceeded",
				zap.String("tier", string(denial.Tier)),
				zap.String("client_ip", clientIP),
				zap.String("account", accountID),
				zap.String("endpoint", endpoint),
				zap.Duration("retry_after", denial.RetryAfter),
			)

			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{
				"error":       "Too many requests",
				"tier":        string(denial.Tier),
				"retry_after": retryAfterSec,
				"message":     rateLimitMessage(denial.Tier),
			})
			return
		}

		c.Next()
	}
}

// checkAllTiers evaluates all three rate limit tiers and returns a denial
// if any tier is exceeded. Returns nil if the request is allowed.
//
// Per-tier sizing: when config.EndpointOverrides has an entry for the
// normalized endpoint name, those tier configs are consulted instead of
// the global PerIP/PerAccount defaults. Missing tier in the override
// (zero MaxRequests) falls back to the global default for that tier.
// Global tier is never overridden — its purpose is a system-wide DDoS
// guard that intentionally crosses all endpoints.
func (rl *AuthRateLimiter) checkAllTiers(ctx context.Context, clientIP, accountID, endpoint string) (*rateLimitDenial, error) {
	endpointKey := normalizeEndpoint(endpoint)
	perIPCfg := rl.config.PerIP
	perAccountCfg := rl.config.PerAccount
	if override, ok := rl.config.EndpointOverrides[endpointKey]; ok {
		if override.PerIP.MaxRequests > 0 {
			perIPCfg = override.PerIP
		}
		if override.PerAccount.MaxRequests > 0 {
			perAccountCfg = override.PerAccount
		}
	}

	// Tier 1: Global rate limit (checked first for efficiency under DDoS)
	globalKey := fmt.Sprintf("auth:global:%s", endpointKey)
	globalDenial, err := rl.checkTier(ctx, globalKey, rl.config.Global, TierGlobal)
	if err != nil {
		return nil, fmt.Errorf("global tier check failed: %w", err)
	}
	if globalDenial != nil {
		return globalDenial, nil
	}

	// Tier 2: Per-IP rate limit
	ipKey := fmt.Sprintf("auth:ip:%s:%s", clientIP, endpointKey)
	ipDenial, err := rl.checkTier(ctx, ipKey, perIPCfg, TierPerIP)
	if err != nil {
		return nil, fmt.Errorf("per-IP tier check failed: %w", err)
	}
	if ipDenial != nil {
		return ipDenial, nil
	}

	// Tier 3: Per-Account rate limit (only if account identifier is available)
	if accountID != "" {
		accountKey := fmt.Sprintf("auth:account:%s:%s", accountID, endpointKey)
		accountDenial, err := rl.checkTier(ctx, accountKey, perAccountCfg, TierPerAccount)
		if err != nil {
			return nil, fmt.Errorf("per-account tier check failed: %w", err)
		}
		if accountDenial != nil {
			return accountDenial, nil
		}
	}

	return nil, nil
}

// checkTier evaluates a single rate limit tier using Redis or in-memory fallback.
func (rl *AuthRateLimiter) checkTier(ctx context.Context, key string, tierCfg TierConfig, tier RateLimitTier) (*rateLimitDenial, error) {
	if rl.redisLimiter != nil {
		return rl.checkTierRedis(ctx, key, tierCfg, tier)
	}
	return rl.checkTierInMemory(key, tierCfg, tier), nil
}

// checkTierRedis evaluates a rate limit tier using the Redis sliding window limiter.
func (rl *AuthRateLimiter) checkTierRedis(ctx context.Context, key string, tierCfg TierConfig, tier RateLimitTier) (*rateLimitDenial, error) {
	result, err := rl.redisLimiter.Check(ctx, key, tierCfg.MaxRequests, tierCfg.Window, tierCfg.BlockDuration)
	if err != nil {
		return nil, fmt.Errorf("redis rate limit check for tier %s failed: %w", tier, err)
	}

	if !result.Allowed {
		return &rateLimitDenial{
			Tier:       tier,
			RetryAfter: result.RetryAfter,
			ResetAt:    result.ResetAt,
		}, nil
	}

	return nil, nil
}

// checkTierInMemory evaluates a rate limit tier using the in-memory fallback store.
func (rl *AuthRateLimiter) checkTierInMemory(key string, tierCfg TierConfig, tier RateLimitTier) *rateLimitDenial {
	now := time.Now()
	entry := rl.fallbackStore.getOrCreate(key)

	entry.mu.Lock()
	defer entry.mu.Unlock()

	// Check if currently blocked
	if entry.blockedUntil.After(now) {
		return &rateLimitDenial{
			Tier:       tier,
			RetryAfter: time.Until(entry.blockedUntil),
			ResetAt:    entry.blockedUntil,
		}
	}

	// Clean expired requests using immutable slice replacement
	windowStart := now.Add(-tierCfg.Window)
	validRequests := make([]time.Time, 0, len(entry.requests))
	for _, req := range entry.requests {
		if req.After(windowStart) {
			validRequests = append(validRequests, req)
		}
	}
	entry.requests = validRequests

	// Check if over limit
	if len(entry.requests) >= tierCfg.MaxRequests {
		entry.blockedUntil = now.Add(tierCfg.BlockDuration)
		return &rateLimitDenial{
			Tier:       tier,
			RetryAfter: tierCfg.BlockDuration,
			ResetAt:    entry.blockedUntil,
		}
	}

	// Record this request
	entry.requests = append(entry.requests, now)
	return nil
}

// extractClientIP securely extracts the real client IP address using trusted proxy validation.
func (rl *AuthRateLimiter) extractClientIP(c *gin.Context) string {
	rl.mu.RLock()
	proxies := rl.trustedProxies
	rl.mu.RUnlock()

	remoteAddr := c.Request.RemoteAddr
	if host, _, err := net.SplitHostPort(remoteAddr); err == nil {
		remoteAddr = host
	}

	if len(proxies) == 0 {
		return remoteAddr
	}

	if !proxies[remoteAddr] {
		return remoteAddr
	}

	forwardedFor := c.GetHeader("X-Forwarded-For")
	if forwardedFor == "" {
		return remoteAddr
	}

	ips := strings.Split(forwardedFor, ",")
	for i := len(ips) - 1; i >= 0; i-- {
		ip := strings.TrimSpace(ips[i])
		if ip == "" {
			continue
		}
		if host, _, err := net.SplitHostPort(ip); err == nil {
			ip = host
		}
		if !proxies[ip] {
			return ip
		}
	}

	return remoteAddr
}

// extractAccountIdentifier attempts to extract an account identifier from the request.
// This is used for per-account rate limiting to prevent credential stuffing.
// It reads from common JSON body fields without consuming the body.
func (rl *AuthRateLimiter) extractAccountIdentifier(c *gin.Context) string {
	// Try to extract from form data (does not consume body for JSON)
	if email := c.PostForm("email"); email != "" {
		return strings.ToLower(email)
	}
	if username := c.PostForm("username"); username != "" {
		return strings.ToLower(username)
	}

	// Try query parameters for endpoints like magic-link verification
	if email := c.Query("email"); email != "" {
		return strings.ToLower(email)
	}

	// For JSON bodies, we peek at the body without consuming it.
	// Gin's ShouldBindBodyWith or reading c.GetRawData would consume it,
	// so we use a lightweight approach: check if the content type is JSON
	// and if the body has already been parsed by a prior middleware.
	// The account identifier is best-effort; if unavailable, per-IP still applies.
	return ""
}

// rateLimitMessage returns a user-friendly message based on the rate limit tier.
func rateLimitMessage(tier RateLimitTier) string {
	switch tier {
	case TierPerIP:
		return "Too many authentication attempts from this IP address. Please wait before trying again."
	case TierPerAccount:
		return "Too many authentication attempts for this account. Please wait before trying again."
	case TierGlobal:
		return "Authentication service is experiencing high demand. Please try again shortly."
	default:
		return "Rate limit exceeded. Please try again later."
	}
}

// normalizeEndpoint normalizes an endpoint path into a stable key for rate limiting.
// This groups similar endpoints together so an attacker can't spread credential-
// stuffing attempts across sibling endpoints to defeat the limit (the original
// motivation for the auth_mfa lump).
//
// 2026-05-19 update: split the MFA bucket into two by abuse profile, so already-
// authenticated users managing their MFA factors via accounts.hexxlock.com don't
// trip the brute-force budget designed for /mfa/verify. Industry pattern (Auth0
// "Management API" vs "Authentication API" tiers; Okta "User Lifecycle" vs
// "Authentication" buckets): credential-checking surfaces get strict limits,
// post-auth management actions get a relaxed sibling. The defense-in-depth on
// the management endpoints stays — RequireAuth + RequireFreshAuth(5min) (RFC
// 9470) is the proper auth-time gate; the rate limit just bounds rapid abuse.
//
// Buckets emitted by this normalizer:
//
//	auth_mfa_credential  — code-verifying surfaces, brute-force-prone:
//	    /auth/mfa/verify, /auth/mfa/send-code, /auth/mfa/complete,
//	    /auth/mfa/step-up/verify, /auth/mfa/enrollment/verify,
//	    /auth/mfa/setup/totp/verify
//	auth_mfa_mgmt        — post-auth user actions, NOT brute-force-prone:
//	    /auth/mfa/setup/* (excluding /verify), /auth/mfa/disable/*,
//	    /auth/mfa/backup-codes (POST), /auth/mfa/enrollment/* (init/skip),
//	    /auth/mfa/methods, /auth/mfa/switch-method, etc.
//
// Both default to TierConfig{} for downstream sizing — the credential bucket
// retains the 5/min/IP strict limit; the mgmt bucket should be sized for normal
// account-management cadence (e.g. 20/min/IP). Per-tier overrides land in
// DefaultAuthRateLimiterConfig.
func normalizeEndpoint(path string) string {
	// Remove version prefixes
	normalized := strings.TrimPrefix(path, "/api/v1")
	normalized = strings.TrimPrefix(normalized, "/api")

	// Split MFA into credential-checking vs post-auth management.
	// Credential paths are listed explicitly (small set, easy to audit).
	// Anything else under /auth/mfa is treated as management.
	if strings.HasPrefix(normalized, "/auth/mfa") {
		if isMFACredentialPath(normalized) {
			return "auth_mfa_credential"
		}
		return "auth_mfa_mgmt"
	}

	// Group signup sub-endpoints together (initiate / verify-email /
	// complete). Signup is a 3-call flow with discrete pending-request
	// state between calls; bucketing them under one endpoint key keeps
	// the abuse budget shared across the flow so 5/min/IP means 5
	// signup ATTEMPTS, not 15 sub-calls.
	if strings.HasPrefix(normalized, "/auth/signup") {
		return "auth_signup"
	}

	// Group magic-link sub-endpoints together
	if strings.HasPrefix(normalized, "/auth/magic-link") {
		return "auth_magic_link"
	}

	// Group password sub-endpoints together
	if strings.HasPrefix(normalized, "/auth/password") {
		return "auth_password"
	}

	// Map specific endpoints
	switch normalized {
	case "/auth/login":
		return "auth_login"
	case "/auth/register":
		return "auth_register"
	default:
		// Fallback: replace slashes with underscores, trim leading underscore
		result := strings.ReplaceAll(strings.TrimPrefix(normalized, "/"), "/", "_")
		if result == "" {
			return "unknown"
		}
		return result
	}
}

// isMFACredentialPath returns true for /auth/mfa/* paths that accept or send
// a one-time credential (TOTP code, email/SMS code) and are therefore
// brute-force-prone. These belong in the strict `auth_mfa_credential` bucket.
//
// Everything else under /auth/mfa (setup, disable, backup-code regenerate,
// enrollment-init, switch-method, methods listing, ...) is post-auth user
// management — relaxed via the `auth_mfa_mgmt` bucket.
//
// Listed explicitly (not regex-derived) so an audit of which endpoints get
// which protection is a single grep. Adding a new credential-checking
// endpoint requires explicit addition here.
func isMFACredentialPath(p string) bool {
	switch p {
	case "/auth/mfa/verify",
		"/auth/mfa/send-code",
		"/auth/mfa/complete",
		"/auth/mfa/step-up/verify",
		"/auth/mfa/enrollment/verify",
		"/auth/mfa/setup/totp/verify",
		"/auth/mfa/enrollment/webauthn/finish":
		return true
	}
	return false
}

// inMemoryTieredStore provides an in-memory rate limit store for use when Redis
// is unavailable. It uses an LRU eviction strategy to bound memory usage.
type inMemoryTieredStore struct {
	mu         sync.Mutex
	entries    map[string]*tieredEntry
	maxEntries int
	stopCh     chan struct{}
	stopOnce   sync.Once
}

// tieredEntry tracks rate limit state for a single key in the in-memory store.
type tieredEntry struct {
	mu           sync.Mutex
	requests     []time.Time
	blockedUntil time.Time
	lastAccess   time.Time
}

// newInMemoryTieredStore creates a new in-memory store with periodic cleanup.
// Call Stop() to terminate the cleanup goroutine when the store is no longer needed.
func newInMemoryTieredStore() *inMemoryTieredStore {
	store := &inMemoryTieredStore{
		entries:    make(map[string]*tieredEntry),
		maxEntries: 50000,
		stopCh:     make(chan struct{}),
	}

	go store.cleanupLoop()

	return store
}

// Stop terminates the cleanup goroutine.
func (s *inMemoryTieredStore) Stop() {
	s.stopOnce.Do(func() { close(s.stopCh) })
}

// getOrCreate retrieves or creates an entry for the given key.
func (s *inMemoryTieredStore) getOrCreate(key string) *tieredEntry {
	s.mu.Lock()
	defer s.mu.Unlock()

	if entry, exists := s.entries[key]; exists {
		entry.mu.Lock()
		entry.lastAccess = time.Now()
		entry.mu.Unlock()
		return entry
	}

	// Evict oldest entries if at capacity
	if len(s.entries) >= s.maxEntries {
		s.evictOldest()
	}

	entry := &tieredEntry{
		requests:   make([]time.Time, 0),
		lastAccess: time.Now(),
	}
	s.entries[key] = entry
	return entry
}

// evictOldest removes the entry with the oldest last access time.
// Must be called with s.mu held.
func (s *inMemoryTieredStore) evictOldest() {
	var oldestKey string
	var oldestTime time.Time

	for key, entry := range s.entries {
		entry.mu.Lock()
		access := entry.lastAccess
		entry.mu.Unlock()
		if oldestKey == "" || access.Before(oldestTime) {
			oldestKey = key
			oldestTime = access
		}
	}

	if oldestKey != "" {
		delete(s.entries, oldestKey)
	}
}

// cleanupLoop periodically removes expired entries from the store.
// It exits when stopCh is closed via Stop().
func (s *inMemoryTieredStore) cleanupLoop() {
	ticker := time.NewTicker(3 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			s.cleanup()
		case <-s.stopCh:
			return
		}
	}
}

// cleanup removes entries that have not been accessed recently and are not blocked.
func (s *inMemoryTieredStore) cleanup() {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-30 * time.Minute)

	for key, entry := range s.entries {
		entry.mu.Lock()
		shouldDelete := entry.lastAccess.Before(cutoff) &&
			entry.blockedUntil.Before(now)
		entry.mu.Unlock()

		if shouldDelete {
			delete(s.entries, key)
		}
	}
}
