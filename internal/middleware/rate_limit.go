// SPDX-License-Identifier: AGPL-3.0-or-later

package middleware

import (
	"container/list"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/services"
	"github.com/dogukanturhal/falcon-id/pkg/logger"
)

// AuthRateLimitConfig defines hardcoded rate limits for critical auth endpoints
// These are security baselines that apply regardless of database rules
type AuthRateLimitConfig struct {
	MaxRequests   int
	WindowSeconds int
	BlockDuration time.Duration
}

// authEndpointLimits defines strict rate limits for authentication endpoints
// These protect against brute-force attacks even if no database rules exist
// SECURITY: Strict rate limits for authentication endpoints to prevent brute-force attacks.
var authEndpointLimits = map[string]AuthRateLimitConfig{
	"/api/auth/login":              {MaxRequests: 15, WindowSeconds: 60, BlockDuration: 5 * time.Minute},  // 15 attempts per minute
	"/api/auth/password/forgot":    {MaxRequests: 5, WindowSeconds: 300, BlockDuration: 5 * time.Minute},  // 5 per 5 min
	"/api/auth/password/reset":     {MaxRequests: 5, WindowSeconds: 300, BlockDuration: 5 * time.Minute},  // 5 per 5 min
	"/api/auth/refresh":            {MaxRequests: 30, WindowSeconds: 60, BlockDuration: 1 * time.Minute},  // 30 per minute
	"/api/auth/magic-link/request": {MaxRequests: 5, WindowSeconds: 300, BlockDuration: 5 * time.Minute},  // 5 per 5 min
	"/api/auth/mfa/send-code":      {MaxRequests: 5, WindowSeconds: 300, BlockDuration: 5 * time.Minute},  // 5 per 5 min
	"/api/auth/mfa/verify":         {MaxRequests: 5, WindowSeconds: 300, BlockDuration: 10 * time.Minute}, // 5 per 5 min, 10 min block (brute-force protection)
	"/api/auth/mfa/complete":       {MaxRequests: 5, WindowSeconds: 300, BlockDuration: 10 * time.Minute}, // 5 per 5 min, 10 min block (brute-force protection)
	"/saml/sp/":                    {MaxRequests: 30, WindowSeconds: 60, BlockDuration: 2 * time.Minute},  // 30 per minute (SAML SLO/ACS)
}

// authRateLimitEntry tracks requests for a specific IP+endpoint
type authRateLimitEntry struct {
	requests     []time.Time
	blockedUntil time.Time
	mu           sync.Mutex
}

// lruEntry wraps a rate limit entry with LRU tracking
type lruEntry struct {
	key   string
	value *authRateLimitEntry
	elem  *list.Element
}

// authRateLimitStore is a thread-safe LRU store for auth rate limiting
type rateLimitStore struct {
	mu         sync.Mutex
	store      map[string]*lruEntry
	lruList    *list.List
	maxEntries int
	entryCount int
}

// authRateLimitStore is the global rate limiting store with LRU eviction
var authRateLimitStore = &rateLimitStore{
	store:      make(map[string]*lruEntry),
	lruList:    list.New(),
	maxEntries: 100000, // Maximum 100k entries to prevent memory exhaustion
}

// LoadOrStore loads an existing entry or creates a new one with LRU eviction
func (s *rateLimitStore) LoadOrStore(key string, value *authRateLimitEntry) (*authRateLimitEntry, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Check if entry exists
	if entry, exists := s.store[key]; exists {
		// Move to front (most recently used)
		s.lruList.MoveToFront(entry.elem)
		return entry.value, true
	}

	// Check if we need to evict (LRU)
	if s.entryCount >= s.maxEntries {
		// Remove least recently used entry
		oldest := s.lruList.Back()
		if oldest != nil {
			oldestEntry := oldest.Value.(*lruEntry)
			delete(s.store, oldestEntry.key)
			s.lruList.Remove(oldest)
			s.entryCount--
		}
	}

	// Create new entry — single struct shared by list and map
	newEntry := &lruEntry{
		key:   key,
		value: value,
	}
	elem := s.lruList.PushFront(newEntry)
	newEntry.elem = elem
	s.store[key] = newEntry
	s.entryCount++

	return value, false
}

// Delete removes an entry from the store
func (s *rateLimitStore) Delete(key string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if entry, exists := s.store[key]; exists {
		delete(s.store, key)
		s.lruList.Remove(entry.elem)
		s.entryCount--
	}
}

// Range iterates over all entries in the store
func (s *rateLimitStore) Range(f func(key string, value *authRateLimitEntry) bool) {
	s.mu.Lock()
	entries := make(map[string]*authRateLimitEntry, len(s.store))
	for k, v := range s.store {
		entries[k] = v.value
	}
	s.mu.Unlock()

	for k, v := range entries {
		if !f(k, v) {
			break
		}
	}
}

// GetEntryCount returns the current number of entries (for monitoring)
func (s *rateLimitStore) GetEntryCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.entryCount
}

// RateLimitMiddleware creates a rate limiting middleware
type RateLimitMiddleware struct {
	service        *services.RateLimitService
	trustedProxies map[string]bool // Map of trusted proxy IPs for fast lookup
}

// NewRateLimitMiddleware creates a new rate limit middleware
func NewRateLimitMiddleware(service *services.RateLimitService) *RateLimitMiddleware {
	return &RateLimitMiddleware{
		service:        service,
		trustedProxies: make(map[string]bool),
	}
}

// SetTrustedProxies sets the list of trusted proxy IPs
// SECURITY: Only IPs in this list are trusted for X-Forwarded-For headers
// FIX: Properly handles both IPv4 and IPv6 addresses using net.SplitHostPort
func (m *RateLimitMiddleware) SetTrustedProxies(proxies []string) {
	m.trustedProxies = make(map[string]bool)
	for _, proxy := range proxies {
		// Normalize IP addresses (remove port if present)
		// Use net.SplitHostPort to handle both IPv4 and IPv6 correctly
		ip := proxy
		if host, _, err := net.SplitHostPort(proxy); err == nil {
			ip = host
		}
		// If SplitHostPort fails, it's likely an IP without port - use as-is
		m.trustedProxies[ip] = true
	}
}

// RateLimit returns a middleware handler that applies rate limiting
func (m *RateLimitMiddleware) RateLimit() gin.HandlerFunc {
	return func(c *gin.Context) {
		if blocked := m.enforceAuthRateLimit(c); blocked {
			return
		}

		tenantID := extractTenantIDFromContext(c)
		identifier := m.resolveIdentifier(c)
		endpoint := c.Request.URL.Path
		method := c.Request.Method

		state, err := m.service.CheckRateLimit(c.Request.Context(), tenantID, identifier, endpoint, method)
		if err != nil {
			logger.Log.Warn("General rate limit check failed, allowing request (fail-open)",
				zap.Error(err),
				zap.String("identifier", identifier),
				zap.String("endpoint", endpoint),
				zap.String("method", method),
			)
			c.Next()
			return
		}

		if state == nil {
			c.Next()
			return
		}

		c.Header("X-RateLimit-Limit", strconv.Itoa(state.Requests+state.Remaining))
		c.Header("X-RateLimit-Remaining", strconv.Itoa(state.Remaining))
		c.Header("X-RateLimit-Reset", strconv.FormatInt(state.ResetAt.Unix(), 10))

		if state.Blocked {
			c.Header("Retry-After", strconv.FormatInt(int64(state.BlockedUntil.Sub(state.WindowEnd).Seconds()), 10))
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{
				"error":       "Too many requests",
				"retry_after": state.BlockedUntil.Unix(),
				"message":     "Rate limit exceeded. Please try again later.",
			})
			return
		}

		c.Next()
	}
}

// enforceAuthRateLimit checks the hardcoded auth endpoint limits and sets headers.
// Returns true if the request was blocked.
func (m *RateLimitMiddleware) enforceAuthRateLimit(c *gin.Context) bool {
	blocked, remaining, resetAt := m.checkAuthRateLimit(c)
	if blocked {
		c.Header("X-RateLimit-Remaining", "0")
		c.Header("X-RateLimit-Reset", strconv.FormatInt(resetAt.Unix(), 10))
		c.Header("Retry-After", strconv.FormatInt(int64(time.Until(resetAt).Seconds()), 10))
		c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{
			"error":       "Too many requests",
			"retry_after": resetAt.Unix(),
			"message":     "Rate limit exceeded for authentication endpoint. Please try again later.",
		})
		return true
	}
	if remaining >= 0 {
		c.Header("X-RateLimit-Remaining", strconv.Itoa(remaining))
		c.Header("X-RateLimit-Reset", strconv.FormatInt(resetAt.Unix(), 10))
	}
	return false
}

// extractTenantIDFromContext parses a tenant UUID from the Gin context (uuid.UUID or string).
func extractTenantIDFromContext(c *gin.Context) uuid.UUID {
	tenantIDVal, exists := c.Get("tenant_id")
	if !exists {
		return uuid.Nil
	}
	switch v := tenantIDVal.(type) {
	case uuid.UUID:
		return v
	case string:
		if parsed, err := uuid.Parse(v); err == nil {
			return parsed
		}
	}
	return uuid.Nil
}

// resolveIdentifier returns the user ID if authenticated, otherwise the client IP.
func (m *RateLimitMiddleware) resolveIdentifier(c *gin.Context) string {
	if userID, exists := c.Get("user_id"); exists {
		if uid, ok := userID.(uuid.UUID); ok {
			return uid.String()
		}
	}
	return m.getClientIP(c)
}

// getClientIP safely extracts the real client IP address with trusted proxy validation
// SECURITY: This prevents X-Forwarded-For header spoofing
// FIX: Properly handles both IPv4 and IPv6 addresses using net.SplitHostPort
func (m *RateLimitMiddleware) getClientIP(c *gin.Context) string {
	// Get the immediate connection IP (RemoteAddr)
	// SECURITY: Use net.SplitHostPort to correctly handle both IPv4 and IPv6
	// IPv4: "192.168.1.1:8080" -> "192.168.1.1"
	// IPv6: "[::1]:8080" -> "::1"
	remoteAddr := c.Request.RemoteAddr
	if host, _, err := net.SplitHostPort(remoteAddr); err == nil {
		remoteAddr = host
	}
	// If SplitHostPort fails, it might be an IP without port - use as-is

	// If we have no trusted proxies configured, always use RemoteAddr
	if len(m.trustedProxies) == 0 {
		return remoteAddr
	}

	// Check if the immediate connection is from a trusted proxy
	if !m.trustedProxies[remoteAddr] {
		// Not from a trusted proxy, use RemoteAddr directly
		return remoteAddr
	}

	// SECURITY: Parse X-Forwarded-For correctly
	// The rightmost IP that is NOT in the trusted proxy list is the real client IP
	// Format: "client-ip, proxy1-ip, proxy2-ip"
	forwardedFor := c.GetHeader("X-Forwarded-For")
	if forwardedFor == "" {
		// No X-Forwarded-For header, fall back to RemoteAddr
		return remoteAddr
	}

	// Split and trim IPs
	ips := strings.Split(forwardedFor, ",")
	for i := len(ips) - 1; i >= 0; i-- {
		ip := strings.TrimSpace(ips[i])
		// Skip empty or invalid IPs
		if ip == "" {
			continue
		}
		// SECURITY: Use net.SplitHostPort to handle both IPv4 and IPv6
		// IPv6 addresses in X-Forwarded-For are typically without brackets
		// but may have port in format "::1:8080" (ambiguous) or "[::1]:8080"
		if host, _, err := net.SplitHostPort(ip); err == nil {
			ip = host
		}
		// If SplitHostPort fails, treat as IP without port

		// Return the first IP from the right that is NOT a trusted proxy
		if !m.trustedProxies[ip] {
			return ip
		}
	}

	// All IPs in X-Forwarded-For are trusted proxies, use RemoteAddr
	return remoteAddr
}

// checkAuthRateLimit checks hardcoded rate limits for critical auth endpoints
// Returns: blocked bool, remaining int, resetAt time.Time
// If remaining is -1, no auth rate limit applies to this endpoint
func (m *RateLimitMiddleware) checkAuthRateLimit(c *gin.Context) (bool, int, time.Time) {
	path := c.Request.URL.Path

	// Check if this endpoint has hardcoded rate limits
	var config AuthRateLimitConfig
	var found bool
	for pattern, cfg := range authEndpointLimits {
		if strings.HasPrefix(path, pattern) || path == pattern {
			config = cfg
			found = true
			break
		}
	}

	if !found {
		return false, -1, time.Time{}
	}

	// SECURITY: Use secure client IP extraction with trusted proxy validation
	clientIP := m.getClientIP(c)
	key := "auth:" + clientIP + ":" + path

	now := time.Now()
	windowStart := now.Add(-time.Duration(config.WindowSeconds) * time.Second)

	// Get or create entry
	entry, _ := authRateLimitStore.LoadOrStore(key, &authRateLimitEntry{
		requests: make([]time.Time, 0),
	})

	entry.mu.Lock()
	defer entry.mu.Unlock()

	// Check if currently blocked
	if entry.blockedUntil.After(now) {
		return true, 0, entry.blockedUntil
	}

	// Clean up old requests outside the window
	validRequests := make([]time.Time, 0)
	for _, req := range entry.requests {
		if req.After(windowStart) {
			validRequests = append(validRequests, req)
		}
	}
	entry.requests = validRequests

	// Check if over limit
	if len(entry.requests) >= config.MaxRequests {
		entry.blockedUntil = now.Add(config.BlockDuration)
		return true, 0, entry.blockedUntil
	}

	// Add current request
	entry.requests = append(entry.requests, now)
	remaining := config.MaxRequests - len(entry.requests)
	resetAt := windowStart.Add(time.Duration(config.WindowSeconds) * time.Second)

	return false, remaining, resetAt
}

// refreshRateLimiterConfig defines the per-IP sliding-window limits for /auth/refresh.
var refreshRateLimiterConfig = AuthRateLimitConfig{
	MaxRequests:   30,
	WindowSeconds: 3600, // 1 hour
	BlockDuration: 10 * time.Minute,
}

// refreshBurstConfig defines a tighter burst window to catch rapid hammering.
var refreshBurstConfig = AuthRateLimitConfig{
	MaxRequests:   10,
	WindowSeconds: 60, // 1 minute burst window
	BlockDuration: 10 * time.Minute,
}

// NewRefreshRateLimiter returns a Gin middleware that enforces per-IP rate limits on the
// token refresh endpoint. It uses the shared in-memory LRU store so it is safe to use even
// when Redis is unavailable. Limits:
//   - 10 requests per minute per IP (burst protection)
//   - 30 requests per hour per IP (sustained protection)
//
// Both windows share the 10-minute block duration. The middleware sets standard
// Retry-After and X-RateLimit-* headers on rejection.
func NewRefreshRateLimiter() gin.HandlerFunc {
	return func(c *gin.Context) {
		remoteAddr := c.Request.RemoteAddr
		if host, _, err := net.SplitHostPort(remoteAddr); err == nil {
			remoteAddr = host
		}

		now := time.Now()

		burstRemaining, burstBlocked := checkAndRecordSlidingWindow("refresh_burst:"+remoteAddr, now, refreshBurstConfig)
		if burstBlocked {
			abortRefreshRateLimited(c, refreshBurstConfig.BlockDuration)
			return
		}

		hourlyRemaining, hourlyBlocked := checkAndRecordSlidingWindow("refresh_hourly:"+remoteAddr, now, refreshRateLimiterConfig)
		if hourlyBlocked {
			abortRefreshRateLimited(c, refreshRateLimiterConfig.BlockDuration)
			return
		}

		remaining := burstRemaining
		if hourlyRemaining < remaining {
			remaining = hourlyRemaining
		}
		c.Header("X-RateLimit-Remaining", strconv.Itoa(remaining))

		c.Next()
	}
}

// checkAndRecordSlidingWindow checks the sliding window for a key, records the current request,
// and returns (remaining, blocked). The entry is mutated in place under its own mutex.
func checkAndRecordSlidingWindow(key string, now time.Time, cfg AuthRateLimitConfig) (remaining int, blocked bool) {
	windowStart := now.Add(-time.Duration(cfg.WindowSeconds) * time.Second)

	entry, _ := authRateLimitStore.LoadOrStore(key, &authRateLimitEntry{requests: make([]time.Time, 0)})
	entry.mu.Lock()
	defer entry.mu.Unlock()

	if entry.blockedUntil.After(now) {
		return 0, true
	}

	valid := make([]time.Time, 0, len(entry.requests))
	for _, t := range entry.requests {
		if t.After(windowStart) {
			valid = append(valid, t)
		}
	}
	entry.requests = valid

	if len(entry.requests) >= cfg.MaxRequests {
		entry.blockedUntil = now.Add(cfg.BlockDuration)
		return 0, true
	}

	entry.requests = append(entry.requests, now)
	return cfg.MaxRequests - len(entry.requests), false
}

// abortRefreshRateLimited responds with 429 and standard rate-limit headers.
func abortRefreshRateLimited(c *gin.Context, blockDuration time.Duration) {
	retryAfter := int64(blockDuration.Seconds())
	if retryAfter < 1 {
		retryAfter = 1
	}
	c.Header("Retry-After", strconv.FormatInt(retryAfter, 10))
	c.Header("X-RateLimit-Remaining", "0")
	c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{
		"error":       "Too many refresh attempts",
		"retry_after": retryAfter,
		"message":     "Token refresh rate limit exceeded. Please wait before trying again.",
	})
}

// AdminMutationRateLimit returns rate limiting middleware for admin mutation endpoints.
// Uses a stricter limit (30 req/min per user) to prevent privilege escalation automation.
// Fails open on errors so that a degraded store does not lock out legitimate admins.
func AdminMutationRateLimit() gin.HandlerFunc {
	const (
		maxRequests   = 30
		windowSeconds = 60
	)

	return func(c *gin.Context) {
		userID := GetCurrentUserID(c)
		if userID == nil {
			c.Next()
			return
		}

		key := "admin_mutation:" + userID.String()

		now := time.Now()
		windowStart := now.Add(-windowSeconds * time.Second)

		entry, _ := authRateLimitStore.LoadOrStore(key, &authRateLimitEntry{
			requests: make([]time.Time, 0),
		})

		entry.mu.Lock()
		defer entry.mu.Unlock()

		// Clean up requests outside the sliding window
		validRequests := make([]time.Time, 0, len(entry.requests))
		for _, req := range entry.requests {
			if req.After(windowStart) {
				validRequests = append(validRequests, req)
			}
		}
		entry.requests = validRequests

		if len(entry.requests) >= maxRequests {
			c.JSON(http.StatusTooManyRequests, gin.H{
				"error": "admin mutation rate limit exceeded, try again later",
			})
			c.Abort()
			return
		}

		entry.requests = append(entry.requests, now)
		c.Next()
	}
}

// authRateLimitCleanupStopCh is used to stop the auth rate limit cleanup goroutine.
var (
	authRateLimitCleanupStopCh   = make(chan struct{})
	authRateLimitCleanupStopOnce sync.Once
)

// StopAuthRateLimitCleanup stops the background auth rate limit cleanup goroutine.
// Safe to call multiple times.
func StopAuthRateLimitCleanup() {
	authRateLimitCleanupStopOnce.Do(func() { close(authRateLimitCleanupStopCh) })
}

// cleanupAuthRateLimitStore periodically cleans up old auth rate limit entries
// Call StopAuthRateLimitCleanup() during shutdown to stop it.
func init() {
	go runAuthRateLimitCleanup()
}

func runAuthRateLimitCleanup() {
	ticker := time.NewTicker(2 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			now := time.Now()
			cutoff := now.Add(-30 * time.Minute)
			var toDelete []string

			authRateLimitStore.Range(func(key string, entry *authRateLimitEntry) bool {
				if shouldDeleteEntry(entry, now, cutoff) {
					toDelete = append(toDelete, key)
				}
				return true
			})

			for _, key := range toDelete {
				authRateLimitStore.Delete(key)
			}
		case <-authRateLimitCleanupStopCh:
			return
		}
	}
}

// shouldDeleteEntry returns true when the entry has no pending state and its last request is older than cutoff.
func shouldDeleteEntry(entry *authRateLimitEntry, now, cutoff time.Time) bool {
	entry.mu.Lock()
	defer entry.mu.Unlock()

	if len(entry.requests) == 0 && entry.blockedUntil.Before(now) {
		return true
	}
	if len(entry.requests) > 0 && entry.requests[len(entry.requests)-1].Before(cutoff) {
		return true
	}
	return false
}
