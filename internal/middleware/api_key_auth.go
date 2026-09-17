// SPDX-License-Identifier: AGPL-3.0-or-later

package middleware

import (
	"context"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/internal/services"
)

// APIKeyAuthMiddleware handles API key authentication
type APIKeyAuthMiddleware struct {
	apiKeyService *services.APIKeyService
}

// NewAPIKeyAuthMiddleware creates a new API key auth middleware
func NewAPIKeyAuthMiddleware(apiKeyService *services.APIKeyService) *APIKeyAuthMiddleware {
	return &APIKeyAuthMiddleware{
		apiKeyService: apiKeyService,
	}
}

// APIKeyAuth returns a middleware that authenticates requests using API keys
// The API key can be provided in:
// - X-API-Key header
// - Authorization header with "Bearer" or "ApiKey" prefix
func (m *APIKeyAuthMiddleware) APIKeyAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		// SECURITY: Only skip API key validation if InternalAuthMiddleware has already
		// validated the request using a constant-time comparison of X-Internal-Key.
		// Never trust X-Service-Name header alone — any external client can spoof it.
		if isInternal, exists := c.Get("is_internal_service"); exists {
			if val, ok := isInternal.(bool); ok && val {
				c.Next()
				return
			}
		}

		apiKey := m.extractAPIKey(c)
		if apiKey == "" {
			c.Next()
			return
		}

		key, ok := m.validateAndAuthorizeAPIKey(c, apiKey)
		if !ok {
			return
		}

		startTime := time.Now()
		setAPIKeyContext(c, key)

		// Usage records the real client public IP — what the API key
		// holder sees in their HTTP client logs, and the value that's
		// useful for "where was this key used from?" auditing.
		clientIP := ClientIP(c.Request)
		recordPath := c.Request.URL.Path
		recordMethod := c.Request.Method
		// context.WithoutCancel detaches the context from the request lifetime so
		// the goroutine can complete even after the HTTP response has been sent.
		recordCtx := context.WithoutCancel(c.Request.Context())

		c.Next()

		responseTime := int(time.Since(startTime).Milliseconds())
		statusCode := c.Writer.Status()
		go m.apiKeyService.RecordUsage(
			recordCtx,
			services.APIKeyUsageRecord{
				KeyID:          key.ID,
				TenantID:       key.TenantID,
				Endpoint:       recordPath,
				Method:         recordMethod,
				IP:             clientIP,
				StatusCode:     statusCode,
				ResponseTimeMs: responseTime,
			},
		)
	}
}

// RequireAPIKeyAuth returns a middleware that requires API key authentication
// Unlike APIKeyAuth(), this middleware will abort if no valid API key is present
func (m *APIKeyAuthMiddleware) RequireAPIKeyAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		apiKey := m.extractAPIKey(c)
		if apiKey == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error":   "API key required",
				"message": "This endpoint requires API key authentication",
			})
			return
		}

		key, ok := m.validateAndAuthorizeAPIKey(c, apiKey)
		if !ok {
			return
		}

		startTime := time.Now()
		setAPIKeyContext(c, key)

		// Usage records the real client public IP — what the API key
		// holder sees in their HTTP client logs, and the value that's
		// useful for "where was this key used from?" auditing.
		clientIP := ClientIP(c.Request)
		recordPath := c.Request.URL.Path
		recordMethod := c.Request.Method
		recordCtx := context.WithoutCancel(c.Request.Context())

		c.Next()

		responseTime := int(time.Since(startTime).Milliseconds())
		statusCode := c.Writer.Status()
		go m.apiKeyService.RecordUsage(
			recordCtx,
			services.APIKeyUsageRecord{
				KeyID:          key.ID,
				TenantID:       key.TenantID,
				Endpoint:       recordPath,
				Method:         recordMethod,
				IP:             clientIP,
				StatusCode:     statusCode,
				ResponseTimeMs: responseTime,
			},
		)
	}
}

// validateAndAuthorizeAPIKey validates the raw API key string and checks IP/endpoint constraints.
// Returns the resolved key and true on success; aborts and returns false on failure.
func (m *APIKeyAuthMiddleware) validateAndAuthorizeAPIKey(c *gin.Context, apiKey string) (*models.APIKey, bool) {
	key, err := m.apiKeyService.ValidateAPIKey(c.Request.Context(), apiKey)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
			"error":   "Invalid API key",
			"message": "The provided API key is invalid or has been revoked",
		})
		return nil, false
	}

	if key.ExpiresAt != nil && key.ExpiresAt.Before(time.Now()) {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
			"error":   "API key expired",
			"message": "The API key has expired",
		})
		return nil, false
	}

	// API key IP-whitelist gates by REAL client public IP — that's
	// what customers configure ("my CI runner at 203.0.113.5 only").
	// The TCP peer is always the APISIX pod IP, so a TCP-peer match
	// would be all-or-nothing across every customer.
	clientIP := ClientIP(c.Request)

	if len(key.IPWhitelist) > 0 && !m.isIPAllowed(clientIP, key.IPWhitelist) {
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
			"error":   "IP not allowed",
			"message": "Your IP address is not allowed to use this API key",
		})
		return nil, false
	}

	if len(key.AllowedEndpoints) > 0 && !m.isEndpointAllowed(c.Request.URL.Path, key.AllowedEndpoints) {
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
			"error":   "Endpoint not allowed",
			"message": "This API key is not authorized for this endpoint",
		})
		return nil, false
	}

	return key, true
}

// setAPIKeyContext stores all API key identity values into the Gin context.
func setAPIKeyContext(c *gin.Context, key *models.APIKey) {
	c.Set("api_key_id", key.ID)
	c.Set("api_key_tenant_id", key.TenantID)
	c.Set("api_key_user_id", key.UserID)
	c.Set("api_key_scopes", key.Scopes)
	c.Set("tenant_id", key.TenantID)
	c.Set("auth_method", "api_key")
	// Signal to CSRF and other middleware that this request was authenticated
	// via an API key so they can skip token-based checks.
	c.Set("api_key_authenticated", true)
	if key.RateLimitOverride != nil {
		c.Set("rate_limit_override", *key.RateLimitOverride)
	}
}

// extractAPIKey extracts the API key from the request
func (m *APIKeyAuthMiddleware) extractAPIKey(c *gin.Context) string {
	// Check X-API-Key header
	if apiKey := c.GetHeader("X-API-Key"); apiKey != "" {
		return apiKey
	}

	// Check Authorization header
	authHeader := c.GetHeader("Authorization")
	if authHeader != "" {
		// Check for "ApiKey" prefix
		if strings.HasPrefix(authHeader, "ApiKey ") {
			return strings.TrimPrefix(authHeader, "ApiKey ")
		}
		// Check for Bearer token that looks like an API key
		if strings.HasPrefix(authHeader, "Bearer hxk_") {
			return strings.TrimPrefix(authHeader, "Bearer ")
		}
	}

	// SECURITY: Query parameter API key extraction has been removed.
	// API keys in URLs are logged by proxies, CDNs, stored in browser history,
	// and leaked via Referer headers. Use X-API-Key header instead.

	return ""
}

// isIPAllowed checks if the client IP is in the whitelist
func (m *APIKeyAuthMiddleware) isIPAllowed(clientIP string, whitelist []string) bool {
	ip := net.ParseIP(clientIP)
	if ip == nil {
		return false
	}

	for _, pattern := range whitelist {
		// Try parsing as CIDR
		_, network, err := net.ParseCIDR(pattern)
		if err == nil {
			if network.Contains(ip) {
				return true
			}
			continue
		}

		// Try parsing as single IP
		patternIP := net.ParseIP(pattern)
		if patternIP != nil && ip.Equal(patternIP) {
			return true
		}
	}

	return false
}

// isEndpointAllowed checks if the endpoint is in the allowed list
func (m *APIKeyAuthMiddleware) isEndpointAllowed(endpoint string, allowed []string) bool {
	for _, pattern := range allowed {
		// Handle wildcard patterns
		if pattern == "*" {
			return true
		}

		// Handle suffix wildcards (e.g., "/api/users/*")
		if strings.HasSuffix(pattern, "/*") {
			prefix := strings.TrimSuffix(pattern, "/*")
			if strings.HasPrefix(endpoint, prefix) {
				return true
			}
			continue
		}

		// Exact match
		if pattern == endpoint {
			return true
		}
	}

	return false
}

// RequireScope returns a middleware that requires specific scopes
func (m *APIKeyAuthMiddleware) RequireScope(requiredScopes ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get scopes from context
		scopesI, exists := c.Get("api_key_scopes")
		if !exists {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error":   "Insufficient permissions",
				"message": "API key authentication required",
			})
			return
		}

		scopes, ok := scopesI.([]string)
		if !ok {
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
				"error": "Internal error processing scopes",
			})
			return
		}

		// Check if any required scope is present
		for _, required := range requiredScopes {
			for _, scope := range scopes {
				if scope == required || scope == "*" {
					c.Next()
					return
				}
			}
		}

		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
			"error":   "Insufficient permissions",
			"message": "This API key does not have the required scopes",
		})
	}
}
