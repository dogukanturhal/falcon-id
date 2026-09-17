// SPDX-License-Identifier: AGPL-3.0-or-later

package middleware

import (
	"crypto/subtle"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// InternalAuthMiddleware handles authentication for internal service-to-service communication
type InternalAuthMiddleware struct {
	internalAPIKey string
}

// NewInternalAuthMiddleware creates a new internal auth middleware
func NewInternalAuthMiddleware(internalAPIKey string) *InternalAuthMiddleware {
	return &InternalAuthMiddleware{
		internalAPIKey: internalAPIKey,
	}
}

// InternalServiceAuth middleware that authenticates internal service requests.
// SECURITY: Only the X-Internal-Key header is accepted for authentication.
// X-API-Key and X-Service-Name headers are NOT used — they are spoofable by
// any external client. Use RequireInternalAuth for endpoints that MUST have
// internal authentication.
func (m *InternalAuthMiddleware) InternalServiceAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		apiKey := c.GetHeader("X-Internal-Key")
		if apiKey == "" {
			c.Next()
			return
		}

		if m.internalAPIKey == "" {
			c.AbortWithStatusJSON(http.StatusServiceUnavailable, gin.H{
				"error":   "Internal authentication not configured",
				"message": "Service-to-service authentication is not available",
			})
			return
		}

		if subtle.ConstantTimeCompare([]byte(apiKey), []byte(m.internalAPIKey)) != 1 {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error":   "Invalid API key",
				"message": "The provided API key is invalid",
			})
			return
		}

		setInternalServiceContext(c)
		c.Next()
	}
}

// RequireInternalAuth middleware that requires internal service authentication
func (m *InternalAuthMiddleware) RequireInternalAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		if isInternalServiceRequest(c) {
			c.Next()
			return
		}

		if m.internalAPIKey == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error":   "Internal authentication not configured",
				"message": "Internal API key is not configured",
			})
			return
		}

		apiKey := c.GetHeader("X-Internal-Key")
		if apiKey == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error":   "Internal key required",
				"message": "This endpoint requires internal service authentication",
			})
			return
		}

		if subtle.ConstantTimeCompare([]byte(apiKey), []byte(m.internalAPIKey)) != 1 {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error":   "Invalid API key",
				"message": "The provided API key is invalid",
			})
			return
		}

		setInternalServiceContext(c)
		c.Next()
	}
}

// isInternalServiceRequest returns true when the context already carries a validated internal service identity.
func isInternalServiceRequest(c *gin.Context) bool {
	if isInternal, exists := c.Get("is_internal_service"); exists {
		if val, ok := isInternal.(bool); ok && val {
			return true
		}
	}
	return false
}

// setInternalServiceContext populates the Gin context with internal service identity values.
func setInternalServiceContext(c *gin.Context) {
	serviceName := c.GetHeader("X-Service-Name")
	if serviceName == "" {
		serviceName = "internal-service"
	}
	if tenantIDStr := c.GetHeader("X-Tenant-ID"); tenantIDStr != "" {
		if tenantID, err := uuid.Parse(tenantIDStr); err == nil {
			c.Set("tenant_id", tenantID)
		}
	}
	c.Set("auth_method", "internal_api_key")
	c.Set("service_name", serviceName)
	c.Set("is_internal_service", true)
}
