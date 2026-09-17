// SPDX-License-Identifier: AGPL-3.0-or-later

// Package middleware provides HTTP middleware for the IAM service.
package middleware

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/pkg/logger"
)

// TenantOwnershipConfig holds tenant ownership validation middleware configuration
type TenantOwnershipConfig struct {
	// SkipPaths are paths to skip tenant ownership validation
	SkipPaths []string
	// SkipMethods are HTTP methods to skip validation (e.g., OPTIONS)
	SkipMethods []string
	// AllowCrossTenantAccess indicates if cross-tenant access is allowed (for platform admins)
	AllowCrossTenantAccess bool
	// ResourceIDParam is the URL parameter name for resource ID (default: "id")
	ResourceIDParam string
}

// DefaultTenantOwnershipConfig returns default tenant ownership configuration
func DefaultTenantOwnershipConfig() TenantOwnershipConfig {
	return TenantOwnershipConfig{
		SkipPaths: []string{
			"/health",
			"/ready",
			"/metrics",
			"/api/auth/",    // Auth endpoints handle tenant internally
			"/.well-known/", // Discovery endpoints
			"/internal/",    // Internal service endpoints
		},
		SkipMethods:            []string{"OPTIONS"},
		AllowCrossTenantAccess: false,
		ResourceIDParam:        "id",
	}
}

// TenantOwnershipMiddleware validates that authenticated users can only access
// resources belonging to their tenant. This prevents IDOR (Insecure Direct Object Reference) attacks.
type TenantOwnershipMiddleware struct {
	config TenantOwnershipConfig
}

// NewTenantOwnershipMiddleware creates a new tenant ownership middleware
func NewTenantOwnershipMiddleware() *TenantOwnershipMiddleware {
	return &TenantOwnershipMiddleware{
		config: DefaultTenantOwnershipConfig(),
	}
}

// NewTenantOwnershipMiddlewareWithConfig creates a middleware with custom configuration
func NewTenantOwnershipMiddlewareWithConfig(config TenantOwnershipConfig) *TenantOwnershipMiddleware {
	return &TenantOwnershipMiddleware{
		config: config,
	}
}

// ValidateTenantOwnership returns a middleware that validates tenant ownership
// SECURITY: This middleware prevents users from one tenant accessing resources of another tenant
func (m *TenantOwnershipMiddleware) ValidateTenantOwnership() gin.HandlerFunc {
	return func(c *gin.Context) {
		if m.isExemptRequest(c) {
			c.Next()
			return
		}

		userTenantID := m.getUserTenantID(c)
		if userTenantID == uuid.Nil {
			c.Next()
			return
		}

		if blocked := m.checkHeaderTenantOwnership(c, userTenantID); blocked {
			return
		}

		if blocked := m.checkPathTenantOwnership(c, userTenantID); blocked {
			return
		}

		c.Set("validated_tenant_id", userTenantID)
		c.Next()
	}
}

// isExemptRequest returns true when the request method or path is configured to skip ownership checks.
func (m *TenantOwnershipMiddleware) isExemptRequest(c *gin.Context) bool {
	for _, method := range m.config.SkipMethods {
		if c.Request.Method == method {
			return true
		}
	}
	path := c.Request.URL.Path
	for _, exemptPath := range m.config.SkipPaths {
		if strings.HasPrefix(path, exemptPath) {
			return true
		}
	}
	return false
}

// checkHeaderTenantOwnership validates the X-Tenant-ID / query tenant_id against the user's tenant.
// Returns true if the request was blocked.
func (m *TenantOwnershipMiddleware) checkHeaderTenantOwnership(c *gin.Context, userTenantID uuid.UUID) bool {
	requestTenantID := m.getRequestTenantID(c)
	if requestTenantID == uuid.Nil || requestTenantID == userTenantID {
		return false
	}
	if m.config.AllowCrossTenantAccess || m.isPlatformAdmin(c) {
		return false
	}
	logger.Log.Warn("Tenant ownership violation attempt",
		zap.String("user_tenant_id", userTenantID.String()),
		zap.String("request_tenant_id", requestTenantID.String()),
		zap.String("path", c.Request.URL.Path),
		zap.String("method", c.Request.Method),
	)
	c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
		"error":   "tenant_mismatch",
		"message": "You do not have permission to access resources from this tenant",
	})
	return true
}

// checkPathTenantOwnership validates the :tenant_id URL parameter against the user's tenant.
// Returns true if the request was blocked.
func (m *TenantOwnershipMiddleware) checkPathTenantOwnership(c *gin.Context, userTenantID uuid.UUID) bool {
	pathTenantID := c.Param("tenant_id")
	if pathTenantID == "" {
		return false
	}
	parsedTenantID, err := uuid.Parse(pathTenantID)
	if err != nil || parsedTenantID == userTenantID {
		return false
	}
	if m.config.AllowCrossTenantAccess || m.isPlatformAdmin(c) {
		return false
	}
	logger.Log.Warn("Tenant ownership violation in URL path",
		zap.String("user_tenant_id", userTenantID.String()),
		zap.String("path_tenant_id", pathTenantID),
		zap.String("path", c.Request.URL.Path),
	)
	c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
		"error":   "tenant_mismatch",
		"message": "You do not have permission to access this tenant's resources",
	})
	return true
}

// getUserTenantID extracts the authenticated user's tenant ID from context
func (m *TenantOwnershipMiddleware) getUserTenantID(c *gin.Context) uuid.UUID {
	// Try to get from current user (set by auth middleware)
	if user := GetCurrentUser(c); user != nil {
		return user.TenantID
	}

	// Try to get from context directly (may be set by other middleware)
	if tenantIDVal, exists := c.Get("tenant_id"); exists {
		switch v := tenantIDVal.(type) {
		case uuid.UUID:
			return v
		case string:
			if parsed, err := uuid.Parse(v); err == nil {
				return parsed
			}
		}
	}

	return uuid.Nil
}

// getRequestTenantID extracts the requested tenant ID from headers or URL
func (m *TenantOwnershipMiddleware) getRequestTenantID(c *gin.Context) uuid.UUID {
	// Check X-Tenant-ID header
	tenantIDStr := c.GetHeader("X-Tenant-ID")
	if tenantIDStr != "" {
		if parsed, err := uuid.Parse(tenantIDStr); err == nil {
			return parsed
		}
	}

	// Check URL query parameter
	tenantIDStr = c.Query("tenant_id")
	if tenantIDStr != "" {
		if parsed, err := uuid.Parse(tenantIDStr); err == nil {
			return parsed
		}
	}

	return uuid.Nil
}

// isPlatformAdmin checks if the current user is a platform admin
func (m *TenantOwnershipMiddleware) isPlatformAdmin(c *gin.Context) bool {
	// Check for platform admin flag set by platform admin middleware
	if isPlatformAdmin, exists := c.Get("is_platform_admin"); exists {
		if val, ok := isPlatformAdmin.(bool); ok {
			return val
		}
	}

	// Check for platform admin role in current user
	if user := GetCurrentUser(c); user != nil {
		return user.HasRole("platform_admin") || user.HasRole("super_admin")
	}

	return false
}

// RequireSameTenant is a simpler middleware that just validates
// the authenticated user's tenant matches the X-Tenant-ID header
func RequireSameTenant() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get user's tenant from auth context
		user := GetCurrentUser(c)
		if user == nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "Not authenticated",
			})
			return
		}

		// Get requested tenant from header
		requestTenantIDStr := c.GetHeader("X-Tenant-ID")
		if requestTenantIDStr == "" {
			// No explicit tenant requested, continue
			c.Next()
			return
		}

		requestTenantID, err := uuid.Parse(requestTenantIDStr)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
				"error": "Invalid tenant ID format",
			})
			return
		}

		// SECURITY: Validate tenant matches
		if requestTenantID != user.TenantID {
			// Check if user is platform admin
			if !user.HasRole("platform_admin") && !user.HasRole("super_admin") {
				logger.Log.Warn("Cross-tenant access denied",
					zap.String("user_id", user.ID.String()),
					zap.String("user_tenant_id", user.TenantID.String()),
					zap.String("requested_tenant_id", requestTenantID.String()),
				)

				c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
					"error":   "tenant_access_denied",
					"message": "You cannot access resources from another tenant",
				})
				return
			}
		}

		c.Next()
	}
}

// ValidateResourceTenantOwnership validates that a resource belongs to the user's tenant
// This is meant to be used within handlers that have already loaded a resource
// Usage: middleware.ValidateResourceTenantOwnership(c, resource.TenantID)
func ValidateResourceTenantOwnership(c *gin.Context, resourceTenantID uuid.UUID) bool {
	user := GetCurrentUser(c)
	if user == nil {
		return false
	}

	// Platform admins can access any tenant's resources
	if user.HasRole("platform_admin") || user.HasRole("super_admin") {
		return true
	}

	// Regular users can only access their own tenant's resources
	return user.TenantID == resourceTenantID
}
