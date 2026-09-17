// SPDX-License-Identifier: AGPL-3.0-or-later

package middleware

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/authorization"
	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/internal/services"
	"github.com/dogukanturhal/falcon-id/pkg/logger"
)

// RequirePlatformAdmin middleware that requires the user to be a platform admin
// SECURITY: This checks both the isPlatformAdmin claim AND verifies the tenant is exampletenant
// Use this for platform-level operations that should only be accessible to HexxLock staff
func (m *AuthMiddleware) RequirePlatformAdmin() gin.HandlerFunc {
	return func(c *gin.Context) {
		userVal, exists := c.Get(CurrentUserKey)
		if !exists {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Not authenticated"})
			return
		}

		user, ok := userVal.(*models.CurrentUser)
		if !ok {
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Invalid user context"})
			return
		}

		// Check isPlatformAdmin flag (server-computed, authoritative)
		if !user.IsPlatformAdmin {
			logger.Log.Warn("Platform admin access denied",
				zap.String("user_id", user.ID.String()),
				zap.String("tenant_id", user.TenantID.String()),
				zap.String("path", c.Request.URL.Path),
			)
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "Platform admin access required"})
			return
		}

		// Double-check tenant is exampletenant (defense in depth)
		if user.TenantID.String() != models.HexxlockInternalTenantID {
			logger.Log.Warn("Platform admin claim mismatch - tenant is not exampletenant",
				zap.String("user_id", user.ID.String()),
				zap.String("tenant_id", user.TenantID.String()),
			)
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "Platform admin access required"})
			return
		}

		c.Next()
	}
}

// userHasAnyRole returns true if the user holds at least one of the specified roles (case-insensitive).
func userHasAnyRole(userRoles, allowedRoles []string) bool {
	for _, role := range userRoles {
		for _, allowed := range allowedRoles {
			if strings.EqualFold(role, allowed) {
				return true
			}
		}
	}
	return false
}

// isVerifiedPlatformAdmin returns true when the user carries the platform admin flag AND
// belongs to the exampletenant tenant (defense in depth).
func isVerifiedPlatformAdmin(user *models.CurrentUser) bool {
	return user.IsPlatformAdmin && user.TenantID.String() == models.HexxlockInternalTenantID
}

// requireUserFromContext extracts *models.CurrentUser from the Gin context, aborting on failure.
// Returns nil when the request has been aborted.
func requireUserFromContext(c *gin.Context) *models.CurrentUser {
	userVal, exists := c.Get(CurrentUserKey)
	if !exists {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Not authenticated"})
		return nil
	}
	user, ok := userVal.(*models.CurrentUser)
	if !ok {
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Invalid user context"})
		return nil
	}
	return user
}

// RequireTenantAdmin middleware that requires the user to have admin role within their OWN tenant
// SECURITY: This validates that the admin role belongs to the user's current tenant context
// Use this for tenant-scoped admin operations
func (m *AuthMiddleware) RequireTenantAdmin() gin.HandlerFunc {
	return func(c *gin.Context) {
		user := requireUserFromContext(c)
		if user == nil {
			return
		}

		if !userHasAnyRole(user.Roles, authorization.TenantAdministratorRoleNames()) {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "Tenant admin access required"})
			return
		}

		c.Next()
	}
}

// RequireTenantAdminOrPlatformAdmin middleware that allows access to either tenant admins or platform admins
// Use this for endpoints that should be accessible by both
func (m *AuthMiddleware) RequireTenantAdminOrPlatformAdmin() gin.HandlerFunc {
	return func(c *gin.Context) {
		user := requireUserFromContext(c)
		if user == nil {
			return
		}

		if isVerifiedPlatformAdmin(user) {
			c.Next()
			return
		}

		if !userHasAnyRole(user.Roles, authorization.TenantAdministratorRoleNames()) {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "Admin access required"})
			return
		}

		c.Next()
	}
}

// RequireResourcePermission checks object-level permission via the authorization engine
// Usage: router.PUT("/invoices/:id", middleware.RequireResourcePermission("invoice", "edit"))
func (m *AuthMiddleware) RequireResourcePermission(resourceType, action string) gin.HandlerFunc {
	return func(c *gin.Context) {
		user := GetCurrentUser(c)
		if user == nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "Not authenticated",
			})
			return
		}

		// SECURITY: fail-closed when authorization engine is not available
		if m.authzEngine == nil {
			logger.Log.Error("SECURITY: RequireResourcePermission called but authzEngine is nil — fail-closed",
				zap.String("resource_type", resourceType),
				zap.String("action", action),
				zap.String("user_id", user.ID.String()),
			)
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error":  "Access denied",
				"reason": "Authorization service unavailable",
			})
			return
		}

		// Extract resource ID from URL parameter (default: "id")
		resourceID := c.Param("id")
		if resourceID == "" {
			// Try alternative parameter name: {resourceType}_id
			resourceID = c.Param(resourceType + "_id")
		}

		if resourceID == "" {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
				"error": "Resource ID required",
			})
			return
		}

		// Build resource permission request
		req := services.ResourcePermissionRequest{
			UserID:       user.ID,
			TenantID:     user.TenantID,
			ResourceType: resourceType,
			ResourceID:   resourceID,
			Action:       action,
		}

		// Check permission via authorization engine
		result, err := m.authzEngine.CheckResourcePermission(c.Request.Context(), req)
		if err != nil {
			logger.Log.Error("Failed to check resource permission",
				zap.Error(err),
				zap.String("user_id", user.ID.String()),
				zap.String("resource_type", resourceType),
				zap.String("resource_id", resourceID),
				zap.String("action", action),
			)
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to check permissions",
			})
			return
		}

		if !result.Allowed {
			logger.Log.Info("Resource permission denied",
				zap.String("user_id", user.ID.String()),
				zap.String("resource_type", resourceType),
				zap.String("resource_id", resourceID),
				zap.String("action", action),
				zap.String("reason", result.Reason),
				zap.String("source", result.Source),
			)

			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error":  "Access denied",
				"reason": result.Reason,
			})
			return
		}

		// Permission granted - add result to context for logging
		c.Set("authz_result", result)

		c.Next()
	}
}

// RequireTenantScopedAdmin middleware that validates tenant-scoped admin access
// SECURITY (CVE-HEXX-IAM-001): Prevents cross-tenant admin access by ensuring the admin user
// belongs to the same tenant as the resource being accessed.
// FAIL-CLOSED BEHAVIOR: If tenant cannot be determined from request, access is DENIED.
func (m *AuthMiddleware) RequireTenantScopedAdmin(tenantParamName string) gin.HandlerFunc {
	return func(c *gin.Context) {
		user := GetCurrentUser(c)
		if user == nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Not authenticated"})
			return
		}

		if isVerifiedPlatformAdmin(user) {
			logger.Log.Debug("Platform admin accessing resource - tenant scope check bypassed",
				zap.String("user_id", user.ID.String()),
				zap.String("path", c.Request.URL.Path),
			)
			c.Next()
			return
		}

		if !userHasTenantScopedAdministratorRole(user.Roles) {
			logger.Log.Warn("Tenant admin role required",
				zap.String("user_id", user.ID.String()),
				zap.String("tenant_id", user.TenantID.String()),
				zap.Strings("user_roles", user.Roles),
			)
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "Tenant admin access required"})
			return
		}

		targetTenantID, err := extractTenantID(c, tenantParamName)
		if err != nil {
			logger.Log.Warn("Failed to extract tenant ID from request - denying access",
				zap.Error(err),
				zap.String("user_id", user.ID.String()),
				zap.String("param_name", tenantParamName),
				zap.String("path", c.Request.URL.Path),
			)
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
				"error":  "Invalid or missing tenant identifier",
				"detail": err.Error(),
			})
			return
		}

		if user.TenantID != *targetTenantID {
			logger.Log.Warn("Cross-tenant admin access attempt blocked",
				zap.String("user_id", user.ID.String()),
				zap.String("user_tenant_id", user.TenantID.String()),
				zap.String("target_tenant_id", targetTenantID.String()),
				zap.String("path", c.Request.URL.Path),
				zap.String("method", c.Request.Method),
			)
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "Access denied: tenant mismatch"})
			return
		}

		c.Set("validated_tenant_id", *targetTenantID)
		c.Next()
	}
}

func userHasTenantScopedAdministratorRole(roles []string) bool {
	for _, role := range roles {
		if authorization.IsTenantScopedAdministratorRole(role) {
			return true
		}
	}
	return false
}

// ValidateTenantAccess is a helper function for handlers to validate tenant-scoped access
// SECURITY (CVE-HEXX-IAM-001): Use this in handlers where middleware cannot be applied.
func ValidateTenantAccess(c *gin.Context, targetTenantID uuid.UUID) error {
	user := GetCurrentUser(c)
	if user == nil {
		return fmt.Errorf("not authenticated")
	}

	// Platform admins have unrestricted access
	if user.IsPlatformAdmin && user.TenantID.String() == models.HexxlockInternalTenantID {
		return nil
	}

	// Validate tenant scope match
	if user.TenantID != targetTenantID {
		logger.Log.Warn("Tenant access validation failed",
			zap.String("user_id", user.ID.String()),
			zap.String("user_tenant_id", user.TenantID.String()),
			zap.String("target_tenant_id", targetTenantID.String()),
		)
		return fmt.Errorf("access denied: tenant mismatch")
	}

	return nil
}

// isMutableMethod returns true for HTTP methods that carry a request body.
func isMutableMethod(method string) bool {
	return method == http.MethodPost || method == http.MethodPut || method == http.MethodPatch
}

// parseTenantIDStr parses a UUID string, returning a descriptive error with the source location.
func parseTenantIDStr(raw, source string) (*uuid.UUID, error) {
	id, err := uuid.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("invalid tenant_id in %s: %w", source, err)
	}
	return &id, nil
}

// extractTenantID extracts tenant_id from URL params, query params, or request body
// SECURITY: FAIL-CLOSED - Returns error if tenant_id cannot be extracted or is invalid
func extractTenantID(c *gin.Context, paramName string) (*uuid.UUID, error) {
	// Strategy 1: URL path parameter (most reliable)
	if raw := c.Param(paramName); raw != "" {
		return parseTenantIDStr(raw, "URL path")
	}

	// Strategy 2: Query parameter
	if raw := c.Query(paramName); raw != "" {
		return parseTenantIDStr(raw, "query params")
	}

	// Strategy 3: Request body (for POST/PUT/PATCH)
	if isMutableMethod(c.Request.Method) {
		if id, err := parseTenantIDFromBody(c, paramName); id != nil || err != nil {
			return id, err
		}
	}

	// Strategy 4: X-Tenant-ID header (fallback, less secure)
	if raw := c.GetHeader("X-Tenant-ID"); raw != "" {
		id, err := parseTenantIDStr(raw, "X-Tenant-ID header")
		if err != nil {
			return nil, err
		}
		logger.Log.Warn("Tenant ID extracted from X-Tenant-ID header - consider using URL/body params instead",
			zap.String("tenant_id", id.String()),
			zap.String("path", c.Request.URL.Path),
		)
		return id, nil
	}

	return nil, fmt.Errorf("tenant_id not found in URL params, query params, body, or headers")
}

// parseTenantIDFromBody attempts to extract paramName from the JSON request body.
// Returns (id, nil) if found, (nil, nil) if absent, (nil, err) on parse failure.
func parseTenantIDFromBody(c *gin.Context, paramName string) (*uuid.UUID, error) {
	var body map[string]interface{}
	if err := c.ShouldBindJSON(&body); err != nil {
		return nil, nil //nolint:nilerr // body may not be JSON; treated as absent
	}
	val, ok := body[paramName]
	if !ok {
		return nil, nil
	}
	raw, ok := val.(string)
	if !ok || raw == "" {
		return nil, nil
	}
	return parseTenantIDStr(raw, "request body")
}
