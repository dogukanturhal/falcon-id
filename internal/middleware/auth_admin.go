// SPDX-License-Identifier: AGPL-3.0-or-later

package middleware

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync/atomic"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/authorization"
	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/internal/services"
	"github.com/dogukanturhal/falcon-id/pkg/logger"
)

// platformAdminRoles are the only role names that grant access to the
// platform plane (§2.8 the product roadmap: "Only platform_admin roles in
// Hexxlock internal tenant ... may administer platform roles / cross-tenant
// functions"). iam_admin is included because admin_bootstrap.go assigns it
// alongside platform_admin to the bootstrap account and it is used
// interchangeably for platform-plane IAM administration.
var platformAdminRoles = []string{"platform_admin", "iam_admin"}

// platformAuthorityPtr holds the OPS_STRICT_PLATFORM_ROLES authority. Unset
// (or non-strict) = legacy behaviour everywhere below.
var platformAuthorityPtr atomic.Pointer[services.PlatformAuthority]

// SetPlatformAuthority installs the strict platform-role authority. Call once
// at startup; nil restores legacy behaviour.
func SetPlatformAuthority(pa *services.PlatformAuthority) { platformAuthorityPtr.Store(pa) }

func strictPlatformRoles() bool { return platformAuthorityPtr.Load().Strict() }

// applyStrictPlatformAuthority overrides the token-derived IsPlatformAdmin
// with a LIVE check against iam_platform_roles when OPS_STRICT_PLATFORM_ROLES
// is on, and records the verdict in PlatformAuthorityVerified. A no-op in
// legacy mode. Tokens minted before the flag flipped (or before an
// elevation expired) therefore stop granting platform admin immediately,
// not at token expiry.
func applyStrictPlatformAuthority(c *gin.Context, u *models.CurrentUser) {
	pa := platformAuthorityPtr.Load()
	if !pa.Strict() || u == nil {
		return
	}
	ctx := context.Background()
	if c != nil && c.Request != nil {
		ctx = c.Request.Context()
	}
	ok := pa.VerifyAdmin(ctx, u.ID, u.TenantID, u.Email, userHasAnyRole(u.Roles, platformAdminRoles))
	u.IsPlatformAdmin = ok
	u.PlatformAuthorityVerified = ok
}

// platformPlaneRoleOK reports whether the principal holds the platform-plane
// role the platform-admin gates require: the legacy tenant role
// (platform_admin / iam_admin), or - under OPS_STRICT_PLATFORM_ROLES - the
// verdict of the live iam_platform_roles check.
func platformPlaneRoleOK(u *models.CurrentUser) bool {
	if strictPlatformRoles() {
		return u.PlatformAuthorityVerified
	}
	return userHasAnyRole(u.Roles, platformAdminRoles)
}

// isPlatformPlaneRoleName reports whether a role name is one of the legacy
// platform-plane tenant roles.
func isPlatformPlaneRoleName(name string) bool {
	return userHasAnyRole([]string{name}, append([]string{"super_admin"}, platformAdminRoles...))
}

// holdsPlatformAdminRole is platformPlaneRoleOK for the tenant-ownership
// checks, which historically also accepted super_admin.
func holdsPlatformAdminRole(u *models.CurrentUser) bool {
	if strictPlatformRoles() {
		return u.PlatformAuthorityVerified
	}
	return u.HasRole("platform_admin") || u.HasRole("super_admin")
}

// RequirePlatformAdmin middleware that requires the user to be a platform admin.
//
// SECURITY (R0 platform-admin audit, docs/audits/2026-09-27-platform-admin-audit.md
// finding F1): this used to grant platform access to ANY user in the
// exampletenant tenant, regardless of role — tenant membership alone
// was treated as sufficient. That is wrong: the internal tenant holds
// non-admin service/operational accounts (e.g. payment-provider-sync,
// mail-operator) that must not receive blanket platform:* access. This now
// requires ALL THREE: the isPlatformAdmin claim, tenant == exampletenant,
// AND the caller holding platform_admin or iam_admin. Fail-closed: any
// missing signal denies.
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

		// SECURITY: tenant membership is necessary but not sufficient — the
		// caller must actually hold a platform-plane role. See finding F1.
		if !platformPlaneRoleOK(user) {
			logger.Log.Warn("Platform admin access denied - internal tenant member without platform role",
				zap.String("user_id", user.ID.String()),
				zap.Strings("roles", user.Roles),
			)
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "Platform admin access required"})
			return
		}

		// PLATFORM_ADMIN_REQUIRE_PHISHING_RESISTANT_MFA: passkey-only plane.
		pr := phishingResistantPolicy{sessions: m.idpSessions}
		if m.config != nil {
			pr.required = m.config.PlatformAdminRequirePhishingResistantMFA
		}
		if pr.deny(c, user, "") {
			return
		}

		c.Next()
	}
}

// UserHasAnyRole is the exported form of userHasAnyRole.
func UserHasAnyRole(userRoles, allowedRoles []string) bool {
	return userHasAnyRole(userRoles, allowedRoles)
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

// isVerifiedPlatformAdmin returns true when the user carries the platform admin flag,
// belongs to the exampletenant tenant, AND holds a platform-plane role
// (defense in depth — see RequirePlatformAdmin / finding F1).
func isVerifiedPlatformAdmin(user *models.CurrentUser) bool {
	return user.IsPlatformAdmin &&
		user.TenantID.String() == models.HexxlockInternalTenantID &&
		platformPlaneRoleOK(user)
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
