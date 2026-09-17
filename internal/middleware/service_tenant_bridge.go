// SPDX-License-Identifier: AGPL-3.0-or-later

package middleware

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// BridgeServiceTenantToTenantID copies the JWT-derived tenant_id from
// `service_tenant_id` (set by ServiceAuth from the access token's
// tenant_id claim) into `tenant_id` (the canonical key read by
// GetTenantID + the existing OAuth admin handlers). MUST be wired AFTER
// ServiceAuth() and BEFORE the route handler.
//
// Why this exists: the admin OAuth-clients handlers
// (CreateClient/UpdateClient/etc.) read tenant via GetTenantID(c) which
// is sourced from `tenant_id`. Browser callers reach those handlers
// through the user-session auth middleware which sets `tenant_id` from
// the user record. Service-to-service callers go through ServiceAuth
// which sets `service_tenant_id` (a separate key, by design — services
// CAN cross tenants under platform-admin scopes). The internal
// /api/v1/internal/oauth-clients/* group reuses the same handlers but
// scopes the request to the JWT's tenant; this bridge makes that
// substitution explicit.
//
// Aborts with 400 if no service tenant is in context — that means the
// service JWT has no tenant_id claim, which is itself a
// post-Bug-1+2 invariant violation worth surfacing.
func BridgeServiceTenantToTenantID() gin.HandlerFunc {
	return func(c *gin.Context) {
		raw, exists := c.Get(CtxKeyServiceTenantID)
		if !exists {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
				"error":             "missing_tenant_context",
				"error_description": "service token did not carry a tenant_id claim; ensure the issuing client has a tenant_id and ServiceAuth() ran before this handler",
			})
			return
		}
		s, ok := raw.(string)
		if !ok || s == "" {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
				"error":             "missing_tenant_context",
				"error_description": "service tenant_id context value is empty or wrong type",
			})
			return
		}
		tenantID, err := uuid.Parse(s)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
				"error":             "invalid_tenant_context",
				"error_description": "service tenant_id is not a valid UUID",
			})
			return
		}
		// Promote to the canonical key. Existing handlers read this via
		// GetTenantID(c) and don't need any change.
		c.Set(TenantIDKey, tenantID)
		c.Next()
	}
}
