// SPDX-License-Identifier: AGPL-3.0-or-later

package middleware

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/dogukanturhal/falcon-id/internal/services"
)

// SCIMAuthMiddleware handles SCIM token authentication
type SCIMAuthMiddleware struct {
	scimService *services.SCIMService
}

// NewSCIMAuthMiddleware creates a new SCIMAuthMiddleware
func NewSCIMAuthMiddleware(scimService *services.SCIMService) *SCIMAuthMiddleware {
	return &SCIMAuthMiddleware{
		scimService: scimService,
	}
}

// RequireSCIMAuth requires a valid SCIM token for the request
func (m *SCIMAuthMiddleware) RequireSCIMAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get Authorization header
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"schemas": []string{"urn:ietf:params:scim:api:messages:2.0:Error"},
				"status":  "401",
				"detail":  "Authorization header required",
			})
			return
		}

		// Check for Bearer token
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"schemas":  []string{"urn:ietf:params:scim:api:messages:2.0:Error"},
				"status":   "401",
				"detail":   "Invalid authorization header format",
				"scimType": "invalidAuth",
			})
			return
		}

		bearerToken := parts[1]

		// Validate the token
		token, err := m.scimService.ValidateToken(c.Request.Context(), bearerToken)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"schemas":  []string{"urn:ietf:params:scim:api:messages:2.0:Error"},
				"status":   "401",
				"detail":   "Invalid or expired token",
				"scimType": "invalidAuth",
			})
			return
		}

		// Update last used timestamp (fire and forget). Record the real
		// client public IP (X-Real-IP, APISIX-stamped from CF-Connecting-IP)
		// — this is the IP the SCIM operator sees in their HTTP client
		// logs and the one that's useful for "where was this token last
		// used from?" auditing. The TCP peer (APISIX pod IP) is identical
		// across every request and provides no audit value.
		go m.scimService.UpdateTokenUsage(c.Request.Context(), token.ID, ClientIP(c.Request))

		// Set tenant ID in context for SCIM operations
		c.Set("scim_tenant_id", token.TenantID)
		c.Set("scim_token_id", token.ID)

		c.Next()
	}
}
