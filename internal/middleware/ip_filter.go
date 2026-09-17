// SPDX-License-Identifier: AGPL-3.0-or-later

package middleware

import (
	"context"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/internal/services"
)

// IPFilterMiddleware creates an IP filtering middleware
type IPFilterMiddleware struct {
	service *services.IPRuleService
}

// NewIPFilterMiddleware creates a new IP filter middleware
func NewIPFilterMiddleware(service *services.IPRuleService) *IPFilterMiddleware {
	return &IPFilterMiddleware{
		service: service,
	}
}

// IPFilter returns a middleware handler that applies IP filtering
func (m *IPFilterMiddleware) IPFilter() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get tenant ID from context
		// SECURITY: No default tenant - IP filtering applies per-tenant only
		tenantIDVal, exists := c.Get("tenant_id")
		if !exists {
			// No tenant context - skip tenant-specific IP filtering
			// Global IP rules (if any) should be handled at the gateway level
			c.Next()
			return
		}

		var tenantID uuid.UUID
		switch v := tenantIDVal.(type) {
		case uuid.UUID:
			tenantID = v
		case string:
			parsed, err := uuid.Parse(v)
			if err != nil {
				// Invalid tenant ID format - skip IP filtering
				c.Next()
				return
			}
			tenantID = parsed
		default:
			// Unknown type - skip IP filtering
			c.Next()
			return
		}

		// Tenant-configured IP rules gate by REAL client public IP — that's
		// what tenant admins enter in the UI ("only 198.51.100.0/24 may
		// access /admin/*"). The TCP peer is always the APISIX pod IP, so
		// a peer-match would be all-or-nothing across every tenant.
		clientIP := ClientIP(c.Request)

		// Determine what this endpoint applies to
		appliesTo := m.determineAppliesTo(c.Request.URL.Path)

		// Check IP against rules
		result, err := m.service.CheckIP(c.Request.Context(), tenantID, clientIP, appliesTo)
		if err != nil {
			// SECURITY: Fail closed — if we cannot evaluate IP rules we must not
			// allow the request through. Failing open would let an attacker bypass
			// IP restrictions by triggering a transient rule-store error.
			zap.L().Error("IP rule check failed", zap.Error(err))
			c.AbortWithStatusJSON(http.StatusServiceUnavailable, gin.H{
				"error": "Unable to verify IP access rules",
			})
			return
		}

		// Capture values before c.Next() / response and use a detached context
		// so the logging goroutine completes even after the HTTP response is sent.
		logCtx := context.WithoutCancel(c.Request.Context())
		logPath := c.Request.URL.Path
		logUA := c.Request.UserAgent()

		// If not allowed, block the request
		if !result.Allowed {
			// Log the denied access
			go m.service.LogAction(logCtx, tenantID, &result.RuleID, clientIP, "denied", logPath, logUA)

			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error":   "Access denied",
				"message": "Your IP address is not allowed to access this resource",
			})
			return
		}

		// If allowed by a specific rule, log it (only for explicit allow rules, not default)
		if result.RuleID != uuid.Nil {
			go m.service.LogAction(logCtx, tenantID, &result.RuleID, clientIP, "allowed", logPath, logUA)
		}

		c.Next()
	}
}

// determineAppliesTo determines what category an endpoint belongs to
func (m *IPFilterMiddleware) determineAppliesTo(path string) models.IPRuleAppliesTo {
	if strings.HasPrefix(path, "/api/admin") {
		return models.IPRuleAppliesToAdmin
	}
	if strings.HasPrefix(path, "/api") {
		return models.IPRuleAppliesToAPI
	}
	return models.IPRuleAppliesToUser
}
