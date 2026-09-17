// SPDX-License-Identifier: AGPL-3.0-or-later

package middleware

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

// RequireScope returns a Gin middleware that aborts the request with 403 if the
// authenticated service principal's token does not carry ALL of the specified
// scopes.
//
// Scopes are read from the "service_scopes" context key populated by
// ServiceAuthMiddleware. The scope string is space-separated per RFC 6749 §3.3.
//
// Usage:
//
//	busGroup.POST("/events/publish",
//	    RequireScope("events:publish"),
//	    publishHandler)
//
//	adminGroup.DELETE("/tenants/:id",
//	    RequireScope("tenants:delete", "platform:admin"),
//	    deleteTenantHandler)
//
// RequireScope must be placed AFTER ServiceAuth() in the middleware chain so
// that service_scopes is already populated when the check runs.
func RequireScope(requiredScopes ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		if len(requiredScopes) == 0 {
			c.Next()
			return
		}

		scopeSet := GetServiceScopes(c)

		for _, required := range requiredScopes {
			if _, ok := scopeSet[required]; !ok {
				c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
					"error":          "insufficient_scope",
					"required_scope": required,
					"service_slug":   serviceSlugFromCtx(c),
					"granted_scopes": scopeStringFromCtx(c),
				})
				return
			}
		}

		c.Next()
	}
}

// RequireAnyScope returns a Gin middleware that passes when the token carries
// AT LEAST ONE of the specified scopes. Use this when multiple access paths
// exist (e.g. "admin:write" OR "events:publish").
func RequireAnyScope(anyOf ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		if len(anyOf) == 0 {
			c.Next()
			return
		}

		scopeSet := GetServiceScopes(c)
		for _, candidate := range anyOf {
			if _, ok := scopeSet[candidate]; ok {
				c.Next()
				return
			}
		}

		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
			"error":           "insufficient_scope",
			"required_any_of": strings.Join(anyOf, " "),
			"service_slug":    serviceSlugFromCtx(c),
			"granted_scopes":  scopeStringFromCtx(c),
		})
	}
}

// serviceSlugFromCtx is a safe helper used only within scope_enforcement.go
// to avoid a circular dependency between error responses and context reads.
func serviceSlugFromCtx(c *gin.Context) string {
	v, _ := c.Get(CtxKeyServiceSlug)
	s, _ := v.(string)
	return s
}

// scopeStringFromCtx returns the raw scope string from context (for diagnostics).
func scopeStringFromCtx(c *gin.Context) string {
	v, _ := c.Get(CtxKeyServiceScopes)
	s, _ := v.(string)
	return s
}
