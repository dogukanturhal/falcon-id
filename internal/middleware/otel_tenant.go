// SPDX-License-Identifier: AGPL-3.0-or-later

package middleware

import (
	"fmt"

	"github.com/gin-gonic/gin"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

// OTelTenantMiddleware enriches the current OpenTelemetry span with tenant,
// realm, and user identifiers extracted from the Gin context.
//
// This middleware must be registered AFTER the auth middleware so that the
// "tenant_id", "realm_id", and "user_id" keys are already present in the
// context before this handler runs.
//
// The existing OTelTracing middleware (middleware/tracing.go) also sets
// tenant.id and user.id, but it runs BEFORE authentication meaning the values
// are only available on the span's post-Next() update.  This middleware
// provides an explicit, well-ordered enrichment point that is easy to compose
// on route groups that require authentication.
func OTelTenantMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		span := trace.SpanFromContext(c.Request.Context())

		if tenantID, exists := c.Get("tenant_id"); exists {
			span.SetAttributes(attribute.String("tenant.id", fmt.Sprintf("%v", tenantID)))
		}
		if realmID, exists := c.Get("realm_id"); exists {
			span.SetAttributes(attribute.String("realm.id", fmt.Sprintf("%v", realmID)))
		}
		if userID, exists := c.Get("user_id"); exists {
			span.SetAttributes(attribute.String("user.id", fmt.Sprintf("%v", userID)))
		}

		c.Next()
	}
}
