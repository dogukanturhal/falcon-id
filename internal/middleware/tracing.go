// SPDX-License-Identifier: AGPL-3.0-or-later

package middleware

import (
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"

	"github.com/dogukanturhal/falcon-id/pkg/tracing"
)

const (
	// TracerName is an exported identifier.
	TracerName = "iam-http-server"
)

// OTelTracing returns a middleware that creates spans for HTTP requests
func OTelTracing() gin.HandlerFunc {
	propagator := otel.GetTextMapPropagator()

	return func(c *gin.Context) {
		ctx := propagator.Extract(c.Request.Context(), propagation.HeaderCarrier(c.Request.Header))

		ctx, span := tracing.StartSpan(ctx, resolveSpanName(c),
			trace.WithSpanKind(trace.SpanKindServer),
			trace.WithAttributes(
				attribute.String("http.method", c.Request.Method),
				attribute.String("http.url", c.Request.URL.String()),
				attribute.String("http.target", c.Request.URL.Path),
				attribute.String("http.host", c.Request.Host),
				attribute.String("http.user_agent", c.Request.UserAgent()),
				attribute.String("http.client_ip", RealClientIP(c)),
			),
		)
		defer span.End()

		setSpanCorrelationIDs(c, span)
		c.Request = c.Request.WithContext(ctx)

		c.Next()

		setSpanResponseAttributes(c, span)
		propagator.Inject(ctx, propagation.HeaderCarrier(c.Writer.Header()))
	}
}

// resolveSpanName returns "METHOD /path" using the Gin full path when available.
func resolveSpanName(c *gin.Context) string {
	path := c.FullPath()
	if path == "" {
		path = normalizePathForMetrics(c.Request.URL.Path)
	}
	return c.Request.Method + " " + path
}

// setSpanCorrelationIDs adds the correlation ID and request ID to the span if they are present.
func setSpanCorrelationIDs(c *gin.Context, span trace.Span) {
	if correlationID := c.GetString(CorrelationIDKey); correlationID != "" {
		span.SetAttributes(attribute.String("correlation_id", correlationID))
	}
	if requestID := c.GetString(RequestIDKey); requestID != "" {
		span.SetAttributes(attribute.String("request_id", requestID))
	}
}

// setSpanResponseAttributes records response status, size, error flag, and user/tenant identity.
func setSpanResponseAttributes(c *gin.Context, span trace.Span) {
	statusCode := c.Writer.Status()
	span.SetAttributes(
		attribute.Int("http.status_code", statusCode),
		attribute.Int("http.response_content_length", c.Writer.Size()),
	)
	if statusCode >= 400 {
		span.SetAttributes(attribute.Bool("error", true))
	}
	if userIDVal, exists := c.Get("user_id"); exists {
		if userID, ok := userIDVal.(uuid.UUID); ok {
			span.SetAttributes(attribute.String("user.id", userID.String()))
		}
	}
	if tenantIDVal, exists := c.Get("tenant_id"); exists {
		if tenantID, ok := tenantIDVal.(uuid.UUID); ok {
			span.SetAttributes(attribute.String("tenant.id", tenantID.String()))
		}
	}
}
