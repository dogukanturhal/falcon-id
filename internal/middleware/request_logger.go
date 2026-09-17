// SPDX-License-Identifier: AGPL-3.0-or-later

package middleware

import (
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/pkg/logger"
	"github.com/dogukanturhal/falcon-id/pkg/tracing"
)

// RequestLogger returns a middleware that logs all requests with context
func RequestLogger() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		path := c.Request.URL.Path
		query := c.Request.URL.RawQuery

		c.Next()

		latency := time.Since(start)
		statusCode := c.Writer.Status()
		fields := buildRequestLogFields(c, path, query, statusCode, latency)
		logRequestByStatus(statusCode, fields)
	}
}

// buildRequestLogFields constructs the structured log fields for a completed request.
//
// `client_ip` uses RealClientIP so the field reflects the originating
// user IP from CF-Connecting-IP when the request arrives through the
// Cloudflare Tunnel, falling back to Gin's c.ClientIP() / TCP peer for
// in-cluster and WireGuard-tunneled flows. The raw `cf_connecting_ip`
// and `xff` fields are emitted alongside as a diagnostic — operators
// can use them to verify the edge-to-origin header chain is intact
// when troubleshooting "all requests log the APISIX pod IP" regressions.
func buildRequestLogFields(c *gin.Context, path, query string, statusCode int, latency time.Duration) []zap.Field {
	fields := []zap.Field{
		zap.String("method", c.Request.Method),
		zap.String("path", path),
		zap.Int("status", statusCode),
		zap.Duration("latency", latency),
		zap.String("client_ip", RealClientIP(c)),
		zap.Int("response_size", c.Writer.Size()),
		zap.String("correlation_id", GetCorrelationID(c)),
		zap.String("request_id", GetRequestID(c)),
	}

	// Diagnostic header echoes — included only when present so the
	// log shape stays slim on the dominant in-cluster traffic.
	if cf := c.GetHeader("Cf-Connecting-Ip"); cf != "" {
		fields = append(fields, zap.String("cf_connecting_ip", cf))
	}
	if cc := c.GetHeader("Cf-Ipcountry"); cc != "" {
		fields = append(fields, zap.String("cf_ipcountry", cc))
	}
	if xff := c.GetHeader("X-Forwarded-For"); xff != "" {
		fields = append(fields, zap.String("xff", xff))
	}

	if query != "" {
		fields = append(fields, zap.String("query", query))
	}
	if ua := c.Request.UserAgent(); ua != "" {
		fields = append(fields, zap.String("user_agent", ua))
	}
	if traceID := tracing.GetTraceID(c.Request.Context()); traceID != "" {
		fields = append(fields, zap.String("trace_id", traceID))
	}
	if userIDVal, exists := c.Get("user_id"); exists {
		if userID, ok := userIDVal.(uuid.UUID); ok {
			fields = append(fields, zap.String("user_id", userID.String()))
		}
	}
	if tenantIDVal, exists := c.Get("tenant_id"); exists {
		if tenantID, ok := tenantIDVal.(uuid.UUID); ok {
			fields = append(fields, zap.String("tenant_id", tenantID.String()))
		}
	}
	if len(c.Errors) > 0 {
		fields = append(fields, zap.String("error", c.Errors.String()))
	}

	return fields
}

// logRequestByStatus logs at the appropriate level based on HTTP status code.
func logRequestByStatus(statusCode int, fields []zap.Field) {
	switch {
	case statusCode >= 500:
		logger.Log.Error("Server error", fields...)
	case statusCode >= 400:
		logger.Log.Warn("Client error", fields...)
	case statusCode >= 300:
		logger.Log.Info("Redirect", fields...)
	default:
		logger.Log.Info("Request completed", fields...)
	}
}
