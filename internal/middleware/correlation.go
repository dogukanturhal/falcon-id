// SPDX-License-Identifier: AGPL-3.0-or-later

package middleware

import (
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

const (
	// CorrelationIDHeader is the header name for correlation ID
	CorrelationIDHeader = "X-Correlation-ID"
	// RequestIDHeader is the header name for request ID
	RequestIDHeader = "X-Request-ID"
	// CorrelationIDKey is the context key for correlation ID
	CorrelationIDKey = "correlation_id"
	// RequestIDKey is the context key for request ID
	RequestIDKey = "request_id"
)

// CorrelationID middleware adds or propagates correlation IDs for request tracking
func CorrelationID() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Check for existing correlation ID in headers
		correlationID := c.GetHeader(CorrelationIDHeader)
		if correlationID == "" {
			correlationID = c.GetHeader(RequestIDHeader)
		}
		if correlationID == "" {
			// Generate new correlation ID
			correlationID = uuid.New().String()
		}

		// Generate request ID (always unique per request)
		requestID := uuid.New().String()

		// Store in context
		c.Set(CorrelationIDKey, correlationID)
		c.Set(RequestIDKey, requestID)

		// Set response headers for downstream tracing
		c.Header(CorrelationIDHeader, correlationID)
		c.Header(RequestIDHeader, requestID)

		c.Next()
	}
}

// GetCorrelationID extracts correlation ID from context
func GetCorrelationID(c *gin.Context) string {
	if id, exists := c.Get(CorrelationIDKey); exists {
		if s, ok := id.(string); ok {
			return s
		}
	}
	return ""
}

// GetRequestID extracts request ID from context
func GetRequestID(c *gin.Context) string {
	if id, exists := c.Get(RequestIDKey); exists {
		if s, ok := id.(string); ok {
			return s
		}
	}
	return ""
}
