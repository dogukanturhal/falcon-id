// SPDX-License-Identifier: AGPL-3.0-or-later

package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/pkg/logger"
)

func init() {
	// Ensure a logger is available for request_logger.go. If it is already
	// initialised by auth_tenant_scoped_test.go (package-level init), this
	// assignment is a no-op.
	if logger.Log == nil {
		logger.Log = zap.NewNop()
	}
}

// buildRequestLoggerRouter returns a Gin router with RequestLogger applied.
func buildRequestLoggerRouter(statusCode int) *gin.Engine {
	_, router := gin.CreateTestContext(httptest.NewRecorder())
	router.Use(RequestLogger())
	router.GET("/test", func(c *gin.Context) {
		c.Status(statusCode)
	})
	router.GET("/api/data", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})
	router.GET("/fail/client", func(c *gin.Context) {
		c.Status(http.StatusBadRequest)
	})
	router.GET("/fail/server", func(c *gin.Context) {
		c.Status(http.StatusInternalServerError)
	})
	return router
}

// TestRequestLogger_PassesThrough verifies the middleware does not block the
// request and the downstream handler runs normally.
func TestRequestLogger_PassesThrough(t *testing.T) {
	router := buildRequestLoggerRouter(http.StatusOK)

	w := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/test", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code,
		"RequestLogger must not block requests")
}

// TestRequestLogger_CapturesCorrectStatus verifies that the response status
// visible to the logger reflects what the handler wrote.
func TestRequestLogger_CapturesCorrectStatus(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		expected int
	}{
		{"200 OK", "/test", http.StatusOK},
		{"400 Bad Request", "/fail/client", http.StatusBadRequest},
		{"500 Internal Server Error", "/fail/server", http.StatusInternalServerError},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			router := buildRequestLoggerRouter(tt.expected)

			w := httptest.NewRecorder()
			req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, tt.path, nil)
			router.ServeHTTP(w, req)

			assert.Equal(t, tt.expected, w.Code,
				"response status must match handler output")
		})
	}
}

// TestRequestLogger_WithQueryString verifies the middleware does not interfere
// with requests that include query strings.
func TestRequestLogger_WithQueryString(t *testing.T) {
	router := buildRequestLoggerRouter(http.StatusOK)

	w := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/test?foo=bar&baz=qux", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

// TestRequestLogger_WithUserAgent verifies the middleware does not interfere
// when a User-Agent header is present.
func TestRequestLogger_WithUserAgent(t *testing.T) {
	router := buildRequestLoggerRouter(http.StatusOK)

	w := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/test", nil)
	req.Header.Set("User-Agent", "test-agent/1.0")
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

// TestRequestLogger_WithCorrelationIDContext verifies that when a correlation ID
// is in the context (set by CorrelationID middleware) the logger middleware still
// completes without error.
func TestRequestLogger_WithCorrelationIDContext(t *testing.T) {
	w := httptest.NewRecorder()
	_, router := gin.CreateTestContext(w)

	// Chain CorrelationID before RequestLogger so context values are populated.
	router.Use(CorrelationID())
	router.Use(RequestLogger())
	router.GET("/test", func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/test", nil)
	req.Header.Set(CorrelationIDHeader, "test-correlation-id-value")
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

// TestRequestLogger_JSONResponseBodyPassesThrough verifies the response body
// written by the downstream handler is available to the client unmodified.
func TestRequestLogger_JSONResponseBodyPassesThrough(t *testing.T) {
	router := buildRequestLoggerRouter(http.StatusOK)

	w := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/data", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "ok")
}
