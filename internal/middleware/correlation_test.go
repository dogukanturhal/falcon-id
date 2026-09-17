// SPDX-License-Identifier: AGPL-3.0-or-later

package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// buildCorrelationRouter returns a router with CorrelationID middleware and a
// handler that exposes context values so tests can inspect them.
func buildCorrelationRouter() (*gin.Engine, *string, *string) {
	var gotCorrelationID, gotRequestID string

	_, router := gin.CreateTestContext(httptest.NewRecorder())
	router.Use(CorrelationID())
	router.GET("/test", func(c *gin.Context) {
		gotCorrelationID = GetCorrelationID(c)
		gotRequestID = GetRequestID(c)
		c.Status(http.StatusOK)
	})

	return router, &gotCorrelationID, &gotRequestID
}

// TestCorrelationID_PropagatesToResponse verifies that a supplied X-Correlation-ID
// header is echoed back on the response.
func TestCorrelationID_PropagatesToResponse(t *testing.T) {
	router, _, _ := buildCorrelationRouter()

	const suppliedID = "550e8400-e29b-41d4-a716-446655440000"

	w := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/test", nil)
	req.Header.Set(CorrelationIDHeader, suppliedID)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, suppliedID, w.Header().Get(CorrelationIDHeader),
		"supplied correlation ID must be echoed in the response header")
}

// TestCorrelationID_PropagatesToContext verifies that a supplied correlation ID
// is stored in the Gin context and retrievable via GetCorrelationID.
func TestCorrelationID_PropagatesToContext(t *testing.T) {
	var capturedID string

	w := httptest.NewRecorder()
	_, router := gin.CreateTestContext(w)
	router.Use(CorrelationID())
	router.GET("/test", func(c *gin.Context) {
		capturedID = GetCorrelationID(c)
		c.Status(http.StatusOK)
	})

	const suppliedID = "550e8400-e29b-41d4-a716-446655440000"
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/test", nil)
	req.Header.Set(CorrelationIDHeader, suppliedID)
	router.ServeHTTP(w, req)

	assert.Equal(t, suppliedID, capturedID,
		"correlation ID must be stored in context")
}

// TestCorrelationID_GeneratesUUIDWhenAbsent verifies that when no correlation ID
// is present in the request, the middleware generates a valid UUID and sets it
// on both the response header and the context.
func TestCorrelationID_GeneratesUUIDWhenAbsent(t *testing.T) {
	var capturedContextID string

	w := httptest.NewRecorder()
	_, router := gin.CreateTestContext(w)
	router.Use(CorrelationID())
	router.GET("/test", func(c *gin.Context) {
		capturedContextID = GetCorrelationID(c)
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/test", nil)
	// No X-Correlation-ID header provided.
	router.ServeHTTP(w, req)

	responseID := w.Header().Get(CorrelationIDHeader)
	require.NotEmpty(t, responseID, "a correlation ID must be generated and set on the response")

	_, err := uuid.Parse(responseID)
	assert.NoError(t, err, "auto-generated correlation ID must be a valid UUID")

	assert.Equal(t, responseID, capturedContextID,
		"context correlation ID must match the response header value")
}

// TestCorrelationID_FallsBackToRequestIDHeader verifies that X-Request-ID is used
// as correlation ID when X-Correlation-ID is absent.
func TestCorrelationID_FallsBackToRequestIDHeader(t *testing.T) {
	var capturedContextID string

	w := httptest.NewRecorder()
	_, router := gin.CreateTestContext(w)
	router.Use(CorrelationID())
	router.GET("/test", func(c *gin.Context) {
		capturedContextID = GetCorrelationID(c)
		c.Status(http.StatusOK)
	})

	const requestID = "aaaabbbb-cccc-dddd-eeee-ffffaaaabbbb"
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/test", nil)
	req.Header.Set(RequestIDHeader, requestID)
	router.ServeHTTP(w, req)

	assert.Equal(t, requestID, capturedContextID,
		"X-Request-ID must be used as the correlation ID when X-Correlation-ID is absent")
	assert.Equal(t, requestID, w.Header().Get(CorrelationIDHeader))
}

// TestCorrelationID_AlwaysGeneratesUniqueRequestID verifies that a fresh
// X-Request-ID (always unique per request) is set regardless of whether a
// correlation ID was supplied.
func TestCorrelationID_AlwaysGeneratesUniqueRequestID(t *testing.T) {
	ids := make(map[string]struct{})

	for i := 0; i < 3; i++ {
		w := httptest.NewRecorder()
		_, router := gin.CreateTestContext(w)
		router.Use(CorrelationID())
		router.GET("/test", func(c *gin.Context) {
			c.Status(http.StatusOK)
		})

		req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/test", nil)
		router.ServeHTTP(w, req)

		rid := w.Header().Get(RequestIDHeader)
		require.NotEmpty(t, rid)

		_, err := uuid.Parse(rid)
		assert.NoError(t, err, "X-Request-ID must be a valid UUID")

		ids[rid] = struct{}{}
	}

	assert.Len(t, ids, 3, "each request must receive a unique X-Request-ID")
}

// TestGetCorrelationID_ReturnsEmptyWhenNotSet verifies the helper returns an
// empty string when no correlation ID is in the context.
func TestGetCorrelationID_ReturnsEmptyWhenNotSet(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	// No middleware applied — context is empty.
	assert.Equal(t, "", GetCorrelationID(c))
}

// TestGetRequestID_ReturnsEmptyWhenNotSet verifies the helper returns an empty
// string when no request ID is in the context.
func TestGetRequestID_ReturnsEmptyWhenNotSet(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	assert.Equal(t, "", GetRequestID(c))
}

// TestCorrelationID_DoesNotBlockRequest confirms the middleware calls Next()
// and the downstream handler executes normally.
func TestCorrelationID_DoesNotBlockRequest(t *testing.T) {
	w := httptest.NewRecorder()
	_, router := gin.CreateTestContext(w)
	router.Use(CorrelationID())
	router.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/test", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}
