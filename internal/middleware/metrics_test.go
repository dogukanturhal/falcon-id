// SPDX-License-Identifier: AGPL-3.0-or-later

package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

// buildMetricsRouter returns a router with PrometheusMetrics middleware applied.
func buildMetricsRouter() *gin.Engine {
	_, router := gin.CreateTestContext(httptest.NewRecorder())
	router.Use(PrometheusMetrics())
	router.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})
	router.GET("/api/users", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"users": []interface{}{}})
	})
	router.GET("/api/users/:id", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"user": gin.H{"id": c.Param("id")}})
	})
	return router
}

// TestPrometheusMetrics_DoesNotBlockRequest verifies that the middleware passes
// through to the downstream handler and the correct status code is returned.
func TestPrometheusMetrics_DoesNotBlockRequest(t *testing.T) {
	router := buildMetricsRouter()

	w := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/test", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code,
		"PrometheusMetrics must not block requests")
}

// TestPrometheusMetrics_PassesThroughResponseBody verifies that the response
// body written by the handler is delivered to the client unchanged.
func TestPrometheusMetrics_PassesThroughResponseBody(t *testing.T) {
	router := buildMetricsRouter()

	w := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/test", nil)
	router.ServeHTTP(w, req)

	assert.Contains(t, w.Body.String(), "ok",
		"response body must be passed through to the client")
}

// TestPrometheusMetrics_4xxStatusPassesThrough verifies the middleware does not
// interfere with 4xx responses.
func TestPrometheusMetrics_4xxStatusPassesThrough(t *testing.T) {
	w := httptest.NewRecorder()
	_, router := gin.CreateTestContext(w)
	router.Use(PrometheusMetrics())
	router.GET("/notfound", func(c *gin.Context) {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
	})

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/notfound", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code,
		"4xx responses must be passed through correctly")
}

// TestPrometheusMetrics_5xxStatusPassesThrough verifies the middleware does not
// interfere with 5xx responses.
func TestPrometheusMetrics_5xxStatusPassesThrough(t *testing.T) {
	w := httptest.NewRecorder()
	_, router := gin.CreateTestContext(w)
	router.Use(PrometheusMetrics())
	router.GET("/error", func(c *gin.Context) {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server error"})
	})

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/error", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code,
		"5xx responses must be passed through correctly")
}

// TestPrometheusMetrics_APIPathWithUUID verifies the middleware handles requests
// with UUID path parameters without panicking.
func TestPrometheusMetrics_APIPathWithUUID(t *testing.T) {
	router := buildMetricsRouter()

	w := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/users/550e8400-e29b-41d4-a716-446655440000", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code,
		"middleware must handle UUID path parameters without issues")
}

// ==================== normalizePathForMetrics ====================

// TestNormalizePathForMetrics_TableDriven verifies that the path normalization
// helper replaces UUIDs and numeric IDs with the :id placeholder.
func TestNormalizePathForMetrics_TableDriven(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"/api/users", "/api/users"},
		{"/api/users/550e8400-e29b-41d4-a716-446655440000", "/api/users/:id"},
		{"/api/tenants/AAAABBBB-CCCC-DDDD-EEEE-FFFFAAAABBBB/users", "/api/tenants/:id/users"},
		{"/api/items/42", "/api/items/:id"},
		{"/api/items/42/details", "/api/items/:id/details"},
		{"/health", "/health"},
		{"/api/no-ids-here", "/api/no-ids-here"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := normalizePathForMetrics(tt.input)
			assert.Equal(t, tt.expected, got,
				"normalizePathForMetrics(%q)", tt.input)
		})
	}
}

// ==================== isUUID / isNumeric / normalizePathSegments ====================

// TestIsUUID_TableDriven verifies the UUID check helper.
func TestIsUUID_TableDriven(t *testing.T) {
	tests := []struct {
		input string
		valid bool
	}{
		{"550e8400-e29b-41d4-a716-446655440000", true},
		{"AAAABBBB-CCCC-DDDD-EEEE-FFFFAAAABBBB", true},
		{"not-a-uuid", false},
		{"", false},
		{"12345678-1234-1234-1234-123456789abc", true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			assert.Equal(t, tt.valid, isUUID(tt.input))
		})
	}
}

// TestIsNumeric_TableDriven verifies the numeric check helper.
func TestIsNumeric_TableDriven(t *testing.T) {
	tests := []struct {
		input   string
		numeric bool
	}{
		{"42", true},
		{"0", true},
		{"12345", true},
		{"", false},
		{"abc", false},
		{"12abc", false},
		{"1.5", false},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			assert.Equal(t, tt.numeric, isNumeric(tt.input))
		})
	}
}

// TestNormalizePathSegments_TableDriven verifies that the segment-level
// normalizer replaces UUID and numeric segments with :id.
func TestNormalizePathSegments_TableDriven(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"/api/users/42", "/api/users/:id"},
		{"/api/users/550e8400-e29b-41d4-a716-446655440000", "/api/users/:id"},
		{"/api/users", "/api/users"},
		{"/api/tenants/42/users/550e8400-e29b-41d4-a716-446655440000", "/api/tenants/:id/users/:id"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := normalizePathSegments(tt.input)
			assert.Equal(t, tt.expected, got,
				"normalizePathSegments(%q)", tt.input)
		})
	}
}
