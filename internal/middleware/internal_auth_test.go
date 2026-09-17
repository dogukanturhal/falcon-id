// SPDX-License-Identifier: AGPL-3.0-or-later

package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testInternalAPIKey = "test-secret-key-12345"

// ==================== InternalServiceAuth ====================

func TestInternalServiceAuth_ValidKey_SetsContext(t *testing.T) {
	m := NewInternalAuthMiddleware(testInternalAPIKey)

	w := httptest.NewRecorder()
	c, router := gin.CreateTestContext(w)
	router.Use(m.InternalServiceAuth())
	router.GET("/test", func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	c.Request = httptest.NewRequestWithContext(context.Background(), "GET", "/test", nil)
	c.Request.Header.Set("X-Internal-Key", testInternalAPIKey)
	router.ServeHTTP(w, c.Request)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestInternalServiceAuth_ValidKey_SetsIsInternalService(t *testing.T) {
	m := NewInternalAuthMiddleware(testInternalAPIKey)

	var isInternal bool
	var exists bool

	w := httptest.NewRecorder()
	_, router := gin.CreateTestContext(w)
	router.Use(m.InternalServiceAuth())
	router.GET("/test", func(c *gin.Context) {
		val, ok := c.Get("is_internal_service")
		exists = ok
		if ok {
			isInternal, _ = val.(bool)
		}
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequestWithContext(context.Background(), "GET", "/test", nil)
	req.Header.Set("X-Internal-Key", testInternalAPIKey)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	require.True(t, exists, "is_internal_service should be set")
	assert.True(t, isInternal, "is_internal_service should be true")
}

func TestInternalServiceAuth_InvalidKey_Returns401(t *testing.T) {
	m := NewInternalAuthMiddleware(testInternalAPIKey)

	w := httptest.NewRecorder()
	_, router := gin.CreateTestContext(w)
	router.Use(m.InternalServiceAuth())
	router.GET("/test", func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequestWithContext(context.Background(), "GET", "/test", nil)
	req.Header.Set("X-Internal-Key", "wrong-key")
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestInternalServiceAuth_NoKey_PassesThrough(t *testing.T) {
	m := NewInternalAuthMiddleware(testInternalAPIKey)

	w := httptest.NewRecorder()
	_, router := gin.CreateTestContext(w)
	router.Use(m.InternalServiceAuth())
	router.GET("/test", func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequestWithContext(context.Background(), "GET", "/test", nil)
	// No auth headers at all
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code,
		"requests without any key should pass through (non-blocking middleware)")
}

// SECURITY: This test ensures the X-Service-Name + X-API-Key fallback is removed.
// An attacker who sends X-Service-Name: anything + X-API-Key: <valid-key> should NOT
// be authenticated as an internal service.
func TestInternalServiceAuth_XServiceNameWithXAPIKey_MustNotAuthenticate(t *testing.T) {
	m := NewInternalAuthMiddleware(testInternalAPIKey)

	var isInternalSet bool

	w := httptest.NewRecorder()
	_, router := gin.CreateTestContext(w)
	router.Use(m.InternalServiceAuth())
	router.GET("/test", func(c *gin.Context) {
		_, isInternalSet = c.Get("is_internal_service")
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequestWithContext(context.Background(), "GET", "/test", nil)
	// Attacker spoofs X-Service-Name and provides a key via X-API-Key
	// This should NOT be accepted — only X-Internal-Key is valid.
	req.Header.Set("X-Service-Name", "attacker-service")
	req.Header.Set("X-API-Key", testInternalAPIKey)
	router.ServeHTTP(w, req)

	// The request should pass through (non-blocking middleware) but
	// is_internal_service should NOT be set.
	assert.False(t, isInternalSet,
		"SECURITY: X-Service-Name + X-API-Key must NOT set is_internal_service. "+
			"Only X-Internal-Key should be accepted.")
}

// Ensure that X-API-Key alone (without X-Internal-Key) does not authenticate.
func TestInternalServiceAuth_XAPIKeyAlone_MustNotAuthenticate(t *testing.T) {
	m := NewInternalAuthMiddleware(testInternalAPIKey)

	var isInternalSet bool

	w := httptest.NewRecorder()
	_, router := gin.CreateTestContext(w)
	router.Use(m.InternalServiceAuth())
	router.GET("/test", func(c *gin.Context) {
		_, isInternalSet = c.Get("is_internal_service")
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequestWithContext(context.Background(), "GET", "/test", nil)
	req.Header.Set("X-API-Key", testInternalAPIKey)
	router.ServeHTTP(w, req)

	assert.False(t, isInternalSet,
		"SECURITY: X-API-Key alone must NOT set is_internal_service")
}

func TestInternalServiceAuth_CustomServiceName_SetInContext(t *testing.T) {
	m := NewInternalAuthMiddleware(testInternalAPIKey)

	var serviceName string

	w := httptest.NewRecorder()
	_, router := gin.CreateTestContext(w)
	router.Use(m.InternalServiceAuth())
	router.GET("/test", func(c *gin.Context) {
		val, _ := c.Get("service_name")
		serviceName, _ = val.(string)
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequestWithContext(context.Background(), "GET", "/test", nil)
	req.Header.Set("X-Internal-Key", testInternalAPIKey)
	req.Header.Set("X-Service-Name", "billing-service")
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "billing-service", serviceName)
}

func TestInternalServiceAuth_DefaultServiceName(t *testing.T) {
	m := NewInternalAuthMiddleware(testInternalAPIKey)

	var serviceName string

	w := httptest.NewRecorder()
	_, router := gin.CreateTestContext(w)
	router.Use(m.InternalServiceAuth())
	router.GET("/test", func(c *gin.Context) {
		val, _ := c.Get("service_name")
		serviceName, _ = val.(string)
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequestWithContext(context.Background(), "GET", "/test", nil)
	req.Header.Set("X-Internal-Key", testInternalAPIKey)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "internal-service", serviceName,
		"service_name should default to 'internal-service' when X-Service-Name is empty")
}

func TestInternalServiceAuth_NoConfiguredKey_Returns503(t *testing.T) {
	m := NewInternalAuthMiddleware("") // No key configured

	w := httptest.NewRecorder()
	_, router := gin.CreateTestContext(w)
	router.Use(m.InternalServiceAuth())
	router.GET("/test", func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequestWithContext(context.Background(), "GET", "/test", nil)
	req.Header.Set("X-Internal-Key", "some-key")
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
}

// ==================== RequireInternalAuth ====================

func TestRequireInternalAuth_WithoutPriorAuth_Returns401(t *testing.T) {
	m := NewInternalAuthMiddleware(testInternalAPIKey)

	w := httptest.NewRecorder()
	_, router := gin.CreateTestContext(w)
	router.Use(m.RequireInternalAuth())
	router.GET("/test", func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequestWithContext(context.Background(), "GET", "/test", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestRequireInternalAuth_WithValidXInternalKey_Authenticates(t *testing.T) {
	// SECURITY: RequireInternalAuth must only accept X-Internal-Key, never X-API-Key.
	m := NewInternalAuthMiddleware(testInternalAPIKey)

	w := httptest.NewRecorder()
	_, router := gin.CreateTestContext(w)
	router.Use(m.RequireInternalAuth())
	router.GET("/test", func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequestWithContext(context.Background(), "GET", "/test", nil)
	req.Header.Set("X-Internal-Key", testInternalAPIKey)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestRequireInternalAuth_WithXAPIKey_MustReturn401(t *testing.T) {
	// SECURITY: X-API-Key must NOT grant internal auth — only X-Internal-Key is accepted.
	m := NewInternalAuthMiddleware(testInternalAPIKey)

	w := httptest.NewRecorder()
	_, router := gin.CreateTestContext(w)
	router.Use(m.RequireInternalAuth())
	router.GET("/test", func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequestWithContext(context.Background(), "GET", "/test", nil)
	req.Header.Set("X-API-Key", testInternalAPIKey)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code,
		"SECURITY: X-API-Key must not satisfy RequireInternalAuth; use X-Internal-Key")
}
