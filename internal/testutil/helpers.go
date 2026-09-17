// SPDX-License-Identifier: AGPL-3.0-or-later

// Package testutil provides test helper utilities.
package testutil

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dogukanturhal/falcon-id/internal/shared/auth"
	"github.com/dogukanturhal/falcon-id/pkg/config"
)

func init() {
	gin.SetMode(gin.TestMode)
}

// SetupGinTestContext creates a gin test context with an httptest recorder.
// Returns the context, recorder, and router for use in handler/middleware tests.
func SetupGinTestContext(method, path string) (*gin.Context, *httptest.ResponseRecorder, *gin.Engine) {
	w := httptest.NewRecorder()
	c, router := gin.CreateTestContext(w)
	req := httptest.NewRequestWithContext(context.Background(), method, path, nil)
	c.Request = req
	return c, w, router
}

// SetupGinTestContextWithBody creates a gin test context with a request body.
func SetupGinTestContextWithBody(method, path, body string) (*gin.Context, *httptest.ResponseRecorder, *gin.Engine) {
	w := httptest.NewRecorder()
	c, router := gin.CreateTestContext(w)
	req := httptest.NewRequestWithContext(context.Background(), method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	c.Request = req
	return c, w, router
}

// SetCurrentUser injects a CurrentUser into the gin context, simulating authenticated requests.
func SetCurrentUser(c *gin.Context, user *auth.CurrentUser) {
	c.Set(auth.CurrentUserKey, user)
	c.Set(auth.UserIDKey, user.ID)
	c.Set(auth.TenantIDKey, user.TenantID)
	c.Set(auth.SessionIDKey, user.SessionID)
	c.Set(auth.AuthMethodKey, user.AuthMethod)
}

// SetTenantID injects a tenant ID into the gin context.
func SetTenantID(c *gin.Context, tenantID uuid.UUID) {
	c.Set(auth.TenantIDKey, tenantID)
}

// NewTestUser creates a standard test user with common defaults.
func NewTestUser(tenantID uuid.UUID) *auth.CurrentUser {
	return &auth.CurrentUser{
		ID:          uuid.New(),
		TenantID:    tenantID,
		Username:    "testuser",
		Email:       "test@example.com",
		Roles:       []string{"user"},
		Permissions: []string{"core:users:read"},
		SessionID:   uuid.New(),
		AuthMethod:  auth.AuthMethodJWT,
	}
}

// NewTestAdmin creates a test admin user with broad permissions.
func NewTestAdmin(tenantID uuid.UUID) *auth.CurrentUser {
	return &auth.CurrentUser{
		ID:       uuid.New(),
		TenantID: tenantID,
		Username: "admin",
		Email:    "admin@example.com",
		Roles:    []string{"admin", "user"},
		Permissions: []string{
			"*",
		},
		SessionID:  uuid.New(),
		AuthMethod: auth.AuthMethodJWT,
	}
}

// NewTestPlatformAdmin creates a test platform admin user.
func NewTestPlatformAdmin() *auth.CurrentUser {
	return &auth.CurrentUser{
		ID:       uuid.New(),
		TenantID: uuid.New(),
		Username: "platform-admin",
		Email:    "platform@example.com",
		Roles:    []string{"platform_admin", "admin"},
		Permissions: []string{
			"*",
		},
		SessionID:  uuid.New(),
		AuthMethod: auth.AuthMethodJWT,
	}
}

// NewTestConfig creates a standard config suitable for tests.
func NewTestConfig() *config.Config {
	return &config.Config{
		Environment:            "test",
		ServiceName:            "falcon-id-test",
		ServicePort:            "8080",
		JWTSecret:              "test-jwt-secret-at-least-32-chars-long!!",
		JWTIssuer:              "falcon-id-test",
		JWTHMACFallbackEnabled: true, // allow HS256 tokens in tests
		AccessTokenExpiry:      15 * time.Minute,
		SessionExpiry:          24 * time.Hour,
		PasswordMinLength:      8,
		PasswordRequireUpper:   true,
		PasswordRequireLower:   true,
		PasswordRequireDigit:   true,
		PasswordRequireSpecial: false,
		MaxLoginAttempts:       5,
		LockoutDuration:        15 * time.Minute,
		RateLimitRequests:      100,
		RateLimitWindow:        time.Minute,
		EncryptionKey:          "test-encryption-key-32-bytes!!!!", // 32 bytes for AES-256
		TokenHashSalt:          "test-token-hash-salt",
	}
}

// AssertJSONError asserts that the response has the expected status code and
// the JSON body contains an "error" field matching errorContains.
func AssertJSONError(t *testing.T, w *httptest.ResponseRecorder, statusCode int, errorContains string) {
	t.Helper()
	assert.Equal(t, statusCode, w.Code)

	var body map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &body)
	require.NoError(t, err, "response body should be valid JSON")

	errField, ok := body["error"]
	require.True(t, ok, "response should contain 'error' field")

	errStr, ok := errField.(string)
	require.True(t, ok, "error field should be a string")
	assert.Contains(t, strings.ToLower(errStr), strings.ToLower(errorContains),
		"error message should contain %q", errorContains)
}

// AssertJSONSuccess asserts that the response has the expected status code and valid JSON.
func AssertJSONSuccess(t *testing.T, w *httptest.ResponseRecorder, statusCode int) map[string]interface{} {
	t.Helper()
	assert.Equal(t, statusCode, w.Code)

	var body map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &body)
	require.NoError(t, err, "response body should be valid JSON")
	return body
}

// JSONBody marshals v to JSON string suitable for request bodies.
func JSONBody(t *testing.T, v interface{}) string {
	t.Helper()
	data, err := json.Marshal(v)
	require.NoError(t, err)
	return string(data)
}

// StringPtr is an exported identifier.
func StringPtr(s string) *string { return &s }

// TimePtr is an exported function.
func TimePtr(t time.Time) *time.Time { return &t }

// UUIDPtr is an exported function.
func UUIDPtr(u uuid.UUID) *uuid.UUID { return &u }

// BoolPtr is an exported function.
func BoolPtr(b bool) *bool { return &b }

// IntPtr is an exported function.
func IntPtr(i int) *int { return &i }

// Int64Ptr is an exported function.
func Int64Ptr(i int64) *int64 { return &i }

// Float64Ptr is an exported function.
func Float64Ptr(f float64) *float64 { return &f }

// --- HTTP test helpers ---

// PerformRequest sends an HTTP request through the gin router and returns the recorder.
func PerformRequest(router *gin.Engine, method, path string, body string, headers map[string]string) *httptest.ResponseRecorder {
	var req *http.Request
	if body != "" {
		req = httptest.NewRequestWithContext(context.Background(), method, path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
	} else {
		req = httptest.NewRequestWithContext(context.Background(), method, path, nil)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	return w
}

// PerformAuthenticatedRequest sends a request with a Bearer token.
func PerformAuthenticatedRequest(router *gin.Engine, method, path, body, token string) *httptest.ResponseRecorder {
	return PerformRequest(router, method, path, body, map[string]string{
		"Authorization": "Bearer " + token,
	})
}
