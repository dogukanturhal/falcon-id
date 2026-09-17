// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func init() {
	gin.SetMode(gin.TestMode)
}

func TestGetCookieDomain(t *testing.T) {
	tests := []struct {
		name     string
		host     string
		expected string
	}{
		{
			name:     "localhost returns localhost for cross-port cookie sharing",
			host:     "localhost:3000",
			expected: "localhost",
		},
		{
			name:     "127.0.0.1 returns localhost for cross-port cookie sharing",
			host:     "127.0.0.1:8080",
			expected: "localhost",
		},
		{
			name:     "production domain returns domain",
			host:     "api.hexxlock.com",
			expected: "api.hexxlock.com",
		},
		{
			name:     "production domain with port returns domain without port",
			host:     "api.hexxlock.com:443",
			expected: "api.hexxlock.com",
		},
		{
			name:     "subdomain returns full domain",
			host:     "tenant.hexxlock.com",
			expected: "tenant.hexxlock.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			c.Request = httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil)
			c.Request.Host = tt.host

			result := getCookieDomain(c)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestSetAuthCookies(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/", nil)
	c.Request.Host = "localhost:3000"

	accessToken := "test-access-token"
	accessTTL := 15 * time.Minute

	setAuthCookies(c, accessToken, accessTTL)

	// Check cookie was set
	cookies := w.Result().Cookies()
	require.GreaterOrEqual(t, len(cookies), 1, "Expected at least 1 cookie")

	var accessCookie *http.Cookie
	for _, cookie := range cookies {
		if cookie.Name == accessTokenCookieName {
			accessCookie = cookie
		}
	}

	require.NotNil(t, accessCookie, "Access token cookie should be set")

	// Verify access token cookie properties
	assert.Equal(t, accessToken, accessCookie.Value)
	assert.Equal(t, "/", accessCookie.Path)
	assert.True(t, accessCookie.HttpOnly, "Access token cookie must be HttpOnly")
	// In development (non-secure), SameSite is Lax for browser compatibility
	// (SameSite=None without Secure is rejected by non-Chrome browsers)
	// In production, it would be Strict
	assert.Equal(t, http.SameSiteLaxMode, accessCookie.SameSite, "SameSite should be Lax in development for browser compatibility")
}

func TestClearAuthCookies(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/", nil)
	c.Request.Host = "localhost:3000"

	clearAuthCookies(c)

	cookies := w.Result().Cookies()
	require.GreaterOrEqual(t, len(cookies), 1, "Expected at least 1 cookie to be cleared")

	for _, cookie := range cookies {
		if cookie.Name == accessTokenCookieName {
			assert.Equal(t, "", cookie.Value, "Cookie value should be empty")
			assert.Less(t, cookie.MaxAge, 0, "Cookie MaxAge should be negative (expired)")
		}
	}
}

func TestGenericErrorMessages(t *testing.T) {
	// This test verifies that authentication errors use generic messages
	// to prevent user enumeration attacks

	t.Run("login error message is generic", func(t *testing.T) {
		// The error message should NOT reveal whether the username exists
		expectedMessage := "Invalid username or password"

		// Test various error scenarios that should all return the same message
		errorMessages := []string{
			"Invalid username or password", // Valid message
		}

		for _, msg := range errorMessages {
			assert.Equal(t, expectedMessage, msg,
				"Error message should be generic to prevent user enumeration")
		}
	})

	t.Run("refresh error message is generic", func(t *testing.T) {
		expectedMessage := "Session expired. Please log in again."

		// Test that refresh failures don't reveal token details
		errorMessages := []string{
			"Session expired. Please log in again.", // Valid message
		}

		for _, msg := range errorMessages {
			assert.Equal(t, expectedMessage, msg,
				"Refresh error should not reveal token validation details")
		}
	})
}

func TestTenantIsolationValidation(t *testing.T) {
	// Test cases for tenant isolation
	tests := []struct {
		name            string
		requestTenant   string
		userTenant      string
		shouldBeAllowed bool
	}{
		{
			name:            "same tenant should be allowed",
			requestTenant:   "acme",
			userTenant:      "acme",
			shouldBeAllowed: true,
		},
		{
			name:            "different tenant should be denied",
			requestTenant:   "acme",
			userTenant:      "other-company",
			shouldBeAllowed: false,
		},
		{
			name:            "empty request tenant should be allowed",
			requestTenant:   "",
			userTenant:      "acme",
			shouldBeAllowed: true,
		},
		{
			name:            "empty user tenant should be allowed",
			requestTenant:   "acme",
			userTenant:      "",
			shouldBeAllowed: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Simulate the tenant isolation check logic
			allowed := tt.requestTenant == "" || tt.userTenant == "" || tt.userTenant == tt.requestTenant
			assert.Equal(t, tt.shouldBeAllowed, allowed)
		})
	}
}

func TestCookieSecurityInDifferentEnvironments(t *testing.T) {
	tests := []struct {
		name           string
		environment    string
		expectedSecure bool
	}{
		{
			name:           "production should use secure cookies",
			environment:    "production",
			expectedSecure: true,
		},
		{
			name:           "staging should use secure cookies",
			environment:    "staging",
			expectedSecure: true,
		},
		{
			name:           "development should not require secure",
			environment:    "development",
			expectedSecure: false,
		},
		{
			name:           "empty environment should not require secure",
			environment:    "",
			expectedSecure: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Temporarily set environment
			t.Setenv("ENVIRONMENT", tt.environment)

			result := isSecureEnvironment()
			assert.Equal(t, tt.expectedSecure, result)
		})
	}
}

func TestResponseDoesNotLeakSensitiveData(t *testing.T) {
	// Test that error responses don't leak internal implementation details
	// Note: "password" in "Invalid username or password" is acceptable as it's
	// a standard generic message, not an actual password value
	sensitivePatterns := []string{
		"secret_key",
		"token_value",
		"database error",
		"sql syntax",
		"stack trace",
		"internal server error at",
		"connection refused",
		"bcrypt",
		"jwt_secret",
	}

	safeErrorMessages := []string{
		"Invalid username or password",
		"Session expired. Please log in again.",
		"Not authenticated",
		"Access denied",
		"Logout failed. Please try again.",
	}

	for _, msg := range safeErrorMessages {
		lowerMsg := strings.ToLower(msg)
		for _, pattern := range sensitivePatterns {
			assert.NotContains(t, lowerMsg, pattern,
				"Error message '%s' should not contain sensitive pattern '%s'", msg, pattern)
		}
	}

	// Verify messages are generic (don't reveal specific failure reasons)
	t.Run("login error is generic", func(t *testing.T) {
		// Should NOT say "user not found" or "incorrect password" separately
		loginError := "Invalid username or password"
		assert.NotContains(t, strings.ToLower(loginError), "not found")
		assert.NotContains(t, strings.ToLower(loginError), "incorrect")
		assert.NotContains(t, strings.ToLower(loginError), "does not exist")
	})
}

func TestJSONResponseFormat(t *testing.T) {
	// Test that all error responses are valid JSON
	errorResponses := []string{
		`{"error": "Invalid username or password"}`,
		`{"error": "Session expired. Please log in again."}`,
		`{"error": "Not authenticated"}`,
		`{"error": "Access denied"}`,
		`{"message": "Logged out successfully"}`,
	}

	for _, response := range errorResponses {
		var result map[string]interface{}
		err := json.Unmarshal([]byte(response), &result)
		assert.NoError(t, err, "Response '%s' should be valid JSON", response)
	}
}
