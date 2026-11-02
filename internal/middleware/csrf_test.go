// SPDX-License-Identifier: AGPL-3.0-or-later

package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testExampleDomain = "example.com"
)

// newCSRFConfig returns a minimal CSRFConfig suitable for tests.
// Origin validation is bypassed by leaving the request Host matching the
// origin – or by sending no origin at all (the middleware allows it).
// RedisClient is nil so the cookie double-submit pattern is used.
func newCSRFConfig() CSRFConfig {
	cfg := DefaultCSRFConfig()
	cfg.RedisClient = nil
	cfg.CookieSecure = false // allow http in tests
	return cfg
}

// newCSRFRouter creates a router with the CSRF middleware on POST /test.
func newCSRFRouter(m *CSRFMiddleware) *gin.Engine {
	router := gin.New()
	router.POST("/test", m.CSRF(), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})
	router.GET("/test", m.CSRF(), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})
	return router
}

// requestWithToken builds a POST request that carries a CSRF token in a
// cookie and the chosen delivery mechanism (header / form field).
func requestWithToken(t *testing.T, token string, viaHeader bool) *http.Request {
	t.Helper()
	var req *http.Request
	if viaHeader {
		req = httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/test", nil)
		req.Header.Set(CSRFTokenHeader, token)
	} else {
		body := "_csrf=" + token
		req = httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/test", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	req.AddCookie(&http.Cookie{Name: CSRFCookieName, Value: token})
	// Use the same host as the cookie origin so the origin check passes
	req.Host = testExampleDomain
	return req
}

// ==================== Safe-method bypass ====================

func TestCSRF_GET_SkipsValidation(t *testing.T) {
	m := NewCSRFMiddlewareWithConfig(newCSRFConfig())

	w := httptest.NewRecorder()
	router := newCSRFRouter(m)

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/test", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestCSRF_HEAD_SkipsValidation(t *testing.T) {
	m := NewCSRFMiddlewareWithConfig(newCSRFConfig())

	w := httptest.NewRecorder()
	_, router := gin.CreateTestContext(w)
	router.HEAD("/test", m.CSRF(), func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequestWithContext(context.Background(), http.MethodHead, "/test", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestCSRF_OPTIONS_SkipsValidation(t *testing.T) {
	m := NewCSRFMiddlewareWithConfig(newCSRFConfig())

	w := httptest.NewRecorder()
	_, router := gin.CreateTestContext(w)
	router.OPTIONS("/test", m.CSRF(), func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequestWithContext(context.Background(), http.MethodOptions, "/test", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestCSRF_TRACE_SkipsValidation(t *testing.T) {
	m := NewCSRFMiddlewareWithConfig(newCSRFConfig())

	w := httptest.NewRecorder()
	_, router := gin.CreateTestContext(w)
	// Register TRACE — gin allows any method via router.Handle
	router.Handle(http.MethodTrace, "/test", m.CSRF(), func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequestWithContext(context.Background(), http.MethodTrace, "/test", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

// ==================== Exempt paths bypass ====================

func TestCSRF_ExemptPath_Login_SkipsValidation(t *testing.T) {
	m := NewCSRFMiddlewareWithConfig(newCSRFConfig())

	w := httptest.NewRecorder()
	_, router := gin.CreateTestContext(w)
	router.POST("/api/auth/login", m.CSRF(), func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/auth/login", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

// RFC 7662 §2.1, RFC 7009 §2.1, RFC 9126 §2.2 — confidential-client auth at
// the endpoint IS the anti-CSRF mechanism for s2s OAuth surfaces. CSRF
// middleware would block every legitimate introspection / revocation /
// pushed-authorization-request call from a non-browser RP. Regression test
// for the 2026-04-29 conformance pack live-deploy gap where /oauth/introspect
// and /oauth/revoke returned 403 csrf_validation_failed.
func TestCSRF_ExemptPath_OAuthIntrospect_SkipsValidation(t *testing.T) {
	m := NewCSRFMiddlewareWithConfig(newCSRFConfig())

	w := httptest.NewRecorder()
	_, router := gin.CreateTestContext(w)
	router.POST("/oauth/introspect", m.CSRF(), func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/oauth/introspect", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

// The ZTNA device-enrollment witness ceremony (/api/v1/auth/webauthn/witness/
// {begin,finish}) is CSRF-exempt for the same reason as the other WebAuthn
// ceremony endpoints: the SameSite=Strict session cookie + platform_admin
// re-check + (at finish) the hardware-key assertion are the anti-CSRF, and the
// session-bound synchronizer token does not fit this app-launched cross-context
// flow (live repro 2026-06-16: every /witness/begin 403'd csrf_validation_failed).
func TestCSRF_ExemptPath_WitnessCeremony_SkipsValidation(t *testing.T) {
	m := NewCSRFMiddlewareWithConfig(newCSRFConfig())
	for _, path := range []string{
		"/api/v1/auth/webauthn/witness/begin",
		"/api/v1/auth/webauthn/witness/finish",
		"/api/auth/webauthn/witness/begin",
		"/api/auth/webauthn/witness/finish",
	} {
		w := httptest.NewRecorder()
		_, router := gin.CreateTestContext(w)
		router.POST(path, m.CSRF(), func(c *gin.Context) { c.Status(http.StatusOK) })
		req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, path, nil)
		router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code, "witness ceremony path %q must be CSRF-exempt", path)
	}
}

func TestCSRF_ExemptPath_OAuthRevoke_SkipsValidation(t *testing.T) {
	m := NewCSRFMiddlewareWithConfig(newCSRFConfig())

	w := httptest.NewRecorder()
	_, router := gin.CreateTestContext(w)
	router.POST("/oauth/revoke", m.CSRF(), func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/oauth/revoke", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestCSRF_ExemptPath_OAuthPAR_SkipsValidation(t *testing.T) {
	m := NewCSRFMiddlewareWithConfig(newCSRFConfig())

	w := httptest.NewRecorder()
	_, router := gin.CreateTestContext(w)
	router.POST("/oauth/par", m.CSRF(), func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/oauth/par", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestCSRF_ExemptPath_InternalPrefix_SkipsValidation(t *testing.T) {
	m := NewCSRFMiddlewareWithConfig(newCSRFConfig())

	w := httptest.NewRecorder()
	_, router := gin.CreateTestContext(w)
	router.POST("/internal/sync", m.CSRF(), func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/internal/sync", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestCSRF_ExemptPath_ScimPrefix_SkipsValidation(t *testing.T) {
	m := NewCSRFMiddlewareWithConfig(newCSRFConfig())

	w := httptest.NewRecorder()
	_, router := gin.CreateTestContext(w)
	router.POST("/scim/v2/Users", m.CSRF(), func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/scim/v2/Users", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

// ==================== API key bypass ====================

func TestCSRF_ApiKeyAuthenticated_SkipsValidation(t *testing.T) {
	m := NewCSRFMiddlewareWithConfig(newCSRFConfig())

	w := httptest.NewRecorder()
	_, router := gin.CreateTestContext(w)
	router.POST("/test", func(c *gin.Context) {
		c.Set("api_key_authenticated", true) // set by ApiKeyAuth middleware
	}, m.CSRF(), func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/test", nil)
	// No CSRF token – should still pass because api_key_authenticated is true
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

// ==================== Token validation via double-submit cookie ====================

func TestCSRF_POST_ValidTokenInHeader_Passes(t *testing.T) {
	m := NewCSRFMiddlewareWithConfig(newCSRFConfig())

	w := httptest.NewRecorder()
	router := newCSRFRouter(m)

	token := "valid-csrf-token-abc123" //nolint:gosec // test fixture value, not a real credential
	req := requestWithToken(t, token, true /* via header */)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestCSRF_POST_ValidTokenInFormField_Passes(t *testing.T) {
	m := NewCSRFMiddlewareWithConfig(newCSRFConfig())

	w := httptest.NewRecorder()
	router := newCSRFRouter(m)

	token := "valid-csrf-token-xyz456" //nolint:gosec // test fixture value, not a real credential
	req := requestWithToken(t, token, false /* via form field */)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestCSRF_POST_MissingToken_Returns403(t *testing.T) {
	m := NewCSRFMiddlewareWithConfig(newCSRFConfig())

	w := httptest.NewRecorder()
	router := newCSRFRouter(m)

	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/test", nil)
	// No CSRF token in header or form, no origin header either
	req.Host = testExampleDomain
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestCSRF_POST_InvalidToken_Returns403(t *testing.T) {
	m := NewCSRFMiddlewareWithConfig(newCSRFConfig())

	w := httptest.NewRecorder()
	router := newCSRFRouter(m)

	// Cookie token differs from header token
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/test", nil)
	req.Host = testExampleDomain
	req.Header.Set(CSRFTokenHeader, "wrong-token")
	req.AddCookie(&http.Cookie{Name: CSRFCookieName, Value: "correct-token"})
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestCSRF_POST_TokenInHeaderButNoCookie_Returns403(t *testing.T) {
	m := NewCSRFMiddlewareWithConfig(newCSRFConfig())

	w := httptest.NewRecorder()
	router := newCSRFRouter(m)

	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/test", nil)
	req.Host = testExampleDomain
	req.Header.Set(CSRFTokenHeader, "some-token")
	// No cookie set – double-submit pattern requires the cookie
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestCSRF_POST_EmptyTokenInHeader_Returns403(t *testing.T) {
	m := NewCSRFMiddlewareWithConfig(newCSRFConfig())

	w := httptest.NewRecorder()
	router := newCSRFRouter(m)

	token := "some-csrf-token" //nolint:gosec // test fixture value, not a real credential
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/test", nil)
	req.Host = testExampleDomain
	req.Header.Set(CSRFTokenHeader, "") // empty header
	req.AddCookie(&http.Cookie{Name: CSRFCookieName, Value: token})
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
}

// ==================== Origin validation ====================

func TestCSRF_POST_NullOrigin_Returns403(t *testing.T) {
	m := NewCSRFMiddlewareWithConfig(newCSRFConfig())

	w := httptest.NewRecorder()
	router := newCSRFRouter(m)

	token := "valid-token"
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/test", nil)
	req.Host = testExampleDomain
	req.Header.Set("Origin", "null") // SECURITY: null origin attack
	req.Header.Set(CSRFTokenHeader, token)
	req.AddCookie(&http.Cookie{Name: CSRFCookieName, Value: token})
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestCSRF_POST_SameOrigin_Passes(t *testing.T) {
	m := NewCSRFMiddlewareWithConfig(newCSRFConfig())

	w := httptest.NewRecorder()
	router := newCSRFRouter(m)

	token := "valid-token-same-origin"
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/test", nil)
	req.Host = testExampleDomain
	req.Header.Set("Origin", "http://example.com") // same host
	req.Header.Set(CSRFTokenHeader, token)
	req.AddCookie(&http.Cookie{Name: CSRFCookieName, Value: token})
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestCSRF_POST_CrossOriginUnknown_Returns403(t *testing.T) {
	m := NewCSRFMiddlewareWithConfig(newCSRFConfig())

	w := httptest.NewRecorder()
	router := newCSRFRouter(m)

	token := "valid-token"
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/test", nil)
	req.Host = testExampleDomain
	req.Header.Set("Origin", "https://evil.attacker.com")
	req.Header.Set(CSRFTokenHeader, token)
	req.AddCookie(&http.Cookie{Name: CSRFCookieName, Value: token})
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestCSRF_POST_NoOriginNoReferer_TokenValidation_StillEnforced(t *testing.T) {
	// When no origin/referer is present, origin check passes (non-browser),
	// but the token itself still must be valid.
	m := NewCSRFMiddlewareWithConfig(newCSRFConfig())

	w := httptest.NewRecorder()
	router := newCSRFRouter(m)

	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/test", nil)
	req.Host = testExampleDomain
	// No Origin, no Referer, no CSRF token
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestCSRF_POST_NoOriginWithValidToken_Passes(t *testing.T) {
	m := NewCSRFMiddlewareWithConfig(newCSRFConfig())

	w := httptest.NewRecorder()
	router := newCSRFRouter(m)

	token := "valid-token-no-origin" //nolint:gosec // test fixture value, not a real credential
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/test", nil)
	req.Host = testExampleDomain
	// No Origin header, token provided via double-submit cookie pattern
	req.Header.Set(CSRFTokenHeader, token)
	req.AddCookie(&http.Cookie{Name: CSRFCookieName, Value: token})
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestCSRF_POST_RefererSameHost_Passes(t *testing.T) {
	m := NewCSRFMiddlewareWithConfig(newCSRFConfig())

	w := httptest.NewRecorder()
	router := newCSRFRouter(m)

	token := "valid-token-referer" //nolint:gosec // test fixture value, not a real credential
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/test", nil)
	req.Host = testExampleDomain
	req.Header.Set("Referer", "http://example.com/page")
	req.Header.Set(CSRFTokenHeader, token)
	req.AddCookie(&http.Cookie{Name: CSRFCookieName, Value: token})
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

// ==================== Custom error handler ====================

func TestCSRF_CustomErrorHandler_CalledOnFailure(t *testing.T) {
	customHandlerCalled := false

	cfg := newCSRFConfig()
	cfg.ErrorHandler = func(c *gin.Context) {
		customHandlerCalled = true
		c.AbortWithStatusJSON(http.StatusTeapot, gin.H{"custom": "error"})
	}
	m := NewCSRFMiddlewareWithConfig(cfg)

	w := httptest.NewRecorder()
	_, router := gin.CreateTestContext(w)
	router.POST("/test", m.CSRF(), func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/test", nil)
	req.Host = testExampleDomain
	// No CSRF token – triggers failure
	router.ServeHTTP(w, req)

	assert.True(t, customHandlerCalled)
	assert.Equal(t, http.StatusTeapot, w.Code)
}

// ==================== isExemptPath unit tests ====================

func TestIsExemptPath_ExactMatch(t *testing.T) {
	m := NewCSRFMiddlewareWithConfig(newCSRFConfig())

	// Exact match paths (no trailing slash in config)
	require.True(t, m.isExemptPath("/api/auth/login"))
	require.True(t, m.isExemptPath("/api/auth/register"))
	require.True(t, m.isExemptPath("/api/auth/password/forgot"))
	require.True(t, m.isExemptPath("/api/auth/mfa/verify"))
}

func TestIsExemptPath_PrefixMatch(t *testing.T) {
	m := NewCSRFMiddlewareWithConfig(newCSRFConfig())

	// Prefix match paths (trailing slash in config)
	require.True(t, m.isExemptPath("/internal/sync"))
	require.True(t, m.isExemptPath("/internal/anything/nested"))
	require.True(t, m.isExemptPath("/scim/v2/Users"))
	require.True(t, m.isExemptPath("/.well-known/jwks.json"))
}

func TestIsExemptPath_NonExempt(t *testing.T) {
	m := NewCSRFMiddlewareWithConfig(newCSRFConfig())

	require.False(t, m.isExemptPath("/api/users"))
	require.False(t, m.isExemptPath("/api/roles"))
	require.False(t, m.isExemptPath("/dashboard"))
}

func TestIsExemptPath_PartialExactDoesNotMatch(t *testing.T) {
	m := NewCSRFMiddlewareWithConfig(newCSRFConfig())

	// "/api/auth/login" is exact – "/api/auth/login/extra" should NOT match
	require.False(t, m.isExemptPath("/api/auth/login/extra"))
}

// ==================== isExemptMethod unit tests ====================

func TestIsExemptMethod_SafeMethods(t *testing.T) {
	m := NewCSRFMiddlewareWithConfig(newCSRFConfig())

	for _, method := range []string{"GET", "HEAD", "OPTIONS", "TRACE"} {
		assert.True(t, m.isExemptMethod(method), "expected %s to be exempt", method)
	}
}

func TestIsExemptMethod_UnsafeMethods(t *testing.T) {
	m := NewCSRFMiddlewareWithConfig(newCSRFConfig())

	for _, method := range []string{"POST", "PUT", "PATCH", "DELETE"} {
		assert.False(t, m.isExemptMethod(method), "expected %s to NOT be exempt", method)
	}
}

// ==================== extractOriginFromURL unit tests ====================

func TestExtractOriginFromURL_ValidURL(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"https://example.com/path/to/page", "https://example.com"},
		{"http://localhost:3000/dashboard", "http://localhost:3000"},
		{"https://app.example.com/login?q=1", "https://app.example.com"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := extractOriginFromURL(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestExtractOriginFromURL_NoScheme_ReturnsEmpty(t *testing.T) {
	result := extractOriginFromURL("example.com/path")
	assert.Empty(t, result)
}

// ==================== matchesOriginPattern unit tests ====================

func TestMatchesOriginPattern_ExactMatch(t *testing.T) {
	assert.True(t, matchesOriginPattern("https://example.com", "https://example.com"))
	assert.False(t, matchesOriginPattern("https://example.com", "https://other.com"))
}

func TestMatchesOriginPattern_WildcardSubdomain(t *testing.T) {
	pattern := "https://*.example.com"
	assert.True(t, matchesOriginPattern("https://app.example.com", pattern))
	assert.True(t, matchesOriginPattern("https://dashboard.example.com", pattern))
	assert.True(t, matchesOriginPattern("https://example.com", pattern))
	assert.False(t, matchesOriginPattern("https://evil.com", pattern))
	assert.False(t, matchesOriginPattern("http://app.example.com", pattern)) // wrong scheme
}

// ==================== DefaultCSRFConfig ====================

func TestDefaultCSRFConfig_HasSensibleDefaults(t *testing.T) {
	cfg := DefaultCSRFConfig()

	assert.Equal(t, CSRFTokenLength, cfg.TokenLength)
	assert.Equal(t, CSRFCookieName, cfg.CookieName)
	assert.Equal(t, CSRFCookieMaxAge, cfg.CookieMaxAge)
	assert.Equal(t, "/", cfg.CookiePath)
	assert.Equal(t, CSRFTokenHeader, cfg.HeaderName)
	assert.False(t, cfg.CookieHTTPOnly, "must be false so JS can read it for double-submit")
	assert.Contains(t, cfg.SkipMethods, "GET")
	assert.Contains(t, cfg.SkipMethods, "HEAD")
	assert.Contains(t, cfg.SkipMethods, "OPTIONS")
	assert.NotEmpty(t, cfg.SkipPaths)
}

// ==================== GenerateTokenForSession ====================

func TestGenerateTokenForSession_ReturnsNonEmptyToken(t *testing.T) {
	m := NewCSRFMiddlewareWithConfig(newCSRFConfig()) // no redis

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil)
	c.Request = req

	token, err := m.GenerateTokenForSession(c, uuid.New())
	require.NoError(t, err)
	assert.NotEmpty(t, token)
}

func TestGenerateTokenForSession_TokenIsURLSafeBase64(t *testing.T) {
	m := NewCSRFMiddlewareWithConfig(newCSRFConfig())

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil)

	token, err := m.GenerateTokenForSession(c, uuid.New())
	require.NoError(t, err)

	// URL-safe base64 should not contain '+' or '/'
	assert.NotContains(t, token, "+")
	assert.NotContains(t, token, "/")
}

// ==================== GetCSRFToken ====================

func TestGetCSRFToken_WhenSet_ReturnsToken(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Set("csrf_token", "my-csrf-token")

	got := GetCSRFToken(c)
	assert.Equal(t, "my-csrf-token", got)
}

func TestGetCSRFToken_WhenNotSet_ReturnsEmpty(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	got := GetCSRFToken(c)
	assert.Empty(t, got)
}

func TestGetCSRFToken_WhenWrongType_ReturnsEmpty(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Set("csrf_token", 12345) // wrong type

	got := GetCSRFToken(c)
	assert.Empty(t, got)
}

// ==================== Custom SkipPaths config ====================

func TestCSRF_CustomSkipPaths_Exempts(t *testing.T) {
	cfg := newCSRFConfig()
	cfg.SkipPaths = append(cfg.SkipPaths, "/custom/exempt")
	m := NewCSRFMiddlewareWithConfig(cfg)

	w := httptest.NewRecorder()
	_, router := gin.CreateTestContext(w)
	router.POST("/custom/exempt", m.CSRF(), func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/custom/exempt", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}
