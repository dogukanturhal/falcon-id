// SPDX-License-Identifier: AGPL-3.0-or-later

package middleware

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

// TestDecodeBasicAuthClientID locks down the parsing contract: the
// decoder MUST surface only the username portion (client_id) and
// silently ignore decode errors so that a malformed Authorization
// header doesn't blow up the limiter.
func TestDecodeBasicAuthClientID(t *testing.T) {
	tests := []struct {
		name   string
		header string
		want   string
	}{
		{"empty", "", ""},
		{"non-basic scheme", "Bearer x", ""},
		{"basic with no payload", "Basic ", ""},
		{"valid client_id:secret", "Basic " + base64.StdEncoding.EncodeToString([]byte("svc-accounts:s3cret")), "svc-accounts"},
		{"empty secret", "Basic " + base64.StdEncoding.EncodeToString([]byte("svc-talon:")), "svc-talon"},
		{"colon-only", "Basic " + base64.StdEncoding.EncodeToString([]byte(":")), ""},
		{"missing colon", "Basic " + base64.StdEncoding.EncodeToString([]byte("svc-accounts")), ""},
		{"malformed base64", "Basic !!!not_base64!!!", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := decodeBasicAuthClientID(tc.header)
			assert.Equal(t, tc.want, got)
		})
	}
}

// TestResolveOAuthTokenIdentifier confirms the resolution order:
// POST form first, then Basic-auth header, then RemoteAddr fallback.
func TestResolveOAuthTokenIdentifier(t *testing.T) {
	gin.SetMode(gin.TestMode)

	t.Run("form client_id wins", func(t *testing.T) {
		c, _ := newPostFormCtx(map[string]string{"client_id": "form-client"})
		c.Request.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("basic-client:s")))
		c.Request.RemoteAddr = "10.0.0.1:42"
		assert.Equal(t, "cid:form-client", resolveOAuthTokenIdentifier(c))
	})
	t.Run("basic auth used when no form", func(t *testing.T) {
		c, _ := newPostFormCtx(map[string]string{"grant_type": "client_credentials"})
		c.Request.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("basic-client:s")))
		c.Request.RemoteAddr = "10.0.0.1:42"
		assert.Equal(t, "cid:basic-client", resolveOAuthTokenIdentifier(c))
	})
	t.Run("ip fallback when neither", func(t *testing.T) {
		c, _ := newPostFormCtx(map[string]string{"grant_type": "client_credentials"})
		c.Request.RemoteAddr = "10.0.0.1:42"
		assert.Equal(t, "ip:10.0.0.1", resolveOAuthTokenIdentifier(c))
	})
}

// TestOAuthTokenRateLimit_BurstBlock asserts that the 61st request in a
// 60-second window is blocked with a 429 + Retry-After. Identifiers are
// per-client_id, so two distinct clients don't share a budget.
func TestOAuthTokenRateLimit_BurstBlock(t *testing.T) {
	gin.SetMode(gin.TestMode)

	// Reset the global store so test order doesn't matter.
	authRateLimitStore.mu.Lock()
	authRateLimitStore.store = make(map[string]*lruEntry)
	authRateLimitStore.lruList.Init()
	authRateLimitStore.mu.Unlock()

	r := gin.New()
	r.POST("/oauth/token", OAuthTokenRateLimit(), func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	form := url.Values{}
	form.Set("client_id", "client-a")

	// 60 OK (limit reached but not exceeded)
	for i := 0; i < 60; i++ {
		req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code, "req %d should pass within burst window", i+1)
	}

	// 61st blocks
	req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	assert.Equal(t, http.StatusTooManyRequests, w.Code)
	assert.NotEmpty(t, w.Header().Get("Retry-After"))

	// A different client_id is unaffected.
	form2 := url.Values{}
	form2.Set("client_id", "client-b")
	req2 := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form2.Encode()))
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w2 := httptest.NewRecorder()
	r.ServeHTTP(w2, req2)
	assert.Equal(t, http.StatusOK, w2.Code, "per-client isolation must hold")
}

// newPostFormCtx returns a *gin.Context wrapping a POST form request
// without spinning up a full router. Used to unit-test
// resolveOAuthTokenIdentifier in isolation.
func newPostFormCtx(form map[string]string) (*gin.Context, *httptest.ResponseRecorder) {
	values := url.Values{}
	for k, v := range form {
		values.Set(k, v)
	}
	req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(values.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = req
	return c, w
}
