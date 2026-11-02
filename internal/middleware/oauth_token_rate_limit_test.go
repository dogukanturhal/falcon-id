// SPDX-License-Identifier: AGPL-3.0-or-later

package middleware

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
	r.POST("/oauth/token", OAuthTokenRateLimit([]string{"acmeapp-bff"}), func(c *gin.Context) {
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

// LD-R3-TX-3: acmeapp-bff calls /oauth/token for every signed-in user, so its
// burst window is per end user: one user's 61st exchange is refused while
// another user of the same client still gets through.
func TestOAuthTokenRateLimit_PerUserForBFF(t *testing.T) {
	gin.SetMode(gin.TestMode)

	authRateLimitStore.mu.Lock()
	authRateLimitStore.store = make(map[string]*lruEntry)
	authRateLimitStore.lruList.Init()
	authRateLimitStore.mu.Unlock()

	r := gin.New()
	r.POST("/oauth/token", OAuthTokenRateLimit([]string{"acmeapp-bff"}), func(c *gin.Context) {
		c.Status(http.StatusOK)
	})
	subjectFor := func(sub string) string {
		tok, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"sub": sub}).SignedString([]byte("k"))
		require.NoError(t, err)
		return tok
	}
	post := func(subject string) int {
		form := url.Values{}
		form.Set("client_id", "acmeapp-bff")
		form.Set("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange")
		form.Set("subject_token", subject)
		req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		return w.Code
	}

	alice := subjectFor("alice")
	for i := 0; i < 60; i++ {
		require.Equal(t, http.StatusOK, post(alice), "req %d", i+1)
	}
	assert.Equal(t, http.StatusTooManyRequests, post(alice), "alice's 61st request trips her own bucket")
	assert.Equal(t, http.StatusOK, post(subjectFor("bob")), "bob shares the client but not the bucket")
}

func TestResolveOAuthTokenUserKey(t *testing.T) {
	gin.SetMode(gin.TestMode)
	c, _ := newPostFormCtx(map[string]string{"refresh_token": "rt-secret"})
	key := resolveOAuthTokenUserKey(c)
	assert.True(t, strings.HasPrefix(key, "rt:"))
	assert.NotContains(t, key, "rt-secret", "raw credentials never become a key")

	c, _ = newPostFormCtx(map[string]string{"subject_token": "not-a-jwt"})
	assert.True(t, strings.HasPrefix(resolveOAuthTokenUserKey(c), "st:"))

	// Public client: a forged sub must not pick the bucket.
	forged, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"sub": "victim"}).SignedString([]byte("k"))
	require.NoError(t, err)
	c, _ = newPostFormCtx(map[string]string{"subject_token": forged})
	key = resolveOAuthTokenUserKey(c)
	assert.True(t, strings.HasPrefix(key, "st:"))
	assert.NotContains(t, key, "victim")
	assert.NotContains(t, key, forged)

	// Confidential client keeps the stable sub bucket.
	c, _ = newPostFormCtx(map[string]string{"subject_token": forged, "client_secret": "s"})
	assert.Equal(t, "sub:victim", resolveOAuthTokenUserKey(c))

	c, _ = newPostFormCtx(map[string]string{})
	c.Request.RemoteAddr = "10.0.0.9:1234"
	assert.Equal(t, "ip:10.0.0.9", resolveOAuthTokenUserKey(c))
}

// Public native clients listed in the per-user set get one bucket per
// install/credential, not one shared client bucket.
func TestOAuthTokenRateLimit_PerUserForPublicClient(t *testing.T) {
	gin.SetMode(gin.TestMode)

	authRateLimitStore.mu.Lock()
	authRateLimitStore.store = make(map[string]*lruEntry)
	authRateLimitStore.lruList.Init()
	authRateLimitStore.mu.Unlock()

	r := gin.New()
	r.POST("/oauth/token", OAuthTokenRateLimit([]string{"mobile-app"}), func(c *gin.Context) {
		c.Status(http.StatusOK)
	})
	post := func(clientID, refresh string) int {
		form := url.Values{}
		form.Set("client_id", clientID)
		form.Set("grant_type", "refresh_token")
		form.Set("refresh_token", refresh)
		req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		return w.Code
	}
	for i := 0; i < 60; i++ {
		require.Equal(t, http.StatusOK, post("mobile-app", "rt-a"))
	}
	assert.Equal(t, http.StatusTooManyRequests, post("mobile-app", "rt-a"))
	assert.Equal(t, http.StatusOK, post("mobile-app", "rt-b"), "other install not locked out")

	// A client not in the list still shares one per-client bucket.
	for i := 0; i < 60; i++ {
		require.Equal(t, http.StatusOK, post("other", "rt-"+strconv.Itoa(i)))
	}
	assert.Equal(t, http.StatusTooManyRequests, post("other", "rt-new"))
}
