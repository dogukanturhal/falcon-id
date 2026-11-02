// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
)

func loginHintRouter() *gin.Engine {
	gin.SetMode(gin.TestMode)
	h := &OAuthProviderHandler{logger: zap.NewNop()}
	r := gin.New()
	r.GET("/oauth/login", h.LoginPage)
	return r
}

func getLogin(t *testing.T, redirect string, extra url.Values) *httptest.ResponseRecorder {
	t.Helper()
	q := url.Values{"redirect": {redirect}}
	for k, v := range extra {
		q[k] = v
	}
	w := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/oauth/login?"+q.Encode(), nil)
	loginHintRouter().ServeHTTP(w, req)
	return w
}

func TestLoginPage_LoginHint_PrefillsAndOffersPasskey(t *testing.T) {
	t.Setenv("OAUTH_LOGIN_REDIRECT_URL", "")
	redirect := "/oauth/authorize?client_id=abc&tenant_id=00000000-0000-0000-0000-000000000002&login_hint=" + url.QueryEscape("alice@example.com")
	w := getLogin(t, redirect, nil)
	body := w.Body.String()

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, body, `value="alice@example.com"`)
	assert.Contains(t, body, "Continue as")
	assert.Contains(t, body, "Use a different account")
	// "Use a different account" drops the hint from the continuation.
	assert.Contains(t, body, `id="use-different" href="/oauth/login?redirect=%2Foauth%2Fauthorize%3Fclient_id%3Dabc%26tenant_id%3D`)
	assert.NotContains(t, body, `use-different" href="/oauth/login?redirect=%2Foauth%2Fauthorize%3Fclient_id%3Dabc%26login_hint`)
	assert.Contains(t, body, "conditional/begin") // passkey started immediately
}

func TestLoginPage_LoginHint_ExplicitParamAndEscaping(t *testing.T) {
	t.Setenv("OAUTH_LOGIN_REDIRECT_URL", "")
	evil := `"><script>alert(1)</script>`
	w := getLogin(t, "/oauth/authorize?client_id=abc", url.Values{"login_hint": {evil}})
	body := w.Body.String()

	assert.NotContains(t, body, "<script>alert(1)</script>")
	assert.Contains(t, body, "&#34;&gt;&lt;script&gt;alert(1)&lt;/script&gt;")
}

func TestLoginPage_NoHint_NoContinueBlock(t *testing.T) {
	t.Setenv("OAUTH_LOGIN_REDIRECT_URL", "")
	w := getLogin(t, "/oauth/authorize?client_id=abc", nil)
	body := w.Body.String()
	assert.NotContains(t, body, "Continue as")
	assert.NotContains(t, body, "Use a different account")
	assert.NotContains(t, body, "conditional/begin")
}

func TestLoginPage_LoginHint_ForwardedToHostedLoginApp(t *testing.T) {
	t.Setenv("OAUTH_LOGIN_REDIRECT_URL", "/login")
	w := getLogin(t, "/oauth/authorize?client_id=abc&login_hint=bob%40example.com", nil)
	loc := w.Header().Get("Location")
	assert.Contains(t, loc, "&email=bob%40example.com")
	assert.Contains(t, loc, "&login_hint=bob%40example.com")
}

func TestLoginHintFrom_RejectsControlCharsAndLong(t *testing.T) {
	assert.Equal(t, "", loginHintFrom("a\nb", ""))
	assert.Equal(t, "", loginHintFrom(string(make([]byte, 300)), ""))
	assert.Equal(t, "x@y.z", loginHintFrom("  x@y.z ", ""))
	assert.Equal(t, "", loginHintFrom("", "/oauth/authorize?client_id=a"))
}
