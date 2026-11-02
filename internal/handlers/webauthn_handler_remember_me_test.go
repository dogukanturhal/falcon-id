// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/pkg/config"
)

func TestWebAuthnRememberMe_QueryParam(t *testing.T) {
	gin.SetMode(gin.TestMode)
	cases := map[string]bool{
		"/login/finish?remember_me=true":  true,
		"/login/finish?remember_me=false": false,
		"/login/finish":                   false,
	}
	for target, want := range cases {
		c, _ := gin.CreateTestContext(httptest.NewRecorder())
		c.Request = httptest.NewRequest("POST", target, nil)
		assert.Equal(t, want, webAuthnRememberMe(c), target)
	}
}

// A passkey login flagged IsRememberMeSession must set the IdP cookie with
// the long remember-me Max-Age; otherwise the default TTL.
func TestWebAuthnLogin_IdpCookieMaxAgeFollowsRememberMe(t *testing.T) {
	gin.SetMode(gin.TestMode)
	cache, _ := newTestSessionCacheForEndSession(t)
	h := &AuthHandler{config: &config.Config{
		SessionTTLDefault:    24 * time.Hour,
		SessionTTLRememberMe: 720 * time.Hour,
	}}
	h.SetSessionCache(cache)

	for _, tc := range []struct {
		remember bool
		want     time.Duration
	}{{true, 720 * time.Hour}, {false, 24 * time.Hour}} {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest("POST", "/api/v1/auth/webauthn/login/finish", nil)
		h.SetLoginResponseCookies(c, &models.LoginResponse{
			AccessToken:         "tok",
			ExpiresIn:           900,
			IsRememberMeSession: tc.remember,
			User:                &models.UserResponse{ID: uuid.New(), TenantID: uuid.New()},
		})
		var maxAge int
		for _, ck := range w.Result().Cookies() {
			if ck.Name == "falcon_idp_session" {
				maxAge = ck.MaxAge
			}
		}
		require.Equal(t, int(tc.want.Seconds()), maxAge, "remember=%v", tc.remember)
	}
}
