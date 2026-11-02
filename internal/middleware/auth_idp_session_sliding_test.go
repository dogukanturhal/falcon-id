// SPDX-License-Identifier: AGPL-3.0-or-later

package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dogukanturhal/falcon-id/internal/models"
	redispkg "github.com/dogukanturhal/falcon-id/pkg/redis"
)

// authorizeWithIdpCookie seeds an IdP session authenticated `age` ago and drives
// GET /oauth/authorize with its cookie through OptionalAuth.
func authorizeWithIdpCookie(t *testing.T, age time.Duration, path string) (*models.CurrentUser, *httptest.ResponseRecorder, *redispkg.SessionCache, uuid.UUID) {
	t.Helper()
	cfg := authTestConfig()
	cfg.SessionTTLDefault = 168 * time.Hour
	m := NewAuthMiddleware(newAuthTestTokenService(cfg), cfg)
	cache := newTestSessionCacheForMiddleware(t)
	cache.SetIdpAbsoluteCap(30 * 24 * time.Hour)
	m.SetSessionCache(cache)

	id := uuid.New()
	require.NoError(t, cache.SetIdpSession(context.Background(), id, &redispkg.IdpSessionData{
		UserID: uuid.New(), TenantID: uuid.New(), AuthTime: time.Now().Add(-age).Unix(), SessionID: uuid.New(),
	}))

	var got *models.CurrentUser
	w := httptest.NewRecorder()
	_, router := gin.CreateTestContext(w)
	router.GET(path, m.OptionalAuth(), func(c *gin.Context) {
		got = GetCurrentUser(c)
		c.Status(http.StatusOK)
	})
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, path, nil)
	req.AddCookie(&http.Cookie{Name: IdpSessionCookieName, Value: id.String()})
	router.ServeHTTP(w, req)
	return got, w, cache, id
}

func idpSetCookie(w *httptest.ResponseRecorder) *http.Cookie {
	for _, ck := range w.Result().Cookies() {
		if ck.Name == IdpSessionCookieName {
			return ck
		}
	}
	return nil
}

// A user active at 25h (past the old 24h cookie lifetime) stays silent and the
// cookie is re-issued with a fresh idle-length Max-Age and the standard attributes.
func TestResolveIdpSessionCookie_Authorize_SlidesCookieAt25h(t *testing.T) {
	user, w, _, id := authorizeWithIdpCookie(t, 25*time.Hour, "/oauth/authorize")
	require.NotNil(t, user, "25h-old SSO session must still authenticate silently")
	ck := idpSetCookie(w)
	require.NotNil(t, ck, "cookie must be re-issued on authorize")
	assert.Equal(t, id.String(), ck.Value)
	assert.Equal(t, int((168 * time.Hour).Seconds()), ck.MaxAge)
	assert.True(t, ck.HttpOnly)
	assert.Equal(t, http.SameSiteLaxMode, ck.SameSite)
	assert.Equal(t, "/", ck.Path)
}

// Near the absolute cap the re-issued Max-Age is clamped to the time left.
func TestResolveIdpSessionCookie_Authorize_MaxAgeClampedToAbsoluteCap(t *testing.T) {
	_, w, _, _ := authorizeWithIdpCookie(t, 30*24*time.Hour-12*time.Hour, "/oauth/authorize")
	ck := idpSetCookie(w)
	require.NotNil(t, ck)
	assert.InDelta(t, (12 * time.Hour).Seconds(), float64(ck.MaxAge), 120, "Max-Age=%s", strconv.Itoa(ck.MaxAge))
}

// Past the absolute cap the session is treated as absent and its record deleted.
func TestResolveIdpSessionCookie_PastAbsoluteCap_NoSessionAndDeleted(t *testing.T) {
	user, w, cache, id := authorizeWithIdpCookie(t, 31*24*time.Hour, "/oauth/authorize")
	assert.Nil(t, user)
	assert.Nil(t, idpSetCookie(w))
	data, err := cache.GetIdpSession(context.Background(), id)
	require.NoError(t, err)
	assert.Nil(t, data, "expired record must be deleted")
}

// Non-authorize routes do not re-issue the cookie.
func TestResolveIdpSessionCookie_OtherRoute_DoesNotReissue(t *testing.T) {
	user, w, _, _ := authorizeWithIdpCookie(t, time.Hour, "/auth/whoami")
	require.NotNil(t, user)
	assert.Nil(t, idpSetCookie(w))
}

// A session minted under a 24h realm cap (AbsoluteCapSeconds recorded at
// creation) must not authenticate silently after 24h, while the same age under
// the 30d default does (TestResolveIdpSessionCookie_Authorize_SlidesCookieAt25h).
func TestResolveIdpSessionCookie_Authorize_PerRealmCap24h(t *testing.T) {
	run := func(age time.Duration) *models.CurrentUser {
		cfg := authTestConfig()
		m := NewAuthMiddleware(newAuthTestTokenService(cfg), cfg)
		cache := newTestSessionCacheForMiddleware(t)
		cache.SetIdpAbsoluteCap(30 * 24 * time.Hour)
		m.SetSessionCache(cache)
		id := uuid.New()
		require.NoError(t, cache.SetIdpSession(context.Background(), id, &redispkg.IdpSessionData{
			UserID: uuid.New(), TenantID: uuid.New(), AuthTime: time.Now().Add(-age).Unix(), SessionID: uuid.New(),
			AbsoluteCapSeconds: int64((24 * time.Hour).Seconds()),
		}))
		var got *models.CurrentUser
		w := httptest.NewRecorder()
		_, router := gin.CreateTestContext(w)
		router.GET("/oauth/authorize", m.OptionalAuth(), func(c *gin.Context) {
			got = GetCurrentUser(c)
			c.Status(http.StatusOK)
		})
		req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/oauth/authorize", nil)
		req.AddCookie(&http.Cookie{Name: IdpSessionCookieName, Value: id.String()})
		router.ServeHTTP(w, req)
		return got
	}
	assert.NotNil(t, run(23*time.Hour), "inside the 24h realm cap stays silent")
	assert.Nil(t, run(25*time.Hour), "past the 24h realm cap must re-login")
}
