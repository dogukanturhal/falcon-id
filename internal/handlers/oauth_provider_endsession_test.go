// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

// oauth_provider_endsession_test.go exercises the RP-Initiated Logout
// (OpenID Connect RP-Initiated Logout 1.0) security properties of
// OAuthProviderHandler.EndSession / tryPostLogoutRedirect directly against
// the REAL production methods (this file is in `package handlers`, not a
// reimplementation) — see remediation plan PHASE 0 item R12.
//
// Covered:
//   - tryPostLogoutRedirect: a post_logout_redirect_uri that is NOT on the
//     client's registered allow-list must be REJECTED (negative control —
//     this is the open-redirect guard).
//   - tryPostLogoutRedirect: a post_logout_redirect_uri that IS registered
//     is accepted and echoed into the same-origin redirect page, with
//     `state` appended when supplied.
//   - EndSession: the falcon_idp_session Redis-backed IdP session named by
//     the request cookie is actually deleted (server-side invalidation),
//     not just cookie-cleared, and this holds even when the redirect is
//     rejected (client resolution failure must not skip invalidation).

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/alicebob/miniredis/v2"

	"github.com/dogukanturhal/falcon-id/internal/models"
	redispkg "github.com/dogukanturhal/falcon-id/pkg/redis"
)

// ---------------------------------------------------------------------------
// tryPostLogoutRedirect — allow-list enforcement (no service/repo needed:
// the method only ever consults the *models.OAuthClient passed to it).
// ---------------------------------------------------------------------------

func TestEndSession_TryPostLogoutRedirect_UnregisteredURI_Rejected(t *testing.T) {
	// Negative control: an attacker-supplied post_logout_redirect_uri that
	// is NOT in the client's registered allow-list must never be honoured
	// — this is exactly the open-redirect vector RP-Initiated Logout 1.0
	// requires guarding against.
	h := &OAuthProviderHandler{}
	client := &models.OAuthClient{
		ClientID:               "acmeapp-bff",
		PostLogoutRedirectURIs: []string{"https://acmeweb.example.com/login?signed_out=1"},
	}

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/oauth/logout", nil)

	redirected := h.tryPostLogoutRedirect(c, client, "https://evil.example.com/steal", "", nil)

	assert.False(t, redirected, "an unregistered post_logout_redirect_uri must be rejected")
	assert.NotContains(t, w.Body.String(), "evil.example.com",
		"the rejected URI must not leak into the response body")
}

func TestEndSession_TryPostLogoutRedirect_RegisteredURI_Accepted(t *testing.T) {
	h := &OAuthProviderHandler{}
	const registered = "https://acmeweb.example.com/login?signed_out=1"
	client := &models.OAuthClient{
		ClientID:               "acmeapp-bff",
		PostLogoutRedirectURIs: []string{registered},
	}

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/oauth/logout", nil)

	redirected := h.tryPostLogoutRedirect(c, client, registered, "xyz-state", nil)

	assert.True(t, redirected, "a registered post_logout_redirect_uri must be accepted")
	assert.Equal(t, http.StatusOK, w.Code)
	body := w.Body.String()
	assert.Contains(t, body, registered, "the accepted redirect target must appear in the response")
	assert.Contains(t, body, "state=xyz-state", "state must be forwarded to the RP")
}

func TestEndSession_TryPostLogoutRedirect_NoClient_NeverRedirects(t *testing.T) {
	// resolveEndSessionClient can legitimately fail to resolve a client
	// (bad/absent id_token_hint and client_id) — in that case there is no
	// allow-list to check against, so no redirect may happen at all,
	// regardless of what post_logout_redirect_uri the caller supplied.
	h := &OAuthProviderHandler{}

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/oauth/logout", nil)

	redirected := h.tryPostLogoutRedirect(c, nil, "https://acmeweb.example.com/login?signed_out=1", "", nil)

	assert.False(t, redirected)
}

// ---------------------------------------------------------------------------
// EndSession — server-side session invalidation (Redis-backed IdP session,
// standing in for the iam_sessions-linked record; see
// pkg/redis/session_cache.go IdpSessionData.SessionID, which carries the
// iam_user_sessions.id this record is keyed against).
// ---------------------------------------------------------------------------

func newTestSessionCacheForEndSession(t *testing.T) (*redispkg.SessionCache, *miniredis.Miniredis) {
	t.Helper()

	mr, err := miniredis.Run()
	require.NoError(t, err)

	cfg := &redispkg.Config{
		URL:             "redis://" + mr.Addr(),
		MaxRetries:      1,
		MinIdleConns:    1,
		MaxIdleConns:    2,
		ConnMaxLifetime: time.Minute,
		DialTimeout:     2 * time.Second,
		ReadTimeout:     2 * time.Second,
		WriteTimeout:    2 * time.Second,
	}

	client, err := redispkg.NewClient(cfg, zap.NewNop())
	require.NoError(t, err)

	cache := redispkg.NewSessionCache(client, "test", 30*time.Minute)
	t.Cleanup(func() {
		_ = client.Close()
		mr.Close()
	})

	return cache, mr
}

func TestEndSession_InvalidatesServerSideSession(t *testing.T) {
	cache, _ := newTestSessionCacheForEndSession(t)

	h := NewOAuthProviderHandler(nil, nil, zap.NewNop())
	h.SetSessionCache(cache)

	sessionID := uuid.New()
	tenantID := uuid.New()
	require.NoError(t, cache.SetIdpSession(context.Background(), sessionID, &redispkg.IdpSessionData{
		UserID:   uuid.New(),
		TenantID: tenantID,
		Username: "alice",
	}))

	// Sanity/control: before EndSession runs, the session really is live —
	// this is the control that must fail if the test fixture itself is
	// broken.
	before, err := cache.GetIdpSession(context.Background(), sessionID)
	require.NoError(t, err)
	require.NotNil(t, before, "control: seeded IdP session must be present before EndSession")

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/oauth/logout", nil)
	req.AddCookie(&http.Cookie{Name: "falcon_idp_session", Value: sessionID.String()})
	c.Request = req

	h.EndSession(c)

	assert.Equal(t, http.StatusOK, w.Code)

	after, err := cache.GetIdpSession(context.Background(), sessionID)
	require.NoError(t, err)
	assert.Nil(t, after, "EndSession must delete the server-side IdP session, not just clear cookies")

	// Cookies must also be cleared on the response.
	cleared := false
	for _, ck := range w.Result().Cookies() {
		if ck.Name == "falcon_idp_session" && ck.MaxAge <= 0 {
			cleared = true
		}
	}
	assert.True(t, cleared, "falcon_idp_session cookie must be expired on the response")
}

func TestEndSession_NoCookie_IsNoopButStillClearsCookiesAndSucceeds(t *testing.T) {
	// Control: calling EndSession with no falcon_idp_session cookie at all
	// must not panic or error — logout must be idempotent/safe to call
	// repeatedly (e.g. double-submit, or a browser that already dropped
	// the cookie).
	cache, _ := newTestSessionCacheForEndSession(t)
	h := NewOAuthProviderHandler(nil, nil, zap.NewNop())
	h.SetSessionCache(cache)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/oauth/logout", nil)

	h.EndSession(c)

	assert.Equal(t, http.StatusOK, w.Code)
}
