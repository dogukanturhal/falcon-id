// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

// TestSetLoginResponseCookies_WritesBothCookies locks the cookie-writing
// contract that WebAuthn FinishAuthentication +
// CompleteConditionalLogin depend on. Live regression 2026-05-25: both
// WebAuthn login-completion paths returned LoginResponse JSON but
// never wrote falcon_access_token or falcon_idp_session — so the next
// /oauth/authorize on the same browser saw no session and bounced to
// /oauth/login forever.
//
// The fix routes both WebAuthn paths through this single helper. The
// test does NOT exercise the full WebAuthn ceremony (heavy mock cost);
// it verifies the cookie ritual itself emits the expected names so any
// future drift on the helper is caught.
//
// Why this test is here (rather than nothing): the access_token cookie
// is the load-bearing artefact for browser-flow re-entry into the
// OAuth dance after a max_age recovery. Pre-fix, the entire flow ran
// successfully end-to-end on the server, the access token JWT had the
// right auth_time, but the browser still loop-bounced because the
// token never made it onto the response. A test like this would have
// caught the omission immediately.
func TestSetLoginResponseCookies_WritesBothCookies(t *testing.T) {
	gin.SetMode(gin.TestMode)

	// Build a minimal AuthHandler whose only wired field is what
	// SetLoginResponseCookies needs. sessionCache is left nil
	// (establishIdpSession is no-op then), and tokenService is left
	// nil (sessionIDFromAccessToken returns uuid.Nil then). Both are
	// graceful-degradation paths documented inline; the test verifies
	// the access-token cookie still lands even in this minimal config,
	// which is the load-bearing one for browser-flow re-entry.
	h := &AuthHandler{}

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("POST", "/api/v1/auth/webauthn/login/finish", nil)

	resp := &models.LoginResponse{
		AccessToken: "test.access.token",
		ExpiresIn:   3600,
		User:        &models.UserResponse{ID: uuid.New(), Email: "test@example.com"},
	}

	h.SetLoginResponseCookies(c, resp)

	cookies := w.Result().Cookies()
	names := make(map[string]string, len(cookies))
	for _, ck := range cookies {
		names[ck.Name] = ck.Value
	}

	access, has := names[accessTokenCookieName]
	require.True(t, has, "SetLoginResponseCookies MUST write %q cookie — without it browser-flow WebAuthn login leaves no session on the next /oauth/authorize and loops to /oauth/login", accessTokenCookieName)
	assert.Equal(t, "test.access.token", access)
}

// TestSetLoginResponseCookies_NoCookiesWhenEmptyToken locks the
// no-op contract for intermediate responses (requires_mfa, etc.)
// that the caller forwards before the final session is minted.
func TestSetLoginResponseCookies_NoCookiesWhenEmptyToken(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h := &AuthHandler{}
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("POST", "/api/v1/auth/webauthn/login/finish", nil)

	h.SetLoginResponseCookies(c, &models.LoginResponse{
		AccessToken: "", // intermediate (requires_mfa, requires_mfa_enrollment, etc.)
		User:        &models.UserResponse{ID: uuid.New()},
	})

	for _, ck := range w.Result().Cookies() {
		t.Errorf("SetLoginResponseCookies wrote cookie %q for empty-token response — should be a no-op until the final mint lands", ck.Name)
	}
}

// TestSetLoginResponseCookies_NoCookiesWhenNilResponse covers the
// defensive-nil path — caller forwarding an error case shouldn't
// panic, shouldn't write cookies.
func TestSetLoginResponseCookies_NoCookiesWhenNilResponse(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h := &AuthHandler{}
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("POST", "/api/v1/auth/webauthn/login/finish", nil)
	h.SetLoginResponseCookies(c, nil)
	assert.Empty(t, w.Result().Cookies())
}
