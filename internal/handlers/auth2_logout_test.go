// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/internal/services"
	"github.com/dogukanturhal/falcon-id/pkg/config"
	redispkg "github.com/dogukanturhal/falcon-id/pkg/redis"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

type auth2LogoutService struct {
	client  *models.OAuthClient
	valid   bool
	subject *uuid.UUID
}

func (s auth2LogoutService) EndSession(context.Context, string) (*models.OAuthClient, *uuid.UUID, error) {
	if !s.valid {
		return nil, nil, errors.New("invalid hint")
	}
	id := uuid.New()
	if s.subject != nil {
		return s.client, s.subject, nil
	}
	return s.client, &id, nil
}
func (s auth2LogoutService) GetClientByClientID(context.Context, string) (*models.OAuthClient, error) {
	return s.client, nil
}

func TestAuth2EndSession_ValidHintSkipsPageAndInvalidatesSession(t *testing.T) {
	cache, _ := newTestSessionCacheForEndSession(t)
	const target = "https://acmeapp.example/login?signed_out=1"
	client := &models.OAuthClient{ClientID: "acmeapp-bff", PostLogoutRedirectURIs: []string{target}}
	subject := uuid.New()
	h := &OAuthProviderHandler{logger: zap.NewNop(), sessionCache: cache, logoutService: auth2LogoutService{client: client, valid: true, subject: &subject}}
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/oauth/logout?client_id=acmeapp-bff&id_token_hint=valid&post_logout_redirect_uri="+url.QueryEscape(target)+"&state=opaque", nil)
	id := uuid.New()
	require.NoError(t, cache.SetIdpSession(context.Background(), id, &redispkg.IdpSessionData{UserID: subject, TenantID: uuid.New()}))
	c.Request.AddCookie(&http.Cookie{Name: "falcon_idp_session", Value: id.String()})
	h.EndSession(c)
	require.Equal(t, 302, w.Code)
	require.NotContains(t, w.Body.String(), "Signing you out")
	u, err := url.Parse(w.Header().Get("Location"))
	require.NoError(t, err)
	require.Equal(t, "1", u.Query().Get("signed_out"))
	require.Equal(t, "opaque", u.Query().Get("state"))
	require.NotEmpty(t, w.Result().Cookies())
	after, err := cache.GetIdpSession(context.Background(), id)
	require.NoError(t, err)
	require.Nil(t, after)
}

func TestAuth2EndSession_InvalidHintUsesBrandedFallbackAndRejectsOpenRedirect(t *testing.T) {
	client := &models.OAuthClient{ClientID: "acmeapp-bff", PostLogoutRedirectURIs: []string{"https://acmeapp.example/login?signed_out=1"}}
	h := &OAuthProviderHandler{logger: zap.NewNop(), logoutService: auth2LogoutService{client: client}}
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/oauth/logout?client_id=acmeapp-bff&id_token_hint=invalid&post_logout_redirect_uri=https://evil.example", nil)
	h.EndSession(c)
	require.Equal(t, 200, w.Code)
	require.Contains(t, w.Body.String(), "AcmeApp")
	require.Contains(t, w.Body.String(), "prefers-color-scheme:dark")
	require.NotContains(t, w.Body.String(), "evil.example")
	require.Empty(t, w.Header().Get("Location"))
}

func TestAuth2MFAErrors_HumanCodesAndSanitizedInfrastructure(t *testing.T) {
	for _, tc := range []struct {
		err    error
		status int
		code   string
	}{
		{&services.MFAFlowError{Code: "mfa_session_expired"}, 401, "mfa_session_expired"},
		{&services.MFAFlowError{Code: "mfa_code_invalid", RemainingAttempts: 3}, 401, "mfa_code_invalid"},
		{&services.MFAFlowError{Code: "mfa_rate_limited"}, 429, "mfa_rate_limited"},
		{errors.New("redis: nil internal DSN"), 503, "traceId"},
	} {
		t.Run(tc.code, func(t *testing.T) {
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			respondMFAFlowError(c, tc.err)
			require.Equal(t, tc.status, w.Code)
			require.Contains(t, w.Body.String(), tc.code)
			require.NotContains(t, w.Body.String(), "DSN")
			if tc.status != 503 {
				name := map[string]string{"mfa_session_expired": "mfa-session-expired.json", "mfa_code_invalid": "mfa-code-invalid.json", "mfa_rate_limited": "mfa-rate-limited.json"}[tc.code]
				fixture, err := os.ReadFile("../../docs/contracts/auth2/" + name)
				require.NoError(t, err)
				require.JSONEq(t, string(fixture), w.Body.String())
			}
		})
	}
}

func TestAuth2Prompt_ResumeKeepsPKCEStateAndDoesNotLoop(t *testing.T) {
	u, err := url.Parse(loginResumeURL("/oauth/authorize?client_id=acmeapp-bff&prompt=login&state=opaque&code_challenge=pkce&redirect_uri=https%3A%2F%2Facmeapp.example%2Fcallback"))
	require.NoError(t, err)
	require.Empty(t, u.Query().Get("prompt"))
	require.Equal(t, "opaque", u.Query().Get("state"))
	require.Equal(t, "pkce", u.Query().Get("code_challenge"))
	require.Equal(t, "https://acmeapp.example/callback", u.Query().Get("redirect_uri"))
}

func TestAuth2MFACompletion_ReplayResetsCookiesAndKeepsResponseSmall(t *testing.T) {
	cache, mr := newTestSessionCacheForEndSession(t)
	cfg := &config.Config{JWTSecret: "fixture-signature-only-32-characters", JWTHMACFallbackEnabled: true}
	tokens := services.NewTokenService(cfg, nil, nil)
	auth := services.NewAuthService(cfg, nil, nil, nil, nil, tokens, nil, nil)
	auth.SetSessionCache(cache)
	h := NewAuthHandler(auth, tokens)
	h.SetSessionCache(cache)
	id := uuid.NewString()
	code := "123456"
	bound, _ := json.Marshal([]any{id, code, "browser", false, "", ""})
	digest := sha256.Sum256(bound)
	resp := &models.LoginResponse{AccessToken: "fixture-token", ExpiresIn: 900, User: &models.UserResponse{ID: uuid.New(), TenantID: uuid.New(), Username: "fixture"}}
	proofTime := time.Now().Add(-time.Minute).Unix()
	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"user_id": resp.User.ID.String(), "tenant_id": resp.User.TenantID.String(), "session_id": uuid.NewString(), "auth_time": proofTime, "exp": time.Now().Add(time.Hour).Unix()}).SignedString([]byte(cfg.JWTSecret))
	require.NoError(t, err)
	resp.AccessToken = token
	record, _ := json.Marshal(map[string]any{"fingerprint": hex.EncodeToString(digest[:]), "response": resp})
	require.NoError(t, cache.Client().Set(context.Background(), "mfa:completion:"+id, string(record), time.Minute))
	for i := 0; i < 2; i++ {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		body, _ := json.Marshal(models.MFACompleteRequest{SessionID: id, MFACode: code})
		c.Request = httptest.NewRequest(http.MethodPost, "/api/v1/auth/mfa/complete", strings.NewReader(string(body)))
		c.Request.Header.Set("Content-Type", "application/json")
		c.Request.Header.Set("User-Agent", "browser")
		if i == 0 {
			c.Request.Header.Set("Prefer", "return=minimal")
		}
		h.CompleteMFALogin(c)
		require.Equal(t, 200, w.Code)
		if i == 0 {
			require.JSONEq(t, `{"success":true}`, w.Body.String())
			require.Equal(t, "return=minimal", w.Header().Get("Preference-Applied"))
		} else {
			var body map[string]any
			require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
			require.Equal(t, resp.AccessToken, body["access_token"])
			require.NotContains(t, body, "user")
		}
		require.Less(t, w.Body.Len(), 8192)
		cookies := map[string]*http.Cookie{}
		for _, cookie := range w.Result().Cookies() {
			cookies[cookie.Name] = cookie
		}
		require.Contains(t, cookies, "falcon_idp_session")
		require.True(t, cookies["falcon_idp_session"].HttpOnly)
		idpID, err := uuid.Parse(cookies["falcon_idp_session"].Value)
		require.NoError(t, err)
		data, err := cache.GetIdpSession(context.Background(), idpID)
		require.NoError(t, err)
		require.Equal(t, proofTime, data.AuthTime)
	}
	mr.FastForward(61 * time.Second)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	body, _ := json.Marshal(models.MFACompleteRequest{SessionID: id, MFACode: code})
	c.Request = httptest.NewRequest(http.MethodPost, "/api/v1/auth/mfa/complete", strings.NewReader(string(body)))
	c.Request.Header.Set("Content-Type", "application/json")
	c.Request.Header.Set("User-Agent", "browser")
	h.CompleteMFALogin(c)
	require.Equal(t, 401, w.Code)
	require.Contains(t, w.Body.String(), "mfa_session_expired")
}
