// SPDX-License-Identifier: AGPL-3.0-or-later

package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/pkg/config"
)

// buildValidTokenWithAuthTime mirrors buildValidToken but lets the caller
// pin auth_time. Required for RFC 9470 freshness regression tests where
// the JWT auth_time claim drives downstream RequireFreshAuth gates +
// /oauth/authorize max_age enforcement; the standard helper omits the
// claim, which masks the very bug this file regresses against.
func buildValidTokenWithAuthTime(t *testing.T, cfg *config.Config, userID, tenantID, sessionID uuid.UUID, authTime int64) string {
	t.Helper()
	now := time.Now()
	claims := jwt.MapClaims{
		"iss":               cfg.JWTIssuer,
		"aud":               "hexxlock-services",
		"sub":               userID.String(),
		"user_id":           userID.String(),
		"tenant_id":         tenantID.String(),
		"username":          "testuser",
		"email":             "test@example.com",
		"session_id":        sessionID.String(),
		"realm_id":          uuid.New().String(),
		"realm_slug":        "default",
		"realm_type":        "shared",
		"is_platform_admin": false,
		"v":                 0,
		"iat":               now.Unix(),
		"exp":               now.Add(15 * time.Minute).Unix(),
		"nbf":               now.Unix(),
		"jti":               uuid.New().String(),
		"auth_time":         authTime,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString([]byte(cfg.JWTSecret))
	require.NoError(t, err)
	return signed
}

// TestOptionalAuth_PropagatesAuthTime_OntoCurrentUser locks the contract
// that OptionalAuth populates CurrentUser.AuthTime from the JWT
// auth_time claim — the bug fixed in this commit had the inline
// construction silently drop the field, which broke /oauth/authorize
// max_age enforcement (every just-minted token was misclassified as
// "infinitely stale" → infinite redirect loop on every OIDC flow with
// max_age=N, live repro 2026-05-24).
//
// The duplicate-construction surface was eliminated by routing through
// setAuthContext (single source of truth, shared with RequireAuth);
// this test makes sure that lock-in stays in place.
func TestOptionalAuth_PropagatesAuthTime_OntoCurrentUser(t *testing.T) {
	cfg := authTestConfig()
	svc := newAuthTestTokenService(cfg)
	m := NewAuthMiddleware(svc, cfg)

	userID := uuid.New()
	tenantID := uuid.New()
	sessionID := uuid.New()
	authTime := time.Now().Add(-30 * time.Second).Unix()

	var capturedUser *models.CurrentUser
	w := httptest.NewRecorder()
	_, router := gin.CreateTestContext(w)
	router.GET("/public", m.OptionalAuth(), func(c *gin.Context) {
		capturedUser = GetCurrentUser(c)
		c.Status(http.StatusOK)
	})

	token := buildValidTokenWithAuthTime(t, cfg, userID, tenantID, sessionID, authTime)
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/public", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	router.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	require.NotNil(t, capturedUser)
	assert.Equal(t, authTime, capturedUser.AuthTime,
		"OptionalAuth MUST propagate the JWT auth_time claim onto CurrentUser — RFC 9470 freshness gates depend on it")
	assert.Equal(t, models.AuthMethodAccessToken, capturedUser.AuthMethod,
		"OptionalAuth MUST set AuthMethod=AccessToken for token-auth requests so RequireAccessToken-style gates can distinguish from IdP-cookie auth")
}

// TestOptionalAuth_PropagatesAuthTime_BearerHeaderPath is the same
// contract on the Authorization-header arm (vs the falcon_access_token
// cookie arm covered above) — both paths flow through the same
// setAuthContext call now, so this is a single regression line that
// would have caught the original bug on either entry point.
func TestOptionalAuth_PropagatesAuthTime_CookiePath(t *testing.T) {
	cfg := authTestConfig()
	svc := newAuthTestTokenService(cfg)
	m := NewAuthMiddleware(svc, cfg)

	userID := uuid.New()
	tenantID := uuid.New()
	sessionID := uuid.New()
	authTime := time.Now().Add(-2 * time.Minute).Unix()

	var capturedUser *models.CurrentUser
	w := httptest.NewRecorder()
	_, router := gin.CreateTestContext(w)
	router.GET("/cookie", m.OptionalAuth(), func(c *gin.Context) {
		capturedUser = GetCurrentUser(c)
		c.Status(http.StatusOK)
	})

	token := buildValidTokenWithAuthTime(t, cfg, userID, tenantID, sessionID, authTime)
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/cookie", nil)
	req.AddCookie(&http.Cookie{Name: "falcon_access_token", Value: token})
	router.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	require.NotNil(t, capturedUser)
	assert.Equal(t, authTime, capturedUser.AuthTime,
		"OptionalAuth MUST propagate auth_time from the falcon_access_token cookie path identically to the Authorization-header path")
}
