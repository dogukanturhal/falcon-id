// SPDX-License-Identifier: AGPL-3.0-or-later

package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/models"
	redispkg "github.com/dogukanturhal/falcon-id/pkg/redis"
)

// newTestSessionCacheForMiddleware spins up a miniredis-backed SessionCache for
// exercising the OptionalAuth falcon_idp_session (cookie-only) auth path.
func newTestSessionCacheForMiddleware(t *testing.T) *redispkg.SessionCache {
	t.Helper()
	mr, err := miniredis.Run()
	require.NoError(t, err, "failed to start miniredis")
	t.Cleanup(mr.Close)

	client, err := redispkg.NewClient(&redispkg.Config{
		URL:             "redis://" + mr.Addr(),
		MaxRetries:      1,
		MinIdleConns:    1,
		MaxIdleConns:    2,
		ConnMaxLifetime: time.Minute,
		DialTimeout:     2 * time.Second,
		ReadTimeout:     2 * time.Second,
		WriteTimeout:    2 * time.Second,
	}, zap.NewNop())
	require.NoError(t, err, "failed to create Redis client")
	t.Cleanup(func() { _ = client.Close() })

	return redispkg.NewSessionCache(client, "test", 30*time.Minute)
}

// runOptionalAuthIdpSessionPath wires an AuthMiddleware with a miniredis IdP
// session for the given tenant, drives OptionalAuth with ONLY the
// falcon_idp_session cookie (no access token, no Authorization header) so the
// resolveIdpSessionCookie arm runs, and returns the resolved CurrentUser.
func runOptionalAuthIdpSessionPath(t *testing.T, tenantID uuid.UUID) *models.CurrentUser {
	t.Helper()
	cfg := authTestConfig()
	svc := newAuthTestTokenService(cfg)
	m := NewAuthMiddleware(svc, cfg)

	cache := newTestSessionCacheForMiddleware(t)
	m.SetSessionCache(cache)

	idpSessionID := uuid.New()
	require.NoError(t, cache.SetIdpSession(context.Background(), idpSessionID, &redispkg.IdpSessionData{
		UserID:    uuid.New(),
		TenantID:  tenantID,
		Username:  "witness-admin",
		Email:     "witness-admin@example.com",
		AuthTime:  time.Now().Unix(),
		SessionID: uuid.New(),
	}))

	var captured *models.CurrentUser
	w := httptest.NewRecorder()
	_, router := gin.CreateTestContext(w)
	router.GET("/witness", m.OptionalAuth(), func(c *gin.Context) {
		captured = GetCurrentUser(c)
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/witness", nil)
	req.AddCookie(&http.Cookie{Name: "falcon_idp_session", Value: idpSessionID.String()})
	router.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	require.NotNil(t, captured, "OptionalAuth must populate CurrentUser from the falcon_idp_session cookie")
	require.Equal(t, models.AuthMethodIdpSession, captured.AuthMethod,
		"this must be the IdP-session arm (not the access-token arm) — otherwise the test isn't covering the witness flow")
	return captured
}

// TestOptionalAuth_IdpSessionPath_DerivesPlatformAdmin_ForInternalTenant locks
// the fix for the WebAuthn witness-enrollment 403. The witness page is mounted
// on OptionalAuth and, in the real flow, the browser only holds the
// falcon_idp_session SSO cookie (the access token lives in the Tauri app). The
// IdP-session arm previously dropped IsPlatformAdmin, so every genuine platform
// admin was denied ("Platform admin required") even with the correct tenant.
// IsPlatformAdmin is tenant-derived (token_service.go computes it as
// tenant==exampletenant), and the IdP session carries the authentic tenant,
// so the cookie path MUST derive the same flag.
func TestOptionalAuth_IdpSessionPath_DerivesPlatformAdmin_ForInternalTenant(t *testing.T) {
	user := runOptionalAuthIdpSessionPath(t, uuid.MustParse(models.HexxlockInternalTenantID))
	assert.True(t, user.IsPlatformAdmin,
		"exampletenant tenant on the IdP-session path MUST resolve IsPlatformAdmin=true (matches token-issuance derivation)")
	assert.Equal(t, models.HexxlockInternalTenantID, user.TenantID.String())
}

// TestOptionalAuth_IdpSessionPath_NonInternalTenant_NotPlatformAdmin is the
// negative control: a non-internal tenant on the same path must NOT gain
// platform-admin status, so the derivation cannot widen privilege.
func TestOptionalAuth_IdpSessionPath_NonInternalTenant_NotPlatformAdmin(t *testing.T) {
	user := runOptionalAuthIdpSessionPath(t, uuid.New())
	assert.False(t, user.IsPlatformAdmin,
		"a non-exampletenant tenant MUST NOT be treated as platform admin on the IdP-session path")
}
