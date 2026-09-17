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

// newRedisBackedCSRF builds a CSRFMiddleware whose synchronizer-token store is a
// fresh miniredis instance, so the Path-1 (Redis) branch of validateToken is
// exercised (the default test config leaves RedisClient nil → cookie-only).
func newRedisBackedCSRF(t *testing.T) (*CSRFMiddleware, *redispkg.Client) {
	t.Helper()
	mr, err := miniredis.Run()
	require.NoError(t, err)
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
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })

	cfg := DefaultCSRFConfig()
	cfg.RedisClient = client
	cfg.CookieSecure = false
	return NewCSRFMiddlewareWithConfig(cfg), client
}

// routerWithSession mounts CSRF behind a middleware that injects a CurrentUser
// carrying sessionID — simulating OptionalAuth's IdP-session resolution, which
// is what the WebAuthn witness-enrollment page runs under.
func routerWithSession(m *CSRFMiddleware, sessionID uuid.UUID) *gin.Engine {
	router := gin.New()
	inject := func(c *gin.Context) {
		c.Set(CurrentUserKey, &models.CurrentUser{ID: uuid.New(), SessionID: sessionID})
		c.Next()
	}
	router.POST("/test", inject, m.CSRF(), func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"ok": true}) })
	return router
}

// TestCSRF_SynchronizerMismatch_FallsThroughToDoubleSubmitCookie locks the
// witness-enrollment CSRF fix. When the per-session synchronizer slot in Redis
// has been overwritten (mismatching the request's token), a valid double-submit
// cookie (hexxlock_csrf == X-CSRF-Token) MUST still pass instead of the old
// short-circuit-to-403. This is what makes the server-rendered witness page
// robust to concurrent renders/retries overwriting the single Redis slot.
func TestCSRF_SynchronizerMismatch_FallsThroughToDoubleSubmitCookie(t *testing.T) {
	m, client := newRedisBackedCSRF(t)
	sessionID := uuid.New()
	// Simulate the synchronizer slot overwritten by a later render.
	require.NoError(t, client.Set(context.Background(), m.getRedisKey(sessionID), "stale-overwritten-token", time.Hour))

	pageToken := "page-render-token-abc"
	router := routerWithSession(m, sessionID)
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/test", nil)
	req.Header.Set(CSRFTokenHeader, pageToken)
	req.AddCookie(&http.Cookie{Name: CSRFCookieName, Value: pageToken}) // double-submit: cookie == header
	req.Host = testExampleDomain

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code,
		"synchronizer mismatch + matching double-submit cookie MUST pass (witness-enrollment robustness)")
}

// TestCSRF_SynchronizerMismatch_NoCookie_StillRejects is the negative control:
// a mismatched synchronizer token with NO double-submit cookie must still 403 —
// the fall-through must not weaken protection when no second proof exists.
func TestCSRF_SynchronizerMismatch_NoCookie_StillRejects(t *testing.T) {
	m, client := newRedisBackedCSRF(t)
	sessionID := uuid.New()
	require.NoError(t, client.Set(context.Background(), m.getRedisKey(sessionID), "stale-overwritten-token", time.Hour))

	router := routerWithSession(m, sessionID)
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/test", nil)
	req.Header.Set(CSRFTokenHeader, "page-render-token-abc") // no hexxlock_csrf cookie
	req.Host = testExampleDomain

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusForbidden, w.Code,
		"synchronizer mismatch with no double-submit cookie MUST still be rejected")
}

// TestCSRF_SynchronizerMatch_StillPasses guards the primary path is intact: a
// matching synchronizer token passes via Path 1 without needing a cookie.
func TestCSRF_SynchronizerMatch_StillPasses(t *testing.T) {
	m, client := newRedisBackedCSRF(t)
	sessionID := uuid.New()
	token := "synchronized-token-xyz"
	require.NoError(t, client.Set(context.Background(), m.getRedisKey(sessionID), token, time.Hour))

	router := routerWithSession(m, sessionID)
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/test", nil)
	req.Header.Set(CSRFTokenHeader, token)
	req.Host = testExampleDomain

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code, "matching synchronizer token MUST still pass via Path 1")
}
