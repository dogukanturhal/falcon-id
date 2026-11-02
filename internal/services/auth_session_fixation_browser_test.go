// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/google/uuid"
	"github.com/pashagolub/pgxmock/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/internal/repositories"
	"github.com/dogukanturhal/falcon-id/pkg/redis"
)

func newBrowserScopedAuthService(t *testing.T) (*AuthService, pgxmock.PgxPoolIface, *redis.SessionCache) {
	t.Helper()
	mr, err := miniredis.Run()
	require.NoError(t, err)
	t.Cleanup(mr.Close)
	client, err := redis.NewClient(&redis.Config{
		URL: "redis://" + mr.Addr(), MaxRetries: 1, MinIdleConns: 1, MaxIdleConns: 2,
		ConnMaxLifetime: time.Minute, DialTimeout: 2 * time.Second,
		ReadTimeout: 2 * time.Second, WriteTimeout: 2 * time.Second,
	}, zap.NewNop())
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })
	cache := redis.NewSessionCache(client, "test", 30*time.Minute)

	mock, err := pgxmock.NewPool()
	require.NoError(t, err)
	t.Cleanup(mock.Close)
	repo := (&repositories.SessionRepository{}).WithDB(mock)
	return &AuthService{sessionRepo: repo, sessionCache: cache}, mock, cache
}

// Two devices of one user share a NAT/WireGuard IP. Signing in on the Mac
// (which presents no old cookie) must not end the iPhone's session.
func TestInvalidateBeforeLogin_SameIPOtherBrowser_Survives(t *testing.T) {
	s, mock, cache := newBrowserScopedAuthService(t)
	userID := uuid.New()
	iphoneIdp := uuid.New()
	require.NoError(t, cache.SetIdpSession(context.Background(), iphoneIdp, &redis.IdpSessionData{
		UserID: userID, TenantID: uuid.New(), SessionID: uuid.New(), AuthTime: time.Now().Unix(),
	}))

	// Mac request carries no falcon_idp_session cookie → nothing may be ended
	// (pgxmock has no expectations, so any query fails the test).
	require.NoError(t, s.invalidateExistingSessionsBeforeLogin(context.Background(), userID))
	assert.NoError(t, mock.ExpectationsWereMet())

	still, err := cache.GetIdpSession(context.Background(), iphoneIdp)
	require.NoError(t, err)
	assert.NotNil(t, still, "other device's SSO record must survive")
}

// Re-login in the same browser retires exactly that browser's old session.
func TestInvalidateBeforeLogin_SameBrowser_OldSessionReplaced(t *testing.T) {
	s, mock, cache := newBrowserScopedAuthService(t)
	userID, oldSession, idpID := uuid.New(), uuid.New(), uuid.New()
	otherIdp := uuid.New()
	require.NoError(t, cache.SetIdpSession(context.Background(), idpID, &redis.IdpSessionData{
		UserID: userID, TenantID: uuid.New(), SessionID: oldSession, AuthTime: time.Now().Unix(),
	}))
	require.NoError(t, cache.SetIdpSession(context.Background(), otherIdp, &redis.IdpSessionData{
		UserID: userID, TenantID: uuid.New(), SessionID: uuid.New(), AuthTime: time.Now().Unix(),
	}))

	mock.ExpectQuery(`(?s)WITH ended AS .*SELECT count`).
		WithArgs(oldSession, models.SessionEndReasonRegeneratedOnLogin).
		WillReturnRows(pgxmock.NewRows([]string{"count"}).AddRow(int64(1)))

	ctx := redis.WithPresentedIdpSession(context.Background(), idpID)
	require.NoError(t, s.invalidateExistingSessionsBeforeLogin(ctx, userID))
	assert.NoError(t, mock.ExpectationsWereMet())

	gone, err := cache.GetIdpSession(context.Background(), idpID)
	require.NoError(t, err)
	assert.Nil(t, gone, "presented browser's IdP record is removed")
	other, err := cache.GetIdpSession(context.Background(), otherIdp)
	require.NoError(t, err)
	assert.NotNil(t, other)
}

// A cookie that belongs to another user must not let a login end that user's session.
func TestInvalidateBeforeLogin_ForeignCookie_Ignored(t *testing.T) {
	s, mock, cache := newBrowserScopedAuthService(t)
	idpID := uuid.New()
	require.NoError(t, cache.SetIdpSession(context.Background(), idpID, &redis.IdpSessionData{
		UserID: uuid.New(), TenantID: uuid.New(), SessionID: uuid.New(), AuthTime: time.Now().Unix(),
	}))
	ctx := redis.WithPresentedIdpSession(context.Background(), idpID)
	require.NoError(t, s.invalidateExistingSessionsBeforeLogin(ctx, uuid.New()))
	assert.NoError(t, mock.ExpectationsWereMet())
}
