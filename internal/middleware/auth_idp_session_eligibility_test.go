// SPDX-License-Identifier: AGPL-3.0-or-later

package middleware

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

	"github.com/dogukanturhal/falcon-id/internal/models"
	redispkg "github.com/dogukanturhal/falcon-id/pkg/redis"
)

type fakeIdpUsers struct{ u *models.User }

func (f fakeIdpUsers) GetByID(context.Context, uuid.UUID) (*models.User, error) { return f.u, nil }

type fakeIdpSessions struct{ s *models.Session }

func (f fakeIdpSessions) GetByID(context.Context, uuid.UUID) (*models.Session, error) {
	return f.s, nil
}

func (f fakeIdpSessions) GetByIDWithRealmContext(context.Context, uuid.UUID, uuid.UUID) (*models.Session, error) {
	return f.s, nil
}

// runIdpCookie drives OptionalAuth with only the SSO cookie and returns the
// resolved user (nil = rejected), the cache and the cookie id.
func runIdpCookie(t *testing.T, data *redispkg.IdpSessionData, users idpUserLookup, sessions idpSessionReader) (*models.CurrentUser, *redispkg.SessionCache, uuid.UUID, *httptest.ResponseRecorder) {
	t.Helper()
	cfg := authTestConfig()
	m := NewAuthMiddleware(newAuthTestTokenService(cfg), cfg)
	cache := newTestSessionCacheForMiddleware(t)
	m.SetSessionCache(cache)
	if users != nil {
		m.SetIdpUserLookup(users)
	}
	if sessions != nil {
		m.SetIdpSessionReader(sessions)
	}
	id := uuid.New()
	require.NoError(t, cache.SetIdpSession(context.Background(), id, data))

	var got *models.CurrentUser
	w := httptest.NewRecorder()
	_, router := gin.CreateTestContext(w)
	router.GET("/x", m.OptionalAuth(), func(c *gin.Context) {
		got = GetCurrentUser(c)
		c.Status(http.StatusOK)
	})
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/x", nil)
	req.AddCookie(&http.Cookie{Name: "falcon_idp_session", Value: id.String()})
	router.ServeHTTP(w, req)
	return got, cache, id, w
}

func idpData(userID uuid.UUID) *redispkg.IdpSessionData {
	return &redispkg.IdpSessionData{UserID: userID, TenantID: uuid.New(), AuthTime: time.Now().Unix(), SessionID: uuid.New()}
}

func liveSession(userID uuid.UUID) *models.Session {
	return &models.Session{ID: uuid.New(), UserID: userID, IsActive: true}
}

func TestIdpCookie_DisabledUserWithLiveSSORejected(t *testing.T) {
	uid := uuid.New()
	disabled := &models.User{ID: uid, IsActive: false, ActivationStatus: "active"}
	got, cache, id, w := runIdpCookie(t, idpData(uid), fakeIdpUsers{disabled}, fakeIdpSessions{liveSession(uid)})
	assert.Nil(t, got, "disabled user must not be resurrected by the SSO cookie")
	rec, err := cache.GetIdpSession(context.Background(), id)
	require.NoError(t, err)
	assert.Nil(t, rec, "rejected SSO record must be deleted")
	assert.Contains(t, w.Header().Get("Set-Cookie"), "falcon_idp_session=")
}

func TestIdpCookie_PendingDeletionAndLockedRejected(t *testing.T) {
	uid := uuid.New()
	for name, u := range map[string]*models.User{
		"pending_deletion": {ID: uid, IsActive: true, ActivationStatus: "pending_deletion"},
		"admin_deleted":    {ID: uid, IsActive: true, ActivationStatus: "admin_deleted"},
		"admin_locked":     {ID: uid, IsActive: true, ActivationStatus: "active", IsLocked: true},
	} {
		t.Run(name, func(t *testing.T) {
			got, _, _, _ := runIdpCookie(t, idpData(uid), fakeIdpUsers{u}, fakeIdpSessions{liveSession(uid)})
			assert.Nil(t, got)
		})
	}
}

func TestIdpCookie_NilBackingSessionIDRejected(t *testing.T) {
	uid := uuid.New()
	d := idpData(uid)
	d.SessionID = uuid.Nil
	got, _, _, _ := runIdpCookie(t, d, nil, nil)
	assert.Nil(t, got)
}

func TestIdpCookie_TimedLockAccepted(t *testing.T) {
	uid := uuid.New()
	future := time.Now().Add(time.Hour)
	u := &models.User{ID: uid, IsActive: true, IsLocked: true, LockedUntil: &future}
	got, _, _, _ := runIdpCookie(t, idpData(uid), fakeIdpUsers{u}, fakeIdpSessions{liveSession(uid)})
	require.NotNil(t, got, "failed-login throttle lock must not sign the user out")
}

func TestIdpCookie_ExplicitlyEndedBackingSessionRejected(t *testing.T) {
	uid := uuid.New()
	reason := "logout"
	s := &models.Session{ID: uuid.New(), UserID: uid, IsActive: false, EndReason: &reason}
	got, _, _, _ := runIdpCookie(t, idpData(uid), fakeIdpUsers{&models.User{ID: uid, IsActive: true}}, fakeIdpSessions{s})
	assert.Nil(t, got)
}

func TestIdpCookie_LapsedBackingSessionAccepted(t *testing.T) {
	uid := uuid.New()
	reason := models.SessionEndReasonExpired
	s := &models.Session{ID: uuid.New(), UserID: uid, IsActive: false, EndReason: &reason}
	got, _, _, _ := runIdpCookie(t, idpData(uid), fakeIdpUsers{&models.User{ID: uid, IsActive: true}}, fakeIdpSessions{s})
	assert.NotNil(t, got, "lapse reasons are not proof of revocation")
}

func TestIdpCookie_NilSessionRowAcceptedNotCached(t *testing.T) {
	uid := uuid.New()
	d := idpData(uid)
	got, cache, _, _ := runIdpCookie(t, d, fakeIdpUsers{&models.User{ID: uid, IsActive: true}}, fakeIdpSessions{nil})
	require.NotNil(t, got, "RLS may hide the row; absence is not a revocation")
	assert.False(t, cache.IdpBackingKnownGood(context.Background(), d.SessionID))
}

func TestIdpCookie_SessionUserMismatchRejected(t *testing.T) {
	uid := uuid.New()
	got, _, _, _ := runIdpCookie(t, idpData(uid), fakeIdpUsers{&models.User{ID: uid, IsActive: true}}, fakeIdpSessions{liveSession(uuid.New())})
	assert.Nil(t, got)
}

type errIdpUsers struct{}

func (errIdpUsers) GetByID(context.Context, uuid.UUID) (*models.User, error) {
	return nil, assert.AnError
}

func TestIdpCookie_LookupErrorRefusesButKeepsRecord(t *testing.T) {
	uid := uuid.New()
	got, cache, id, _ := runIdpCookie(t, idpData(uid), errIdpUsers{}, fakeIdpSessions{liveSession(uid)})
	assert.Nil(t, got)
	rec, err := cache.GetIdpSession(context.Background(), id)
	require.NoError(t, err)
	assert.NotNil(t, rec, "transient failure must not delete the SSO record")
}

func TestIdpCookie_HealthyUserAccepted(t *testing.T) {
	uid := uuid.New()
	got, cache, _, _ := runIdpCookie(t, idpData(uid), fakeIdpUsers{&models.User{ID: uid, IsActive: true, ActivationStatus: "active"}}, fakeIdpSessions{liveSession(uid)})
	require.NotNil(t, got)
	assert.Equal(t, uid, got.ID)
	_ = cache
}
