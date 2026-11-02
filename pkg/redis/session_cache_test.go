// SPDX-License-Identifier: AGPL-3.0-or-later

package redis

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// newTestSessionCache creates a SessionCache backed by a fresh miniredis instance.
func newTestSessionCache(t *testing.T) (*SessionCache, *miniredis.Miniredis) {
	t.Helper()

	mr, err := miniredis.Run()
	require.NoError(t, err, "failed to start miniredis")

	cfg := &Config{
		URL:             "redis://" + mr.Addr(),
		MaxRetries:      1,
		MinIdleConns:    1,
		MaxIdleConns:    2,
		ConnMaxLifetime: time.Minute,
		DialTimeout:     2 * time.Second,
		ReadTimeout:     2 * time.Second,
		WriteTimeout:    2 * time.Second,
	}

	client, err := NewClient(cfg, zap.NewNop())
	require.NoError(t, err, "failed to create Redis client")

	cache := NewSessionCache(client, "test", 30*time.Minute)
	t.Cleanup(func() {
		_ = client.Close()
		mr.Close()
	})

	return cache, mr
}

func makeSession() *CachedSession {
	return &CachedSession{
		SessionID:   uuid.New(),
		UserID:      uuid.New(),
		TenantID:    uuid.New(),
		Username:    "testuser",
		Email:       "test@example.com",
		Roles:       []string{"admin", "viewer"},
		Permissions: []string{"crm.view", "invoice.create"},
		DeviceInfo:  "Chrome/120",
		IPAddress:   "10.0.0.1",
		CreatedAt:   time.Now().Truncate(time.Second),
		ExpiresAt:   time.Now().Add(30 * time.Minute).Truncate(time.Second),
	}
}

func makeSessionData() (uuid.UUID, *SessionData) {
	sessionID := uuid.New()
	return sessionID, &SessionData{
		UserID:      uuid.New(),
		TenantID:    uuid.New(),
		Username:    "alice",
		Email:       "alice@example.com",
		Roles:       []string{"member"},
		Permissions: []string{"crm.view", "crm.*"},
		RealmID:     uuid.New(),
		RealmSlug:   "main",
		RealmType:   "tenant",
		RoleVersion: 5,
		DeviceInfo:  "Firefox/121",
		IPAddress:   "192.168.0.1",
		CreatedAt:   time.Now().Unix(),
	}
}

// ─── Set / Get ────────────────────────────────────────────────────────────────

func TestSessionCache_Set_Get_RoundTrip(t *testing.T) {
	cache, _ := newTestSessionCache(t)
	ctx := context.Background()

	session := makeSession()

	require.NoError(t, cache.Set(ctx, session))

	got, err := cache.Get(ctx, session.SessionID)
	require.NoError(t, err)
	require.NotNil(t, got)

	assert.Equal(t, session.SessionID, got.SessionID)
	assert.Equal(t, session.UserID, got.UserID)
	assert.Equal(t, session.TenantID, got.TenantID)
	assert.Equal(t, session.Username, got.Username)
	assert.Equal(t, session.Email, got.Email)
	assert.Equal(t, session.Roles, got.Roles)
	assert.Equal(t, session.Permissions, got.Permissions)
}

func TestSessionCache_Get_Miss(t *testing.T) {
	cache, _ := newTestSessionCache(t)
	ctx := context.Background()

	got, err := cache.Get(ctx, uuid.New())
	require.NoError(t, err, "cache miss should return nil, nil")
	assert.Nil(t, got)
}

// ─── Delete ───────────────────────────────────────────────────────────────────

func TestSessionCache_Delete_ExistingSession(t *testing.T) {
	cache, _ := newTestSessionCache(t)
	ctx := context.Background()

	session := makeSession()
	require.NoError(t, cache.Set(ctx, session))

	require.NoError(t, cache.Delete(ctx, session.SessionID))

	got, err := cache.Get(ctx, session.SessionID)
	require.NoError(t, err)
	assert.Nil(t, got, "session should be gone after Delete")
}

func TestSessionCache_Delete_NonExistentSession(t *testing.T) {
	cache, _ := newTestSessionCache(t)
	ctx := context.Background()

	// Deleting a non-existent session should not error.
	err := cache.Delete(ctx, uuid.New())
	require.NoError(t, err)
}

// ─── Exists ───────────────────────────────────────────────────────────────────

func TestSessionCache_Exists_True(t *testing.T) {
	cache, _ := newTestSessionCache(t)
	ctx := context.Background()

	session := makeSession()
	require.NoError(t, cache.Set(ctx, session))

	ok, err := cache.Exists(ctx, session.SessionID)
	require.NoError(t, err)
	assert.True(t, ok)
}

func TestSessionCache_Exists_False(t *testing.T) {
	cache, _ := newTestSessionCache(t)
	ctx := context.Background()

	ok, err := cache.Exists(ctx, uuid.New())
	require.NoError(t, err)
	assert.False(t, ok)
}

// ─── Refresh ─────────────────────────────────────────────────────────────────

func TestSessionCache_Refresh_ExtendsTTL(t *testing.T) {
	cache, mr := newTestSessionCache(t)
	ctx := context.Background()

	session := makeSession()
	require.NoError(t, cache.Set(ctx, session))

	// Fast-forward time so the original TTL is partially consumed.
	mr.FastForward(10 * time.Minute)

	require.NoError(t, cache.Refresh(ctx, session.SessionID))

	// After refresh the session should still be present.
	got, err := cache.Get(ctx, session.SessionID)
	require.NoError(t, err)
	assert.NotNil(t, got, "session should still exist after refresh")
}

func TestSessionCache_Refresh_NonExistentSession(t *testing.T) {
	cache, _ := newTestSessionCache(t)
	ctx := context.Background()

	// Refreshing a non-existent session should not error.
	err := cache.Refresh(ctx, uuid.New())
	require.NoError(t, err)
}

// ─── GetUserSessionCount ─────────────────────────────────────────────────────

func TestSessionCache_GetUserSessionCount(t *testing.T) {
	cache, _ := newTestSessionCache(t)
	ctx := context.Background()

	userID := uuid.New()

	// No sessions yet.
	count, err := cache.GetUserSessionCount(ctx, userID)
	require.NoError(t, err)
	assert.Equal(t, int64(0), count)

	// Add two sessions for the same user.
	for i := 0; i < 2; i++ {
		s := makeSession()
		s.UserID = userID
		require.NoError(t, cache.Set(ctx, s))
	}

	count, err = cache.GetUserSessionCount(ctx, userID)
	require.NoError(t, err)
	assert.Equal(t, int64(2), count)
}

// ─── DeleteUserSessions ───────────────────────────────────────────────────────

func TestSessionCache_DeleteUserSessions(t *testing.T) {
	cache, _ := newTestSessionCache(t)
	ctx := context.Background()

	userID := uuid.New()
	var sessionIDs []uuid.UUID

	// Add 3 sessions for the user.
	for i := 0; i < 3; i++ {
		s := makeSession()
		s.UserID = userID
		require.NoError(t, cache.Set(ctx, s))
		sessionIDs = append(sessionIDs, s.SessionID)
	}

	require.NoError(t, cache.DeleteUserSessions(ctx, userID))

	// All sessions should be gone.
	for _, sid := range sessionIDs {
		got, err := cache.Get(ctx, sid)
		require.NoError(t, err)
		assert.Nil(t, got, "session %s should be deleted", sid)
	}

	count, err := cache.GetUserSessionCount(ctx, userID)
	require.NoError(t, err)
	assert.Equal(t, int64(0), count)
}

func TestSessionCache_DeleteUserSessions_NoSessions(t *testing.T) {
	cache, _ := newTestSessionCache(t)
	ctx := context.Background()

	// Should not error when user has no sessions.
	err := cache.DeleteUserSessions(ctx, uuid.New())
	require.NoError(t, err)
}

// ─── SetSessionData / GetSessionData ─────────────────────────────────────────

func TestSessionCache_SetSessionData_GetSessionData_RoundTrip(t *testing.T) {
	cache, _ := newTestSessionCache(t)
	ctx := context.Background()

	sessionID, data := makeSessionData()
	require.NoError(t, cache.SetSessionData(ctx, sessionID, data))

	got, err := cache.GetSessionData(ctx, sessionID)
	require.NoError(t, err)
	require.NotNil(t, got)

	assert.Equal(t, data.UserID, got.UserID)
	assert.Equal(t, data.TenantID, got.TenantID)
	assert.Equal(t, data.Username, got.Username)
	assert.Equal(t, data.Email, got.Email)
	assert.Equal(t, data.Roles, got.Roles)
	assert.Equal(t, data.Permissions, got.Permissions)
	assert.Equal(t, data.RoleVersion, got.RoleVersion)
	assert.Equal(t, data.RealmSlug, got.RealmSlug)
}

func TestSessionCache_GetSessionData_Miss(t *testing.T) {
	cache, _ := newTestSessionCache(t)
	ctx := context.Background()

	got, err := cache.GetSessionData(ctx, uuid.New())
	require.NoError(t, err, "cache miss should return nil, nil")
	assert.Nil(t, got)
}

// ─── DeleteSessionData ────────────────────────────────────────────────────────

func TestSessionCache_DeleteSessionData(t *testing.T) {
	cache, _ := newTestSessionCache(t)
	ctx := context.Background()

	sessionID, data := makeSessionData()
	require.NoError(t, cache.SetSessionData(ctx, sessionID, data))

	require.NoError(t, cache.DeleteSessionData(ctx, sessionID, data.UserID))

	got, err := cache.GetSessionData(ctx, sessionID)
	require.NoError(t, err)
	assert.Nil(t, got, "session data should be gone after delete")
}

// ─── TTL behaviour ────────────────────────────────────────────────────────────

func TestSessionCache_TTL_Expiry(t *testing.T) {
	mr, err := miniredis.Run()
	require.NoError(t, err)
	defer mr.Close()

	cfg := &Config{
		URL:         "redis://" + mr.Addr(),
		MaxRetries:  1,
		DialTimeout: 2 * time.Second,
	}
	client, err := NewClient(cfg, zap.NewNop())
	require.NoError(t, err)
	defer client.Close() //nolint:errcheck

	// Very short TTL for the test.
	ttl := 1 * time.Second
	cache := NewSessionCache(client, "test", ttl)
	ctx := context.Background()

	session := makeSession()
	require.NoError(t, cache.Set(ctx, session))

	// Confirm it is present.
	got, err := cache.Get(ctx, session.SessionID)
	require.NoError(t, err)
	require.NotNil(t, got)

	// Fast-forward past the TTL.
	mr.FastForward(ttl + time.Second)

	// It should now be gone.
	got, err = cache.Get(ctx, session.SessionID)
	require.NoError(t, err)
	assert.Nil(t, got, "session should expire after TTL")
}

// ─── InvalidateUserSessionsByRoleVersion ─────────────────────────────────────

func TestSessionCache_InvalidateUserSessionsByRoleVersion(t *testing.T) {
	cache, _ := newTestSessionCache(t)
	ctx := context.Background()

	userID := uuid.New()

	// Session with old role version (version 2).
	oldID, oldData := makeSessionData()
	oldData.UserID = userID
	oldData.RoleVersion = 2
	require.NoError(t, cache.SetSessionData(ctx, oldID, oldData))

	// Session with current role version (version 5).
	newID, newData := makeSessionData()
	newData.UserID = userID
	newData.RoleVersion = 5
	require.NoError(t, cache.SetSessionData(ctx, newID, newData))

	// Invalidate sessions with version < 5.
	err := cache.InvalidateUserSessionsByRoleVersion(ctx, userID, 5)
	require.NoError(t, err)

	// Old session should be gone.
	gotOld, err := cache.GetSessionData(ctx, oldID)
	require.NoError(t, err)
	assert.Nil(t, gotOld, "old-version session should be invalidated")

	// New session should survive.
	gotNew, err := cache.GetSessionData(ctx, newID)
	require.NoError(t, err)
	assert.NotNil(t, gotNew, "current-version session should survive")
}

// ─── GetRoleVersion / IncrementRoleVersion ───────────────────────────────────

func TestSessionCache_GetRoleVersion_NoVersionSet(t *testing.T) {
	cache, _ := newTestSessionCache(t)
	ctx := context.Background()

	version, err := cache.GetRoleVersion(ctx, uuid.New())
	require.NoError(t, err)
	assert.Equal(t, int64(0), version)
}

func TestSessionCache_IncrementRoleVersion(t *testing.T) {
	cache, _ := newTestSessionCache(t)
	ctx := context.Background()

	tenantID := uuid.New()

	v1, err := cache.IncrementRoleVersion(ctx, tenantID)
	require.NoError(t, err)
	assert.Equal(t, int64(1), v1)

	v2, err := cache.IncrementRoleVersion(ctx, tenantID)
	require.NoError(t, err)
	assert.Equal(t, int64(2), v2)

	got, err := cache.GetRoleVersion(ctx, tenantID)
	require.NoError(t, err)
	assert.Equal(t, int64(2), got)
}

// ─── IsImpersonated ──────────────────────────────────────────────────────────

func TestSessionData_IsImpersonated_False(t *testing.T) {
	_, data := makeSessionData()
	assert.False(t, data.IsImpersonated())
}

func TestSessionData_IsImpersonated_True(t *testing.T) {
	_, data := makeSessionData()
	impID := uuid.New()
	data.ImpersonatorID = &impID
	assert.True(t, data.IsImpersonated())
}

// ─── IsRedisUnavailableError ──────────────────────────────────────────────────

func TestIsRedisUnavailableError(t *testing.T) {
	t.Run("identifies UnavailableError", func(t *testing.T) {
		err := &UnavailableError{Operation: "test", Err: assert.AnError}
		assert.True(t, IsRedisUnavailableError(err))
	})

	t.Run("ignores other errors", func(t *testing.T) {
		assert.False(t, IsRedisUnavailableError(assert.AnError))
	})

	t.Run("nil error", func(t *testing.T) {
		assert.False(t, IsRedisUnavailableError(nil))
	})
}

func TestRedisUnavailableError_Error(t *testing.T) {
	inner := assert.AnError
	e := &UnavailableError{Operation: "session retrieval", Err: inner}
	msg := e.Error()
	assert.Contains(t, msg, "redis unavailable")
	assert.Contains(t, msg, "session retrieval")
}

func TestRedisUnavailableError_Unwrap(t *testing.T) {
	inner := assert.AnError
	e := &UnavailableError{Operation: "op", Err: inner}
	assert.Equal(t, inner, e.Unwrap())
}

// ─── Client helper ───────────────────────────────────────────────────────────

func TestSessionCache_Client(t *testing.T) {
	cache, _ := newTestSessionCache(t)
	assert.NotNil(t, cache.Client())
}

// The sliding IdP TTL must never extend past AuthTime + absolute cap, and a
// record past the cap is deleted and reported missing.
func TestGetIdpSession_SlidingTTLBoundedByAbsoluteCap(t *testing.T) {
	cache, mr := newTestSessionCache(t)
	cache.SetIdpAbsoluteCap(10 * 24 * time.Hour)
	ctx := context.Background()

	near, past, fresh := uuid.New(), uuid.New(), uuid.New()
	mk := func(age time.Duration) *IdpSessionData {
		return &IdpSessionData{UserID: uuid.New(), TenantID: uuid.New(), AuthTime: time.Now().Add(-age).Unix()}
	}
	require.NoError(t, cache.SetIdpSession(ctx, near, mk(9*24*time.Hour)))  // 1d left
	require.NoError(t, cache.SetIdpSession(ctx, past, mk(11*24*time.Hour))) // over cap
	require.NoError(t, cache.SetIdpSession(ctx, fresh, mk(time.Hour)))      // >7d left

	d, err := cache.GetIdpSession(ctx, near)
	require.NoError(t, err)
	require.NotNil(t, d)
	assert.LessOrEqual(t, mr.TTL(cache.idpSessionKey(near)), 24*time.Hour+time.Minute, "TTL must be clamped to the cap")

	d, err = cache.GetIdpSession(ctx, past)
	require.NoError(t, err)
	assert.Nil(t, d)
	assert.False(t, mr.Exists(cache.idpSessionKey(past)), "past-cap record must be deleted")

	_, err = cache.GetIdpSession(ctx, fresh)
	require.NoError(t, err)
	assert.Equal(t, idpSessionTTL, mr.TTL(cache.idpSessionKey(fresh)))
}

// A realm cap resolved at creation is recorded on the record: a 24h realm
// session dies at 24h while a no-policy (30d default) session stays silent at 25h.
func TestIdpSession_PerRealmAbsoluteCap(t *testing.T) {
	cache, _ := newTestSessionCache(t)
	cache.SetIdpAbsoluteCap(30 * 24 * time.Hour)
	platform, customer := uuid.New(), uuid.New()
	calls := 0
	cache.SetRealmCapResolver(func(_ context.Context, tenantID uuid.UUID) (time.Duration, bool, error) {
		calls++
		if tenantID == platform {
			return 24 * time.Hour, true, nil
		}
		return 0, false, nil
	})
	ctx := context.Background()
	authAt := time.Now().Add(-25 * time.Hour).Unix()

	pid, cid := uuid.New(), uuid.New()
	require.NoError(t, cache.SetIdpSession(ctx, pid, &IdpSessionData{UserID: uuid.New(), TenantID: platform, AuthTime: authAt}))
	require.NoError(t, cache.SetIdpSession(ctx, cid, &IdpSessionData{UserID: uuid.New(), TenantID: customer, AuthTime: authAt}))

	d, err := cache.GetIdpSession(ctx, pid)
	require.NoError(t, err)
	assert.Nil(t, d, "24h realm: session older than 24h must require login")

	d, err = cache.GetIdpSession(ctx, cid)
	require.NoError(t, err)
	require.NotNil(t, d, "30d realm: silent at 25h")
	assert.Zero(t, d.AbsoluteCapSeconds)

	// Fresh platform session records the cap; lookups are cached.
	fid := uuid.New()
	require.NoError(t, cache.SetIdpSession(ctx, fid, &IdpSessionData{UserID: uuid.New(), TenantID: platform, AuthTime: time.Now().Unix()}))
	d, err = cache.GetIdpSession(ctx, fid)
	require.NoError(t, err)
	require.NotNil(t, d)
	assert.Equal(t, int64(86400), d.AbsoluteCapSeconds)
	assert.Equal(t, 2, calls, "platform tenant resolved once, customer once (cached)")
}

// Legacy records (no recorded cap) and resolver errors keep the global cap.
func TestIdpSession_RealmCapFallbacks(t *testing.T) {
	cache, _ := newTestSessionCache(t)
	cache.SetIdpAbsoluteCap(30 * 24 * time.Hour)
	cache.SetRealmCapResolver(func(context.Context, uuid.UUID) (time.Duration, bool, error) {
		return 0, false, assert.AnError
	})
	ctx := context.Background()
	id := uuid.New()
	require.NoError(t, cache.SetIdpSession(ctx, id, &IdpSessionData{UserID: uuid.New(), TenantID: uuid.New(), AuthTime: time.Now().Add(-25 * time.Hour).Unix()}))
	d, err := cache.GetIdpSession(ctx, id)
	require.NoError(t, err)
	assert.NotNil(t, d)

	deadline, ok := cache.IdpAbsoluteDeadline(&IdpSessionData{AuthTime: 1000})
	require.True(t, ok)
	assert.Equal(t, time.Unix(1000, 0).Add(30*24*time.Hour), deadline)
}
