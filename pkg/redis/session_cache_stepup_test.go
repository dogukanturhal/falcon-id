// SPDX-License-Identifier: AGPL-3.0-or-later

package redis

import (
	"context"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

func TestAuth2IdpStepUp_RefreshesFreshnessWithoutExtendingTTL(t *testing.T) {
	cache, mr := newTestSessionCache(t)
	ctx := context.Background()
	id, uid, sid := uuid.New(), uuid.New(), uuid.New()
	require.NoError(t, cache.SetIdpSession(ctx, id, &IdpSessionData{UserID: uid, SessionID: sid, AuthTime: 1}))
	mr.FastForward(time.Minute)
	ttl := mr.TTL(cache.idpSessionKey(id))
	now := time.Now().Unix()
	updated, err := cache.RefreshIdpSessionAuthTime(ctx, id, uid, sid, now)
	require.NoError(t, err)
	require.True(t, updated)
	require.Equal(t, ttl, mr.TTL(cache.idpSessionKey(id)))
	authTime, found, err := cache.GetIdpSessionAuthTime(ctx, id)
	require.NoError(t, err)
	require.True(t, found)
	require.Equal(t, now, authTime)
}

func TestAuth2IdpStepUp_RejectsWrongPrincipalAndDoesNotResurrectLogout(t *testing.T) {
	cache, _ := newTestSessionCache(t)
	ctx := context.Background()
	id, uid, sid := uuid.New(), uuid.New(), uuid.New()
	require.NoError(t, cache.SetIdpSession(ctx, id, &IdpSessionData{UserID: uid, SessionID: sid, AuthTime: 1}))
	updated, err := cache.RefreshIdpSessionAuthTime(ctx, id, uuid.New(), sid, 100)
	require.NoError(t, err)
	require.False(t, updated)
	updated, err = cache.RefreshIdpSessionAuthTime(ctx, id, uid, uuid.New(), 100)
	require.NoError(t, err)
	require.False(t, updated)
	require.NoError(t, cache.DeleteIdpSession(ctx, id))
	updated, err = cache.RefreshIdpSessionAuthTime(ctx, id, uid, sid, 100)
	require.NoError(t, err)
	require.False(t, updated)
	_, found, err := cache.GetIdpSessionAuthTime(ctx, id)
	require.NoError(t, err)
	require.False(t, found)
}
