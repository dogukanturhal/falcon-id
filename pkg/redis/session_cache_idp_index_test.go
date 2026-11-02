// SPDX-License-Identifier: AGPL-3.0-or-later

package redis

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIdpSessionUserIndex_AddRemoveDeleteAll(t *testing.T) {
	cache, _ := newTestSessionCache(t)
	ctx := context.Background()
	user, other := uuid.New(), uuid.New()
	a, b, c := uuid.New(), uuid.New(), uuid.New()

	require.NoError(t, cache.SetIdpSession(ctx, a, &IdpSessionData{UserID: user}))
	require.NoError(t, cache.SetIdpSession(ctx, b, &IdpSessionData{UserID: user}))
	require.NoError(t, cache.SetIdpSession(ctx, c, &IdpSessionData{UserID: other}))

	members, err := cache.client.Redis().SMembers(ctx, cache.idpUserSetKey(user)).Result()
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{a.String(), b.String()}, members)
	assert.Positive(t, cache.client.Redis().TTL(ctx, cache.idpUserSetKey(user)).Val())

	// Delete removes the index entry.
	require.NoError(t, cache.DeleteIdpSession(ctx, a))
	members, _ = cache.client.Redis().SMembers(ctx, cache.idpUserSetKey(user)).Result()
	assert.ElementsMatch(t, []string{b.String()}, members)

	// Delete-all removes remaining sessions of that user only.
	n, err := cache.DeleteAllIdpSessionsByUser(ctx, user)
	require.NoError(t, err)
	assert.Equal(t, 1, n)
	got, _ := cache.GetIdpSession(ctx, b)
	assert.Nil(t, got)
	got, _ = cache.GetIdpSession(ctx, c)
	assert.NotNil(t, got)
}

func TestIdpSessionUserIndex_LegacyEntryFoundByScan(t *testing.T) {
	cache, _ := newTestSessionCache(t)
	ctx := context.Background()
	user := uuid.New()
	id := uuid.New()
	require.NoError(t, cache.SetIdpSession(ctx, id, &IdpSessionData{UserID: user}))
	// Simulate an entry that predates the index.
	require.NoError(t, cache.client.Redis().Del(ctx, cache.idpUserSetKey(user)).Err())

	n, err := cache.DeleteAllIdpSessionsByUser(ctx, user)
	require.NoError(t, err)
	assert.Equal(t, 1, n)
}

func TestIdpSessionDeleteExceptAndByRow(t *testing.T) {
	cache, _ := newTestSessionCache(t)
	ctx := context.Background()
	user := uuid.New()
	rowKeep, rowDrop := uuid.New(), uuid.New()
	keep, drop := uuid.New(), uuid.New()
	require.NoError(t, cache.SetIdpSession(ctx, keep, &IdpSessionData{UserID: user, SessionID: rowKeep}))
	require.NoError(t, cache.SetIdpSession(ctx, drop, &IdpSessionData{UserID: user, SessionID: rowDrop}))

	gone, err := cache.DeleteAllIdpSessionsByUserExcept(ctx, user, rowKeep)
	require.NoError(t, err)
	assert.Equal(t, []uuid.UUID{drop}, gone)
	got, _ := cache.GetIdpSession(ctx, keep)
	assert.NotNil(t, got)

	ids, err := cache.DeleteIdpSessionsByRowID(ctx, user, rowKeep)
	require.NoError(t, err)
	assert.Equal(t, []uuid.UUID{keep}, ids)
}
