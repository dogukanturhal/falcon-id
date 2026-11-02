// SPDX-License-Identifier: AGPL-3.0-or-later

package redis

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

type testEnvelope struct {
	Modules []string `json:"modules"`
}

func TestEntitlementCache_SetThenGetFresh_Hit(t *testing.T) {
	client, mr := setupTestRedis(t)
	defer mr.Close()
	defer client.Close() //nolint:errcheck

	svc := NewEntitlementCacheService(client, zap.NewNop())
	ctx := context.Background()
	tenantID := "tenant-1"

	env := testEnvelope{Modules: []string{"crm"}}
	require.NoError(t, svc.Set(ctx, tenantID, env))

	var out testEnvelope
	hit, err := svc.GetFresh(ctx, tenantID, &out)
	require.NoError(t, err)
	assert.True(t, hit)
	assert.Equal(t, env, out)
}

func TestEntitlementCache_GetFresh_Miss(t *testing.T) {
	client, mr := setupTestRedis(t)
	defer mr.Close()
	defer client.Close() //nolint:errcheck

	svc := NewEntitlementCacheService(client, zap.NewNop())
	var out testEnvelope
	hit, err := svc.GetFresh(context.Background(), "never-set-tenant", &out)
	require.NoError(t, err)
	assert.False(t, hit, "absent key must report a miss, not an error")
}

func TestEntitlementCache_Set_AlsoWritesLKG(t *testing.T) {
	client, mr := setupTestRedis(t)
	defer mr.Close()
	defer client.Close() //nolint:errcheck

	svc := NewEntitlementCacheService(client, zap.NewNop())
	ctx := context.Background()
	tenantID := "tenant-2"

	env := testEnvelope{Modules: []string{"marketing"}}
	require.NoError(t, svc.Set(ctx, tenantID, env))

	var out testEnvelope
	hit, err := svc.GetLKG(ctx, tenantID, &out)
	require.NoError(t, err)
	assert.True(t, hit, "Set must write the LKG key too, not just fresh")
	assert.Equal(t, env, out)
}

// TestEntitlementCache_LKGOutlivesFreshExpiry proves the core LKG
// behavior: once the fresh key's short TTL elapses, GetFresh reports a
// miss but GetLKG (much longer TTL) still serves the last confirmed
// snapshot. This is the exact mechanism the service layer relies on to
// survive a sustained Postgres outage without failing closed prematurely.
func TestEntitlementCache_LKGOutlivesFreshExpiry(t *testing.T) {
	client, mr := setupTestRedis(t)
	defer mr.Close()
	defer client.Close() //nolint:errcheck

	svc := NewEntitlementCacheService(client, zap.NewNop())
	ctx := context.Background()
	tenantID := "tenant-3"

	env := testEnvelope{Modules: []string{"crm"}}
	require.NoError(t, svc.Set(ctx, tenantID, env))

	// Fast-forward miniredis's clock past the fresh TTL but not the LKG TTL.
	mr.FastForward(EntitlementCacheTTL + time.Second)

	var freshOut testEnvelope
	hit, err := svc.GetFresh(ctx, tenantID, &freshOut)
	require.NoError(t, err)
	assert.False(t, hit, "fresh key must have expired")

	var lkgOut testEnvelope
	hit, err = svc.GetLKG(ctx, tenantID, &lkgOut)
	require.NoError(t, err)
	assert.True(t, hit, "LKG key must still be alive well past the fresh TTL")
	assert.Equal(t, env, lkgOut)
}

func TestEntitlementCache_LKGAlsoExpiresEventually(t *testing.T) {
	client, mr := setupTestRedis(t)
	defer mr.Close()
	defer client.Close() //nolint:errcheck

	svc := NewEntitlementCacheService(client, zap.NewNop())
	ctx := context.Background()
	tenantID := "tenant-4"

	require.NoError(t, svc.Set(ctx, tenantID, testEnvelope{Modules: []string{"crm"}}))

	mr.FastForward(EntitlementLKGTTL + time.Second)

	var out testEnvelope
	hit, err := svc.GetLKG(ctx, tenantID, &out)
	require.NoError(t, err)
	assert.False(t, hit, "LKG must eventually expire too, forcing fail-closed")
}

func TestEntitlementCache_InvalidateFresh_LeavesLKGIntact(t *testing.T) {
	client, mr := setupTestRedis(t)
	defer mr.Close()
	defer client.Close() //nolint:errcheck

	svc := NewEntitlementCacheService(client, zap.NewNop())
	ctx := context.Background()
	tenantID := "tenant-5"

	env := testEnvelope{Modules: []string{"crm"}}
	require.NoError(t, svc.Set(ctx, tenantID, env))
	require.NoError(t, svc.InvalidateFresh(ctx, tenantID))

	var freshOut testEnvelope
	hit, err := svc.GetFresh(ctx, tenantID, &freshOut)
	require.NoError(t, err)
	assert.False(t, hit, "InvalidateFresh must drop the fresh key")

	var lkgOut testEnvelope
	hit, err = svc.GetLKG(ctx, tenantID, &lkgOut)
	require.NoError(t, err)
	assert.True(t, hit, "InvalidateFresh must NOT touch the LKG key")
	assert.Equal(t, env, lkgOut)
}

func TestEntitlementCache_CorruptEntry_TreatedAsMissAndDeleted(t *testing.T) {
	client, mr := setupTestRedis(t)
	defer mr.Close()
	defer client.Close() //nolint:errcheck

	svc := NewEntitlementCacheService(client, zap.NewNop())
	ctx := context.Background()
	tenantID := "tenant-6"

	// Write garbage directly into the fresh key, bypassing Set.
	require.NoError(t, client.Set(ctx, freshKey(tenantID), "{not valid json", EntitlementCacheTTL))

	var out testEnvelope
	hit, err := svc.GetFresh(ctx, tenantID, &out)
	require.NoError(t, err, "a corrupt entry must never surface as an error")
	assert.False(t, hit)

	// The poisoned key must have been deleted so it doesn't keep
	// poisoning subsequent reads.
	_, err = client.Get(ctx, freshKey(tenantID))
	assert.Error(t, err, "corrupt key must have been deleted (expect redis.Nil-wrapped error)")
}

func TestEntitlementCache_TenantsAreIsolated(t *testing.T) {
	client, mr := setupTestRedis(t)
	defer mr.Close()
	defer client.Close() //nolint:errcheck

	svc := NewEntitlementCacheService(client, zap.NewNop())
	ctx := context.Background()

	require.NoError(t, svc.Set(ctx, "tenant-a", testEnvelope{Modules: []string{"crm"}}))
	require.NoError(t, svc.Set(ctx, "tenant-b", testEnvelope{Modules: []string{"marketing"}}))

	var outA, outB testEnvelope
	_, err := svc.GetFresh(ctx, "tenant-a", &outA)
	require.NoError(t, err)
	_, err = svc.GetFresh(ctx, "tenant-b", &outB)
	require.NoError(t, err)

	assert.Equal(t, []string{"crm"}, outA.Modules)
	assert.Equal(t, []string{"marketing"}, outB.Modules)
}
