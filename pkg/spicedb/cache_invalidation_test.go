// SPDX-License-Identifier: AGPL-3.0-or-later

package spicedb

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	v1 "github.com/authzed/authzed-go/proto/authzed/api/v1"
	"github.com/authzed/authzed-go/v1"
	"github.com/google/uuid"
	"github.com/dogukanturhal/falcon-id/pkg/config"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// fakeWriteServer accepts every WriteRelationships call so the write paths
// can be exercised without a live SpiceDB.
type fakeWriteServer struct {
	v1.UnimplementedPermissionsServiceServer
}

func (fakeWriteServer) WriteRelationships(context.Context, *v1.WriteRelationshipsRequest) (*v1.WriteRelationshipsResponse, error) {
	return &v1.WriteRelationshipsResponse{}, nil
}

func newInvalidationClient(t *testing.T) (*Client, *miniredis.Miniredis) {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	srv := grpc.NewServer()
	v1.RegisterPermissionsServiceServer(srv, fakeWriteServer{})
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)

	sc, err := authzed.NewClient(lis.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)

	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })

	return &Client{spicedb: sc, redis: rdb, config: &config.Config{SpiceDBCacheTTL: 30 * time.Second}}, mr
}

// seed caches an "allowed" decision, as CheckPermission would after a miss.
func seed(t *testing.T, c *Client, tenantID, userID uuid.UUID) string {
	t.Helper()
	key := c.generateCacheKey(tenantID, userID, "tenant", tenantID.String(), "admin")
	require.NoError(t, c.cacheResult(context.Background(), key, true))
	cached, err := c.checkCache(context.Background(), key)
	require.NoError(t, err)
	require.True(t, cached)
	return key
}

func requireEvicted(t *testing.T, mr *miniredis.Miniredis, key string) {
	t.Helper()
	require.False(t, mr.Exists(key), "revoke must be visible immediately, not after the cache TTL")
}

func TestElevationRevoke_InvalidatesCachedDecisionImmediately(t *testing.T) {
	ctx := context.Background()
	tenantID, otherTenant := uuid.New(), uuid.New()
	userID, bystander := uuid.New(), uuid.New()

	t.Run("DeleteUserRole", func(t *testing.T) {
		c, mr := newInvalidationClient(t)
		key := seed(t, c, tenantID, userID)
		other := seed(t, c, tenantID, bystander)
		_, err := c.DeleteUserRole(ctx, tenantID, userID, uuid.New())
		require.NoError(t, err)
		requireEvicted(t, mr, key)
		require.True(t, mr.Exists(other), "other users' entries are left alone")
	})

	t.Run("DeletePlatformElevation clears every tenant", func(t *testing.T) {
		c, mr := newInvalidationClient(t)
		k1 := seed(t, c, tenantID, userID)
		k2 := seed(t, c, otherTenant, userID)
		other := seed(t, c, tenantID, bystander)
		_, err := c.DeletePlatformElevation(ctx, userID, "platform_admin")
		require.NoError(t, err)
		requireEvicted(t, mr, k1)
		requireEvicted(t, mr, k2)
		require.True(t, mr.Exists(other))
	})

	t.Run("WritePlatformElevation", func(t *testing.T) {
		c, mr := newInvalidationClient(t)
		key := seed(t, c, tenantID, userID)
		_, err := c.WritePlatformElevation(ctx, userID, "platform_admin", time.Now().Add(time.Hour))
		require.NoError(t, err)
		requireEvicted(t, mr, key)
	})

	t.Run("DeleteRoleAssignment", func(t *testing.T) {
		c, mr := newInvalidationClient(t)
		key := seed(t, c, tenantID, userID)
		require.NoError(t, c.DeleteRoleAssignment(ctx, tenantID, userID, "crm"))
		requireEvicted(t, mr, key)
	})

	t.Run("DeleteResourceRelationship", func(t *testing.T) {
		c, mr := newInvalidationClient(t)
		key := seed(t, c, tenantID, userID)
		other := seed(t, c, otherTenant, userID)
		require.NoError(t, c.DeleteResourceRelationship(ctx, tenantID, "tenant", tenantID.String(), "admin", "user", userID.String()))
		requireEvicted(t, mr, key)
		require.True(t, mr.Exists(other), "other tenants are left alone")
	})
}
