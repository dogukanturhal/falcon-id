// SPDX-License-Identifier: AGPL-3.0-or-later

package spicedb

import (
	"context"
	"os"
	"testing"
	"time"

	v1 "github.com/authzed/authzed-go/proto/authzed/api/v1"
	"github.com/authzed/authzed-go/v1"
	"github.com/authzed/grpcutil"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/dogukanturhal/falcon-id/pkg/config"
)

// newAuthzReasonsClient connects to the throwaway SpiceDB started by
// hack/run-authz-reasons-tests.sh and loads the production schema.
func newAuthzReasonsClient(t *testing.T) *Client {
	t.Helper()
	endpoint := os.Getenv("TEST_SPICEDB_ENDPOINT")
	if endpoint == "" {
		t.Skip("TEST_SPICEDB_ENDPOINT is required; run hack/run-authz-reasons-tests.sh")
	}
	token := os.Getenv("TEST_SPICEDB_TOKEN")
	// NewClient's health check needs a schema, so load it through a raw client first.
	raw, err := authzed.NewClient(endpoint, grpc.WithTransportCredentials(insecure.NewCredentials()), grpcutil.WithInsecureBearerToken(token))
	require.NoError(t, err)
	schema, err := os.ReadFile("../../deploy/helm/spicedb-schema/files/spicedb.zed")
	require.NoError(t, err)
	_, err = raw.WriteSchema(context.Background(), &v1.WriteSchemaRequest{Schema: string(schema)})
	require.NoError(t, err)
	c, err := NewClient(context.Background(), &config.Config{
		SpiceDBEnabled: true, SpiceDBEndpoint: endpoint, SpiceDBToken: token, SpiceDBInsecure: true,
	}, nil)
	require.NoError(t, err)
	return c
}

func TestAuthzReasons_SpiceDBOutcomes(t *testing.T) {
	c := newAuthzReasonsClient(t)
	ctx := context.Background()
	tenant, granted, nobody := uuid.New(), uuid.New(), uuid.New()
	permID := PermissionToSpiceDBID("marketing:leads:read")

	_, err := c.WriteRelationship(ctx, "access_grant", tenant.String()+"/"+permID, "granted_to", "user", tenant.String()+"/"+granted.String())
	require.NoError(t, err)

	t.Run("allowed and denied map to tri-state outcomes", func(t *testing.T) {
		// Bulk checks use minimize_latency, so a just-written tuple may take a
		// moment to become visible.
		require.Eventually(t, func() bool {
			got, err := c.CheckBulkPermissionsDetailed(ctx, tenant, granted, "access_grant", []string{permID}, "check")
			return err == nil && got[permID].Allowed
		}, 5*time.Second, 100*time.Millisecond)
		var got map[string]CheckOutcome
		var err error

		got, err = c.CheckBulkPermissionsDetailed(ctx, tenant, nobody, "access_grant", []string{permID}, "check")
		require.NoError(t, err)
		assert.False(t, got[permID].Allowed)
		assert.False(t, got[permID].Conditional)
		assert.False(t, got[permID].Errored)
	})

	t.Run("bool API stays a projection of the detailed one", func(t *testing.T) {
		got, err := c.CheckBulkPermissions(ctx, tenant, granted, "access_grant", []string{permID}, "check")
		require.NoError(t, err)
		assert.True(t, got[permID])
	})

	t.Run("undecided caveat is CONDITIONAL and names the missing context", func(t *testing.T) {
		elevated := uuid.New()
		// active_elevation caveat with expires_at but no `now` at check time.
		_, err := c.WritePlatformElevation(ctx, elevated, "platform_admin", time.Now().Add(time.Hour))
		require.NoError(t, err)
		resp, err := c.AuthzedClient().CheckPermission(ctx, &v1.CheckPermissionRequest{
			Consistency: &v1.Consistency{Requirement: &v1.Consistency_FullyConsistent{FullyConsistent: true}},
			Resource:    &v1.ObjectReference{ObjectType: "hxl_platform", ObjectId: "hexxlock"},
			Permission:  "manage_identity",
			Subject:     &v1.SubjectReference{Object: &v1.ObjectReference{ObjectType: "user", ObjectId: elevated.String()}},
		})
		require.NoError(t, err)
		o := outcomeFromPermissionship(resp.Permissionship, resp.PartialCaveatInfo)
		assert.False(t, o.Allowed, "undecided caveat must never allow")
		assert.True(t, o.Conditional)
		assert.Contains(t, o.MissingContext, "now")
	})
}

func TestAuthzReasons_SimulateTrace(t *testing.T) {
	c := newAuthzReasonsClient(t)
	ctx := context.Background()
	tenant, granted, nobody := uuid.New(), uuid.New(), uuid.New()
	permID := PermissionToSpiceDBID("marketing:leads:read")
	_, err := c.WriteRelationship(ctx, "access_grant", tenant.String()+"/"+permID, "granted_to", "user", tenant.String()+"/"+granted.String())
	require.NoError(t, err)

	res, err := c.SimulatePermission(ctx, tenant, granted, "access_grant", permID, "check")
	require.NoError(t, err)
	assert.True(t, res.Allowed)
	assert.Equal(t, "access_grant:"+permID, res.Trace.Resource, "tenant prefix is stripped from trace ids")
	assert.NotEmpty(t, res.Trace.Children, "trace carries the resolution path")

	res, err = c.SimulatePermission(ctx, tenant, nobody, "access_grant", permID, "check")
	require.NoError(t, err)
	assert.False(t, res.Allowed)

	// Cross-tenant: the same user id scoped to ANOTHER tenant gets nothing.
	res, err = c.SimulatePermission(ctx, uuid.New(), granted, "access_grant", permID, "check")
	require.NoError(t, err)
	assert.False(t, res.Allowed)
}
