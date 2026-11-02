// SPDX-License-Identifier: AGPL-3.0-or-later

package spicedb

import (
	"context"
	"testing"
	"time"

	v1 "github.com/authzed/authzed-go/proto/authzed/api/v1"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/structpb"
)

// jitFixture wires a role-backed access_grant: roleID holds the permission, and
// membership in roleID is what a JIT grant adds.
type jitFixture struct {
	c      *Client
	tenant uuid.UUID
	role   uuid.UUID
	permID string
}

func newJITFixture(t *testing.T) *jitFixture {
	t.Helper()
	c := newAuthzReasonsClient(t)
	f := &jitFixture{c: c, tenant: uuid.New(), role: uuid.New(), permID: PermissionToSpiceDBID("marketing:leads:read")}
	_, err := c.WriteRelationship(context.Background(), "access_grant", f.tenant.String()+"/"+f.permID, "granted_to_role", "role", f.tenant.String()+"/"+f.role.String())
	require.NoError(t, err)
	return f
}

// writeExpiredMember writes a caveated role#member tuple whose expires_at is
// already in the past (WriteUserRoleUntil is only used for live grants).
func (f *jitFixture) writeExpiredMember(t *testing.T, user uuid.UUID) {
	t.Helper()
	ctxStruct := &structpb.Struct{Fields: map[string]*structpb.Value{
		"expires_at": structpb.NewStringValue(time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)),
	}}
	_, err := f.c.AuthzedClient().WriteRelationships(context.Background(), &v1.WriteRelationshipsRequest{Updates: []*v1.RelationshipUpdate{{
		Operation: v1.RelationshipUpdate_OPERATION_TOUCH,
		Relationship: &v1.Relationship{
			Resource:       &v1.ObjectReference{ObjectType: "role", ObjectId: f.tenant.String() + "/" + f.role.String()},
			Relation:       "member",
			Subject:        &v1.SubjectReference{Object: &v1.ObjectReference{ObjectType: "user", ObjectId: f.tenant.String() + "/" + user.String()}},
			OptionalCaveat: &v1.ContextualizedCaveat{CaveatName: "active_elevation", Context: ctxStruct},
		},
	}}})
	require.NoError(t, err)
}

func (f *jitFixture) allowed(t *testing.T, tenant, user uuid.UUID) (single, bulk bool) {
	t.Helper()
	ctx := context.Background()
	ok, err := f.c.CheckPermissionWithConsistency(ctx, tenant, user, "access_grant", f.permID, "check", ConsistencyFullyConsistent, "")
	require.NoError(t, err)
	got, err := f.c.CheckBulkPermissionsDetailed(ctx, tenant, user, "access_grant", []string{f.permID}, "check")
	require.NoError(t, err)
	return ok, got[f.permID].Allowed
}

func TestAuthzReasons_JITCaveat(t *testing.T) {
	f := newJITFixture(t)
	ctx := context.Background()
	active, expired, plain, other := uuid.New(), uuid.New(), uuid.New(), uuid.New()

	_, err := f.c.WriteUserRoleUntil(ctx, f.tenant, active, f.role, time.Now().Add(time.Hour))
	require.NoError(t, err)
	f.writeExpiredMember(t, expired)
	_, err = f.c.WriteUserRole(ctx, f.tenant, plain, f.role)
	require.NoError(t, err)

	t.Run("active grant allowed through CheckPermission and bulk", func(t *testing.T) {
		require.Eventually(t, func() bool {
			ok, err := f.c.CheckPermission(ctx, f.tenant, active, "access_grant", f.permID, "check")
			return err == nil && ok
		}, 5*time.Second, 100*time.Millisecond)
		single, bulk := f.allowed(t, f.tenant, active)
		assert.True(t, single)
		assert.True(t, bulk)
		roles, err := f.c.LookupUserRoles(ctx, f.tenant, active)
		require.NoError(t, err)
		assert.Equal(t, []string{f.role.String()}, roles, "LookupResources also decides the caveat")
	})

	t.Run("expired grant denied", func(t *testing.T) {
		single, bulk := f.allowed(t, f.tenant, expired)
		assert.False(t, single)
		assert.False(t, bulk)
		o, err := f.c.CheckBulkPermissionsDetailed(ctx, f.tenant, expired, "access_grant", []string{f.permID}, "check")
		require.NoError(t, err)
		assert.False(t, o[f.permID].Conditional, "expiry is a decided false, not a missing-context conditional")
	})

	t.Run("plain non-caveated grant unchanged", func(t *testing.T) {
		single, bulk := f.allowed(t, f.tenant, plain)
		assert.True(t, single)
		assert.True(t, bulk)
	})

	t.Run("other user and cross-tenant user are not elevated", func(t *testing.T) {
		single, bulk := f.allowed(t, f.tenant, other)
		assert.False(t, single)
		assert.False(t, bulk)
		single, bulk = f.allowed(t, uuid.New(), active) // same user id, another tenant
		assert.False(t, single)
		assert.False(t, bulk)
	})

	t.Run("a caveat needing other context still denies (conditional)", func(t *testing.T) {
		// entitlement_window shares the shape, but a tuple whose caveat context
		// lacks expires_at AND is checked with only `now` must stay CONDITIONAL.
		user := uuid.New()
		_, err := f.c.AuthzedClient().WriteRelationships(ctx, &v1.WriteRelationshipsRequest{Updates: []*v1.RelationshipUpdate{{
			Operation: v1.RelationshipUpdate_OPERATION_TOUCH,
			Relationship: &v1.Relationship{
				Resource:       &v1.ObjectReference{ObjectType: "role", ObjectId: f.tenant.String() + "/" + f.role.String()},
				Relation:       "member",
				Subject:        &v1.SubjectReference{Object: &v1.ObjectReference{ObjectType: "user", ObjectId: f.tenant.String() + "/" + user.String()}},
				OptionalCaveat: &v1.ContextualizedCaveat{CaveatName: "active_elevation"}, // no expires_at
			},
		}}})
		require.NoError(t, err)
		o, err := f.c.CheckBulkPermissionsDetailed(ctx, f.tenant, user, "access_grant", []string{f.permID}, "check")
		require.NoError(t, err)
		assert.False(t, o[f.permID].Allowed)
		assert.True(t, o[f.permID].Conditional)
		assert.Contains(t, o[f.permID].MissingContext, "expires_at")
		assert.NotContains(t, o[f.permID].MissingContext, "now")
	})

	t.Run("revoke removes the tuple", func(t *testing.T) {
		_, err := f.c.DeleteUserRole(ctx, f.tenant, active, f.role)
		require.NoError(t, err)
		// FullyConsistent single check sees the delete at once; the bulk path is
		// minimize_latency, so wait out the memory datastore's quantization window.
		ok, err := f.c.CheckPermissionWithConsistency(ctx, f.tenant, active, "access_grant", f.permID, "check", ConsistencyFullyConsistent, "")
		require.NoError(t, err)
		assert.False(t, ok)
		require.Eventually(t, func() bool {
			_, bulk := f.allowed(t, f.tenant, active)
			return !bulk
		}, 10*time.Second, 200*time.Millisecond)
	})
}
