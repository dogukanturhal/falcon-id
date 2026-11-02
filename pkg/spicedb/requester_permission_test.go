// SPDX-License-Identifier: AGPL-3.0-or-later

package spicedb

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func TestAuthzReasons_RequesterLeastPrivilegeAndRevocation(t *testing.T) {
	c := newAuthzReasonsClient(t)
	ctx := context.Background()
	tenant, role, user := uuid.New(), uuid.New(), uuid.New()
	preaccWrite(t, c, preaccTuple{resType: "role", resID: tenant.String() + "/" + role.String(), relation: "member", subType: "user", subID: tenant.String() + "/" + user.String()})
	_, err := c.WriteUserTenant(ctx, tenant, user, "member")
	require.NoError(t, err, "free seat classes still have normal tenant membership, as BootstrapUserMembership writes")
	company := tenant.String() + "/" + uuid.NewString()
	preaccWrite(t, c, preaccTuple{resType: "company", resID: company, relation: "tenant", subType: "tenant", subID: tenant.String()})
	allowedCompany, _, _ := preaccCheck(t, c, "company", company, "view", tenant.String()+"/"+user.String(), nil)
	require.True(t, allowedCompany)
	canManageCompany, _, _ := preaccCheck(t, c, "company", company, "manage", tenant.String()+"/"+user.String(), nil)
	require.False(t, canManageCompany)
	for _, relation := range []string{"maintenance_request_creator", "maintenance_request_reader"} {
		_, err := c.WriteRolePermission(ctx, tenant, role, "module", "cmms", relation)
		require.NoError(t, err)
	}
	for _, permission := range []string{"maintenance_requests_create_own", "maintenance_requests_read_own"} {
		allowed, _, _ := preaccCheck(t, c, "module", tenant.String()+"/cmms", permission, tenant.String()+"/"+user.String(), nil)
		require.True(t, allowed)
	}
	for _, permission := range []string{"view", "edit", "maintenance_requests_read", "maintenance_requests_create", "work_orders_read", "assets_update"} {
		allowed, _, _ := preaccCheck(t, c, "module", tenant.String()+"/cmms", permission, tenant.String()+"/"+user.String(), nil)
		require.False(t, allowed, permission)
	}
	_, err = c.WriteRolePermission(ctx, tenant, role, "module", "core", "legal_entity_reader")
	require.NoError(t, err)
	allowed, _, _ := preaccCheck(t, c, "module", tenant.String()+"/core", "legal_entities_read", tenant.String()+"/"+user.String(), nil)
	require.True(t, allowed, "the free requester can establish company context")
	for _, permission := range []string{"view", "edit", "manage", "delete"} {
		allowed, _, _ := preaccCheck(t, c, "module", tenant.String()+"/core", permission, tenant.String()+"/"+user.String(), nil)
		require.False(t, allowed, "company references must not grant broad Core access")
	}
	edges, err := c.LookupTenantRolePermissions(ctx, tenant)
	require.NoError(t, err)
	require.Len(t, edges, 3, "reconciler must see narrow grants to revoke stale permissions")
	for _, edge := range edges {
		_, err := c.DeleteRolePermission(ctx, tenant, role, edge.ObjectType, edge.ObjectID, edge.Relation)
		require.NoError(t, err)
	}
	allowed, _, _ = preaccCheck(t, c, "module", tenant.String()+"/cmms", "maintenance_requests_create_own", tenant.String()+"/"+user.String(), nil)
	require.False(t, allowed)
}
