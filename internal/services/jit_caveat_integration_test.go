// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"testing"
	"time"

	v1 "github.com/authzed/authzed-go/proto/authzed/api/v1"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/pkg/config"
	"github.com/dogukanturhal/falcon-id/pkg/spicedb"
)

// JIT (caveated active_elevation) grants against real SpiceDB, through the
// authorize/batch and authorize/simulate decision path.
func TestAuthzReasons_JITCaveatBatchAndSimulate(t *testing.T) {
	sdb := newAuthzReasonsSpiceDB(t)
	ctx := context.Background()
	tenant, role := uuid.New(), uuid.New()
	actor, active, expired, plain, other := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	const perm = "marketing:leads:read"

	_, err := sdb.WriteRelationship(ctx, "access_grant", tenant.String()+"/"+spicedb.PermissionToSpiceDBID(perm), "granted_to_role", "role", tenant.String()+"/"+role.String())
	require.NoError(t, err)
	_, err = sdb.WriteUserRoleUntil(ctx, tenant, active, role, time.Now().Add(time.Hour))
	require.NoError(t, err)
	_, err = sdb.WriteUserRole(ctx, tenant, plain, role)
	require.NoError(t, err)
	_, err = sdb.AuthzedClient().WriteRelationships(ctx, &v1.WriteRelationshipsRequest{Updates: []*v1.RelationshipUpdate{{
		Operation: v1.RelationshipUpdate_OPERATION_TOUCH,
		Relationship: &v1.Relationship{
			Resource: &v1.ObjectReference{ObjectType: "role", ObjectId: tenant.String() + "/" + role.String()},
			Relation: "member",
			Subject:  &v1.SubjectReference{Object: &v1.ObjectReference{ObjectType: "user", ObjectId: tenant.String() + "/" + expired.String()}},
			OptionalCaveat: &v1.ContextualizedCaveat{CaveatName: "active_elevation", Context: &structpb.Struct{Fields: map[string]*structpb.Value{
				"expires_at": structpb.NewStringValue(time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)),
			}}},
		},
	}}})
	require.NoError(t, err)

	engine := NewAuthorizationEngine(nil, nil, nil, nil, sdb, &config.Config{})
	SetEngineModuleEntitlementChecker(engine, fakeEntitlements{"marketing": true})
	svc := NewAuthorizationService(nil, nil, nil, nil)
	svc.SetSpiceDBClient(sdb, &config.Config{})
	svc.SetAuthorizationEngine(engine)
	svc.SetSimulationAuditor(&sodAuditRecorder{})

	batch := func(tenantID, user uuid.UUID) models.PermissionDecision {
		r, err := svc.AuthorizeBatch(ctx, &models.BatchAuthorizeRequest{UserID: user, TenantID: tenantID, Permissions: []string{perm}})
		require.NoError(t, err)
		return r.Decisions[perm]
	}

	require.Eventually(t, func() bool { return batch(tenant, active).Allowed }, 10*time.Second, 200*time.Millisecond,
		"active unexpired JIT grant must be allowed by authorize/batch")

	assert.False(t, batch(tenant, expired).Allowed, "expired grant denied")
	assert.True(t, batch(tenant, plain).Allowed, "plain grant unchanged")
	assert.False(t, batch(tenant, other).Allowed, "different user not elevated")
	assert.False(t, batch(uuid.New(), active).Allowed, "cross-tenant user not elevated")

	// /simulate verdict equals /batch for the active-grant case, and the trace
	// shows the caveat was decided TRUE (not missing context).
	sim, err := svc.Simulate(ctx, actor, active, tenant, perm)
	require.NoError(t, err)
	assert.Equal(t, batch(tenant, active), sim.Decision)
	assert.True(t, sim.Decision.Allowed)
	caveats, ok := sim.Caveats.([]spicedb.CaveatEvaluation)
	require.True(t, ok)
	require.NotEmpty(t, caveats)
	for _, c := range caveats {
		assert.Equal(t, "RESULT_TRUE", c.Result, c.Name)
	}

	simExpired, err := svc.Simulate(ctx, actor, expired, tenant, perm)
	require.NoError(t, err)
	assert.Equal(t, batch(tenant, expired), simExpired.Decision)
	assert.False(t, simExpired.Decision.Allowed)
}
