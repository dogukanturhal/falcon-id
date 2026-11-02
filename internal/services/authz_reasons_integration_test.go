// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	v1 "github.com/authzed/authzed-go/proto/authzed/api/v1"
	authzed "github.com/authzed/authzed-go/v1"
	"github.com/authzed/grpcutil"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/pkg/config"
	"github.com/dogukanturhal/falcon-id/pkg/spicedb"
)

// Real Postgres (SoD violations) + real SpiceDB tests for authorize/batch
// reasons and authorize/simulate. Run: hack/run-authz-reasons-tests.sh.

type fakeEntitlements map[string]bool

func (f fakeEntitlements) IsTenantEntitled(_ context.Context, _ uuid.UUID, module string) (bool, error) {
	e, ok := f[module]
	if !ok {
		return false, errors.New("entitlement lookup failed")
	}
	return e, nil
}

type fakeSuspension map[uuid.UUID]bool

func (f fakeSuspension) IsSuspended(_ context.Context, t uuid.UUID) bool { return f[t] }

func newAuthzReasonsSpiceDB(t *testing.T) *spicedb.Client {
	t.Helper()
	endpoint := os.Getenv("TEST_SPICEDB_ENDPOINT")
	if endpoint == "" {
		t.Skip("TEST_SPICEDB_ENDPOINT is required; run hack/run-authz-reasons-tests.sh")
	}
	token := os.Getenv("TEST_SPICEDB_TOKEN")
	raw, err := authzed.NewClient(endpoint, grpc.WithTransportCredentials(insecure.NewCredentials()), grpcutil.WithInsecureBearerToken(token))
	require.NoError(t, err)
	schema, err := os.ReadFile("../../deploy/helm/spicedb-schema/files/spicedb.zed")
	require.NoError(t, err)
	_, err = raw.WriteSchema(context.Background(), &v1.WriteSchemaRequest{Schema: string(schema)})
	require.NoError(t, err)
	c, err := spicedb.NewClient(context.Background(), &config.Config{
		SpiceDBEnabled: true, SpiceDBEndpoint: endpoint, SpiceDBToken: token, SpiceDBInsecure: true,
	}, nil)
	require.NoError(t, err)
	return c
}

func TestAuthzReasons_BatchReasonsAgainstRealSpiceDBAndPostgres(t *testing.T) {
	sdb := newAuthzReasonsSpiceDB(t)
	pg := newSoDPG(t)
	ctx := context.Background()

	tenant := pg.tenant
	suspendedTenant := uuid.New()
	const (
		permOK        = "marketing:leads:read"   // granted
		permNoGrant   = "marketing:leads:delete" // entitled module, no grant
		permNoModule  = "crm:contacts:read"      // tenant not entitled to crm
		permLookupErr = "billing:invoices:read"  // entitlement lookup errors -> fail closed
		permSoD       = "accounting:journal_entries:approve"
		permSoDPair   = "accounting:journal_entries:create"
	)
	user := pg.user(t)
	grant := func(perm string, tenantID, userID uuid.UUID) {
		_, err := sdb.WriteRelationship(ctx, "access_grant", tenantID.String()+"/"+spicedb.PermissionToSpiceDBID(perm), "granted_to", "user", tenantID.String()+"/"+userID.String())
		require.NoError(t, err)
	}
	grant(permOK, tenant, user)
	grant(permNoModule, tenant, user) // SpiceDB would allow; entitlement guard must still deny
	grant(permLookupErr, tenant, user)
	grant(permSoDPair, tenant, user)

	// Open block-mode SoD violation touching permSoD (user has no grant for it).
	rule := &models.SoDRule{TenantID: &tenant, Module: "accounting", PermissionA: permSoDPair, PermissionB: permSoD, Mode: models.SoDModeBlock}
	require.NoError(t, pg.repo.CreateRule(ctx, rule))
	require.NoError(t, pg.repo.UpsertViolation(ctx, &models.SoDViolation{
		TenantID: tenant, UserID: user, RuleID: rule.ID, PermissionA: permSoDPair, PermissionB: permSoD, Mode: models.SoDModeBlock, RoleIDs: []uuid.UUID{},
	}))

	engine := NewAuthorizationEngine(nil, nil, nil, nil, sdb, &config.Config{})
	SetEngineModuleEntitlementChecker(engine, fakeEntitlements{"marketing": true, "crm": false, "accounting": true})
	svc := NewAuthorizationService(nil, nil, nil, nil)
	svc.SetAuthorizationEngine(engine)
	svc.SetSoDViolationLister(NewSoDService(pg.repo, pg.repo, nil))
	svc.SetTenantSuspensionChecker(fakeSuspension{suspendedTenant: true})

	perms := []string{permOK, permNoGrant, permNoModule, permLookupErr, permSoD}
	var resp *models.BatchAuthorizeResponse
	require.Eventually(t, func() bool { // minimize_latency: wait for tuple visibility
		r, err := svc.AuthorizeBatch(ctx, &models.BatchAuthorizeRequest{UserID: user, TenantID: tenant, Permissions: perms})
		resp = r
		return err == nil && r.Decisions[permOK].Allowed
	}, 10*time.Second, 200*time.Millisecond)

	d := resp.Decisions
	assert.Equal(t, models.PermissionDecision{Allowed: true}, d[permOK])
	assert.True(t, resp.Results[permOK], "legacy results map stays populated")

	assert.False(t, d[permNoGrant].Allowed)
	assert.Equal(t, models.DecisionReasonPermissionDenied, d[permNoGrant].Reason)

	assert.False(t, d[permNoModule].Allowed, "entitlement guard beats a SpiceDB grant")
	assert.Equal(t, models.DecisionReasonEntitlementMissing, d[permNoModule].Reason)
	assert.Equal(t, "crm", d[permNoModule].Module)

	assert.False(t, d[permLookupErr].Allowed, "entitlement lookup failure fails closed")
	assert.Equal(t, models.DecisionReasonUnavailable, d[permLookupErr].Reason)

	assert.False(t, d[permSoD].Allowed)
	assert.Equal(t, models.DecisionReasonSoDConflict, d[permSoD].Reason)

	for k, v := range resp.Results {
		assert.Equal(t, d[k].Allowed, v, "results and decisions never disagree for %s", k)
	}

	// Suspended tenant: every key denied with tenant_suspended, SpiceDB untouched.
	sus, err := svc.AuthorizeBatch(ctx, &models.BatchAuthorizeRequest{UserID: user, TenantID: suspendedTenant, Permissions: []string{permOK}})
	require.NoError(t, err)
	assert.False(t, sus.Decisions[permOK].Allowed)
	assert.Equal(t, models.DecisionReasonTenantSuspended, sus.Decisions[permOK].Reason)

	// Cross-tenant: same user id asked in ANOTHER tenant gets nothing.
	other, err := svc.AuthorizeBatch(ctx, &models.BatchAuthorizeRequest{UserID: user, TenantID: uuid.New(), Permissions: []string{permOK}})
	require.NoError(t, err)
	assert.False(t, other.Decisions[permOK].Allowed)
}

func TestAuthzReasons_SimulateMatchesBatchAndAudits(t *testing.T) {
	sdb := newAuthzReasonsSpiceDB(t)
	ctx := context.Background()
	tenant, actor, target := uuid.New(), uuid.New(), uuid.New()
	const perm = "marketing:leads:read"
	_, err := sdb.WriteRelationship(ctx, "access_grant", tenant.String()+"/"+spicedb.PermissionToSpiceDBID(perm), "granted_to", "user", tenant.String()+"/"+target.String())
	require.NoError(t, err)

	engine := NewAuthorizationEngine(nil, nil, nil, nil, sdb, &config.Config{})
	SetEngineModuleEntitlementChecker(engine, fakeEntitlements{"marketing": true})
	svc := NewAuthorizationService(nil, nil, nil, nil)
	svc.SetSpiceDBClient(sdb, &config.Config{})
	svc.SetAuthorizationEngine(engine)
	rec := &sodAuditRecorder{}
	svc.SetSimulationAuditor(rec)

	var resp *models.SimulateResponse
	require.Eventually(t, func() bool {
		r, err := svc.Simulate(ctx, actor, target, tenant, perm)
		resp = r
		return err == nil && r.Decision.Allowed
	}, 10*time.Second, 200*time.Millisecond)
	assert.NotNil(t, resp.Trace, "simulate carries the SpiceDB resolution trace")

	// Same verdict as authorize/batch for the same (user, tenant, permission).
	batch, err := svc.AuthorizeBatch(ctx, &models.BatchAuthorizeRequest{UserID: target, TenantID: tenant, Permissions: []string{perm}})
	require.NoError(t, err)
	assert.Equal(t, batch.Decisions[perm], resp.Decision)

	// Denied simulation explains itself.
	denied, err := svc.Simulate(ctx, actor, uuid.New(), tenant, perm)
	require.NoError(t, err)
	assert.False(t, denied.Decision.Allowed)
	assert.Equal(t, models.DecisionReasonPermissionDenied, denied.Decision.Reason)

	// Every simulation (allowed or denied, including Eventually retries) is audited.
	assert.GreaterOrEqual(t, rec.count(), 2)
	for _, a := range rec.events {
		assert.Equal(t, "authz.simulate", a)
	}
}
