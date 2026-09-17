// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/internal/repositories"
)

// TestMearaxEntitlement_RealPostgres_SignupGrantsActiveInstance is an
// integration test against a REAL (local, disposable) Postgres instance —
// not mocks — exercising the exact same production code path wired in
// cmd/services.go for the self-service-signup 403 bug:
//
//	PostSignupProvisioner.OnSignupComplete
//	  -> ProvisioningConsumer.HandleSubscriptionActivated
//	    -> ProductInstanceService.Provision            (real repo, real INSERT)
//	    -> ProvisioningOrchestrator.Reconcile           (real repo, real UPDATEs)
//	  -> ProductSubscriptionResolver.Resolve            (real repo, real SELECT)
//
// It only runs when PG_VERIFY_DSN is set (a local docker Postgres seeded
// with the iam_products / iam_product_instances tables per
// the GitOps repository' falcon-id SchemaDefinition) so it never runs
// against a real cluster and never runs unattended in CI without that
// opt-in. This is NOT a replacement for the unit tests in
// signup_post_provisioner_test.go — it is the "did the real SQL actually
// do the right thing" check those mocks can't provide.
func TestMearaxEntitlement_RealPostgres_SignupGrantsActiveInstance(t *testing.T) {
	dsn := os.Getenv("PG_VERIFY_DSN")
	if dsn == "" {
		t.Skip("PG_VERIFY_DSN not set — skipping real-Postgres integration test")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	pool, err := pgxpool.New(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	require.NoError(t, pool.Ping(ctx))

	productRepo := repositories.NewProductRepository(pool)
	instanceRepo := repositories.NewProductInstanceRepository(pool)

	// Seed a "mearax" product row, mirroring the well-known product ID
	// used in cmd/services.go (models.WellKnownProductMearax) and in the
	// the GitOps repository migration bundle that seeded the one existing
	// production instance.
	mearax := &models.Product{
		ID:     uuid.New(), // distinct per test run; the well-known ID is prod-only
		Name:   "Mearax",
		Slug:   "mearax-e2e-" + uuid.NewString()[:8],
		Type:   "first_party",
		Status: "active",
	}
	require.NoError(t, productRepo.Create(ctx, mearax))

	// Wire the exact same three components cmd/services.go wires, with
	// dbProvisioner and spiceDB nil — mirroring the "mearax is shared-
	// schema, no per-tenant DB provisioning" conclusion documented in
	// the GitOps repository/.../migration-bundle-mearax-product-and-hexxlock-entitlement.yaml.
	instanceService := NewProductInstanceService(instanceRepo, productRepo)
	orchestrator := NewProvisioningOrchestrator(instanceRepo, productRepo, nil, nil, pool, ProvisioningOrchestratorConfig{
		ReconcileInterval: 200 * time.Millisecond,
	})
	orchestrator.Start(ctx)
	defer orchestrator.Stop()
	consumer := NewProvisioningConsumer(instanceService, orchestrator)

	postSignup := NewPostSignupProvisioner(nil, nil, nil)
	postSignup.SetProductEntitlementProvisioner(consumer, mearax.ID)

	resolver := NewProductSubscriptionResolver(instanceRepo, productRepo)

	tenantID := uuid.New()
	userID := uuid.New()

	// --- Real signup-completion call ---
	err = postSignup.OnSignupComplete(ctx, tenantID, userID, "personal")
	require.NoError(t, err)

	// HandleSubscriptionActivated fires orchestrator.Reconcile
	// asynchronously in a goroutine (see provisioning_consumer.go) —
	// poll briefly instead of asserting state immediately.
	var instance *models.ProductInstance
	require.Eventually(t, func() bool {
		instance, err = instanceRepo.GetByTenantAndProduct(ctx, tenantID, mearax.ID)
		return err == nil && instance != nil && instance.ProvisioningState == models.ProvisioningStateActive
	}, 5*time.Second, 50*time.Millisecond, "product instance should reach 'active' state")

	require.NotNil(t, instance)
	require.Equal(t, models.ProvisioningStateActive, instance.ProvisioningState)
	require.NotNil(t, instance.PlanID)
	require.Equal(t, "starter", *instance.PlanID, "self-service signup should carry the configured default ('starter') plan")

	// --- This is what falcon-id-client middleware actually gates on:
	// the JWT `products` claim, populated by ProductSubscriptionResolver
	// from ACTIVE iam_product_instances rows. ---
	claims, err := resolver.Resolve(ctx, tenantID)
	require.NoError(t, err)
	require.Len(t, claims, 1, "tenant should have exactly one active product claim (mearax)")
	require.Equal(t, mearax.ID, claims[0].ProductID)
	require.Equal(t, mearax.Slug, claims[0].ProductSlug)
	require.NotNil(t, claims[0].PlanID)
	require.Equal(t, "starter", *claims[0].PlanID)
}

// TestMearaxEntitlement_RealPostgres_ControlNoEntitlementWired is the
// CONTROL for the test above: it repeats the identical signup flow but
// WITHOUT calling SetProductEntitlementProvisioner — i.e. the exact state
// of the code before this fix. It proves the resolver genuinely returns
// no claims (the condition that produces the reported
// /unauthorized?reason=product_not_entitled 403) when the entitlement
// step is absent, so the positive test above is verifying something real
// and not a tautology.
func TestMearaxEntitlement_RealPostgres_ControlNoEntitlementWired(t *testing.T) {
	dsn := os.Getenv("PG_VERIFY_DSN")
	if dsn == "" {
		t.Skip("PG_VERIFY_DSN not set — skipping real-Postgres integration test")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	pool, err := pgxpool.New(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	require.NoError(t, pool.Ping(ctx))

	productRepo := repositories.NewProductRepository(pool)
	instanceRepo := repositories.NewProductInstanceRepository(pool)

	mearax := &models.Product{
		ID:     uuid.New(),
		Name:   "Mearax",
		Slug:   "mearax-control-" + uuid.NewString()[:8],
		Type:   "first_party",
		Status: "active",
	}
	require.NoError(t, productRepo.Create(ctx, mearax))

	// Deliberately do NOT call SetProductEntitlementProvisioner — this is
	// the pre-fix wiring state.
	postSignup := NewPostSignupProvisioner(nil, nil, nil)
	resolver := NewProductSubscriptionResolver(instanceRepo, productRepo)

	tenantID := uuid.New()
	userID := uuid.New()

	err = postSignup.OnSignupComplete(ctx, tenantID, userID, "personal")
	require.NoError(t, err)

	// Give any (nonexistent) async work a moment, then assert no instance
	// and no claims — this is the exact condition the falcon-id-client
	// middleware turns into a 403 product_not_entitled redirect.
	time.Sleep(200 * time.Millisecond)

	instance, err := instanceRepo.GetByTenantAndProduct(ctx, tenantID, mearax.ID)
	require.Error(t, err, "no product instance should exist when the entitlement step isn't wired")
	require.Nil(t, instance)

	claims, err := resolver.Resolve(ctx, tenantID)
	require.NoError(t, err)
	require.Empty(t, claims, "tenant should have zero product claims without the entitlement fix")
}
