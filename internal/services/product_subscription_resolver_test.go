// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"fmt"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

// ── Mock implementations ────────────────────────────────────────────────────

type mockSubscriptionInstanceRepo struct {
	instances []models.ProductInstance
	// err, when set, is returned by ListVisibleByTenant instead of any
	// instances — simulates a DB/transport failure so callers can assert
	// fail-closed behaviour (no products claim, never "all products").
	err error
}

func (m *mockSubscriptionInstanceRepo) ListVisibleByTenant(_ context.Context, tenantID uuid.UUID) ([]models.ProductInstance, error) {
	if m.err != nil {
		return nil, m.err
	}
	var result []models.ProductInstance
	for _, pi := range m.instances {
		if pi.TenantID != tenantID {
			continue
		}
		if pi.ProvisioningState == models.ProvisioningStateDeleting || pi.ProvisioningState == models.ProvisioningStateDeleted {
			continue
		}
		result = append(result, pi)
	}
	return result, nil
}

type mockSubscriptionProductRepo struct {
	products map[uuid.UUID]*models.Product
}

func (m *mockSubscriptionProductRepo) GetByID(_ context.Context, id uuid.UUID) (*models.Product, error) {
	if p, ok := m.products[id]; ok {
		return p, nil
	}
	return nil, fmt.Errorf("product not found")
}

// ── Tests ───────────────────────────────────────────────────────────────────

func TestProductSubscriptionResolver_NoActiveInstances(t *testing.T) {
	tenantID := uuid.New()
	instanceRepo := &mockSubscriptionInstanceRepo{instances: nil}
	productRepo := &mockSubscriptionProductRepo{products: map[uuid.UUID]*models.Product{}}

	resolver := NewProductSubscriptionResolver(instanceRepo, productRepo)
	claims, err := resolver.Resolve(context.Background(), tenantID)
	require.NoError(t, err)
	assert.Empty(t, claims)
}

func TestProductSubscriptionResolver_SingleProduct(t *testing.T) {
	tenantID := uuid.New()
	productID := uuid.New()

	instanceRepo := &mockSubscriptionInstanceRepo{
		instances: []models.ProductInstance{
			{ID: uuid.New(), TenantID: tenantID, ProductID: productID, ProvisioningState: models.ProvisioningStateActive},
		},
	}
	productRepo := &mockSubscriptionProductRepo{
		products: map[uuid.UUID]*models.Product{
			productID: {ID: productID, Slug: "examplesuite", Name: "Example Suite"},
		},
	}

	resolver := NewProductSubscriptionResolver(instanceRepo, productRepo)
	claims, err := resolver.Resolve(context.Background(), tenantID)
	require.NoError(t, err)
	require.Len(t, claims, 1)
	assert.Equal(t, productID, claims[0].ProductID)
	assert.Equal(t, "examplesuite", claims[0].ProductSlug)
}

func TestProductSubscriptionResolver_MultipleProducts(t *testing.T) {
	tenantID := uuid.New()
	erpID := uuid.New()
	pmsID := uuid.New()

	instanceRepo := &mockSubscriptionInstanceRepo{
		instances: []models.ProductInstance{
			{ID: uuid.New(), TenantID: tenantID, ProductID: erpID, ProvisioningState: models.ProvisioningStateActive},
			{ID: uuid.New(), TenantID: tenantID, ProductID: pmsID, ProvisioningState: models.ProvisioningStateActive},
		},
	}
	productRepo := &mockSubscriptionProductRepo{
		products: map[uuid.UUID]*models.Product{
			erpID: {ID: erpID, Slug: "examplesuite", Name: "Example Suite"},
			pmsID: {ID: pmsID, Slug: "example-pms", Name: "Example PMS"},
		},
	}

	resolver := NewProductSubscriptionResolver(instanceRepo, productRepo)
	claims, err := resolver.Resolve(context.Background(), tenantID)
	require.NoError(t, err)
	require.Len(t, claims, 2)

	slugs := []string{claims[0].ProductSlug, claims[1].ProductSlug}
	assert.Contains(t, slugs, "examplesuite")
	assert.Contains(t, slugs, "example-pms")
}

// TestProductSubscriptionResolver_NonActiveStillVisible covers Gap 2 of the
// signup-provisioning-interstitial fix: a still-provisioning or failed
// instance must still surface in the claim (so the falcon-id-client gate can
// distinguish "provisioning" from "never subscribed") rather than being
// silently dropped the way ListActiveByTenant used to drop it. Before this
// fix, TestProductSubscriptionResolver_IgnoresNonActive asserted the
// opposite — that non-active instances produced NO claim at all — which is
// exactly the behavior that collapsed "still setting up" into the same hard
// 403 as "not entitled".
func TestProductSubscriptionResolver_NonActiveStillVisible(t *testing.T) {
	tenantID := uuid.New()
	pendingProductID := uuid.New()
	failedProductID := uuid.New()

	instanceRepo := &mockSubscriptionInstanceRepo{
		instances: []models.ProductInstance{
			{ID: uuid.New(), TenantID: tenantID, ProductID: pendingProductID, ProvisioningState: models.ProvisioningStatePending},
			{ID: uuid.New(), TenantID: tenantID, ProductID: failedProductID, ProvisioningState: models.ProvisioningStateFailed},
		},
	}
	productRepo := &mockSubscriptionProductRepo{
		products: map[uuid.UUID]*models.Product{
			pendingProductID: {ID: pendingProductID, Slug: "examplesuite", Name: "Example Suite"},
			failedProductID:  {ID: failedProductID, Slug: "example-pms", Name: "Example PMS"},
		},
	}

	resolver := NewProductSubscriptionResolver(instanceRepo, productRepo)
	claims, err := resolver.Resolve(context.Background(), tenantID)
	require.NoError(t, err)
	require.Len(t, claims, 2)

	byProduct := map[string]ProductClaim{}
	for _, c := range claims {
		byProduct[c.ProductSlug] = c
	}
	assert.Equal(t, "provisioning", byProduct["examplesuite"].State)
	assert.Equal(t, "failed", byProduct["example-pms"].State)
}

// TestProductSubscriptionResolver_ActiveStateOmitted asserts the zero-value
// contract on State: an ACTIVE instance's claim carries State == "" so it
// round-trips through the `omitempty` JSON tag exactly like it did before
// this field existed — no token shrinks or gate behavior changes for the
// common case.
func TestProductSubscriptionResolver_ActiveStateOmitted(t *testing.T) {
	tenantID := uuid.New()
	productID := uuid.New()

	instanceRepo := &mockSubscriptionInstanceRepo{
		instances: []models.ProductInstance{
			{ID: uuid.New(), TenantID: tenantID, ProductID: productID, ProvisioningState: models.ProvisioningStateActive},
		},
	}
	productRepo := &mockSubscriptionProductRepo{
		products: map[uuid.UUID]*models.Product{
			productID: {ID: productID, Slug: "examplesuite", Name: "Example Suite"},
		},
	}

	resolver := NewProductSubscriptionResolver(instanceRepo, productRepo)
	claims, err := resolver.Resolve(context.Background(), tenantID)
	require.NoError(t, err)
	require.Len(t, claims, 1)
	assert.Equal(t, "", claims[0].State)
}

// TestProductSubscriptionResolver_ExcludesCancelled asserts that
// 'deleting'/'deleted' rows (a cancelled subscription) are excluded
// entirely — they must look identical to "never subscribed" so the gate
// gives them the hard 403, not the provisioning interstitial.
func TestProductSubscriptionResolver_ExcludesCancelled(t *testing.T) {
	tenantID := uuid.New()
	deletingID := uuid.New()
	deletedID := uuid.New()

	instanceRepo := &mockSubscriptionInstanceRepo{
		instances: []models.ProductInstance{
			{ID: uuid.New(), TenantID: tenantID, ProductID: deletingID, ProvisioningState: models.ProvisioningStateDeleting},
			{ID: uuid.New(), TenantID: tenantID, ProductID: deletedID, ProvisioningState: models.ProvisioningStateDeleted},
		},
	}
	productRepo := &mockSubscriptionProductRepo{
		products: map[uuid.UUID]*models.Product{
			deletingID: {ID: deletingID, Slug: "examplesuite", Name: "Example Suite"},
			deletedID:  {ID: deletedID, Slug: "example-pms", Name: "Example PMS"},
		},
	}

	resolver := NewProductSubscriptionResolver(instanceRepo, productRepo)
	claims, err := resolver.Resolve(context.Background(), tenantID)
	require.NoError(t, err)
	assert.Empty(t, claims)
}

func TestProductSubscriptionResolver_SkipsMissingProduct(t *testing.T) {
	tenantID := uuid.New()
	knownID := uuid.New()
	unknownID := uuid.New()

	instanceRepo := &mockSubscriptionInstanceRepo{
		instances: []models.ProductInstance{
			{ID: uuid.New(), TenantID: tenantID, ProductID: knownID, ProvisioningState: models.ProvisioningStateActive},
			{ID: uuid.New(), TenantID: tenantID, ProductID: unknownID, ProvisioningState: models.ProvisioningStateActive},
		},
	}
	productRepo := &mockSubscriptionProductRepo{
		products: map[uuid.UUID]*models.Product{
			knownID: {ID: knownID, Slug: "examplesuite", Name: "Example Suite"},
			// unknownID not in products map
		},
	}

	resolver := NewProductSubscriptionResolver(instanceRepo, productRepo)
	claims, err := resolver.Resolve(context.Background(), tenantID)
	require.NoError(t, err)
	require.Len(t, claims, 1)
	assert.Equal(t, "examplesuite", claims[0].ProductSlug)
}

// TestProductSubscriptionResolver_RepoErrorPropagates asserts that a
// failure in the underlying instance repo (DB down, timeout, etc.) is
// surfaced as an error rather than swallowed into an empty/partial claim
// set. Callers (token_service, OAuthProviderService) rely on this error
// return to fail closed — see TestGenerateMinimalToken_ResolverError_OmitsProductsClaim
// and TestOAuthProductsClaim_ResolverError_OmitsProductsClaim.
func TestProductSubscriptionResolver_RepoErrorPropagates(t *testing.T) {
	tenantID := uuid.New()
	instanceRepo := &mockSubscriptionInstanceRepo{err: fmt.Errorf("connection reset")}
	productRepo := &mockSubscriptionProductRepo{products: map[uuid.UUID]*models.Product{}}

	resolver := NewProductSubscriptionResolver(instanceRepo, productRepo)
	claims, err := resolver.Resolve(context.Background(), tenantID)
	require.Error(t, err)
	assert.Nil(t, claims, "on error, resolver must not return a partial/empty-but-non-nil claim set")
}

func TestProductSubscriptionResolver_WithPlanID(t *testing.T) {
	tenantID := uuid.New()
	productID := uuid.New()
	planID := "enterprise"

	instanceRepo := &mockSubscriptionInstanceRepo{
		instances: []models.ProductInstance{
			{ID: uuid.New(), TenantID: tenantID, ProductID: productID, PlanID: &planID, ProvisioningState: models.ProvisioningStateActive},
		},
	}
	productRepo := &mockSubscriptionProductRepo{
		products: map[uuid.UUID]*models.Product{
			productID: {ID: productID, Slug: "examplesuite", Name: "Example Suite"},
		},
	}

	resolver := NewProductSubscriptionResolver(instanceRepo, productRepo)
	claims, err := resolver.Resolve(context.Background(), tenantID)
	require.NoError(t, err)
	require.Len(t, claims, 1)
	assert.Equal(t, "enterprise", *claims[0].PlanID)
}
