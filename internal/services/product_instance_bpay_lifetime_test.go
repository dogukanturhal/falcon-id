// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"github.com/google/uuid"
	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/stretchr/testify/require"
	"testing"
)

type bpayExistingRootRepo struct {
	productInstanceRepo
	instance *models.ProductInstance
	resets   int
}

func (r *bpayExistingRootRepo) GetByTenantAndProduct(context.Context, uuid.UUID, uuid.UUID) (*models.ProductInstance, error) {
	return r.instance, nil
}
func (r *bpayExistingRootRepo) ResetForReprovisioning(context.Context, uuid.UUID) error {
	r.resets++
	return nil
}

type bpayRootProduct struct{ product *models.Product }

func (r bpayRootProduct) GetByID(context.Context, uuid.UUID) (*models.Product, error) {
	return r.product, nil
}

func TestBpayPaidReplacementReusesRootWithoutResettingPaidCompPlan(t *testing.T) {
	tenant, product := uuid.New(), uuid.New()
	plan, replacementPlan := "existing-comp-or-paid-plan", "new-commercial-offer"
	root := &models.ProductInstance{ID: uuid.New(), TenantID: tenant, ProductID: product, PlanID: &plan, ProvisioningState: models.ProvisioningStateActive}
	repo := &bpayExistingRootRepo{instance: root}
	service := NewProductInstanceService(repo, bpayRootProduct{product: &models.Product{ID: product, Status: models.ProductStatusActive, Slug: "business"}})
	got, err := service.Provision(context.Background(), product, &models.CreateProductInstanceRequest{TenantID: tenant, PlanID: &replacementPlan})
	require.NoError(t, err)
	require.Same(t, root, got)
	require.Equal(t, plan, *got.PlanID)
	require.Zero(t, repo.resets)
	require.Equal(t, "", claimStateForProvisioningState(got.ProvisioningState), "root JWT claim remains accessible; module snapshots govern actual benefits")
}
