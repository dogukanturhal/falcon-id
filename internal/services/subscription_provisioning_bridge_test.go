// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"fmt"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

// --- Mocks ---

type mockBridgeInstanceRepo struct {
	instances map[string]*models.ProductInstance
	created   *models.ProductInstance
}

func newMockBridgeInstanceRepo() *mockBridgeInstanceRepo {
	return &mockBridgeInstanceRepo{instances: make(map[string]*models.ProductInstance)}
}

func (m *mockBridgeInstanceRepo) Create(_ context.Context, instance *models.ProductInstance) error {
	m.created = instance
	key := instance.TenantID.String() + ":" + instance.ProductID.String()
	m.instances[key] = instance
	return nil
}

func (m *mockBridgeInstanceRepo) GetByTenantAndProduct(_ context.Context, tenantID, productID uuid.UUID) (*models.ProductInstance, error) {
	key := tenantID.String() + ":" + productID.String()
	if inst, ok := m.instances[key]; ok {
		return inst, nil
	}
	return nil, fmt.Errorf("not found")
}

type mockBridgeProductRepo struct {
	products map[uuid.UUID]*models.Product
}

func newMockBridgeProductRepo() *mockBridgeProductRepo {
	return &mockBridgeProductRepo{products: make(map[uuid.UUID]*models.Product)}
}

func (m *mockBridgeProductRepo) GetBySlug(_ context.Context, slug string) (*models.Product, error) {
	for _, p := range m.products {
		if p.Slug == slug {
			return p, nil
		}
	}
	return nil, fmt.Errorf("not found")
}

func (m *mockBridgeProductRepo) GetByID(_ context.Context, id uuid.UUID) (*models.Product, error) {
	if p, ok := m.products[id]; ok {
		return p, nil
	}
	return nil, fmt.Errorf("not found")
}

// --- Tests ---

func TestSubscriptionBridge_TriggerProvisioning_CreatesInstance(t *testing.T) {
	productID := uuid.New()
	tenantID := uuid.New()

	instRepo := newMockBridgeInstanceRepo()
	prodRepo := newMockBridgeProductRepo()
	prodRepo.products[productID] = &models.Product{
		ID:   productID,
		Slug: "examplesuite",
	}

	bridge := NewSubscriptionProvisioningBridge(instRepo, prodRepo)

	instance, err := bridge.TriggerProvisioning(context.Background(), tenantID, productID, "pool")

	assert.NoError(t, err)
	assert.NotNil(t, instance)
	assert.Equal(t, tenantID, instance.TenantID)
	assert.Equal(t, productID, instance.ProductID)
	assert.Equal(t, models.ProvisioningStatePending, instance.ProvisioningState)
	assert.Equal(t, "pool", *instance.PlanID)
}

func TestSubscriptionBridge_TriggerProvisioning_Idempotent(t *testing.T) {
	productID := uuid.New()
	tenantID := uuid.New()

	instRepo := newMockBridgeInstanceRepo()
	prodRepo := newMockBridgeProductRepo()
	prodRepo.products[productID] = &models.Product{ID: productID, Slug: "erp"}

	bridge := NewSubscriptionProvisioningBridge(instRepo, prodRepo)

	// First call creates
	inst1, err := bridge.TriggerProvisioning(context.Background(), tenantID, productID, "pool")
	assert.NoError(t, err)

	// Second call returns existing
	inst2, err := bridge.TriggerProvisioning(context.Background(), tenantID, productID, "pool")
	assert.NoError(t, err)
	assert.Equal(t, inst1.ID, inst2.ID, "should return same instance")
}

func TestSubscriptionBridge_TriggerProvisioning_ProductNotFound(t *testing.T) {
	instRepo := newMockBridgeInstanceRepo()
	prodRepo := newMockBridgeProductRepo()

	bridge := NewSubscriptionProvisioningBridge(instRepo, prodRepo)

	_, err := bridge.TriggerProvisioning(context.Background(), uuid.New(), uuid.New(), "pool")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "product not found")
}

func TestSubscriptionBridge_TriggerProvisioning_DefaultIsolation(t *testing.T) {
	productID := uuid.New()
	tenantID := uuid.New()

	instRepo := newMockBridgeInstanceRepo()
	prodRepo := newMockBridgeProductRepo()
	prodRepo.products[productID] = &models.Product{ID: productID, Slug: "erp"}

	bridge := NewSubscriptionProvisioningBridge(instRepo, prodRepo)

	// Empty isolation tier should default to "pool"
	instance, err := bridge.TriggerProvisioning(context.Background(), tenantID, productID, "")
	assert.NoError(t, err)
	assert.Equal(t, "pool", *instance.PlanID)
}
