// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/pkg/logger"
)

func init() {
	// Initialize a no-op logger for tests that use the provisioning orchestrator.
	if logger.Log == nil {
		logger.Log = zap.NewNop()
	}
}

// mockInstanceRepo is a minimal in-memory implementation of productInstanceRepo
// for testing the provisioning orchestrator.
type mockInstanceRepo struct {
	instances map[uuid.UUID]*models.ProductInstance
}

func newMockInstanceRepo() *mockInstanceRepo {
	return &mockInstanceRepo{instances: make(map[uuid.UUID]*models.ProductInstance)}
}

func (m *mockInstanceRepo) Create(_ context.Context, pi *models.ProductInstance) error {
	if pi.ID == uuid.Nil {
		pi.ID = uuid.New()
	}
	m.instances[pi.ID] = pi
	return nil
}

func (m *mockInstanceRepo) GetByID(_ context.Context, id uuid.UUID) (*models.ProductInstance, error) {
	pi, ok := m.instances[id]
	if !ok {
		return nil, fmt.Errorf("no rows in result set")
	}
	return pi, nil
}

func (m *mockInstanceRepo) GetByTenantAndProduct(_ context.Context, tenantID, productID uuid.UUID) (*models.ProductInstance, error) {
	for _, pi := range m.instances {
		if pi.TenantID == tenantID && pi.ProductID == productID {
			return pi, nil
		}
	}
	return nil, fmt.Errorf("no rows in result set")
}

func (m *mockInstanceRepo) ListByTenant(_ context.Context, tenantID uuid.UUID, _, _ int) ([]models.ProductInstance, int64, error) {
	var result []models.ProductInstance
	for _, pi := range m.instances {
		if pi.TenantID == tenantID && pi.ProvisioningState != models.ProvisioningStateDeleted {
			result = append(result, *pi)
		}
	}
	return result, int64(len(result)), nil
}

func (m *mockInstanceRepo) ListByProduct(_ context.Context, productID uuid.UUID) ([]models.ProductInstance, error) {
	var result []models.ProductInstance
	for _, pi := range m.instances {
		if pi.ProductID == productID {
			result = append(result, *pi)
		}
	}
	return result, nil
}

func (m *mockInstanceRepo) ListPending(_ context.Context) ([]models.ProductInstance, error) {
	var result []models.ProductInstance
	for _, pi := range m.instances {
		if !pi.ProvisioningState.IsTerminal() && pi.ProvisioningState != models.ProvisioningStateDeleting {
			result = append(result, *pi)
		}
	}
	return result, nil
}

func (m *mockInstanceRepo) UpdateState(_ context.Context, id uuid.UUID, state models.ProvisioningState, currentStep *string) error {
	pi, ok := m.instances[id]
	if !ok {
		return fmt.Errorf("not found")
	}
	pi.ProvisioningState = state
	pi.CurrentStep = currentStep
	return nil
}

func (m *mockInstanceRepo) CompleteStep(_ context.Context, id uuid.UUID, step string, newState models.ProvisioningState) error {
	pi, ok := m.instances[id]
	if !ok {
		return fmt.Errorf("not found")
	}
	pi.CompletedSteps = append(pi.CompletedSteps, step)
	pi.ProvisioningState = newState
	pi.CurrentStep = nil
	return nil
}

func (m *mockInstanceRepo) SetFailed(_ context.Context, id uuid.UUID, reason string) error {
	pi, ok := m.instances[id]
	if !ok {
		return fmt.Errorf("not found")
	}
	pi.ProvisioningState = models.ProvisioningStateFailed
	pi.FailureReason = &reason
	return nil
}

func (m *mockInstanceRepo) SetActive(_ context.Context, id uuid.UUID) error {
	pi, ok := m.instances[id]
	if !ok {
		return fmt.Errorf("not found")
	}
	pi.ProvisioningState = models.ProvisioningStateActive
	return nil
}

func (m *mockInstanceRepo) SetDeleted(_ context.Context, id uuid.UUID) error {
	pi, ok := m.instances[id]
	if !ok {
		return fmt.Errorf("not found")
	}
	pi.ProvisioningState = models.ProvisioningStateDeleted
	return nil
}

func (m *mockInstanceRepo) UpdateDatabaseInfo(_ context.Context, id uuid.UUID, host, dbName, schema, username string, connEnc []byte) error {
	pi, ok := m.instances[id]
	if !ok {
		return fmt.Errorf("not found")
	}
	pi.DatabaseHost = &host
	pi.DatabaseName = &dbName
	pi.DatabaseSchema = &schema
	pi.DatabaseUsername = &username
	pi.ConnectionStringEnc = connEnc
	return nil
}

func (m *mockInstanceRepo) UpdateMigrationVersion(_ context.Context, id uuid.UUID, version int) error {
	pi, ok := m.instances[id]
	if !ok {
		return fmt.Errorf("not found")
	}
	pi.LastMigrationVersion = version
	return nil
}

func (m *mockInstanceRepo) ResetForRetry(_ context.Context, id uuid.UUID) error {
	pi, ok := m.instances[id]
	if !ok {
		return fmt.Errorf("not found")
	}
	pi.ProvisioningState = models.ProvisioningStatePending
	return nil
}

func (m *mockInstanceRepo) ResetForManualRetry(_ context.Context, id uuid.UUID) error {
	pi, ok := m.instances[id]
	if !ok {
		return fmt.Errorf("not found")
	}
	pi.ProvisioningState = models.ProvisioningStatePending
	pi.RetryCount = 0
	pi.MaxRetriesExhausted = false
	pi.NextRetryAt = nil
	return nil
}

func (m *mockInstanceRepo) SetFailedWithRetry(_ context.Context, id uuid.UUID, reason string, retryCount int, nextRetryAt time.Time) error {
	pi, ok := m.instances[id]
	if !ok {
		return fmt.Errorf("not found")
	}
	pi.ProvisioningState = models.ProvisioningStateFailed
	pi.FailureReason = &reason
	pi.RetryCount = retryCount
	pi.NextRetryAt = &nextRetryAt
	return nil
}

func (m *mockInstanceRepo) SetPermanentlyFailed(_ context.Context, id uuid.UUID, reason string) error {
	pi, ok := m.instances[id]
	if !ok {
		return fmt.Errorf("not found")
	}
	pi.ProvisioningState = models.ProvisioningStateFailed
	pi.FailureReason = &reason
	pi.MaxRetriesExhausted = true
	return nil
}

func (m *mockInstanceRepo) ResetForReprovisioning(_ context.Context, id uuid.UUID) error {
	pi, ok := m.instances[id]
	if !ok {
		return fmt.Errorf("not found")
	}
	pi.ProvisioningState = models.ProvisioningStatePending
	pi.FailureReason = nil
	pi.RetryCount = 0
	pi.MaxRetriesExhausted = false
	pi.NextRetryAt = nil
	return nil
}

// mockProductRepo for the orchestrator.
type mockOrchestratorProductRepo struct {
	products map[uuid.UUID]*models.Product
}

func newMockProductRepo() *mockOrchestratorProductRepo {
	return &mockOrchestratorProductRepo{products: make(map[uuid.UUID]*models.Product)}
}

func (m *mockOrchestratorProductRepo) GetByID(_ context.Context, id uuid.UUID) (*models.Product, error) {
	p, ok := m.products[id]
	if !ok {
		return nil, fmt.Errorf("product not found")
	}
	return p, nil
}

func TestProvisioningOrchestrator_ReconcileFullCycle(t *testing.T) {
	ctx := context.Background()

	instanceRepo := newMockInstanceRepo()
	productRepo := newMockProductRepo()

	productID := uuid.New()
	productRepo.products[productID] = &models.Product{
		ID:     productID,
		Name:   "Test Product",
		Slug:   "test-product",
		Status: models.ProductStatusActive,
	}

	orchestrator := NewProvisioningOrchestrator(
		instanceRepo, productRepo, nil, nil, nil,
		ProvisioningOrchestratorConfig{MaxRetries: 3},
	)

	// Create a pending instance.
	pi := &models.ProductInstance{
		ID:                uuid.New(),
		TenantID:          uuid.New(),
		ProductID:         productID,
		ProvisioningState: models.ProvisioningStatePending,
		CompletedSteps:    []string{},
	}
	instanceRepo.instances[pi.ID] = pi

	// Each Reconcile call advances one step through the saga.
	// Step 1: pending → migrating (database created)
	err := orchestrator.Reconcile(ctx, pi.ID)
	require.NoError(t, err)
	assert.Equal(t, models.ProvisioningStateMigrating, pi.ProvisioningState)
	assert.Contains(t, pi.CompletedSteps, "creating")

	// Step 2: migrating → seeding (migrations run)
	err = orchestrator.Reconcile(ctx, pi.ID)
	require.NoError(t, err)
	assert.Equal(t, models.ProvisioningStateSeeding, pi.ProvisioningState)
	assert.Contains(t, pi.CompletedSteps, "migrating")

	// Step 3: seeding → configuring_auth (data seeded)
	err = orchestrator.Reconcile(ctx, pi.ID)
	require.NoError(t, err)
	assert.Equal(t, models.ProvisioningStateConfiguringAuth, pi.ProvisioningState)
	assert.Contains(t, pi.CompletedSteps, "seeding")

	// Step 4: configuring_auth → registering_service (SpiceDB configured)
	err = orchestrator.Reconcile(ctx, pi.ID)
	require.NoError(t, err)
	assert.Equal(t, models.ProvisioningStateRegisteringService, pi.ProvisioningState)
	assert.Contains(t, pi.CompletedSteps, "configuring_auth")

	// Step 5: registering_service → active (service registered, instance activated)
	err = orchestrator.Reconcile(ctx, pi.ID)
	require.NoError(t, err)
	assert.Equal(t, models.ProvisioningStateActive, pi.ProvisioningState)
	assert.Contains(t, pi.CompletedSteps, "registering_service")

	// All 5 steps completed.
	assert.Len(t, pi.CompletedSteps, 5)

	// Active is terminal — reconcile is a no-op.
	err = orchestrator.Reconcile(ctx, pi.ID)
	require.NoError(t, err)
	assert.Equal(t, models.ProvisioningStateActive, pi.ProvisioningState)
}

func TestProvisioningOrchestrator_ReconcileDeletion(t *testing.T) {
	ctx := context.Background()

	instanceRepo := newMockInstanceRepo()
	productRepo := newMockProductRepo()

	orchestrator := NewProvisioningOrchestrator(
		instanceRepo, productRepo, nil, nil, nil,
		ProvisioningOrchestratorConfig{},
	)

	pi := &models.ProductInstance{
		ID:                uuid.New(),
		TenantID:          uuid.New(),
		ProductID:         uuid.New(),
		ProvisioningState: models.ProvisioningStateDeleting,
		CompletedSteps:    []string{},
	}
	instanceRepo.instances[pi.ID] = pi

	err := orchestrator.Reconcile(ctx, pi.ID)
	require.NoError(t, err)
	assert.Equal(t, models.ProvisioningStateDeleted, pi.ProvisioningState)
}

func TestProvisioningOrchestrator_IdempotentReconcile(t *testing.T) {
	ctx := context.Background()

	instanceRepo := newMockInstanceRepo()
	productRepo := newMockProductRepo()

	orchestrator := NewProvisioningOrchestrator(
		instanceRepo, productRepo, nil, nil, nil,
		ProvisioningOrchestratorConfig{},
	)

	// Active instance: reconcile should be a no-op.
	pi := &models.ProductInstance{
		ID:                uuid.New(),
		TenantID:          uuid.New(),
		ProductID:         uuid.New(),
		ProvisioningState: models.ProvisioningStateActive,
		CompletedSteps:    []string{},
	}
	instanceRepo.instances[pi.ID] = pi

	err := orchestrator.Reconcile(ctx, pi.ID)
	require.NoError(t, err)
	assert.Equal(t, models.ProvisioningStateActive, pi.ProvisioningState)

	// Failed instance: also a no-op.
	pi.ProvisioningState = models.ProvisioningStateFailed
	err = orchestrator.Reconcile(ctx, pi.ID)
	require.NoError(t, err)
	assert.Equal(t, models.ProvisioningStateFailed, pi.ProvisioningState)
}

func TestProvisioningOrchestrator_FailOnMissingProduct(t *testing.T) {
	ctx := context.Background()

	instanceRepo := newMockInstanceRepo()
	productRepo := newMockProductRepo() // empty — no products

	orchestrator := NewProvisioningOrchestrator(
		instanceRepo, productRepo, nil, nil, nil,
		ProvisioningOrchestratorConfig{},
	)

	pi := &models.ProductInstance{
		ID:                uuid.New(),
		TenantID:          uuid.New(),
		ProductID:         uuid.New(), // product doesn't exist in repo
		ProvisioningState: models.ProvisioningStatePending,
		CompletedSteps:    []string{},
	}
	instanceRepo.instances[pi.ID] = pi

	err := orchestrator.Reconcile(ctx, pi.ID)
	require.NoError(t, err) // error is handled internally via SetFailed
	assert.Equal(t, models.ProvisioningStateFailed, pi.ProvisioningState)
	require.NotNil(t, pi.FailureReason)
	assert.Contains(t, *pi.FailureReason, "product lookup failed")
}

func TestProductInstanceService_Provision(t *testing.T) {
	ctx := context.Background()

	instanceRepo := newMockInstanceRepo()
	productRepo := newMockProductRepo()

	productID := uuid.New()
	productRepo.products[productID] = &models.Product{
		ID:     productID,
		Name:   "Test Product",
		Slug:   "test-product",
		Status: models.ProductStatusActive,
	}

	svc := NewProductInstanceService(instanceRepo, productRepo)

	tenantID := uuid.New()
	req := &models.CreateProductInstanceRequest{TenantID: tenantID}

	// First provision should succeed.
	pi, err := svc.Provision(ctx, productID, req)
	require.NoError(t, err)
	assert.Equal(t, models.ProvisioningStatePending, pi.ProvisioningState)
	assert.Equal(t, tenantID, pi.TenantID)
	assert.Equal(t, productID, pi.ProductID)

	// Second provision for same tenant+product should fail (duplicate).
	_, err = svc.Provision(ctx, productID, req)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "already has an instance")
}

func TestProductInstanceService_Deprovision(t *testing.T) {
	ctx := context.Background()

	instanceRepo := newMockInstanceRepo()
	productRepo := newMockProductRepo()

	svc := NewProductInstanceService(instanceRepo, productRepo)

	pi := &models.ProductInstance{
		ID:                uuid.New(),
		TenantID:          uuid.New(),
		ProductID:         uuid.New(),
		ProvisioningState: models.ProvisioningStateActive,
		CompletedSteps:    []string{},
	}
	instanceRepo.instances[pi.ID] = pi

	err := svc.Deprovision(ctx, pi.ID)
	require.NoError(t, err)
	assert.Equal(t, models.ProvisioningStateDeleting, pi.ProvisioningState)
}
