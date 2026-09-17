// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

// ---------------------------------------------------------------------------
// NoopTemporalClient
// ---------------------------------------------------------------------------

func TestNoopTemporalClient_StartProvisioningWorkflow(t *testing.T) {
	client := &NoopTemporalClient{}

	input := ProvisioningWorkflowInput{
		InstanceID: uuid.New(),
		TenantID:   uuid.New(),
		ProductID:  uuid.New(),
		PlanID:     "starter",
	}

	workflowID, err := client.StartProvisioningWorkflow(context.Background(), input)

	assert.Empty(t, workflowID, "noop client must return an empty workflow ID")
	require.Error(t, err, "noop client must return an error")
	assert.Contains(t, err.Error(), "temporal: not enabled")
}

func TestNoopTemporalClient_StartDeprovisioningWorkflow(t *testing.T) {
	client := &NoopTemporalClient{}

	workflowID, err := client.StartDeprovisioningWorkflow(context.Background(), uuid.New())

	assert.Empty(t, workflowID, "noop client must return an empty workflow ID")
	require.Error(t, err, "noop client must return an error")
	assert.Contains(t, err.Error(), "temporal: not enabled")
}

func TestNoopTemporalClient_GetWorkflowStatus(t *testing.T) {
	client := &NoopTemporalClient{}

	status, err := client.GetWorkflowStatus(context.Background(), "some-workflow-id")

	assert.Equal(t, "unknown", status, "noop client must return 'unknown' status")
	require.Error(t, err, "noop client must return an error")
	assert.Contains(t, err.Error(), "temporal: not enabled")
}

func TestNoopTemporalClient_Close_IsNoop(t *testing.T) {
	client := &NoopTemporalClient{}
	// Close must not panic or return an error.
	assert.NotPanics(t, func() { client.Close() })
}

func TestNoopTemporalClient_ImplementsInterface(_ *testing.T) {
	// Compile-time check that NoopTemporalClient satisfies the interface.
	// If this assignment fails to compile, the interface contract is broken.
	var _ TemporalProvisioningClient = &NoopTemporalClient{}
}

// ---------------------------------------------------------------------------
// DefaultTemporalProvisioningConfig
// ---------------------------------------------------------------------------

func TestDefaultTemporalProvisioningConfig(t *testing.T) {
	cfg := DefaultTemporalProvisioningConfig()

	assert.False(t, cfg.Enabled, "Temporal must be disabled by default")
	assert.Equal(t, "temporal:7233", cfg.HostPort)
	assert.Equal(t, "hexxlock-provisioning", cfg.Namespace)
	assert.Equal(t, "provisioning-tasks", cfg.TaskQueue)
	assert.Equal(t, 30*time.Minute, cfg.WorkflowTimeout)
	assert.Equal(t, 10*time.Minute, cfg.ActivityTimeout)
}

// ---------------------------------------------------------------------------
// ProvisioningWorkflowInput / ProvisioningWorkflowResult
// ---------------------------------------------------------------------------

func TestProvisioningWorkflowInput_Fields(t *testing.T) {
	instanceID := uuid.New()
	tenantID := uuid.New()
	productID := uuid.New()

	input := ProvisioningWorkflowInput{
		InstanceID: instanceID,
		TenantID:   tenantID,
		ProductID:  productID,
		PlanID:     "enterprise",
	}

	assert.Equal(t, instanceID, input.InstanceID)
	assert.Equal(t, tenantID, input.TenantID)
	assert.Equal(t, productID, input.ProductID)
	assert.Equal(t, "enterprise", input.PlanID)
}

func TestProvisioningWorkflowResult_Fields(t *testing.T) {
	id := uuid.New()
	result := ProvisioningWorkflowResult{
		InstanceID: id,
		Status:     "active",
		Error:      "",
		Duration:   5 * time.Minute,
	}

	assert.Equal(t, id, result.InstanceID)
	assert.Equal(t, "active", result.Status)
	assert.Empty(t, result.Error)
	assert.Equal(t, 5*time.Minute, result.Duration)
}

// ---------------------------------------------------------------------------
// ProvisioningActivities — wraps orchestrator steps correctly
// ---------------------------------------------------------------------------

// buildTestOrchestrator returns a minimal ProvisioningOrchestrator backed by
// in-memory mocks suitable for activity unit tests.
func buildTestOrchestrator(instanceRepo *mockInstanceRepo, productRepo *mockOrchestratorProductRepo) *ProvisioningOrchestrator {
	return NewProvisioningOrchestrator(
		instanceRepo, productRepo, nil, nil, nil,
		ProvisioningOrchestratorConfig{MaxRetries: 3},
	)
}

func TestProvisioningActivities_CreateDatabase(t *testing.T) {
	ctx := context.Background()

	instanceRepo := newMockInstanceRepo()
	productRepo := newMockProductRepo()

	productID := uuid.New()
	productRepo.products[productID] = &models.Product{
		ID:     productID,
		Slug:   "test-product",
		Status: models.ProductStatusActive,
	}

	pi := &models.ProductInstance{
		ID:                uuid.New(),
		TenantID:          uuid.New(),
		ProductID:         productID,
		ProvisioningState: models.ProvisioningStatePending,
		CompletedSteps:    []string{},
	}
	instanceRepo.instances[pi.ID] = pi

	orch := buildTestOrchestrator(instanceRepo, productRepo)
	activities := NewProvisioningActivities(orch, zap.NewNop())

	input := ProvisioningWorkflowInput{
		InstanceID: pi.ID,
		TenantID:   pi.TenantID,
		ProductID:  pi.ProductID,
	}

	err := activities.CreateDatabase(ctx, input)
	require.NoError(t, err)

	// After CreateDatabase the instance must have advanced to "migrating".
	assert.Equal(t, models.ProvisioningStateMigrating, pi.ProvisioningState,
		"CreateDatabase activity must advance state to migrating")
	assert.Contains(t, pi.CompletedSteps, "creating")
}

func TestProvisioningActivities_RunMigrations(t *testing.T) {
	ctx := context.Background()

	instanceRepo := newMockInstanceRepo()
	productRepo := newMockProductRepo()

	productID := uuid.New()
	productRepo.products[productID] = &models.Product{
		ID:     productID,
		Slug:   "test-product",
		Status: models.ProductStatusActive,
	}

	pi := &models.ProductInstance{
		ID:                uuid.New(),
		TenantID:          uuid.New(),
		ProductID:         productID,
		ProvisioningState: models.ProvisioningStateMigrating,
		CompletedSteps:    []string{"creating"},
	}
	instanceRepo.instances[pi.ID] = pi

	orch := buildTestOrchestrator(instanceRepo, productRepo)
	activities := NewProvisioningActivities(orch, zap.NewNop())

	input := ProvisioningWorkflowInput{
		InstanceID: pi.ID,
		TenantID:   pi.TenantID,
		ProductID:  pi.ProductID,
	}

	err := activities.RunMigrations(ctx, input)
	require.NoError(t, err)

	assert.Equal(t, models.ProvisioningStateSeeding, pi.ProvisioningState,
		"RunMigrations activity must advance state to seeding")
	assert.Contains(t, pi.CompletedSteps, "migrating")
}

func TestProvisioningActivities_SeedData(t *testing.T) {
	ctx := context.Background()

	instanceRepo := newMockInstanceRepo()
	productRepo := newMockProductRepo()

	pi := &models.ProductInstance{
		ID:                uuid.New(),
		TenantID:          uuid.New(),
		ProductID:         uuid.New(),
		ProvisioningState: models.ProvisioningStateSeeding,
		CompletedSteps:    []string{"creating", "migrating"},
	}
	instanceRepo.instances[pi.ID] = pi

	orch := buildTestOrchestrator(instanceRepo, productRepo)
	activities := NewProvisioningActivities(orch, zap.NewNop())

	input := ProvisioningWorkflowInput{
		InstanceID: pi.ID,
		TenantID:   pi.TenantID,
		ProductID:  pi.ProductID,
	}

	err := activities.SeedData(ctx, input)
	require.NoError(t, err)

	assert.Equal(t, models.ProvisioningStateConfiguringAuth, pi.ProvisioningState,
		"SeedData activity must advance state to configuring_auth")
	assert.Contains(t, pi.CompletedSteps, "seeding")
}

func TestProvisioningActivities_ConfigureAuth(t *testing.T) {
	ctx := context.Background()

	instanceRepo := newMockInstanceRepo()
	productRepo := newMockProductRepo()

	pi := &models.ProductInstance{
		ID:                uuid.New(),
		TenantID:          uuid.New(),
		ProductID:         uuid.New(),
		ProvisioningState: models.ProvisioningStateConfiguringAuth,
		CompletedSteps:    []string{"creating", "migrating", "seeding"},
	}
	instanceRepo.instances[pi.ID] = pi

	orch := buildTestOrchestrator(instanceRepo, productRepo)
	// spiceDB is nil so the step completes without writing relationships.
	activities := NewProvisioningActivities(orch, zap.NewNop())

	input := ProvisioningWorkflowInput{
		InstanceID: pi.ID,
		TenantID:   pi.TenantID,
		ProductID:  pi.ProductID,
	}

	err := activities.ConfigureAuth(ctx, input)
	require.NoError(t, err)

	assert.Equal(t, models.ProvisioningStateRegisteringService, pi.ProvisioningState,
		"ConfigureAuth activity must advance state to registering_service")
	assert.Contains(t, pi.CompletedSteps, "configuring_auth")
}

func TestProvisioningActivities_RegisterService(t *testing.T) {
	ctx := context.Background()

	instanceRepo := newMockInstanceRepo()
	productRepo := newMockProductRepo()

	pi := &models.ProductInstance{
		ID:                uuid.New(),
		TenantID:          uuid.New(),
		ProductID:         uuid.New(),
		ProvisioningState: models.ProvisioningStateRegisteringService,
		CompletedSteps:    []string{"creating", "migrating", "seeding", "configuring_auth"},
	}
	instanceRepo.instances[pi.ID] = pi

	orch := buildTestOrchestrator(instanceRepo, productRepo)
	activities := NewProvisioningActivities(orch, zap.NewNop())

	input := ProvisioningWorkflowInput{
		InstanceID: pi.ID,
		TenantID:   pi.TenantID,
		ProductID:  pi.ProductID,
	}

	err := activities.RegisterService(ctx, input)
	require.NoError(t, err)

	assert.Equal(t, models.ProvisioningStateActive, pi.ProvisioningState,
		"RegisterService activity must set state to active")
	assert.Contains(t, pi.CompletedSteps, "registering_service")
}

func TestProvisioningActivities_ReturnsErrorOnMissingInstance(t *testing.T) {
	ctx := context.Background()

	instanceRepo := newMockInstanceRepo() // empty — no instances
	productRepo := newMockProductRepo()

	orch := buildTestOrchestrator(instanceRepo, productRepo)
	activities := NewProvisioningActivities(orch, zap.NewNop())

	input := ProvisioningWorkflowInput{
		InstanceID: uuid.New(), // unknown ID
		TenantID:   uuid.New(),
		ProductID:  uuid.New(),
	}

	// Every activity must surface a non-nil error when the instance is missing.
	t.Run("CreateDatabase", func(t *testing.T) {
		err := activities.CreateDatabase(ctx, input)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "CreateDatabase activity")
	})

	t.Run("RunMigrations", func(t *testing.T) {
		err := activities.RunMigrations(ctx, input)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "RunMigrations activity")
	})

	t.Run("SeedData", func(t *testing.T) {
		err := activities.SeedData(ctx, input)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "SeedData activity")
	})

	t.Run("ConfigureAuth", func(t *testing.T) {
		err := activities.ConfigureAuth(ctx, input)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "ConfigureAuth activity")
	})

	t.Run("RegisterService", func(t *testing.T) {
		err := activities.RegisterService(ctx, input)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "RegisterService activity")
	})
}

func TestNewProvisioningActivities_PanicsOnNilOrchestrator(t *testing.T) {
	assert.Panics(t, func() {
		NewProvisioningActivities(nil, zap.NewNop())
	}, "NewProvisioningActivities must panic when orchestrator is nil")
}

// ---------------------------------------------------------------------------
// Orchestrator Temporal dispatch — dual-mode integration
// ---------------------------------------------------------------------------

// fakeTemporalClient records calls so we can assert dispatch behaviour.
type fakeTemporalClient struct {
	startCalls   []ProvisioningWorkflowInput
	returnErr    error
	returnWorkID string
}

func (f *fakeTemporalClient) StartProvisioningWorkflow(_ context.Context, input ProvisioningWorkflowInput) (string, error) {
	f.startCalls = append(f.startCalls, input)
	return f.returnWorkID, f.returnErr
}

func (f *fakeTemporalClient) StartDeprovisioningWorkflow(_ context.Context, _ uuid.UUID) (string, error) {
	return "", nil
}

func (f *fakeTemporalClient) GetWorkflowStatus(_ context.Context, _ string) (string, error) {
	return "RUNNING", nil
}

func (f *fakeTemporalClient) Close() {}

func TestOrchestratorReconcile_DispatchesToTemporalWhenEnabled(t *testing.T) {
	ctx := context.Background()

	instanceRepo := newMockInstanceRepo()
	productRepo := newMockProductRepo()

	productID := uuid.New()
	productRepo.products[productID] = &models.Product{
		ID:     productID,
		Slug:   "crm",
		Status: models.ProductStatusActive,
	}

	plan := "starter"
	pi := &models.ProductInstance{
		ID:                uuid.New(),
		TenantID:          uuid.New(),
		ProductID:         productID,
		PlanID:            &plan,
		ProvisioningState: models.ProvisioningStatePending,
		CompletedSteps:    []string{},
	}
	instanceRepo.instances[pi.ID] = pi

	client := &fakeTemporalClient{returnWorkID: "wf-abc123"}

	orch := NewProvisioningOrchestrator(
		instanceRepo, productRepo, nil, nil, nil,
		ProvisioningOrchestratorConfig{},
	).WithTemporalClient(client)

	err := orch.Reconcile(ctx, pi.ID)
	require.NoError(t, err)

	// Temporal must have been called exactly once.
	require.Len(t, client.startCalls, 1)
	assert.Equal(t, pi.ID, client.startCalls[0].InstanceID)
	assert.Equal(t, pi.TenantID, client.startCalls[0].TenantID)
	assert.Equal(t, pi.ProductID, client.startCalls[0].ProductID)
	assert.Equal(t, "starter", client.startCalls[0].PlanID)

	// The instance state must remain "pending" — Temporal owns the transition.
	assert.Equal(t, models.ProvisioningStatePending, pi.ProvisioningState,
		"orchestrator must not advance state when dispatching to Temporal")
}

func TestOrchestratorReconcile_FallsBackToLocalOnTemporalError(t *testing.T) {
	ctx := context.Background()

	instanceRepo := newMockInstanceRepo()
	productRepo := newMockProductRepo()

	productID := uuid.New()
	productRepo.products[productID] = &models.Product{
		ID:     productID,
		Slug:   "crm",
		Status: models.ProductStatusActive,
	}

	pi := &models.ProductInstance{
		ID:                uuid.New(),
		TenantID:          uuid.New(),
		ProductID:         productID,
		ProvisioningState: models.ProvisioningStatePending,
		CompletedSteps:    []string{},
	}
	instanceRepo.instances[pi.ID] = pi

	// Client that always fails (e.g., Temporal server is down).
	client := &fakeTemporalClient{returnErr: assert.AnError}

	orch := NewProvisioningOrchestrator(
		instanceRepo, productRepo, nil, nil, nil,
		ProvisioningOrchestratorConfig{},
	).WithTemporalClient(client)

	err := orch.Reconcile(ctx, pi.ID)
	require.NoError(t, err)

	// Local reconciliation must have taken over: the instance advances to migrating.
	assert.Equal(t, models.ProvisioningStateMigrating, pi.ProvisioningState,
		"orchestrator must fall back to local reconciliation when Temporal dispatch fails")
	assert.Contains(t, pi.CompletedSteps, "creating")
}

func TestOrchestratorReconcile_NoTemporalClient_ProcessesLocally(t *testing.T) {
	ctx := context.Background()

	instanceRepo := newMockInstanceRepo()
	productRepo := newMockProductRepo()

	productID := uuid.New()
	productRepo.products[productID] = &models.Product{
		ID:     productID,
		Slug:   "crm",
		Status: models.ProductStatusActive,
	}

	pi := &models.ProductInstance{
		ID:                uuid.New(),
		TenantID:          uuid.New(),
		ProductID:         productID,
		ProvisioningState: models.ProvisioningStatePending,
		CompletedSteps:    []string{},
	}
	instanceRepo.instances[pi.ID] = pi

	// No Temporal client — purely local mode (default).
	orch := NewProvisioningOrchestrator(
		instanceRepo, productRepo, nil, nil, nil,
		ProvisioningOrchestratorConfig{},
	)

	err := orch.Reconcile(ctx, pi.ID)
	require.NoError(t, err)

	assert.Equal(t, models.ProvisioningStateMigrating, pi.ProvisioningState)
	assert.Contains(t, pi.CompletedSteps, "creating")
}

func TestOrchestratorReconcile_TemporalSkippedForNonPendingInstances(t *testing.T) {
	ctx := context.Background()

	instanceRepo := newMockInstanceRepo()
	productRepo := newMockProductRepo()

	productID := uuid.New()
	productRepo.products[productID] = &models.Product{
		ID:     productID,
		Slug:   "crm",
		Status: models.ProductStatusActive,
	}

	// Instance already mid-flight (migrating) — Temporal must NOT be called.
	pi := &models.ProductInstance{
		ID:                uuid.New(),
		TenantID:          uuid.New(),
		ProductID:         productID,
		ProvisioningState: models.ProvisioningStateMigrating,
		CompletedSteps:    []string{"creating"},
	}
	instanceRepo.instances[pi.ID] = pi

	client := &fakeTemporalClient{returnWorkID: "wf-should-not-be-called"}

	orch := NewProvisioningOrchestrator(
		instanceRepo, productRepo, nil, nil, nil,
		ProvisioningOrchestratorConfig{},
	).WithTemporalClient(client)

	err := orch.Reconcile(ctx, pi.ID)
	require.NoError(t, err)

	// Temporal must NOT have been called for a mid-flight instance.
	assert.Empty(t, client.startCalls, "Temporal must not be called for non-pending instances")

	// Local reconciliation advances state normally.
	assert.Equal(t, models.ProvisioningStateSeeding, pi.ProvisioningState)
}

func TestWithTemporalClient_ChainReturnsSameOrchestrator(t *testing.T) {
	instanceRepo := newMockInstanceRepo()
	productRepo := newMockProductRepo()

	orch := NewProvisioningOrchestrator(
		instanceRepo, productRepo, nil, nil, nil,
		ProvisioningOrchestratorConfig{},
	)

	client := &NoopTemporalClient{}
	result := orch.WithTemporalClient(client)

	assert.Same(t, orch, result, "WithTemporalClient must return the same orchestrator for chaining")
	assert.Equal(t, TemporalProvisioningClient(client), orch.temporalClient)
}

func TestWithTemporalClient_AcceptsNil(t *testing.T) {
	instanceRepo := newMockInstanceRepo()
	productRepo := newMockProductRepo()

	orch := NewProvisioningOrchestrator(
		instanceRepo, productRepo, nil, nil, nil,
		ProvisioningOrchestratorConfig{},
	).WithTemporalClient(&NoopTemporalClient{})

	// Clearing the client must work without panic.
	result := orch.WithTemporalClient(nil)
	assert.Same(t, orch, result)
	assert.Nil(t, orch.temporalClient)
}
