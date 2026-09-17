// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

// TemporalProvisioningConfig holds configuration for Temporal-based provisioning.
//
// When Enabled is false (the default), the existing PostgreSQL advisory-lock
// reconciliation loop is used without any changes. When Enabled is true, the
// orchestrator dispatches new pending instances to Temporal workflows instead
// of processing them locally. In both modes, the same underlying step functions
// (stepCreate, stepMigrate, …) perform the actual work, so correctness and
// database state are identical.
type TemporalProvisioningConfig struct {
	// Enabled controls whether Temporal workflows are used instead of the
	// reconciliation loop. Default: false.
	Enabled bool

	// HostPort is the Temporal server address (e.g., "temporal:7233").
	HostPort string

	// Namespace is the Temporal namespace for provisioning workflows.
	Namespace string

	// TaskQueue is the task queue name for provisioning activities.
	TaskQueue string

	// WorkflowTimeout is the maximum time a provisioning workflow can run.
	// This is the end-to-end deadline for the full provisioning saga.
	WorkflowTimeout time.Duration

	// ActivityTimeout is the maximum time a single provisioning step can take.
	// Each activity (CreateDatabase, RunMigrations, etc.) is bounded by this.
	ActivityTimeout time.Duration
}

// DefaultTemporalProvisioningConfig returns a TemporalProvisioningConfig populated
// with safe defaults. Temporal is disabled by default; all other values are set to
// sensible production-ready values that can be overridden by configuration.
func DefaultTemporalProvisioningConfig() TemporalProvisioningConfig {
	return TemporalProvisioningConfig{
		Enabled:         false,
		HostPort:        "temporal:7233",
		Namespace:       "hexxlock-provisioning",
		TaskQueue:       "provisioning-tasks",
		WorkflowTimeout: 30 * time.Minute,
		ActivityTimeout: 10 * time.Minute,
	}
}

// ProvisioningWorkflowInput is the serialisable input for a provisioning workflow.
// All fields are value types so the struct can be round-tripped through JSON
// without losing information.
type ProvisioningWorkflowInput struct {
	InstanceID uuid.UUID `json:"instance_id"`
	TenantID   uuid.UUID `json:"tenant_id"`
	ProductID  uuid.UUID `json:"product_id"`
	PlanID     string    `json:"plan_id"`
}

// ProvisioningWorkflowResult is the serialisable output of a provisioning workflow.
type ProvisioningWorkflowResult struct {
	InstanceID uuid.UUID     `json:"instance_id"`
	Status     string        `json:"status"`
	Error      string        `json:"error,omitempty"`
	Duration   time.Duration `json:"duration"`
}

// ProvisioningActivities defines Temporal activity implementations that map
// one-to-one to the steps in ProvisioningOrchestrator. Each activity is a
// thin wrapper that delegates to the orchestrator's existing step functions so
// the state-machine logic lives in exactly one place.
//
// Activity design notes:
//   - Activities are intentionally coarse-grained: each corresponds to one
//     provisioning step and advances the instance through exactly that step.
//   - The orchestrator's Reconcile method re-reads state from the database on
//     every call (level-triggered), so calling Reconcile after each activity
//     is idempotent and safe to retry.
//   - When Temporal is disabled, the reconciliation loop calls these same steps
//     directly via Reconcile, so no duplication of logic exists.
type ProvisioningActivities struct {
	orchestrator *ProvisioningOrchestrator
	logger       *zap.Logger
}

// NewProvisioningActivities creates a ProvisioningActivities that delegates
// to the given orchestrator. The orchestrator must not be nil.
func NewProvisioningActivities(orchestrator *ProvisioningOrchestrator, logger *zap.Logger) *ProvisioningActivities {
	if orchestrator == nil {
		panic("NewProvisioningActivities: orchestrator must not be nil")
	}
	if logger == nil {
		logger = zap.NewNop()
	}
	return &ProvisioningActivities{
		orchestrator: orchestrator,
		logger:       logger,
	}
}

// CreateDatabase is the Temporal activity for the "creating" provisioning step.
// It provisions database resources for the product instance based on the plan tier
// (silo / bridge / pool) and persists the connection details.
//
// The underlying implementation is ProvisioningOrchestrator.stepCreate.
// Because stepCreate reads state from the database and only acts when the instance
// is in the "pending" state, this activity is idempotent on retry.
func (a *ProvisioningActivities) CreateDatabase(ctx context.Context, input ProvisioningWorkflowInput) error {
	a.logger.Info("Temporal activity: CreateDatabase starting",
		zap.String("instance_id", input.InstanceID.String()),
		zap.String("tenant_id", input.TenantID.String()),
	)

	pi, err := a.orchestrator.instanceRepo.GetByID(ctx, input.InstanceID)
	if err != nil {
		return fmt.Errorf("CreateDatabase activity: get instance: %w", err)
	}

	if err := a.orchestrator.stepCreate(ctx, pi); err != nil {
		return fmt.Errorf("CreateDatabase activity: step failed: %w", err)
	}

	a.logger.Info("Temporal activity: CreateDatabase completed",
		zap.String("instance_id", input.InstanceID.String()),
	)
	return nil
}

// RunMigrations is the Temporal activity for the "migrating" provisioning step.
// It runs product-specific SQL migrations on the provisioned database using the
// migration source defined in the product capability manifest.
//
// The underlying implementation is ProvisioningOrchestrator.stepMigrate.
// If no migration source is configured, the step completes as a no-op.
func (a *ProvisioningActivities) RunMigrations(ctx context.Context, input ProvisioningWorkflowInput) error {
	a.logger.Info("Temporal activity: RunMigrations starting",
		zap.String("instance_id", input.InstanceID.String()),
	)

	pi, err := a.orchestrator.instanceRepo.GetByID(ctx, input.InstanceID)
	if err != nil {
		return fmt.Errorf("RunMigrations activity: get instance: %w", err)
	}

	if err := a.orchestrator.stepMigrate(ctx, pi); err != nil {
		return fmt.Errorf("RunMigrations activity: step failed: %w", err)
	}

	a.logger.Info("Temporal activity: RunMigrations completed",
		zap.String("instance_id", input.InstanceID.String()),
	)
	return nil
}

// SeedData is the Temporal activity for the "seeding" provisioning step.
// It inserts default tenant data into the provisioned database.
//
// The underlying implementation is ProvisioningOrchestrator.stepSeed.
// Currently a no-op pending product-specific seed script support.
func (a *ProvisioningActivities) SeedData(ctx context.Context, input ProvisioningWorkflowInput) error {
	a.logger.Info("Temporal activity: SeedData starting",
		zap.String("instance_id", input.InstanceID.String()),
	)

	pi, err := a.orchestrator.instanceRepo.GetByID(ctx, input.InstanceID)
	if err != nil {
		return fmt.Errorf("SeedData activity: get instance: %w", err)
	}

	if err := a.orchestrator.stepSeed(ctx, pi); err != nil {
		return fmt.Errorf("SeedData activity: step failed: %w", err)
	}

	a.logger.Info("Temporal activity: SeedData completed",
		zap.String("instance_id", input.InstanceID.String()),
	)
	return nil
}

// ConfigureAuth is the Temporal activity for the "configuring_auth" provisioning step.
// It writes SpiceDB authorization relationships for the product instance so that
// the tenant gains access to the provisioned product.
//
// The underlying implementation is ProvisioningOrchestrator.stepConfigureAuth.
// SpiceDB writes are idempotent so this activity is safe to retry.
func (a *ProvisioningActivities) ConfigureAuth(ctx context.Context, input ProvisioningWorkflowInput) error {
	a.logger.Info("Temporal activity: ConfigureAuth starting",
		zap.String("instance_id", input.InstanceID.String()),
	)

	pi, err := a.orchestrator.instanceRepo.GetByID(ctx, input.InstanceID)
	if err != nil {
		return fmt.Errorf("ConfigureAuth activity: get instance: %w", err)
	}

	if err := a.orchestrator.stepConfigureAuth(ctx, pi); err != nil {
		return fmt.Errorf("ConfigureAuth activity: step failed: %w", err)
	}

	a.logger.Info("Temporal activity: ConfigureAuth completed",
		zap.String("instance_id", input.InstanceID.String()),
	)
	return nil
}

// RegisterService is the Temporal activity for the "registering_service" provisioning step.
// It registers the product instance in the service registry and marks the instance as
// active, completing the provisioning saga.
//
// The underlying implementation is ProvisioningOrchestrator.stepRegisterService.
func (a *ProvisioningActivities) RegisterService(ctx context.Context, input ProvisioningWorkflowInput) error {
	a.logger.Info("Temporal activity: RegisterService starting",
		zap.String("instance_id", input.InstanceID.String()),
	)

	pi, err := a.orchestrator.instanceRepo.GetByID(ctx, input.InstanceID)
	if err != nil {
		return fmt.Errorf("RegisterService activity: get instance: %w", err)
	}

	if err := a.orchestrator.stepRegisterService(ctx, pi); err != nil {
		return fmt.Errorf("RegisterService activity: step failed: %w", err)
	}

	a.logger.Info("Temporal activity: RegisterService completed",
		zap.String("instance_id", input.InstanceID.String()),
	)
	return nil
}

// TemporalProvisioningClient is the interface the ProvisioningOrchestrator uses to
// dispatch workflows to Temporal. The interface is intentionally narrow so that:
//
//  1. The Temporal SDK is not imported anywhere in falcon-id until the concrete
//     implementation is wired up (when Temporal is actually deployed).
//  2. A NoopTemporalClient can stand in during development and testing without
//     any real Temporal infrastructure.
//  3. The interface can be satisfied by a fake in unit tests without the full SDK.
//
// Workflow IDs returned by StartProvisioningWorkflow and StartDeprovisioningWorkflow
// are opaque strings; callers should treat them as correlation IDs and pass them to
// GetWorkflowStatus for polling.
type TemporalProvisioningClient interface {
	// StartProvisioningWorkflow dispatches a new provisioning workflow to Temporal.
	// Returns the workflow execution ID that can be used with GetWorkflowStatus.
	StartProvisioningWorkflow(ctx context.Context, input ProvisioningWorkflowInput) (string, error)

	// StartDeprovisioningWorkflow dispatches a deprovisioning workflow for the
	// given instance. Returns the workflow execution ID.
	StartDeprovisioningWorkflow(ctx context.Context, instanceID uuid.UUID) (string, error)

	// GetWorkflowStatus returns the current execution status of a workflow run
	// (e.g., "RUNNING", "COMPLETED", "FAILED", "TIMED_OUT"). Returns an error if
	// the workflow cannot be queried.
	GetWorkflowStatus(ctx context.Context, workflowID string) (string, error)

	// Close releases any resources held by the client (connections, goroutines).
	// Must be called when the client is no longer needed.
	Close()
}

// NoopTemporalClient is the null-object implementation of TemporalProvisioningClient
// used when Temporal is disabled (the default). All mutating methods return a typed
// error so callers can detect the "not enabled" condition and fall back gracefully.
// GetWorkflowStatus returns ("unknown", error) consistently.
type NoopTemporalClient struct{}

// StartProvisioningWorkflow always returns an error because Temporal is not enabled.
func (n *NoopTemporalClient) StartProvisioningWorkflow(_ context.Context, _ ProvisioningWorkflowInput) (string, error) {
	return "", fmt.Errorf("temporal: not enabled — using reconciliation loop")
}

// StartDeprovisioningWorkflow always returns an error because Temporal is not enabled.
func (n *NoopTemporalClient) StartDeprovisioningWorkflow(_ context.Context, _ uuid.UUID) (string, error) {
	return "", fmt.Errorf("temporal: not enabled — using reconciliation loop")
}

// GetWorkflowStatus always returns ("unknown", error) because Temporal is not enabled.
func (n *NoopTemporalClient) GetWorkflowStatus(_ context.Context, _ string) (string, error) {
	return "unknown", fmt.Errorf("temporal: not enabled")
}

// Close is a no-op for the noop implementation.
func (n *NoopTemporalClient) Close() {}
