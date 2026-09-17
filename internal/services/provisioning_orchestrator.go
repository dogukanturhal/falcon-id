// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/pkg/database"
	"github.com/dogukanturhal/falcon-id/pkg/logger"
	"github.com/dogukanturhal/falcon-id/pkg/metrics"
)

// Advisory lock key for the provisioning reconciler leader election.
// Only one replica should run the reconciliation loop at a time.
const advisoryLockProvisioningReconciler int64 = 857491001

// ProvisioningOrchestratorConfig holds configuration for the orchestrator.
type ProvisioningOrchestratorConfig struct {
	// ReconcileInterval is how often the background loop checks for pending instances.
	ReconcileInterval time.Duration
	// MaxRetries is the number of times a failed step is retried before giving up.
	MaxRetries int
	// ProductMigrationsPath is the base directory for product migration SQL files.
	// Each product's migration_source maps to a subdirectory under this path.
	// Example: "/app/product-migrations" → migrations at "/app/product-migrations/crm/*.sql"
	// If empty, only the static ProductMigrationResolver registry is used.
	ProductMigrationsPath string
}

// orchestratorProductRepo defines the product repository methods.
type orchestratorProductRepo interface {
	GetByID(ctx context.Context, id uuid.UUID) (*models.Product, error)
}

// orchestratorSpiceDBClient defines the SpiceDB methods used by the orchestrator.
type orchestratorSpiceDBClient interface {
	WriteRelationship(ctx context.Context, resourceType, resourceID, relation, subjectType, subjectID string) error
	DeleteRelationship(ctx context.Context, resourceType, resourceID, relation, subjectType, subjectID string) error
}

// orchestratorRouteRegistrar is the narrow interface the orchestrator uses to
// register and remove APISIX routes for product instances.  The concrete
// implementation is RouteRegistrationService; tests can inject a fake.
type orchestratorRouteRegistrar interface {
	RegisterRoutes(ctx context.Context, instance *models.ProductInstance, product *models.Product) error
	DeregisterRoutes(ctx context.Context, instanceID uuid.UUID) error
}

// orchestratorDBGroupRepo defines the repository methods for product database groups.
type orchestratorDBGroupRepo interface {
	ListByProduct(ctx context.Context, productID uuid.UUID) ([]models.ProductDatabaseGroup, error)
}

// orchestratorInstanceDBRepo defines the repository methods for instance databases.
type orchestratorInstanceDBRepo interface {
	Create(ctx context.Context, idb *models.InstanceDatabase) error
	ListByInstance(ctx context.Context, instanceID uuid.UUID) ([]models.InstanceDatabase, error)
	UpdateStatus(ctx context.Context, id uuid.UUID, status string) error
	UpdateDatabaseInfo(ctx context.Context, id uuid.UUID, host, dbName, schema, username string, connEnc []byte) error
	SetActive(ctx context.Context, id uuid.UUID) error
	DeleteByInstance(ctx context.Context, instanceID uuid.UUID) error
}

// ProvisioningOrchestrator coordinates the multi-step provisioning saga for
// product instances.  It follows the Kubernetes operator reconciliation pattern:
// level-triggered (reads current state), idempotent, and self-healing.
//
// In multi-replica K8s deployments, the reconciliation loop uses a PostgreSQL
// advisory lock for leader election — only one replica processes instances at
// a time. When pool is nil (e.g., in tests), the lock is skipped.
//
// When temporalClient is non-nil and refers to a real Temporal implementation,
// new pending instances are dispatched to Temporal workflows instead of being
// processed locally. The local reconciliation loop remains active as a fallback:
// if Temporal dispatch fails, the instance is processed locally so provisioning
// never stalls. Set temporalClient via WithTemporalClient after construction.
type ProvisioningOrchestrator struct {
	instanceRepo      productInstanceRepo
	productRepo       orchestratorProductRepo
	dbProvisioner     *ProductDBProvisioner
	spiceDB           orchestratorSpiceDBClient
	routeService      orchestratorRouteRegistrar // nil means route registration is skipped
	migrationResolver *ProductMigrationResolver
	pool              *pgxpool.Pool // for advisory lock leader election; nil in tests
	config            ProvisioningOrchestratorConfig
	temporalClient    TemporalProvisioningClient // nil means local reconciliation only

	// Multi-DB support — nil means single-DB mode (backward compatible).
	dbGroupRepo    orchestratorDBGroupRepo
	instanceDBRepo orchestratorInstanceDBRepo

	notifier            ProvisioningLifecycleNotifier // nil means no notifications
	lifecycleDispatcher *LifecycleCallbackDispatcher  // nil means no product callbacks

	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// ProvisioningLifecycleNotifier records provisioning lifecycle events.
type ProvisioningLifecycleNotifier interface {
	NotifyActivated(ctx context.Context, instanceID, tenantID, productID uuid.UUID) error
	NotifyFailed(ctx context.Context, instanceID, tenantID, productID uuid.UUID, reason string) error
	NotifyDeleted(ctx context.Context, instanceID, tenantID, productID uuid.UUID) error
}

// NewProvisioningOrchestrator creates a new provisioning orchestrator.
// The pool parameter is used for advisory lock leader election in K8s
// multi-replica deployments. Pass nil in tests to skip locking.
func NewProvisioningOrchestrator(
	instanceRepo productInstanceRepo,
	productRepo orchestratorProductRepo,
	dbProvisioner *ProductDBProvisioner,
	spiceDB orchestratorSpiceDBClient,
	pool *pgxpool.Pool,
	config ProvisioningOrchestratorConfig,
) *ProvisioningOrchestrator {
	if config.ReconcileInterval == 0 {
		config.ReconcileInterval = 30 * time.Second
	}
	if config.MaxRetries == 0 {
		config.MaxRetries = 5
	}
	return &ProvisioningOrchestrator{
		instanceRepo:      instanceRepo,
		productRepo:       productRepo,
		dbProvisioner:     dbProvisioner,
		spiceDB:           spiceDB,
		pool:              pool,
		migrationResolver: NewProductMigrationResolver(config.ProductMigrationsPath),
		config:            config,
	}
}

// WithTemporalClient wires a Temporal client into the orchestrator.
// When the client is non-nil and Temporal dispatch succeeds, pending instances
// are handled by Temporal workflows rather than the local reconciliation loop.
// Passing nil removes a previously set client and falls back to local mode.
//
// This method is not goroutine-safe; call it before Start.
func (o *ProvisioningOrchestrator) WithTemporalClient(client TemporalProvisioningClient) *ProvisioningOrchestrator {
	o.temporalClient = client
	return o
}

// WithMultiDBSupport wires multi-database provisioning support into the orchestrator.
// When both repos are non-nil, the orchestrator provisions all databases defined
// in the product's database group instead of a single database.
// Passing nil disables multi-DB mode (backward compatible single-DB behavior).
//
// This method is not goroutine-safe; call it before Start.
func (o *ProvisioningOrchestrator) WithMultiDBSupport(
	dbGroupRepo orchestratorDBGroupRepo,
	instanceDBRepo orchestratorInstanceDBRepo,
) *ProvisioningOrchestrator {
	o.dbGroupRepo = dbGroupRepo
	o.instanceDBRepo = instanceDBRepo
	return o
}

// WithProvisioningNotifier wires a lifecycle notifier into the orchestrator.
// When non-nil, the orchestrator records events on activation, failure, and deletion.
func (o *ProvisioningOrchestrator) WithProvisioningNotifier(n ProvisioningLifecycleNotifier) *ProvisioningOrchestrator {
	o.notifier = n
	return o
}

// WithLifecycleCallbackDispatcher wires a product lifecycle callback dispatcher.
// When non-nil, the orchestrator dispatches callbacks to product-registered webhooks.
func (o *ProvisioningOrchestrator) WithLifecycleCallbackDispatcher(d *LifecycleCallbackDispatcher) *ProvisioningOrchestrator {
	o.lifecycleDispatcher = d
	return o
}

// WithRouteRegistrationService wires a RouteRegistrationService (or any
// orchestratorRouteRegistrar) into the orchestrator.  When non-nil, the
// stepRegisterService step will register APISIX routes for the product instance.
// Passing nil disables route registration (e.g. in tests that do not need it).
//
// This method is not goroutine-safe; call it before Start.
func (o *ProvisioningOrchestrator) WithRouteRegistrationService(svc orchestratorRouteRegistrar) *ProvisioningOrchestrator {
	o.routeService = svc
	return o
}

// Start begins the background reconciliation loop.
func (o *ProvisioningOrchestrator) Start(ctx context.Context) {
	ctx, o.cancel = context.WithCancel(ctx)
	o.wg.Add(1)
	go func() {
		defer o.wg.Done()
		ticker := time.NewTicker(o.config.ReconcileInterval)
		defer ticker.Stop()

		logger.Log.Info("Provisioning orchestrator started",
			zap.Duration("interval", o.config.ReconcileInterval),
		)

		for {
			select {
			case <-ctx.Done():
				logger.Log.Info("Provisioning orchestrator stopped")
				return
			case <-ticker.C:
				o.reconcileAll(ctx)
			}
		}
	}()
}

// Stop gracefully shuts down the orchestrator.
func (o *ProvisioningOrchestrator) Stop() {
	if o.cancel != nil {
		o.cancel()
	}
	o.wg.Wait()
}

// reconcileAll fetches all non-terminal instances and reconciles each one.
// In multi-replica deployments, it acquires a PostgreSQL advisory lock first
// so that only one replica runs the reconciliation loop at a time (leader election).
func (o *ProvisioningOrchestrator) reconcileAll(ctx context.Context) {
	// Acquire advisory lock for leader election (skip in tests where pool is nil).
	if o.pool != nil {
		conn, err := o.pool.Acquire(ctx)
		if err != nil {
			logger.Log.Error("Failed to acquire connection for reconciler lock", zap.Error(err))
			return
		}
		defer conn.Release()

		var acquired bool
		err = conn.QueryRow(ctx, "SELECT pg_try_advisory_lock($1)", advisoryLockProvisioningReconciler).Scan(&acquired)
		if err != nil {
			logger.Log.Error("Failed to try advisory lock", zap.Error(err))
			return
		}
		if !acquired {
			logger.Log.Debug("Another replica holds the provisioning reconciler lock — skipping this tick")
			return
		}
		defer func() {
			_, _ = conn.Exec(ctx, "SELECT pg_advisory_unlock($1)", advisoryLockProvisioningReconciler)
		}()
	}

	instances, err := o.instanceRepo.ListPending(ctx)
	if err != nil {
		logger.Log.Error("Failed to list pending instances", zap.Error(err))
		return
	}

	for i := range instances {
		if ctx.Err() != nil {
			return
		}
		if err := o.Reconcile(ctx, instances[i].ID); err != nil {
			logger.Log.Error("Reconcile failed for instance",
				zap.String("instance_id", instances[i].ID.String()),
				zap.Error(err),
			)
		}
	}
}

// Reconcile advances a single product instance through the provisioning saga.
// It reads the current state and determines the next action (level-triggered).
// Calling Reconcile multiple times is safe (idempotent).
func (o *ProvisioningOrchestrator) Reconcile(ctx context.Context, instanceID uuid.UUID) error {
	pi, err := o.instanceRepo.GetByID(ctx, instanceID)
	if err != nil {
		return fmt.Errorf("get instance: %w", err)
	}

	// Handle retryable failed instances: if the reconciler picked this up, it means
	// ListPending included it because next_retry_at <= NOW(). Transition back to pending.
	if pi.ProvisioningState == models.ProvisioningStateFailed && !pi.MaxRetriesExhausted && pi.NextRetryAt != nil {
		logger.Log.Info("Retrying failed instance",
			zap.String("instance_id", pi.ID.String()),
			zap.Int("retry_count", pi.RetryCount),
		)
		metrics.ProvisioningRetries.WithLabelValues(pi.ProductID.String()).Inc()
		if err := o.instanceRepo.ResetForRetry(ctx, pi.ID); err != nil {
			return fmt.Errorf("reset for retry: %w", err)
		}
		// Re-read the updated instance
		pi, err = o.instanceRepo.GetByID(ctx, instanceID)
		if err != nil {
			return fmt.Errorf("get instance after retry reset: %w", err)
		}
	}

	if pi.ProvisioningState.IsTerminal() {
		return nil
	}

	// If Temporal is enabled, dispatch pending instances to a workflow instead of
	// processing them locally. This is the dual-mode integration point: Temporal
	// handles new work while the reconciliation loop continues to act as a safety
	// net for in-progress or already-started instances.
	//
	// Only "pending" instances are dispatched — instances already mid-flight
	// (creating, migrating, seeding, …) continue through the local state machine
	// to avoid splitting a saga across two execution engines.
	if o.temporalClient != nil && pi.ProvisioningState == models.ProvisioningStatePending {
		input := ProvisioningWorkflowInput{
			InstanceID: pi.ID,
			TenantID:   pi.TenantID,
			ProductID:  pi.ProductID,
		}
		if pi.PlanID != nil {
			input.PlanID = *pi.PlanID
		}

		workflowID, err := o.temporalClient.StartProvisioningWorkflow(ctx, input)
		if err == nil {
			logger.Log.Info("Dispatched instance to Temporal workflow",
				zap.String("workflow_id", workflowID),
				zap.String("instance_id", pi.ID.String()),
				zap.String("tenant_id", pi.TenantID.String()),
			)
			return nil
		}
		// Temporal dispatch failed — fall through to local reconciliation so
		// provisioning is never blocked by Temporal unavailability.
		logger.Log.Warn("Temporal dispatch failed, falling back to local reconciliation",
			zap.String("instance_id", pi.ID.String()),
			zap.Error(err),
		)
	}

	// Handle deletion.
	if pi.ProvisioningState == models.ProvisioningStateDeleting {
		return o.handleDeletion(ctx, pi)
	}

	// Forward provisioning.
	// Each step transitions from its starting state to the next stable state.
	// stepCreate: pending → migrating (via creating)
	// stepMigrate: migrating → seeding
	// stepSeed: seeding → configuring_auth
	// stepConfigureAuth: configuring_auth → registering_service
	// stepRegisterService: registering_service → active
	// Resolve product slug for metric labels.
	productSlug := pi.ProductID.String()
	if product, err := o.productRepo.GetByID(ctx, pi.ProductID); err == nil {
		productSlug = product.Slug
	}

	runStep := func(stepName string, fn func() error) error {
		timer := metrics.NewProvisioningTimer(stepName, productSlug)
		if err := fn(); err != nil {
			timer.ObserveFailure("step_error")
			return err
		}
		timer.ObserveSuccess()
		return nil
	}

	switch pi.ProvisioningState {
	case models.ProvisioningStatePending:
		return runStep("creating", func() error { return o.stepCreate(ctx, pi) })
	case models.ProvisioningStateMigrating:
		return runStep("migrating", func() error { return o.stepMigrate(ctx, pi) })
	case models.ProvisioningStateSeeding:
		return runStep("seeding", func() error { return o.stepSeed(ctx, pi) })
	case models.ProvisioningStateConfiguringAuth:
		return runStep("configuring_auth", func() error { return o.stepConfigureAuth(ctx, pi) })
	case models.ProvisioningStateRegisteringService:
		return runStep("registering_service", func() error { return o.stepRegisterService(ctx, pi) })
	default:
		return fmt.Errorf("unexpected state: %s", pi.ProvisioningState)
	}
}

// reconcileUntilTerminalStepPause is the pause between successive Reconcile
// calls inside ReconcileUntilTerminal. It exists only to keep a step that
// happens to return near-instantly from turning the loop into a DB-hammering
// busy-loop — it is not standing in for the real wait, which is bounded by
// the caller's context deadline and by each step's own (real) work.
const reconcileUntilTerminalStepPause = 50 * time.Millisecond

// ReconcileUntilTerminal drives instanceID's provisioning saga forward by
// calling Reconcile repeatedly until it reaches a terminal state (active,
// failed, or deleted) or ctx is done, whichever comes first.
//
// Reconcile is level-triggered and advances at most ONE saga step per call
// (pending→creating→migrating→seeding→configuring_auth→registering_service→
// active) — the background reconciler loop (reconcileAll/Start) relies on
// exactly that to spread work across ticks. A caller that needs the full
// saga finished before proceeding — e.g. self-service signup minting a JWT
// immediately afterward, whose products[] claim is only correct once the
// instance is genuinely ACTIVE — must drive it to completion itself; calling
// Reconcile once and assuming it reached the end was the bug (t-582-adjacent
// signup/product_not_entitled incident, 2026-09-11).
//
// On ctx cancellation/timeout this returns ctx's error and leaves the
// instance in whatever intermediate, valid state it last reached — never a
// half-written step, since each step only persists after its own work
// completes. The background ticker keeps running independently of this call
// and will pick the instance back up and finish it later.
func (o *ProvisioningOrchestrator) ReconcileUntilTerminal(ctx context.Context, instanceID uuid.UUID) error {
	for {
		if err := o.Reconcile(ctx, instanceID); err != nil {
			return err
		}

		pi, err := o.instanceRepo.GetByID(ctx, instanceID)
		if err != nil {
			return fmt.Errorf("get instance: %w", err)
		}

		if pi.ProvisioningState.IsTerminal() {
			if pi.ProvisioningState == models.ProvisioningStateFailed {
				reason := ""
				if pi.FailureReason != nil {
					reason = *pi.FailureReason
				}
				return fmt.Errorf("provisioning failed: %s", reason)
			}
			return nil
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(reconcileUntilTerminalStepPause):
		}
	}
}

// stepCreate provisions the database resources.
func (o *ProvisioningOrchestrator) stepCreate(ctx context.Context, pi *models.ProductInstance) error {
	step := "creating"
	if err := o.instanceRepo.UpdateState(ctx, pi.ID, models.ProvisioningStateCreating, &step); err != nil {
		return err
	}

	product, err := o.productRepo.GetByID(ctx, pi.ProductID)
	if err != nil {
		return o.failInstance(ctx, pi.ID, fmt.Sprintf("product lookup failed: %v", err))
	}

	manifest, _ := product.ParseManifest()

	if o.dbProvisioner == nil {
		// No provisioner available — skip to pool mode (no DB to create).
		return o.instanceRepo.CompleteStep(ctx, pi.ID, "creating", models.ProvisioningStateMigrating)
	}

	// Determine isolation override from plan.
	isolationOverride := ""
	if pi.PlanID != nil {
		switch *pi.PlanID {
		case planEnterprise:
			isolationOverride = models.IsolationSilo
		case "professional":
			isolationOverride = models.IsolationBridge
		case "starter", "free":
			isolationOverride = models.IsolationPool
		}
	}

	// Multi-DB path: provision all databases in the product's database group.
	if o.dbGroupRepo != nil && o.instanceDBRepo != nil {
		groups, err := o.dbGroupRepo.ListByProduct(ctx, product.ID)
		if err != nil {
			return o.failInstance(ctx, pi.ID, fmt.Sprintf("list database groups: %v", err))
		}
		if len(groups) > 0 {
			return o.provisionMultiDB(ctx, pi, groups, manifest, isolationOverride)
		}
	}

	// Single-DB fallback: original behavior.
	result, err := o.dbProvisioner.ProvisionProductDatabase(ctx, pi.TenantID, product.Slug, manifest, isolationOverride)
	if err != nil {
		return o.failInstance(ctx, pi.ID, fmt.Sprintf("database provisioning failed: %v", err))
	}

	// Persist database connection details.
	if err := o.instanceRepo.UpdateDatabaseInfo(ctx, pi.ID,
		result.Host, result.DatabaseName, result.Schema, result.Username, result.ConnectionEnc,
	); err != nil {
		return o.failInstance(ctx, pi.ID, fmt.Sprintf("failed to store db info: %v", err))
	}

	return o.instanceRepo.CompleteStep(ctx, pi.ID, "creating", models.ProvisioningStateMigrating)
}

// provisionMultiDB provisions all databases in a product's database group and
// stores connection details on each InstanceDatabase record.
func (o *ProvisioningOrchestrator) provisionMultiDB(ctx context.Context, pi *models.ProductInstance, groups []models.ProductDatabaseGroup, manifest *models.ProductManifest, isolationOverride string) error {
	for i, group := range groups {
		idb := &models.InstanceDatabase{
			InstanceID:      pi.ID,
			DatabaseGroupID: group.ID,
			DatabaseName:    group.DatabaseName,
			IsolationMode:   isolationOverride,
			Status:          models.InstanceDBStatusCreating,
		}
		if idb.IsolationMode == "" {
			idb.IsolationMode = "pool"
		}
		if err := o.instanceDBRepo.Create(ctx, idb); err != nil {
			return o.failInstance(ctx, pi.ID, fmt.Sprintf("create instance db record for %s: %v", group.DatabaseName, err))
		}
		result, err := o.dbProvisioner.ProvisionProductDatabase(ctx, pi.TenantID, group.DatabaseName, manifest, isolationOverride)
		if err != nil {
			_ = o.instanceDBRepo.UpdateStatus(ctx, idb.ID, models.InstanceDBStatusFailed)
			return o.failInstance(ctx, pi.ID, fmt.Sprintf("provision %s failed: %v", group.DatabaseName, err))
		}
		if err := o.instanceDBRepo.UpdateDatabaseInfo(ctx, idb.ID,
			result.Host, result.DatabaseName, result.Schema, result.Username, result.ConnectionEnc,
		); err != nil {
			return o.failInstance(ctx, pi.ID, fmt.Sprintf("store db info for %s: %v", group.DatabaseName, err))
		}
		if err := o.instanceDBRepo.SetActive(ctx, idb.ID); err != nil {
			return o.failInstance(ctx, pi.ID, fmt.Sprintf("activate %s: %v", group.DatabaseName, err))
		}
		if i == 0 {
			if err := o.instanceRepo.UpdateDatabaseInfo(ctx, pi.ID,
				result.Host, result.DatabaseName, result.Schema, result.Username, result.ConnectionEnc,
			); err != nil {
				return o.failInstance(ctx, pi.ID, fmt.Sprintf("store primary db info: %v", err))
			}
		}
		logger.Log.Info("Database provisioned for instance",
			zap.String("instance_id", pi.ID.String()),
			zap.String("database", group.DatabaseName),
			zap.Int("index", i+1),
			zap.Int("total", len(groups)),
		)
	}
	return o.instanceRepo.CompleteStep(ctx, pi.ID, "creating", models.ProvisioningStateMigrating)
}

// stepMigrate runs product-specific migrations on the provisioned database.
// It reads the product manifest's migration_source and resolves it to an fs.FS
// via the ProductMigrationResolver. Resolution order:
//  1. Static registry (compile-time embedded FS or test overrides)
//  2. Filesystem discovery at <ProductMigrationsPath>/<migration_source>/
//
// If no migration source is configured or no migrations are found, the step
// is skipped gracefully.
//
// To add migrations for a new module: add SQL files to the product migrations
// directory and set migration_source in the product manifest. No Go code changes.
func (o *ProvisioningOrchestrator) stepMigrate(ctx context.Context, pi *models.ProductInstance) error {
	step := "migrating"
	if err := o.instanceRepo.UpdateState(ctx, pi.ID, models.ProvisioningStateMigrating, &step); err != nil {
		return err
	}

	product, err := o.productRepo.GetByID(ctx, pi.ProductID)
	if err != nil {
		return o.failInstance(ctx, pi.ID, fmt.Sprintf("product lookup for migration: %v", err))
	}

	manifest, _ := product.ParseManifest()

	// Multi-DB migration path: iterate over all instance databases and run
	// migrations using each group's migration_dir.
	if o.instanceDBRepo != nil && o.dbGroupRepo != nil {
		instanceDBs, err := o.instanceDBRepo.ListByInstance(ctx, pi.ID)
		if err != nil {
			return o.failInstance(ctx, pi.ID, fmt.Sprintf("list instance databases for migration: %v", err))
		}
		if len(instanceDBs) > 0 {
			return o.migrateMultiDB(ctx, pi, instanceDBs, manifest)
		}
	}

	// Single-DB fallback: run migrations when the manifest specifies a migration source,
	// a matching FS is found, and the instance has database info.
	if manifest != nil && manifest.Database != nil && manifest.Database.MigrationSource != "" {
		if err := o.runSingleDBMigration(ctx, pi, product, manifest.Database.MigrationSource); err != nil {
			return err
		}
	}

	logger.Log.Info("Migration step completed",
		zap.String("instance_id", pi.ID.String()),
	)

	return o.instanceRepo.CompleteStep(ctx, pi.ID, "migrating", models.ProvisioningStateSeeding)
}

// runSingleDBMigration resolves migSource and runs SQL migrations for a single-DB product instance.
func (o *ProvisioningOrchestrator) runSingleDBMigration(ctx context.Context, pi *models.ProductInstance, product *models.Product, migSource string) error {
	migFS, ok := o.migrationResolver.Resolve(migSource)
	if !ok {
		return o.failInstance(ctx, pi.ID, fmt.Sprintf(
			"migration source %q not found (base_path=%q); ensure migration SQL files exist",
			migSource, o.config.ProductMigrationsPath,
		))
	}
	if o.dbProvisioner == nil || pi.DatabaseHost == nil {
		return nil
	}
	pool, err := o.dbProvisioner.ConnectToInstanceDB(ctx, pi)
	if err != nil {
		return o.failInstance(ctx, pi.ID, fmt.Sprintf("connect for migration: %v", err))
	}
	defer pool.Close()

	migrator := database.NewMigrator(pool, migFS, logger.Log)
	if err := migrator.Run(ctx); err != nil {
		return o.failInstance(ctx, pi.ID, fmt.Sprintf("product migration failed: %v", err))
	}

	logger.Log.Info("Product migrations applied",
		zap.String("instance_id", pi.ID.String()),
		zap.String("product", product.Slug),
		zap.String("migration_source", migSource),
	)
	return nil
}

// migrateMultiDB runs migrations for each InstanceDatabase associated with a product instance.
func (o *ProvisioningOrchestrator) migrateMultiDB(ctx context.Context, pi *models.ProductInstance, instanceDBs []models.InstanceDatabase, manifest *models.ProductManifest) error {
	for _, idb := range instanceDBs {
		if idb.DatabaseHost == nil {
			continue
		}
		tmpPI := &models.ProductInstance{
			ID:             pi.ID,
			DatabaseHost:   idb.DatabaseHost,
			DatabaseName:   &idb.DatabaseName,
			DatabaseSchema: &idb.DatabaseSchema,
		}
		if idb.DatabaseUsername != nil {
			tmpPI.DatabaseUsername = idb.DatabaseUsername
		}
		migFS, ok := o.migrationResolver.Resolve(idb.DatabaseName)
		if !ok && manifest != nil && manifest.Database != nil && manifest.Database.MigrationSource != "" {
			migFS, ok = o.migrationResolver.Resolve(manifest.Database.MigrationSource)
		}
		if !ok {
			logger.Log.Debug("No migrations found for instance database",
				zap.String("database", idb.DatabaseName),
				zap.String("instance_id", pi.ID.String()),
			)
			continue
		}
		_ = o.instanceDBRepo.UpdateStatus(ctx, idb.ID, models.InstanceDBStatusMigrating)
		pool, err := o.dbProvisioner.ConnectToInstanceDB(ctx, tmpPI)
		if err != nil {
			_ = o.instanceDBRepo.UpdateStatus(ctx, idb.ID, models.InstanceDBStatusFailed)
			return o.failInstance(ctx, pi.ID, fmt.Sprintf("connect for migration %s: %v", idb.DatabaseName, err))
		}
		migrator := database.NewMigrator(pool, migFS, logger.Log)
		if err := migrator.Run(ctx); err != nil {
			pool.Close()
			_ = o.instanceDBRepo.UpdateStatus(ctx, idb.ID, models.InstanceDBStatusFailed)
			return o.failInstance(ctx, pi.ID, fmt.Sprintf("migration %s failed: %v", idb.DatabaseName, err))
		}
		pool.Close()
		_ = o.instanceDBRepo.SetActive(ctx, idb.ID)
		logger.Log.Info("Instance database migrated",
			zap.String("instance_id", pi.ID.String()),
			zap.String("database", idb.DatabaseName),
		)
	}
	logger.Log.Info("Multi-DB migration step completed",
		zap.String("instance_id", pi.ID.String()),
		zap.Int("database_count", len(instanceDBs)),
	)
	return o.instanceRepo.CompleteStep(ctx, pi.ID, "migrating", models.ProvisioningStateSeeding)
}

// stepSeed inserts default data into the provisioned database.
func (o *ProvisioningOrchestrator) stepSeed(ctx context.Context, pi *models.ProductInstance) error {
	step := "seeding"
	if err := o.instanceRepo.UpdateState(ctx, pi.ID, models.ProvisioningStateSeeding, &step); err != nil {
		return err
	}

	// TODO: In a full implementation, this would run seed scripts.
	// Product manifests could define a seed_source path.

	logger.Log.Info("Seeding step completed",
		zap.String("instance_id", pi.ID.String()),
	)

	return o.instanceRepo.CompleteStep(ctx, pi.ID, "seeding", models.ProvisioningStateConfiguringAuth)
}

// stepConfigureAuth writes SpiceDB relationships for product access.
func (o *ProvisioningOrchestrator) stepConfigureAuth(ctx context.Context, pi *models.ProductInstance) error {
	step := "configuring_auth"
	if err := o.instanceRepo.UpdateState(ctx, pi.ID, models.ProvisioningStateConfiguringAuth, &step); err != nil {
		return err
	}

	if o.spiceDB != nil {
		// Write: platform_product#subscribed_tenant@tenant
		if err := o.spiceDB.WriteRelationship(ctx,
			"platform_product", pi.ProductID.String(),
			"subscribed_tenant",
			"tenant", pi.TenantID.String(),
		); err != nil {
			return o.failInstance(ctx, pi.ID, fmt.Sprintf("SpiceDB write failed: %v", err))
		}

		// Write: platform_product_instance#tenant@tenant
		if err := o.spiceDB.WriteRelationship(ctx,
			"platform_product_instance", pi.ID.String(),
			"tenant",
			"tenant", pi.TenantID.String(),
		); err != nil {
			return o.failInstance(ctx, pi.ID, fmt.Sprintf("SpiceDB instance relationship failed: %v", err))
		}

		// Write: platform_product_instance#product@platform_product
		if err := o.spiceDB.WriteRelationship(ctx,
			"platform_product_instance", pi.ID.String(),
			"product",
			"platform_product", pi.ProductID.String(),
		); err != nil {
			return o.failInstance(ctx, pi.ID, fmt.Sprintf("SpiceDB product relationship failed: %v", err))
		}

		logger.Log.Info("SpiceDB relationships configured",
			zap.String("instance_id", pi.ID.String()),
		)
	}

	return o.instanceRepo.CompleteStep(ctx, pi.ID, "configuring_auth", models.ProvisioningStateRegisteringService)
}

// stepRegisterService registers the product's API endpoints with APISIX and
// activates the instance.  When routeService is nil the registration step is
// skipped gracefully — this allows the orchestrator to operate in environments
// without an APISIX Admin API (e.g. unit tests, air-gapped deployments).
func (o *ProvisioningOrchestrator) stepRegisterService(ctx context.Context, pi *models.ProductInstance) error {
	step := "registering_service"
	if err := o.instanceRepo.UpdateState(ctx, pi.ID, models.ProvisioningStateRegisteringService, &step); err != nil {
		return err
	}

	if o.routeService != nil {
		// Resolve the product so the route service can read the manifest.
		product, err := o.productRepo.GetByID(ctx, pi.ProductID)
		if err != nil {
			return o.failInstance(ctx, pi.ID, fmt.Sprintf("product lookup for route registration: %v", err))
		}

		if err := o.routeService.RegisterRoutes(ctx, pi, product); err != nil {
			return o.failInstance(ctx, pi.ID, fmt.Sprintf("APISIX route registration failed: %v", err))
		}

		logger.Log.Info("APISIX routes registered",
			zap.String("instance_id", pi.ID.String()),
			zap.String("product_slug", product.Slug),
		)
	} else {
		logger.Log.Debug("Route registration skipped (no route service configured)",
			zap.String("instance_id", pi.ID.String()),
		)
	}

	logger.Log.Info("Service registration step completed",
		zap.String("instance_id", pi.ID.String()),
	)

	// Complete the step and transition directly to active.
	if err := o.instanceRepo.CompleteStep(ctx, pi.ID, "registering_service", models.ProvisioningStateActive); err != nil {
		return err
	}

	if err := o.instanceRepo.SetActive(ctx, pi.ID); err != nil {
		return o.failInstance(ctx, pi.ID, fmt.Sprintf("activation failed: %v", err))
	}

	logger.Log.Info("Product instance activated",
		zap.String("instance_id", pi.ID.String()),
		zap.String("tenant_id", pi.TenantID.String()),
		zap.String("product_id", pi.ProductID.String()),
	)

	// Notify external services (outbox pattern)
	if o.notifier != nil {
		if err := o.notifier.NotifyActivated(ctx, pi.ID, pi.TenantID, pi.ProductID); err != nil {
			logger.Log.Warn("Failed to record provisioning activated event (non-fatal)",
				zap.String("instance_id", pi.ID.String()),
				zap.Error(err),
			)
		}
	}

	// Dispatch product lifecycle callback (best-effort)
	if o.lifecycleDispatcher != nil {
		if err := o.lifecycleDispatcher.Dispatch(ctx, pi.ProductID, pi.ID, pi.TenantID, "provisioning.activated", ""); err != nil {
			logger.Log.Warn("Lifecycle callback dispatch failed (non-fatal)",
				zap.String("instance_id", pi.ID.String()),
				zap.Error(err),
			)
		}
	}

	return nil
}

// handleDeletion performs the reverse saga to deprovision an instance.
func (o *ProvisioningOrchestrator) handleDeletion(ctx context.Context, pi *models.ProductInstance) error {
	// Step 1: Remove APISIX routes registered for this instance.
	if o.routeService != nil {
		if err := o.routeService.DeregisterRoutes(ctx, pi.ID); err != nil {
			logger.Log.Error("Failed to deregister APISIX routes",
				zap.String("instance_id", pi.ID.String()),
				zap.Error(err),
			)
			// Continue with deletion despite route cleanup failure — the routes
			// will eventually be garbage-collected by the APISIX reconciler.
		}
	}

	// Step 2: Revoke SpiceDB relationships.
	if o.spiceDB != nil {
		_ = o.spiceDB.DeleteRelationship(ctx,
			"platform_product_instance", pi.ID.String(),
			"product",
			"platform_product", pi.ProductID.String(),
		)
		_ = o.spiceDB.DeleteRelationship(ctx,
			"platform_product_instance", pi.ID.String(),
			"tenant",
			"tenant", pi.TenantID.String(),
		)
		_ = o.spiceDB.DeleteRelationship(ctx,
			"platform_product", pi.ProductID.String(),
			"subscribed_tenant",
			"tenant", pi.TenantID.String(),
		)
	}

	// Step 3a: Deprovision multi-DB instance databases.
	if o.instanceDBRepo != nil {
		instanceDBs, err := o.instanceDBRepo.ListByInstance(ctx, pi.ID)
		if err != nil {
			logger.Log.Error("Failed to list instance databases for deletion",
				zap.String("instance_id", pi.ID.String()),
				zap.Error(err),
			)
		} else if len(instanceDBs) > 0 {
			for _, idb := range instanceDBs {
				_ = o.instanceDBRepo.UpdateStatus(ctx, idb.ID, models.InstanceDBStatusDeleting)
			}
			// Clean up instance database records after deprovisioning.
			if err := o.instanceDBRepo.DeleteByInstance(ctx, pi.ID); err != nil {
				logger.Log.Error("Failed to delete instance database records",
					zap.String("instance_id", pi.ID.String()),
					zap.Error(err),
				)
			}
		}
	}

	// Step 3b: Deprovision database resources.
	// Resolve the product manifest so the provisioner can perform extension-specific
	// cleanup (e.g. citus_schema_undistribute) before DROP SCHEMA.
	if o.dbProvisioner != nil {
		var manifest *models.ProductManifest
		if product, err := o.productRepo.GetByID(ctx, pi.ProductID); err == nil {
			manifest, _ = product.ParseManifest()
		}

		if err := o.dbProvisioner.DeprovisionProductDatabase(ctx, pi, manifest); err != nil {
			logger.Log.Error("Failed to deprovision database",
				zap.String("instance_id", pi.ID.String()),
				zap.Error(err),
			)
			// Continue with deletion despite database cleanup failure.
		}
	}

	// Step 4: Notify external services.
	if o.notifier != nil {
		if err := o.notifier.NotifyDeleted(ctx, pi.ID, pi.TenantID, pi.ProductID); err != nil {
			logger.Log.Warn("Failed to record provisioning deleted event (non-fatal)",
				zap.String("instance_id", pi.ID.String()),
				zap.Error(err),
			)
		}
	}
	// Dispatch product lifecycle callback (best-effort)
	if o.lifecycleDispatcher != nil {
		if err := o.lifecycleDispatcher.Dispatch(ctx, pi.ProductID, pi.ID, pi.TenantID, "provisioning.deleted", ""); err != nil {
			logger.Log.Warn("Lifecycle callback dispatch failed (non-fatal)",
				zap.String("instance_id", pi.ID.String()),
				zap.Error(err),
			)
		}
	}

	// Step 5: Mark as deleted.
	return o.instanceRepo.SetDeleted(ctx, pi.ID)
}

// failInstance marks an instance as failed with automatic retry using exponential backoff.
// If the instance has exhausted its configured MaxRetries, it is permanently failed.
// Otherwise, the retry_count is incremented and next_retry_at is scheduled.
func (o *ProvisioningOrchestrator) failInstance(ctx context.Context, id uuid.UUID, reason string) error {
	// Read current state to get retry_count.
	pi, err := o.instanceRepo.GetByID(ctx, id)
	if err != nil {
		logger.Log.Error("Failed to read instance for retry check",
			zap.String("instance_id", id.String()),
			zap.Error(err),
		)
		return o.instanceRepo.SetFailed(ctx, id, reason)
	}

	newRetryCount := pi.RetryCount + 1
	if newRetryCount > o.config.MaxRetries {
		return o.permanentlyFailInstance(ctx, id, pi, reason)
	}

	return o.scheduleRetry(ctx, id, pi, newRetryCount, reason)
}

// permanentlyFailInstance marks the instance as permanently failed and notifies external services.
func (o *ProvisioningOrchestrator) permanentlyFailInstance(ctx context.Context, id uuid.UUID, pi *models.ProductInstance, reason string) error {
	logger.Log.Error("Product instance provisioning permanently failed (retries exhausted)",
		zap.String("instance_id", id.String()),
		zap.Int("retry_count", pi.RetryCount),
		zap.Int("max_retries", o.config.MaxRetries),
		zap.String("reason", reason),
	)
	if o.notifier != nil {
		if nErr := o.notifier.NotifyFailed(ctx, id, pi.TenantID, pi.ProductID, reason); nErr != nil {
			logger.Log.Warn("Failed to record provisioning failed event (non-fatal)",
				zap.String("instance_id", id.String()),
				zap.Error(nErr),
			)
		}
	}
	if o.lifecycleDispatcher != nil {
		if dErr := o.lifecycleDispatcher.Dispatch(ctx, pi.ProductID, id, pi.TenantID, "provisioning.failed", reason); dErr != nil {
			logger.Log.Warn("Lifecycle callback dispatch failed (non-fatal)",
				zap.String("instance_id", id.String()),
				zap.Error(dErr),
			)
		}
	}
	return o.instanceRepo.SetPermanentlyFailed(ctx, id, reason)
}

// scheduleRetry increments the retry count and schedules the next attempt with exponential backoff.
func (o *ProvisioningOrchestrator) scheduleRetry(ctx context.Context, id uuid.UUID, _ *models.ProductInstance, newRetryCount int, reason string) error {
	// Exponential backoff: 30s, 60s, 120s, 240s, 480s (capped at 10 min)
	backoff := time.Duration(30*(1<<(newRetryCount-1))) * time.Second
	if backoff > 10*time.Minute {
		backoff = 10 * time.Minute
	}
	nextRetry := time.Now().Add(backoff)

	logger.Log.Warn("Product instance provisioning failed, scheduling retry",
		zap.String("instance_id", id.String()),
		zap.Int("retry", newRetryCount),
		zap.Int("max_retries", o.config.MaxRetries),
		zap.Duration("backoff", backoff),
		zap.Time("next_retry_at", nextRetry),
		zap.String("reason", reason),
	)
	return o.instanceRepo.SetFailedWithRetry(ctx, id, reason, newRetryCount, nextRetry)
}
