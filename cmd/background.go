// SPDX-License-Identifier: AGPL-3.0-or-later

// Package main provides the entry point.
package main

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/middleware"
	svc "github.com/dogukanturhal/falcon-id/internal/services"
	"github.com/dogukanturhal/falcon-id/internal/shared/retention"
	"github.com/dogukanturhal/falcon-id/internal/tenantprojection"
	"github.com/dogukanturhal/falcon-id/pkg/config"
	"github.com/dogukanturhal/falcon-id/pkg/keys"
	"github.com/dogukanturhal/falcon-id/pkg/logger"
	sharedconfig "github.com/dogukanturhal/platform-shared/config"
	"github.com/prometheus/client_golang/prometheus"
	serviceauth "github.com/dogukanturhal/platform-shared/service-auth"
)

// BackgroundTasks holds all background task components.
type BackgroundTasks struct {
	RetentionScheduler   *retention.Scheduler
	KeyRotation          *keys.RotationScheduler
	GDPRConsumerCancel   context.CancelFunc
	BCLDrainerCancel     context.CancelFunc
	TenantProjectionStop func() // graceful shutdown hook for Phase 1a consumer
}

// startBackgroundTasks initializes and starts all background tasks.
func startBackgroundTasks(svcs *Services, repos *Repositories, infra *Infrastructure) *BackgroundTasks {
	// Initialize retention scheduler
	retentionScheduler := initRetentionScheduler(infra)

	// Start webhook delivery workers
	svcs.Webhook.Start()
	logger.Info("Webhook delivery workers started")

	// Start AD sync scheduler
	svcs.ADSync.StartScheduler(context.Background())
	logger.Info("AD sync scheduler started")

	// Start SAML metadata refresh scheduler
	if svcs.SAMLMetadata != nil {
		svcs.SAMLMetadata.StartRefreshScheduler(context.Background())
		logger.Info("SAML metadata refresh scheduler started")
	}

	// Start seat-quota reconciler scheduler (feat/seat-quota-reconciler).
	// Nil when outbound OAuth creds/QUOTA_SERVICE_URL are unset
	// (buildSeatQuotaReconcilerHTTPClient in cmd/services.go); StartScheduler
	// itself also no-ops when SEAT_QUOTA_RECONCILER_ENABLED=false.
	if svcs.SeatQuotaReconciler != nil {
		svcs.SeatQuotaReconciler.StartScheduler(context.Background())
		logger.Info("Seat-quota reconciler scheduler started")
	}

	if svcs.SpiceDBReconciler != nil {
		svcs.SpiceDBReconciler.StartScheduler(context.Background())
		logger.Info("SpiceDB reconciler scheduler started")
	}

	// Start config invalidation subscriber for per-tenant dynamic config
	if svcs.ConfigProvider != nil {
		svcs.ConfigProvider.StartInvalidationSubscriber(context.Background())
		logger.Info("Config invalidation subscriber started")
	}

	// Start GDPR deletion consumer (polls integration-bus for user.data_deletion_requested events).
	var gdprCancel context.CancelFunc
	if svcs.GDPRConsumer != nil {
		gdprCtx, cancel := context.WithCancel(context.Background())
		gdprCancel = cancel
		go svcs.GDPRConsumer.Start(gdprCtx)
		logger.Info("GDPR deletion consumer started")
	}

	// Start JWT signing key rotation scheduler. The KeyManager already
	// persists keys + secret-encrypts them at rest (AES-256-GCM); the
	// scheduler is what actually triggers KeyManager.Rotate() when an
	// active key crosses the 7-day-to-expiry threshold (see
	// pkg/keys/rotation.go:checkAndRotate). Without this goroutine
	// running, the active signing key remains valid until its TTL
	// expires — a leaked key has no operational kill-switch and the
	// graceful-rotation contract advertised on /.well-known/jwks.json
	// (active + retired keys served simultaneously for verifier
	// overlap) silently degrades.
	//
	// Check interval is 1 hour: rotation happens at most once a day in
	// steady state (90-day key lifetime → ~13 days warning window
	// after first cross of threshold), and 1h gives operators a
	// generous detection window for "did the rotation fire today".
	var keyRotation *keys.RotationScheduler
	if svcs.KeyManager != nil {
		keyRotation = keys.NewRotationScheduler(svcs.KeyManager, 1*time.Hour, logger.Log)
		keyRotation.Start(context.Background())
		logger.Info("JWT signing key rotation scheduler started",
			zap.Duration("check_interval", 1*time.Hour),
		)
	} else {
		logger.Warn("KeyManager not configured — JWT signing keys will not auto-rotate")
	}

	// Start the OIDC Back-Channel Logout transactional-outbox drainer
	// (Phase 2 of the 2026-05-10 SLO restoration). The drainer wakes
	// every 5s, takes a Postgres advisory lock to single-flight across
	// HA replicas, and attempts HTTP delivery on up to 50 pending rows
	// per tick with capped exponential backoff (1s/5s/30s/5m/30m,
	// 5 retries → status='dead'). All status transitions emit
	// iam_oauth_bcl_* metrics; pod-restart-safe by design.
	var bclDrainerCancel context.CancelFunc
	if repos != nil && repos.OAuthLogoutOutbox != nil {
		drainer := svc.NewBackchannelLogoutDrainer(
			repos.OAuthLogoutOutbox,
			svc.DefaultBackchannelLogoutDrainerConfig(),
			logger.Log,
		)
		drainerCtx, cancel := context.WithCancel(context.Background())
		bclDrainerCancel = cancel
		go drainer.Start(drainerCtx)
		logger.Info("BCL outbox drainer started",
			zap.Duration("tick_interval", 5*time.Second),
			zap.Int("batch_size", 50),
		)
	} else {
		logger.Warn("BCL outbox drainer not started: OAuthLogoutOutbox repo not wired")
	}

	tenantProjectionStop := startTenantProjection(infra)

	return &BackgroundTasks{
		RetentionScheduler:   retentionScheduler,
		KeyRotation:          keyRotation,
		GDPRConsumerCancel:   gdprCancel,
		BCLDrainerCancel:     bclDrainerCancel,
		TenantProjectionStop: tenantProjectionStop,
	}
}

// initRetentionScheduler initializes the shared retention scheduler for IAM service.
//
// Loads policies from the iam_data_retention_policies registry table
// (owner-coupled lifecycle pattern — see migration v0.232.250 + the
// 2026-05-20 orphan-iam_refresh_tokens incident notes). Falls back to
// the legacy IAMPolicies() Go slice when the registry table is empty
// or missing (graceful upgrade path: this binary can start before the
// creating migration has run).
//
// The fallback path emits a Warn so prolonged use is visible in logs —
// once the migration is shipped the registry is the source of truth
// and the fallback should never fire.
func initRetentionScheduler(infra *Infrastructure) *retention.Scheduler {
	ctx := context.Background()

	policies, loadErr := retention.LoadFromTable(ctx, infra.DB.Pool, "iam_data_retention_policies", logger.Log)
	source := "registry_table"
	switch {
	case loadErr != nil:
		// Database-level failure other than 42P01 (LoadFromTable
		// already swallows 42P01 with a Warn). Fall back to the
		// legacy slice so the scheduler still starts; logger.Error
		// makes the regression visible.
		logger.Error("retention registry load failed — falling back to legacy IAMPolicies() slice",
			zap.Error(loadErr),
		)
		policies = retention.IAMPolicies()
		source = "legacy_slice_due_to_db_error"
	case len(policies) == 0:
		// Registry exists + is empty, OR the table doesn't exist
		// yet (deploy ordering). Either way, fall back so the
		// scheduler isn't starved. Warn so the operator knows we're
		// not on the canonical path.
		logger.Warn("retention registry returned 0 policies — falling back to legacy IAMPolicies() slice",
			zap.String("hint", "ensure migration v0.232.250 has run; once shipped, the registry table is the canonical source"),
		)
		policies = retention.IAMPolicies()
		source = "legacy_slice_due_to_empty_registry"
	}

	scheduler, err := retention.NewScheduler(retention.Config{
		PgxPool:  infra.DB.Pool,
		Policies: policies,
		Interval: 5 * time.Minute,
		Logger:   logger.Log,
	})
	if err != nil {
		logger.Fatal("Failed to create retention scheduler", zap.Error(err))
	}

	if err := scheduler.Start(ctx); err != nil {
		logger.Fatal("Failed to start retention scheduler", zap.Error(err))
	}

	logger.Info("Retention scheduler initialized successfully",
		zap.Int("policies", len(policies)),
		zap.String("policy_source", source),
		zap.Duration("interval", 5*time.Minute))

	return scheduler
}

// Stop stops all background tasks gracefully.
func (bt *BackgroundTasks) Stop(svcs *Services) {
	// Stop the tenant projection consumer first so any in-flight UPDATE
	// completes before the DB pool is closed by infra.Close().
	if bt.TenantProjectionStop != nil {
		bt.TenantProjectionStop()
		logger.Info("Tenant projection consumer stopped")
	}

	// Stop BCL outbox drainer first so an in-flight drain tick has a
	// chance to release its advisory lock cleanly before the rest of
	// the shutdown cascade.
	if bt.BCLDrainerCancel != nil {
		bt.BCLDrainerCancel()
		logger.Info("BCL outbox drainer stopped")
	}

	// Stop GDPR deletion consumer
	if bt.GDPRConsumerCancel != nil {
		bt.GDPRConsumerCancel()
		logger.Info("GDPR deletion consumer stopped")
	}

	// Stop the provisioning orchestrator's reconciliation loop.
	if svcs.ProvisioningOrchestrator != nil {
		svcs.ProvisioningOrchestrator.Stop()
		logger.Info("Provisioning orchestrator stopped")
	}

	// Stop key rotation scheduler before retention so a key rotation
	// in flight at shutdown isn't interrupted by the retention worker
	// pruning rotated-key rows it might still be referring to.
	if bt.KeyRotation != nil {
		bt.KeyRotation.Stop()
		logger.Info("JWT signing key rotation scheduler stopped")
	}

	// Stop retention scheduler
	if bt.RetentionScheduler != nil {
		if err := bt.RetentionScheduler.Stop(); err != nil {
			logger.Error("Failed to stop retention scheduler", zap.Error(err))
		} else {
			logger.Info("Retention scheduler stopped")
		}
	}

	// Stop webhook workers
	svcs.Webhook.Stop()
	logger.Info("Webhook delivery workers stopped")

	// Stop AD sync scheduler
	svcs.ADSync.StopScheduler()
	logger.Info("AD sync scheduler stopped")

	// Stop SAML metadata refresh scheduler
	if svcs.SAMLMetadata != nil {
		svcs.SAMLMetadata.StopRefreshScheduler()
		logger.Info("SAML metadata refresh scheduler stopped")
	}

	// Stop seat-quota reconciler scheduler
	if svcs.SeatQuotaReconciler != nil {
		svcs.SeatQuotaReconciler.StopScheduler()
		logger.Info("Seat-quota reconciler scheduler stopped")
	}

	if svcs.SpiceDBReconciler != nil {
		svcs.SpiceDBReconciler.StopScheduler()
		logger.Info("SpiceDB reconciler scheduler stopped")
	}

	// Stop config invalidation subscriber
	if svcs.ConfigProvider != nil {
		svcs.ConfigProvider.StopInvalidationSubscriber()
		logger.Info("Config invalidation subscriber stopped")
	}

	// Stop middleware cleanup goroutines
	middleware.StopAuthRateLimitCleanup()
	logger.Info("Auth rate limit cleanup stopped")

	middleware.StopCSRFCleanup()
	logger.Info("CSRF rate limit cleanup stopped")
}

// startTenantProjection wires and starts the ADR 0029 Phase 1a reverse
// projection consumer. The consumer is gated by TENANT_PROJECTION_ENABLED
// (default true) so ops can disable it without a code change.
//
// Boot order:
//  1. Bootstrap.RunOnce — REST snapshot fills iam_tenants from tenant-management
//     before the Kafka consumer joins (closes the cold-start gap).
//  2. subscriber.Run  — durable consumer group joins and processes live events.
//
// Returns a stop function that callers invoke on shutdown.
func startTenantProjection(infra *Infrastructure) func() {
	cfg := infra.Config
	if !cfg.TenantProjectionEnabled {
		logger.Info("Tenant projection consumer disabled (TENANT_PROJECTION_ENABLED=false)")
		return func() {}
	}

	if infra.DB == nil || infra.DB.Pool == nil {
		logger.Warn("Tenant projection: DB pool unavailable, consumer not started")
		return func() {}
	}

	repo := tenantprojection.NewRepository(infra.DB.Pool)
	sugar := logger.Log.Sugar()
	metrics := tenantprojection.NewMetrics(prometheus.DefaultRegisterer, sugar)

	// Bootstrap: REST snapshot before Kafka consumer joins.
	// Use a bounded context (60 s) so a slow tenant-management start-up
	// doesn't block falcon-id indefinitely.
	//
	// HTTP client selection (ADR 0029 follow-up handoff G):
	//
	//   - When SERVICE_CLIENT_ID + SERVICE_CLIENT_SECRET are wired, use
	//     shared/service-auth.NewIAMHTTPClient to mint an OAuth2
	//     client_credentials token from falcon-id's own /oauth/token
	//     endpoint with `scope=platform:tenants:read`, then attach it
	//     as a Bearer on the bootstrap REST poll. This is the
	//     production path: tenant-management's /api/v1/internal/tenants
	//     is JWKS-gated and scope-checked.
	//
	//   - When credentials are absent (dev/test, fresh-initdb pre-
	//     bootstrap), fall back to http.DefaultClient and let the poll
	//     401 silently. The Kafka consumer will catch up live events;
	//     pre-existing tenants stay un-projected until the operator
	//     wires the ExternalSecret. Logging the gap.
	bootstrapURL := cfg.TenantManagementInternalURL
	bootstrapClient := buildTenantBootstrapClient(cfg, sugar)
	b := tenantprojection.NewBootstrap(bootstrapClient, bootstrapURL, repo, sugar)
	bootstrapCtx, bootstrapCancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer bootstrapCancel()

	n, err := b.RunOnce(bootstrapCtx)
	if err != nil {
		// Non-fatal: log and continue. The Kafka consumer will process
		// any events that arrived since the service last ran.
		logger.Warn("Tenant projection bootstrap failed, continuing without REST snapshot",
			zap.Error(err))
	} else {
		logger.Info("Tenant projection bootstrap complete",
			zap.Int("tenants_processed", n))
	}

	// Build Kafka subscriber.
	brokers := splitCSV(cfg.KafkaBrokers)
	saslCfg := sharedconfig.LoadKafkaSASLConfig()
	subCfg := tenantprojection.SubscriberConfig{
		Brokers:  brokers,
		GroupID:  tenantprojection.ConsumerGroup,
		SASLCfg:  saslCfg,
		DLQTopic: tenantprojection.DLQTopic,
	}
	sub := tenantprojection.NewTenantSubscriber(subCfg, repo, metrics, sugar)

	subCtx, subCancel := context.WithCancel(context.Background())
	go func() {
		if err := sub.Run(subCtx); err != nil {
			logger.Error("Tenant projection consumer exited unexpectedly", zap.Error(err))
		}
	}()
	logger.Info("Tenant projection consumer started",
		zap.Strings("brokers", brokers),
		zap.String("group", tenantprojection.ConsumerGroup),
		zap.Bool("enabled", true),
	)

	return func() {
		subCancel()
		sub.Stop()
	}
}

// buildTenantBootstrapClient returns the *http.Client used by the
// tenantprojection bootstrap REST poll. When SERVICE_CLIENT_ID +
// SERVICE_CLIENT_SECRET + IAM_SERVICE_URL are all set, the returned
// client transparently mints an OAuth2 client_credentials token from
// falcon-id's own /oauth/token endpoint with `scope=platform:tenants:read`
// and attaches it as a Bearer on every outbound request — the path
// tenant-management's /api/v1/internal/tenants chain expects.
//
// When any of the three are empty the function falls back to
// http.DefaultClient and logs a warning. This keeps fresh-initdb /
// dev-without-Vault paths working: the receiver will return 401 for
// the bootstrap poll but the Kafka consumer behind it still catches
// live tenant.* events.
//
// ADR 0029 follow-up handoff (G).
func buildTenantBootstrapClient(cfg *config.Config, log *zap.SugaredLogger) *http.Client {
	if cfg.ServiceClientID == "" || cfg.ServiceClientSecret == "" || cfg.IAMServiceURL == "" {
		log.Warnw("tenantprojection bootstrap: outbound OAuth creds missing, falling back to unauthenticated http.DefaultClient — REST poll WILL 401 against a scope-gated receiver",
			"have_client_id", cfg.ServiceClientID != "",
			"have_client_secret", cfg.ServiceClientSecret != "",
			"have_iam_url", cfg.IAMServiceURL != "",
		)
		return http.DefaultClient
	}
	iamHTTP, err := serviceauth.NewIAMHTTPClient(serviceauth.IAMHTTPClientConfig{
		IAMURL:       cfg.IAMServiceURL,
		ClientID:     cfg.ServiceClientID,
		ClientSecret: cfg.ServiceClientSecret,
		// Request both the legacy registration scope AND the new
		// projection scope. Falcon-ID's ClientCredentialsGrant filters
		// the requested set against the client's registered scopes, so
		// requesting service:register on a client that doesn't have it
		// is silently dropped (no error). svc-falcon-id is registered
		// with `service:register` + `platform:tenants:read` per the
		// the GitOps repository ServiceClientClaim, so both flow through.
		Scope: "service:register platform:tenants:read",
	})
	if errors.Is(err, serviceauth.ErrMissingCredentials) {
		// Shouldn't happen — we just checked above — but defensively
		// fall through with the unauthenticated client the helper
		// returns alongside the error.
		log.Warnw("tenantprojection bootstrap: ErrMissingCredentials after non-empty check (race?) — using unauthenticated client", "error", err)
		return iamHTTP
	}
	if err != nil {
		log.Errorw("tenantprojection bootstrap: NewIAMHTTPClient failed, falling back to unauthenticated http.DefaultClient", "error", err)
		return http.DefaultClient
	}
	log.Infow("tenantprojection bootstrap: OAuth-authenticated client wired",
		"iam_url", cfg.IAMServiceURL,
		"client_id", cfg.ServiceClientID,
		"scope", "service:register platform:tenants:read",
	)
	return iamHTTP
}

// splitCSV splits a comma-separated string into a trimmed slice, dropping empty
// entries. Used for KAFKA_BROKERS.
func splitCSV(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}
