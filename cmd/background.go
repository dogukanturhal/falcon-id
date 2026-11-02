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

	"github.com/dogukanturhal/falcon-id/internal/entitlementsync"
	"github.com/dogukanturhal/falcon-id/internal/middleware"
	svc "github.com/dogukanturhal/falcon-id/internal/services"
	"github.com/dogukanturhal/falcon-id/internal/shared/retention"
	"github.com/dogukanturhal/falcon-id/internal/signupgap"
	"github.com/dogukanturhal/falcon-id/internal/tenantprojection"
	"github.com/dogukanturhal/falcon-id/internal/opsaudit"
	"github.com/dogukanturhal/falcon-id/internal/tenantstatus"
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
	// EntitlementSyncStop stops the example.tenant.modules.sync consumer
	// (the product roadmap §4.1, internal/entitlementsync).
	EntitlementSyncStop func()

	// TenantStatusStop stops the example.tenant.status consumer
	// (R1-GAPS row 27, internal/tenantstatus).
	TenantStatusStop func()
	// OpsAuditStop stops the platform.ops-audit.v1 consumer (internal/opsaudit,
	// OPS_AUDIT_CONSUMER_ENABLED).
	OpsAuditStop func()
	// TenantPurgeStop stops the tenant purge saga participant
	// (internal/tenantpurge, TENANT_PURGE_PARTICIPANT_ENABLED).
	TenantPurgeStop func()
	// SignupGapReconcilerStop stops the signup-abandonment-recovery
	// reconcilers (reap + stall detection — see internal/signupgap).
	SignupGapReconcilerStop func()
	RoleRevokeDrainerStop   func()
	// JITExpirySweeperCancel stops the JIT access grant expiry sweeper.
	JITExpirySweeperCancel context.CancelFunc
	// OriginRegistryRefreshCancel stops the Stage 3 dynamic CORS/CSRF
	// origin registry's background refresh loop (svcs.OriginRegistry).
	OriginRegistryRefreshCancel context.CancelFunc
	// InvitationExpirySweeperCancel stops the team-invitation expiry sweep
	// (flips overdue pending iam_team_invitations to 'expired' and releases
	// their tenant_seat_counters.seats_pending reservations).
	InvitationExpirySweeperCancel context.CancelFunc
	// PlatformElevationSweeperCancel stops the R1 platform-plane JIT
	// elevation auto-revoke sweeper (svcs.PlatformJIT.RunExpirySweep).
	PlatformElevationSweeperCancel context.CancelFunc
	// PlatformBreakGlassSLASweeperCancel stops the R1 platform-plane
	// break-glass 24h retroactive-approval SLA sweeper
	// (svcs.PlatformJIT.RunBreakGlassSLASweep).
	PlatformBreakGlassSLASweeperCancel context.CancelFunc
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
	if svcs.EmployeeAccessExpiry != nil {
		svcs.EmployeeAccessExpiry.Start(context.Background())
	}

	if svcs.SeatQuotaReconciler != nil {
		svcs.SeatQuotaReconciler.StartScheduler(context.Background())
		logger.Info("Seat-quota reconciler scheduler started")
	}

	if svcs.SpiceDBReconciler != nil {
		svcs.SpiceDBReconciler.StartScheduler(context.Background())
		logger.Info("SpiceDB reconciler scheduler started")
	}

	if svcs.TenantAPIKey != nil {
		svcs.TenantAPIKey.StartCompanySyncWorker(context.Background(), 30*time.Second)
		logger.Info("Tenant API key company-sync worker started")
	}
	var roleRevokeDrainerStop func()
	if svcs.RoleRevokeDrainer != nil {
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		go func() { defer close(done); svcs.RoleRevokeDrainer.Start(ctx) }()
		roleRevokeDrainerStop = func() { cancel(); <-done }
		logger.Info("Durable SpiceDB role revoke drainer started", zap.Duration("poll_interval", time.Second))
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
	// Check interval is 5 minutes on every replica: KeyManager.Maintain
	// elects one rotator via a Postgres advisory lock, publishes the next
	// key as pending, and activates it after SIGNING_KEY_PUBLISH_DELAY, so
	// the interval bounds activation lateness. Replicas also reload keys
	// from the DB every SIGNING_KEY_RELOAD_INTERVAL.
	var keyRotation *keys.RotationScheduler
	if svcs.KeyManager != nil {
		keyRotation = keys.NewRotationScheduler(svcs.KeyManager, 5*time.Minute, logger.Log)
		keyRotation.Start(context.Background())
		logger.Info("JWT signing key rotation scheduler started",
			zap.Duration("check_interval", 5*time.Minute),
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

	tenantProjectionStop := startTenantProjection(infra, svcs)
	entitlementSyncStop := startEntitlementSync(infra, svcs)
	startModuleAccessReconcile(infra, svcs)
	startAcmeAppGrantSync(infra, svcs)
	tenantStatusStop := startTenantStatus(infra, svcs)
	opsAuditStop := startOpsAudit(infra)
	tenantPurgeStop := startTenantPurge(infra)
	signupGapReconcilerStop := startSignupGapReconciler(repos)
	jitExpirySweeperCancel := startJITExpirySweeper(svcs)
	if svcs.SoDReevaluator != nil {
		svcs.SoDReevaluator.Start(context.Background())
		logger.Info("SoD continuous re-evaluation started", zap.Duration("interval", svc.SoDReevaluationInterval))
	}
	invitationExpirySweeperCancel := startInvitationExpirySweeper(repos)
	platformElevationSweeperCancel := startPlatformElevationSweeper(svcs)
	platformBreakGlassSLASweeperCancel := startPlatformBreakGlassSLASweeper(svcs)

	// Stage 3: dynamic CORS/CSRF origin registry background refresh.
	// StartBackgroundRefresh is nil-safe (no-ops, starts no goroutine) when
	// svcs.OriginRegistry has no lister configured — see
	// buildTenantManagementOriginLister's fallback posture in
	// cmd/services.go. The initial synchronous refresh it performs is
	// itself bounded by the registry's configured timeout (10s — see
	// NewDynamicOriginRegistry's call site), so this never blocks startup
	// indefinitely.
	originRegistryCtx, originRegistryCancel := context.WithCancel(context.Background())
	svcs.OriginRegistry.StartBackgroundRefresh(originRegistryCtx)
	logger.Info("Dynamic CORS/CSRF origin registry background refresh started")

	return &BackgroundTasks{
		RetentionScheduler:                 retentionScheduler,
		KeyRotation:                        keyRotation,
		GDPRConsumerCancel:                 gdprCancel,
		BCLDrainerCancel:                   bclDrainerCancel,
		TenantProjectionStop:               tenantProjectionStop,
		EntitlementSyncStop:                entitlementSyncStop,
		TenantStatusStop:                   tenantStatusStop,
		OpsAuditStop:                       opsAuditStop,
		TenantPurgeStop:                    tenantPurgeStop,
		SignupGapReconcilerStop:            signupGapReconcilerStop,
		RoleRevokeDrainerStop:              roleRevokeDrainerStop,
		JITExpirySweeperCancel:             jitExpirySweeperCancel,
		OriginRegistryRefreshCancel:        originRegistryCancel,
		InvitationExpirySweeperCancel:      invitationExpirySweeperCancel,
		PlatformElevationSweeperCancel:     platformElevationSweeperCancel,
		PlatformBreakGlassSLASweeperCancel: platformBreakGlassSLASweeperCancel,
	}
}

// platformElevationSweepInterval controls how often
// PlatformJIT.RunExpirySweep runs. Same rationale as jitExpirySweepInterval
// above — bounds the over-grant window between an elevation's expires_at
// and its SpiceDB hxl_platform relationship actually being deleted. The
// active_elevation caveat already stops CheckPermission from honoring an
// expired grant even if this sweep is delayed; this loop exists to make
// the DB row status + the SpiceDB relationship converge to "revoked" /
// absent promptly, not to be the sole enforcement boundary.
const platformElevationSweepInterval = 30 * time.Second

// startPlatformElevationSweeper runs PlatformJITService.RunExpirySweep on a
// fixed interval, DB-driven and idempotent (see the service method's doc
// comment) — safe to run from every replica without coordination.
func startPlatformElevationSweeper(svcs *Services) context.CancelFunc {
	if svcs == nil || svcs.PlatformJIT == nil {
		logger.Warn("PlatformJITService not wired — platform elevation auto-revoke sweeper NOT started")
		return func() {}
	}

	ctx, cancel := context.WithCancel(context.Background())
	ticker := time.NewTicker(platformElevationSweepInterval)

	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				revoked, err := svcs.PlatformJIT.RunExpirySweep(ctx, 100)
				if err != nil {
					logger.Error("Platform elevation auto-revoke sweep encountered errors", zap.Error(err), zap.Int("revoked", revoked))
				} else if revoked > 0 {
					logger.Info("Platform elevation auto-revoke sweep completed", zap.Int("revoked", revoked))
				}
			}
		}
	}()

	logger.Info("Platform elevation auto-revoke sweeper started",
		zap.Duration("interval", platformElevationSweepInterval),
	)
	return cancel
}

// platformBreakGlassSLASweepInterval controls how often
// PlatformJIT.RunBreakGlassSLASweep runs. Checked far less often than the
// expiry sweeper above: the SLA window it enforces is 24h
// (models.BreakGlassRetroactiveApprovalSLA), so a 5-minute poll interval
// gives ample margin without hammering the DB.
const platformBreakGlassSLASweepInterval = 5 * time.Minute

// startPlatformBreakGlassSLASweeper runs
// PlatformJITService.RunBreakGlassSLASweep on a fixed interval. It flags
// (never auto-revokes) any break-glass activation whose 24h
// retroactive-approval SLA has lapsed with no approver — see the service
// method's doc comment for why flagging, not revocation, is correct here.
func startPlatformBreakGlassSLASweeper(svcs *Services) context.CancelFunc {
	if svcs == nil || svcs.PlatformJIT == nil {
		logger.Warn("PlatformJITService not wired — break-glass SLA sweeper NOT started")
		return func() {}
	}

	ctx, cancel := context.WithCancel(context.Background())
	ticker := time.NewTicker(platformBreakGlassSLASweepInterval)

	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				violations, err := svcs.PlatformJIT.RunBreakGlassSLASweep(ctx, 100)
				if err != nil {
					logger.Error("Break-glass SLA sweep encountered errors", zap.Error(err), zap.Int("violations", violations))
				} else if violations > 0 {
					logger.Error("PLATFORM BREAK-GLASS SLA VIOLATION(S) DETECTED — retroactive approval overdue", zap.Int("violations", violations))
				}
			}
		}
	}()

	logger.Info("Break-glass 24h retroactive-approval SLA sweeper started",
		zap.Duration("interval", platformBreakGlassSLASweepInterval),
	)
	return cancel
}

// jitExpirySweepInterval controls how often ExpireGrants runs. A JIT grant's
// worst-case over-grant window (time between expires_at and the SpiceDB
// relationship actually being deleted) is bounded by this interval, so it is
// deliberately short relative to the minimum grant duration (60s).
const jitExpirySweepInterval = 30 * time.Second

// startJITExpirySweeper runs JITAccessService.ExpireGrants on a fixed
// interval so that a grant's expires_at is actually enforced: without this
// loop, an expired grant's SpiceDB role#member relationship (the boundary
// AuthorizationEngine.CheckPermission consults) is never removed, and the
// elevation silently outlives its own expiry. Returns a cancel func for
// graceful shutdown; a nil JITAccess service (should not happen — wired
// unconditionally in cmd/services.go) is handled defensively by not
// starting the loop.
func startJITExpirySweeper(svcs *Services) context.CancelFunc {
	if svcs == nil || svcs.JITAccess == nil {
		logger.Warn("JIT access expiry sweeper not started: JITAccessService unavailable")
		return func() {}
	}

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		ticker := time.NewTicker(jitExpirySweepInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := svcs.JITAccess.ExpireGrants(ctx); err != nil {
					logger.Error("JIT access expiry sweep encountered errors", zap.Error(err))
				}
			}
		}
	}()
	logger.Info("JIT access expiry sweeper started",
		zap.Duration("interval", jitExpirySweepInterval),
	)
	return cancel
}

// invitationExpirySweepInterval controls how often overdue pending
// iam_team_invitations are flipped to 'expired' and their
// tenant_seat_counters.seats_pending reservations released. A 14-day
// invitation expiry does not need second-level precision, so this runs far
// less often than the JIT sweeper: an invitation sitting a few minutes past
// its own expires_at before the sweep catches it only delays freeing a
// pending seat by that long, and GetByTokenForUpdate/IsValid already refuse
// an expired-but-not-yet-swept token synchronously either way.
const invitationExpirySweepInterval = 5 * time.Minute

// startInvitationExpirySweeper runs
// TeamInvitationRepository.ExpirePendingAndReleaseSeats on a fixed interval
// (the product roadmap §4.1 "invitations ... expiry job";
// the product specification §13.2/§13.7). Without this loop, an
// expired invitation's seat reservation would hold seats_pending forever
// once its own status flip finally happens on next access (accept/list),
// permanently shrinking a tenant's effective seat_limit headroom for
// invitations nobody will ever accept.
func startInvitationExpirySweeper(repos *Repositories) context.CancelFunc {
	if repos == nil || repos.TeamInvitation == nil {
		logger.Warn("Team invitation expiry sweeper not started: TeamInvitationRepository unavailable")
		return func() {}
	}

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		ticker := time.NewTicker(invitationExpirySweepInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				counts, err := repos.TeamInvitation.ExpirePendingAndReleaseSeats(ctx)
				if err != nil {
					logger.Error("Team invitation expiry sweep encountered errors", zap.Error(err))
					continue
				}
				if len(counts) == 0 {
					continue
				}
				if repos.SeatCounter == nil {
					logger.Warn("Team invitation expiry sweep expired invitations but SeatCounterRepository is unavailable; pending reservations not released",
						zap.Int("tenants_affected", len(counts)))
					continue
				}
				if err := repos.SeatCounter.ReleaseReservationsBulk(ctx, counts); err != nil {
					logger.Error("Team invitation expiry sweep: failed to release seat reservations", zap.Error(err))
				}
			}
		}
	}()
	logger.Info("Team invitation expiry sweeper started",
		zap.Duration("interval", invitationExpirySweepInterval),
	)
	return cancel
}

// startSignupGapReconciler wires and starts the two signup-abandonment-
// recovery background workers (see internal/signupgap):
//   - a Reconciler that reaps expired, never-completed signup requests
//     (the genuinely-dead failure shape)
//   - a GapReconciler that counts currently-recoverable, stalled signup
//     requests (verified, not completed, not yet expired) and publishes
//     that count as a gauge for operator visibility
//
// Both are driven off repos.SignupRequest directly — no new repository
// construction needed, since *repositories.SignupRequestRepository
// already implements both signupgap.ExpiredSignupReaper (DeleteExpired,
// pre-existing) and signupgap.StallDetector (CountStalledSignups, added
// alongside this package).
//
// Returns a stop function callers invoke on shutdown.
func startSignupGapReconciler(repos *Repositories) func() {
	if repos == nil || repos.SignupRequest == nil {
		logger.Warn("Signup gap reconciler: SignupRequest repository unavailable, not started")
		return func() {}
	}

	reapMetrics := signupgap.NewMetrics(prometheus.DefaultRegisterer)
	reaper := signupgap.NewReconciler(repos.SignupRequest, reapMetrics, logger.Log.Sugar(), signupgap.Config{})
	reaper.Start(context.Background())
	logger.Info("Signup gap reap reconciler started")

	gapMetrics := signupgap.NewGapMetrics(prometheus.DefaultRegisterer)
	gapReconciler := signupgap.NewGapReconciler(repos.SignupRequest, gapMetrics, logger.Log.Sugar(), signupgap.GapConfig{})
	gapReconciler.Start(context.Background())
	logger.Info("Signup stall gap reconciler started")

	return func() {
		gapReconciler.Stop()
		reaper.Stop()
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

	if bt.TenantStatusStop != nil {
		bt.TenantStatusStop()
	}
	if bt.OpsAuditStop != nil {
		bt.OpsAuditStop()
	}
	if bt.TenantPurgeStop != nil {
		bt.TenantPurgeStop()
	}
	if bt.EntitlementSyncStop != nil {
		bt.EntitlementSyncStop()
		logger.Info("Entitlement sync consumer stopped")
	}

	if bt.SignupGapReconcilerStop != nil {
		bt.SignupGapReconcilerStop()
		logger.Info("Signup gap reconcilers stopped")
	}
	if bt.RoleRevokeDrainerStop != nil {
		bt.RoleRevokeDrainerStop()
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

	if svcs != nil && svcs.SoDReevaluator != nil {
		svcs.SoDReevaluator.Stop()
		logger.Info("SoD re-evaluation stopped")
	}

	// Stop JIT access expiry sweeper.
	if bt.JITExpirySweeperCancel != nil {
		bt.JITExpirySweeperCancel()
		logger.Info("JIT access expiry sweeper stopped")
	}

	// Stop platform-plane JIT elevation auto-revoke + break-glass SLA
	// sweepers.
	if bt.PlatformElevationSweeperCancel != nil {
		bt.PlatformElevationSweeperCancel()
		logger.Info("Platform elevation auto-revoke sweeper stopped")
	}
	if bt.PlatformBreakGlassSLASweeperCancel != nil {
		bt.PlatformBreakGlassSLASweeperCancel()
		logger.Info("Break-glass SLA sweeper stopped")
	}

	// Stop the dynamic CORS/CSRF origin registry's background refresh.
	if bt.OriginRegistryRefreshCancel != nil {
		bt.OriginRegistryRefreshCancel()
		logger.Info("Dynamic CORS/CSRF origin registry background refresh stopped")
	}

	// Stop the team-invitation expiry sweeper.
	if bt.InvitationExpirySweeperCancel != nil {
		bt.InvitationExpirySweeperCancel()
		logger.Info("Team invitation expiry sweeper stopped")
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
	if svcs.EmployeeAccessExpiry != nil {
		svcs.EmployeeAccessExpiry.Stop()
	}

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
func startTenantProjection(infra *Infrastructure, svcs *Services) func() {
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
	if svcs != nil && svcs.SignupTrialProvisioner != nil {
		b.SetTrialReadyHook(svcs.SignupTrialProvisioner.EnsureTrialProduct)
	}
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
	if svcs != nil && svcs.SignupTrialProvisioner != nil {
		sub.SetTrialReadyHook(svcs.SignupTrialProvisioner.EnsureTrialProduct)
	}

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

// startModuleAccessReconcile runs the module-access reconcile once, shortly
// after startup, so tenants whose entitlements predate the provisioner get
// their module roles and owner grants without an operator step. Every replica
// runs it; EnsureModuleAccess serializes per tenant with an advisory lock and
// is idempotent. Disable with MODULE_ACCESS_RECONCILE_ON_STARTUP=false.
func startModuleAccessReconcile(infra *Infrastructure, svcs *Services) {
	if !infra.Config.ModuleAccessReconcileOnStartup {
		logger.Info("Module access startup reconcile disabled (MODULE_ACCESS_RECONCILE_ON_STARTUP=false)")
		return
	}
	if svcs == nil || svcs.ModuleAccess == nil {
		return
	}
	go func() {
		defer func() {
			if r := recover(); r != nil {
				logger.Error("Module access startup reconcile panicked", zap.Any("panic", r))
			}
		}()
		time.Sleep(60 * time.Second)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()
		sum, err := svcs.ModuleAccess.ReconcileAll(ctx)
		if err != nil {
			logger.Warn("Module access startup reconcile failed", zap.Error(err))
			return
		}
		logger.Info("Module access startup reconcile finished",
			zap.Int("tenants", sum.Tenants),
			zap.Int("roles_provisioned", sum.RolesProvisioned),
			zap.Int("grants_made", sum.GrantsMade),
			zap.Int("failed", sum.Failed),
		)
	}()
}

// startAcmeAppGrantSync tops up catalog permission grants on every tenant's
// existing AcmeApp system roles once, shortly after startup (new catalog
// permissions such as core:settings:* otherwise never reach existing tenants,
// since provisioning skips tenants that already have the owner role). Additive
// and idempotent (DO NOTHING rows + SpiceDB TOUCH), safe on every replica.
// Disable with ACMEAPP_GRANT_SYNC_ON_STARTUP=false.
func startAcmeAppGrantSync(infra *Infrastructure, svcs *Services) {
	if !infra.Config.AcmeAppGrantSyncOnStartup {
		logger.Info("AcmeApp grant sync disabled (ACMEAPP_GRANT_SYNC_ON_STARTUP=false)")
		return
	}
	if svcs == nil || svcs.AcmeAppRoleProvisioner == nil {
		return
	}
	go func() {
		defer func() {
			if r := recover(); r != nil {
				logger.Error("AcmeApp grant sync panicked", zap.Any("panic", r))
			}
		}()
		time.Sleep(90 * time.Second)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()
		sum, err := svcs.AcmeAppRoleProvisioner.ReconcileAllTenantRolePermissions(ctx)
		if err != nil {
			logger.Warn("AcmeApp grant sync failed", zap.Error(err))
			return
		}
		logger.Info("AcmeApp grant sync finished",
			zap.Int("tenants", sum.Tenants),
			zap.Int("failed", sum.Failed),
		)
	}()
}

// startEntitlementSync wires and starts the example.tenant.modules.sync
// consumer (internal/entitlementsync, the product roadmap §4.1). Unlike
// startTenantProjection, there is no REST bootstrap snapshot phase: the
// entitlements table has no separate "authoritative REST source" to
// cold-start from (tenant-management's mirror IS the snapshot producer),
// so a fresh consumer simply reads from the earliest retained Kafka
// offset it hasn't committed yet, or waits for the next periodic full
// resync tenant-management publishes.
func startEntitlementSync(infra *Infrastructure, svcs *Services) func() {
	cfg := infra.Config
	if !cfg.EntitlementSyncEnabled {
		logger.Info("Entitlement sync consumer disabled (ENTITLEMENT_SYNC_ENABLED=false)")
		return func() {}
	}

	if svcs == nil || svcs.Entitlement == nil {
		logger.Warn("Entitlement sync: TenantEntitlementService unavailable, consumer not started")
		return func() {}
	}

	sugar := logger.Log.Sugar()
	metrics := entitlementsync.NewMetrics(prometheus.DefaultRegisterer, sugar)

	brokers := splitCSV(cfg.KafkaBrokers)
	saslCfg := sharedconfig.LoadKafkaSASLConfig()
	subCfg := entitlementsync.SubscriberConfig{
		Brokers:  brokers,
		GroupID:  entitlementsync.ConsumerGroup,
		SASLCfg:  saslCfg,
		DLQTopic: entitlementsync.DLQTopic,
	}
	sub := entitlementsync.NewSubscriber(subCfg, svcs.Entitlement, metrics, sugar)

	subCtx, subCancel := context.WithCancel(context.Background())
	go func() {
		if err := sub.Run(subCtx); err != nil {
			logger.Error("Entitlement sync consumer exited unexpectedly", zap.Error(err))
		}
	}()
	logger.Info("Entitlement sync consumer started",
		zap.Strings("brokers", brokers),
		zap.String("group", entitlementsync.ConsumerGroup),
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

// startTenantStatus wires and starts the example.tenant.status consumer
// (internal/tenantstatus, R1-GAPS row 27). It persists tenant suspension state
// and revokes the tenant's sessions + OAuth tokens on suspend. Like
// startEntitlementSync there is no REST bootstrap: the consumer group starts at
// the earliest retained offset and the gate fails open until state arrives.
func startTenantStatus(infra *Infrastructure, svcs *Services) func() {
	cfg := infra.Config
	if !cfg.TenantStatusEnabled {
		logger.Info("Tenant status consumer disabled (TENANT_STATUS_ENABLED=false)")
		return func() {}
	}
	if svcs == nil || svcs.TenantStatusRepo == nil {
		logger.Warn("Tenant status: repository unavailable, consumer not started")
		return func() {}
	}
	sugar := logger.Log.Sugar()
	metrics := tenantstatus.NewMetrics(prometheus.DefaultRegisterer, sugar)
	brokers := splitCSV(cfg.KafkaBrokers)
	consumer := tenantstatus.NewConsumer(svcs.TenantStatusRepo, svcs.TenantStatusGate, metrics, sugar)
	sub := tenantstatus.NewSubscriber(tenantstatus.SubscriberConfig{
		Brokers:  brokers,
		GroupID:  tenantstatus.ConsumerGroup,
		SASLCfg:  sharedconfig.LoadKafkaSASLConfig(),
		DLQTopic: tenantstatus.DLQTopic,
	}, consumer, metrics, sugar)
	subCtx, subCancel := context.WithCancel(context.Background())
	go func() {
		if err := sub.Run(subCtx); err != nil {
			logger.Error("Tenant status consumer exited unexpectedly", zap.Error(err))
		}
	}()
	logger.Info("Tenant status consumer started",
		zap.Strings("brokers", brokers),
		zap.String("group", tenantstatus.ConsumerGroup),
	)
	return func() {
		subCancel()
		sub.Stop()
	}
}

// startOpsAudit starts the platform.ops-audit.v1 consumer that appends
// operator audit events to platform_admin_audit_log (internal/opsaudit,
// migration 0035). OFF by default (OPS_AUDIT_CONSUMER_ENABLED=false): the
// table's new columns, event_id index and INSERT-only trigger must be applied
// first (Keystone bundle falcon-id v0.232.289). A no-op when KAFKA_BROKERS is
// empty.
func startOpsAudit(infra *Infrastructure) func() {
	cfg := infra.Config
	if !cfg.OpsAuditConsumerEnabled {
		return func() {}
	}
	if infra.DB == nil || infra.DB.Pool == nil {
		logger.Warn("Ops audit consumer: database unavailable, not started")
		return func() {}
	}
	sugar := logger.Log.Sugar()
	brokers := splitCSV(cfg.KafkaBrokers)
	sub := opsaudit.NewSubscriber(opsaudit.SubscriberConfig{
		Brokers: brokers,
		GroupID: opsaudit.ConsumerGroup,
		SASLCfg: sharedconfig.LoadKafkaSASLConfig(),
	}, opsaudit.NewConsumer(infra.DB.Pool), sugar)
	subCtx, subCancel := context.WithCancel(context.Background())
	go func() {
		if err := sub.Run(subCtx); err != nil {
			logger.Error("Ops audit consumer exited unexpectedly", zap.Error(err))
		}
	}()
	logger.Info("Ops audit consumer started",
		zap.Strings("brokers", brokers),
		zap.String("topic", opsaudit.Topic),
		zap.String("group", opsaudit.ConsumerGroup),
	)
	return func() {
		subCancel()
		sub.Stop()
	}
}
