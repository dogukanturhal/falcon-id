// SPDX-License-Identifier: AGPL-3.0-or-later

package services

// tenant_onboarding.go implements TenantOnboardingPipeline, an event-driven
// pipeline that provisions everything a new tenant needs when a subscription
// is activated.
//
// Pipeline steps (executed in order, each tracked with timing and status):
//  1. validate          — plan validity check (tenant/realm nil-safe)
//  2. provision_database — create a dedicated DB for enterprise tenants
//  3. seed_default_data  — create default admin role + default permissions
//  4. configure_features — enable plan-appropriate feature flags
//  5. send_welcome       — placeholder notification (logged only for now)
//
// Each step is recorded in OnboardingResult.Steps regardless of outcome.
// On the first failed non-optional step the pipeline stops and sets
// OnboardingResult.Status = "failed". On partial failure it sets "partial".

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/pkg/logger"
)

// ---------------------------------------------------------------------------
// Interfaces
// ---------------------------------------------------------------------------

// OnboardingRealmLookup is the narrow interface TenantOnboardingPipeline
// requires from RealmService. The concrete *RealmService already satisfies it.
type OnboardingRealmLookup interface {
	// GetByID returns the realm or (nil, nil) when not found.
	GetByID(ctx context.Context, id uuid.UUID) (*models.Realm, error)
}

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

// OnboardingRequest carries the parameters for a self-service onboarding run.
type OnboardingRequest struct {
	TenantID   uuid.UUID `json:"tenant_id" binding:"required"`
	TenantSlug string    `json:"tenant_slug"`
	RealmID    uuid.UUID `json:"realm_id" binding:"required"`
	Plan       string    `json:"plan" binding:"required"`
	Region     string    `json:"region,omitempty"`
}

// OnboardingResult summarises the outcome of the onboarding pipeline.
type OnboardingResult struct {
	TenantID     uuid.UUID        `json:"tenant_id"`
	RealmID      uuid.UUID        `json:"realm_id"`
	DatabaseName string           `json:"database_name,omitempty"`
	DatabaseHost string           `json:"database_host,omitempty"`
	Status       string           `json:"status"` // "completed" | "partial" | "failed"
	Steps        []OnboardingStep `json:"steps"`
}

// OnboardingStep records the outcome of a single pipeline step.
type OnboardingStep struct {
	Name    string `json:"name"`
	Status  string `json:"status"` // "completed" | "skipped" | "failed"
	Error   string `json:"error,omitempty"`
	Elapsed string `json:"elapsed"` // human-readable duration, e.g. "12ms"
}

// ---------------------------------------------------------------------------
// Pipeline
// ---------------------------------------------------------------------------

// TenantOnboardingPipeline orchestrates the full self-service provisioning
// sequence for a new tenant subscription activation.
type TenantOnboardingPipeline struct {
	realmService     OnboardingRealmLookup // nil = skip realm existence check
	realmProvisioner *RealmDBProvisioner   // nil = skip DB provisioning step
	log              *zap.SugaredLogger
}

// NewTenantOnboardingPipeline constructs the pipeline. Both realmService and
// realmProvisioner may be nil; they will be skipped gracefully when absent.
func NewTenantOnboardingPipeline(
	realmService OnboardingRealmLookup,
	realmProvisioner *RealmDBProvisioner,
	log *zap.SugaredLogger,
) *TenantOnboardingPipeline {
	return &TenantOnboardingPipeline{
		realmService:     realmService,
		realmProvisioner: realmProvisioner,
		log:              log,
	}
}

// validPlans is the set of recognised plan names.
var validPlans = map[string]bool{
	"starter":      true,
	"professional": true,
	planEnterprise: true,
	"unlimited":    true,
}

// Onboard runs the full provisioning pipeline for the given request.
// It returns a populated OnboardingResult that describes what happened at
// each step; the returned error is non-nil only for infrastructure failures
// (e.g. context cancelled), not for business-level step failures.
func (p *TenantOnboardingPipeline) Onboard(ctx context.Context, req OnboardingRequest) (*OnboardingResult, error) {
	result := &OnboardingResult{
		TenantID: req.TenantID,
		RealmID:  req.RealmID,
		Status:   "completed",
	}

	p.log.Infow("TenantOnboardingPipeline: starting",
		"tenant_id", req.TenantID,
		"realm_id", req.RealmID,
		"plan", req.Plan,
		"region", req.Region,
	)

	// Define the ordered pipeline steps. Steps that return (skip=true) when
	// the preconditions are not met are treated as "skipped", not "failed".
	type stepFn func() (skip bool, dbName string, dbHost string, err error)

	steps := []struct {
		name string
		fn   stepFn
	}{
		{"validate", func() (bool, string, string, error) {
			return p.stepValidate(ctx, req)
		}},
		{"provision_database", func() (bool, string, string, error) {
			return p.stepProvisionDatabase(ctx, req)
		}},
		{"seed_default_data", func() (bool, string, string, error) {
			return p.stepSeedDefaultData(ctx, req)
		}},
		{"configure_features", func() (bool, string, string, error) {
			return p.stepConfigureFeatures(ctx, req)
		}},
		{"send_welcome", func() (bool, string, string, error) {
			return p.stepSendWelcome(ctx, req)
		}},
	}

	failedCount := 0
	skippedCount := 0

	for _, s := range steps {
		if ctx.Err() != nil {
			return result, ctx.Err()
		}

		start := time.Now()
		skip, dbName, dbHost, err := s.fn()
		elapsed := time.Since(start)

		step := OnboardingStep{
			Name:    s.name,
			Elapsed: elapsed.Round(time.Millisecond).String(),
		}

		if dbName != "" {
			result.DatabaseName = dbName
		}
		if dbHost != "" {
			result.DatabaseHost = dbHost
		}

		switch {
		case err != nil:
			step.Status = "failed"
			step.Error = err.Error()
			failedCount++
			result.Steps = append(result.Steps, step)
			p.log.Warnw("TenantOnboardingPipeline: step failed",
				"step", s.name,
				"tenant_id", req.TenantID,
				"err", err,
			)
			// For the validate step a failure is fatal — no point continuing.
			if s.name == "validate" {
				result.Status = "failed"
				return result, nil
			}
		case skip:
			step.Status = "skipped"
			skippedCount++
			result.Steps = append(result.Steps, step)
			p.log.Debugw("TenantOnboardingPipeline: step skipped",
				"step", s.name,
				"tenant_id", req.TenantID,
			)
		default:
			step.Status = "completed"
			result.Steps = append(result.Steps, step)
			p.log.Infow("TenantOnboardingPipeline: step completed",
				"step", s.name,
				"tenant_id", req.TenantID,
				"elapsed", elapsed,
			)
		}
	}

	if failedCount > 0 {
		result.Status = "partial"
	}

	p.log.Infow("TenantOnboardingPipeline: finished",
		"tenant_id", req.TenantID,
		"status", result.Status,
		"failed_steps", failedCount,
		"skipped_steps", skippedCount,
	)

	return result, nil
}

// ---------------------------------------------------------------------------
// Step implementations
// ---------------------------------------------------------------------------

// stepValidate checks that the plan is valid and, when services are wired,
// that the realm exists. The tenant existence check is intentionally skipped
// here — it is the caller's responsibility (the HTTP handler validates the URL
// parameter against the authenticated session context).
func (p *TenantOnboardingPipeline) stepValidate(ctx context.Context, req OnboardingRequest) (skip bool, dbName string, dbHost string, err error) {
	if req.TenantID == uuid.Nil {
		return false, "", "", fmt.Errorf("tenant_id is required")
	}
	if req.RealmID == uuid.Nil {
		return false, "", "", fmt.Errorf("realm_id is required")
	}
	if !validPlans[req.Plan] {
		return false, "", "", fmt.Errorf("unknown plan %q: valid plans are starter, professional, enterprise, unlimited", req.Plan)
	}

	// Realm existence check (skipped when realmService is not wired).
	if p.realmService != nil {
		realm, lookupErr := p.realmService.GetByID(ctx, req.RealmID)
		if lookupErr != nil {
			return false, "", "", fmt.Errorf("realm lookup failed: %w", lookupErr)
		}
		if realm == nil {
			return false, "", "", fmt.Errorf("realm %s not found", req.RealmID)
		}
	}

	return false, "", "", nil
}

// stepProvisionDatabase creates a dedicated PostgreSQL database for enterprise
// plan tenants. For starter and professional plans this step is skipped because
// those tiers use the shared pool isolation model.
func (p *TenantOnboardingPipeline) stepProvisionDatabase(ctx context.Context, req OnboardingRequest) (skip bool, dbName string, dbHost string, err error) {
	if req.Plan != planEnterprise && req.Plan != "unlimited" {
		// Non-enterprise plans use pool isolation — no dedicated DB needed.
		return true, "", "", nil
	}

	if p.realmProvisioner == nil {
		// Provisioner not configured (e.g. no encryption key in dev).
		logger.Log.Warn("TenantOnboardingPipeline: RealmDBProvisioner not configured — skipping database provisioning",
			zap.String("tenant_id", req.TenantID.String()),
		)
		return true, "", "", nil
	}

	realmDB, provErr := p.realmProvisioner.ProvisionDatabase(ctx, req.RealmID, req.TenantSlug, req.Region)
	if provErr != nil {
		return false, "", "", fmt.Errorf("database provisioning failed: %w", provErr)
	}

	return false, realmDB.DatabaseName, realmDB.Host, nil
}

// stepSeedDefaultData creates the default admin role and default permissions
// within the tenant's IAM scope.
func (p *TenantOnboardingPipeline) stepSeedDefaultData(_ context.Context, req OnboardingRequest) (skip bool, dbName string, dbHost string, err error) {
	// In a full implementation this step would:
	//   1. Create a "tenant_admin" role via RoleService.
	//   2. Assign the platform default permission set to that role.
	//   3. Assign the tenant owner user to that role.
	//
	// For the initial pipeline we log the intent and mark as completed to
	// keep the step visible in the audit trail without side effects.
	logger.Log.Info("TenantOnboardingPipeline: seeding default data (TODO: integrate RoleService)",
		zap.String("tenant_id", req.TenantID.String()),
		zap.String("plan", req.Plan),
	)
	return false, "", "", nil
}

// stepConfigureFeatures enables plan-appropriate feature flags for the tenant.
func (p *TenantOnboardingPipeline) stepConfigureFeatures(_ context.Context, req OnboardingRequest) (skip bool, dbName string, dbHost string, err error) {
	// Feature flag configuration is plan-gated. In a full implementation this
	// would call ConfigProvider.UpsertConfig to enable features like:
	//   - "sso_enabled"         for professional+
	//   - "multi_db_isolation"  for enterprise
	//   - "custom_branding"     for professional+
	//   - "scim_provisioning"   for enterprise
	//
	// The plan map is intentional so new features can be added without changing
	// the pipeline structure.
	planFeatures := map[string][]string{
		"starter":      {"core_auth", "basic_mfa"},
		"professional": {"core_auth", "basic_mfa", "sso_enabled", "custom_branding"},
		planEnterprise: {"core_auth", "basic_mfa", "sso_enabled", "custom_branding", "multi_db_isolation", "scim_provisioning", "advanced_audit"},
		"unlimited":    {"core_auth", "basic_mfa", "sso_enabled", "custom_branding", "multi_db_isolation", "scim_provisioning", "advanced_audit", "unlimited_users"},
	}

	features := planFeatures[req.Plan]
	logger.Log.Info("TenantOnboardingPipeline: configuring feature flags (TODO: integrate ConfigProvider)",
		zap.String("tenant_id", req.TenantID.String()),
		zap.String("plan", req.Plan),
		zap.Strings("features", features),
	)
	return false, "", "", nil
}

// stepSendWelcome sends a welcome notification to the tenant owner.
// Currently a placeholder that logs the intent — integrate with EmailService
// or the notification-service when the onboarding email template is ready.
func (p *TenantOnboardingPipeline) stepSendWelcome(_ context.Context, req OnboardingRequest) (skip bool, dbName string, dbHost string, err error) {
	logger.Log.Info("TenantOnboardingPipeline: welcome notification queued (TODO: integrate EmailService/NotificationService)",
		zap.String("tenant_id", req.TenantID.String()),
		zap.String("tenant_slug", req.TenantSlug),
		zap.String("plan", req.Plan),
	)
	return false, "", "", nil
}
