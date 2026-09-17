// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/pkg/logger"
	"github.com/dogukanturhal/falcon-id/pkg/metrics"
)

// productEntitlementSyncTimeout bounds how long OnSignupComplete will
// synchronously wait (via SyncProductEntitlementProvisioner, below) for
// the tenant's product entitlement to reach ACTIVE before falling back
// to the pre-existing best-effort/async behaviour. Chosen generously
// above the observed steady-state provisioning latency (create+migrate+
// seed+configure_auth+register_service completed in ~5.8s including one
// retry, in the production incident this closes) while still bounding
// signup's added latency to a single-digit number of seconds — never an
// open-ended hang, and never a fixed `sleep` (this is a real deadline on
// real reconcile work, not a delay).
const productEntitlementSyncTimeout = 12 * time.Second

// DefaultAppAccessGranter provisions default app access for a newly created user.
type DefaultAppAccessGranter interface {
	GrantDefaultAccess(ctx context.Context, tenantID, userID uuid.UUID) error
}

// SubdomainProvisioner creates a default subdomain for a tenant (e.g., company.example.io).
type SubdomainProvisioner interface {
	ProvisionSubdomain(ctx context.Context, tenantID uuid.UUID, slug string) error
}

// TenantSlugResolver resolves a tenant's slug from its ID. Used by the
// post-signup provisioner to derive the subdomain.
type TenantSlugResolver interface {
	GetSlugByID(ctx context.Context, tenantID uuid.UUID) (string, error)
}

// ConsumerRoleAssigner assigns the `consumer_user` role to a freshly-
// created personal-account user. The role is bootstrapped by
// cmd/consumer_role_bootstrap.go at startup; this interface looks up +
// assigns by name so the post-signup hook doesn't need to know the
// role's UUID.
type ConsumerRoleAssigner interface {
	AssignConsumerRole(ctx context.Context, userID uuid.UUID) error
}

// FounderRoleAssigner grants the founding user of a brand-new
// business-account tenant that tenant's admin role (name "org_admin" —
// see cmd/signup_adapters.go's founderRoleAssignerAdapter), ensuring the
// role row exists for that tenant first.
//
// This is deliberately a SEPARATE mechanism from DefaultAppAccessGranter/
// DefaultAccessPolicy: SR-DAP-01 (internal/services/default_access_granter.go)
// blocks "org_admin" (and every other admin-tier role) from ever being
// assigned through admin-configured default-access policies, and that
// guard is correct and untouched — a self-service caller must never be
// able to grant themselves admin via a policy. The founding user of a
// tenant they just created is a structurally different case (there is,
// by definition, no other admin on the tenant yet), so it is provisioned
// through this dedicated, hardcoded path instead of through the
// policy-driven one SR-DAP-01 guards — mirroring how ConsumerRoleAssigner
// above is also a hardcoded provisioning-time assignment, not a policy.
//
// Must run synchronously inside OnSignupComplete, before CompleteSignup
// mints the onboarding session JWT (AuthService.IssueSessionForNewUser
// reads roles live from iam_user_roles at mint time — see
// auth_signup_session.go) — otherwise the founder is left holding a
// token with no role claim and 403s on onboarding/slug until they
// re-authenticate.
type FounderRoleAssigner interface {
	AssignFounderRole(ctx context.Context, tenantID, userID uuid.UUID) error
}

// downstreamMailboxProvisioner provisions the downstream side of a new signup —
// the personal mailbox <username>@downstream.com (consumer tenant) for personal
// accounts, or the business work-email domain as a custom tenant domain for
// business accounts. Best-effort; satisfied by *downstreamProvisioner.
type downstreamMailboxProvisioner interface {
	ProvisionPersonalMailbox(ctx context.Context, userID uuid.UUID) error
	ProvisionTenantDomain(ctx context.Context, tenantID, userID uuid.UUID) error
}

// ProductEntitlementProvisioner enqueues a tenant's entitlement for a
// specific first-party product (e.g. Mearax) through the SAME
// subscription-activation pipeline a billing webhook would use — see
// ProvisioningConsumer.HandleSubscriptionActivated. It creates (or reuses,
// idempotently) a pending iam_product_instances row and kicks the async
// ProvisioningOrchestrator reconciler; it never fabricates an "active" row
// directly. Without this, a self-service tenant gets a tenant + user but no
// product entitlement, and its first login is redirected to
// /unauthorized?reason=product_not_entitled by the falcon-id-client
// middleware (which gates on the JWT `products` claim, itself populated
// exclusively from ACTIVE iam_product_instances rows).
type ProductEntitlementProvisioner interface {
	HandleSubscriptionActivated(ctx context.Context, event SubscriptionActivatedEvent) error
}

// SyncProductEntitlementProvisioner is an optional capability of
// ProductEntitlementProvisioner. OnSignupComplete type-asserts for it and,
// when present, calls it instead of HandleSubscriptionActivated so the
// product instance is reconciled to ACTIVE (or a bounded timeout is hit)
// before OnSignupComplete returns and CompleteSignup mints the signup
// session's JWT.
//
// Why this matters: HandleSubscriptionActivated only creates the pending
// iam_product_instances row and detaches reconciliation into a background
// goroutine — by design, since its other caller (the billing-webhook Kafka
// consumer) has no request waiting on it. Self-service signup's
// auto-login (falcon-id!358) DOES have one: AuthService.IssueSessionForNewUser
// mints a JWT immediately after this hook returns, and that JWT's
// products[] claim is resolved from iam_product_instances at that exact
// moment. Without waiting here, the mint always races the async reconcile
// and — every time observed in production — loses: the row was still
// `provisioning_state=pending`/mid-saga when the token was signed, so
// products[] came back empty and the very first request hit
// /unauthorized?reason=product_not_entitled, permanently (nothing
// refreshes the claim later; see also the v2-token fix on
// GenerateAccessTokenV2/models.SpiceDBClaims.ProductSubscriptions, which
// closes the other half of that same incident).
//
// *ProvisioningConsumer (the production ProductEntitlementProvisioner)
// implements this; test mocks that don't are simply skipped and fall
// back to the pre-existing async path, so no test needs updating.
type SyncProductEntitlementProvisioner interface {
	HandleSubscriptionActivatedSync(ctx context.Context, event SubscriptionActivatedEvent) error
}

// TrialStarter starts a cardless billing trial for a tenant by calling
// subscription-management's S2S POST /api/v1/internal/tenants/{id}/trial.
// packageCode is the subscription_packages.code the user picked during
// signup (e.g. "starter"/"professional"/"scale" — see
// CreateSignupRequestInput.PlanCode); empty when the signup path that
// called this never collected a plan (OnSignupComplete, as opposed to
// OnSignupCompleteWithPlan) or the caller explicitly chose not to. Either
// way subscription-management resolves the trial itself: an explicit code
// resolves via PackageRepository.FindByCode, and an empty one falls back to
// its own operator-configured default package (subscription_packages.
// is_default) — refusing to start a trial at all rather than guessing one
// when no default is configured (see TrialService.StartTrial). Falcon-id
// itself never picks a package on the caller's behalf either way.
//
// This is NOT the same thing as ProductEntitlementProvisioner above:
// entitlement provisioning gives the tenant access to a first-party product
// (e.g. Mearax) via iam_product_instances; StartTrial writes billing state
// (TenantSubscription.Status/TrialEnd) that tenant-management's 15-minute
// reconciler reads to decide whether to suspend a tenant. The two pipelines
// are unrelated and both run, independently, out of OnSignupComplete.
type TrialStarter interface {
	StartTrial(ctx context.Context, tenantID uuid.UUID, packageCode string) error
}

// PlanAwarePostSignupHook is an OPTIONAL capability of PostSignupHook —
// same type-assertion idiom as SyncProductEntitlementProvisioner above.
// SignupService's CompleteSignup type-asserts its postSignupHook for this
// interface and, when present, calls OnSignupCompleteWithPlan instead of
// OnSignupComplete so step 7 (cardless trial start) gets the user's chosen
// plan/package code. Hooks that have no notion of a plan (e.g.
// SignupEventPublisher, which only ever publishes an event) simply don't
// implement this and keep receiving the pre-existing OnSignupComplete call
// unchanged — this is additive, not a breaking signature change on
// PostSignupHook itself.
type PlanAwarePostSignupHook interface {
	OnSignupCompleteWithPlan(ctx context.Context, tenantID, userID uuid.UUID, accountType, planCode string) error
}

// PostSignupProvisioner implements PostSignupHook by orchestrating:
//  1. Default app access grants (GAP 3)
//  2. Subdomain creation (GAP 5) — business accounts only
//  3. Consumer role assignment (ENT-2) — personal accounts only
//  4. SSF account-created event emission (ENT-7 Phase 1 — NoOp by default)
//  6. Product entitlement provisioning (e.g. Mearax) — see
//     ProductEntitlementProvisioner above.
//  7. Cardless trial start (business accounts only) — see TrialStarter above.
//
// All operations are best-effort — errors are logged but never propagated —
// EXCEPT that the product-entitlement step logs at Error (not Warn), since
// its failure means the tenant cannot use the product at all, not just a
// degraded feature. The trial-start step (7) stays at Warn/non-fatal like
// the other best-effort steps: unlike product entitlement, a tenant with no
// trial started is simply not billed yet, not locked out of anything, and
// tenant-management's reconciler only acts on tenants that HAVE a
// subscription row past its window — no row means no reconciler action at
// all, so failing to start one here is safe to leave for backfill.
type PostSignupProvisioner struct {
	appAccessGranter     DefaultAppAccessGranter
	subdomainProv        SubdomainProvisioner
	slugResolver         TenantSlugResolver
	consumerRoleAsgn     ConsumerRoleAssigner
	founderRoleAsgn      FounderRoleAssigner
	ssfEmitter           SSFEventEmitter
	downstreamProv         downstreamMailboxProvisioner
	productEntitlement   ProductEntitlementProvisioner
	entitlementProductID uuid.UUID
	defaultPlanCode      string
	trialStarter         TrialStarter

	// entitlementSyncTimeout overrides productEntitlementSyncTimeout when
	// non-zero. Unexported and set directly by tests in this package
	// (see TestPostSignupProvisioner_OnSignupComplete_EntitlementSyncTimeout)
	// so the timeout-exceeded path can be exercised in milliseconds
	// instead of actually waiting out the real 12s bound — no exported
	// API surface added for what is purely a test seam.
	entitlementSyncTimeout time.Duration
}

// NewPostSignupProvisioner creates a new provisioner. All dependencies are optional.
func NewPostSignupProvisioner(
	appAccessGranter DefaultAppAccessGranter,
	subdomainProv SubdomainProvisioner,
	slugResolver TenantSlugResolver,
) *PostSignupProvisioner {
	return &PostSignupProvisioner{
		appAccessGranter: appAccessGranter,
		subdomainProv:    subdomainProv,
		slugResolver:     slugResolver,
	}
}

// SetConsumerRoleAssigner wires the consumer-role assigner that runs on
// personal-account signups. Keeping this as a post-construction setter
// keeps NewPostSignupProvisioner's signature backward-compatible (the
// existing 5-place constructor call in cmd/services.go doesn't need to
// change every time we add a new optional dependency).
func (p *PostSignupProvisioner) SetConsumerRoleAssigner(a ConsumerRoleAssigner) {
	p.consumerRoleAsgn = a
}

// SetFounderRoleAssigner wires the founder-role assigner that runs on
// business-account signups, granting the founding user their new
// tenant's org_admin role. See FounderRoleAssigner's doc comment for why
// this is a distinct mechanism from DefaultAppAccessGranter/SR-DAP-01.
// Nil-safe: when unset, OnSignupComplete simply skips this step.
func (p *PostSignupProvisioner) SetFounderRoleAssigner(a FounderRoleAssigner) {
	p.founderRoleAsgn = a
}

// SetdownstreamProvisioner wires the downstream provisioner that runs after signup:
// personal -> mailbox <username>@downstream.com, business -> custom tenant domain.
func (p *PostSignupProvisioner) SetdownstreamProvisioner(h downstreamMailboxProvisioner) {
	p.downstreamProv = h
}

// SetProductEntitlementProvisioner wires the product-entitlement step: every
// tenant produced by self-service signup gets a pending, then reconciled,
// ACTIVE iam_product_instances row for productID (e.g.
// models.WellKnownProductMearax). Nil-safe: when unset, OnSignupComplete
// simply skips this step (e.g. in unit tests or deployments where signup
// intentionally doesn't grant a first-party product).
func (p *PostSignupProvisioner) SetProductEntitlementProvisioner(provisioner ProductEntitlementProvisioner, productID uuid.UUID) {
	p.productEntitlement = provisioner
	p.entitlementProductID = productID
}

// SetTrialStarter wires the cardless-trial-start step (business accounts
// only) that calls subscription-management's S2S trial-start endpoint. See
// TrialStarter's doc comment above for what this does and does not do.
// Nil-safe: unset, OnSignupComplete simply skips step 7 (e.g. in unit
// tests, or a deployment where outbound S2S creds to subscription-
// management aren't configured).
func (p *PostSignupProvisioner) SetTrialStarter(t TrialStarter) {
	p.trialStarter = t
}

// SetSSFEmitter wires the Shared Signals Framework event emitter
// (ENT-7). Defaults to nil; cmd/services.go wires a NoOpSSFEmitter
// at boot so the emit-call sites in OnSignupComplete always have
// something to call. Real delivery (outbox + RFC 8417 delivery
// worker) lands in ENT-7 Phase 2.
func (p *PostSignupProvisioner) SetSSFEmitter(e SSFEventEmitter) {
	p.ssfEmitter = e
}

// SetDefaultPlanCode wires the subscription plan used when activating the
// product entitlement below (see OnSignupComplete step 6). The caller
// (cmd/services.go) resolves SIGNUP_DEFAULT_PLAN_CODE once from config and
// passes the same value here that it passes to
// services.NewSignupService(...) — the two sites are never allowed to read
// the env independently, so they can't drift apart.
// entitlementTimeout returns the bound for the synchronous entitlement wait
// in OnSignupComplete: entitlementSyncTimeout when a test in this package
// has overridden it, otherwise the real productEntitlementSyncTimeout
// constant. Kept as a method (rather than inlining the zero-check at the
// call site) so the "what timeout actually applies" question has one
// answer, tested directly by TestPostSignupProvisioner_entitlementTimeout.
func (p *PostSignupProvisioner) entitlementTimeout() time.Duration {
	if p.entitlementSyncTimeout > 0 {
		return p.entitlementSyncTimeout
	}
	return productEntitlementSyncTimeout
}

func (p *PostSignupProvisioner) SetDefaultPlanCode(code string) {
	p.defaultPlanCode = code
}

// defaultPlan returns the configured default plan code, falling back to
// "starter" if unset (guards direct construction, e.g. tests, that skip
// SetDefaultPlanCode).
func (p *PostSignupProvisioner) defaultPlan() string {
	if p.defaultPlanCode != "" {
		return p.defaultPlanCode
	}
	return "starter"
}

// OnSignupComplete implements PostSignupHook. Starts a cardless trial
// against the operator-configured default package (no plan chosen).
func (p *PostSignupProvisioner) OnSignupComplete(ctx context.Context, tenantID, userID uuid.UUID, accountType string) error {
	return p.onSignupComplete(ctx, tenantID, userID, accountType, "")
}

// OnSignupCompleteWithPlan implements PlanAwarePostSignupHook. Identical to
// OnSignupComplete except step 7 (cardless trial start) is told which
// package the user picked during signup (CreateSignupRequestInput.PlanCode)
// instead of always falling back to subscription-management's
// operator-configured default. See PlanAwarePostSignupHook's doc comment
// for why this is a separate method rather than a changed signature on
// OnSignupComplete/PostSignupHook.
func (p *PostSignupProvisioner) OnSignupCompleteWithPlan(ctx context.Context, tenantID, userID uuid.UUID, accountType, planCode string) error {
	return p.onSignupComplete(ctx, tenantID, userID, accountType, planCode)
}

func (p *PostSignupProvisioner) onSignupComplete(ctx context.Context, tenantID, userID uuid.UUID, accountType, planCode string) error {
	// 1. Grant default app access
	if p.appAccessGranter != nil {
		if err := p.appAccessGranter.GrantDefaultAccess(ctx, tenantID, userID); err != nil {
			logger.Warn("Post-signup: failed to grant default app access (non-fatal)",
				zap.String("tenant_id", tenantID.String()),
				zap.String("user_id", userID.String()),
				zap.Error(err),
			)
		}
	}

	// 3. Assign consumer_user role (personal/consumer signups only).
	// The role is bootstrapped by cmd/consumer_role_bootstrap.go at
	// pod startup; absence here would surface as logger.Warn + the
	// user lands without the role tag (recoverable via admin role-
	// assignment). Frontend conditional rendering (Phase 5 of the
	// consumer-tenant rollout) keys off this role.
	if p.consumerRoleAsgn != nil && accountType != discoverAccountTypeBusiness {
		if err := p.consumerRoleAsgn.AssignConsumerRole(ctx, userID); err != nil {
			logger.Warn("Post-signup: failed to assign consumer_user role (non-fatal)",
				zap.String("tenant_id", tenantID.String()),
				zap.String("user_id", userID.String()),
				zap.Error(err),
			)
		}
	}

	// 3b. Assign the founding user their new tenant's org_admin role
	// (business signups only). MUST run before CompleteSignup mints the
	// onboarding session JWT — see FounderRoleAssigner's doc comment.
	// Non-fatal like every other step here, matching the consumer-role
	// step's posture: the tenant/user rows already committed via
	// MarkCompleted before this hook runs (see SignupService.CompleteSignup),
	// so a failure here must not turn an otherwise-successful signup into
	// an error response the client would retry against an
	// already-completed request. A failure instead leaves the founder
	// 403ing on onboarding/slug exactly like the pre-fix bug, visible via
	// this Warn log for operator follow-up/backfill.
	if p.founderRoleAsgn != nil && accountType == discoverAccountTypeBusiness {
		if err := p.founderRoleAsgn.AssignFounderRole(ctx, tenantID, userID); err != nil {
			logger.Warn("Post-signup: failed to assign founder org_admin role (non-fatal)",
				zap.String("tenant_id", tenantID.String()),
				zap.String("user_id", userID.String()),
				zap.Error(err),
			)
		}
	}

	// 2. Provision subdomain (business accounts only)
	if p.subdomainProv != nil && accountType == discoverAccountTypeBusiness && p.slugResolver != nil {
		slug, err := p.slugResolver.GetSlugByID(ctx, tenantID)
		if err != nil {
			logger.Warn("Post-signup: failed to resolve tenant slug for subdomain (non-fatal)",
				zap.String("tenant_id", tenantID.String()),
				zap.Error(err),
			)
		} else if slug != "" {
			if err := p.subdomainProv.ProvisionSubdomain(ctx, tenantID, slug); err != nil {
				logger.Warn("Post-signup: subdomain provisioning failed (non-fatal)",
					zap.String("tenant_id", tenantID.String()),
					zap.String("slug", slug),
					zap.Error(err),
				)
			}
		}
	}

	// 5. Provision the downstream side (best-effort). Personal accounts get a
	//    mailbox <username>@downstream.com under the consumer tenant; business
	//    accounts get their work-email domain registered as a custom tenant
	//    domain (ownership verification is a separate self-service step).
	if p.downstreamProv != nil {
		if accountType == discoverAccountTypeBusiness {
			if err := p.downstreamProv.ProvisionTenantDomain(ctx, tenantID, userID); err != nil {
				logger.Warn("Post-signup: downstream custom-domain provisioning failed (non-fatal)",
					zap.String("tenant_id", tenantID.String()),
					zap.String("user_id", userID.String()),
					zap.Error(err),
				)
			}
		} else if err := p.downstreamProv.ProvisionPersonalMailbox(ctx, userID); err != nil {
			logger.Warn("Post-signup: downstream mailbox provisioning failed (non-fatal)",
				zap.String("user_id", userID.String()),
				zap.Error(err),
			)
		}
	}

	// 4. SSF account-created event (ENT-7 Phase 1 — NoOp by
	// default; outbox + delivery worker land in Phase 2). Per
	// RFC 8417, security-event subscribers expect a deterministic
	// account-created signal — without this hook, downstream SIEM
	// / Wazuh have to poll the iam_users table to detect new
	// users, which doesn't scale and has alert-latency issues.
	if p.ssfEmitter != nil {
		if err := p.ssfEmitter.EmitAccountCreated(ctx, AccountCreatedEvent{
			UserID:      userID,
			TenantID:    tenantID,
			AccountType: accountType,
		}); err != nil {
			logger.Warn("Post-signup: SSF emit failed (non-fatal)",
				zap.String("user_id", userID.String()),
				zap.Error(err),
			)
		}
	}

	// 6. Grant the tenant's product entitlement (e.g. Mearax) so the user
	//    isn't bounced to /unauthorized?reason=product_not_entitled on
	//    first login. Routed through the same subscription-activation
	//    pipeline a billing webhook would use (ProvisioningConsumer →
	//    ProductInstanceService.Provision → ProvisioningOrchestrator.
	//    Reconcile), so self-service signup goes through the real
	//    pending→active state machine instead of fabricating a completed
	//    row. Idempotent: Provision() reuses the existing instance if one
	//    already exists for this tenant+product.
	//
	//    Plan: self-service signup today only ever produces tenants on the
	//    configured default plan (SIGNUP_DEFAULT_PLAN_CODE, see
	//    SetDefaultPlanCode and SignupService.provisionTenant, both the
	//    business and personal/consumer paths) — pass that straight
	//    through. Thread the real chosen plan here once signup gains plan
	//    selection.
	//
	//    Unlike every other step above, a failure here is logged at Error,
	//    not Warn: the tenant genuinely cannot use the product until this
	//    resolves. It is NOT silently swallowed — check
	//    iam_product_instances.provisioning_state / failure_reason /
	//    next_retry_at for the affected tenant+product to diagnose; the
	//    orchestrator retries automatically with exponential backoff.
	if p.productEntitlement != nil && p.entitlementProductID != uuid.Nil {
		plan := p.defaultPlan()
		event := SubscriptionActivatedEvent{
			TenantID:  tenantID,
			ProductID: &p.entitlementProductID,
			PlanID:    &plan,
		}

		// Prefer the synchronous variant so the instance is ACTIVE (not
		// merely enqueued) before the signup-session JWT is minted right
		// after this hook returns — see SyncProductEntitlementProvisioner's
		// doc comment for the race this closes. Bounded by
		// productEntitlementSyncTimeout, not open-ended: on timeout this
		// falls through to the same non-fatal error logging as the async
		// path always had, and the background orchestrator ticker
		// finishes the job later regardless.
		var entitlementErr error
		if syncProv, ok := p.productEntitlement.(SyncProductEntitlementProvisioner); ok {
			syncCtx, cancel := context.WithTimeout(ctx, p.entitlementTimeout())
			entitlementErr = syncProv.HandleSubscriptionActivatedSync(syncCtx, event)
			cancel()
		} else {
			entitlementErr = p.productEntitlement.HandleSubscriptionActivated(ctx, event)
		}

		if entitlementErr != nil {
			logger.Error("Post-signup: product entitlement provisioning failed — tenant cannot use the product until this is resolved",
				zap.String("tenant_id", tenantID.String()),
				zap.String("user_id", userID.String()),
				zap.String("product_id", p.entitlementProductID.String()),
				zap.Error(entitlementErr),
			)
		}
	}

	// 7. Start a cardless billing trial (business accounts only). See
	//    TrialStarter's doc comment for how this differs from step 6's
	//    product entitlement.
	//
	//    Stays non-fatal to signup (a failure here must not block account
	//    creation), but is NOT the "safe to leave for later" gap it used
	//    to be documented as: "no subscription row means tenant-management's
	//    reconciler has nothing to act on" was the false assumption behind
	//    production incident t-trial-silent-failure (tenant
	//    029a3c7e-b733-4c47-8854-37957dee6633) — a business tenant whose
	//    trial start failed here was left with subscription_status='trial'
	//    and trial_ends_at=NULL *forever*, because tenant-management's
	//    expiry reconciler (internal/trialexpiry) only ever matches
	//    trial_ends_at < NOW(), and NULL never satisfies that. A Warn log
	//    and nothing else is indistinguishable from success at every
	//    downstream layer that matters (alerting, billing).
	//
	//    So this failure is now: (a) logged at Error, not Warn, with the
	//    tenant/user IDs so an operator can find the exact record; (b)
	//    counted on a dedicated metric (metrics.TrialStartFailures) so an
	//    alert can fire on the rate rather than requiring someone to grep
	//    logs. It is deliberately NOT retried inline here (unlike step 6's
	//    entitlement provisioning) — the systemic backstop is
	//    tenant-management's trial_ends_at-gap reconciler, which detects
	//    subscription_status='trial' AND trial_ends_at IS NULL on its own
	//    poll interval and repairs it by calling this same idempotent
	//    StartTrial route again, regardless of why the first call failed.
	//
	//    Personal/consumer accounts deliberately do NOT get a trial —
	//    mirrors step 2 (subdomain) and step "MUST run..." (founder role)
	//    above, which are also business-only: cardless trials are a
	//    business-account billing concept, and subscription-management's
	//    TenantSubscription table has no meaning for a personal tenant.
	if p.trialStarter != nil && accountType == discoverAccountTypeBusiness {
		if err := p.trialStarter.StartTrial(ctx, tenantID, planCode); err != nil {
			metrics.TrialStartFailures.WithLabelValues(accountType).Inc()
			logger.Error("Post-signup: trial start failed — tenant will show subscription_status=trial with no trial_ends_at until tenant-management's trial-gap reconciler repairs it; alert on falcon_id_trial_start_failed_total",
				zap.String("tenant_id", tenantID.String()),
				zap.String("user_id", userID.String()),
				zap.Error(err),
			)
		}
	}

	return nil
}
