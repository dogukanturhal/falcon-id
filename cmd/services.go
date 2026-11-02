// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"os"
	"time"

	goredis "github.com/redis/go-redis/v9"
	resilient "github.com/dogukanturhal/hexx-pep-core/pkg/resilient"
	"github.com/dogukanturhal/platform-shared/quota"
	serviceauth "github.com/dogukanturhal/platform-shared/service-auth"
	"go.uber.org/zap"

	"github.com/google/uuid"
	"github.com/dogukanturhal/platform-shared/hooks"

	"github.com/dogukanturhal/falcon-id/internal/middleware"
	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/internal/repositories"
	"github.com/dogukanturhal/falcon-id/internal/security"
	"github.com/dogukanturhal/falcon-id/internal/services"
	"github.com/dogukanturhal/falcon-id/internal/tenantstatus"
	"github.com/dogukanturhal/falcon-id/pkg/config"
	"github.com/dogukanturhal/falcon-id/pkg/crypto"
	"github.com/dogukanturhal/falcon-id/pkg/hibp"
	"github.com/dogukanturhal/falcon-id/pkg/keys"
	"github.com/dogukanturhal/falcon-id/pkg/keystoneclient"
	"github.com/dogukanturhal/falcon-id/pkg/logger"
	"github.com/dogukanturhal/falcon-id/pkg/redis"
)

// Services holds all service instances.
type Services struct {
	Audit            *services.AuditService
	Token            *services.TokenService
	Role             *services.RoleService
	SoD              *services.SoDService
	SoDReevaluator   *services.SoDReevaluator
	Permission       *services.PermissionService
	RoleTemplate     *services.RoleTemplateService
	User             *services.UserService
	UserPreferences  *services.UserPreferencesService
	LDAP             *services.LDAPService
	ADSync           *services.ADSyncService
	Auth             *services.AuthService
	SocialAuth       *services.SocialAuthService
	Email            *services.EmailService
	MFA              *services.MFAService
	MFAEnrollment    *services.MFAEnrollmentService
	PasswordReset    *services.PasswordResetService
	PasswordPolicy   *services.PasswordPolicyService
	RateLimit        *services.RateLimitService
	IPRule           *services.IPRuleService
	APIKey           *services.APIKeyService
	TenantAPIKey     *services.TenantAPIKeyService // nil unless DEVELOPER_KEYS_ENABLED and wired
	ServiceAccount   *services.ServiceAccountService
	OAuthProvider    *services.OAuthProviderService
	SAML             *services.SAMLService
	SAMLSP           *services.SAMLSPService
	SAMLMetadata     *services.SAMLMetadataService
	SCIM             *services.SCIMService
	AccessTerminator *services.UserAccessTerminator
	Group            *services.GroupService
	Organization     *services.OrganizationService
	Impersonation    *services.ImpersonationService
	Webhook          *services.WebhookService
	Device           *services.DeviceService
	Recovery         *services.RecoveryService
	PushMFA          *services.PushMFAService
	MagicLink        *services.MagicLinkService
	Invitation       *services.InvitationService
	Consent          *services.ConsentService
	Risk             *services.RiskService
	OPA              *services.OPAService
	Authorization    *services.AuthorizationService
	AuthzEngine      services.AuthorizationEngine
	Tenant           *services.TenantService
	AppAccess        *services.AppAccessService
	Realm            *services.RealmService
	ConfigProvider   *services.ConfigProvider
	// Entitlement is the fail-closed tenant module entitlement source
	// (the product roadmap §4.1) backing GET /api/v1/tenant/entitlements,
	// PUT/GET /internal/v1/tenants/{id}/module-entitlements, and the
	// example.tenant.modules.sync Kafka consumer
	// (internal/entitlementsync).
	Entitlement *services.TenantEntitlementService

	// TenantStatusRepo / TenantStatusGate back tenant suspension enforcement
	// (R1-GAPS row 27, internal/tenantstatus): the repo applies
	// example.tenant.status events, the gate is the cached read side.
	TenantStatusRepo *tenantstatus.Repository
	TenantStatusGate *tenantstatus.Gate
	// AcmeAppRoleProvisioner creates the AcmeApp role catalog for a
	// tenant. Wired into signup (see postSignupProvisioner above) and also
	// exposed here so the admin backfill endpoint
	// (the platform role-backfill endpoint) can provision the
	// same catalog for pre-existing tenants without re-deriving a divergent
	// role list.
	AcmeAppRoleProvisioner *services.AcmeAppRoleProvisioner
	// Product & licensing
	Product         *services.ProductService
	License         *services.LicenseService
	ProductInstance *services.ProductInstanceService
	AppRegistration *services.AppRegistrationService
	// Applications & service principals
	Application        *services.ApplicationService
	ServicePrincipal   *services.ServicePrincipalService
	AppConsent         *services.AppConsentService
	SPCredential       *services.SPCredentialService
	SPSignInActivity   *services.SPSignInActivityService
	ApplicationOwner   *services.ApplicationOwnerService
	AppIDP             *services.AppIdentityProviderService
	AppInstallation    *services.AppInstallationService
	AppRole            *services.AppRoleService
	CredentialPolicy   *services.CredentialPolicyService
	ConsentRequest     *services.ConsentRequestService
	RegistrationPolicy *services.RegistrationPolicyService
	StaleAppDetection  *services.StaleAppDetectionService
	// Identity & access
	Delegation     *services.DelegationService
	TempAccessPass *services.TempAccessPassService
	GuestUser      *services.GuestUserService
	JITAccess      *services.JITAccessService
	// PlatformJIT — R1 platform plane: JIT elevation + break-glass
	// (iam_platform_roles / iam_jit_elevations, migration 0016).
	PlatformJIT            *services.PlatformJITService
	PlatformAuth           *services.PlatformAuthority
	AccessReview           *services.AccessReviewService
	EmailDomain            *services.EmailDomainService
	TenantBranding         *services.TenantBrandingService
	TenantQuota            *services.TenantQuotaService
	IDPRouting             *services.IDPRoutingService
	IDPTenantOverride      *services.IDPTenantOverrideService
	WebAuthn               *services.WebAuthnService
	Witness                *services.WitnessService
	TokenExchange          *services.TokenExchangeService
	ManagedIdentity        *services.ManagedIdentityService
	SCP                    *services.SCPService
	Signup                 *services.SignupService
	SignupTrialProvisioner *services.PostSignupProvisioner
	RealmFederation        *services.RealmFederationService
	RealmDBProvisioner     *services.RealmDBProvisioner
	// Platform & compliance
	ConditionalAccess      *services.ConditionalAccessService
	CompliancePolicyEngine *services.CompliancePolicyEngine
	ComplianceScheduler    *services.ComplianceScheduler
	ComplianceReport       *services.ComplianceReportService
	ImmutableAudit         *services.ImmutableAuditService
	SessionAnalytics       *services.SessionAnalyticsService
	UsageMetering          *services.UsageMeteringService
	ThreatCorrelation      *services.ThreatCorrelationService
	// ITDR — Identity Threat Detection and Response. Query/admin endpoints
	// only here; the real-time detection pipeline (impossible-travel,
	// credential stuffing, MFA fatigue) lives behind Redis streams and
	// is wired separately when that infra is up. Pipeline may be nil;
	// the GET/POST/PUT query endpoints still serve from the repo.
	ITDR                    *services.ITDRService
	RoutingWebhook          *services.RoutingWebhookService
	SpiceDBReconciler       *services.SpiceDBReconciler
	RoleRevokeDrainer       *services.RoleRevokeDrainer
	SeatQuotaReconciler     *services.SeatQuotaReconciler
	TemplateRoleProvisioner *services.TemplateRoleProvisioner
	ModuleAccess            *services.ModuleAccessProvisioner
	EmployeeAccess          *services.EmployeeAccessService
	EmployeeAccessExpiry    *services.EmployeeAccessExpiryWorker
	HREmploymentSync        *services.HREmploymentSyncService
	TenantBootstrap         *services.TenantBootstrapService
	Discover                *services.DiscoverService
	AuthHooks               *services.AuthHooksService
	ProvisioningStatus      *services.ProvisioningStatusService
	// Identifier-first realm discovery
	RealmDiscovery *services.RealmDiscoveryService
	// Host-based tenant discovery — host→tenant resolution for the
	// unified-dashboard SDK when customers reach a SaaS app via their
	// custom domain (crm.acme-corp.com). See
	// internal/services/host_discovery_service.go.
	HostDiscovery *services.HostDiscoveryService
	// OnboardingSlug backs the onboarding wizard's subdomain-slug step
	// (PATCH /api/v1/onboarding/slug). nil when TENANT_MANAGEMENT_INTERNAL_URL
	// or outbound S2S creds are unset — route registration short-circuits.
	OnboardingSlug *services.OnboardingSlugService

	// TenantWorkspaceName replaces the signup placeholder workspace name
	// (S2S rename from business + platform-admin backfill); never nil.
	TenantWorkspaceName *services.TenantWorkspaceNameService

	// OnboardingStatus backs the onboarding wizard's entry-time re-entry
	// guard (GET /api/v1/auth/onboarding/status), reading
	// slug_confirmed_at from tenant-management. Same nil-safe posture as
	// OnboardingSlug — reuses the platform:tenants:read scope
	// svc-falcon-id already holds, no new S2S grant needed.
	OnboardingStatus *services.OnboardingStatusService
	// Enterprise bridges
	SubscriptionBridge *services.SubscriptionProvisioningBridge
	// ProvisioningOrchestrator is the reconciler that advances a "pending"
	// iam_product_instances row through pending → ... → active. Started in
	// initServices; stopped in BackgroundTasks.Stop. Both self-service
	// signup (via ProvisioningConsumer) and the billing subscription-
	// activated webhook (via SubscriptionBridge) feed it pending rows.
	ProvisioningOrchestrator *services.ProvisioningOrchestrator
	DomainVerification       *services.DomainVerificationWorker
	// Tenant-host re-verification — daily TXT recheck for verified
	// custom domains; auto-suspends hosts after 14 consecutive
	// failures. Sibling of DomainVerification (email-domain pattern).
	TenantHostVerification *services.TenantHostVerificationWorker
	// GDPR data deletion consumer (async side — drains the integration-bus
	// user.data_deletion_requested stream into the DataDeletionService.DeleteUser
	// cascade). Wired in startBackgroundTasks; nil-safe.
	GDPRConsumer *services.GDPRDeletionConsumer
	// DeviceFingerprint — richer-signal device-tracking store.
	DeviceFingerprint *services.DeviceFingerprintService
	// GDPR synchronous side — request creation, status, cancel, legal-hold.
	// Backs the /api/v1/users/:id/{export,delete,deletion-status} and
	// /api/v1/deletion-requests/:id/{cancel,legal-hold} HTTP routes.
	// DataDeletion owns the iam_deletion_requests row + the 30-day grace
	// window; the OAuth-token sweep is wired via SetOAuthRepository so a
	// deleted user's tokens are revoked at the IdP boundary instead of
	// surviving until natural expiry (Phase 3 dropped iam_refresh_tokens —
	// without this wiring there's no revocation path).
	DataExport   *services.DataExportService
	DataDeletion *services.DataDeletionService
	// AdminAudit — dedicated audit logger for admin-actor surface
	// mutations (distinct from the general AuditService).
	AdminAudit *services.AdminAuditService
	// SchemaVersion — per-tenant schema drift detection (read-only platform-admin).
	SchemaVersion *services.SchemaVersionTracker
	// TenantResourceMonitor — per-tenant resource sampling (nil-safe when Redis unavailable).
	TenantResourceMonitor *services.TenantResourceMonitor
	// ProvisioningPolicy — governance rules dry-run engine. Backs
	// /api/v1/platform/policy/{evaluate,rules}. Read-only +
	// pure-in-memory; no DB / Redis dep — always wired.
	ProvisioningPolicy *services.PolicyEngine
	// AgentIdentity — autonomous-agent (AI / human-attended
	// automation) lifecycle service. Backs the 9 routes under
	// /api/v1/platform/agents/*.
	AgentIdentity *services.AgentIdentityService
	// ComplianceLiveEvidence — live SOC2 / GDPR / KVKK report
	// generator (no pre-stored evaluations; every report reflects
	// current posture). Backs the 3 routes under
	// /api/v1/platform/compliance/{soc2,gdpr,kvkk}.
	ComplianceLiveEvidence *services.ComplianceLiveEvidenceService
	// JWT key provider — kept for backward compatibility; KeyManager takes precedence.
	JWTKeyProvider *crypto.JWTKeyProvider
	// KeyManager — DB-persisted signing keys with AES-256-GCM at-rest encryption.
	// Replaces the ephemeral JWTKeyProvider for production deployments (Keycloak/Auth0 pattern).
	KeyManager *keys.KeyManager
	// OriginRegistry is the Stage 3 dynamic, tenant-registry-derived CORS/
	// CSRF origin set (internal/middleware.DynamicOriginRegistry), refreshed
	// in the background off tenant-management's tenant list + per-tenant
	// app_host (platform-core !80). Wired into middleware.CORSWithRegistry
	// (cmd/routes.go) and CSRFMiddleware.SetOriginRegistry (cmd/handlers.go).
	// Nil-safe throughout: nil (or a lister-less registry, when
	// TENANT_MANAGEMENT_INTERNAL_URL/outbound OAuth creds are unset)
	// contributes nothing, and CORS/CSRF fall back to their existing
	// static allowlists exactly as before Stage 3 — see
	// DynamicOriginRegistry's fail-closed doc comment.
	OriginRegistry *middleware.DynamicOriginRegistry
}

// initServices initializes all services and wires dependencies.
func initServices(repos *Repositories, infra *Infrastructure) *Services {
	cfg := infra.Config

	jwtKeyProvider, err := crypto.NewJWTKeyProvider(logger.Log, "")
	if err != nil {
		logger.Fatal("Failed to initialise JWT key provider", zap.Error(err))
	}

	keyManager := initKeyManager(infra, cfg)
	if jwtKeyProvider.IsEphemeral() {
		if keyManager != nil {
			// KeyManager takes precedence for both signing and JWKS (see Services.KeyManager
			// doc comment above), so the ephemeral key generated above is never used.
			logger.Log.Debug("ephemeral JWT signing key generated at startup (UNUSED: DB-backed KeyManager is active and takes precedence for signing and JWKS)")
		} else {
			logger.Log.Warn(
				"No JWT RSA private key configured and no DB-backed KeyManager available. " +
					"The ephemeral key generated at startup IS the active signing key. " +
					"Tokens will be invalidated on restart. " +
					"Set JWT_PRIVATE_KEY, JWT_PRIVATE_KEY_FILE, or configure KeyManager in production.",
			)
		}
	}

	// Core services
	auditService := services.NewAuditService(repos.Token, infra.DB.Pool)
	tokenService := services.NewTokenService(cfg, repos.Token, repos.User)
	// OPS_STRICT_PLATFORM_ROLES (default off): platform-admin authority comes
	// from iam_platform_roles instead of tenant membership / legacy tenant
	// roles. Off = every path below is unchanged.
	platformAuthority := services.NewPlatformAuthority(cfg.OpsStrictPlatformRoles, cfg.OpsBreakGlassEmail, repos.PlatformAuthority)
	tokenService.SetPlatformAuthority(platformAuthority)
	middleware.SetPlatformAuthority(platformAuthority)
	if cfg.OpsStrictPlatformRoles {
		logger.Warn("OPS_STRICT_PLATFORM_ROLES is ON: platform-admin authority now comes from iam_platform_roles only")
	}
	tokenService.SetJWTKeyProvider(jwtKeyProvider)
	if keyManager != nil {
		tokenService.SetKeyManager(keyManager)
	}
	// Phase 3.1 — let TokenService delegate per-user revocation to the
	// iam_oauth_tokens layer (replacing the now-no-op'd
	// RevokeAllUserRefreshTokens against the dropped iam_refresh_tokens).
	// Used by Logout / ChangePassword / DataDeletion via
	// tokenService.RevokeAllUserOAuthTokens.
	tokenService.SetOAuthClientRepository(repos.OAuthClient)
	roleService := services.NewRoleService(repos.Role, repos.Permission, auditService)
	if cfg.DeveloperKeysEnabled {
		// WO#20: refuse API-key-forbidden grants to roles active tenant API keys hold.
		roleService.SetAPIKeyRoleUsage(repos.APIKey)
	}
	permissionService := services.NewPermissionService(repos.Permission, auditService)
	// ADR-A10 SoD (Separation of Duties) evaluation + rule matrix
	// (23-authorization-rbac-abac-rebac.md §5.2/§8.3). Warn mode only in
	// R1 — see sod_service.go doc comment.
	sodService := services.NewSoDService(repos.SoD, repos.SoD, repos.Permission)
	// Continuous SoD re-evaluation (spec 23 5.2): daily full pass (started in
	// startBackgroundTasks, leader-locked) + on rule change. Warn mode only.
	sodReevaluator := services.NewSoDReevaluator(repos.SoD, repos.Permission, auditService, infra.DB.Pool)
	sodService.SetRuleChangeHook(sodReevaluator.ReevaluateTenantAsync)
	userService := services.NewUserService(cfg, repos.User, repos.Role, tokenService, auditService)
	// example.iam.user.* lifecycle events -> Kafka -> business HR employee sync (RHR-B4).
	wireIAMUserEventPublisher(cfg, userService)
	// ADR-A10 SoD: evaluate on every user role-assignment write (§5.2 —
	// "evaluation on EVERY role-assignment write"). SetUserRoles is the
	// primary such write path (Phase 2 team-management "set roles" UI).
	userService.SetSoDService(sodService)
	// Per-user opaque preferences (iam_users.preferences JSONB — migration
	// 0003). Service owns the registry of valid product slugs + JSON merge
	// patch logic; handler at /api/v1/users/me/preferences exposes the
	// read/write surface.
	userPreferencesService := services.NewUserPreferencesService(infra.DB.Pool)

	// LDAP services
	ldapService := services.NewLDAPService(cfg, repos.IDP, repos.User, repos.Role)
	ldapService.SetSettingsRepo(repos.Settings)
	ldapService.SetGroupRepo(repos.Group)
	if infra.EncryptionService != nil {
		ldapService.SetEncryptionService(infra.EncryptionService)
	}

	// AD Sync Service
	adSyncService := services.NewADSyncService(cfg, ldapService, repos.ADSync, repos.LDAPSyncHistory, repos.IDP)
	adSyncService.SetAuditService(auditService)

	// Auth services
	authService := services.NewAuthService(cfg, repos.User, repos.Role, repos.Session, repos.Token, tokenService, auditService, ldapService)
	socialAuthService := services.NewSocialAuthService(cfg, repos.IDP, repos.FedAccount, repos.User, repos.Role, tokenService, auditService)

	configProvider := initConfigProvider(cfg, repos, infra, tokenService)

	// Feed ConfigProvider.FrontendURL a trustworthy per-tenant source:
	// tenant-management's app_host (platform-core !80, not yet merged —
	// see buildTenantManagementAppHostHTTPClient's doc comment). nil when
	// creds/URL are missing or the client can't be built — FrontendURL's
	// existing local-cache -> Redis -> DB -> static-default chain is
	// unchanged in that case (SetAppHostResolver no-ops on a nil resolver).
	if appHostHTTP := buildTenantManagementAppHostHTTPClient(cfg, logger.Log); appHostHTTP != nil {
		appHostReader := newHTTPTenantManagementAppHostReader(cfg.TenantManagementInternalURL, appHostHTTP)
		configProvider.SetAppHostResolver(appHostReader)
		logger.Info("ConfigProvider.FrontendURL wired to tenant-management app_host resolution")
	} else {
		logger.Warn("ConfigProvider.FrontendURL app-host resolver disabled: outbound S2S client to tenant-management unavailable; frontend_url stays local-cache/Redis/DB/static-default only")
	}

	// Stage 3: dynamic, tenant-registry-derived CORS/CSRF origin set. Built
	// from a SEPARATE app-host reader instance (its own HTTP client) than
	// the one just wired into configProvider above — decoupling keeps a
	// slow/broken origin-list refresh from ever affecting FrontendURL
	// resolution, and vice versa. See buildTenantManagementOriginLister's
	// doc comment for the fail-closed contract and why the registry is
	// always constructed (never nil), even when its underlying lister is
	// nil.
	originLister := buildTenantManagementOriginLister(cfg, logger.Log)
	originRegistry := middleware.NewDynamicOriginRegistry(originLister, 5*time.Minute, 10*time.Second, logger.Log)
	if originLister == nil {
		logger.Warn("Stage 3 dynamic CORS/CSRF origin registry has no tenant-management lister configured; CORS/CSRF stay on their static allowlists only")
	}

	wireTokenServiceRedis(tokenService, authService, userService, roleService, socialAuthService, repos, infra, cfg)

	// Email and MFA services
	emailService := services.NewEmailService(cfg)
	// Without this, EmailService.ResolveFrontendURL's configProvider branch
	// is always nil and every emitted link/sender silently uses the static
	// FRONTEND_URL env var regardless of tenant — this wiring was missing
	// entirely before this change, so ConfigProvider.FrontendURL (and by
	// extension the app-host resolution wired above) was dead code from
	// EmailService's perspective.
	emailService.SetConfigProvider(configProvider)

	// Email transactional outbox + drainer for NON-CREDENTIAL mail.
	// Behind FALCON_ID_EMAIL_OUTBOX_ENABLED (default false) so the
	// at-least-once path can be canaried without disturbing the
	// synchronous default — same discipline as the CAEP outbox.
	//
	// Credential mail (one-time codes, password-reset and magic links)
	// is NEVER queued regardless of this flag: MayQueue refuses it and
	// the table CHECK constraint refuses it again. Falcon-ID persists no
	// plaintext code today, and NIST SP 800-63B §5.1.3.2 bounds
	// out-of-band auth at 10 minutes with single use, so a retried code
	// is a dead code. See internal/services/email_delivery_policy.go.
	if cfg.EmailOutboxEnabled {
		emailOutboxRepo := repositories.NewEmailOutboxRepository(infra.DB.Pool)
		emailService.SetOutbox(emailOutboxRepo)
		emailDrainerCfg := services.DefaultEmailOutboxDrainerConfig()
		emailDrainer := services.NewEmailOutboxDrainer(emailOutboxRepo, emailService, emailDrainerCfg, logger.Log)
		// Long-lived background drainer; reaped with the process on exit,
		// same lifetime treatment as the CAEP drainer below.
		go emailDrainer.Start(context.Background()) //nolint:gosec // long-lived background drainer
		logger.Info("email outbox drainer started — at-least-once delivery for non-credential mail",
			zap.Duration("tick", emailDrainerCfg.TickInterval),
			zap.Int("batch", emailDrainerCfg.BatchSize),
		)
	}
	mfaService := services.NewMFAService(cfg, repos.User, repos.MFA, emailService, ldapService)
	passwordResetService := services.NewPasswordResetService(cfg, repos.User, repos.Token, emailService, auditService)
	passwordResetService.SetSessionRepo(repos.Session)
	passwordResetService.SetOAuthRevoker(tokenService)
	passwordPolicyService := services.NewPasswordPolicyService(repos.PasswordPolicy)
	rateLimitService := services.NewRateLimitService(repos.RateLimit)

	// HIBP breach-password check (ASVS V6 / NIST 800-63B §5.1.1.2). Wired into
	// every password-set chokepoint — signup (UserService.Create), admin/self
	// set-password (UserService.SetPassword), self-service change
	// (AuthService.ChangePassword), and forgot-password reset
	// (PasswordResetService.ResetPassword). The check uses the HIBP
	// k-anonymity range API (only the first 5 SHA-1 chars leave the process)
	// and fails OPEN on any HIBP error so a transient outage never blocks a
	// legitimate password change. Default-on; disable via
	// PASSWORD_BREACH_CHECK_ENABLED=false for air-gapped deployments.
	if cfg.PasswordBreachCheckEnabled {
		var hibpOpts []hibp.Option
		if cfg.HIBPResilienceEnabled {
			// DDIL P3.11: shared breaker + backoff around the outbound HIBP fetch.
			hibpBreaker := resilient.NewBreaker(resilient.BreakerConfig{
				FailureThreshold: cfg.HIBPBreakerFailureThreshold,
				OpenTimeout:      cfg.HIBPBreakerResetTimeout,
				OnStateChange: func(from, to resilient.State) {
					logger.Warn("HIBP circuit breaker state change",
						zap.String("from", from.String()), zap.String("to", to.String()))
				},
			})
			hibpOpts = append(hibpOpts, hibp.WithResilience(hibpBreaker, 3))
		}
		hibpClient := hibp.NewClient(hibpOpts...)
		userService.SetBreachChecker(hibpClient)
		authService.SetBreachChecker(hibpClient)
		passwordResetService.SetBreachChecker(hibpClient)
		logger.Info("HIBP breach-password check enabled (ASVS V6 / NIST 800-63B) on signup + password-change flows")
	} else {
		logger.Warn("HIBP breach-password check DISABLED via PASSWORD_BREACH_CHECK_ENABLED=false — breached passwords will be accepted")
	}

	if infra.RateLimiter != nil && cfg.RedisRateLimitEnabled {
		rateLimitService.SetRedisRateLimiter(infra.RateLimiter)
		logger.Info("Redis-based rate limiting enabled")
	}

	// Security and integration services
	ipRuleService := services.NewIPRuleService(repos.IPRule)
	apiKeyService := services.NewAPIKeyService(repos.APIKey)
	serviceAccountService := services.NewServiceAccountService(repos.ServiceAccount, repos.Role, cfg)
	serviceAccountService.SetTokenSigner(tokenService)

	oauthProviderService, err := services.NewOAuthProviderService(repos.OAuthClient, repos.User, cfg)
	if err != nil {
		logger.Fatal("Failed to initialize OAuth provider service", zap.Error(err))
	}
	if keyManager != nil {
		oauthProviderService.SetKeyManager(keyManager)
		logger.Info("KeyManager wired to OAuthProviderService (DB-persisted keys, graceful rotation)")
	}
	if infra.RedisClient != nil {
		parRedisStore := redis.NewPARStore(infra.RedisClient, "hexxlock", 0)
		oauthProviderService.SetPARStore(newRedisPARStoreAdapter(parRedisStore))
		logger.Info("PAR (RFC 9126) enabled for OAuth provider service")
	}
	// Wire the trusted-external-issuer registry into the OAuth
	// provider service. Enables /oauth/token grant_type=token-exchange
	// with subject_token_type=urn:ietf:params:oauth:token-type:jwt
	// (Talon IAP → BFF bridge). Trust at request time still requires
	// (a) iam_oauth_clients.allow_external_jwt_exchange = true on the
	// calling client AND (b) a row in
	// iam_oauth_client_trusted_external_issuers for the specific
	// (client, issuer) pair — both are configured per-application via
	// the GitOps repository' ServiceClientClaim, not at process startup.
	if repos.OAuthTrustedExternalIssuer != nil {
		oauthProviderService.SetExternalIssuerRepository(repos.OAuthTrustedExternalIssuer)
		logger.Info("RFC 8693 external-JWT token exchange enabled (Talon IAP → BFF bridge)")
	}
	// Wire the tenant repository for redirect_uri policy enforcement
	// on CreateClient / UpdateClient. Production-tier tenants reject
	// http:// + loopback redirects; demo-tier tenants permit them.
	// See internal/services/oauth_provider_redirect_uri.go for the policy.
	oauthProviderService.SetTenantTypeLookup(repos.Tenant)
	logger.Info("Tier-1 redirect_uri policy enabled (production-tier tenants reject http://localhost)")

	// Wire AuthService as the session-context provider for the OAuth
	// refresh-rotation drift detector (RefreshTokens →
	// detectSessionDrift). Enables Auth0/Okta-canonical behaviour:
	// when refresh-token rotation arrives from a different OS-class
	// or country than the linked iam_sessions row, a fresh session
	// row is cut and the rotated token re-bound to it. Without this
	// wiring the OAuth provider falls back to legacy behaviour
	// (preserves IdpSessionID verbatim, surface symptom: user sees
	// stale OS / country attribution in accounts.example.com Active
	// Sessions UI). See OAuthProviderService.sessionContextSvc doc.
	oauthProviderService.SetSessionContextService(authService)

	// Tenant suspension enforcement (R1-GAPS row 27). One shared gate (short-TTL
	// cache over iam_tenant_status; fails OPEN for unknown tenants) is consulted
	// by login, session creation, token issue/refresh, bearer-token validation
	// and the IdP SSO cookie path. Populated by the example.tenant.status
	// consumer started in background.go.
	tenantStatusRepo := tenantstatus.NewRepository(infra.DB.Pool)
	tenantStatusGate := tenantstatus.NewGate(tenantStatusRepo, 0, logger.Log)
	tokenService.SetTenantSuspensionChecker(tenantStatusGate)
	authService.SetTenantSuspensionChecker(tenantStatusGate)
	oauthProviderService.SetTenantSuspensionChecker(tenantStatusGate)
	oauthProviderService.SetPlatformAuthority(platformAuthority)
	if infra.SpiceDBClient != nil {
		// Operator token exchange (audience hexxlock-ops); stays refused until
		// OPS_OPERATOR_EXCHANGE_CLIENT_IDS lists a client.
		oauthProviderService.SetOperatorExchange(infra.SpiceDBClient)
	}

	// WO#20 tenant API keys (developer access); nil while the flag is off.
	tenantAPIKeyService := buildTenantAPIKeyService(cfg, infra, repos, auditService, oauthProviderService, tenantStatusGate, logger.Log)

	// RFC 8693 tenant token exchange (target_tenant_id): an external
	// accountant exchanges their token for a short-lived client-tenant token,
	// gated on an active iam_user_memberships row. Per-user rate limit via
	// Redis when available (a typed-nil limiter must not reach the interface).
	if infra.RateLimiter != nil {
		oauthProviderService.SetTenantExchange(repos.UserMembership, infra.RateLimiter)
	} else {
		oauthProviderService.SetTenantExchange(repos.UserMembership, nil)
	}
	logger.Info("OAuth refresh-rotation session-drift detection enabled (cuts new iam_sessions row on country/OS-class drift)")

	// Wire IdP-session AuthTime lookup so /oauth/token-minted tokens
	// carry the RFC 9470 §6.1 `auth_time` claim. Without this, every
	// access token issued by the BFF code-exchange path silently
	// dropped auth_time, downstream RequireFreshAuth gates saw
	// CurrentUser.AuthTime==0, and every step-up-protected mutation
	// (passkey delete, mfa/disable/totp, mfa/disable/email, password
	// change) 401'd indefinitely even after a fresh password+OTP
	// re-auth. The 6th layer of the redirect-loop chain closed
	// 2026-05-25; auth_time emission on /api/v1/auth/login was
	// covered earlier by !243 (GenerateAccessTokenV2 path), but the
	// OAuth /oauth/token mint path uses OAuthProviderService.
	// generateTokens (raw jwt.MapClaims, no token_service involvement)
	// and was missed in that fix.
	if infra.SessionCache != nil {
		oauthProviderService.SetSessionCacheAuthTimeSource(infra.SessionCache)
	}

	samlService, err := services.NewSAMLService(repos.SAML, repos.User, cfg)
	if err != nil {
		logger.Fatal("Failed to initialize SAML service", zap.Error(err))
	}

	// SAML SP (Inbound Federation) service
	samlSPService := services.NewSAMLSPService(cfg, repos.IDP, repos.SAMLSP, repos.User, repos.Role, repos.FedAccount, tokenService, auditService)
	// SAML Metadata Discovery service
	samlMetadataService := services.NewSAMLMetadataService(cfg, repos.SAML)

	scimService := services.NewSCIMService(repos.SCIM, repos.User, repos.Role, cfg)
	groupService := services.NewGroupService(repos.Group, repos.User, repos.Role)
	// ADR-A10 SoD: a group's role set change affects every member's
	// effective permissions — see GroupService.SetRoles.
	groupService.SetSoDService(sodService)

	// Wire GroupService as the subject-claims provider so OIDC id_tokens
	// and (scope-gated) access_tokens emit `groups` and `roles`. Without
	// this the emitter degrades gracefully to omitting both claims —
	// backward-compatible for every client that hasn't opted in via scope.
	// Claims-side failures use the package-level logger via the
	// OAuthProviderService's internal diagnostics; no per-instance zap
	// logger is required.
	oauthProviderService.SetSubjectClaimsProvider(groupService)
	orgService := services.NewOrganizationService(repos.Organization, repos.User)
	impersonationService := services.NewImpersonationService(repos.Impersonation, repos.User, repos.Session, auditService, authService)
	webhookService := services.NewWebhookService(repos.Webhook)
	deviceService := services.NewDeviceService(repos.Device)
	// Push-MFA service. Fails gracefully if EncryptionKey is unset
	// (returns nil service + non-fatal log); the cmd/handlers.go and
	// cmd/routes.go nil-guards keep the rest of the app booting.
	var pushMFAService *services.PushMFAService
	if cfg.EncryptionKey != "" && repos.PushMFA != nil {
		var pushErr error
		pushMFAService, pushErr = services.NewPushMFAService(cfg, repos.PushMFA, cfg.EncryptionKey)
		if pushErr != nil {
			logger.Log.Warn("PushMFAService init failed — push-MFA routes will return 503",
				zap.Error(pushErr))
			pushMFAService = nil
		} else if repos.User != nil {
			// Wire the user repo so RegisterDevice can flip the
			// user.mfa_enabled summary flag once a device is registered.
			// Without this the OAuth /authorize ACR step-up gate routes
			// push-only users to /auth/mfa/enrollment instead of
			// /challenge. Mirrors the TOTP / email / WebAuthn enrollment
			// flows that maintain this denormalized flag.
			pushMFAService.SetUserRepo(repos.User)
		}
	} else {
		logger.Log.Warn("PushMFAService skipped — EncryptionKey unset or repo nil")
	}
	magicLinkService := services.NewMagicLinkService(cfg, repos.MagicLink, repos.User, repos.Session, tokenService, emailService, auditService)
	magicLinkService.SetTenantRepository(repos.Tenant)
	invitationService := services.NewInvitationService(cfg, repos.Invitation, repos.User, repos.Role, repos.Session, tokenService, emailService, auditService)
	invitationService.SetTenantRepository(repos.Tenant)
	consentService := services.NewConsentService(repos.Consent, auditService)
	riskService := services.NewRiskService(repos.Risk, repos.Device, auditService)
	appAccessService := services.NewAppAccessService(repos.AppAccess, repos.OAuthClient)

	wireAuthService(authService, mfaService, riskService, deviceService, groupService, repos)
	authService.SetAppAccessService(appAccessService)

	// MFA registration-interrupt enrollment service (NIST SP 800-63B-4 §5.1):
	// when risk-based MFA fires for a user without an enrolled authenticator
	// the AuthService mints an enrollment_token via this service instead of
	// emailing a code to an unbound mailbox. Requires Redis (session cache);
	// without it the wiring is skipped and risk-MFA for unenrolled users
	// fails closed at /api/v1/auth/login (see createMFAEnrollmentInterrupt).
	var mfaEnrollmentService *services.MFAEnrollmentService
	if infra.RedisClient != nil {
		mfaEnrollmentService = services.NewMFAEnrollmentService(infra.RedisClient, mfaService, repos.User, auditService)
		authService.SetMFAEnrollmentService(mfaEnrollmentService)
		logger.Info("MFA enrollment-interrupt service wired (registration-interrupt for unenrolled risk-MFA users)")
	} else {
		logger.Warn("Redis client not available — MFA enrollment-interrupt disabled; risk-MFA for unenrolled users will fail closed")
	}

	// Account-recovery service (recovery email). Redis holds the ephemeral,
	// brute-force-bounded OTP challenge; without it the verification flow has
	// nowhere to stash the pending code, so the feature is disabled (the
	// handler is only wired when this is non-nil).
	var recoveryService *services.RecoveryService
	if infra.RedisClient != nil {
		recoveryService = services.NewRecoveryService(repos.Recovery, repos.User, emailService, infra.RedisClient, cfg, auditService)
		logger.Info("Recovery service wired (recovery-email verification)")
	} else {
		logger.Warn("Redis client not available — recovery-email verification disabled")
	}

	wireSocialAuthService(socialAuthService, mfaService, riskService, deviceService, repos, infra)
	wireSAMLSPService(samlSPService, mfaService, riskService, deviceService, repos, infra)

	// Wire assertion replay store for SAML replay prevention
	if infra.RedisClient != nil {
		replayStore := security.NewRedisReplayStore(infra.RedisClient.Redis(), false)
		samlSPService.SetReplayStore(replayStore)
		logger.Info("SAML assertion replay store enabled")
	}

	// Validate that all critical SAML SLO dependencies are wired.
	// SECURITY: Fail startup if SLO dependencies are missing — incomplete SLO is a security risk.
	if err := samlSPService.Validate(); err != nil {
		logger.Fatal("SAML SLO validation failed — required dependencies are missing", zap.Error(err))
	}

	// Initialize OPA service
	opaService, err := services.NewOPAService(cfg)
	if err != nil {
		if cfg.UseABAC {
			// SECURITY: ABAC is on but its embedded policies are broken: fail boot loudly.
			logger.Fatal("Failed to initialize OPA service while USE_ABAC is enabled", zap.Error(err))
		}
		logger.Warn("Failed to initialize OPA service, ABAC will be unavailable", zap.Error(err))
		opaService = nil
	} else {
		logger.Info("OPA service initialized")
	}

	// Initialize authorization service
	authorizationService := services.NewAuthorizationService(repos.Permission, repos.User, opaService, auditService)

	authorizationService.SetTenantSuspensionChecker(tenantStatusGate)
	authorizationService.SetSoDViolationLister(sodService)

	// Wire SpiceDB to authorization service
	if infra.SpiceDBClient != nil {
		authorizationService.SetSpiceDBClient(infra.SpiceDBClient, cfg)
	}

	// Initialize unified authorization engine
	authorizationEngine := services.NewAuthorizationEngine(repos.Permission, opaService, auditService, infra.SessionCache, infra.SpiceDBClient, cfg)
	logger.Info("Unified authorization engine initialized")

	// DDIL P3.2: enable governed offline authorization. When SpiceDB is
	// unreachable, the engine serves the signed, time-boxed last-known-good
	// decision within budget (then fails closed). The SessionCache supplies the
	// per-tenant role-version as the revocation epoch, and its role-version hook
	// propagates revocations to the offline layer so they are honoured even
	// while disconnected.
	var offlineRoleVer services.RoleVersionProvider
	if infra.SessionCache != nil {
		offlineRoleVer = infra.SessionCache
	}
	if err := services.EnableEngineOfflineAuthz(authorizationEngine, cfg, offlineRoleVer, logger.Log); err != nil {
		logger.Warn("Failed to enable DDIL offline authorization; strict fail-closed retained", zap.Error(err))
	} else if cfg.DDILOfflineAuthzEnabled {
		if infra.SessionCache != nil {
			engineForHook := authorizationEngine
			infra.SessionCache.SetRoleVersionHook(func(tenantID uuid.UUID, version int64) {
				if version < 0 {
					version = 0
				}
				services.RevokeEngineTenantOffline(engineForHook, tenantID, uint64(version))
			})
		}
		logger.Info("DDIL governed offline authorization enabled (P3.2)")
	}

	// Platform management services
	tenantService := services.NewTenantService(infra.DB.Pool, logger.Log)

	// Wire encryption service for decrypting tenant owner PII
	if infra.EncryptionService != nil {
		tenantService.SetEncryptor(infra.EncryptionService)
		logger.Info("Tenant PII decryption enabled")
	}

	// Wire Redis cache for tenant lookups
	if infra.RedisClient != nil {
		tenantCache := redis.NewTenantCacheService(infra.RedisClient, logger.Log, "iam:tenant", 5*time.Minute)
		tenantService.SetCache(tenantCache)
		logger.Info("Tenant cache enabled with 5 minute TTL")
	}

	// Realm service
	var realmService *services.RealmService
	if cfg.RealmEnabled && repos.Realm != nil {
		realmService = services.NewRealmService(repos.Realm, cfg, logger.Log)

		// Wire consolidated IDP repository for cross-DB tenant IDP queries
		if repos.IDP != nil {
			realmService.SetIDPRepository(repos.IDP)
		}

		// Wire Redis cache to realm service
		if infra.RedisClient != nil {
			realmCache := redis.NewRealmCache(infra.RedisClient, "iam:realm:", 600000000000) // 10 minutes
			realmService.SetRedisCache(realmCache)
			logger.Info("Realm Redis cache enabled with 10 minute TTL")
		}

		logger.Info("Realm service initialized",
			zap.Bool("subdomain_enabled", cfg.RealmSubdomainEnabled),
			zap.Bool("header_enabled", cfg.RealmHeaderEnabled),
			zap.Bool("url_prefix_enabled", cfg.RealmURLPrefixEnabled),
			zap.String("default_slug", cfg.RealmDefaultSlug),
		)
	}

	// -------------------------------------------------------------------------
	// Product & licensing services
	// -------------------------------------------------------------------------
	productService := services.NewProductService(repos.Product, auditService)
	licenseService := services.NewLicenseService(repos.License, repos.Product, auditService, cfg)
	productInstanceService := services.NewProductInstanceService(repos.ProductInstance, repos.Product)
	appRegistrationService := services.NewAppRegistrationService(repos.AppRegistration, auditService)

	// Product subscription resolver — populates JWT product claims from active instances.
	// Wired into BOTH the legacy /api/v1/auth/login mint path (via tokenService) AND
	// the OAuth 2.1 /oauth/token mint path (via oauthProviderService) so every token
	// issuance path carries the `products` claim. Without the OAuth wiring, tokens
	// from authorization_code + refresh_token + token-exchange grants silently
	// dropped the claim — downstream product-entitlement middleware (e.g. acmeweb
	// productSlug gate in falcon-id-client) then had no source for /app/* gating
	// decisions and bounced every user to /unauthorized.
	productSubscriptionResolver := services.NewProductSubscriptionResolver(repos.ProductInstance, repos.Product)
	tokenService.SetProductSubscriptionResolver(productSubscriptionResolver)
	oauthProviderService.SetProductSubscriptionResolver(productSubscriptionResolver)
	logger.Info("Product subscription resolver wired to token service + OAuth provider service")

	// Provisioning status service (for unified dashboard)
	provisioningStatusService := services.NewProvisioningStatusService(repos.ProductInstance, repos.InstanceDatabase)

	// -------------------------------------------------------------------------
	// Application Object / Service Principal services
	// -------------------------------------------------------------------------
	appConsentService := services.NewAppConsentService(repos.AppConsent)
	spCredentialService := services.NewSPCredentialService(repos.SPCredential)
	spSignInActivityService := services.NewSPSignInActivityService(repos.SPSignInActivity)
	applicationOwnerService := services.NewApplicationOwnerService(repos.ApplicationOwner)
	appIDPService := services.NewAppIdentityProviderService(repos.AppIDP)
	appInstallationService := services.NewAppInstallationService(repos.AppInstallation, repos.Product)
	appRoleService := services.NewAppRoleService(repos.AppRole, repos.Application)
	credentialPolicyService := services.NewCredentialPolicyService(repos.CredentialPolicy)
	consentRequestService := services.NewConsentRequestService(repos.ConsentRequest)
	registrationPolicyService := services.NewRegistrationPolicyService(repos.RegistrationPolicy)
	servicePrincipalService := services.NewServicePrincipalService(repos.ServicePrincipal)

	applicationService := services.NewApplicationService(repos.Application, repos.ServicePrincipal)

	// StaleAppDetectionService — staleSignInChecker and staleSPCounter are unexported
	// interfaces with methods not implemented by the concrete repos; pass nil for both
	// so the service can still be created and returns deterministic defaults.
	staleAppDetectionService := services.NewStaleAppDetectionService(
		repos.Application,
		nil, // staleSignInChecker — HasRecentActivity not on SPSignInActivityRepository
		nil, // staleSPCounter — GetServicePrincipalCount not on ServicePrincipalRepository
	)

	// -------------------------------------------------------------------------
	// Identity & access services
	// -------------------------------------------------------------------------
	// DelegationService SpiceDB interface uses uuid-based DeleteRelationship, which
	// is incompatible with pkg/spicedb.Client's string-based signature. Pass nil;
	// SpiceDB syncing is skipped gracefully when the client is absent.
	delegationService := services.NewDelegationService(
		repos.Delegation,
		repos.User,
		nil, // services.SpiceDBClient — interface incompatible with pkg/spicedb.Client
		auditService,
		logger.Log,
	)

	// Temp Access Pass — uses adapter pattern defined in tap_adapter.go
	tapRepoAdapter := newTempAccessPassRepoAdapter(repos.TempAccessPass)
	tempAccessPassService := services.NewTempAccessPassService(tapRepoAdapter, logger.Log)

	guestUserService := services.NewGuestUserService(repos.GuestUser, repos.Role, auditService)

	// JITAccessService's SpiceDB interface matches *spicedb.Client.WriteUserRoleUntil/
	// DeleteUserRole directly (uuid-based role#member writes) so the real client
	// satisfies it with no adapter. SpiceDB is the actual enforcement boundary
	// for a JIT grant — AuthorizationEngine.CheckPermission is SpiceDB-only — so
	// this must never be nil in an environment that serves traffic.
	jitAccessService := services.NewJITAccessService(
		repos.JITAccess,
		repos.JITEligible,
		repos.StepUpVerification,
		repos.User,
		infra.SpiceDBClient,
		auditService,
		logger.Log,
	)
	var revokeClient interface {
		DeleteUserRole(context.Context, uuid.UUID, uuid.UUID, uuid.UUID) (string, error)
	}
	if infra.SpiceDBClient != nil {
		revokeClient = infra.SpiceDBClient
	}
	roleRevokeDrainer := services.NewRoleRevokeDrainer(infra.DB.Pool, revokeClient, logger.Log)
	userService.SetRoleRevokeDrainer(roleRevokeDrainer)
	jitAccessService.SetRoleRevokeDrainer(roleRevokeDrainer)

	// PlatformJITService — R1 platform plane: JIT elevation + break-glass.
	// infra.SpiceDBClient (*spicedb.Client) satisfies platformSpiceDBClient
	// structurally via WritePlatformElevation/DeletePlatformElevation
	// (pkg/spicedb/platform.go) — no adapter needed, same pattern as
	// jitAccessService above. repos.PlatformElevation itself satisfies
	// platformUserTenantLookup via GetUserTenantID.
	platformJITService := services.NewPlatformJITService(
		repos.PlatformElevation,
		repos.PlatformElevation,
		infra.SpiceDBClient,
		auditService,
		logger.Log,
	)

	// AccessReviewService role/group interfaces require ListUserRoleAssignments /
	// ListUserGroupMemberships — methods not present on the concrete repos yet.
	// Pass nil; the service handles missing repos by seeding empty review items.
	accessReviewService := services.NewAccessReviewService(
		repos.AccessReview,
		nil, // accessReviewRoleRepo — ListUserRoleAssignments not on RoleRepository
		nil, // accessReviewGroupRepo — ListUserGroupMemberships not on GroupRepository
		auditService,
		logger.Log,
	)

	emailDomainService := services.NewEmailDomainService(repos.EmailDomainRegistry)

	// RealmDiscoveryService — identifier-first HRD (Azure Entra ID pattern).
	// The consumer tenant ID is the fallback for email domains not registered in
	// tenant_domains. Defaults to WellKnownTenantDefaultID but can be overridden
	// via CONSUMER_TENANT_ID for deployments that use a dedicated consumer tenant.
	consumerTenantID := models.WellKnownTenantDefaultID
	if raw := os.Getenv("CONSUMER_TENANT_ID"); raw != "" {
		if parsed, parseErr := uuid.Parse(raw); parseErr == nil {
			consumerTenantID = parsed
		} else {
			logger.Warn("CONSUMER_TENANT_ID is not a valid UUID — using default", zap.String("value", raw))
		}
	}
	realmDiscoveryService := services.NewRealmDiscoveryService(
		repos.TenantDomain,
		repos.Tenant,
		consumerTenantID,
	)

	tenantBrandingService := services.NewTenantBrandingService(repos.TenantBranding)
	tenantQuotaService := services.NewTenantQuotaService(repos.TenantQuota, logger.Log)
	idpRoutingService := services.NewIDPRoutingService(repos.IDPRouting)
	idpTenantOverrideService := services.NewIDPTenantOverrideService(repos.IDPTenantOverride, repos.IDP)

	// CAEService — continuous-access-evaluation publisher per OpenID
	// Continuous Access Evaluation Profile. Used by:
	//
	//   - WebAuthnService → CAECredentialCompromised on sign-count
	//     regression (W3C WebAuthn §6.1.3 clone evidence).
	//   - OAuthProviderService → CAESessionRevoked on token revocation.
	//   - AuthService → CAEPasswordChanged on password change /reset.
	//   - MFAService → CAEMFARevoked on factor removal.
	//   - RoleService → CAERoleRevoked on role permission reduction.
	//
	// The publisher adapter is thin (delegates to *redis.Client); when
	// Redis is unavailable the service is left nil and every publish-
	// site short-circuits — DB-layer revocations still hold but the
	// real-time fan-out to receivers (Talon IAP, SSE subscribers) is
	// degraded to "next-token-refresh propagation" until Redis returns.
	var caeService *services.CAEService
	if infra.RedisClient != nil {
		caeService = services.NewCAEService(&redisCAEPublisher{client: infra.RedisClient}, logger.Log)
	}

	// Wire CAEService into every service that has a publish-site. Each
	// service's SetCAEService is nil-safe (no-op when caeService is
	// nil), so this block is the single place to add new wiring without
	// touching service constructors. Discovered during the tier-1
	// verification pass: the existing publishers (RevokeToken,
	// WebAuthn) were dead code because no SetCAEService callsite
	// existed for OAuthProviderService and the other services had no
	// publish-site at all.
	if caeService != nil {
		oauthProviderService.SetCAEService(caeService)
		authService.SetCAEService(caeService)
		mfaService.SetCAEService(caeService)
		roleService.SetCAEService(caeService)
		passwordResetService.SetCAEService(caeService)
		logger.Info("CAEService wired to OAuth/Auth/MFA/Role/PasswordReset services (continuous access evaluation)")
	}

	// Single access-termination path (sessions, OAuth tokens, IdP SSO cookies,
	// JWT blacklist, BCL, CAE). Redis-backed deps are passed only when present
	// so the terminator's nil checks see true nil interfaces. BCL and the CAEP
	// emitter are attached later (handlers.go / emitter init).
	var (
		termSSO       services.UserAccessTerminatorSSOCache
		termBlacklist services.UserAccessTerminatorBlacklist
	)
	if infra.SessionCache != nil {
		termSSO = infra.SessionCache
	}
	if infra.TokenBlacklist != nil {
		termBlacklist = infra.TokenBlacklist
	}
	accessTerminator := services.NewUserAccessTerminator(repos.Session, tokenService, termSSO, termBlacklist, nil, caeService, services.UserBlacklistTTL(cfg), logger.Log)
	userService.SetAccessTerminator(accessTerminator)
	authService.SetAccessTerminator(accessTerminator)
	mfaService.SetAccessTerminator(accessTerminator)
	passwordResetService.SetAccessTerminator(accessTerminator)
	scimService.SetAccessTerminator(accessTerminator)

	// Phase 2 (talon-service-tokens) — wire the audit emitter into
	// OAuthProviderService so ClientCredentialsGrant publishes a
	// SecurityCategoryAuthentication event for every machine-token
	// mint. Counterpart to TokenService.LogLogin for the human path.
	// Setter is nil-safe; auditService is constructed earlier in this
	// function so unconditional wiring is safe.
	oauthProviderService.SetAuditService(auditService)
	logger.Info("AuditService wired to OAuthProviderService (machine-token mint audit funnel)")

	// Phase C (2026-05-26): SecurityNotificationService — user-facing
	// emails on security events (password change, account lock, MFA
	// factor removal, suspicious login). Mirrors caeService wiring
	// pattern. Nil-safe — when EmailService isn't configured the
	// notifier's internal IsConfigured guard short-circuits and the
	// underlying CAE/DB writes remain authoritative.
	var securityNotifier *services.SecurityNotificationService
	if emailService != nil {
		securityNotifier = services.NewSecurityNotificationService(emailService, nil)
		authService.SetSecurityNotificationService(securityNotifier)
		mfaService.SetSecurityNotificationService(securityNotifier)
		logger.Info("SecurityNotificationService wired to Auth + MFA services (Phase C — out-of-band email on security events)")
	}

	// WebAuthn / FIDO2 wiring. RPID is the eTLD+1 root that scopes every
	// credential — it is immutable per credential, so changing it after any
	// passkey is registered invalidates all of them. RPOrigins MUST list
	// every host running the login or accounts UI; subdomains of RPID are
	// not auto-trusted.
	webAuthnDisplayName := cfg.WebAuthnRPDisplayName
	if webAuthnDisplayName == "" {
		webAuthnDisplayName = "HexxLock"
	}
	var webAuthnService *services.WebAuthnService
	if cfg.WebAuthnRPID != "" && len(cfg.WebAuthnRPOrigins) > 0 && infra.RedisClient != nil {
		webAuthnSessionCache := services.NewWebAuthnSessionCache(infra.RedisClient)
		var waErr error
		webAuthnService, waErr = services.NewWebAuthnService(
			repos.WebAuthn,
			repos.User,
			webAuthnSessionCache,
			auditService,
			caeService,
			logger.Log,
			services.WebAuthnConfig{
				RPID:          cfg.WebAuthnRPID,
				RPDisplayName: webAuthnDisplayName,
				RPOrigins:     cfg.WebAuthnRPOrigins,
			},
		)
		if waErr != nil {
			logger.Fatal("Failed to initialise WebAuthn service", zap.Error(waErr))
		}
	} else {
		logger.Log.Warn("WebAuthn service disabled — set WEBAUTHN_RP_ID + WEBAUTHN_RP_ORIGINS and ensure Redis is reachable to enable passkey login")
	}

	// Wire WebAuthn into the registration-interrupt enrollment flow so
	// admin-passkey-required interrupts can drive users through a FIDO2
	// ceremony from the existing /api/v1/auth/mfa/enrollment surface. No-op
	// when either dependency is missing — the InitWebAuthn / VerifyWebAuthn
	// methods then return a "service not wired" error to the handler.
	if mfaEnrollmentService != nil && webAuthnService != nil {
		mfaEnrollmentService.SetWebAuthn(webAuthnService)
	}

	// Wire WebAuthnService into AuthService so the
	// /api/v1/auth/mfa/webauthn/{begin,finish} endpoints (Phase A.2)
	// can issue + verify assertion ceremonies bound to a temp MFA
	// session. Nil-safe — when unset (test harness, partial
	// deployments), BeginWebAuthnMFA / CompleteWebAuthnMFA return
	// "webauthn service not configured" and the handler surfaces 503.
	if webAuthnService != nil {
		authService.SetWebAuthnService(webAuthnService)
	}

	// ZTNA enrollment witness state + TOTP fallback (migration 0039). The
	// shared TOTP replay claim and the witness state both live in Redis; with
	// no Redis the witness endpoints fail closed (503).
	var witnessService *services.WitnessService
	if witnessRedis := witnessRedisClient(infra); witnessRedis != nil {
		mfaService.SetTOTPReplayStore(witnessRedis)
		if repos.WebAuthn != nil {
			var policy witnessPolicySource = allowAllWitnessPolicy{}
			if repos.Realm != nil {
				policy = repos.Realm
			}
			witnessService = services.NewWitnessService(services.WitnessServiceDeps{
				Redis:       witnessRedis,
				Users:       repos.User,
				Passkeys:    repos.WebAuthn,
				Policy:      policy,
				MFA:         mfaService,
				Minter:      tokenService,
				Audit:       auditService,
				Notifier:    securityNotifier,
				TOTPEnabled: cfg.WitnessTOTPEnabled,
				Logger:      logger.Log,
			})
			logger.Info("Device witness service wired", zap.Bool("totp_fallback_enabled", cfg.WitnessTOTPEnabled))
		}
	}
	if repos.Realm != nil && realmService != nil {
		realmService.SetWitnessPolicyRepository(repos.Realm)
		realmService.SetSessionPolicyRepository(repos.Realm)
	}
	if repos.Realm != nil && infra.SessionCache != nil {
		realmRepo := repos.Realm
		infra.SessionCache.SetRealmCapResolver(func(ctx context.Context, tenantID uuid.UUID) (time.Duration, bool, error) {
			secs, ok, err := realmRepo.SessionAbsoluteTTLSecondsByTenant(ctx, tenantID)
			return time.Duration(secs) * time.Second, ok, err
		})
	}

	// TokenExchangeService requires GenerateServiceToken which TokenService doesn't
	// implement. Pass nil; the service issues tokens via its own JWT generation
	// path when the token service is absent.
	tokenExchangeService := services.NewTokenExchangeService(
		repos.WorkloadIdentity,
		nil, // tokenExchangeTokenService — GenerateServiceToken not on TokenService
		logger.Log,
	)

	// Token endpoint for managed identity self-registration flows.
	// Falls back to SAML SP base URL if a dedicated service URL is not configured.
	managedIdentityTokenEndpoint := cfg.SAMLSPBaseURL
	managedIdentityService := services.NewManagedIdentityService(
		repos.ServicePrincipal,
		repos.BootstrapToken,
		managedIdentityTokenEndpoint,
	)

	scpService := services.NewSCPService(repos.SCP, logger.Log)

	// Signup service — uses adapters defined in signup_adapters.go and
	// tenant_management_registrar.go
	signupOTPKey, err := services.DeriveSignupOTPKey(cfg.TokenHashSalt)
	if err != nil {
		logger.Fatal("Failed to derive signup OTP key", zap.Error(err))
	}
	signupService := services.NewSignupService(
		repos.SignupRequest,
		emailService,
		&signupTenantCreatorAdapter{repo: repos.Tenant, realmRepo: repos.Realm},
		newHTTPTenantManagementRegistrar(cfg.TenantManagementInternalURL),
		&signupUserCreatorAdapter{svc: userService},
		&signupUserLookupAdapter{repo: repos.User},
		cfg.ConsumerEmailDomain,
		cfg.SignupDefaultPlanCode,
		signupOTPKey,
	)

	realmFederationService := services.NewRealmFederationService(repos.RealmFederation, auditService)

	// Realm DB provisioner — requires encryption service AND a Kubernetes
	// client. The k8s client lets the provisioner enroll per-tenant
	// LogicalDatabase + DatabaseSchema CRs with Keystone (replacing the
	// embedded golang-migrate path retired in phase-2b MR4). Building the
	// in-cluster client is a hard dependency: no client → no realm
	// onboarding (the provisioner stays nil and ProvisionDatabase callers
	// receive a "realm provisioning unavailable" error path).
	var realmDBProvisioner *services.RealmDBProvisioner
	if infra.EncryptionService != nil {
		keystoneK8s, err := keystoneclient.New()
		if err != nil {
			logger.Log.Warn("Realm DB provisioner disabled — Keystone k8s client unavailable",
				zap.Error(err),
				zap.String("hint", "the falcon-id pod needs automountServiceAccountToken=true and a RoleBinding to ClusterRole/keystone-tenant-enroller (see the GitOps repository platform/keystone/resources/falcon-id/rolebinding-tenant-enroller.yaml)"),
			)
		} else {
			realmDBProvisioner = services.NewRealmDBProvisioner(
				infra.DB.Pool,
				infra.EncryptionService,
				repos.RealmDatabase,
				keystoneK8s,
				services.RealmDBProvisionerConfig{},
			)
		}
	}

	// -------------------------------------------------------------------------
	// Platform & compliance services
	// -------------------------------------------------------------------------
	conditionalAccessService := services.NewConditionalAccessService(infra.DB.Pool)

	compliancePolicyEngine := services.NewCompliancePolicyEngine(infra.DB.Pool)
	complianceScheduler := services.NewComplianceScheduler(compliancePolicyEngine, infra.DB.Pool, 24*time.Hour)
	complianceReportService := services.NewComplianceReportService(infra.DB.Pool)

	// Immutable audit — no concrete store wired yet; service initializes with nil store and
	// degrades gracefully (audit integrity endpoints return errors when store is absent).
	immutableAuditService := services.NewImmutableAuditService(nil, logger.Log)

	// Session analytics — backed by go-redis (peak tracking) and pgxpool (DB queries).
	// Both dependencies are optional; the service degrades gracefully when either is nil.
	var sessionAnalyticsService *services.SessionAnalyticsService
	{
		var goRedisForAnalytics *goredis.Client
		if infra.RedisClient != nil {
			goRedisForAnalytics = infra.RedisClient.Redis()
		}
		sessionAnalyticsService = services.NewSessionAnalyticsService(goRedisForAnalytics, infra.DB.Pool, logger.Log)
	}

	usageMeteringService := services.NewUsageMeteringService(repos.UsageRecord)

	// Threat correlation — uses SIEM service internally; pass nil SIEM for now (graceful degradation)
	threatCorrelationService := services.NewThreatCorrelationService(infra.DB.Pool, nil, auditService, logger.Log)

	// ITDR — query/admin endpoints. Pipeline=nil means the real-time
	// detection loop is OFF (no new threats are produced), but every
	// frontend GET/POST against /platform/security/{threats,detection-rules}
	// serves from the repo. The pipeline can be wired later via
	// itdrService.SetDetectionPipeline(...) when Redis streams come up.
	itdrService := services.NewITDRService(repos.ITDR, nil, logger.Log)

	routingWebhookService := services.NewRoutingWebhookService(repos.RoutingWebhook)

	// SpiceDB reconciler & tenant bootstrap (both nil-safe)
	var spiceDBReconciler *services.SpiceDBReconciler
	var tenantBootstrapService *services.TenantBootstrapService
	// feat/seat-quota-reconciler — constructed below, once cfg/logger are in
	// scope, only when outbound OAuth creds allow it (nil-safe).
	var seatQuotaReconciler *services.SeatQuotaReconciler
	if infra.SpiceDBClient != nil {
		spiceDBReconciler = services.NewSpiceDBReconciler(infra.SpiceDBClient, infra.DB.Pool, cfg)
		tenantBootstrapService = services.NewTenantBootstrapService(infra.SpiceDBClient)
		// Wildcard role grants (e.g. core:parties:*) expand against the catalog.
		tenantBootstrapService.SetPermissionCatalog(repos.Permission)
		// Keep SpiceDB role-membership writes synchronous with the team
		// role-assignment path (UserService.SetUserRoles) instead of relying
		// solely on spiceDBReconciler's scheduled pass (24h in production).
		userService.SetSpiceDBClient(infra.SpiceDBClient)
	}

	// Role templates (the product roadmap §4.1): module-published versioned
	// starter-role catalogs, distinct from the hardcoded AcmeApp
	// catalog (services.AcmeAppRoleProvisioner, wired further below).
	// templateRoleProvisioner materializes/reconciles tenant roles from
	// iam_role_templates; wired into permissionService (manifest validation
	// on POST /internal/v1/permissions/register) and into
	// provisioningConsumer (the "module granted" trigger — see
	// services.WithTemplateRoleProvisioner). tenantBootstrapService may be
	// nil (SpiceDB relation sync then skipped), same nil-safety as above.
	roleTemplateValidator := services.NewRoleTemplateValidator(repos.RoleTemplate)
	templateRoleProvisioner := services.NewTemplateRoleProvisioner(
		repos.Role,
		repos.RoleTemplate,
		repos.Permission,
		tenantBootstrapService,
	)
	permissionService.SetRoleTemplateSupport(repos.RoleTemplate, roleTemplateValidator, templateRoleProvisioner)
	roleTemplateService := services.NewRoleTemplateService(repos.RoleTemplate, permissionService, templateRoleProvisioner)

	// Discover service — wires all repos needed for Home Realm Discovery
	idpTenantOverrideForDiscover := services.NewIDPTenantOverrideService(repos.IDPTenantOverride, repos.IDP)
	discoverService := services.NewDiscoverService(
		repos.EmailDomainRegistry,
		repos.Tenant,
		repos.User,
		repos.IDP,
		repos.TenantBranding,
		idpTenantOverrideForDiscover,
	)
	// Wire the optional WebAuthn repo so the discover response carries
	// has_passkey for known users. Lets the login UI render a "Sign in
	// with passkey" button for users whose row has registered creds —
	// critical for passwordless / passkey-only accounts where the
	// password field is meaningless. Fail-safe when nil (has_passkey
	// always false → UI falls back to password-only UX).
	if repos.WebAuthn != nil {
		discoverService.SetWebAuthnRepo(repos.WebAuthn)
	}

	// Host-based tenant discovery — powers the unified-dashboard SDK's
	// runtime host→tenant lookup for multi-tenant SaaS custom domains
	// (e.g., crm.acme-corp.com). 5-minute positive / 30-second negative
	// in-process LRU per the cross-vendor research consensus
	// (Auth0/Okta/Entra B2C/Cognito/Cloudflare Access).
	// nil DNS resolver → service uses net.DefaultResolver. Tests pass
	// a mock resolver; production goes through the cluster's DNS for
	// TXT lookups when verifying customer-claimed hostnames.
	hostDiscoveryService := services.NewHostDiscoveryService(repos.TenantHost, nil, logger.Log)
	// Wire the slug-lookup dependency for DiscoverBySlug (GET
	// /internal/v1/tenant-discovery/by-slug) — the SDK middleware's
	// subdomain fail-closed check. See TenantSlugRepoIface's doc
	// comment on why this queries iam_tenants (repos.Tenant) rather
	// than iam_tenant_hosts.
	hostDiscoveryService.SetTenantRepository(repos.Tenant)

	// Onboarding slug-confirmation service (PATCH /api/v1/onboarding/slug).
	// Persists the rename in tenant-management via an OAuth-authenticated
	// S2S client and activates "<slug>.<TenantApexDomain>" in the
	// hostDiscoveryService instance above. nil when outbound S2S creds or
	// TENANT_MANAGEMENT_INTERNAL_URL are unset (fresh initdb / dev-without-
	// Vault boots) — mirrors buildQuotaClient's fallback posture.
	var onboardingSlugService *services.OnboardingSlugService
	if slugUpdaterHTTP := buildTenantManagementSlugUpdaterHTTPClient(cfg, logger.Log); slugUpdaterHTTP != nil {
		slugUpdater := newHTTPTenantManagementSlugUpdater(cfg.TenantManagementInternalURL, slugUpdaterHTTP)
		// repos.Tenant (*repositories.TenantRepository) satisfies
		// services.LocalTenantSlugWriter via its UpdateSlug method —
		// the local iam_tenants write-back ConfirmSlug needs alongside
		// the tenant-management push above.
		onboardingSlugService = services.NewOnboardingSlugService(slugUpdater, repos.Tenant, hostDiscoveryService, cfg.TenantApexDomain)
	} else {
		logger.Log.Warn("onboarding slug endpoint disabled: outbound S2S client to tenant-management unavailable")
	}

	// Onboarding status-read service (GET /api/v1/auth/onboarding/status).
	// Reads slug_confirmed_at from tenant-management via a read-scoped
	// (platform:tenants:read) S2S client — the SAME scope svc-falcon-id
	// already holds for other reads (see cmd/background.go), so no new
	// ServiceClientClaim grant is required. Deliberately scoped to the
	// onboarding-entry path only, NOT the hot GET /me/settings path, and
	// deliberately NOT sourced via the Kafka reverse-projection into
	// iam_tenants (ADR-0029 intentionally keeps that projection to
	// status+metadata only, dropping plan/type and this field). nil when
	// outbound S2S creds or TENANT_MANAGEMENT_INTERNAL_URL are unset,
	// mirroring onboardingSlugService's own fallback posture.
	var onboardingStatusService *services.OnboardingStatusService
	if statusReaderHTTP := buildTenantManagementStatusReaderHTTPClient(cfg, logger.Log); statusReaderHTTP != nil {
		statusReader := newHTTPTenantManagementStatusReader(cfg.TenantManagementInternalURL, statusReaderHTTP)
		onboardingStatusService = services.NewOnboardingStatusService(statusReader)
	} else {
		logger.Log.Warn("onboarding status endpoint disabled: outbound S2S client to tenant-management unavailable")
	}

	// Placeholder workspace name ("My Company") replacement: S2S rename for
	// business's first-legal-entity hook, mirror of saved names into
	// tenant-management, and the platform-admin backfill.
	tenantWorkspaceNameService := buildTenantWorkspaceNameService(cfg, repos.Tenant, logger.Log)

	// Auth hooks service — backed by hook engine from platform-services/shared
	hookEngine := hooks.NewHookEngine(logger.Log)
	authHooksService := services.NewAuthHooksService(hookEngine, logger.Log)

	// -------------------------------------------------------------------------
	// Enterprise integration wiring (GAPs 1-8)
	// -------------------------------------------------------------------------

	// P0: Wire realm resolver to UserService (Entra ID "home tenant" pattern)
	if realmService != nil {
		userService.SetRealmResolver(realmService)
		logger.Info("Realm resolver wired to UserService for tenant→realm mapping")
	}

	// feat/seat-quota-enforcement: wire quota-service client to UserService
	// so Create/Delete enforce and track per-tenant seat (resource_type=
	// "users") usage. Nil-safe — buildQuotaClient logs and returns nil
	// (enforcement stays a no-op) when outbound OAuth creds or the quota
	// service URL are not configured, matching buildTenantBootstrapClient's
	// fallback posture in cmd/background.go for the same ServiceClientID/
	// ServiceClientSecret pair.
	if quotaClient := buildQuotaClient(cfg, logger.Log); quotaClient != nil {
		userService.SetQuotaClient(quotaClient)
		logger.Info("Quota-service client wired to UserService for seat-quota enforcement",
			zap.String("quota_service_url", cfg.QuotaServiceURL),
			zap.Bool("enforcement_enabled", cfg.QuotaEnforcementEnabled),
		)
	}

	// feat/seat-quota-reconciler: periodic absolute recount of billable
	// seats per tenant, on top of the synchronous check/increment/decrement
	// path above — see SeatQuotaReconciler's doc comment for why seats (a
	// STOCK) need this in addition to deltas. Uses a separate authenticated
	// HTTP client scoped to quota:admin (distinct from quota:usage:read/
	// update above) since quota-service's admin/reconcile route sits
	// behind a stricter permission gate.
	if seatQuotaHTTP := buildSeatQuotaReconcilerHTTPClient(cfg, logger.Log); seatQuotaHTTP != nil {
		seatQuotaReconciler = services.NewSeatQuotaReconciler(infra.DB.Pool, cfg.QuotaServiceURL, seatQuotaHTTP, cfg)
		logger.Info("Seat-quota reconciler wired",
			zap.String("quota_service_url", cfg.QuotaServiceURL),
			zap.Bool("reconciler_enabled", cfg.SeatQuotaReconcilerEnabled),
			zap.Duration("reconciler_interval", cfg.SeatQuotaReconcilerInterval),
		)
	}

	// Employee-class (ESS) seats never count against the seat quota (R-HR WP-21): the quota
	// paths ask the membership ledger, and the expiry worker switches lapsed accounts off.
	userService.SetSeatFreeChecker(repos.UserMembership)
	userService.SetSeatMembershipLifecycle(repos.UserMembership)
	employeeAccessService := services.NewEmployeeAccessService(repos.User, repos.UserMembership, tenantBootstrapService, logger.Log)
	employeeAccessExpiry := services.NewEmployeeAccessExpiryWorker(infra.DB.Pool, repos.UserMembership, employeeAccessService, cfg.EmployeeAccessExpiryInterval)
	hrEmploymentSync := services.NewHREmploymentSyncService(repos.HREmploymentSync, repos.User, userService, repos.UserMembership, templateRoleProvisioner, tenantBootstrapService)

	// GAP 8: Product manifest → Permission auto-registration
	productService.SetPermissionRegistrar(permissionService)
	logger.Info("Product permission auto-registration enabled")

	// GAP 4: Email domain → HRD login routing
	authService.SetLoginDiscoverer(discoverService)
	logger.Info("HRD login discovery enabled for email-based tenant resolution")

	// GAP 2: Module entitlement → Permission filtering
	var entitlementChecker services.ModuleEntitlementChecker
	if repos.ProductInstance != nil && repos.Product != nil {
		entitlementChecker = services.NewDefaultModuleEntitlementChecker(repos.ProductInstance, repos.Product)
		services.SetEngineModuleEntitlementChecker(authorizationEngine, entitlementChecker)
		permissionService.SetModuleEntitlementChecker(entitlementChecker)
		roleService.SetModuleEntitlementChecker(entitlementChecker)
		logger.Info("Module entitlement checker wired to authorization engine, permission service, and role service")
	}

	// GAP 1: Subscription → Provisioning bridge
	subscriptionBridge := services.NewSubscriptionProvisioningBridge(repos.ProductInstance, repos.Product)
	logger.Info("Subscription provisioning bridge initialized")

	// GAP 1b: Provisioning orchestrator — the reconciler that actually
	// advances a "pending" iam_product_instances row through
	// pending → creating → migrating → seeding → configuring_auth →
	// registering_service → active. The orchestrator, its Kafka worker,
	// and its consumer all existed in code but were never started from any
	// binary (verified 2026-09-10: NewProvisioningOrchestrator had zero
	// callers outside its own definition and _test.go files) — every
	// product instance ever created via the subscription-activated webhook
	// was stuck in "pending" forever with nothing to reconcile it.
	//
	// dbProvisioner/spiceDB are nil for now: no product currently requires
	// per-tenant DB provisioning or SpiceDB relationship writes for its
	// entitlement to be meaningful. AcmeWeb in particular is shared-schema —
	// the one existing exampletenant iam_product_instances row has all
	// database_* columns null (see the GitOps repository
	// migration-bundle-acmeweb-product-and-hexxlock-entitlement.yaml, which
	// documents the same reasoning). With both nil, stepCreate/
	// stepConfigureAuth/stepRegisterService each no-op their real work — but
	// Reconcile() only ever advances ONE state per call (verified against a
	// real Postgres in internal/services/acmeweb_entitlement_e2e_test.go); a
	// fresh "pending" instance still has to pass through creating→
	// migrating→seeding→configuring_auth→registering_service→active, one
	// tick at a time. A product that DOES need real per-tenant DB
	// provisioning must wire a *ProductDBProvisioner here before it can
	// safely rely on this orchestrator.
	//
	// ReconcileInterval is set to 5s (default is 30s) specifically so a
	// self-service signup's acmeweb entitlement converges to "active" in
	// single-digit seconds after the async Reconcile() kicked off by
	// ProvisioningConsumer.HandleSubscriptionActivated advances it past the
	// first state — at the 30s default, the full 5-step walk could take up
	// to ~2.5 minutes of a new user staring at a 403. The advisory-lock
	// leader election and the 50-row-per-tick cap keep this cheap even at
	// this interval.
	provisioningOrchestrator := services.NewProvisioningOrchestrator(
		repos.ProductInstance,
		repos.Product,
		nil, // dbProvisioner — see comment above
		nil, // spiceDB — see comment above
		infra.DB.Pool,
		services.ProvisioningOrchestratorConfig{
			ReconcileInterval: 5 * time.Second,
		},
	)
	provisioningOrchestrator.Start(context.Background())
	logger.Info("Provisioning orchestrator started — pending product instances now reconcile to active")

	// provisioningConsumer drives product-entitlement provisioning through
	// the exact same pipeline a billing subscription.activated webhook
	// would use (Provision → async Reconcile). Reused below by the
	// post-signup hook so self-service signup never fabricates an "active"
	// row directly.
	provisioningConsumer := services.NewProvisioningConsumer(
		productInstanceService,
		provisioningOrchestrator,
		services.WithTemplateRoleProvisioner(templateRoleProvisioner, repos.Product),
	)

	// GAP 6: DNS domain verification worker
	domainVerificationWorker := services.NewDomainVerificationWorker(repos.EmailDomainRegistry, nil)

	// Tenant-host re-verification worker. Daily TXT recheck of
	// every active + pending host; auto-suspends after 14
	// consecutive failures. cacheInvalidate hook punches through
	// HostDiscoveryService's LRU on state transitions so the next
	// /internal/v1/tenant-discovery read sees the new state.
	tenantHostVerificationWorker := services.NewTenantHostVerificationWorker(
		repos.TenantHost,
		nil, // nil DNSResolver → net.DefaultResolver
		hostDiscoveryService.Invalidate,
		logger.Log,
	)
	logger.Info("Domain verification worker initialized")

	// GAP 3 + GAP 5: Post-signup hook (default app access + subdomain creation)
	defaultAccessGranter := services.NewDefaultAccessGranter(
		repos.DefaultAccessPolicy,
		repos.Role,
		&roleAssignerAdapter{userRepo: repos.User},
		&groupServiceAdapter{groupSvc: groupService},
		&userTenantValidator{userRepo: repos.User},
	)
	postSignupProvisioner := services.NewPostSignupProvisioner(defaultAccessGranter, nil, nil)
	// Wire the consumer-role assigner: assigns the consumer_user role
	// (bootstrapped by cmd/consumer_role_bootstrap.go) to every
	// personal-account signup. Frontend conditional rendering keys
	// off this role to hide owner-only tenant-settings pages.
	postSignupProvisioner.SetConsumerRoleAssigner(&consumerRoleAssignerAdapter{
		roleRepo: repos.Role,
		userRepo: repos.User,
	})
	// Wire the founder-role assigner: grants the founding user of every
	// business-account signup their new tenant's org_admin role, lazily
	// creating that per-tenant role row on first use. Without this, no
	// business signup ever gets any role on their own tenant, so
	// onboarding step 3 (PATCH .../onboarding/slug, which requires a
	// tenant-admin-level role) 403s for every business signup.
	postSignupProvisioner.SetFounderRoleAssigner(&founderRoleAssignerAdapter{
		roleRepo:        repos.Role,
		userRepo:        repos.User,
		tenantBootstrap: tenantBootstrapService,
	})
	// Wire the AcmeApp marketing role model provisioner: creates
	// Owner/Admin/Marketing Manager/Editor/Analyst/Billing for the new
	// tenant and assigns the founding user Owner, in addition to the
	// org_admin grant above. Without this, only today's manually-seeded
	// tenants have real marketing roles and every future signup is stuck
	// with org_admin's flat all-or-nothing team permissions.
	//
	// Constructed once and also returned on the Services struct (below) so
	// the same instance backs the admin backfill endpoint
	// (the platform role-backfill endpoint) that provisions the
	// role catalog for tenants that existed before this provisioner was
	// wired into signup - see cmd/handlers.go.
	acmeappRoleProvisioner := services.NewAcmeAppRoleProvisioner(
		repos.Role,
		repos.Permission,
		repos.User,
		tenantBootstrapService,
	)
	postSignupProvisioner.SetAcmeAppRoleProvisioner(acmeappRoleProvisioner)
	// Grant the tenant's AcmeWeb product entitlement on signup completion —
	// otherwise every self-service tenant gets a tenant + user but no
	// iam_product_instances row, and its first login 403s at
	// /unauthorized?reason=product_not_entitled (falcon-id-client
	// middleware gates on the JWT `products` claim, which is populated
	// exclusively from ACTIVE iam_product_instances rows). Routed through
	// provisioningConsumer so self-service signup uses the identical
	// pending→reconcile pipeline a billing webhook would use.
	postSignupProvisioner.SetProductEntitlementProvisioner(provisioningConsumer, models.WellKnownProductAcmeWeb)
	// Cardless trial start (business accounts only — see TrialStarter's and
	// step 7's doc comments in signup_post_provisioner.go for why this is
	// distinct from the product-entitlement step above, and why it stays
	// best-effort/non-fatal). nil when outbound S2S creds or
	// SUBSCRIPTION_MANAGEMENT_INTERNAL_URL are unset (fresh initdb / dev-
	// without-Vault boots) — mirrors buildQuotaClient's fallback posture.
	if trialStarterHTTP := buildSubscriptionManagementTrialStarterHTTPClient(cfg, logger.Log); trialStarterHTTP != nil {
		postSignupProvisioner.SetTrialStarter(
			newHTTPSubscriptionManagementTrialStarter(cfg.SubscriptionManagementInternalURL, trialStarterHTTP),
		)
	} else {
		logger.Log.Warn("onboarding trial-start step disabled: outbound S2S client to subscription-management unavailable")
	}
	// Same resolved config value passed to services.NewSignupService above —
	// both sites read cfg.SignupDefaultPlanCode exactly once, so they can't
	// drift apart onto different plans.
	postSignupProvisioner.SetDefaultPlanCode(cfg.SignupDefaultPlanCode)
	// SSF emitter — Phase 2 flips from NoOp to the real CAEPEmitter
	// when KeyManager is wired (it always is in production; nil only
	// in test fixtures). The CAEPEmitter implements SSFEventEmitter
	// AND adds EmitSessionRevoked + EmitCredentialChange so AuthService
	// can fire CAEP 1.0 SETs on logout. Stream subscriptions live in
	// iam_ssf_streams (CRUD via the SSF management API in
	// internal/handlers/ssf_handler.go); per-event push delivery is
	// best-effort + log-on-failure in Phase 1 — Phase 2 will add a
	// PG-backed outbox + drainer modelled on
	// backchannel_logout_drainer.go for at-least-once delivery + RFC
	// 8936 poll.
	if keyManager != nil {
		caepEmitter, ceErr := services.NewCAEPEmitter(
			services.CAEPEmitterConfig{Issuer: cfg.JWTIssuer},
			repos.SSF,
			keyManager,
			logger.Log,
		)
		if ceErr != nil {
			logger.Error("CAEP emitter init failed — falling back to NoOp",
				zap.Error(ceErr))
			postSignupProvisioner.SetSSFEmitter(services.NewNoOpSSFEmitter())
		} else {
			postSignupProvisioner.SetSSFEmitter(caepEmitter)
			authService.SetCAEPEmitter(caepEmitter)
			passwordResetService.SetCAEPEmitter(caepEmitter)
			accessTerminator.SetCAEPEmitter(caepEmitter)
			if webAuthnService != nil {
				webAuthnService.SetCAEPEmitter(caepEmitter)
			}

			// ZTNA Phase 6 — CAEP transactional outbox + drainer.
			// Behind FALCON_ID_CAEP_OUTBOX_ENABLED so operators can
			// canary the at-least-once path without disabling the
			// Phase 1 sync default. When the flag is unset (default
			// false) the emitter keeps Phase 1 best-effort behaviour.
			if cfg.CAEPOutboxEnabled {
				caepOutboxRepo := repositories.NewCAEPEventOutboxRepository(infra.DB.Pool)
				caepEmitter.SetOutbox(caepOutboxRepo)
				caepDrainerCfg := services.DefaultCAEPOutboxDrainerConfig()
				caepDrainerCfg.Issuer = cfg.JWTIssuer
				caepDrainer := services.NewCAEPOutboxDrainer(caepOutboxRepo, keyManager, caepDrainerCfg, logger.Log)
				// Long-lived background drainer. context.Background() because
				// the SetupServices function does not receive a process
				// lifetime context; the drainer survives until process exit.
				// On SIGTERM the main goroutine returns and the process
				// exits — drainer goroutine is reaped with it.
				go caepDrainer.Start(context.Background()) //nolint:gosec // long-lived background drainer
				logger.Info("CAEP outbox drainer started — at-least-once SET delivery",
					zap.Duration("tick", caepDrainerCfg.TickInterval),
					zap.Int("batch", caepDrainerCfg.BatchSize),
				)
			}

			logger.Info("CAEP transmitter enabled — session-revoked + credential-change SETs will fan out to subscribed streams",
				zap.String("issuer", cfg.JWTIssuer))
		}
	} else {
		// KeyManager not wired — only happens in unit-test fixtures.
		postSignupProvisioner.SetSSFEmitter(services.NewNoOpSSFEmitter())
	}
	signupService.SetPostSignupHook(postSignupProvisioner)
	logger.Info("Post-signup provisioner enabled (with default access granter)")

	// Lets CompleteSignup mint a real session (same code path as a normal
	// password login, see AuthService.IssueSessionForNewUser) instead of
	// forcing the client through a second hosted-login round trip.
	signupService.SetSessionIssuer(authService)
	signupService.SetPreferencesWriter(userPreferencesService)

	// A signup that started from an OIDC /oauth/authorize request resumes it
	// after verification: the continuation is validated against the registered
	// clients (shared with the login redirect) and stored server-side, with
	// SIGNUP_DEFAULT_APP_URL as the fallback destination.
	signupService.SetContinuationValidator(oauthProviderService)
	signupService.SetDefaultAppURL(cfg.SignupDefaultAppURL)

	// Lets InitiateSignup's up-front "claim your subdomain" step (and the
	// live GET /signup/check-slug endpoint) verify slug availability
	// synchronously against tenant-management instead of only finding
	// out about a collision later, indirectly, via provisionTenant's
	// create-and-retry loop. nil when outbound S2S creds/URL are
	// missing (fresh initdb / dev-without-Vault boots) — matches every
	// other optional S2S client's fallback posture in this file; a
	// missing checker means an explicit signup-time slug is refused
	// (see TenantSlugAvailabilityChecker's doc comment), not silently
	// accepted.
	if slugCheckerHTTP := buildTenantManagementSlugCheckerHTTPClient(cfg, logger.Log); slugCheckerHTTP != nil {
		signupService.SetSlugChecker(newHTTPTenantManagementSlugChecker(cfg.TenantManagementInternalURL, slugCheckerHTTP))
		logger.Info("Signup slug-availability checker wired")
	} else {
		logger.Warn("Signup slug-availability checker disabled: outbound S2S client to tenant-management unavailable")
	}

	// DeviceFingerprintService — richer-signal device store.
	deviceFingerprintService := services.NewDeviceFingerprintService(repos.DeviceFingerprint)
	// ProvisioningPolicy engine — pure-in-memory governance rules
	// for the /api/v1/platform/policy/{evaluate,rules} dry-run
	// surface. Loads the default rule set at construction time.
	provisioningPolicyEngine := services.NewPolicyEngine(logger.Log.Sugar())

	// GDPR Art. 15 (right to access — data export) + Art. 17 (right to
	// erasure — data deletion + legal hold). The synchronous request-
	// creation path; the async DeleteUser cascade fires from the
	// GDPRConsumer when integration-bus carries user.data_deletion_requested.
	dataExportService := services.NewDataExportService(
		repos.User,
		repos.Session,
		nil, // MFA factor state intentionally not exported.
		repos.Device,
		infra.DB.Pool,
	)
	deletionRepo := services.NewDeletionRepository(infra.DB.Pool)
	dataDeletionService := services.NewDataDeletionService(
		deletionRepo,
		repos.User,
		repos.Session,
		repos.Device,
		repos.MFA,
		auditService,
		infra.DB.Pool,
	)
	dataDeletionService.SetOAuthRepository(repos.OAuthClient)

	// AgentIdentityService — AI-agent + human-attended-automation lifecycle.
	agentIdentityService := services.NewAgentIdentityService(repos.AgentIdentity, cfg)

	// ComplianceLiveEvidenceService — live SOC2 / GDPR / KVKK reports.
	complianceLiveEvidenceService := services.NewComplianceLiveEvidenceService(infra.DB.Pool, logger.Log.Sugar())

	// AdminAudit logs admin-actor surface mutations to iam_admin_audit_events.
	adminAuditService := services.NewAdminAuditService(infra.DB.Pool, auditService)

	// Platform-admin read surfaces: schema drift + tenant resource metering.
	schemaVersionService := services.NewSchemaVersionTracker(infra.DB.Pool, logger.Log.Sugar())
	var tenantResourceMonitor *services.TenantResourceMonitor
	if infra.RedisClient != nil {
		tenantResourceMonitor = services.NewTenantResourceMonitor(
			infra.DB.Pool,
			infra.RedisClient.Redis(),
			logger.Log.Sugar(),
		)
	}

	// TenantEntitlementService: fail-closed entitlement source
	// (the product roadmap §4.1). Redis-backed fresh(60s)+LKG cache is only
	// wired when infra.RedisClient is configured; with no Redis, every
	// read goes straight to Postgres (still correct, just uncached) --
	// there is no scenario where entitlements silently "fail open" for
	// lack of a cache.
	// NOTE: entitlementCacheSvc is passed as a genuinely nil interface
	// (never a nil *EntitlementCacheService boxed in a non-nil interface)
	// when Redis is unconfigured — see
	// services.NewTenantEntitlementService's nil-cache handling.
	var entitlementService *services.TenantEntitlementService
	if infra.RedisClient != nil {
		entitlementService = services.NewTenantEntitlementService(
			repos.ModuleEntitlement,
			redis.NewEntitlementCacheService(infra.RedisClient, logger.Log),
		)
	} else {
		entitlementService = services.NewTenantEntitlementService(repos.ModuleEntitlement, nil)
	}
	// Mirror entitlements into SpiceDB tenant#entitled_module (spec 23 4.2).
	// Guarded so a nil *spicedb.Client is never boxed into the interface.
	if infra.SpiceDBClient != nil {
		entitlementService.SetSpiceDBSyncer(infra.SpiceDBClient)
	}

	// Module access: entitlement -> role templates + owner grants. The same
	// provisioner backs the PutSnapshot hook, the startup reconcile, the
	// platform endpoint and the first-template-registration reconcile.
	// tenantBootstrapService is passed only when non-nil so a nil pointer is
	// never boxed into the interface.
	var moduleAccessSpiceDB interface {
		BootstrapUserRole(ctx context.Context, tenantID, userID, roleID uuid.UUID) (string, error)
	}
	if tenantBootstrapService != nil {
		moduleAccessSpiceDB = tenantBootstrapService
	}
	moduleAccessProvisioner := services.NewModuleAccessProvisioner(
		templateRoleProvisioner,
		repos.Role,
		repos.User,
		moduleAccessSpiceDB,
		repos.ModuleEntitlement,
		repositories.NewAdvisoryLocker(infra.DB.Pool),
	)
	var moduleAccessRolePermSpiceDB interface {
		BootstrapRolePermissions(ctx context.Context, tenantID, roleID uuid.UUID, permissions []string) (*services.BootstrapResult, error)
	}
	if tenantBootstrapService != nil {
		moduleAccessRolePermSpiceDB = tenantBootstrapService
	}
	var moduleAccessSessions services.SessionCache
	if infra.SessionCache != nil {
		moduleAccessSessions = infra.SessionCache
	}
	moduleAccessProvisioner.SetOwnerPermissionSync(repos.Permission, moduleAccessRolePermSpiceDB, moduleAccessSessions)
	entitlementService.SetModuleGrantHook(moduleAccessProvisioner)
	permissionService.SetModuleAccessReconciler(moduleAccessProvisioner)

	// The role picker treats a module as entitled when the legacy
	// product-manifest check OR the entitlement projection says so. The
	// authz engine keeps the legacy checker only: business enforces
	// entitlements at runtime.
	if entitlementChecker != nil {
		projectionChecker := services.NewProjectionOrLegacyChecker(entitlementChecker, entitlementService)
		permissionService.SetModuleEntitlementChecker(projectionChecker)
		roleService.SetModuleEntitlementChecker(projectionChecker)
	}

	logger.Info("All services initialized",
		zap.Int("total_services", 82),
	)

	return &Services{
		Entitlement:            entitlementService,
		TenantStatusRepo:       tenantStatusRepo,
		TenantStatusGate:       tenantStatusGate,
		Audit:                  auditService,
		Token:                  tokenService,
		UserPreferences:        userPreferencesService,
		Role:                   roleService,
		SoD:                    sodService,
		SoDReevaluator:         sodReevaluator,
		Permission:             permissionService,
		RoleTemplate:           roleTemplateService,
		User:                   userService,
		AcmeAppRoleProvisioner: acmeappRoleProvisioner,
		LDAP:                   ldapService,
		ADSync:                 adSyncService,
		Auth:                   authService,
		SocialAuth:             socialAuthService,
		Email:                  emailService,
		MFA:                    mfaService,
		MFAEnrollment:          mfaEnrollmentService,
		PasswordReset:          passwordResetService,
		PasswordPolicy:         passwordPolicyService,
		RateLimit:              rateLimitService,
		IPRule:                 ipRuleService,
		APIKey:                 apiKeyService,
		TenantAPIKey:           tenantAPIKeyService,
		ServiceAccount:         serviceAccountService,
		OAuthProvider:          oauthProviderService,
		SAML:                   samlService,
		SAMLSP:                 samlSPService,
		SAMLMetadata:           samlMetadataService,
		SCIM:                   scimService,
		AccessTerminator:       accessTerminator,
		Group:                  groupService,
		Organization:           orgService,
		Impersonation:          impersonationService,
		Webhook:                webhookService,
		Device:                 deviceService,
		Recovery:               recoveryService,
		PushMFA:                pushMFAService,
		MagicLink:              magicLinkService,
		Invitation:             invitationService,
		Consent:                consentService,
		Risk:                   riskService,
		OPA:                    opaService,
		Authorization:          authorizationService,
		AuthzEngine:            authorizationEngine,
		Tenant:                 tenantService,
		AppAccess:              appAccessService,
		Realm:                  realmService,
		ConfigProvider:         configProvider,
		// Product & licensing
		Product:         productService,
		License:         licenseService,
		ProductInstance: productInstanceService,
		AppRegistration: appRegistrationService,
		// Applications & service principals
		Application:        applicationService,
		ServicePrincipal:   servicePrincipalService,
		AppConsent:         appConsentService,
		SPCredential:       spCredentialService,
		SPSignInActivity:   spSignInActivityService,
		ApplicationOwner:   applicationOwnerService,
		AppIDP:             appIDPService,
		AppInstallation:    appInstallationService,
		AppRole:            appRoleService,
		CredentialPolicy:   credentialPolicyService,
		ConsentRequest:     consentRequestService,
		RegistrationPolicy: registrationPolicyService,
		StaleAppDetection:  staleAppDetectionService,
		// Identity & access
		Delegation:             delegationService,
		TempAccessPass:         tempAccessPassService,
		GuestUser:              guestUserService,
		JITAccess:              jitAccessService,
		PlatformJIT:            platformJITService,
		PlatformAuth:           platformAuthority,
		AccessReview:           accessReviewService,
		EmailDomain:            emailDomainService,
		TenantBranding:         tenantBrandingService,
		TenantQuota:            tenantQuotaService,
		IDPRouting:             idpRoutingService,
		IDPTenantOverride:      idpTenantOverrideService,
		WebAuthn:               webAuthnService,
		Witness:                witnessService,
		TokenExchange:          tokenExchangeService,
		ManagedIdentity:        managedIdentityService,
		SCP:                    scpService,
		Signup:                 signupService,
		SignupTrialProvisioner: postSignupProvisioner,
		RealmFederation:        realmFederationService,
		RealmDBProvisioner:     realmDBProvisioner,
		// Platform & compliance
		ConditionalAccess:       conditionalAccessService,
		CompliancePolicyEngine:  compliancePolicyEngine,
		ComplianceScheduler:     complianceScheduler,
		ComplianceReport:        complianceReportService,
		ImmutableAudit:          immutableAuditService,
		SessionAnalytics:        sessionAnalyticsService,
		UsageMetering:           usageMeteringService,
		ThreatCorrelation:       threatCorrelationService,
		ITDR:                    itdrService,
		RoutingWebhook:          routingWebhookService,
		SpiceDBReconciler:       spiceDBReconciler,
		RoleRevokeDrainer:       roleRevokeDrainer,
		SeatQuotaReconciler:     seatQuotaReconciler,
		TemplateRoleProvisioner: templateRoleProvisioner,
		ModuleAccess:            moduleAccessProvisioner,
		EmployeeAccess:          employeeAccessService,
		EmployeeAccessExpiry:    employeeAccessExpiry,
		HREmploymentSync:        hrEmploymentSync,
		TenantBootstrap:         tenantBootstrapService,
		Discover:                discoverService,
		AuthHooks:               authHooksService,
		ProvisioningStatus:      provisioningStatusService,
		// Identifier-first realm discovery
		RealmDiscovery: realmDiscoveryService,
		// Host-based tenant discovery for custom domains (SDK runtime)
		HostDiscovery:    hostDiscoveryService,
		OnboardingSlug:   onboardingSlugService,
		OnboardingStatus: onboardingStatusService,
		// Placeholder workspace-name replacement (S2S rename + admin backfill)
		TenantWorkspaceName: tenantWorkspaceNameService,
		// GDPR — synchronous request-creation + status side. The async
		// consumer (GDPRConsumer) is wired separately when integration-bus
		// is configured.
		DataExport:   dataExportService,
		DataDeletion: dataDeletionService,
		// Enterprise bridges
		SubscriptionBridge:       subscriptionBridge,
		ProvisioningOrchestrator: provisioningOrchestrator,
		DomainVerification:       domainVerificationWorker,
		TenantHostVerification:   tenantHostVerificationWorker,
		// Adaptive-MFA / device-fingerprint surface
		DeviceFingerprint: deviceFingerprintService,
		// Admin-action audit logger (separate trail from general AuditService)
		AdminAudit: adminAuditService,
		// Platform-admin read surfaces (schema drift + tenant metering)
		SchemaVersion:         schemaVersionService,
		TenantResourceMonitor: tenantResourceMonitor,
		// Governance dry-run engine for provisioning requests
		ProvisioningPolicy: provisioningPolicyEngine,
		// AI-agent identity + live compliance evidence reports
		AgentIdentity:          agentIdentityService,
		ComplianceLiveEvidence: complianceLiveEvidenceService,
		JWTKeyProvider:         jwtKeyProvider,
		KeyManager:             keyManager,
		OriginRegistry:         originRegistry,
	}
}

// signingKeyOptions maps config to KeyManager rotation options and enforces the
// invariants that make publish-before-activate safe: the publish delay must exceed the
// JWKS max-age plus the reload interval, and rotated keys must outlive the longest
// access token.
func signingKeyOptions(cfg *config.Config) keys.Options {
	opts := keys.Options{
		PublishDelay:   cfg.SigningKeyPublishDelay,
		ReloadInterval: cfg.SigningKeyReloadInterval,
		RetireAfter:    cfg.SigningKeyRetireAfter,
	}.WithDefaults()
	maxAge := cfg.JWKSMaxAge
	if maxAge <= 0 {
		maxAge = 300 * time.Second
	}
	if min := maxAge + opts.ReloadInterval + time.Minute; opts.PublishDelay < min {
		logger.Warn("SIGNING_KEY_PUBLISH_DELAY too short for JWKS_MAX_AGE + SIGNING_KEY_RELOAD_INTERVAL, raising",
			zap.Duration("configured", opts.PublishDelay), zap.Duration("effective", min))
		opts.PublishDelay = min
	}
	if min := cfg.AccessTokenExpiry + time.Hour; opts.RetireAfter < min {
		logger.Warn("SIGNING_KEY_RETIRE_AFTER shorter than ACCESS_TOKEN_EXPIRY + 1h, raising",
			zap.Duration("configured", opts.RetireAfter), zap.Duration("effective", min))
		opts.RetireAfter = min
	}
	return opts
}

// initKeyManager creates and initializes the DB-backed KeyManager.
// Falls back gracefully to nil (which means the ephemeral JWTKeyProvider is used instead).
func initKeyManager(infra *Infrastructure, cfg *config.Config) *keys.KeyManager {
	signingKeyEncHex := os.Getenv("SIGNING_KEY_ENCRYPTION_KEY")
	if signingKeyEncHex == "" {
		signingKeyEncHex = cfg.EncryptionKey
	}
	if signingKeyEncHex == "" {
		signingKeyEncHex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	}

	var encBytes []byte
	decoded, decErr := hex.DecodeString(signingKeyEncHex)
	if decErr != nil || len(decoded) != 32 {
		hash := sha256.Sum256([]byte(signingKeyEncHex))
		encBytes = hash[:]
	} else {
		encBytes = decoded
	}

	km, kmErr := keys.NewKeyManager(infra.DB.Pool, encBytes, logger.Log)
	if kmErr != nil {
		return keyManagerUnavailable(cfg, "create", kmErr)
	}
	km.Configure(signingKeyOptions(cfg))
	if initErr := km.Initialize(context.Background()); initErr != nil {
		return keyManagerUnavailable(cfg, "initialize", initErr)
	}
	logger.Info("Database-backed key manager initialized (Keycloak/Auth0 pattern)")
	return km
}

// keyManagerUnavailable refuses to start with an ephemeral per-pod signing key
// outside development: such a pod would sign tokens no other replica can verify.
func keyManagerUnavailable(cfg *config.Config, action string, err error) *keys.KeyManager {
	if cfg.Environment == "development" {
		logger.Warn("Failed to "+action+" KeyManager, falling back to ephemeral JWTKeyProvider (development only)", zap.Error(err))
		return nil
	}
	logger.Fatal("Failed to "+action+" signing KeyManager; refusing ephemeral per-pod signing key outside development", zap.Error(err))
	return nil
}

// initConfigProvider creates the ConfigProvider and wires it to the token service.
func initConfigProvider(cfg *config.Config, repos *Repositories, infra *Infrastructure, tokenService *services.TokenService) *services.ConfigProvider {
	var goRedisClient *goredis.Client
	if infra.RedisClient != nil {
		goRedisClient = infra.RedisClient.Redis()
	}
	cp, err := services.NewConfigProvider(cfg, repos.TenantConfig, goRedisClient, logger.Log, services.DefaultConfigProviderConfig())
	if err != nil {
		logger.Fatal("Failed to initialize ConfigProvider", zap.Error(err))
	}
	tokenService.SetConfigProvider(cp)
	logger.Info("ConfigProvider initialized for per-tenant dynamic configuration")
	return cp
}

// wireTokenServiceRedis wires all Redis-backed components to the token, auth, user, and role services.
func wireTokenServiceRedis(
	tokenService *services.TokenService,
	authService *services.AuthService,
	userService *services.UserService,
	roleService *services.RoleService,
	socialAuthService *services.SocialAuthService,
	repos *Repositories,
	infra *Infrastructure,
	_ *config.Config,
) {
	if infra.TokenBlacklist != nil {
		tokenService.SetTokenBlacklist(infra.TokenBlacklist)
		logger.Info("Token blacklist enabled for token service")
	}

	tokenService.SetSessionRepository(repos.Session)
	if repos.Realm != nil {
		// Per-realm session policy overrides (SessionIdleTimeoutMinutes,
		// SessionMaxLifetimeHours) beat the global config during refresh.
		// Realms with zero values on both fields keep the global defaults.
		tokenService.SetRealmPolicyReader(repos.Realm)

		// MFA enrollment grace evaluation (migration 235). nil-safe —
		// when the realm repo isn't wired (test harness) the auth
		// service short-circuits to the pre-grace hard-block path.
		authService.SetRealmRepository(repos.Realm)
	}

	if infra.SessionCache != nil {
		authService.SetSessionCache(infra.SessionCache)
		tokenService.SetSessionCache(infra.SessionCache)
		userService.SetSessionCache(infra.SessionCache)
		roleService.SetSessionCache(infra.SessionCache)
		logger.Info("Session cache enabled for auth, token, user, and role services")
	}

	if infra.RedisClient == nil {
		return
	}

	socialAuthService.SetRedisClient(infra.RedisClient)
	logger.Info("Redis client enabled for SSO MFA sessions")

	userCacheConfig := redis.DefaultCacheConfig()
	userCache := redis.NewUserCacheService(infra.RedisClient, logger.Log, userCacheConfig)
	userService.SetRedisCache(userCache)
	logger.Info("User cache enabled with TTLs",
		zap.Duration("profile_ttl", userCacheConfig.UserProfileTTL),
		zap.Duration("role_ttl", userCacheConfig.RoleCheckTTL),
		zap.Duration("permission_ttl", userCacheConfig.PermissionTTL),
	)
}

// wireAuthService wires the MFA, risk, device, group, and tenant dependencies to the auth service.
func wireAuthService(
	authService *services.AuthService,
	mfaService *services.MFAService,
	riskService *services.RiskService,
	deviceService *services.DeviceService,
	groupService *services.GroupService,
	repos *Repositories,
) {
	authService.SetMFAService(mfaService)
	authService.SetRiskService(riskService)
	authService.SetDeviceService(deviceService)
	authService.SetGroupService(groupService)
	authService.SetTenantRepository(repos.Tenant)
	// Admin-passkey policy gate (require_passkey_for_admin tenant flag) —
	// wired here so /auth/login can interrupt admins-without-passkey into
	// the registration-interrupt flow.
	authService.SetFeatureFlagRepository(repos.FeatureFlag)
	authService.SetWebAuthnRepository(repos.WebAuthn)
}

// wireSocialAuthService wires conditional access and session dependencies to the social auth service.
func wireSocialAuthService(
	socialAuthService *services.SocialAuthService,
	mfaService *services.MFAService,
	riskService *services.RiskService,
	deviceService *services.DeviceService,
	repos *Repositories,
	infra *Infrastructure,
) {
	socialAuthService.SetSessionRepository(repos.Session)
	if infra.EncryptionService != nil {
		socialAuthService.SetEncryptionService(infra.EncryptionService)
	}
	socialAuthService.SetMFAService(mfaService)
	socialAuthService.SetRiskService(riskService)
	socialAuthService.SetDeviceService(deviceService)
	socialAuthService.SetTenantRepository(repos.Tenant)
}

// wireSAMLSPService wires conditional access, session, and blacklist dependencies to the SAML SP service.
func wireSAMLSPService(
	samlSPService *services.SAMLSPService,
	mfaService *services.MFAService,
	riskService *services.RiskService,
	deviceService *services.DeviceService,
	repos *Repositories,
	infra *Infrastructure,
) {
	samlSPService.SetMFAService(mfaService)
	samlSPService.SetRiskService(riskService)
	samlSPService.SetDeviceService(deviceService)
	samlSPService.SetSessionRepository(repos.Session)
	if infra.TokenBlacklist != nil {
		samlSPService.SetTokenBlacklist(infra.TokenBlacklist)
	}
	if infra.RedisClient != nil {
		samlSPService.SetSessionCache(infra.RedisClient)
	}
}

// redisCAEPublisher adapts *redis.Client to the services.CAEPublisher
// interface. The interface's Publish returns an error; the underlying
// go-redis Publish returns *IntCmd whose Err() is the publish error.
type redisCAEPublisher struct {
	client *redis.Client
}

// Publish satisfies services.CAEPublisher. The first return value of the
// underlying go-redis call is the number of subscribers that received the
// message — irrelevant to publishers, so we discard it.
func (p *redisCAEPublisher) Publish(ctx context.Context, channel string, message []byte) error {
	return p.client.Redis().Publish(ctx, channel, message).Err()
}

// buildQuotaClient builds the *quota.QuotaClient UserService uses to
// enforce/track per-tenant seat (resource_type="users") usage against
// quota-service. Returns nil (enforcement stays a no-op — see
// UserService.SetQuotaClient's doc comment) when QuotaServiceURL is unset
// or the same SERVICE_CLIENT_ID/SERVICE_CLIENT_SECRET/IAM_SERVICE_URL used
// by cmd/background.go's buildTenantBootstrapClient are missing, rather
// than failing boot — this mirrors that function's fallback posture for
// the identical creds pair and keeps fresh-initdb / dev-without-Vault boots
// working.
//
// The outbound OAuth2 client is svc-falcon-id (falcon-id-oauth
// ServiceClientClaim in the GitOps repository), which as of feat/seat-quota-
// enforcement additionally carries the quota:usage:read and
// quota:usage:update scopes alongside its existing service:register and
// platform:tenants:read grants — reusing the one client with a per-call
// Scope, the same pattern notification-service uses for its own
// email_sends_monthly quota wiring, rather than provisioning a second
// client_credentials client for the same service.
// buildTenantManagementSlugUpdaterHTTPClient builds the authenticated
// *http.Client the onboarding-slug endpoint uses to call tenant-
// management's S2S-scope-gated PUT /api/v1/internal/tenants/{id}.
// Requests the platform:tenants:write scope — svc-falcon-id's
// falcon-id-oauth ServiceClientClaim (the GitOps repository) must grant it
// alongside the existing platform:tenants:read/service:register grants
// or every call here 403s. Same client_credentials client as
// buildQuotaClient, one more scope requested per call — mirrors that
// function's own doc comment on why a second client isn't provisioned.
//
// Returns nil (route registration becomes a no-op) when outbound OAuth
// creds or TENANT_MANAGEMENT_INTERNAL_URL are missing, matching
// buildQuotaClient's fallback posture for fresh-initdb / dev-without-
// Vault boots.
func buildTenantManagementSlugUpdaterHTTPClient(cfg *config.Config, log *zap.Logger) *http.Client {
	if cfg.TenantManagementInternalURL == "" {
		log.Warn("onboarding slug endpoint disabled: TENANT_MANAGEMENT_INTERNAL_URL is empty")
		return nil
	}
	if cfg.ServiceClientID == "" || cfg.ServiceClientSecret == "" || cfg.IAMServiceURL == "" {
		log.Warn("onboarding slug endpoint disabled: outbound OAuth creds missing",
			zap.Bool("have_client_id", cfg.ServiceClientID != ""),
			zap.Bool("have_client_secret", cfg.ServiceClientSecret != ""),
			zap.Bool("have_iam_url", cfg.IAMServiceURL != ""),
		)
		return nil
	}

	httpClient, err := serviceauth.NewIAMHTTPClient(serviceauth.IAMHTTPClientConfig{
		IAMURL:       cfg.IAMServiceURL,
		ClientID:     cfg.ServiceClientID,
		ClientSecret: cfg.ServiceClientSecret,
		Scope:        "platform:tenants:write",
	})
	if err != nil {
		log.Error("onboarding slug endpoint disabled: NewIAMHTTPClient failed", zap.Error(err))
		return nil
	}

	return httpClient
}

// buildTenantManagementStatusReaderHTTPClient builds the authenticated
// *http.Client the onboarding-status endpoint uses to call tenant-
// management's S2S-scope-gated GET /api/v1/internal/tenants/{id}.
// Requests platform:tenants:read — svc-falcon-id's falcon-id-oauth
// ServiceClientClaim already grants this scope for other reads (see
// cmd/background.go), so no new grant is needed here, unlike
// buildTenantManagementSlugUpdaterHTTPClient's write scope above.
//
// Returns nil (route registration becomes a no-op) when outbound OAuth
// creds or TENANT_MANAGEMENT_INTERNAL_URL are missing, matching
// buildTenantManagementSlugUpdaterHTTPClient's own fallback posture.
func buildTenantManagementStatusReaderHTTPClient(cfg *config.Config, log *zap.Logger) *http.Client {
	if cfg.TenantManagementInternalURL == "" {
		log.Warn("onboarding status endpoint disabled: TENANT_MANAGEMENT_INTERNAL_URL is empty")
		return nil
	}
	if cfg.ServiceClientID == "" || cfg.ServiceClientSecret == "" || cfg.IAMServiceURL == "" {
		log.Warn("onboarding status endpoint disabled: outbound OAuth creds missing",
			zap.Bool("have_client_id", cfg.ServiceClientID != ""),
			zap.Bool("have_client_secret", cfg.ServiceClientSecret != ""),
			zap.Bool("have_iam_url", cfg.IAMServiceURL != ""),
		)
		return nil
	}

	httpClient, err := serviceauth.NewIAMHTTPClient(serviceauth.IAMHTTPClientConfig{
		IAMURL:       cfg.IAMServiceURL,
		ClientID:     cfg.ServiceClientID,
		ClientSecret: cfg.ServiceClientSecret,
		Scope:        "platform:tenants:read",
	})
	if err != nil {
		log.Error("onboarding status endpoint disabled: NewIAMHTTPClient failed", zap.Error(err))
		return nil
	}

	return httpClient
}

// buildTenantManagementAppHostHTTPClient builds the authenticated
// *http.Client ConfigProvider.FrontendURL uses to call tenant-management's
// S2S-scope-gated GET /api/v1/internal/tenants/{id}/app-host
// (platform-core !80, not yet merged as of this writing).
//
// Requests platform:tenants:app-host:read EXPLICITLY — never rely on
// NewIAMHTTPClient's Scope defaulting; a prior incident here (NewIAMHTTPClient
// defaulting Scope to "service:register") 403'd every other S2S call for
// ten days. This is a NEW scope, deliberately separate from the blanket
// platform:tenants:read svc-falcon-id's falcon-id-oauth ServiceClientClaim
// already carries (see buildTenantManagementStatusReaderHTTPClient above) —
// unlike that function's reuse of an existing grant, this one requires a
// SEPARATE the GitOps repository MR adding the
// platform:tenants:app-host:read grant to svc-falcon-id's
// ServiceClientClaim before any call through this client will succeed.
// That the GitOps repository MR must merge (and the pod restart to pick up
// the refreshed token) before this client's calls stop 403ing — minting a
// fresh token only proves svc-falcon-id's OAuth client itself has the
// scope, not that an already-running pod's cached hour-long token does.
//
// Returns nil (FrontendURL's app-host resolver stays unset — see
// initServices in cmd/services.go) when outbound OAuth creds or
// TENANT_MANAGEMENT_INTERNAL_URL are missing, matching every other builder
// in this file's fallback posture.
func buildTenantManagementAppHostHTTPClient(cfg *config.Config, log *zap.Logger) *http.Client {
	if cfg.TenantManagementInternalURL == "" {
		log.Warn("frontend-url app-host resolver disabled: TENANT_MANAGEMENT_INTERNAL_URL is empty")
		return nil
	}
	if cfg.ServiceClientID == "" || cfg.ServiceClientSecret == "" || cfg.IAMServiceURL == "" {
		log.Warn("frontend-url app-host resolver disabled: outbound OAuth creds missing",
			zap.Bool("have_client_id", cfg.ServiceClientID != ""),
			zap.Bool("have_client_secret", cfg.ServiceClientSecret != ""),
			zap.Bool("have_iam_url", cfg.IAMServiceURL != ""),
		)
		return nil
	}

	httpClient, err := serviceauth.NewIAMHTTPClient(serviceauth.IAMHTTPClientConfig{
		IAMURL:       cfg.IAMServiceURL,
		ClientID:     cfg.ServiceClientID,
		ClientSecret: cfg.ServiceClientSecret,
		Scope:        "platform:tenants:app-host:read",
	})
	if err != nil {
		log.Error("frontend-url app-host resolver disabled: NewIAMHTTPClient failed", zap.Error(err))
		return nil
	}

	return httpClient
}

// buildTenantManagementOriginLister builds the Stage 3 middleware.
// TenantOriginLister backing the dynamic CORS/CSRF origin registry
// (Services.OriginRegistry). It uses TWO separate authenticated clients:
//   - a platform:tenants:read client for the bulk tenant list (the SAME
//     scope buildTenantManagementStatusReaderHTTPClient / the slug checker
//     already request — no new grant needed for this half), and
//   - a platform:tenants:app-host:read client for the per-active-tenant
//     app_host lookup (the SAME NEW scope buildTenantManagementAppHostHTTPClient
//     requests — one the GitOps repository ServiceClientClaim grant covers
//     both this lister and ConfigProvider.FrontendURL's resolver).
//
// Returns nil (Services.OriginRegistry is still constructed by the caller,
// just with a nil lister — see NewDynamicOriginRegistry — so CORS/CSRF
// keep working off their static allowlists only) when either client can't
// be built, matching every other builder in this file's fallback posture.
func buildTenantManagementOriginLister(cfg *config.Config, log *zap.Logger) *httpTenantManagementOriginLister {
	listClient := buildTenantManagementStatusReaderHTTPClient(cfg, log)
	if listClient == nil {
		log.Warn("dynamic CORS/CSRF origin registry disabled: tenant list client unavailable")
		return nil
	}

	appHostHTTP := buildTenantManagementAppHostHTTPClient(cfg, log)
	if appHostHTTP == nil {
		log.Warn("dynamic CORS/CSRF origin registry disabled: app-host client unavailable")
		return nil
	}
	appHostReader := newHTTPTenantManagementAppHostReader(cfg.TenantManagementInternalURL, appHostHTTP)

	return newHTTPTenantManagementOriginLister(cfg.TenantManagementInternalURL, listClient, appHostReader, log)
}

// buildTenantManagementSlugCheckerHTTPClient builds the authenticated
// *http.Client SignupService uses to call tenant-management's
// S2S-scope-gated GET /api/v1/internal/tenants/slug-available/{slug}.
// Requests platform:tenants:read — the SAME scope
// buildTenantManagementStatusReaderHTTPClient above already requests, so
// no new svc-falcon-id ServiceClientClaim grant is needed in
// the GitOps repository. Mirrors that function's fallback posture: returns
// nil (the up-front slug claim step becomes unavailable — see
// TenantSlugAvailabilityChecker's doc comment on why that means
// "refused", not "silently allowed") when outbound OAuth creds or
// TENANT_MANAGEMENT_INTERNAL_URL are missing.
func buildTenantManagementSlugCheckerHTTPClient(cfg *config.Config, log *zap.Logger) *http.Client {
	if cfg.TenantManagementInternalURL == "" {
		log.Warn("signup slug checker disabled: TENANT_MANAGEMENT_INTERNAL_URL is empty")
		return nil
	}
	if cfg.ServiceClientID == "" || cfg.ServiceClientSecret == "" || cfg.IAMServiceURL == "" {
		log.Warn("signup slug checker disabled: outbound OAuth creds missing",
			zap.Bool("have_client_id", cfg.ServiceClientID != ""),
			zap.Bool("have_client_secret", cfg.ServiceClientSecret != ""),
			zap.Bool("have_iam_url", cfg.IAMServiceURL != ""),
		)
		return nil
	}

	httpClient, err := serviceauth.NewIAMHTTPClient(serviceauth.IAMHTTPClientConfig{
		IAMURL:       cfg.IAMServiceURL,
		ClientID:     cfg.ServiceClientID,
		ClientSecret: cfg.ServiceClientSecret,
		Scope:        "platform:tenants:read",
	})
	if err != nil {
		log.Error("signup slug checker disabled: NewIAMHTTPClient failed", zap.Error(err))
		return nil
	}

	return httpClient
}

// buildSubscriptionManagementTrialStarterHTTPClient builds the
// authenticated *http.Client the onboarding-completion trial-start step
// (PostSignupProvisioner's TrialStarter) uses to call subscription-
// management's S2S scope-gated
// POST /api/v1/internal/tenants/{id}/trial. Requests the
// subscription-management:trials:start scope — svc-falcon-id's
// falcon-id-oauth ServiceClientClaim (the GitOps repository) must grant it
// or every call here 403s. Same client_credentials client as
// buildQuotaClient / buildTenantManagementSlugUpdaterHTTPClient, one more
// scope requested per call — mirrors those functions' own doc comments on
// why a second client isn't provisioned.
//
// Returns nil (the trial-start step becomes a no-op, matching
// PostSignupProvisioner's nil-safe TrialStarter contract) when outbound
// OAuth creds or SUBSCRIPTION_MANAGEMENT_INTERNAL_URL are missing,
// matching buildQuotaClient's fallback posture for fresh-initdb / dev-
// without-Vault boots.
func buildSubscriptionManagementTrialStarterHTTPClient(cfg *config.Config, log *zap.Logger) *http.Client {
	if cfg.SubscriptionManagementInternalURL == "" {
		log.Warn("onboarding trial-start step disabled: SUBSCRIPTION_MANAGEMENT_INTERNAL_URL is empty")
		return nil
	}
	if cfg.ServiceClientID == "" || cfg.ServiceClientSecret == "" || cfg.IAMServiceURL == "" {
		log.Warn("onboarding trial-start step disabled: outbound OAuth creds missing",
			zap.Bool("have_client_id", cfg.ServiceClientID != ""),
			zap.Bool("have_client_secret", cfg.ServiceClientSecret != ""),
			zap.Bool("have_iam_url", cfg.IAMServiceURL != ""),
		)
		return nil
	}

	httpClient, err := serviceauth.NewIAMHTTPClient(serviceauth.IAMHTTPClientConfig{
		IAMURL:       cfg.IAMServiceURL,
		ClientID:     cfg.ServiceClientID,
		ClientSecret: cfg.ServiceClientSecret,
		Scope:        "subscription-management:trials:start",
	})
	if err != nil {
		log.Error("onboarding trial-start step disabled: NewIAMHTTPClient failed", zap.Error(err))
		return nil
	}

	return httpClient
}

func buildQuotaClient(cfg *config.Config, log *zap.Logger) *quota.QuotaClient {
	if cfg.QuotaServiceURL == "" {
		log.Warn("seat-quota enforcement disabled: QUOTA_SERVICE_URL is empty")
		return nil
	}
	if cfg.ServiceClientID == "" || cfg.ServiceClientSecret == "" || cfg.IAMServiceURL == "" {
		log.Warn("seat-quota enforcement disabled: outbound OAuth creds missing",
			zap.Bool("have_client_id", cfg.ServiceClientID != ""),
			zap.Bool("have_client_secret", cfg.ServiceClientSecret != ""),
			zap.Bool("have_iam_url", cfg.IAMServiceURL != ""),
		)
		return nil
	}

	quotaHTTP, err := serviceauth.NewIAMHTTPClient(serviceauth.IAMHTTPClientConfig{
		IAMURL:       cfg.IAMServiceURL,
		ClientID:     cfg.ServiceClientID,
		ClientSecret: cfg.ServiceClientSecret,
		Scope:        "quota:usage:read quota:usage:update",
	})
	if err != nil {
		log.Error("seat-quota enforcement disabled: NewIAMHTTPClient failed", zap.Error(err))
		return nil
	}

	return quota.NewQuotaClientWithHTTPClient(cfg.QuotaServiceURL, cfg.QuotaEnforcementEnabled, quotaHTTP)
}

// buildSeatQuotaReconcilerHTTPClient builds the authenticated *http.Client
// SeatQuotaReconciler uses to call quota-service's POST /api/v1/quota/
// admin/reconcile. Separate from buildQuotaClient's http.Client above
// because that route sits behind RequirePermission("quota:admin",
// "platform:admin") — a stricter gate than the quota:usage:read/update
// scopes the synchronous check/increment/decrement path uses — so the
// outbound token needs the quota:admin scope requested explicitly.
//
// Same svc-falcon-id OAuth2 client (falcon-id-oauth ServiceClientClaim) as
// buildQuotaClient — one client, scope requested per call, mirroring
// the business service repository's df5373d1 pattern which added quota:admin to its
// existing ServiceClientClaim for the identical reconcile call rather than
// provisioning a second client_credentials client. the GitOps repository must
// grant quota:admin on svc-falcon-id's claim alongside this change or every
// call here 403s.
//
// Returns nil (scheduler start becomes a no-op — see
// SeatQuotaReconciler.StartScheduler) when outbound OAuth creds are
// missing, matching buildQuotaClient's fallback posture for fresh-initdb /
// dev-without-Vault boots.
func buildSeatQuotaReconcilerHTTPClient(cfg *config.Config, log *zap.Logger) *http.Client {
	if cfg.QuotaServiceURL == "" {
		log.Warn("seat-quota reconciler disabled: QUOTA_SERVICE_URL is empty")
		return nil
	}
	if cfg.ServiceClientID == "" || cfg.ServiceClientSecret == "" || cfg.IAMServiceURL == "" {
		log.Warn("seat-quota reconciler disabled: outbound OAuth creds missing",
			zap.Bool("have_client_id", cfg.ServiceClientID != ""),
			zap.Bool("have_client_secret", cfg.ServiceClientSecret != ""),
			zap.Bool("have_iam_url", cfg.IAMServiceURL != ""),
		)
		return nil
	}

	httpClient, err := serviceauth.NewIAMHTTPClient(serviceauth.IAMHTTPClientConfig{
		IAMURL:       cfg.IAMServiceURL,
		ClientID:     cfg.ServiceClientID,
		ClientSecret: cfg.ServiceClientSecret,
		Scope:        "quota:admin",
	})
	if err != nil {
		log.Error("seat-quota reconciler disabled: NewIAMHTTPClient failed", zap.Error(err))
		return nil
	}

	return httpClient
}

// witnessPolicySource is the realm-policy read the witness service needs.
type witnessPolicySource interface {
	DeviceWitnessTOTPAllowed(ctx context.Context, tenantID uuid.UUID) (bool, error)
}

// allowAllWitnessPolicy is used when realms are not wired: the column default
// is true, and the FALCON_WITNESS_TOTP_ENABLED kill switch still gates.
type allowAllWitnessPolicy struct{}

func (allowAllWitnessPolicy) DeviceWitnessTOTPAllowed(context.Context, uuid.UUID) (bool, error) {
	return true, nil
}

// witnessRedisClient returns the go-redis client used for witness state and
// the shared TOTP replay claim, or nil when Redis is not configured.
func witnessRedisClient(infra *Infrastructure) goredis.Cmdable {
	switch {
	case infra.RedisClient != nil:
		return infra.RedisClient.Redis()
	case infra.SessionCache != nil:
		return infra.SessionCache.Client().Redis()
	}
	return nil
}
