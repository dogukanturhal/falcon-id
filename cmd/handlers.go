// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"os"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/dogukanturhal/platform-shared/hooks"

	"github.com/dogukanturhal/falcon-id/internal/handlers"
	platformhandlers "github.com/dogukanturhal/falcon-id/internal/handlers/platform"
	"github.com/dogukanturhal/falcon-id/internal/middleware"
	"github.com/dogukanturhal/falcon-id/internal/opsconsole"
	"github.com/dogukanturhal/falcon-id/internal/repositories"
	svc "github.com/dogukanturhal/falcon-id/internal/services"
	"github.com/dogukanturhal/falcon-id/pkg/config"
	"github.com/dogukanturhal/falcon-id/pkg/logger"
	"github.com/dogukanturhal/falcon-id/pkg/spicedb"
)

// Handlers holds all handler instances.
type Handlers struct {
	ApprovalDirectory *handlers.ApprovalDirectoryHandler
	NotifRecipients   *handlers.NotificationRecipientsHandler
	TeamScope         *handlers.TeamScopeHandler
	TenantTeam        *handlers.TenantTeamHandler
	Auth              *handlers.AuthHandler
	User              *handlers.UserHandler
	UserPreferences   *handlers.UserPreferencesHandler
	Role              *handlers.RoleHandler
	SoD               *handlers.SoDHandler
	SocialAuth        *handlers.SocialAuthHandler
	Admin             *handlers.AdminHandler
	MFA               *handlers.MFAHandler
	PushMFA           *handlers.PushMFAHandler
	OnboardingVerify  *handlers.OnboardingVerifyHandler
	OnboardingSlug    *handlers.OnboardingSlugHandler

	// TenantWorkspaceName: S2S placeholder rename + platform-admin backfill.
	TenantWorkspaceName *handlers.TenantWorkspaceNameHandler

	OnboardingStatus  *handlers.OnboardingStatusHandler
	AD                *handlers.ADHandler
	Settings          *handlers.SettingsHandler
	APIKey            *handlers.APIKeyHandler
	TenantAPIKey      *handlers.TenantAPIKeyHandler
	TenantAPIKeyLimit gin.HandlerFunc // rate limiter for POST /oauth/token/api-key
	ServiceAccount    *handlers.ServiceAccountHandler
	OAuthProvider     *handlers.OAuthProviderHandler
	SAML              *handlers.SAMLHandler
	SAMLSP            *handlers.SAMLSPHandler
	SCIM              *handlers.SCIMHandler
	Group             *handlers.GroupHandler
	Organization      *handlers.OrganizationHandler
	Impersonation     *handlers.ImpersonationHandler
	Webhook           *handlers.WebhookHandler
	Device            *handlers.DeviceHandler
	// Recovery — self-service account-recovery (recovery email). nil when
	// Redis is unavailable (the service it wraps is Redis-gated).
	Recovery           *handlers.RecoveryHandler
	MagicLink          *handlers.MagicLinkHandler
	Invitation         *handlers.InvitationHandler
	Consent            *handlers.ConsentHandler
	Risk               *handlers.RiskHandler
	Policy             *handlers.PolicyHandler
	Tenant             *handlers.TenantHandler
	Entitlement        *handlers.EntitlementHandler
	FeatureFlag        *handlers.FeatureFlagHandler
	Permission         *handlers.PermissionHandler
	RoleTemplate       *handlers.RoleTemplateHandler
	ADSync             *handlers.ADSyncHandler
	Context            *handlers.ContextHandler
	PlatformManagement *handlers.PlatformManagementHandler
	AppAccess          *handlers.AppAccessHandler
	Realm              *handlers.RealmHandler
	Metrics            *platformhandlers.MetricsHandler
	Authorization      *handlers.AuthorizationHandler
	TenantConfig       *handlers.TenantConfigHandler
	CSRFMiddleware     *middleware.CSRFMiddleware
	RealmMiddleware    *middleware.RealmMiddleware
	StepUpMiddleware   *middleware.StepUpMiddleware
	// Product & licensing
	Product         *handlers.ProductHandler
	License         *handlers.LicenseHandler
	ProductInstance *handlers.ProductInstanceHandler
	AppRegistration *handlers.AppRegistrationHandler
	// Applications & service principals
	Application                *handlers.ApplicationHandler
	AppRole                    *handlers.AppRoleHandler
	CredentialPolicy           *handlers.CredentialPolicyHandler
	CredentialAnalysis         *handlers.CredentialAnalysisHandler
	ConsentRequest             *handlers.ConsentRequestHandler
	RegistrationPolicy         *handlers.RegistrationPolicyHandler
	ServicePrincipal           *handlers.ServicePrincipalHandler
	ManagedIdentity            *handlers.ManagedIdentityHandler
	WorkloadIdentity           *handlers.WorkloadIdentityHandler
	OAuthTrustedExternalIssuer *handlers.OAuthTrustedExternalIssuerHandler
	// Identity & access
	TempAccessPass *handlers.TempAccessPassHandler
	Signup         *handlers.SignupHandler
	Delegation     *handlers.DelegationHandler
	GuestUser      *handlers.GuestUserHandler
	JITAccess      *handlers.JITAccessHandler
	// PlatformJIT — R1 platform plane: JIT elevation + break-glass.
	// /internal/v1/{jit-elevations,break-glass,platform-roles}.
	PlatformJIT       *handlers.PlatformJITHandler
	PlatformAuth      *handlers.PlatformAuthorityHandler
	// Ops — staff console operator-chain surface (/internal/v1/ops/*,
	// /internal/v1/ops-approvals/*); nil unless the operator exchange is on.
	Ops *opsconsole.Console
	AccessReview      *handlers.AccessReviewHandler
	EmailDomain       *handlers.EmailDomainHandler
	TenantBranding    *handlers.TenantBrandingHandler
	TenantQuota       *handlers.TenantQuotaHandler
	IDPRouting        *handlers.IDPRoutingHandler
	IDPTenantOverride *handlers.IDPTenantOverrideHandler
	WebAuthn          *handlers.WebAuthnHandler
	WitnessTOTP       *handlers.WitnessTOTPHandler
	SCP               *handlers.SCPHandler
	RealmDB           *handlers.RealmDBHandler
	RealmFederation   *handlers.RealmFederationHandler
	// Platform & compliance
	ConditionalAccess *handlers.ConditionalAccessHandler
	CompliancePolicy  *handlers.CompliancePolicyHandler
	ComplianceReport  *handlers.ComplianceReportHandler
	AuditIntegrity    *handlers.AuditIntegrityHandler
	SessionAnalytics  *handlers.SessionAnalyticsHandler
	Usage             *handlers.UsageHandler
	ThreatCorrelation *handlers.ThreatCorrelationHandler
	ITDR              *handlers.ITDRHandler
	// Discovery & routing
	Discover        *handlers.DiscoverHandler
	Catalog         *handlers.CatalogHandler
	RoutingWebhook  *handlers.RoutingWebhookHandler
	Hooks           *handlers.HooksHandler
	AppInstallation *handlers.AppInstallationHandler
	SpiceDBDebug    *handlers.SpiceDBDebugHandler
	// Multi-product database isolation
	ProductDatabaseGroup *handlers.ProductDatabaseGroupHandler
	// Default access policies
	DefaultAccessPolicy *handlers.DefaultAccessPolicyHandler
	// Subscription event bridge
	SubscriptionEvent *handlers.SubscriptionEventHandler
	// Dynamic group rules
	DynamicGroupRule *handlers.DynamicGroupRuleHandler
	// Platform JWT public-key discovery (RS256 migration)
	JWKS *handlers.JWKSHandler
	// SSF, CAE & backchannel logout
	SSF               *handlers.SSFHandler
	CAE               *handlers.CAEHandler
	BackchannelLogout *handlers.BackchannelLogoutHandler
	// Stub handlers for frontend endpoints not yet backed by real logic
	Stub *handlers.StubHandler
	// Internal storage — presigned MinIO download URL generator
	InternalStorage *handlers.InternalStorageHandler
	// Real-time permission change SSE stream
	PermissionStream *handlers.PermissionStreamHandler
	// Avatar upload — direct MinIO upload for user profile pictures
	AvatarUpload *handlers.AvatarUploadHandler
	// GDPR Art. 15 + 17 — data export + deletion + legal hold. Backs the
	// /api/v1/users/:id/{export,delete,deletion-status} and
	// /api/v1/deletion-requests/:id/{cancel,legal-hold} routes.
	GDPR *handlers.GDPRHandler
	// Identifier-first realm discovery
	RealmDiscovery *handlers.RealmDiscoveryHandler
	// Host-based tenant discovery — internal-only s2s endpoint
	// for SDK runtime host→tenant resolution.
	HostDiscovery *handlers.HostDiscoveryHandler
	// Slug-based tenant discovery — internal-only s2s endpoint the SDK
	// middleware's subdomain branch uses to fail closed on an unknown
	// `<slug>.<baseDomain>`. Companion of HostDiscovery above; see
	// TenantSlugDiscoveryHandler's doc comment for why it queries
	// iam_tenants directly instead of routing through HostDiscovery.
	TenantSlugDiscovery *handlers.TenantSlugDiscoveryHandler
	// Internal s2s host registration — domain-management promotes
	// hostnames it verified through its own lane into discovery.
	InternalTenantHost *handlers.InternalTenantHostHandler
	// Tenant-host admin CRUD — claim/list/verify/suspend/delete
	// custom domain registrations under
	// /api/v1/admin/tenants/:tenant_id/hosts.
	TenantHostAdmin *handlers.TenantHostAdminHandler
	// DeviceFingerprint — user-facing surface for the richer
	// iam_device_fingerprints store.
	DeviceFingerprint *handlers.DeviceFingerprintHandler
	// AdminAudit — read-side surface for the admin-action audit log.
	AdminAudit *handlers.AdminAuditHandler
	// Audit — tenant-admin user-facing audit surface (query + archive).
	// archive paths return 503 until AuditArchiverService is wired.
	Audit *handlers.AuditHandler
	// Platform-admin read surfaces — drift detection + tenant metering.
	SchemaVersion  *handlers.SchemaVersionHandler
	TenantMetering *handlers.TenantMeteringHandler
	// ProvisioningPolicy — governance-rules dry-run surface.
	// Backs /api/v1/platform/policy/{evaluate,rules}.
	ProvisioningPolicy *handlers.ProvisioningPolicyHandler
	// AgentIdentity — AI / autonomous-agent identity lifecycle.
	// 9 routes under /api/v1/platform/agents/*. Token-issuance
	// surface gates on platform_admin + step-up.
	AgentIdentity *handlers.AgentIdentityHandler
	// ComplianceEvidence — SOC2 / GDPR / KVKK live evidence
	// report generators. 3 read-only platform-admin routes
	// under /api/v1/platform/compliance/{soc2,gdpr,kvkk}.
	ComplianceEvidence *handlers.ComplianceEvidenceHandler
	// TenantTransfer — STUB surface for ENT-6 consumer→business
	// account migration. Endpoints return 501 today; real
	// implementation in Phase 2 (cmd/services.go and the actual
	// data-cascade logic).
	TenantTransfer *handlers.TenantTransferHandler
	// TenantSettings — Phase 2 General settings page prereq.
	// GET/PATCH /api/v1/tenants/me/settings (timezone + default sender domain).
	TenantSettings *handlers.TenantSettingsHandler
	// TeamInvitation — Phase 2 Team page prereq.
	// Full invite/RSVP workflow + tenant user list + role management.
	TeamInvitation *handlers.TeamInvitationHandler
	// SeatLimit — interim internal seat_limit source
	// (PUT/GET /internal/v1/tenants/:id/seat-limit) until subscription-
	// management/entitlements data exists. See seat_limit_handler.go.
	SeatLimit *handlers.SeatLimitHandler
	HREmploymentSync *handlers.HREmploymentSyncHandler
	// IAMDevices — ZTNA Phase 3 device enrollment internal API.
	// POST /internal/v1/iam-devices/enroll and
	// GET  /internal/v1/iam-devices/by-ek-hash/:hash.
	// Consumer: jess controller (devicepolicy.FalconIDEnrollmentStore).
	// Auth: ServiceAuth (OAuth2 client_credentials Bearer).
	// Reference: ADR 0043 §3.c.0, falcon-id!285.
	IAMDevices *handlers.IAMDevicesHandler
	// IAMDevicePreReg — corporate device pre-registration internal API
	// (the zero-touch CORP allowlist). GET corp-asset/by-ek-hash (jess
	// attest-time check) + bulk/list/delete CRUD (jess-web admin). Migration
	// 0007. Auth: ServiceAuth (s2s, jess controller only).
	IAMDevicePreReg *handlers.IAMDevicePreRegHandler
}

// initHandlers initializes all handlers and wires dependencies.
func initHandlers(services *Services, repos *Repositories, infra *Infrastructure) *Handlers {
	cfg := infra.Config

	// Initialize handlers
	authHandler := handlers.NewAuthHandler(services.Auth, services.Token)
	authHandler.SetPasswordResetService(services.PasswordReset)
	authHandler.SetIdpRepository(repos.IDP)
	// Wire the remember-me cookie TTL knobs (SessionTTLDefault /
	// SessionTTLRememberMe) onto the handler so falcon_idp_session
	// cookie Max-Age matches the iam_sessions.expires_at horizon set
	// inside AuthService.sessionTTLForLogin.
	authHandler.SetConfig(cfg)
	if infra.SessionCache != nil {
		authHandler.SetSessionCache(infra.SessionCache)
	}
	if infra.TokenBlacklist != nil {
		authHandler.SetTokenBlacklist(infra.TokenBlacklist)
	}
	if repos.Session != nil {
		authHandler.SetSessionRepository(repos.Session)
	}
	if services.MFAEnrollment != nil {
		authHandler.SetMFAEnrollmentService(services.MFAEnrollment)
	}

	userHandler := handlers.NewUserHandler(services.User)
	userPreferencesHandler := handlers.NewUserPreferencesHandler(services.UserPreferences, logger.Log)
	roleHandler := handlers.NewRoleHandler(services.Role)
	sodHandler := handlers.NewSoDHandler(services.SoD)
	socialAuthHandler := handlers.NewSocialAuthHandler(services.SocialAuth, cfg, logger.Log)

	adminHandler := handlers.NewAdminHandler(services.User, services.Role, repos.Session, repos.IDP, services.LDAP, services.Audit, logger.Log)
	adminHandler.SetMFAService(services.MFA)
	adminHandler.SetPasswordPolicyService(services.PasswordPolicy)
	adminHandler.SetRateLimitService(services.RateLimit)
	adminHandler.SetIPRuleService(services.IPRule)
	adminHandler.SetDeviceService(services.Device)
	adminHandler.SetTokenService(services.Token)
	adminHandler.SetLDAPSyncHistoryRepo(repos.LDAPSyncHistory)
	if infra.TokenBlacklist != nil {
		adminHandler.SetTokenBlacklist(infra.TokenBlacklist)
	}
	if infra.EncryptionService != nil {
		adminHandler.SetEncryptionService(infra.EncryptionService)
	}

	mfaHandler := handlers.NewMFAHandler(services.MFA)
	// Saved workspace names are mirrored into tenant-management (best effort).
	tenantSettingsHandler := handlers.NewTenantSettingsHandler(repos.Tenant, logger.Log)
	tenantSettingsHandler.SetWorkspaceNamePusher(services.TenantWorkspaceName)
	// Onboarding contact-verification handler — AcmeWeb wizard's
	// "confirm your mobile number" step, wired to send/verify via EMAIL
	// (see MFAService's onboarding-verify doc comment). Shares the MFA
	// service's email-OTP primitives but is registered on its own routes
	// so it is never gated on MFAEnabled.
	onboardingVerifyHandler := handlers.NewOnboardingVerifyHandler(services.MFA)
	// Onboarding subdomain-slug handler. nil-safe: NewOnboardingSlugHandler
	// on a nil *services.OnboardingSlugService is fine, route registration
	// (cmd/routes.go::registerOnboardingSlugRoute) checks for nil and
	// skips mounting the route entirely when outbound S2S creds to
	// tenant-management are unavailable.
	var onboardingSlugHandler *handlers.OnboardingSlugHandler
	if services.OnboardingSlug != nil {
		onboardingSlugHandler = handlers.NewOnboardingSlugHandler(services.OnboardingSlug)
	}
	// Onboarding status handler (GET /api/v1/auth/onboarding/status) —
	// backs the wizard's entry-time re-entry guard. nil-safe on the same
	// pattern as onboardingSlugHandler: route registration
	// (cmd/routes.go::registerOnboardingStatusRoute) checks for nil and
	// skips mounting the route entirely when outbound S2S creds to
	// tenant-management are unavailable.
	var onboardingStatusHandler *handlers.OnboardingStatusHandler
	if services.OnboardingStatus != nil {
		onboardingStatusHandler = handlers.NewOnboardingStatusHandler(services.OnboardingStatus)
	}
	// Push-MFA handler (registered alongside other /api/v1/auth/mfa/*
	// routes in cmd/routes.go::registerMFARoutes). Service may be nil
	// in environments where push providers (FCM/APNs) aren't
	// configured — the route registration short-circuits on nil.
	var pushMFAHandler *handlers.PushMFAHandler
	if services.PushMFA != nil {
		pushMFAHandler = handlers.NewPushMFAHandler(services.PushMFA)
	}
	adHandler := handlers.NewADHandler(services.LDAP, logger.Log)
	settingsHandler := handlers.NewSettingsHandler(repos.Settings, infra.EncryptionService, logger.Log)
	apiKeyHandler := handlers.NewAPIKeyHandler(services.APIKey, logger.Log)
	tenantAPIKeyHandler := handlers.NewTenantAPIKeyHandler(services.TenantAPIKey, logger.Log)
	var tenantAPIKeyLimit gin.HandlerFunc
	if infra.RedisClient != nil {
		tenantAPIKeyLimit = middleware.APIKeyExchangeRateLimit(infra.RedisClient.Redis(), logger.Log)
	} else {
		tenantAPIKeyLimit = middleware.APIKeyExchangeRateLimit(nil, logger.Log)
	}
	serviceAccountHandler := handlers.NewServiceAccountHandler(services.ServiceAccount, logger.Log)
	oauthProviderHandler := handlers.NewOAuthProviderHandler(services.OAuthProvider, services.Auth, logger.Log)
	oauthProviderHandler.SetTenantLookup(repos.Tenant)
	oauthProviderHandler.SetTokenService(services.Token)
	if infra.SessionCache != nil {
		oauthProviderHandler.SetSessionCache(infra.SessionCache)
	}
	samlHandler := handlers.NewSAMLHandler(services.SAML)
	samlSPHandler := handlers.NewSAMLSPHandler(services.SAMLSP, services.SAMLMetadata, logger.Log)
	scimHandler := handlers.NewSCIMHandler(services.SCIM, logger.Log)
	groupHandler := handlers.NewGroupHandler(services.Group, services.User)
	orgHandler := handlers.NewOrganizationHandler(services.Organization, services.User)
	impersonationHandler := handlers.NewImpersonationHandler(services.Impersonation)
	webhookHandler := handlers.NewWebhookHandler(services.Webhook)
	deviceHandler := handlers.NewDeviceHandler(services.Device)
	var recoveryHandler *handlers.RecoveryHandler
	if services.Recovery != nil {
		recoveryHandler = handlers.NewRecoveryHandler(services.Recovery)
	}
	magicLinkHandler := handlers.NewMagicLinkHandler(services.MagicLink)
	invitationHandler := handlers.NewInvitationHandler(services.Invitation)
	consentHandler := handlers.NewConsentHandler(services.Consent)
	riskHandler := handlers.NewRiskHandler(services.Risk, services.User)
	policyHandler := handlers.NewPolicyHandler(repos.Policy, repos.Settings)
	tenantHandler := handlers.NewTenantHandler(repos.Tenant, repos.User, logger.Log)
	var entitlementHandler *handlers.EntitlementHandler
	if services.Entitlement != nil {
		entitlementHandler = handlers.NewEntitlementHandler(services.Entitlement, logger.Log)
	}
	featureFlagHandler := handlers.NewFeatureFlagHandler(logger.Log)
	permissionHandler := handlers.NewPermissionHandler(services.Permission)
	roleTemplateHandler := handlers.NewRoleTemplateHandler(services.RoleTemplate)
	adSyncHandler := handlers.NewADSyncHandler(services.ADSync)
	authorizationHandler := handlers.NewAuthorizationHandler(services.Authorization, services.User)
	tenantConfigHandler := handlers.NewTenantConfigHandler(services.ConfigProvider, repos.TenantConfig, logger.Log)
	appAccessHandler := handlers.NewAppAccessHandler(services.AppAccess, logger.Log)

	// Wire OPA service to policy handler
	if services.OPA != nil {
		policyHandler.SetOPAService(services.OPA)
	}

	// Initialize context handler
	contextHandler := handlers.NewContextHandler(handlers.ContextHandlerConfig{
		TokenService: services.Token,
		AuditService: services.Audit,
		UserRepo:     repos.User,
		TenantRepo:   repos.Tenant,
		RealmRepo:    repos.RealmForContext,
		RoleRepo:     repos.Role,
		SessionCache: infra.SessionCache,
		RedisClient:  infra.RedisClient,
		RateLimiter:  infra.RateLimiter,
		DB:           infra.DB.Pool,
	})

	// Initialize platform management handler
	platformManagementHandler := handlers.NewPlatformManagementHandler(
		services.User,
		services.Role,
		services.Permission,
		services.Tenant,
		services.Audit,
		logger.Log,
		services.AcmeAppRoleProvisioner,
	)
	if services.ModuleAccess != nil {
		platformManagementHandler.SetModuleAccessReconciler(services.ModuleAccess)
	}

	metricsHandler, realmHandler, realmMiddleware := initPlatformComponents(cfg, services, repos, infra, tenantHandler)

	// Initialize CSRF middleware. The middleware chain in
	// cmd/routes.go applyGlobalMiddleware mounts authMiddleware.OptionalAuth()
	// BEFORE this CSRF middleware so the synchronizer-token Path 1
	// (per-session Redis lookup keyed by user.SessionID) has the user
	// context populated. This mirrors the canonical "auth/session
	// middleware before CSRF" ordering used by Spring Security,
	// Django, Rails, and gorilla/csrf.
	var csrfMiddleware *middleware.CSRFMiddleware
	if infra.RedisClient != nil {
		csrfMiddleware = middleware.NewCSRFMiddleware(infra.RedisClient)
		// Stage 3: same dynamic, tenant-registry-derived origin set CORS
		// consults (cmd/routes.go's CORSWithRegistry) — additive only, see
		// DynamicOriginRegistry's fail-closed doc comment. services is
		// nil-safe here too (SetOriginRegistry no-ops on a nil registry).
		csrfMiddleware.SetOriginRegistry(services.OriginRegistry)
		logger.Info("CSRF protection enabled with Redis session storage")
		authHandler.SetCSRFMiddleware(csrfMiddleware)
	} else {
		logger.Warn("CSRF protection disabled - Redis not available")
	}

	// Step-up middleware + MFA handler share the same repo instance
	// constructed in initRepositories so RequireFreshAuthForAction
	// (cmd/routes.go) and the /mfa/step-up/verify handler agree on
	// the iam_step_up_verifications view. Prior to 2026-05-26 this
	// was constructed inline here, leaving the middleware blind to
	// the rows the handler wrote.
	stepUpMiddleware := middleware.NewStepUpMiddleware(repos.StepUpVerification, logger.Log)
	mfaHandler.SetStepUpRepo(repos.StepUpVerification)
	mfaHandler.SetSessionCache(infra.SessionCache)

	// Tier-1 IdP step-up — wire SessionRepo so MFA-verify handlers can
	// elevate the current session's RFC 8176 AMR atomically with factor
	// verification. Closes the OAuth /authorize re-prompt loop documented
	// in mfa_handler.go elevateCurrentSessionAMR. Idempotent — repo's
	// AppendAuthMethod skips already-present methods.
	if repos.Session != nil {
		mfaHandler.SetSessionRepo(repos.Session)
	}

	// -------------------------------------------------------------------------
	// Product & licensing handlers
	// -------------------------------------------------------------------------
	productHandler := handlers.NewProductHandler(services.Product)
	licenseHandler := handlers.NewLicenseHandler(services.License)
	appRegistrationHandler := handlers.NewAppRegistrationHandler(services.AppRegistration)

	// Always create the handler so read-only routes (list by tenant, list by product)
	// are registered even when the orchestrator is nil (e.g. encryption not configured).
	// Write operations (Provision, Deprovision, Retry) check for nil orchestrator at runtime.
	// The orchestrator is now started in initServices (see GAP 1b) — wire the real
	// instance here instead of nil so admin Provision/Deprovision/Retry actually work.
	productInstanceHandler := handlers.NewProductInstanceHandler(services.ProductInstance, services.ProvisioningOrchestrator)
	productInstanceHandler.SetInstanceDBRepo(repos.InstanceDatabase)
	productInstanceHandler.SetInstanceRepo(repos.ProductInstance)
	productInstanceHandler.SetProvisioningStatusService(services.ProvisioningStatus)
	if infra.EncryptionService != nil {
		productInstanceHandler.SetEncryptionService(infra.EncryptionService)
	}

	// Multi-product database isolation handler
	dbGroupHandler := handlers.NewProductDatabaseGroupHandler(repos.ProductDatabaseGroup)

	// -------------------------------------------------------------------------
	// Application Object / Service Principal handlers
	// -------------------------------------------------------------------------
	appRoleHandler := handlers.NewAppRoleHandler(services.AppRole)
	credentialPolicyHandler := handlers.NewCredentialPolicyHandler(services.CredentialPolicy)
	credentialAnalysisHandler := handlers.NewCredentialAnalysisHandler(services.SPCredential)
	consentRequestHandler := handlers.NewConsentRequestHandler(services.ConsentRequest)
	registrationPolicyHandler := handlers.NewRegistrationPolicyHandler(services.RegistrationPolicy)
	servicePrincipalHandler := handlers.NewServicePrincipalHandler(services.ServicePrincipal)
	managedIdentityHandler := handlers.NewManagedIdentityHandler(services.ManagedIdentity, logger.Log)
	workloadIdentityHandler := handlers.NewWorkloadIdentityHandler(services.TokenExchange, logger.Log)
	// RFC 8693 :jwt token-exchange admin surface (v0.232.237) — manages
	// the per-tenant registry of external IdPs Falcon-ID accepts as
	// subject_token sources, plus per-client (BFF) trust grants.
	oauthTrustedExternalIssuerHandler := handlers.NewOAuthTrustedExternalIssuerHandler(
		repos.OAuthTrustedExternalIssuer, logger.Log)
	oauthTrustedExternalIssuerHandler.SetClientLookup(services.OAuthProvider.GetClient)

	applicationHandler := handlers.NewApplicationHandler(
		services.Application,
		services.AppConsent,
		services.SPCredential,
	)
	applicationHandler.SetOwnerService(services.ApplicationOwner)
	applicationHandler.SetSignInActivityService(services.SPSignInActivity)
	applicationHandler.SetStaleDetectionService(services.StaleAppDetection)
	applicationHandler.SetAppIDPService(services.AppIDP)

	// -------------------------------------------------------------------------
	// Identity & access handlers
	// -------------------------------------------------------------------------
	tempAccessPassHandler := handlers.NewTempAccessPassHandler(services.TempAccessPass)
	signupHandler := handlers.NewSignupHandler(services.Signup, logger.Log)
	delegationHandler := handlers.NewDelegationHandler(services.Delegation, logger.Log)
	guestUserHandler := handlers.NewGuestUserHandler(services.GuestUser)
	jitAccessHandler := handlers.NewJITAccessHandler(services.JITAccess, logger.Log)
	platformJITHandler := handlers.NewPlatformJITHandler(services.PlatformJIT, logger.Log)
	platformAuthHandler := handlers.NewPlatformAuthorityHandler(repos.PlatformAuthority, services.PlatformJIT, services.PlatformAuth, logger.Log)
	accessReviewHandler := handlers.NewAccessReviewHandler(services.AccessReview, logger.Log)
	emailDomainHandler := handlers.NewEmailDomainHandler(services.EmailDomain)
	tenantBrandingHandler := handlers.NewTenantBrandingHandler(services.TenantBranding)
	tenantQuotaHandler := handlers.NewTenantQuotaHandler(services.TenantQuota, logger.Log)
	idpRoutingHandler := handlers.NewIDPRoutingHandler(services.IDPRouting)
	idpTenantOverrideHandler := handlers.NewIDPTenantOverrideHandler(services.IDPTenantOverride, logger.Log)
	// WebAuthn handler is only constructed when the service is wired —
	// the routes registrar gates on a nil handler, so passing a nil-service
	// handler here would surface as a nil-deref at request time. The Auth
	// service is the link from a verified WebAuthn ceremony to a full
	// LoginResponse (session + tokens), so it is required for the login
	// endpoints to issue anything beyond a "credential verified" stub.
	var webAuthnHandler *handlers.WebAuthnHandler
	if services.WebAuthn != nil {
		webAuthnHandler = handlers.NewWebAuthnHandler(services.WebAuthn, services.Auth, logger.Log)
		webAuthnHandler.SetStepUpRepo(repos.StepUpVerification)
		// RFC 9470 step-up — WebAuthn /step-up/{begin,finish} endpoints need
		// SessionRepository to elevate the current session's AMR after a
		// successful passkey assertion. Matches MFAHandler.SetSessionRepo
		// wiring above.
		if repos.Session != nil {
			webAuthnHandler.SetSessionRepo(repos.Session)
		}
		// Browser-cookie ritual for WebAuthn login completion paths. Without
		// this wiring CompleteConditionalLogin + FinishAuthentication return
		// the LoginResponse JSON but never write falcon_access_token or
		// falcon_idp_session, leaving the browser with no session for the
		// next /oauth/authorize → infinite redirect loop downstream.
		// Single source of truth for the cookie pair: AuthHandler.SetLoginResponseCookies.
		if authHandler != nil {
			webAuthnHandler.SetAuthHandler(authHandler)
		}
		// Phase B (2026-05-26): wire MFAService so FinishRegistration
		// auto-generates backup codes when a passkey is the user's
		// first MFA factor. Nil-safe — when unset, registration still
		// succeeds; the user just has zero recovery codes (matches
		// pre-Phase-B behaviour). The user can regenerate via the
		// existing /api/v1/auth/mfa/backup-codes endpoint.
		if services.MFA != nil {
			webAuthnHandler.SetMFAService(services.MFA)
		}
		// ZTNA Path B witness (2026-06-09): wire TokenService so
		// FinishWitnessEnroll can mint the compact RS256 enrollment JWS
		// using the existing issuer key. When TokenService has no RS256
		// key wired (HS256-only environment) the endpoint returns 503.
		webAuthnHandler.SetTokenService(services.Token)
		// Begin-time {device_uuid, ek_pubkey_hash, state} binding store for the
		// passkey witness (nil Witness -> /witness/* return 503, fail closed).
		if services.Witness != nil {
			webAuthnHandler.SetWitnessState(services.Witness)
		}
		// Witness enrollment page (2026-06-10): wire CSRF middleware so
		// the page can mint a per-session CSRF token and embed it in the
		// bootstrap payload — the page's subsequent POSTs to /witness/
		// {begin,finish} pass it as X-CSRF-Token. Nil-safe; when unset
		// the page renders with an empty token and the first POST
		// surfaces a retryable error.
		if csrfMiddleware != nil {
			webAuthnHandler.SetCSRFMiddleware(csrfMiddleware)
		}
	}
	var witnessTOTPHandler *handlers.WitnessTOTPHandler
	if services.Witness != nil {
		witnessTOTPHandler = handlers.NewWitnessTOTPHandler(services.Witness, logger.Log)
	}
	scpHandler := handlers.NewSCPHandler(services.SCP, logger.Log)

	// Realm DB handler — uses adapters from realm_db_adapters.go
	var realmDBHandler *handlers.RealmDBHandler
	if services.RealmDBProvisioner != nil && services.Realm != nil {
		realmDBHandler = handlers.NewRealmDBHandler(
			newRealmDBProvisionerAdapter(services.RealmDBProvisioner),
			newRealmLookupAdapter(services.Realm),
		)
	}

	realmFederationHandler := handlers.NewRealmFederationHandler(services.RealmFederation)

	// -------------------------------------------------------------------------
	// Platform & compliance handlers
	// -------------------------------------------------------------------------
	conditionalAccessHandler := handlers.NewConditionalAccessHandler(services.ConditionalAccess, logger.Log)
	compliancePolicyHandler := handlers.NewCompliancePolicyHandler(services.CompliancePolicyEngine, services.ComplianceScheduler)
	complianceReportHandler := handlers.NewComplianceReportHandler(services.ComplianceReport, logger.Log)
	auditIntegrityHandler := handlers.NewAuditIntegrityHandler(services.ImmutableAudit, logger.Log)
	sessionAnalyticsHandler := handlers.NewSessionAnalyticsHandler(services.SessionAnalytics)
	usageHandler := handlers.NewUsageHandler(services.UsageMetering)
	threatCorrelationHandler := handlers.NewThreatCorrelationHandler(services.ThreatCorrelation, logger.Log)
	// ITDR — only constructed when the service is wired. Powers the
	// /platform/security/threats + /detection-rules surface that
	// falcon-admin's security pages call.
	var itdrHandler *handlers.ITDRHandler
	if services.ITDR != nil {
		itdrHandler = handlers.NewITDRHandler(services.ITDR, logger.Log)
	}

	// -------------------------------------------------------------------------
	// Discovery & routing handlers
	// -------------------------------------------------------------------------
	discoverHandler := handlers.NewDiscoverHandler(services.Discover, logger.Log)
	realmDiscoveryHandler := handlers.NewRealmDiscoveryHandler(services.RealmDiscovery)
	hostDiscoveryHandler := handlers.NewHostDiscoveryHandler(services.HostDiscovery)
	tenantSlugDiscoveryHandler := handlers.NewTenantSlugDiscoveryHandler(services.HostDiscovery)
	internalTenantHostHandler := handlers.NewInternalTenantHostHandler(services.HostDiscovery)
	tenantHostAdminHandler := handlers.NewTenantHostAdminHandler(services.HostDiscovery)
	catalogHandler := handlers.NewCatalogHandler(repos.Product, logger.Log)
	routingWebhookHandler := handlers.NewRoutingWebhookHandler(services.RoutingWebhook)

	// Hooks handler — backed by hook engine
	hookEngine := hooks.NewHookEngine(logger.Log)
	hooksHandler := handlers.NewHooksHandler(services.AuthHooks, hookEngine, logger.Log)

	appInstallationHandler := handlers.NewAppInstallationHandler(services.AppInstallation)

	// SpiceDB debug handler
	var spiceDBDebugHandler *handlers.SpiceDBDebugHandler
	if infra.SpiceDBClient != nil {
		var permResolver *spicedb.PermissionResolver
		if infra.SpiceDBClient != nil {
			permResolver = spicedb.NewPermissionResolver(infra.SpiceDBClient)
		}
		spiceDBDebugHandler = handlers.NewSpiceDBDebugHandler(
			services.AuthzEngine,
			services.SpiceDBReconciler,
			permResolver,
			services.TenantBootstrap,
		)
	}

	// -------------------------------------------------------------------------
	// SSF, CAE & back-channel logout handlers
	// -------------------------------------------------------------------------
	// BackchannelLogoutService: fan-out OIDC back-channel logout tokens to all
	// registered RPs when a user session is terminated. The service is wired with
	// a client lister (to enumerate registered clients for a tenant) and a token
	// signer (to issue signed logout JWTs). It also acts as an RP for receiving
	// back-channel logout tokens from upstream IDPs via the Receive endpoint.
	backchannelLogoutSvc := svc.NewBackchannelLogoutService(
		&oauthClientReaderAdapter{repo: repos.OAuthClient},
		&sessionInvalidatorAdapter{repo: repos.Session},
		svc.DefaultBackchannelLogoutConfig(),
		logger.Log,
	)
	backchannelLogoutSvc.SetClientLister(&oauthClientListerAdapter{repo: repos.OAuthClient})
	backchannelLogoutSvc.SetTokenSigner(&tokenSignerAdapter{tokenService: services.Token})
	// Phase 2 (Tier-1 SLO restoration): persistent outbox + drainer.
	// NotifyLogout enqueues rows here; the drainer (started by
	// startBackgroundTasks) handles HTTP delivery with capped retry.
	backchannelLogoutSvc.SetOutboxEnqueuer(repos.OAuthLogoutOutbox)
	// F1 (Tier-1 SLO restoration follow-up): wire the integration-bus
	// audit publisher when FALCON_INTEGRATION_BUS_URL is set. Audit
	// events for `bcl_enqueued` transitions land in the WORM
	// audit-archive MinIO bucket via the existing audit-archiver NATS
	// pipeline (memory: internal engineering notes).
	// 7-year retention per internal engineering notes.
	//
	// When the env is unset (no integration-bus deployed yet), this is
	// a no-op — Prometheus metrics + structured zap logs continue to
	// cover operational observability without WORM-grade audit.
	if busURL := os.Getenv("FALCON_INTEGRATION_BUS_URL"); busURL != "" {
		auditPub := svc.NewIntegrationBusPublisher(busURL, logger.Log)
		backchannelLogoutSvc.SetAuditPublisher(auditPub)
		logger.Info("BackchannelLogout: audit publisher wired", zap.String("integration_bus_url", busURL))
	} else {
		logger.Debug("BackchannelLogout: FALCON_INTEGRATION_BUS_URL unset, audit publisher disabled")
	}
	services.Auth.SetBackchannelLogout(backchannelLogoutSvc)
	// TokenService also needs BCL so refresh-token reuse detection can
	// fan out session_invalidated to every RP holding a live access token.
	services.Token.SetBackchannelLogout(backchannelLogoutSvc)
	// UserService uses BCL on the admin-disable cascade (Phase 5a):
	// active→disabled transition fires RFC 7009 RevokeAllUserOAuthTokens
	// + BCL fan-out so revocation latency is <5s instead of bound by
	// access-token TTL.
	services.User.SetBackchannelLogout(backchannelLogoutSvc)
	// Access terminator (disable/delete/reset/SCIM/admin revoke) fans out BCL too.
	services.AccessTerminator.SetBackchannel(backchannelLogoutSvc)
	adminHandler.SetAccessTerminator(services.AccessTerminator)

	backchannelLogoutHandler := handlers.NewBackchannelLogoutHandler(backchannelLogoutSvc, logger.Log)

	// FrontchannelLogoutService — RP-initiated logout iframe rendering for
	// OpenID Connect Front-Channel Logout 1.0. Complements BCL: BCL is the
	// server-to-server cascade, FCL is the browser iframe cascade. Both
	// run on every /oauth/logout — see oauthProviderHandler.SetFrontchannelLogout.
	frontchannelLogoutSvc := svc.NewFrontchannelLogoutService(
		&frontchannelLogoutListerAdapter{repo: repos.OAuthClient},
		logger.Log,
	)
	oauthProviderHandler.SetFrontchannelLogout(frontchannelLogoutSvc)

	stubHandler := handlers.NewStubHandler(infra.DB.Pool)
	stubHandler.SetTenantPurgePlanner(buildTenantPurgePlanner(infra.Config, logger.Log))

	// DeviceFingerprintHandler — user-self-service for the richer-signal device store.
	deviceFingerprintHandler := handlers.NewDeviceFingerprintHandler(services.DeviceFingerprint)
	// AdminAuditHandler — read-only query surface for the admin-action audit trail.
	adminAuditHandler := handlers.NewAdminAuditHandler(services.AdminAudit, logger.Log)
	// AuditHandler — tenant-admin query + archive surface (archiver nil → 503 on archive paths).
	auditHandler := handlers.NewAuditHandler(services.Audit, nil)
	// Platform-admin read surfaces — drift + metering.
	schemaVersionHandler := handlers.NewSchemaVersionHandler(services.SchemaVersion, logger.Log)
	tenantMeteringHandler := handlers.NewTenantMeteringHandler(infra.DB.Pool, services.TenantResourceMonitor)
	// ProvisioningPolicyHandler — governance dry-run for platform-admin
	// callers planning a provisioning change.
	provisioningPolicyHandler := handlers.NewProvisioningPolicyHandler(services.ProvisioningPolicy, logger.Log)
	// AgentIdentityHandler — autonomous-agent lifecycle surface.
	// Distinct from ServiceAccount: agents are human-attended
	// automation principals (AI workflows, GitHub Actions etc.),
	// not anonymous s2s.
	agentIdentityHandler := handlers.NewAgentIdentityHandler(services.AgentIdentity)

	// ComplianceEvidenceHandler — live SOC2 / GDPR / KVKK reports.
	complianceEvidenceHandler := handlers.NewComplianceEvidenceHandler(services.ComplianceLiveEvidence, logger.Log)

	// Tenant-transfer STUB handler (ENT-6 Phase 1). Routes return
	// 501 + tracking metadata so frontend can mock against a stable
	// URL surface while Phase 2 implementation lands.
	tenantTransferHandler := handlers.NewTenantTransferHandler(logger.Log)

	internalStorageHandler := initInternalStorageHandler(cfg)
	avatarUploadHandler := initAvatarUploadHandler(cfg, services)

	// GDPR Art. 15 + 17 handler. The rate limiter is the same Redis-backed
	// limiter used by the auth surface — the handler enforces a
	// 1-per-24h-per-user cap on data export inline, so this is the
	// dependency that gates that quota. May be nil in environments where
	// Redis isn't wired; the handler short-circuits to "allow" on nil
	// (test ergonomics — production Redis is load-bearing per the
	// /health/ready check).
	gdprHandler := handlers.NewGDPRHandler(
		services.DataExport,
		services.DataDeletion,
		services.User,
		infra.RateLimiter,
	)

	// Platform JWKS handler — exposes the RS256 public key(s) for platform-issued JWTs.
	// When KeyManager is wired, all active+rotated keys are served (graceful rotation).
	// Merges OAuth provider keys so clients have a single discovery endpoint.
	jwksHandler := handlers.NewJWKSHandler(services.JWTKeyProvider)
	jwksHandler.SetMaxAge(cfg.JWKSMaxAge)
	if services.KeyManager != nil {
		jwksHandler.SetKeyManager(services.KeyManager)
	}
	jwksHandler.SetOAuthKeysFunc(oauthProviderHandler.GetJWKSData)

	// Default access policy handler
	defaultAccessPolicyHandler := handlers.NewDefaultAccessPolicyHandler(repos.DefaultAccessPolicy)

	// Subscription event handler (receives events from subscription-management)
	subscriptionEventHandler := handlers.NewSubscriptionEventHandler(services.SubscriptionBridge)

	// Dynamic group rule handler
	dynamicGroupRuleHandler := handlers.NewDynamicGroupRuleHandler(repos.DynamicGroupRule)

	// Permission stream SSE handler — real-time permission change notifications.
	// Requires a go-redis *Client for Pub/Sub subscriptions.
	var permissionStreamHandler *handlers.PermissionStreamHandler
	if infra.RedisClient != nil {
		permissionStreamHandler = handlers.NewPermissionStreamHandler(
			infra.RedisClient.Redis(), logger.Log)
	}

	// ZTNA Phase 3 IAM devices handler — internal s2s enrollment API.
	// Backed by IAMDevicesRepository (falcon-id!285). ServiceAuth-gated
	// (registered in registerInternalAPIRoutes). Consumer: jess controller
	// via devicepolicy.FalconIDEnrollmentStore (ADR 0043 §3.c.0).
	iamDevicesHandler := handlers.NewIAMDevicesHandler(repos.IAMDevices)

	// Corporate device pre-registration handler — the zero-touch CORP
	// allowlist (migration 0007). ServiceAuth-gated; consumed by jess.
	iamDevicePreRegHandler := handlers.NewIAMDevicePreRegHandler(repos.IAMDevicePreReg)

	logger.Info("Handlers initialized",
		zap.Int("total_handlers", 80),
		zap.Bool("realm_enabled", realmHandler != nil),
		zap.Bool("product_instance_enabled", productInstanceHandler != nil),
		zap.Bool("realm_db_enabled", realmDBHandler != nil),
		zap.Bool("spicedb_debug_enabled", spiceDBDebugHandler != nil),
	)

	teamInvitationHandler := handlers.NewTeamInvitationHandler(repos.Tenant, repos.User, repos.Role, services.Role, repos.TeamInvitation, logger.Log)
	teamInvitationHandler.SetMachineRepositories(repos.ServiceAccount, repos.ServicePrincipal)
	teamInvitationHandler.SetEmailService(services.Email)
	teamInvitationHandler.SetTenantBootstrap(services.TenantBootstrap)
	teamInvitationHandler.SetEmployeeAccountServices(services.User, services.TemplateRoleProvisioner, services.Invitation, services.EmployeeAccess)
	teamInvitationHandler.SetSeatRepositories(repos.UserMembership, repos.SeatCounter)
	teamInvitationHandler.SetFirstPartyEmailProof(repos.SignupRequest)
	teamInvitationHandler.SetOnboardingServices(services.User, services.Auth)
	teamInvitationHandler.SetContextCacheInvalidator(func(ctx context.Context, userID uuid.UUID) {
		handlers.InvalidateUserContextsCache(ctx, infra.RedisClient, userID)
	})

	seatLimitHandler := handlers.NewSeatLimitHandler(repos.SeatCounter, logger.Log)
	hrEmploymentSyncHandler := handlers.NewHREmploymentSyncHandler(services.HREmploymentSync)

	return &Handlers{
		ApprovalDirectory:  handlers.NewApprovalDirectoryHandler(repos.UserMembership, infra.SpiceDBClient),
		TeamScope:          handlers.NewTeamScopeHandler(services.Organization),
		TenantTeam:         handlers.NewTenantTeamHandler(services.Organization),
		NotifRecipients:    handlers.NewNotificationRecipientsHandler(repositories.NewNotificationRecipientRepository(infra.DB.Pool, infra.EncryptionService), services.AuthzEngine),
		Auth:               authHandler,
		User:               userHandler,
		UserPreferences:    userPreferencesHandler,
		Role:               roleHandler,
		SoD:                sodHandler,
		SocialAuth:         socialAuthHandler,
		Admin:              adminHandler,
		MFA:                mfaHandler,
		PushMFA:            pushMFAHandler,
		OnboardingVerify:   onboardingVerifyHandler,
		OnboardingSlug:     onboardingSlugHandler,
		OnboardingStatus:   onboardingStatusHandler,
		AD:                 adHandler,
		Settings:           settingsHandler,
		APIKey:             apiKeyHandler,
		TenantAPIKey:       tenantAPIKeyHandler,
		TenantAPIKeyLimit:  tenantAPIKeyLimit,
		ServiceAccount:     serviceAccountHandler,
		OAuthProvider:      oauthProviderHandler,
		SAML:               samlHandler,
		SAMLSP:             samlSPHandler,
		SCIM:               scimHandler,
		Group:              groupHandler,
		Organization:       orgHandler,
		Impersonation:      impersonationHandler,
		Webhook:            webhookHandler,
		Device:             deviceHandler,
		Recovery:           recoveryHandler,
		MagicLink:          magicLinkHandler,
		Invitation:         invitationHandler,
		Consent:            consentHandler,
		Risk:               riskHandler,
		Policy:             policyHandler,
		Tenant:             tenantHandler,
		Entitlement:        entitlementHandler,
		FeatureFlag:        featureFlagHandler,
		Permission:         permissionHandler,
		RoleTemplate:       roleTemplateHandler,
		ADSync:             adSyncHandler,
		Context:            contextHandler,
		PlatformManagement: platformManagementHandler,
		AppAccess:          appAccessHandler,
		Realm:              realmHandler,
		Metrics:            metricsHandler,
		Authorization:      authorizationHandler,
		TenantConfig:       tenantConfigHandler,
		CSRFMiddleware:     csrfMiddleware,
		RealmMiddleware:    realmMiddleware,
		StepUpMiddleware:   stepUpMiddleware,
		// Product & licensing
		Product:              productHandler,
		License:              licenseHandler,
		ProductInstance:      productInstanceHandler,
		AppRegistration:      appRegistrationHandler,
		ProductDatabaseGroup: dbGroupHandler,
		// Applications & service principals
		Application:                applicationHandler,
		AppRole:                    appRoleHandler,
		CredentialPolicy:           credentialPolicyHandler,
		CredentialAnalysis:         credentialAnalysisHandler,
		ConsentRequest:             consentRequestHandler,
		RegistrationPolicy:         registrationPolicyHandler,
		ServicePrincipal:           servicePrincipalHandler,
		ManagedIdentity:            managedIdentityHandler,
		WorkloadIdentity:           workloadIdentityHandler,
		OAuthTrustedExternalIssuer: oauthTrustedExternalIssuerHandler,
		// Identity & access
		TempAccessPass:    tempAccessPassHandler,
		Signup:            signupHandler,
		Delegation:        delegationHandler,
		GuestUser:         guestUserHandler,
		JITAccess:         jitAccessHandler,
		PlatformJIT:       platformJITHandler,
		PlatformAuth:      platformAuthHandler,
		Ops:               initOpsConsole(services, repos, infra),
		AccessReview:      accessReviewHandler,
		EmailDomain:       emailDomainHandler,
		TenantBranding:    tenantBrandingHandler,
		TenantQuota:       tenantQuotaHandler,
		IDPRouting:        idpRoutingHandler,
		IDPTenantOverride: idpTenantOverrideHandler,
		WebAuthn:          webAuthnHandler,
		WitnessTOTP:       witnessTOTPHandler,
		SCP:               scpHandler,
		RealmDB:           realmDBHandler,
		RealmFederation:   realmFederationHandler,
		// Platform & compliance
		ConditionalAccess: conditionalAccessHandler,
		CompliancePolicy:  compliancePolicyHandler,
		ComplianceReport:  complianceReportHandler,
		AuditIntegrity:    auditIntegrityHandler,
		SessionAnalytics:  sessionAnalyticsHandler,
		Usage:             usageHandler,
		ThreatCorrelation: threatCorrelationHandler,
		ITDR:              itdrHandler,
		// Discovery & routing
		Discover:            discoverHandler,
		RealmDiscovery:      realmDiscoveryHandler,
		HostDiscovery:       hostDiscoveryHandler,
		TenantSlugDiscovery: tenantSlugDiscoveryHandler,
		InternalTenantHost:  internalTenantHostHandler,
		TenantHostAdmin:     tenantHostAdminHandler,
		DeviceFingerprint:   deviceFingerprintHandler,
		AdminAudit:          adminAuditHandler,
		Audit:               auditHandler,
		SchemaVersion:       schemaVersionHandler,
		TenantMetering:      tenantMeteringHandler,
		ProvisioningPolicy:  provisioningPolicyHandler,
		AgentIdentity:       agentIdentityHandler,
		ComplianceEvidence:  complianceEvidenceHandler,
		TenantTransfer:      tenantTransferHandler,
		TenantSettings:      tenantSettingsHandler,
		TenantWorkspaceName: handlers.NewTenantWorkspaceNameHandler(services.TenantWorkspaceName, logger.Log),
		TeamInvitation:      teamInvitationHandler,
		SeatLimit:           seatLimitHandler,
		HREmploymentSync:    hrEmploymentSyncHandler,
		Catalog:             catalogHandler,
		RoutingWebhook:      routingWebhookHandler,
		Hooks:               hooksHandler,
		AppInstallation:     appInstallationHandler,
		SpiceDBDebug:        spiceDBDebugHandler,
		DefaultAccessPolicy: defaultAccessPolicyHandler,
		SubscriptionEvent:   subscriptionEventHandler,
		DynamicGroupRule:    dynamicGroupRuleHandler,
		JWKS:                jwksHandler,
		BackchannelLogout:   backchannelLogoutHandler,
		Stub:                stubHandler,
		InternalStorage:     internalStorageHandler,
		PermissionStream:    permissionStreamHandler,
		AvatarUpload:        avatarUploadHandler,
		GDPR:                gdprHandler,
		IAMDevices:          iamDevicesHandler,
		IAMDevicePreReg:     iamDevicePreRegHandler,
	}
}

// initPlatformComponents initializes the metrics handler, realm handler, and realm middleware
// when the control plane database is available. Returns nil values when the control plane is absent.
func initPlatformComponents(
	cfg *config.Config,
	services *Services,
	repos *Repositories,
	infra *Infrastructure,
	tenantHandler *handlers.TenantHandler,
) (*platformhandlers.MetricsHandler, *handlers.RealmHandler, *middleware.RealmMiddleware) {
	if infra.ControlPlaneDB == nil {
		return nil, nil, nil
	}

	metricsHandler := platformhandlers.NewMetricsHandler(infra.DB.Pool)
	if infra.RedisClient != nil {
		metricsHandler.SetRedisClient(infra.RedisClient)
		logger.Info("Redis metrics enabled for metrics handler")
	}
	logger.Info("Platform components initialized (including metrics handler)")

	if !cfg.RealmEnabled || services.Realm == nil {
		return metricsHandler, nil, nil
	}

	realmHandler := handlers.NewRealmHandler(services.Realm, logger.Log)
	realmMiddleware := middleware.NewRealmMiddleware(services.Realm, cfg, logger.Log)
	realmMiddleware.Configure(middleware.RealmMiddlewareConfig{
		SubdomainEnabled: cfg.RealmSubdomainEnabled,
		HeaderEnabled:    cfg.RealmHeaderEnabled,
		URLPrefixEnabled: cfg.RealmURLPrefixEnabled,
		DefaultRealmSlug: cfg.RealmDefaultSlug,
	})
	tenantHandler.SetRealmRepo(repos.Realm)
	logger.Info("Realm architecture components initialized",
		zap.Bool("subdomain_enabled", cfg.RealmSubdomainEnabled),
		zap.Bool("header_enabled", cfg.RealmHeaderEnabled),
		zap.Bool("url_prefix_enabled", cfg.RealmURLPrefixEnabled),
		zap.String("default_slug", cfg.RealmDefaultSlug),
		zap.Bool("redis_cache_enabled", infra.RedisClient != nil),
	)
	return metricsHandler, realmHandler, realmMiddleware
}

// buildMinIOConfig builds a storage config from application config.
func buildMinIOConfig(cfg *config.Config) handlers.InternalStorageConfig {
	return handlers.InternalStorageConfig{
		Endpoint:         cfg.MinIOEndpoint,
		ExternalEndpoint: cfg.MinIOExternalEndpoint,
		AccessKey:        cfg.MinIOAccessKey,
		SecretKey:        cfg.MinIOSecretKey,
		DefaultBucket:    cfg.MinIOBucket,
	}
}

// initInternalStorageHandler initializes the presigned MinIO download handler.
// Initialization is best-effort; returns nil on error so IAM startup is not blocked.
func initInternalStorageHandler(cfg *config.Config) *handlers.InternalStorageHandler {
	storageCfg := buildMinIOConfig(cfg)
	h, err := handlers.NewInternalStorageHandler(storageCfg)
	if err != nil {
		logger.Warn("InternalStorageHandler init failed — presigned-download endpoint will return 503",
			zap.Error(err),
		)
		return nil
	}
	logger.Info("InternalStorageHandler initialized",
		zap.String("minio_endpoint", storageCfg.Endpoint),
		zap.String("minio_external_endpoint", storageCfg.ExternalEndpoint),
		zap.String("default_bucket", storageCfg.DefaultBucket),
	)
	return h
}

// initAvatarUploadHandler initializes the MinIO avatar upload handler.
// Initialization is best-effort; returns nil on error so IAM startup is not blocked.
func initAvatarUploadHandler(cfg *config.Config, services *Services) *handlers.AvatarUploadHandler {
	storageCfg := buildMinIOConfig(cfg)
	h, err := handlers.NewAvatarUploadHandler(storageCfg, services.Auth)
	if err != nil {
		logger.Warn("AvatarUploadHandler init failed — avatar upload will return 503",
			zap.Error(err),
		)
		return nil
	}
	logger.Info("AvatarUploadHandler initialized")
	return h
}
