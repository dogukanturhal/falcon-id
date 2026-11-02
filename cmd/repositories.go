// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/repositories"
	"github.com/dogukanturhal/falcon-id/pkg/logger"
)

// Repositories holds all repository instances.
type Repositories struct {
	User               *repositories.UserRepository
	Role               *repositories.RoleRepository
	Permission         *repositories.PermissionRepository
	RoleTemplate       *repositories.RoleTemplateRepository
	Session            *repositories.SessionRepository
	Token              *repositories.TokenRepository
	IDP                *repositories.IdentityProviderRepository
	FedAccount         *repositories.FederatedAccountRepository
	MFA                *repositories.MFARepository
	Settings           *repositories.SettingsRepository
	APIKey             *repositories.APIKeyRepository
	ServiceAccount     *repositories.ServiceAccountRepository
	OAuthClient        *repositories.OAuthClientRepository
	SAML               *repositories.SAMLRepository
	SAMLSP             *repositories.SAMLSPRepository
	SCIM               *repositories.SCIMRepository
	Group              *repositories.GroupRepository
	Organization       *repositories.OrganizationRepository
	Impersonation      *repositories.ImpersonationRepository
	Webhook            *repositories.WebhookRepository
	Device             *repositories.DeviceRepository
	PushMFA            *repositories.PushMFARepository
	MagicLink          *repositories.MagicLinkRepository
	Invitation         *repositories.InvitationRepository
	Consent            *repositories.ConsentRepository
	Risk               *repositories.RiskRepository
	Policy             *repositories.PolicyRepository
	Tenant             *repositories.TenantRepository
	LDAPSyncHistory    *repositories.LDAPSyncHistoryRepository
	ADSync             *repositories.ADSyncRepository
	PasswordPolicy     *repositories.PasswordPolicyRepository
	RateLimit          *repositories.RateLimitRepository
	IPRule             *repositories.IPRuleRepository
	StepUpVerification *repositories.StepUpVerificationRepository
	AppAccess          *repositories.AppAccessRepository
	Realm              *repositories.RealmRepository
	RealmForContext    *repositories.RealmRepository
	TenantConfig       *repositories.TenantConfigRepository
	// ADR-A10 SoD (Separation of Duties) rule matrix + violations
	// (migration 0015).
	SoD *repositories.SoDRepository
	// Product & licensing
	Product         *repositories.ProductRepository
	License         *repositories.LicenseRepository
	ProductInstance *repositories.ProductInstanceRepository
	AppRegistration *repositories.AppRegistrationRepository
	// Applications & service principals
	Application        *repositories.ApplicationRepository
	ServicePrincipal   *repositories.ServicePrincipalRepository
	AppConsent         *repositories.AppConsentRepository
	SPCredential       *repositories.SPCredentialRepository
	SPSignInActivity   *repositories.SPSignInActivityRepository
	ApplicationOwner   *repositories.ApplicationOwnerRepository
	AppIDP             *repositories.AppIdentityProviderRepository
	AppInstallation    *repositories.AppInstallationRepository
	AppRole            *repositories.ApplicationRoleAssignmentRepository
	CredentialPolicy   *repositories.CredentialPolicyRepository
	ConsentRequest     *repositories.ConsentRequestRepository
	RegistrationPolicy *repositories.RegistrationPolicyRepository
	BootstrapToken     *repositories.BootstrapTokenRepository
	// Identity & access
	Delegation     *repositories.DelegationRepository
	TempAccessPass *repositories.TempAccessPassRepository
	GuestUser      *repositories.GuestUserRepository
	JITAccess      *repositories.JITAccessRepository
	JITEligible    *repositories.JITEligibleRepository
	// PlatformElevation — R1 platform plane: JIT elevation + break-glass
	// (iam_platform_roles / iam_jit_elevations, migration 0016).
	PlatformElevation *repositories.PlatformElevationRepository
	// PlatformAuthority — live iam_platform_roles reads (OPS_STRICT_PLATFORM_ROLES,
	// operator token exchange, legacy-admin report).
	PlatformAuthority   *repositories.PlatformAuthorityRepository
	AccessReview        *repositories.AccessReviewRepository
	EmailDomainRegistry *repositories.EmailDomainRegistryRepository
	TenantBranding      *repositories.TenantBrandingRepository
	TenantHost          *repositories.TenantHostRepository
	TenantQuota         *repositories.TenantQuotaRepository
	IDPRouting          *repositories.IDPRoutingRepository
	IDPTenantOverride   *repositories.IDPTenantOverrideRepository
	WebAuthn            *repositories.WebAuthnRepository
	WorkloadIdentity    *repositories.WorkloadIdentityRepository
	// OAuthTrustedExternalIssuer backs the RFC 8693 :jwt subject_token_type
	// path (Talon IAP → BFF token-handler bridge) — distinct from
	// WorkloadIdentity which targets SPIFFE / k8s workload federation.
	// Schema landed in keystone bundle falcon-id-v0.232.237.
	OAuthTrustedExternalIssuer *repositories.OAuthTrustedExternalIssuerRepository
	SCP                        *repositories.SCPRepository
	SignupRequest              *repositories.SignupRequestRepository
	RealmFederation            *repositories.RealmFederationRepository
	RealmDatabase              *repositories.RealmDatabaseRepository
	UsageRecord                *repositories.UsageRecordRepository
	RoutingWebhook             *repositories.RoutingWebhookRepository
	// Multi-product database isolation
	ProductDatabaseGroup *repositories.ProductDatabaseGroupRepository
	InstanceDatabase     *repositories.InstanceDatabaseRepository
	// Default access policies
	DefaultAccessPolicy *repositories.DefaultAccessPolicyRepository
	// Provisioning events
	ProvisioningEvent *repositories.ProvisioningEventRepository
	// Dynamic group rules
	DynamicGroupRule *repositories.DynamicGroupRuleRepository
	// Security features: ITDR and SSF
	ITDR *repositories.ITDRRepository
	SSF  *repositories.SSFRepository
	// Identifier-first realm discovery
	TenantDomain *repositories.TenantDomainRepository
	// Platform feature flags (used by AuthService for admin-passkey policy etc.)
	FeatureFlag *repositories.FeatureFlagRepository
	// OAuthLogoutOutbox backs the BCL transactional-outbox / drainer
	// pattern (Phase 2 of the 2026-05-10 SLO restoration). Schema landed
	// in keystone bundle falcon-id-v0.234.234.
	OAuthLogoutOutbox *repositories.OAuthLogoutOutboxRepository
	// DeviceFingerprint backs the iam_device_fingerprints richer-signal
	// table (geo / browser version / screen resolution / timezone). Used
	// by DeviceFingerprintService — distinct from Device above, which
	// manages the simpler iam_user_devices table for user-facing trust mgmt.
	DeviceFingerprint *repositories.DeviceFingerprintRepository
	// AgentIdentity backs the AI-agent identity lifecycle surface
	// (/api/v1/platform/agents/*). Distinct from ServiceAccount —
	// agents are autonomous human-attended automation principals
	// (think GitHub Actions, agent-driven workflows), not
	// service-to-service auth.
	AgentIdentity *repositories.AgentIdentityRepository
	// TeamInvitation — Phase 2 Team page invite/RSVP workflow.
	TeamInvitation *repositories.TeamInvitationRepository
	// UserMembership — tenant<->user membership + seat_class ledger
	// (iam_user_memberships, migration 0013). Seat-counting source of truth.
	UserMembership *repositories.UserMembershipRepository
	HREmploymentSync *repositories.HREmploymentSyncRepository
	// SeatCounter — race-free tenant_seat_counters reservation counter
	// (migration 0013). See internal/repositories/seat_counter_repository.go.
	SeatCounter *repositories.SeatCounterRepository
	// IAMDevices — ZTNA Phase 3 device-cert enrollment registry.
	// Introduced by migration 0004_iam_devices.sql (falcon-id!284) and
	// the repository layer (falcon-id!285). Used by IAMDevicesHandler
	// for the internal s2s enrollment + TOFU lookup endpoints.
	IAMDevices *repositories.IAMDevicesRepository
	// IAMDevicePreReg — corporate device pre-registration allowlist
	// (migration 0007). The zero-touch CORP trust layer: jess downgrades
	// CORP -> BYOD for any genuine-TPM device not on this allowlist.
	IAMDevicePreReg *repositories.IAMDevicePreRegRepository
	// Recovery — account-recovery methods (recovery email today; phone
	// reserved). Migration 0005_user_recovery_methods.sql. Backs the
	// self-service /users/me/recovery endpoints via RecoveryService.
	Recovery *repositories.RecoveryRepository
	// ModuleEntitlement backs iam_tenant_module_entitlements +
	// iam_tenant_entitlement_flags (migration
	// 0014_iam_tenant_module_entitlements.sql, the product roadmap §4.1). Fed
	// by the example.tenant.modules.sync Kafka consumer
	// (internal/entitlementsync) and PUT
	// /internal/v1/tenants/{id}/module-entitlements, read by GET
	// /api/v1/tenant/entitlements via
	// services.TenantEntitlementService.
	ModuleEntitlement *repositories.ModuleEntitlementRepository
}

// initRepositories initializes all repositories.
func initRepositories(infra *Infrastructure) *Repositories {
	repos := &Repositories{
		TenantConfig:       repositories.NewTenantConfigRepository(infra.DB.Pool),
		User:               repositories.NewUserRepository(infra.DB.Pool),
		Role:               repositories.NewRoleRepository(infra.DB.Pool),
		Permission:         repositories.NewPermissionRepository(infra.DB.Pool),
		RoleTemplate:       repositories.NewRoleTemplateRepository(infra.DB.Pool),
		SoD:                repositories.NewSoDRepository(infra.DB.Pool),
		Session:            repositories.NewSessionRepository(infra.DB.Pool),
		Token:              repositories.NewTokenRepository(infra.DB.Pool),
		IDP:                repositories.NewIdentityProviderRepository(infra.DB.Pool),
		FedAccount:         repositories.NewFederatedAccountRepository(infra.DB.Pool),
		MFA:                repositories.NewMFARepository(infra.DB.Pool),
		Settings:           repositories.NewSettingsRepository(infra.DB.Pool),
		APIKey:             repositories.NewAPIKeyRepository(infra.DB.Pool),
		ServiceAccount:     repositories.NewServiceAccountRepository(infra.DB.Pool),
		OAuthClient:        repositories.NewOAuthClientRepository(infra.DB.Pool),
		SAML:               repositories.NewSAMLRepository(infra.DB.Pool),
		SAMLSP:             repositories.NewSAMLSPRepository(infra.DB.Pool),
		SCIM:               repositories.NewSCIMRepository(infra.DB.Pool),
		Group:              repositories.NewGroupRepository(infra.DB.Pool),
		Organization:       repositories.NewOrganizationRepository(infra.DB.Pool),
		Impersonation:      repositories.NewImpersonationRepository(infra.DB.Pool),
		Webhook:            repositories.NewWebhookRepository(infra.DB.Pool),
		Device:             repositories.NewDeviceRepository(infra.DB.Pool),
		Recovery:           repositories.NewRecoveryRepository(infra.DB.Pool),
		PushMFA:            repositories.NewPushMFARepository(infra.DB.Pool),
		MagicLink:          repositories.NewMagicLinkRepository(infra.DB.Pool),
		Invitation:         repositories.NewInvitationRepository(infra.DB.Pool),
		Consent:            repositories.NewConsentRepository(infra.DB.Pool),
		Risk:               repositories.NewRiskRepository(infra.DB.Pool),
		Policy:             repositories.NewPolicyRepository(infra.DB.Pool),
		Tenant:             repositories.NewTenantRepository(infra.DB.Pool),
		LDAPSyncHistory:    repositories.NewLDAPSyncHistoryRepository(infra.DB.Pool),
		ADSync:             repositories.NewADSyncRepository(infra.DB.Pool),
		PasswordPolicy:     repositories.NewPasswordPolicyRepository(infra.DB.Pool),
		RateLimit:          repositories.NewRateLimitRepository(infra.DB.Pool),
		IPRule:             repositories.NewIPRuleRepository(infra.DB.Pool),
		StepUpVerification: repositories.NewStepUpVerificationRepository(infra.DB.Pool),
		AppAccess:          repositories.NewAppAccessRepository(infra.DB.Pool),
		ModuleEntitlement:  repositories.NewModuleEntitlementRepository(infra.DB.Pool),
		// Product & licensing
		Product:         repositories.NewProductRepository(infra.DB.Pool),
		License:         repositories.NewLicenseRepository(infra.DB.Pool),
		ProductInstance: repositories.NewProductInstanceRepository(infra.DB.Pool),
		AppRegistration: repositories.NewAppRegistrationRepository(infra.DB.Pool),
		// Applications & service principals
		Application:        repositories.NewApplicationRepository(infra.DB.Pool),
		ServicePrincipal:   repositories.NewServicePrincipalRepository(infra.DB.Pool),
		AppConsent:         repositories.NewAppConsentRepository(infra.DB.Pool),
		SPCredential:       repositories.NewSPCredentialRepository(infra.DB.Pool),
		SPSignInActivity:   repositories.NewSPSignInActivityRepository(infra.DB.Pool),
		ApplicationOwner:   repositories.NewApplicationOwnerRepository(infra.DB.Pool),
		AppIDP:             repositories.NewAppIdentityProviderRepository(infra.DB.Pool),
		AppInstallation:    repositories.NewAppInstallationRepository(infra.DB.Pool),
		AppRole:            repositories.NewApplicationRoleAssignmentRepository(infra.DB.Pool),
		CredentialPolicy:   repositories.NewCredentialPolicyRepository(infra.DB.Pool),
		ConsentRequest:     repositories.NewConsentRequestRepository(infra.DB.Pool),
		RegistrationPolicy: repositories.NewRegistrationPolicyRepository(infra.DB.Pool),
		BootstrapToken:     repositories.NewBootstrapTokenRepository(infra.DB.Pool),
		// Identity & access
		Delegation:                 repositories.NewDelegationRepository(infra.DB.Pool),
		TempAccessPass:             repositories.NewTempAccessPassRepository(infra.DB.Pool),
		GuestUser:                  repositories.NewGuestUserRepository(infra.DB.Pool),
		JITAccess:                  repositories.NewJITAccessRepository(infra.DB.Pool),
		JITEligible:                repositories.NewJITEligibleRepository(infra.DB.Pool),
		PlatformElevation:          repositories.NewPlatformElevationRepository(infra.DB.Pool),
		PlatformAuthority:          repositories.NewPlatformAuthorityRepository(infra.DB.Pool),
		AccessReview:               repositories.NewAccessReviewRepository(infra.DB.Pool),
		EmailDomainRegistry:        repositories.NewEmailDomainRegistryRepository(infra.DB.Pool),
		TenantBranding:             repositories.NewTenantBrandingRepository(infra.DB.Pool),
		TenantHost:                 repositories.NewTenantHostRepository(infra.DB.Pool),
		TenantQuota:                repositories.NewTenantQuotaRepository(infra.DB.Pool),
		IDPRouting:                 repositories.NewIDPRoutingRepository(infra.DB.Pool),
		IDPTenantOverride:          repositories.NewIDPTenantOverrideRepository(infra.DB.Pool),
		WebAuthn:                   repositories.NewWebAuthnRepository(infra.DB.Pool),
		FeatureFlag:                repositories.NewFeatureFlagRepository(infra.DB.Pool),
		OAuthLogoutOutbox:          repositories.NewOAuthLogoutOutboxRepository(infra.DB.Pool),
		WorkloadIdentity:           repositories.NewWorkloadIdentityRepository(infra.DB.Pool),
		OAuthTrustedExternalIssuer: repositories.NewOAuthTrustedExternalIssuerRepository(infra.DB.Pool),
		SCP:                        repositories.NewSCPRepository(infra.DB.Pool),
		SignupRequest:              repositories.NewSignupRequestRepository(infra.DB.Pool),
		RealmFederation:            repositories.NewRealmFederationRepository(infra.DB.Pool),
		RealmDatabase:              repositories.NewRealmDatabaseRepository(infra.DB.Pool),
		UsageRecord:                repositories.NewUsageRecordRepository(infra.DB.Pool),
		RoutingWebhook:             repositories.NewRoutingWebhookRepository(infra.DB.Pool),
		// Multi-product database isolation
		ProductDatabaseGroup: repositories.NewProductDatabaseGroupRepository(infra.DB.Pool),
		InstanceDatabase:     repositories.NewInstanceDatabaseRepository(infra.DB.Pool),
		// Default access policies
		DefaultAccessPolicy: repositories.NewDefaultAccessPolicyRepository(infra.DB.Pool),
		// Provisioning events
		ProvisioningEvent: repositories.NewProvisioningEventRepository(infra.DB.Pool),
		// Dynamic group rules
		DynamicGroupRule: repositories.NewDynamicGroupRuleRepository(infra.DB.Pool),
		// Security features: ITDR and SSF (tables pending migrations 150-151;
		// repositories degrade gracefully until migrations run)
		ITDR: repositories.NewITDRRepository(infra.DB.Pool),
		SSF:  repositories.NewSSFRepository(infra.DB.Pool),
		// Identifier-first realm discovery
		TenantDomain: repositories.NewTenantDomainRepository(infra.DB.Pool),
		// Richer device-fingerprint store (separate from iam_user_devices)
		DeviceFingerprint: repositories.NewDeviceFingerprintRepository(infra.DB.Pool),
		// AI-agent identity lifecycle store
		AgentIdentity:  repositories.NewAgentIdentityRepository(infra.DB.Pool),
		TeamInvitation: repositories.NewTeamInvitationRepository(infra.DB.Pool),
		UserMembership: repositories.NewUserMembershipRepository(infra.DB.Pool),
		HREmploymentSync: repositories.NewHREmploymentSyncRepository(infra.DB.Pool),
		SeatCounter:    repositories.NewSeatCounterRepository(infra.DB.Pool),
		// ZTNA Phase 3 — device-cert enrollment registry (ADR 0043).
		IAMDevices: repositories.NewIAMDevicesRepository(infra.DB.Pool),
		// Corporate device pre-registration allowlist (migration 0007).
		IAMDevicePreReg: repositories.NewIAMDevicePreRegRepository(infra.DB.Pool),
	}

	// Wire encryption service for PII encryption and token encryption.
	// Additional repositories receive it for read-path decryption of JOINed
	// iam_users columns (email/first_name/last_name/display_name) so admin
	// list endpoints (members, role-members, impersonation history) return
	// plaintext instead of `enc:v1:base64...` ciphertext.
	if infra.EncryptionService != nil {
		repos.User.SetEncryptionService(infra.EncryptionService)
		repos.FedAccount.SetEncryptionService(infra.EncryptionService)
		repos.MFA.SetEncryptionService(infra.EncryptionService)
		repos.Organization.SetEncryptionService(infra.EncryptionService)
		repos.Group.SetEncryptionService(infra.EncryptionService)
		repos.Role.SetEncryptionService(infra.EncryptionService)
		repos.Impersonation.SetEncryptionService(infra.EncryptionService)
		logger.Info("Encryption service configured for User, FederatedAccount, MFA, Organization, Group, Role, and Impersonation repositories")
	}

	// Initialize control plane repositories if available
	if infra.ControlPlaneDB != nil {
		repos.Realm = repositories.NewRealmRepository(infra.ControlPlaneDB.Pool)
		repos.RealmForContext = repositories.NewRealmRepository(infra.ControlPlaneDB.Pool)
		logger.Info("Control plane repositories initialized")
	}

	logger.Info("Repositories initialized",
		zap.Int("data_plane_repos", 63),
		zap.Bool("control_plane_repos", infra.ControlPlaneDB != nil),
	)

	return repos
}
