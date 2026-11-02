// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/dogukanturhal/falcon-id/internal/middleware"
	"github.com/dogukanturhal/falcon-id/pkg/logger"
)

const (
	// Admin route path segments duplicated 3+ times
	pathIDPByID             = "/identity-providers/:id"
	pathEmployees           = "/employees"
	pathRateLimitsByID      = "/security/rate-limits/:id"
	pathIPRulesByID         = "/security/ip-rules/:id"
	pathAPIKeysByID         = "/api-keys/:id" //nolint:gosec // not a credential, this is a route prefix constant
	pathServiceAccountsByID = "/service-accounts/:id"
	pathOAuthClientsByID    = "/oauth-clients/:id"
	pathSAMLSPByID          = "/saml/service-providers/:id"
	pathSCIMTokensByID      = "/scim/tokens/:id" //nolint:gosec // not a credential, this is a route prefix constant
	pathFeatureFlagsByID    = "/feature-flags/:id"
	pathIAMGroupsByID       = "/iam-groups/:id"
	pathIAMGroupsIDMembers  = "/iam-groups/:id/members"
	pathIAMGroupsIDRoles    = "/iam-groups/:id/roles"
	pathOrgsByID            = "/organizations/:id"
	pathOrgsIDMembers       = "/organizations/:id/members"
	pathOrgsIDIAMRoles      = "/organizations/:id/iam-roles"
	pathWebhooksByID        = "/webhooks/:id"
	pathRiskPoliciesByID    = "/security/risk-policies/:id"
	pathPolicies            = "/policies"
	pathPoliciesByID        = "/policies/:id"
	pathDeletion            = "/deletion"
	pathStorage             = "/storage"
	pathStats               = "/stats"
	pathPresignedDownload   = "/presigned-download"

	// Platform admin permission strings duplicated 3+ times
	permPlatformUsersRead    = "platform:users:read"
	permPlatformUsersUpdate  = "platform:users:update"
	permPlatformRealmsRead   = "platform:realms:read"
	permPlatformRealmsUpdate = "platform:realms:update"

	// Platform admin route param paths
	pathTenantID           = "/:tenant_id"
	pathTenantIDUserUserID = "/:tenant_id/users/:user_id"
	pathIDIDPProviderID    = "/:id/identity-providers/:provider_id"
	pathDomainID           = "/:domain_id"

	// SCIM route paths
	pathSCIMUsersID  = "/Users/:id"
	pathSCIMGroupsID = "/Groups/:id"
)

// registerAdminRoutes registers all admin routes.
// scopeServiceRegister is the baseline scope every platform service client holds
// (the token client defaults to it); internal routes without a more specific
// scope require it.
const scopeServiceRegister = "service:register"

func registerAdminRoutes(api *gin.RouterGroup, handlers *Handlers, authMiddleware *middleware.AuthMiddleware) {
	admin := api.Group("/admin")
	admin.Use(authMiddleware.RequireAuth())
	admin.Use(authMiddleware.RequireRole("admin", "platform_admin", "iam_admin"))
	{
		// Sessions
		// Read-only LIST stays open under RequireAuth + RequireRole.
		// Mutating endpoints (revoke session / revoke all user sessions
		// / mutate MFA / unlock / etc.) gate on RFC 9470 fresh MFA per
		// the same posture as role mutations and OAuth-client writes.
		// Cookie theft alone is then insufficient to mass-revoke an
		// entire tenant's sessions or to mass-unlock recently-locked
		// accounts (a denial-of-service vector + a credential-stuffing
		// recovery aid for an attacker).
		adminUserStepUp := handlers.StepUpMiddleware.RequireStepUp("admin_user_mutation", 5*time.Minute)

		admin.GET("/sessions", handlers.Admin.ListAllSessions)
		admin.DELETE("/sessions/:id", adminUserStepUp, handlers.Admin.RevokeSession)
		admin.DELETE("/users/:id/sessions", adminUserStepUp, handlers.Admin.RevokeUserSessions)

		// Audit Logs
		admin.GET("/audit-logs", handlers.Admin.ListAuditLogs)
		admin.GET("/audit-logs/:id", handlers.Admin.GetAuditLog)

		// Admin-Action Audit Surface (Tier-1 security review)
		// Distinct from the general /audit-logs trail above —
		// /audit/admin-actions surfaces ONLY admin-actor surface
		// mutations (who changed what on which resource, with
		// per-actor + per-action + success-rate stats). Read-only;
		// events are written by LogEvent calls from the admin
		// handlers themselves. Static "/stats" route is registered
		// BEFORE "/:id" because gin's radix tree prefers static
		// segments over params, but listing them in this order is
		// the human-readable invariant.
		if handlers.AdminAudit != nil {
			adminAudit := admin.Group("/audit/admin-actions")
			{
				adminAudit.GET("", handlers.AdminAudit.ListAdminAuditLogs)
				adminAudit.GET("/stats", handlers.AdminAudit.GetAdminAuditStats)
				adminAudit.GET("/:id", handlers.AdminAudit.GetAdminAuditLog)
			}
		}

		// Tenant Transfer (ENT-6 STUB — returns 501 + tracking
		// metadata until Phase 2 implementation lands). Routes
		// register today so frontend can mock against a stable
		// URL shape; the OPTIONS preflight + 501 responses are
		// sufficient for UX iteration.
		if handlers.TenantTransfer != nil {
			tt := admin.Group("/tenant-transfers")
			{
				tt.GET("", handlers.TenantTransfer.List)
				tt.POST("", handlers.TenantTransfer.Create)
				tt.POST("/:id/approve", handlers.TenantTransfer.Approve)
				tt.POST("/:id/reject", handlers.TenantTransfer.Reject)
			}
		}

		// Identity Providers
		admin.GET("/identity-providers", handlers.Admin.ListIdentityProviders)
		admin.POST("/identity-providers", handlers.Admin.CreateIdentityProvider)
		admin.GET(pathIDPByID, handlers.Admin.GetIdentityProvider)
		admin.PUT(pathIDPByID, handlers.Admin.UpdateIdentityProvider)
		admin.DELETE(pathIDPByID, handlers.Admin.DeleteIdentityProvider)
		admin.POST("/identity-providers/:id/test", handlers.Admin.TestIdentityProvider)

		// LDAP specific
		admin.POST("/ldap/test-connection", handlers.Admin.TestLDAPConnection)
		admin.POST("/identity-providers/:id/sync", handlers.Admin.SyncLDAPUsers)
		admin.GET("/identity-providers/:id/sync-history", handlers.Admin.GetLDAPSyncHistory)

		// AD Sync Management
		admin.POST("/ad-sync/trigger", handlers.ADSync.TriggerSync)
		admin.GET("/ad-sync/running", handlers.ADSync.IsRunning)
		admin.GET("/ad-sync/stats", handlers.ADSync.GetSyncStats)
		admin.GET("/ad-sync/status/:provider_id", handlers.ADSync.GetSyncStatus)
		admin.GET("/ad-sync/history/:provider_id", handlers.ADSync.GetSyncHistory)
		admin.GET("/ad-sync/conflicts/:provider_id", handlers.ADSync.GetPendingConflicts)
		admin.POST("/ad-sync/conflicts/:conflict_id/resolve", handlers.ADSync.ResolveConflict)

		// User MFA & Email Management
		// Mutating endpoints gated by step-up — admin MFA flips and
		// device removals are recovery-class operations that an
		// attacker with a stolen admin cookie would use to lower a
		// target account's assurance level (force MFA off → password-
		// only login → take over). Read endpoints stay open.
		admin.POST("/users/:id/send-verification-email", adminUserStepUp, handlers.Admin.SendUserVerificationEmail)
		admin.GET("/users/:id/mfa", handlers.Admin.GetUserMFAStatus)
		admin.PUT("/users/:id/mfa", adminUserStepUp, handlers.Admin.SetUserMFA)
		// Force-verify bypasses the standard out-of-band email-link
		// challenge and silently marks a target email as verified.
		// Step-up gated for the same reason as MFA flip — an attacker
		// with a stolen admin cookie could otherwise silently confirm
		// a phished email and unblock downstream auth flows that gate
		// on EmailVerifiedAt.
		admin.POST("/users/:id/force-verify-email", adminUserStepUp, handlers.Admin.ForceVerifyUserEmail)

		// User Device Management (Admin)
		admin.GET("/users/:id/devices", handlers.Admin.GetUserDevices)
		admin.DELETE("/users/:id/devices/:device_id", adminUserStepUp, handlers.Admin.AdminDeleteUserDevice)
		admin.POST("/users/:id/devices/:device_id/untrust", adminUserStepUp, handlers.Admin.AdminUntrustUserDevice)

		// App-Access read surface — list every application-role
		// assignment for a given user across all applications in the
		// tenant. Powers the admin UI's "what apps does this user
		// touch" view. Read-only, no step-up.
		//
		// Path param MUST be `:id` (not `:user_id`) — gin's
		// radix-tree refuses to register two routes under the same
		// prefix with different param names at the same slot. The
		// other `/users/*` admin routes here use `:id` (line 142
		// etc.), so this route was crash-looping every pod that
		// included it (gin panic at addRoute, tree.go:230) until
		// the handler was aligned to read c.Param("id").
		admin.GET("/users/:id/role-assignments", handlers.AppAccess.ListUserAssignments)

		// AD Employee Management
		admin.GET(pathEmployees, handlers.AD.ListEmployees)
		admin.POST(pathEmployees, handlers.AD.CreateEmployee)
		admin.PUT(pathEmployees, handlers.AD.UpdateEmployee)
		admin.DELETE(pathEmployees, handlers.AD.DeleteEmployee)
		admin.POST("/employees/password", handlers.AD.ResetPassword)
		admin.POST("/employees/status", handlers.AD.SetAccountStatus)

		// AD Group Management
		admin.GET("/groups", handlers.AD.ListGroups)
		admin.POST("/groups/members", handlers.AD.AddUserToGroup)
		admin.DELETE("/groups/members", handlers.AD.RemoveUserFromGroup)

		// IAM Settings
		admin.GET("/settings", handlers.Settings.GetSettings) //nolint:staticcheck // intentional: backward-compat route
		admin.PUT("/settings", handlers.Settings.UpdateSettings)
		admin.POST("/settings/test-ldap", handlers.Settings.TestLDAPSettings)

		// Security - Password Policy
		admin.GET("/security/password-policy", handlers.Admin.GetPasswordPolicy)
		admin.PUT("/security/password-policy", handlers.Admin.UpdatePasswordPolicy)

		// Security - Rate Limiting
		admin.GET("/security/rate-limits", handlers.Admin.ListRateLimitRules)
		admin.POST("/security/rate-limits", handlers.Admin.CreateRateLimitRule)
		admin.GET("/security/rate-limits/events", handlers.Admin.GetRateLimitEvents)
		admin.GET(pathRateLimitsByID, handlers.Admin.GetRateLimitRule)
		admin.PUT(pathRateLimitsByID, handlers.Admin.UpdateRateLimitRule)
		admin.DELETE(pathRateLimitsByID, handlers.Admin.DeleteRateLimitRule)

		// Security - IP Rules
		admin.GET("/security/ip-rules", handlers.Admin.ListIPRules)
		admin.POST("/security/ip-rules", handlers.Admin.CreateIPRule)
		admin.GET("/security/ip-rules/logs", handlers.Admin.GetIPRuleLogs)
		admin.GET(pathIPRulesByID, handlers.Admin.GetIPRule)
		admin.PUT(pathIPRulesByID, handlers.Admin.UpdateIPRule)
		admin.DELETE(pathIPRulesByID, handlers.Admin.DeleteIPRule)

		// API Keys Management (Admin)
		admin.GET("/api-keys", handlers.APIKey.ListAPIKeys)
		admin.POST("/api-keys", handlers.APIKey.CreateAPIKey)
		admin.GET(pathAPIKeysByID, handlers.APIKey.GetAPIKey)
		admin.PUT(pathAPIKeysByID, handlers.APIKey.UpdateAPIKey)
		admin.DELETE(pathAPIKeysByID, handlers.APIKey.DeleteAPIKey)
		admin.POST("/api-keys/:id/revoke", handlers.APIKey.RevokeAPIKey)
		admin.POST("/api-keys/:id/regenerate", handlers.APIKey.RegenerateAPIKey)
		admin.GET("/api-keys/:id/stats", handlers.APIKey.GetAPIKeyUsageStats)

		// Service Accounts Management (Admin)
		admin.GET("/service-accounts", handlers.ServiceAccount.ListServiceAccounts)
		admin.POST("/service-accounts", handlers.ServiceAccount.CreateServiceAccount)
		admin.GET(pathServiceAccountsByID, handlers.ServiceAccount.GetServiceAccount)
		admin.PUT(pathServiceAccountsByID, handlers.ServiceAccount.UpdateServiceAccount)
		admin.DELETE(pathServiceAccountsByID, handlers.ServiceAccount.DeleteServiceAccount)
		admin.POST("/service-accounts/:id/regenerate-secret", handlers.ServiceAccount.RegenerateSecret)
		admin.POST("/service-accounts/:id/revoke-tokens", handlers.ServiceAccount.RevokeTokens)

		// OAuth Clients Management (Admin) — write paths gated by
		// step-up (RFC 9470). Reads stay open under RequireAuth +
		// RequireRole. Mutating an OAuth client is a high-impact
		// action: a tenant admin can rename, change redirect_uris,
		// revoke all sessions of the client's users, or rotate the
		// secret in a way that immediately breaks every downstream
		// consumer. Demanding a fresh MFA verification within the
		// last 5 minutes neutralises a stolen-cookie attacker who
		// hasn't also captured a fresh MFA factor — the same posture
		// applied to role mutations in cmd/routes.go.
		//
		// The /api/v1/internal/oauth-clients/* surface used by the
		// platform's ServiceClient provisioner is NOT gated here:
		// service-to-service tokens have no human session to step up,
		// and that route already runs ServiceAuth + RequireScope
		// + TrustedRegistration which is its own integrity envelope.
		oauthAdminStepUp := handlers.StepUpMiddleware.RequireStepUp("oauth_client_mutation", 5*time.Minute)
		admin.GET("/oauth-clients", handlers.OAuthProvider.ListClients)
		admin.POST("/oauth-clients", oauthAdminStepUp, handlers.OAuthProvider.CreateClient)
		admin.GET(pathOAuthClientsByID, handlers.OAuthProvider.GetClient)
		admin.PUT(pathOAuthClientsByID, oauthAdminStepUp, handlers.OAuthProvider.UpdateClient)
		admin.DELETE(pathOAuthClientsByID, oauthAdminStepUp, handlers.OAuthProvider.DeleteClient)
		admin.POST("/oauth-clients/:id/regenerate-secret", oauthAdminStepUp, handlers.OAuthProvider.RegenerateSecret)
		admin.POST("/oauth-clients/:id/revoke-tokens", oauthAdminStepUp, handlers.OAuthProvider.RevokeClientTokens)

		// RFC 8693 external-JWT exchange admin surface (v0.232.237).
		// CRUD on the per-tenant registry of trusted external IdPs +
		// per-client (BFF) grants linking a client to specific issuers
		// it may exchange JWTs from. Step-up enforced the same way as
		// oauth-clients mutations — granting external trust is at
		// least as sensitive as creating a client.
		admin.GET("/oauth-trusted-external-issuers", handlers.OAuthTrustedExternalIssuer.List)
		admin.POST("/oauth-trusted-external-issuers", oauthAdminStepUp, handlers.OAuthTrustedExternalIssuer.Create)
		admin.GET("/oauth-trusted-external-issuers/:id", handlers.OAuthTrustedExternalIssuer.Get)
		admin.PUT("/oauth-trusted-external-issuers/:id", oauthAdminStepUp, handlers.OAuthTrustedExternalIssuer.Update)
		admin.DELETE("/oauth-trusted-external-issuers/:id", oauthAdminStepUp, handlers.OAuthTrustedExternalIssuer.Delete)
		// Per-client grants. The handler's clientLookup is wired in
		// cmd/handlers.go where both OAuthProvider and this handler
		// are available; 503-pre-wire safety on the handler side.
		admin.POST("/oauth-clients/:id/trusted-external-issuers", oauthAdminStepUp, handlers.OAuthTrustedExternalIssuer.GrantClient)
		admin.DELETE("/oauth-clients/:id/trusted-external-issuers/:issuer_id", oauthAdminStepUp, handlers.OAuthTrustedExternalIssuer.RevokeClient)

		// SAML Service Provider Management (Admin)
		admin.GET("/saml/service-providers", handlers.SAML.ListServiceProviders)
		admin.POST("/saml/service-providers", handlers.SAML.CreateServiceProvider)
		admin.GET(pathSAMLSPByID, handlers.SAML.GetServiceProvider)
		admin.PUT(pathSAMLSPByID, handlers.SAML.UpdateServiceProvider)
		admin.DELETE(pathSAMLSPByID, handlers.SAML.DeleteServiceProvider)
		admin.GET("/saml/service-providers/:id/logs", handlers.SAML.GetAssertionLogs)

		// SAML Metadata Discovery (Admin)
		admin.POST("/saml/service-providers/import-url", handlers.SAMLSP.ImportMetadataFromURL)
		admin.POST("/saml/service-providers/import-xml", handlers.SAMLSP.ImportMetadataFromXML)
		admin.POST("/saml/service-providers/import-confirm", handlers.SAMLSP.ConfirmMetadataImport)
		admin.POST("/saml/service-providers/:id/refresh-metadata", handlers.SAMLSP.RefreshMetadata)
		admin.GET("/saml/service-providers/:id/metadata-history", handlers.SAMLSP.GetMetadataHistory)

		// SCIM Token Management (Admin)
		admin.GET("/scim/tokens", handlers.SCIM.ListTokens)
		admin.POST("/scim/tokens", handlers.SCIM.CreateToken)
		admin.GET(pathSCIMTokensByID, handlers.SCIM.GetToken)
		admin.PUT(pathSCIMTokensByID, handlers.SCIM.UpdateToken)
		admin.DELETE(pathSCIMTokensByID, handlers.SCIM.DeleteToken)
		admin.POST("/scim/tokens/:id/revoke", handlers.SCIM.RevokeToken)

		// IAM User Groups Management (Admin)
		registerIAMGroupRoutes(admin, handlers, authMiddleware)

		// Organization Hierarchy Management (Admin)
		registerOrganizationRoutes(admin, handlers, authMiddleware)

		// Impersonation Management (Admin)
		registerAdminImpersonationRoutes(admin, handlers)

		// Webhook Management (Admin)
		registerWebhookRoutes(admin, handlers)

		// Risk-based Authentication (Admin)
		registerRiskRoutes(admin, handlers)

		// ABAC Policy Management (Admin)
		registerPolicyRoutes(admin, handlers, authMiddleware)

		// Tenant Configuration (Admin)
		admin.GET("/tenant-config", handlers.TenantConfig.ListConfig)
		admin.PUT("/tenant-config", handlers.TenantConfig.UpsertConfig)
		admin.PUT("/tenant-config/bulk", handlers.TenantConfig.BulkUpsertConfig)
		admin.DELETE("/tenant-config/:key", handlers.TenantConfig.DeleteConfig)
		admin.GET("/tenant-config/keys", handlers.TenantConfig.ListKeys)

		// Feature Flags (Admin)
		admin.GET("/feature-flags", handlers.FeatureFlag.List)
		admin.POST("/feature-flags", handlers.FeatureFlag.Create)
		admin.GET(pathFeatureFlagsByID, handlers.FeatureFlag.GetByID)
		admin.PUT(pathFeatureFlagsByID, handlers.FeatureFlag.Update)
		admin.DELETE(pathFeatureFlagsByID, handlers.FeatureFlag.Delete)

		// App Access Control (Admin)
		registerAppAccessRoutes(admin, handlers)

		// Conditional Access Policies (Admin)
		registerConditionalAccessRoutes(admin, handlers)

		// Service Control Policies (Admin)
		registerSCPRoutes(admin, handlers)

		// Access Review Campaigns (Admin)
		registerAccessReviewRoutes(admin, handlers)

		// Email Domain Registry (Admin)
		registerEmailDomainRoutes(admin, handlers, authMiddleware)

		// Tenant Custom-Domain Registry (Admin) — host-based discovery
		// claim/verify/suspend/delete for SaaS app custom domains.
		registerTenantHostAdminRoutes(admin, handlers, authMiddleware)

		// Guest User Management (Admin)
		registerGuestUserRoutes(admin, handlers)

		// JIT Access Grants (Admin)
		registerJITAccessRoutes(admin, handlers)

		// Tenant Branding (Admin)
		registerTenantBrandingRoutes(admin, handlers, authMiddleware)

		// Tenant Quotas (Admin)
		registerTenantQuotaRoutes(admin, handlers, authMiddleware)

		// IDP Routing Rules (Admin)
		registerIDPRoutingRoutes(admin, handlers)

		// IDP Tenant Overrides (Admin)
		registerIDPTenantOverrideRoutes(admin, handlers)

		// Session Analytics (Admin)
		registerSessionAnalyticsRoutes(admin, handlers)

		// Usage Metering (Admin)
		registerUsageRoutes(admin, handlers)

		// Auth Hooks (Admin)
		registerHooksRoutes(admin, handlers)

		// Routing Webhooks (Admin)
		registerRoutingWebhookRoutes(admin, handlers)

		// NOTE: SAML admin routes already registered above (lines 123-136)

		// Signing Keys (Admin) — stub
		admin.GET("/signing-keys", handlers.Stub.ListSigningKeys)
		admin.POST("/signing-keys", handlers.Stub.CreateSigningKey)
		admin.GET("/signing-keys/:id", handlers.Stub.GetSigningKey)
		admin.DELETE("/signing-keys/:id", handlers.Stub.DeleteSigningKey)
		admin.POST("/signing-keys/:id/rotate", handlers.Stub.RotateSigningKey)

		// Force email verification — REAL handler is registered above
		// at line 138 (admin.POST with handlers.Admin.ForceVerifyUserEmail
		// + adminUserStepUp gate). The stub registration that lived
		// here was a relic from before !206 wired the real
		// AdminHandler.ForceVerifyUserEmail method. Registering both
		// produces a gin radix-tree panic at startup
		// (`handlers are already registered for path
		// /api/v1/admin/users/:id/force-verify-email`), crashing
		// every pod. The stub is removed here, not kept as a
		// fallback — the real handler does the work + writes the
		// audit row.

		// SMTP test (Admin) — stub
		admin.POST("/tenant-config/smtp/test", handlers.Stub.TestSMTPConfig)

		// --- Frontend SDK path aliases ---
		// The Falcon SDK client calls these paths under /admin, but the real handlers
		// are registered under /platform. Register aliases so both paths work.

		// SpiceDB admin aliases — SDK calls /admin/spicedb/*, backend has /platform/spicedb/*
		if handlers.SpiceDBDebug != nil {
			spicedbAdmin := admin.Group("/spicedb")
			{
				spicedbAdmin.POST("/debug/permission", handlers.SpiceDBDebug.DebugPermission)
				spicedbAdmin.GET("/reconciler/status", handlers.SpiceDBDebug.GetReconcilerStatus)
				spicedbAdmin.POST("/reconciler/trigger", handlers.SpiceDBDebug.TriggerReconciliation)
				spicedbAdmin.POST("/users/:id/effective-permissions", handlers.SpiceDBDebug.GetEffectivePermissions)
				spicedbAdmin.POST("/bulk-assign", handlers.SpiceDBDebug.BulkAssign)
			}
		}

		// Guest users alias — SDK calls /admin/guests/*, backend has /admin/guest-users/*
		if handlers.GuestUser != nil {
			guests := admin.Group("/guests")
			{
				guests.GET("", handlers.GuestUser.ListGuests)
				guests.POST("/invite", handlers.GuestUser.InviteGuest)
				guests.GET("/:id", handlers.GuestUser.GetGuest)
				guests.PUT("/:id", handlers.GuestUser.UpdateGuest)
				guests.DELETE("/:id", handlers.GuestUser.DeleteGuest)
				guests.POST("/:id/resend", handlers.GuestUser.ResendInvitation)
				guests.PUT("/:id/roles", handlers.GuestUser.SetRoles)
			}
		}

		// JIT access root alias — SDK calls GET /admin/jit-access, backend has /admin/jit-access/grants
		if handlers.JITAccess != nil {
			admin.GET("/jit-access", handlers.JITAccess.ListGrants)
			admin.POST("/jit-access/:id/approve", handlers.JITAccess.ApproveAccess)
			admin.POST("/jit-access/:id/revoke", handlers.JITAccess.RevokeGrant)
		}

		// Threats alias — SDK calls /admin/threats/*, backend has /platform/threat-correlation
		{
			threats := admin.Group("/threats")
			threats.GET("", handlers.Stub.ListThreats)
			threats.GET("/:id", handlers.Stub.GetThreat)
			threats.PUT("/:id", handlers.Stub.UpdateThreat)
		}

		// App installations alias — SDK calls /admin/app-installations/*, backend has /platform/app-installations/*
		if handlers.AppInstallation != nil {
			appInstAdmin := admin.Group("/app-installations")
			{
				appInstAdmin.GET("", handlers.AppInstallation.ListInstallations)
				appInstAdmin.POST("/install", handlers.AppInstallation.Install)
				appInstAdmin.GET("/:id", handlers.AppInstallation.GetInstallation)
				appInstAdmin.POST("/:id/uninstall", handlers.AppInstallation.Uninstall)
			}
		}

		// User app assignments — SDK calls /admin/apps/user/:user_id/assignments
		admin.GET("/apps/user/:user_id/assignments", handlers.Stub.GetUserAppAssignments)

		// IDP Routing rules (Admin) — falcon-admin /security/idp-routing page.
		// Handler + service + repo all exist; this is the missing router wire.
		if handlers.IDPRouting != nil {
			idpRouting := admin.Group("/idp-routing")
			{
				idpRouting.GET("", handlers.IDPRouting.ListRules)
				idpRouting.POST("", handlers.IDPRouting.CreateRule)
				idpRouting.PUT("/:id", handlers.IDPRouting.UpdateRule)
				idpRouting.DELETE("/:id", handlers.IDPRouting.DeleteRule)
				idpRouting.POST("/resolve", handlers.IDPRouting.ResolveIDP)
			}
		}

		// IDP Tenant Overrides (Admin): routes are already registered
		// upstream at line 308 via registerIDPTenantOverrideRoutes(...)
		// — re-registering them here in commit f31ad24 caused gin to
		// panic at startup with:
		//
		//   panic: handlers are already registered for path
		//   '/api/v1/admin/idp-overrides'
		//
		// Verified live 2026-05-20 06:09 UTC: the post-merge image
		// (e9dbdca) crashlooped 18 times, while the pre-merge image
		// (3bba97d) stayed up on three other replicas. Removing the
		// duplicate registration here preserves the existing
		// registerIDPTenantOverrideRoutes() path semantics that were
		// in production before f31ad24. If the new path shapes
		// (REST-idiomatic GET/PUT/DELETE on /:id) are actually wanted,
		// the upstream function definition itself should be modified
		// — not reproduced inline here.

		// WebAuthn admin (Admin) — falcon-admin /security/webauthn-credentials.
		// User-facing /webauthn/{begin,finish}/{registration,authentication}
		// is wired elsewhere; this is the cross-user admin view + revoke.
		if handlers.WebAuthn != nil {
			webauthnAdmin := admin.Group("/webauthn/credentials")
			{
				webauthnAdmin.GET("", handlers.WebAuthn.ListCredentials)
				webauthnAdmin.POST("/:id/revoke", handlers.WebAuthn.AdminRevokeCredential)
			}
		}
	}
}

// registerIAMGroupRoutes registers IAM group management routes.
func registerIAMGroupRoutes(admin *gin.RouterGroup, handlers *Handlers, _ *middleware.AuthMiddleware) {
	admin.GET("/iam-groups", handlers.Group.ListGroups)
	admin.GET("/iam-groups/tree", handlers.Group.GetGroupTree)
	admin.POST("/iam-groups", handlers.Group.CreateGroup)
	admin.GET(pathIAMGroupsByID, handlers.Group.GetGroup)
	admin.PUT(pathIAMGroupsByID, handlers.Group.UpdateGroup)
	admin.DELETE(pathIAMGroupsByID, handlers.Group.DeleteGroup)
	admin.GET(pathIAMGroupsIDMembers, handlers.Group.GetMembers)
	admin.POST(pathIAMGroupsIDMembers, handlers.Group.AddMembers)
	admin.DELETE(pathIAMGroupsIDMembers, handlers.Group.RemoveMembers)
	admin.GET(pathIAMGroupsIDRoles, handlers.Group.GetGroupRoles)
	admin.POST(pathIAMGroupsIDRoles, handlers.Group.AssignRoles)
	admin.PUT(pathIAMGroupsIDRoles, handlers.Group.SetRoles)
	admin.DELETE(pathIAMGroupsIDRoles, handlers.Group.RemoveRoles)

	// User Groups endpoints (Admin)
	admin.GET("/users/:id/iam-groups", handlers.Group.GetUserGroups)
	admin.GET("/users/:id/effective-roles", handlers.Group.GetUserEffectiveRoles)
}

// registerOrganizationRoutes registers organization hierarchy management routes.
func registerOrganizationRoutes(admin *gin.RouterGroup, handlers *Handlers, _ *middleware.AuthMiddleware) {
	admin.GET("/organizations/types", handlers.Organization.GetOrgTypes)
	admin.GET("/organizations/roles", handlers.Organization.GetOrgRoles)
	admin.GET("/organizations/tree", handlers.Organization.GetOrganizationTree)
	admin.GET("/organizations", handlers.Organization.ListOrganizations)
	admin.POST("/organizations", handlers.Organization.CreateOrganization)
	admin.GET(pathOrgsByID, handlers.Organization.GetOrganization)
	admin.PUT(pathOrgsByID, handlers.Organization.UpdateOrganization)
	admin.DELETE(pathOrgsByID, handlers.Organization.DeleteOrganization)
	admin.GET(pathOrgsIDMembers, handlers.Organization.GetMembers)
	admin.POST(pathOrgsIDMembers, handlers.Organization.AddMember)
	admin.POST("/organizations/:id/members/batch", handlers.Organization.AddMembers)
	admin.DELETE(pathOrgsIDMembers, handlers.Organization.RemoveMembers)
	admin.PUT("/organizations/:id/members/:user_id", handlers.Organization.UpdateMember)
	admin.GET("/organizations/:id/ancestors", handlers.Organization.GetAncestors)
	admin.GET("/organizations/:id/descendants", handlers.Organization.GetDescendants)
	admin.GET(pathOrgsIDIAMRoles, handlers.Organization.GetAssignedRoles)
	admin.POST(pathOrgsIDIAMRoles, handlers.Organization.AssignRoles)
	admin.DELETE(pathOrgsIDIAMRoles, handlers.Organization.UnassignRoles)

	// User Organizations endpoints (Admin)
	admin.GET("/users/:id/organizations", handlers.Organization.GetUserOrganizations)
	admin.GET("/users/:id/primary-organization", handlers.Organization.GetUserPrimaryOrganization)
}

// registerAdminImpersonationRoutes registers impersonation management routes.
func registerAdminImpersonationRoutes(admin *gin.RouterGroup, handlers *Handlers) {
	admin.POST("/users/:id/impersonate", handlers.Impersonation.StartImpersonation)
	admin.GET("/users/:id/impersonation", handlers.Impersonation.GetActiveImpersonation)
	admin.GET("/impersonation-sessions", handlers.Impersonation.ListImpersonationSessions)
	admin.GET("/impersonation-sessions/:id", handlers.Impersonation.GetImpersonationSession)
	admin.POST("/impersonation-sessions/:id/end", handlers.Impersonation.EndImpersonationByAdmin)
}

// registerWebhookRoutes registers webhook management routes.
func registerWebhookRoutes(admin *gin.RouterGroup, handlers *Handlers) {
	admin.GET("/webhooks/event-types", handlers.Webhook.GetEventTypes)
	admin.GET("/webhooks", handlers.Webhook.ListWebhooks)
	admin.POST("/webhooks", handlers.Webhook.CreateWebhook)
	admin.GET(pathWebhooksByID, handlers.Webhook.GetWebhook)
	admin.PUT(pathWebhooksByID, handlers.Webhook.UpdateWebhook)
	admin.DELETE(pathWebhooksByID, handlers.Webhook.DeleteWebhook)
	admin.POST("/webhooks/:id/test", handlers.Webhook.TestWebhook)
	admin.GET("/webhooks/:id/deliveries", handlers.Webhook.ListDeliveries)
	admin.GET("/webhooks/:id/stats", handlers.Webhook.GetDeliveryStats)
	admin.GET("/webhooks/deliveries/:deliveryId", handlers.Webhook.GetDelivery)
	admin.POST("/webhooks/deliveries/:deliveryId/retry", handlers.Webhook.RetryDelivery)
}

// registerRiskRoutes registers risk-based authentication routes.
func registerRiskRoutes(admin *gin.RouterGroup, handlers *Handlers) {
	admin.GET("/security/risk-policies", handlers.Risk.GetPolicies)
	admin.POST("/security/risk-policies", handlers.Risk.CreatePolicy)
	admin.GET(pathRiskPoliciesByID, handlers.Risk.GetPolicy)
	admin.PUT(pathRiskPoliciesByID, handlers.Risk.UpdatePolicy)
	admin.DELETE(pathRiskPoliciesByID, handlers.Risk.DeletePolicy)
	admin.GET("/security/risk-thresholds", handlers.Risk.GetThresholds)
	admin.PUT("/security/risk-thresholds", handlers.Risk.UpdateThresholds)
	admin.GET("/users/:id/risk-signals", handlers.Risk.GetUserSignals)
	admin.POST("/security/risk-signals/:id/resolve", handlers.Risk.ResolveSignal)
}

// registerPolicyRoutes registers ABAC policy management routes.
func registerPolicyRoutes(admin *gin.RouterGroup, handlers *Handlers, authMiddleware *middleware.AuthMiddleware) {
	admin.GET(pathPolicies, handlers.Policy.List)
	admin.POST(pathPolicies, authMiddleware.RequirePlatformAdmin(), handlers.Policy.Create)
	admin.GET(pathPoliciesByID, handlers.Policy.GetByID)
	admin.PUT(pathPoliciesByID, authMiddleware.RequirePlatformAdmin(), handlers.Policy.Update)
	admin.DELETE(pathPoliciesByID, authMiddleware.RequirePlatformAdmin(), handlers.Policy.Delete)
	admin.POST("/policies/test", authMiddleware.RequirePlatformAdmin(), handlers.Policy.TestPolicy)
	admin.POST("/policies/reload", authMiddleware.RequirePlatformAdmin(), handlers.Policy.ReloadPolicies)

	// ABAC Status
	admin.GET("/abac/status", handlers.Policy.GetABACStatus)

	// Default Access Policies
	admin.POST("/default-access-policies", handlers.DefaultAccessPolicy.Create)
	admin.GET("/default-access-policies", handlers.DefaultAccessPolicy.List)
	admin.PATCH("/default-access-policies/:id", handlers.DefaultAccessPolicy.Update)
	admin.DELETE("/default-access-policies/:id", handlers.DefaultAccessPolicy.Delete)

	// Dynamic Group Rules
	admin.POST("/dynamic-group-rules", handlers.DynamicGroupRule.Create)
	admin.GET("/dynamic-group-rules", handlers.DynamicGroupRule.List)
	admin.PATCH("/dynamic-group-rules/:id", handlers.DynamicGroupRule.Update)
	admin.DELETE("/dynamic-group-rules/:id", handlers.DynamicGroupRule.Delete)
}

// registerPlatformAdminRoutes registers platform admin routes.
// Platform admins now authenticate through the standard IAM flow with app-access-control.
// Legacy platform admin auth endpoints (/platform/auth/login, /refresh, /me, /logout, /validate) are removed.
func registerPlatformAdminRoutes(api *gin.RouterGroup, handlers *Handlers, authMiddleware *middleware.AuthMiddleware, _ *middleware.AuthRateLimiter) {
	platformAdmin := api.Group("/platform")
	platformAdmin.Use(authMiddleware.RequireAuth(), authMiddleware.RequirePlatformAdmin())
	{
		// Invitation Management Routes (Platform Admin)
		invitations := platformAdmin.Group("/invitations")
		{
			invitations.POST("", authMiddleware.RequirePermission("platform:users:create"), handlers.Invitation.CreateInvitation)
		}

		// User Invitation Routes (Platform Admin)
		platformUsers := platformAdmin.Group("/users")
		{
			platformUsers.GET("/:user_id/invitation", authMiddleware.RequirePermission(permPlatformUsersRead), handlers.Invitation.GetPendingInvitation)
			platformUsers.POST("/:user_id/resend-invitation", authMiddleware.RequirePermission(permPlatformUsersUpdate), handlers.Invitation.ResendInvitation)
			platformUsers.DELETE("/:user_id/invitation", authMiddleware.RequirePermission(permPlatformUsersUpdate), handlers.Invitation.RevokeInvitation)
		}

		// Platform Management Routes
		registerPlatformManagementRoutes(platformAdmin, handlers, authMiddleware)

		// Realm Management Routes
		registerRealmManagementRoutes(platformAdmin, handlers, authMiddleware)

		// Platform Metrics and Quotas Routes
		if handlers.Metrics != nil {
			handlers.Metrics.RegisterRoutes(platformAdmin)
			logger.Info("Platform metrics routes registered at /api/platform/metrics and /api/platform/quotas")
		}

		// Compliance Reports (Platform Admin)
		registerComplianceReportRoutes(platformAdmin, handlers)

		// Compliance Policies (Platform Admin)
		registerCompliancePolicyRoutes(platformAdmin, handlers)

		// Realm Federation Trusts (Platform Admin)
		registerRealmFederationRoutes(platformAdmin, handlers)

		// Audit Integrity Verification (Platform Admin)
		registerAuditIntegrityRoutes(platformAdmin, handlers)

		// Threat Correlation Events (Platform Admin)
		registerThreatCorrelationRoutes(platformAdmin, handlers)

		// ITDR — Identity Threat Detection and Response (Platform Admin).
		// Handler + service + repo were already built but had never been
		// wired to a router. Frontend (falcon-admin /security/threats and
		// /security/detection-rules) was 404'ing every call until this.
		if handlers.ITDR != nil {
			itdrSec := platformAdmin.Group("/security")
			{
				itdrSec.GET("/threats", handlers.ITDR.ListThreats)
				itdrSec.GET("/threats/:id", handlers.ITDR.GetThreat)
				itdrSec.POST("/threats/:id/acknowledge", handlers.ITDR.AcknowledgeThreat)
				itdrSec.GET("/detection-rules", handlers.ITDR.ListDetectionRules)
				itdrSec.PUT("/detection-rules/:id", handlers.ITDR.UpdateDetectionRule)
			}
		}

		// App Installations (Platform Admin)
		registerAppInstallationRoutes(platformAdmin, handlers)

		// SpiceDB Debug (Platform Admin)
		registerSpiceDBDebugRoutes(platformAdmin, handlers)

		// Platform Audit Logs (separate from admin audit-logs)
		platformAdmin.GET("/audit-logs", handlers.Stub.ListPlatformAuditLogs)
		platformAdmin.GET("/audit-logs/export", handlers.Stub.ExportPlatformAuditLogs)

		// Schema Version Tracking (Platform Admin)
		// Read-only drift-detection surface for the per-tenant
		// iam_tenant_schema_versions registry. Static `/drift` and
		// `/tenant/:tenant_id` routes go BEFORE the bare `""` route
		// only for human-readability — gin's radix tree prefers
		// static segments regardless of registration order.
		if handlers.SchemaVersion != nil {
			schemaVer := platformAdmin.Group("/schema-versions")
			{
				schemaVer.GET("", handlers.SchemaVersion.ListVersions)
				schemaVer.GET("/drift", handlers.SchemaVersion.GetDriftReport)
				schemaVer.GET("/tenant/:tenant_id", handlers.SchemaVersion.GetTenantVersions)
			}
		}

		// Tenant Resource Metering (Platform Admin)
		// Read-only surface for billing / capacity-planning views.
		// `/tenant-resources` is the live snapshot;
		// `/metering/tenant/:tenant_id` + `/metering/summary` serve
		// the sampled historical view from the resource monitor.
		// Handler degrades gracefully when the monitor is nil
		// (Redis unavailable) — returns empty rather than 500.
		if handlers.TenantMetering != nil {
			platformAdmin.GET("/tenant-resources", handlers.TenantMetering.GetTenantResources)
			metering := platformAdmin.Group("/metering")
			{
				metering.GET("/tenant/:tenant_id", handlers.TenantMetering.GetTenantMetering)
				metering.GET("/summary", handlers.TenantMetering.GetMeteringSummary)
			}
		}

		// Provisioning Governance Policy Engine (Platform Admin)
		// Dry-run-only surface — POST /evaluate runs the in-memory
		// rule set against a candidate provisioning input WITHOUT
		// mutating any state; GET /rules lists the active rules so
		// the platform-admin UI can show "what gates apply if I
		// provision tenant X with plan Y in region Z". No DB writes
		// from either endpoint; engine is pure-in-memory.
		if handlers.ProvisioningPolicy != nil {
			policy := platformAdmin.Group("/policy")
			{
				policy.POST("/evaluate", handlers.ProvisioningPolicy.EvaluatePolicy)
				policy.GET("/rules", handlers.ProvisioningPolicy.ListRules)
			}
		}

		// AI-Agent Identity Management (Platform Admin)
		// 9 routes for autonomous-agent lifecycle. Read paths gate
		// only on the parent group's RequireAuth +
		// RequirePlatformAdmin; write paths add a dedicated
		// `agent_identity_mutation` step-up bucket because
		// suspending / revoking / rotating credentials is
		// credential-equivalent, and IssueToken mints a fresh
		// agent token (session-class privilege).
		if handlers.AgentIdentity != nil {
			agentStepUp := handlers.StepUpMiddleware.RequireStepUp("agent_identity_mutation", 5*time.Minute)
			agents := platformAdmin.Group("/agents")
			{
				agents.GET("", handlers.AgentIdentity.List)
				agents.GET("/:id", handlers.AgentIdentity.GetByID)
				agents.GET("/:id/activity", handlers.AgentIdentity.GetActivity)
				agents.POST("", agentStepUp, handlers.AgentIdentity.Create)
				agents.PUT("/:id", agentStepUp, handlers.AgentIdentity.Update)
				agents.POST("/:id/suspend", agentStepUp, handlers.AgentIdentity.Suspend)
				agents.POST("/:id/revoke", agentStepUp, handlers.AgentIdentity.Revoke)
				agents.POST("/:id/rotate-credentials", agentStepUp, handlers.AgentIdentity.RotateCredentials)
				agents.POST("/token", handlers.AgentIdentity.IssueToken)
			}
		}

		// Live Compliance Evidence Reports (Platform Admin)
		// Read-only — every report reflects current system posture
		// at request time. SOC2 / GDPR / KVKK auditors hit these
		// endpoints during their evidence-collection runs. No
		// step-up — audit-grade reports should be cheap to re-run.
		if handlers.ComplianceEvidence != nil {
			compliance := platformAdmin.Group("/compliance")
			{
				compliance.GET("/soc2", handlers.ComplianceEvidence.SOC2Report)
				compliance.GET("/gdpr", handlers.ComplianceEvidence.GDPRReport)
				compliance.GET("/kvkk", handlers.ComplianceEvidence.KVKKReport)
			}
		}

		// NOTE: storage/compute/network are registered at /api/v1 level (not /platform)
		// via registerInfrastructureStubRoutes in routes.go

		// Stub routes for frontend endpoints not yet backed by real logic
		registerStubRoutes(platformAdmin, handlers, authMiddleware)
	}
	logger.Info("Platform admin routes registered at /api/platform")
}

// registerPlatformManagementRoutes registers platform management routes.
func registerPlatformManagementRoutes(platformAdmin *gin.RouterGroup, handlers *Handlers, authMiddleware *middleware.AuthMiddleware) {
	platformMgmt := platformAdmin.Group("/management")
	{
		// Tenant Management (Cross-tenant)
		tenantMgmt := platformMgmt.Group("/tenants")
		{
			tenantMgmt.GET("", authMiddleware.RequirePermission("platform:tenants:read"), handlers.PlatformManagement.ListTenants)
			tenantMgmt.POST("", handlers.Stub.CreateTenant)
			tenantMgmt.GET(pathTenantID, authMiddleware.RequirePermission("platform:tenants:read"), handlers.PlatformManagement.GetTenant)
			tenantMgmt.PUT(pathTenantID, authMiddleware.RequirePermission("platform:tenants:update"), handlers.PlatformManagement.UpdateTenant)
			// Previously ungated (any authenticated caller, any role) and
			// returned a fake 200 success. Gated now, and the handler
			// itself reports 501 honestly — see StubHandler.DeleteTenant.
			tenantMgmt.DELETE(pathTenantID, authMiddleware.RequirePermission("platform:tenants:delete"), handlers.Stub.DeleteTenant)
			// Backfill of workspaces still named "My Company": dry run by default,
			// {"dryRun": false} applies. Idempotent; reports tenants with no legal entity.
			tenantMgmt.POST("/placeholder-names/backfill", authMiddleware.RequirePermission("platform:tenants:update"), handlers.TenantWorkspaceName.Backfill)
			tenantMgmt.POST("/:tenant_id/suspend", authMiddleware.RequirePermission("platform:tenants:suspend"), handlers.PlatformManagement.SuspendTenant)
			tenantMgmt.POST("/:tenant_id/reactivate", authMiddleware.RequirePermission("platform:tenants:update"), handlers.PlatformManagement.ReactivateTenant)

			// Per-tenant user management
			tenantMgmt.GET("/:tenant_id/users", authMiddleware.RequirePermission(permPlatformUsersRead), handlers.PlatformManagement.ListTenantUsers)
			tenantMgmt.POST("/:tenant_id/users", authMiddleware.RequirePermission("platform:users:create"), handlers.PlatformManagement.CreateTenantUser)
			tenantMgmt.GET(pathTenantIDUserUserID, authMiddleware.RequirePermission(permPlatformUsersRead), handlers.PlatformManagement.GetTenantUser)
			tenantMgmt.PUT(pathTenantIDUserUserID, authMiddleware.RequirePermission(permPlatformUsersUpdate), handlers.PlatformManagement.UpdateTenantUser)
			tenantMgmt.DELETE(pathTenantIDUserUserID, authMiddleware.RequirePermission("platform:users:delete"), handlers.PlatformManagement.DeleteTenantUser)
			// Admin lifecycle: reversible soft-delete/restore share the
			// existing "platform:users:delete" grant; irreversible
			// hard-delete requires the separate, stricter
			// "platform:users:hard_delete" grant so that authority can
			// be handed out independently (an operator who can soft-
			// delete/restore does not automatically get erasure power).
			tenantMgmt.POST(pathTenantIDUserUserID+"/soft-delete", authMiddleware.RequirePermission("platform:users:delete"), handlers.PlatformManagement.SoftDeleteTenantUser)
			tenantMgmt.POST(pathTenantIDUserUserID+"/restore", authMiddleware.RequirePermission("platform:users:delete"), handlers.PlatformManagement.RestoreTenantUser)
			tenantMgmt.POST(pathTenantIDUserUserID+"/hard-delete", authMiddleware.RequirePermission("platform:users:hard_delete"), handlers.PlatformManagement.HardDeleteTenantUser)
			tenantMgmt.POST("/:tenant_id/users/:user_id/reset-password", authMiddleware.RequirePermission(permPlatformUsersUpdate), handlers.PlatformManagement.ResetUserPassword)
			tenantMgmt.POST("/:tenant_id/users/:user_id/unlock", authMiddleware.RequirePermission(permPlatformUsersUpdate), handlers.PlatformManagement.UnlockUser)
			tenantMgmt.PUT("/:tenant_id/users/:user_id/roles", authMiddleware.RequirePermission(permPlatformUsersUpdate), handlers.PlatformManagement.SetUserRoles)

			// Per-tenant role management
			tenantMgmt.GET("/:tenant_id/roles", authMiddleware.RequirePermission("platform:roles:read"), handlers.PlatformManagement.ListTenantRoles)
			tenantMgmt.POST("/:tenant_id/roles", authMiddleware.RequirePermission("platform:roles:create"), handlers.PlatformManagement.CreateTenantRole)

			// Module-access reconcile for one tenant: materializes the role
			// templates of every module the tenant is entitled to and grants
			// the module-admin roles to its owners. Idempotent.
			tenantMgmt.POST("/:tenant_id/module-access/reconcile", authMiddleware.RequirePermission("platform:roles:create"), handlers.PlatformManagement.ReconcileModuleAccess)
		}

		// Same reconcile across every tenant (rollout / recovery).
		platformMgmt.POST("/module-access/reconcile", authMiddleware.RequirePermission("platform:roles:create"), handlers.PlatformManagement.ReconcileModuleAccess)

		// Platform-wide permissions
		platformMgmt.GET("/permissions", authMiddleware.RequirePermission("platform:permissions:read"), handlers.PlatformManagement.ListPlatformPermissions)

		// Platform audit log
		platformMgmt.GET("/audit-log", authMiddleware.RequirePermission("platform:audit:read"), handlers.PlatformManagement.GetPlatformAuditLog)

		// Platform statistics
		platformMgmt.GET("/statistics", authMiddleware.RequirePermission("platform:statistics:read"), handlers.PlatformManagement.GetPlatformStatistics)
	}
}

// registerRealmManagementRoutes registers realm management routes.
func registerRealmManagementRoutes(platformAdmin *gin.RouterGroup, handlers *Handlers, authMiddleware *middleware.AuthMiddleware) {
	if handlers.Realm == nil {
		return
	}

	realms := platformAdmin.Group("/realms")
	{
		// Realm CRUD
		realms.GET("", authMiddleware.RequirePermission(permPlatformRealmsRead), handlers.Realm.ListRealms)
		realms.POST("", authMiddleware.RequirePermission("platform:realms:create"), handlers.Realm.CreateRealm)
		realms.GET("/:id", authMiddleware.RequirePermission(permPlatformRealmsRead), handlers.Realm.GetRealm)
		realms.PUT("/:id", authMiddleware.RequirePermission(permPlatformRealmsUpdate), handlers.Realm.UpdateRealm)
		realms.DELETE("/:id", authMiddleware.RequirePermission("platform:realms:delete"), handlers.Realm.ArchiveRealm)

		// Realm lifecycle
		realms.POST("/:id/activate", authMiddleware.RequirePermission(permPlatformRealmsUpdate), handlers.Realm.ActivateRealm)
		realms.POST("/:id/suspend", authMiddleware.RequirePermission(permPlatformRealmsUpdate), handlers.Realm.SuspendRealm)

		// Security policies
		realms.GET("/:id/security-policy", authMiddleware.RequirePermission(permPlatformRealmsRead), handlers.Realm.GetSecurityPolicy)
		realms.PUT("/:id/security-policy", authMiddleware.RequirePermission(permPlatformRealmsUpdate), handlers.Realm.UpdateSecurityPolicy)

		// Device witness policy (authenticator-app fallback for ZTNA enrollment)
		realms.GET("/:id/device-witness-policy", authMiddleware.RequirePermission(permPlatformRealmsRead), handlers.Realm.GetDeviceWitnessPolicy)
		realms.PUT("/:id/device-witness-policy", authMiddleware.RequirePermission(permPlatformRealmsUpdate), handlers.Realm.UpdateDeviceWitnessPolicy)
		realms.GET("/:id/session-policy", authMiddleware.RequirePermission(permPlatformRealmsRead), handlers.Realm.GetSessionPolicy)
		realms.PUT("/:id/session-policy", authMiddleware.RequirePermission(permPlatformRealmsUpdate), handlers.Realm.UpdateSessionPolicy)

		// Identity providers
		realms.GET("/:id/identity-providers", authMiddleware.RequirePermission(permPlatformRealmsRead), handlers.Realm.ListIdentityProviders)
		realms.POST("/:id/identity-providers", authMiddleware.RequirePermission(permPlatformRealmsUpdate), handlers.Realm.AddIdentityProvider)
		realms.GET(pathIDIDPProviderID, authMiddleware.RequirePermission(permPlatformRealmsRead), handlers.Realm.GetIdentityProvider)
		realms.PUT(pathIDIDPProviderID, authMiddleware.RequirePermission(permPlatformRealmsUpdate), handlers.Realm.UpdateIdentityProvider)
		realms.DELETE(pathIDIDPProviderID, authMiddleware.RequirePermission("platform:realms:delete"), handlers.Realm.RemoveIdentityProvider)

		// Tenant identity providers (aggregated view across all tenants in a realm)
		realms.GET("/:id/tenant-identity-providers", authMiddleware.RequirePermission(permPlatformRealmsRead), handlers.Realm.ListTenantIdentityProviders)

		// Tenant management within realm
		realms.GET("/:id/tenants", authMiddleware.RequirePermission(permPlatformRealmsRead), handlers.Realm.ListRealmTenants)
		realms.POST("/:id/tenants", authMiddleware.RequirePermission(permPlatformRealmsUpdate), handlers.Realm.AssignTenantToRealm)
		realms.DELETE("/:id/tenants/:tenant_id", authMiddleware.RequirePermission(permPlatformRealmsUpdate), handlers.Realm.RemoveTenantFromRealm)
		realms.POST("/:id/tenants/:tenant_id/migrate", authMiddleware.RequirePermission(permPlatformRealmsUpdate), handlers.Realm.MigrateTenant)

		// Admin assignments
		realms.GET("/:id/admins", authMiddleware.RequirePermission(permPlatformRealmsRead), handlers.Realm.ListRealmAdmins)
		realms.POST("/:id/admins", authMiddleware.RequirePermission(permPlatformRealmsUpdate), handlers.Realm.AssignRealmAdmin)
		realms.DELETE("/:id/admins/:admin_id", authMiddleware.RequirePermission(permPlatformRealmsUpdate), handlers.Realm.RemoveRealmAdmin)

		// Audit logs
		realms.GET("/:id/audit-logs", authMiddleware.RequirePermission(permPlatformRealmsRead), handlers.Realm.ListRealmAuditLogs)

		// Domain management
		realms.GET("/:id/domains", authMiddleware.RequirePermission(permPlatformRealmsRead), handlers.Realm.ListRealmDomains)
		realms.POST("/:id/domains", authMiddleware.RequirePermission(permPlatformRealmsUpdate), handlers.Realm.AddRealmDomain)
		realms.DELETE("/:id/domains/:domain_id", authMiddleware.RequirePermission(permPlatformRealmsUpdate), handlers.Realm.RemoveRealmDomain)
		realms.POST("/:id/domains/:domain_id/verify", authMiddleware.RequirePermission(permPlatformRealmsUpdate), handlers.Realm.VerifyRealmDomain)
		realms.POST("/:id/domains/:domain_id/primary", authMiddleware.RequirePermission(permPlatformRealmsUpdate), handlers.Realm.SetPrimaryDomain)

		// Realm database provisioning (optional — requires RealmDB handler)
		if handlers.RealmDB != nil {
			realms.GET("/:id/database-health", authMiddleware.RequirePermission(permPlatformRealmsRead), handlers.RealmDB.GetDatabaseHealth)
			realms.POST("/:id/provision-database", authMiddleware.RequirePermission(permPlatformRealmsUpdate), handlers.RealmDB.ProvisionDatabase)
			realms.DELETE("/:id/decommission-database", authMiddleware.RequirePermission(permPlatformRealmsUpdate), handlers.RealmDB.DecommissionDatabase)
		}
	}
	logger.Info("Realm management routes registered at /api/platform/realms")
}

// registerAppAccessRoutes registers app access control admin routes.
func registerAppAccessRoutes(admin *gin.RouterGroup, handlers *Handlers) {
	apps := admin.Group("/apps")
	{
		// Role assignments per application
		apps.GET("/:client_id/roles", handlers.AppAccess.ListRoleAssignments)
		apps.POST("/:client_id/roles", handlers.AppAccess.AssignRole)
		apps.DELETE("/:client_id/roles/:assignment_id", handlers.AppAccess.RevokeRole)

		// Auth policy per application
		apps.GET("/:client_id/policy", handlers.AppAccess.GetAuthPolicy)
		apps.PUT("/:client_id/policy", handlers.AppAccess.UpsertAuthPolicy)
	}
}

// registerConditionalAccessRoutes registers conditional access policy admin routes.
func registerConditionalAccessRoutes(admin *gin.RouterGroup, handlers *Handlers) {
	if handlers.ConditionalAccess == nil {
		return
	}
	ca := admin.Group("/conditional-access")
	{
		ca.GET("", handlers.ConditionalAccess.List)
		ca.POST("", handlers.ConditionalAccess.Create)
		ca.GET("/evaluation-log", handlers.ConditionalAccess.ListEvaluationLog)
		ca.POST("/simulate", handlers.ConditionalAccess.Simulate)
		ca.GET("/:id", handlers.ConditionalAccess.GetByID)
		ca.PUT("/:id", handlers.ConditionalAccess.Update)
		ca.DELETE("/:id", handlers.ConditionalAccess.Delete)
		ca.POST("/:id/enable", handlers.ConditionalAccess.Enable)
		ca.POST("/:id/disable", handlers.ConditionalAccess.Disable)
	}
}

// registerSCPRoutes registers service control policy admin routes.
func registerSCPRoutes(admin *gin.RouterGroup, handlers *Handlers) {
	if handlers.SCP == nil {
		return
	}
	scps := admin.Group("/scps")
	{
		scps.GET("", handlers.SCP.List)
		scps.POST("", handlers.SCP.Create)
		scps.GET("/:id", handlers.SCP.GetByID)
		scps.PATCH("/:id", handlers.SCP.Update)
		scps.DELETE("/:id", handlers.SCP.Delete)
		scps.POST("/:id/enable", handlers.SCP.Enable)
		scps.POST("/:id/disable", handlers.SCP.Disable)
	}
}

// registerAccessReviewRoutes registers access review campaign admin routes.
func registerAccessReviewRoutes(admin *gin.RouterGroup, handlers *Handlers) {
	if handlers.AccessReview == nil {
		return
	}
	reviews := admin.Group("/access-reviews")
	{
		reviews.GET("", handlers.AccessReview.ListCampaigns)
		reviews.POST("", handlers.AccessReview.CreateCampaign)
		reviews.GET("/pending", handlers.AccessReview.ListPendingItems)
		reviews.GET("/:id", handlers.AccessReview.GetCampaign)
		reviews.POST("/:id/finalize", handlers.AccessReview.FinalizeCampaign)
		reviews.POST("/:id/items/:itemId/decide", handlers.AccessReview.SubmitDecision)
	}
}

// registerEmailDomainRoutes registers email domain registry admin routes.
// Routes are nested under /admin/tenants/:tenant_id/domains.
//
// SECURITY (R0 platform-admin audit finding F2): this group used to inherit
// only the blanket admin.Use(RequireRole("admin","platform_admin","iam_admin"))
// gate from the parent /admin group, with no check that :tenant_id matches
// the caller's own tenant. Any customer tenant's own "admin" role holder
// could pass a DIFFERENT tenant_id in the URL and manage that tenant's
// email domains. RequireTenantScopedAdmin (CVE-HEXX-IAM-001 fix, previously
// built but never wired to any route) closes this: platform admins bypass,
// everyone else must match tenant_id to their own tenant.
func registerEmailDomainRoutes(admin *gin.RouterGroup, handlers *Handlers, authMiddleware *middleware.AuthMiddleware) {
	if handlers.EmailDomain == nil {
		return
	}
	tenantDomains := admin.Group("/tenants/:tenant_id/domains")
	tenantDomains.Use(authMiddleware.RequireTenantScopedAdmin("tenant_id"))
	{
		tenantDomains.GET("", handlers.EmailDomain.ListDomains)
		tenantDomains.POST("", handlers.EmailDomain.RegisterDomain)
		tenantDomains.GET(pathDomainID, handlers.EmailDomain.GetDomain)
		tenantDomains.PATCH(pathDomainID, handlers.EmailDomain.UpdateDomain)
		tenantDomains.POST("/:domain_id/verify", handlers.EmailDomain.VerifyDomain)
		tenantDomains.DELETE(pathDomainID, handlers.EmailDomain.DeleteDomain)
	}
}

// registerTenantHostAdminRoutes registers tenant custom-domain admin
// routes under /api/v1/admin/tenants/:tenant_id/hosts. Mirror of
// registerEmailDomainRoutes — same auth envelope, same parameter
// names, parallel flow (claim → publish TXT → verify).
//
// SECURITY (R0 platform-admin audit finding F2): same cross-tenant IDOR as
// registerEmailDomainRoutes — see that comment. RequireTenantScopedAdmin
// closes it.
func registerTenantHostAdminRoutes(admin *gin.RouterGroup, handlers *Handlers, authMiddleware *middleware.AuthMiddleware) {
	if handlers.TenantHostAdmin == nil {
		return
	}
	tenantHosts := admin.Group("/tenants/:tenant_id/hosts")
	tenantHosts.Use(authMiddleware.RequireTenantScopedAdmin("tenant_id"))
	{
		tenantHosts.GET("", handlers.TenantHostAdmin.ListHosts)
		tenantHosts.POST("", handlers.TenantHostAdmin.ClaimHost)
		tenantHosts.GET("/:host_id", handlers.TenantHostAdmin.GetHost)
		tenantHosts.POST("/:host_id/verify", handlers.TenantHostAdmin.VerifyOne)
		tenantHosts.POST("/:host_id/suspend", handlers.TenantHostAdmin.SuspendHost)
		tenantHosts.DELETE("/:host_id", handlers.TenantHostAdmin.DeleteHost)
	}
}

// registerGuestUserRoutes registers guest user management admin routes.
func registerGuestUserRoutes(admin *gin.RouterGroup, handlers *Handlers) {
	if handlers.GuestUser == nil {
		return
	}
	guests := admin.Group("/guest-users")
	{
		guests.GET("", handlers.GuestUser.ListGuests)
		guests.POST("/invite", handlers.GuestUser.InviteGuest)
		guests.GET("/:id", handlers.GuestUser.GetGuest)
		guests.PUT("/:id", handlers.GuestUser.UpdateGuest)
		guests.DELETE("/:id", handlers.GuestUser.DeleteGuest)
		guests.POST("/:id/resend", handlers.GuestUser.ResendInvitation)
		guests.PUT("/:id/roles", handlers.GuestUser.SetRoles)
	}
}

// registerJITAccessRoutes registers just-in-time access grant admin routes.
func registerJITAccessRoutes(admin *gin.RouterGroup, handlers *Handlers) {
	if handlers.JITAccess == nil {
		return
	}
	jit := admin.Group("/jit-access")
	{
		jit.GET("/grants", handlers.JITAccess.ListGrants)
		jit.POST("/grants", handlers.JITAccess.RequestAccess)
		jit.POST("/grants/:id/approve", handlers.JITAccess.ApproveAccess)
		jit.POST("/grants/:id/activate", handlers.JITAccess.ActivateGrant)
		jit.POST("/grants/:id/revoke", handlers.JITAccess.RevokeGrant)
	}
}

// registerTenantBrandingRoutes registers tenant branding admin routes.
// Routes are nested under /admin/tenants/:tenant_id/branding.
//
// SECURITY (R0 platform-admin audit finding F2): same cross-tenant IDOR as
// registerEmailDomainRoutes — see that comment. RequireTenantScopedAdmin
// closes it.
func registerTenantBrandingRoutes(admin *gin.RouterGroup, handlers *Handlers, authMiddleware *middleware.AuthMiddleware) {
	if handlers.TenantBranding == nil {
		return
	}
	tenantBranding := admin.Group("/tenants/:tenant_id/branding")
	tenantBranding.Use(authMiddleware.RequireTenantScopedAdmin("tenant_id"))
	{
		tenantBranding.GET("", handlers.TenantBranding.GetBranding)
		tenantBranding.PUT("", handlers.TenantBranding.UpdateBranding)
		tenantBranding.DELETE("", handlers.TenantBranding.DeleteBranding)
	}
}

// registerTenantQuotaRoutes registers tenant quota admin routes.
//
// SECURITY (R0 platform-admin audit finding F2 / F3):
//   - Per-tenant quota: same cross-tenant IDOR as registerEmailDomainRoutes
//     — see that comment. RequireTenantScopedAdmin closes it.
//   - Tier defaults (/admin/quota/tiers) are platform-global (no :tenant_id
//     at all) — they set the default quota for every tenant on a tier, so
//     ANY tenant's own "admin" role holder reaching them (as before, via
//     just the parent group's RequireRole gate) could alter quotas for
//     every OTHER tenant on the platform. This is genuinely platform-plane
//     and requires RequirePlatformAdmin, not tenant-scoping.
func registerTenantQuotaRoutes(admin *gin.RouterGroup, handlers *Handlers, authMiddleware *middleware.AuthMiddleware) {
	if handlers.TenantQuota == nil {
		return
	}
	// Per-tenant quota endpoints
	tenantQuota := admin.Group("/tenants/:tenant_id/quota")
	tenantQuota.Use(authMiddleware.RequireTenantScopedAdmin("tenant_id"))
	{
		tenantQuota.GET("", handlers.TenantQuota.GetTenantQuota)
		tenantQuota.PUT("", handlers.TenantQuota.UpsertTenantQuota)
		tenantQuota.DELETE("", handlers.TenantQuota.DeleteTenantQuota)
	}
	// Tier defaults — platform-global, not tenant-scoped.
	tierDefaults := admin.Group("/quota/tiers")
	tierDefaults.Use(authMiddleware.RequirePlatformAdmin())
	{
		tierDefaults.GET("", handlers.TenantQuota.GetTierDefaults)
		tierDefaults.PUT("/:tier", handlers.TenantQuota.UpdateTierDefault)
	}
}

// registerIDPRoutingRoutes registers IDP routing rule admin routes.
func registerIDPRoutingRoutes(admin *gin.RouterGroup, handlers *Handlers) {
	if handlers.IDPRouting == nil {
		return
	}
	routing := admin.Group("/idp-routing-rules")
	{
		routing.GET("", handlers.IDPRouting.ListRules)
		routing.POST("", handlers.IDPRouting.CreateRule)
		routing.POST("/resolve", handlers.IDPRouting.ResolveIDP)
		routing.PUT("/:id", handlers.IDPRouting.UpdateRule)
		routing.DELETE("/:id", handlers.IDPRouting.DeleteRule)
	}
}

// registerIDPTenantOverrideRoutes registers per-tenant IDP override admin routes.
func registerIDPTenantOverrideRoutes(admin *gin.RouterGroup, handlers *Handlers) {
	if handlers.IDPTenantOverride == nil {
		return
	}
	overrides := admin.Group("/idp-overrides")
	{
		overrides.GET("", handlers.IDPTenantOverride.ListOverrides)
		overrides.PUT("", handlers.IDPTenantOverride.UpsertOverride)
		overrides.GET("/login-providers", handlers.IDPTenantOverride.GetLoginProviders)
		overrides.GET("/:provider_id", handlers.IDPTenantOverride.GetOverride)
		overrides.DELETE("/:id", handlers.IDPTenantOverride.DeleteOverride)
	}
}

// registerSessionAnalyticsRoutes registers session analytics admin routes.
func registerSessionAnalyticsRoutes(admin *gin.RouterGroup, handlers *Handlers) {
	if handlers.SessionAnalytics == nil {
		return
	}
	analytics := admin.Group("/session-analytics")
	{
		analytics.GET("/all", handlers.SessionAnalytics.GetAllAnalytics)
		analytics.GET(pathTenantID, handlers.SessionAnalytics.GetAnalytics)
	}
}

// registerUsageRoutes registers usage metering admin routes.
func registerUsageRoutes(admin *gin.RouterGroup, handlers *Handlers) {
	if handlers.Usage == nil {
		return
	}
	usage := admin.Group("/usage")
	{
		usage.GET("", handlers.Usage.GetUsageSummary)
		usage.GET("/:product_id", handlers.Usage.GetProductUsage)
	}
}

// registerHooksRoutes registers auth hooks admin routes.
func registerHooksRoutes(admin *gin.RouterGroup, handlers *Handlers) {
	if handlers.Hooks == nil {
		return
	}
	hooksGroup := admin.Group("/hooks")
	{
		hooksGroup.GET("", handlers.Hooks.ListHooks)
		hooksGroup.POST("", handlers.Hooks.CreateHook)
		hooksGroup.GET("/:id", handlers.Hooks.GetHook)
		hooksGroup.PUT("/:id", handlers.Hooks.UpdateHook)
		hooksGroup.DELETE("/:id", handlers.Hooks.DeleteHook)
		hooksGroup.POST("/:id/test", handlers.Hooks.TestHook)
	}
}

// registerRoutingWebhookRoutes registers routing webhook admin routes.
func registerRoutingWebhookRoutes(admin *gin.RouterGroup, handlers *Handlers) {
	if handlers.RoutingWebhook == nil {
		return
	}
	rwh := admin.Group("/routing-webhooks")
	{
		rwh.GET("", handlers.RoutingWebhook.ListWebhooks)
		rwh.POST("", handlers.RoutingWebhook.CreateWebhook)
		rwh.GET("/:id", handlers.RoutingWebhook.GetWebhook)
		rwh.PUT("/:id", handlers.RoutingWebhook.UpdateWebhook)
		rwh.DELETE("/:id", handlers.RoutingWebhook.DeleteWebhook)
		rwh.POST("/:id/test", handlers.RoutingWebhook.TestWebhook)
		rwh.GET("/:id/logs", handlers.RoutingWebhook.ListLogs)
	}
}

// registerComplianceReportRoutes registers compliance report platform admin routes.
func registerComplianceReportRoutes(platformAdmin *gin.RouterGroup, handlers *Handlers) {
	if handlers.ComplianceReport == nil {
		return
	}
	reports := platformAdmin.Group("/compliance/reports")
	{
		reports.GET("", handlers.ComplianceReport.List)
		reports.POST("", handlers.ComplianceReport.Create)
		reports.GET("/templates", handlers.ComplianceReport.ListTemplates)
		reports.GET("/:id", handlers.ComplianceReport.GetByID)
		reports.GET("/:id/download", handlers.ComplianceReport.Download)
		reports.DELETE("/:id", handlers.ComplianceReport.Delete)
	}
}

// registerCompliancePolicyRoutes registers compliance policy platform admin routes.
func registerCompliancePolicyRoutes(platformAdmin *gin.RouterGroup, handlers *Handlers) {
	if handlers.CompliancePolicy == nil {
		return
	}
	compliance := platformAdmin.Group("/compliance")
	{
		compliance.GET("/controls", handlers.CompliancePolicy.ListControls)
		compliance.GET("/policies", handlers.CompliancePolicy.ListPolicies)
		compliance.POST("/policies", handlers.CompliancePolicy.CreatePolicy)
		compliance.PUT("/policies/:id", handlers.CompliancePolicy.UpdatePolicy)
		compliance.DELETE("/policies/:id", handlers.CompliancePolicy.DeletePolicy)
		compliance.POST("/evaluate", handlers.CompliancePolicy.TriggerEvaluation)
		compliance.GET("/dashboard", handlers.CompliancePolicy.GetDashboard)
		compliance.GET("/evaluations", handlers.CompliancePolicy.ListEvaluations)
		compliance.POST("/baselines", handlers.CompliancePolicy.CaptureBaseline)
		compliance.GET("/drift", handlers.CompliancePolicy.GetDriftAlerts)
	}
}

// registerRealmFederationRoutes registers realm federation trust platform admin routes.
func registerRealmFederationRoutes(platformAdmin *gin.RouterGroup, handlers *Handlers) {
	if handlers.RealmFederation == nil {
		return
	}
	trusts := platformAdmin.Group("/federation/trusts")
	{
		trusts.GET("", handlers.RealmFederation.ListTrusts)
		trusts.POST("", handlers.RealmFederation.CreateTrust)
		trusts.GET("/:id", handlers.RealmFederation.GetTrust)
		trusts.PUT("/:id", handlers.RealmFederation.UpdateTrust)
		trusts.DELETE("/:id", handlers.RealmFederation.DeleteTrust)
		trusts.POST("/:id/approve", handlers.RealmFederation.ApproveTrust)
		trusts.POST("/:id/suspend", handlers.RealmFederation.SuspendTrust)
	}
}

// registerAuditIntegrityRoutes registers audit integrity platform admin routes.
func registerAuditIntegrityRoutes(platformAdmin *gin.RouterGroup, handlers *Handlers) {
	if handlers.AuditIntegrity == nil {
		return
	}
	platformAdmin.GET("/audit-integrity/verify", handlers.AuditIntegrity.VerifyChainIntegrity)
}

// registerThreatCorrelationRoutes registers threat correlation platform admin routes.
func registerThreatCorrelationRoutes(platformAdmin *gin.RouterGroup, handlers *Handlers) {
	if handlers.ThreatCorrelation == nil {
		return
	}
	threats := platformAdmin.Group("/threat-correlation")
	{
		threats.GET("", handlers.ThreatCorrelation.ListEvents)
		threats.GET("/:id", handlers.ThreatCorrelation.GetEvent)
		threats.PUT("/:id", handlers.ThreatCorrelation.UpdateEventStatus)
	}
}

// registerAppInstallationRoutes registers app installation platform admin routes.
func registerAppInstallationRoutes(platformAdmin *gin.RouterGroup, handlers *Handlers) {
	if handlers.AppInstallation == nil {
		return
	}
	appInstalls := platformAdmin.Group("/app-installations")
	{
		appInstalls.GET("", handlers.AppInstallation.ListInstallations)
		appInstalls.POST("/install", handlers.AppInstallation.Install)
		appInstalls.POST("/uninstall", handlers.AppInstallation.Uninstall)
		appInstalls.GET("/:id", handlers.AppInstallation.GetInstallation)
	}
}

// registerSpiceDBDebugRoutes registers SpiceDB debug platform admin routes.
func registerSpiceDBDebugRoutes(platformAdmin *gin.RouterGroup, handlers *Handlers) {
	if handlers.SpiceDBDebug == nil {
		return
	}
	spicedb := platformAdmin.Group("/spicedb")
	{
		spicedb.POST("/debug-permission", handlers.SpiceDBDebug.DebugPermission)
		spicedb.GET("/reconciler/status", handlers.SpiceDBDebug.GetReconcilerStatus)
		spicedb.POST("/reconciler/trigger", handlers.SpiceDBDebug.TriggerReconciliation)
		spicedb.POST("/users/:id/effective-permissions", handlers.SpiceDBDebug.GetEffectivePermissions)
		spicedb.POST("/bulk-assign", handlers.SpiceDBDebug.BulkAssign)
	}
}

// registerStubRoutes registers placeholder routes for endpoints that the
// platform-admin frontend calls but that are not yet backed by real business logic.
// All return 200 with empty/default payloads to prevent frontend 404 errors.
//
// NOTE: Tenant sub-resource stub routes (/tenants/:tenant_id/*) are registered
// separately via registerStubTenantRoutes on the top-level router to avoid Gin
// tree conflicts with routes in routes_products.go that share the same prefix.
func registerStubRoutes(platformAdmin *gin.RouterGroup, handlers *Handlers, _ *middleware.AuthMiddleware) {
	stub := handlers.Stub

	// Platform analytics (dashboard calls /platform/analytics)
	platformAdmin.GET("/analytics", stub.GetPlatformAnalytics)

	// Billing endpoints
	billing := platformAdmin.Group("/billing")
	{
		billing.GET("/metrics", stub.GetBillingMetrics)
		billing.GET("/revenue", stub.GetBillingRevenue)
		billing.GET("/invoices", stub.GetBillingInvoices)
		billing.GET("/invoices/:id", stub.GetBillingInvoice)
		billing.POST("/invoices/:id/void", stub.VoidInvoice)
		billing.POST("/invoices/:id/mark-paid", stub.MarkInvoicePaid)
		billing.GET("/payments", stub.GetBillingPayments)
		billing.GET("/payments/:id", stub.GetBillingPayment)
		billing.POST("/payments/:id/refund", stub.RefundPayment)
	}

	// Deletion pipeline
	platformAdmin.GET("/deletion-pipeline", stub.GetDeletionPipeline)

	// Provisioning queue/history
	provisioning := platformAdmin.Group("/provisioning")
	{
		provisioning.GET("/queue", stub.GetProvisioningQueue)
		provisioning.GET("/history", stub.GetProvisioningHistory)
		provisioning.POST("/:task_id/retry", stub.RetryProvisioningTask)
		provisioning.POST("/:task_id/cancel", stub.CancelProvisioningTask)
	}

	logger.Info("Stub routes registered for frontend compatibility")
}

// registerStubTenantRoutes registers tenant sub-resource stub routes on the
// top-level router. These share the /api/v1/platform/tenants/:tenant_id prefix
// with routes in routes_products.go (instances), so they must be registered at
// the same level to keep Gin's radix tree consistent.
func registerStubTenantRoutes(router *gin.Engine, handlers *Handlers, authMiddleware *middleware.AuthMiddleware) {
	stub := handlers.Stub

	tenants := router.Group("/api/v1/platform/tenants/:tenant_id")
	tenants.Use(authMiddleware.RequireAuth(), authMiddleware.RequirePlatformAdmin())
	{
		tenants.GET("/provisioning-status", stub.GetTenantProvisioningStatus)
		tenants.GET("/suspensions", stub.GetTenantSuspensions)
		tenants.POST("/suspend", stub.SuspendTenant)
		tenants.POST("/resume", stub.ResumeTenant)
		tenants.GET(pathDeletion, stub.GetTenantDeletion)
		tenants.POST(pathDeletion, stub.RequestTenantDeletion)
		tenants.DELETE(pathDeletion, stub.CancelTenantDeletion)
		tenants.GET("/compliance-holds", stub.GetTenantComplianceHolds)
		tenants.POST("/compliance-holds", stub.CreateTenantComplianceHold)
		tenants.DELETE("/compliance-holds/:hold_id", stub.DeleteTenantComplianceHold)
		tenants.GET("/modules/status", stub.GetTenantModulesStatus)
		tenants.POST("/modules/:module_id/activate", stub.ActivateTenantModule)
		tenants.POST("/modules/:module_id/deactivate", stub.DeactivateTenantModule)
		tenants.POST("/modules/:module_id/extend-grace", stub.ExtendModuleGrace)
		tenants.POST("/modules/:module_id/cancel-removal", stub.CancelModuleRemoval)
		tenants.PUT("/quotas/:resource", stub.UpdateTenantQuota)
	}

	// Bulk operations on separate path to avoid wildcard conflict
	bulk := router.Group("/api/v1/platform/tenants/bulk")
	bulk.Use(authMiddleware.RequireAuth(), authMiddleware.RequirePlatformAdmin())
	{
		bulk.POST("/suspend", stub.BulkSuspendTenants)
		bulk.POST("/resume", stub.BulkResumeTenants)
	}
}

// registerInfrastructureStubRoutes registers stub routes for infrastructure pages
// (storage, compute, network). These are separate microservices in production but
// need stub responses in falcon-id so the platform-admin frontend doesn't 404.
// NOTE: Cloudflare/domains go through APISIX to domain-management service, not falcon-id.
func registerInfrastructureStubRoutes(api *gin.RouterGroup, handlers *Handlers, authMiddleware *middleware.AuthMiddleware) {
	stub := handlers.Stub

	// Storage — frontend calls /api/v1/storage/*
	storage := api.Group("/storage")
	storage.Use(authMiddleware.RequireAuth())
	{
		storage.GET(pathStats, stub.GetStorageStats)
		storage.GET("/usage", stub.GetStorageUsage)
		storage.GET("/health", stub.GetStorageHealth)
		storage.GET("/quota", stub.GetStorageQuota)
		storage.GET("/files", stub.ListStorageFiles)
		storage.GET("/files/:file_id", stub.GetStorageFile)
		storage.DELETE("/files/:file_id", stub.DeleteStorageFile)
		storage.POST("/upload", stub.UploadStorageFile)
		storage.GET("/tenants/:tenant_id/usage", stub.GetStorageTenantUsage)
		storage.GET("/tenants/:tenant_id/files", stub.GetStorageTenantFiles)
	}

	// Compute — frontend calls /api/v1/compute/*
	compute := api.Group("/compute")
	compute.Use(authMiddleware.RequireAuth())
	{
		compute.GET(pathStats, stub.GetComputeStats)
		compute.GET("/workloads", stub.ListComputeWorkloads)
		compute.GET("/workloads/:id", stub.GetComputeWorkload)
		compute.GET("/functions", stub.ListComputeFunctions)
		compute.GET("/scaling", stub.GetComputeScaling)
		compute.GET("/events", stub.GetComputeEvents)
	}

	// Network — frontend calls /api/v1/network/*
	network := api.Group("/network")
	network.Use(authMiddleware.RequireAuth())
	{
		network.GET(pathStats, stub.GetNetworkStats)
		network.GET("/vnets", stub.ListNetworkVNets)
		network.GET("/security-groups", stub.ListNetworkSecurityGroups)
		network.GET("/load-balancers", stub.ListNetworkLoadBalancers)
		network.GET("/dns", stub.ListNetworkDNS)
		network.GET("/events", stub.GetNetworkEvents)
	}

	logger.Info("Infrastructure stub routes registered (storage, compute, network)")
}

// registerInternalAPIRoutes registers internal service-to-service API routes.
func registerInternalAPIRoutes(router *gin.Engine, handlers *Handlers, authMiddleware *middleware.AuthMiddleware, _ *middleware.InternalAuthMiddleware, _ *middleware.APIKeyAuthMiddleware, serviceAuthMiddleware *middleware.ServiceAuthMiddleware) {
	// Internal API for service-to-service communication
	// Accepts: OAuth2 client_credentials Bearer JWT (composite key validation)
	//          OR legacy X-Internal-Key header (migration period fallback)
	internal := router.Group("/internal")
	internal.Use(serviceAuthMiddleware.ServiceAuth())
	internal.Use(middleware.RequireAnyScopeOrInternalKey(scopeServiceRegister))
	{
		// Kept for backward compatibility -- nothing in this codebase or any
		// sibling repo calls this bare path (checked: every caller goes
		// through platform-shared's permissions.Client, which has only ever
		// posted to /internal/v1/permissions/register, see below). Left in
		// place anyway rather than removed, in case an out-of-band caller
		// (a runbook, a manual curl) depends on it.
		internal.POST("/permissions/register", handlers.Permission.RegisterModule)
	}

	// Internal service-to-service API.
	//
	// Auth: serviceAuthMiddleware.ServiceAuth() — accepts:
	//   (a) OAuth2 client_credentials Bearer JWT (canonical, RFC 6749 §4.4)
	//   (b) Legacy X-Internal-Key header (migration-period fallback)
	//
	// The `internal` group above (line 1379) already uses ServiceAuth(); this
	// /internal/v1 group is consolidated onto the same middleware so there is
	// ONE auth path across the service surface. Per-group .Use() retained so
	// each sub-group's auth requirement is locally visible at the route site
	// — matches the pre-migration shape and reads correctly under code review.
	//
	// operational notes — "delete
	// INTERNAL_API_KEY config/middleware/env on sight". The legacy
	// InternalAuthMiddleware will be ripped in a follow-up MR once telemetry
	// confirms no traffic uses X-Internal-Key (track via Prometheus counter
	// `service_auth_method_total{method="internal_key"}` added by
	// service_auth.go — TODO: wire that counter).
	//
	// Uses /internal/v1 prefix to avoid route conflicts with public /api/v1 routes.
	internalV1 := router.Group("/internal/v1")
	if handlers.ApprovalDirectory != nil {
		router.POST("/api/v1/authorization/lookup-subjects", serviceAuthMiddleware.ServiceAuth(), middleware.RequireScope("authz:lookup"), handlers.ApprovalDirectory.LookupSubjects)
		router.POST("/api/v1/authorization/check-batch", serviceAuthMiddleware.ServiceAuth(), middleware.RequireScope("authz:check"), handlers.ApprovalDirectory.BatchCheck)
	}
	{
		// Module permission-catalogue self-registration. Every service that
		// links platform-shared/permissions.Client posts here at startup
		// (client.go builds "%s/internal/v1/permissions/register") -- this
		// route simply never existed on the /internal/v1 group, only on the
		// legacy /internal one above, so registration has been 404ing
		// (non-blocking, so silently) for every consumer since whenever this
		// group's /v1 consolidation happened. Confirmed via
		// hexxlock_falcon_id: payment:admin, platform:admin and every
		// payment% permission were simply absent, and platform_admin had
		// zero rows in iam_role_permissions, because the module catalogues
		// that would have created them never landed.
		internalPermissions := internalV1.Group("/permissions")
		internalPermissions.Use(serviceAuthMiddleware.ServiceAuth())
	internalPermissions.Use(middleware.RequireAnyScopeOrInternalKey(scopeServiceRegister))
		{
			internalPermissions.POST("/register", handlers.Permission.RegisterModule)
		}

		// Role-templates module-revoke fallback trigger (the product roadmap
		// §4.1) — see RoleTemplateHandler.RevokeModule's doc comment: there
		// is no existing Kafka "module revoked" event, only the
		// subscription-activated one (wired into the grant side via
		// services.WithTemplateRoleProvisioner in cmd/services.go).
		internalRoleTemplates := internalV1.Group("/role-templates")
		internalRoleTemplates.Use(serviceAuthMiddleware.ServiceAuth())
		// Revoke strips grants from every template-derived role of a tenant, so a
		// valid service token alone is not enough: the caller (the entitlement
		// owner) must hold this scope via its ServiceClientClaim.
		internalRoleTemplates.Use(middleware.RequireScope("iam:role-templates:revoke"))
		{
			internalRoleTemplates.POST("/revoke", handlers.RoleTemplate.RevokeModule)
		}

		// Internal user management
		internalUsers := internalV1.Group("/users")
		internalUsers.Use(serviceAuthMiddleware.ServiceAuth())
	internalUsers.Use(middleware.RequireAnyScopeOrInternalKey(scopeServiceRegister))
		{
			internalUsers.POST("", handlers.User.Create)
		}

		// Internal role management
		internalRoles := internalV1.Group("/roles")
		internalRoles.Use(serviceAuthMiddleware.ServiceAuth())
		internalRoles.Use(middleware.RequireAnyScopeOrInternalKey(scopeServiceRegister))
		{
			internalRoles.POST("", handlers.Role.Create)
			internalRoles.GET("", handlers.Role.List)

			// ADR-A10 delegated-admin guard (17-module-account.md §12.2,
			// 23-authorization-rbac-abac-rebac.md §3.2): additive
			// single-permission grant, enforcing the entitlement +
			// platform-tenant boundary server-side regardless of caller.
			// Stricter than the group: dedicated scope on top of service:register, and
			// the handler requires a JWT and checks the role tenant against the token.
			internalRoles.POST("/:id/actions/grant-permission", middleware.RequireScope("iam:roles:grant-permission"), handlers.Role.GrantPermission)
		}

		// Internal SoD evaluation (23-authorization-rbac-abac-rebac.md
		// §5.2/§8.3): re-evaluates a user's current role assignments
		// against the seeded iam_sod_rules ruleset and upserts
		// iam_sod_violations. Warn mode only in R1 — never blocks.
		internalSoD := internalV1.Group("/sod")
		internalSoD.Use(serviceAuthMiddleware.ServiceAuth())
	internalSoD.Use(middleware.RequireAnyScopeOrInternalKey(scopeServiceRegister))
		{
			internalSoD.POST("/evaluate", handlers.SoD.Evaluate)
		}

		// Internal tenant management
		internalTenants := internalV1.Group("/tenants")
		internalTenants.Use(serviceAuthMiddleware.ServiceAuth())
		{
			if handlers.ApprovalDirectory != nil {
				internalTenants.GET("/:id/approval-membership-summary", middleware.RequireScope("iam:members:read"), handlers.ApprovalDirectory.MembershipSummary)
				internalTenants.GET("/:id/approval-members/:user_id", middleware.RequireScope("iam:members:read"), handlers.ApprovalDirectory.ApprovalMember)
			}
			if handlers.TeamScope != nil {
				internalTenants.GET("/:id/users/:user_id/team-scope", middleware.RequireScope(scopeTeamsRead), handlers.TeamScope.GetTeamScope)
			}
			if handlers.NotifRecipients != nil {
				internalTenants.POST("/:id/notification-recipients", middleware.RequireScope("iam:members:read"), handlers.NotifRecipients.Resolve)
			}
			internalTenants.POST("", middleware.RequireAnyScopeOrInternalKey(scopeServiceRegister), handlers.Tenant.CreateTenant)
			internalTenants.GET("/:id/connection-info", middleware.RequireAnyScopeOrInternalKey(scopeServiceRegister), handlers.Tenant.GetTenantConnectionInfoByID)

			// Resolved SMTP configuration for a tenant. notification-service
			// calls this at send preflight, and until it was registered the
			// route 404'd — so EVERY outbound email failed with "email
			// integration not configured for this tenant" before a connection
			// was ever opened. The handler, its struct field and its
			// construction were all already here; it was simply never mounted,
			// which is why the failure looked like a tenant data problem rather
			// than a missing route.
			//
			// ⚠ The wildcard MUST be :id, not :tenant_id. Gin PANICS at startup
			// on two different wildcard names at the same position within one
			// group, and this group already uses :id for connection-info.
			// GetInternalSMTPConfig reads c.Param("id") regardless of what its
			// own doc comment says.
			if handlers.TenantConfig != nil {
				internalTenants.GET("/:id/smtp-config", middleware.RequireAnyScopeOrInternalKey(scopeServiceRegister), handlers.TenantConfig.GetInternalSMTPConfig)
			}

			// Active user (seat) count for a tenant — feat/seat-quota-
			// enforcement. quota-service's users-resource backfill script
			// calls this to seed/reconcile seat usage against iam_users,
			// the only live authoritative user-count source on the
			// platform. Returns {"tenant_id","active_user_count"} where
			// the count excludes inactive users and users in their
			// deletion_scheduled_at grace period (see
			// UserRepository.CountActiveByTenant).
			internalTenants.GET("/:id/users/count", middleware.RequireAnyScopeOrInternalKey(scopeServiceRegister), handlers.Tenant.GetTenantUserCount)
			// Point membership check for S2S callers (business lead-owner validation
			// fallback when core.users has not synced yet): 200 {"active":bool} / 404.
			// Scope-gated; same :id wildcard as the siblings, no listing.
			internalTenants.GET("/:id/members/:userId",
				middleware.RequireScope("iam:members:read"),
				handlers.Tenant.GetTenantMember)
			// Employee-class (ESS) accounts for the business HR module (R-HR WP-21): seat-free, hr:employee role only.
			// Wildcards stay :id/:userId (Gin rejects a different name under the same prefix).
			internalTenants.POST("/:id/employee-accounts",
				middleware.RequireScope("iam:employee-accounts:write"),
				handlers.TeamInvitation.ProvisionEmployeeAccount)
			internalTenants.PUT("/:id/employee-accounts/:userId/access-expiry",
				middleware.RequireScope("iam:employee-accounts:write"),
				handlers.TeamInvitation.SetEmployeeAccessExpiry)
			// Source-owned HR projection. Deliberately independent from ESS expiry, which
			// deactivates an employee account globally and is not safe for employment exit.
			internalTenants.PUT("/:id/hr-employment-sync/scopes", middleware.RequireScope("iam:hr-employment-sync:write"), handlers.HREmploymentSync.PutScope)
			internalTenants.PUT("/:id/hr-employments/:employeeId", middleware.RequireScope("iam:hr-employment-sync:write"), handlers.HREmploymentSync.PutEmployment)

			// Interim seat_limit source (the product roadmap §2.1/§4.9,
			// the product specification §13.2): falcon-id has
			// no queryable included-seats/entitlement-plan data yet (no
			// subscription-management/quota-service sync exists for it), so
			// until that lands, an operator or an eventual
			// subscription-management sync sets seat_limit directly via
			// this endpoint. GET is read-only (iam:seats:read); PUT requires
			// iam:seats:write since it changes enforcement for a tenant.
			// This path is already exempt from the X-Tenant-ID gate — see
			// internal/middleware/tenant.go's publicEndpoints, which lists
			// "/internal/v1/tenants/" (prefix match).
			if handlers.SeatLimit != nil {
				internalTenants.GET("/:id/seat-limit", middleware.RequireScope("iam:seats:read"), handlers.SeatLimit.GetSeatLimit)
				internalTenants.PUT("/:id/seat-limit", middleware.RequireScope("iam:seats:write"), handlers.SeatLimit.SetSeatLimit)
			}

			// Placeholder workspace name replacement ("My Company"). business
			// calls this after a tenant's first legal entity is created; it only
			// renames while the tenant is still on the placeholder, so repeat or
			// racing calls are harmless no-ops.
			if handlers.TenantWorkspaceName != nil {
				internalTenants.PUT("/:id/workspace-name",
					middleware.RequireScope("iam:tenants:workspace-name:write"),
					handlers.TenantWorkspaceName.RenameIfPlaceholder)
			}

			// Tenant module entitlements (the product roadmap §4.1). Read is
			// available to any authenticated S2S caller holding
			// iam:entitlements:read; write additionally requires
			// iam:entitlements:write, since PUT is the out-of-band
			// ops/backfill/replay path that can rewrite a tenant's
			// entitlement state outright (the normal path is the
			// example.tenant.modules.sync Kafka consumer in
			// internal/entitlementsync, which needs no HTTP scope at
			// all). This path is already covered by the
			// /internal/v1/tenants/ prefix exemption in
			// internal/middleware/tenant.go's publicEndpoints list, so no
			// new entry is needed there.
			if handlers.Entitlement != nil {
				internalTenants.GET("/:id/module-entitlements",
					middleware.RequireScope("iam:entitlements:read"),
					handlers.Entitlement.GetModuleEntitlements)
				internalTenants.PUT("/:id/module-entitlements",
					middleware.RequireScope("iam:entitlements:write"),
					handlers.Entitlement.PutModuleEntitlements)
			}
		}

		// Internal authorization endpoints
		internalAuthorize := internalV1.Group("/authorize")
		internalAuthorize.Use(serviceAuthMiddleware.ServiceAuth())
	internalAuthorize.Use(middleware.RequireAnyScopeOrInternalKey(scopeServiceRegister))
		{
			internalAuthorize.POST("", handlers.Authorization.Authorize)
			internalAuthorize.POST("/batch", handlers.Authorization.AuthorizeBatch)
		}

		// Subscription event bridge (receives events from subscription-management)
		internalSubEvents := internalV1.Group("/subscription-events")
		internalSubEvents.Use(serviceAuthMiddleware.ServiceAuth())
	internalSubEvents.Use(middleware.RequireAnyScopeOrInternalKey(scopeServiceRegister))
		{
			internalSubEvents.POST("/activated", handlers.SubscriptionEvent.HandleActivated)
		}

		// Internal tenant database lookup — MOVED to db-provisioner (port 8061).
		// The authoritative endpoint is now:
		//   GET db-provisioner:8061/internal/v1/tenant-databases/:tenant_id/:database_name
		// The handler (ProductInstance.LookupTenantDatabase) is kept on the struct for
		// potential future use but is no longer registered as a route here.

		// Internal host-based tenant discovery — the unified-dashboard
		// Next.js SDK middleware calls this from inside the cluster on
		// every inbound request that needs tenant context (when the
		// customer reached the SaaS app via a custom domain like
		// crm.acme-corp.com). NEVER exposed at the public edge —
		// host-header injection becomes trivial otherwise (cross-vendor
		// research consensus: Auth0 / Okta / Entra B2C / Cognito all
		// keep the equivalent lookup behind their internal control
		// plane). The endpoint emits Cache-Control hints so the SDK
		// can stack its own short-lived in-process cache without
		// rebuilding the cache policy.
		//
		// Route: GET /internal/v1/tenant-discovery?host=<host>
		// Auth: ServiceAuth (same envelope as user/role/tenant
		//       internal routes above) — service-to-service only.
		internalDiscovery := internalV1.Group("/tenant-discovery")
		internalDiscovery.Use(serviceAuthMiddleware.ServiceAuth())
	internalDiscovery.Use(middleware.RequireAnyScopeOrInternalKey(scopeServiceRegister))
		{
			if handlers.HostDiscovery != nil {
				internalDiscovery.GET("", handlers.HostDiscovery.Discover)
			}

			// Slug-based sibling of the host lookup above — GET
			// /internal/v1/tenant-discovery/by-slug?slug=<slug>. Resolves
			// against iam_tenants directly (NOT iam_tenant_hosts, which
			// holds essentially only custom domains in production). This
			// is what closes the base-domain subdomain fail-open gap:
			// the Next.js SDK middleware validates a `<slug>.<baseDomain>`
			// candidate's SHAPE client-side, then calls this endpoint to
			// confirm the slug is an actual tenant before serving the app.
			// Same auth envelope as the host lookup (ServiceAuth,
			// service-to-service only, never at the public edge).
			if handlers.TenantSlugDiscovery != nil {
				internalDiscovery.GET("/by-slug", handlers.TenantSlugDiscovery.DiscoverBySlug)
			}
		}

		// Internal tenant-host registration — the write-side sibling of
		// tenant-discovery. domain-management calls this after its own
		// ownership verification + Cloudflare custom-hostname TLS so the
		// host starts resolving without a second manual admin claim.
		// Route: POST /internal/v1/tenant-hosts
		internalTenantHosts := internalV1.Group("/tenant-hosts")
		internalTenantHosts.Use(serviceAuthMiddleware.ServiceAuth())
	internalTenantHosts.Use(middleware.RequireAnyScopeOrInternalKey(scopeServiceRegister))
		{
			if handlers.InternalTenantHost != nil {
				internalTenantHosts.POST("", handlers.InternalTenantHost.Register)
				internalTenantHosts.DELETE("", handlers.InternalTenantHost.Unregister)
			}
		}

		// ZTNA Phase 3 — device-cert enrollment internal API.
		//
		// Two endpoints consumed exclusively by jess controller via
		// devicepolicy.FalconIDEnrollmentStore (feat/ztna-phase3-controller-wiring):
		//
		//   POST /internal/v1/iam-devices/enroll
		//     Persists a new IAMDeviceRow (Path A or B enrollment).
		//     201 → enrolled; 409 → ek_pubkey_hash conflict (impersonation signal);
		//     400 → validation error; 500 → transport error.
		//
		//   GET /internal/v1/iam-devices/by-ek-hash/:hash
		//     Path B TOFU lookup anchor. 200 → found; 404 → first-seen (clean path);
		//     400 → bad hash; 500 → transport error.
		//
		// Auth: ServiceAuth (OAuth2 client_credentials Bearer, same envelope as
		//       /internal/v1/tenant-discovery and /internal/v1/tenant-hosts).
		// References: ADR 0043 §3.c.0, falcon-id!284 (migration), falcon-id!285 (repo).
		if handlers.IAMDevices != nil {
			internalIAMDevices := internalV1.Group("/iam-devices")
			internalIAMDevices.Use(serviceAuthMiddleware.ServiceAuth())
			internalIAMDevices.Use(middleware.RequireAnyScopeOrInternalKey(scopeServiceRegister, "iam-devices:enroll"))
			{
				internalIAMDevices.POST("/enroll", handlers.IAMDevices.Enroll)
				internalIAMDevices.GET("/by-ek-hash/:hash", handlers.IAMDevices.GetByEKHash)
				// by-uuid lookup (incl. revoked_at) — consumed by the jess
				// device-cert renewal handler (ADR 0048) to fail-closed on a
				// revoked-but-not-yet-expired device before re-minting.
				internalIAMDevices.GET("/by-uuid/:uuid", handlers.IAMDevices.GetByUUID)
			}
		}

		// Corporate device pre-registration — the zero-touch CORP allowlist
		// (migration 0007). Same /internal/v1/iam-devices group + ServiceAuth.
		//
		//   GET    /internal/v1/iam-devices/corp-asset/by-ek-hash/:hash
		//     Attest-time allowlist check. 200 {is_corporate_asset} always
		//     (false for an unknown EK — "not a corporate asset" is a valid
		//     answer, not 404). jess downgrades CORP -> BYOD when false.
		//   POST   /internal/v1/iam-devices/pre-registrations/bulk
		//     Idempotent bulk import (re-imports skipped; per-row errors reported).
		//   GET    /internal/v1/iam-devices/pre-registrations?tenant_id=<uuid>
		//   DELETE /internal/v1/iam-devices/pre-registrations/:id?tenant_id=<uuid>
		//
		// Caller: jess (directly for the corp-asset check; on behalf of a
		// human admin in jess-web for the CRUD — human-admin gating happens
		// in jess, this tier is s2s only).
		if handlers.IAMDevicePreReg != nil {
			preReg := internalV1.Group("/iam-devices")
			preReg.Use(serviceAuthMiddleware.ServiceAuth())
			preReg.Use(middleware.RequireAnyScopeOrInternalKey(scopeServiceRegister, "iam-devices:enroll"))
			{
				preReg.GET("/corp-asset/by-ek-hash/:hash", handlers.IAMDevicePreReg.CorpAssetByEKHash)
				preReg.POST("/pre-registrations/bulk", handlers.IAMDevicePreReg.BulkPreRegister)
				preReg.GET("/pre-registrations", handlers.IAMDevicePreReg.List)
				preReg.DELETE("/pre-registrations/:id", handlers.IAMDevicePreReg.Delete)
			}
		}

		// Internal storage — presigned MinIO download URLs.
		// Called by C# business modules (CRM, PLM, …) via Hexxlock.Shared StorageClient.
		// Route: POST /internal/v1/storage/presigned-download
		// Also registered at /api/v1/internal/storage/presigned-download via APISIX rewrite
		// (see config/apisix/apisix-dev.yaml — the C# client uses /api/v1/internal/…).
		internalStorage := internalV1.Group("/storage")
		internalStorage.Use(serviceAuthMiddleware.ServiceAuth())
	internalStorage.Use(middleware.RequireAnyScopeOrInternalKey(scopeServiceRegister))
		{
			if handlers.InternalStorage != nil {
				internalStorage.POST(pathPresignedDownload, handlers.InternalStorage.PresignedDownload)
			} else {
				// Fallback: return 503 so callers get a clear error instead of a 404.
				internalStorage.POST(pathPresignedDownload, func(c *gin.Context) {
					c.JSON(http.StatusServiceUnavailable, gin.H{
						"error": "storage handler not initialised — check MINIO_ENDPOINT configuration",
					})
				})
			}
		}

		// R1 platform plane: JIT elevation + break-glass + standing
		// platform-role admin. Two-layer auth per this rollout's hard
		// rule ("tenant/user from the validated JWT only"):
		//   1. ServiceAuth()+RequireScope("platform:jit-elevations") —
		//      authenticates the CALLING SERVICE (the acmeweb BFF).
		//   2. RequireActorAuth()+RequirePlatformInternalActor() —
		//      authenticates the HUMAN OPERATOR acting through it (see
		//      internal/middleware/actor_auth.go's doc comment) and
		//      rejects any actor whose OWN tenant isn't the
		//      Platform-internal tenant, fail-closed, before the handler
		//      runs at all. Every handler method derives requester_id/
		//      approver_id from middleware.GetActorUserID(c) exclusively
		//      — never a body field.
		//
		// Exempted from ExtractTenant's X-Tenant-ID requirement in
		// internal/middleware/tenant.go (see the "/internal/v1/jit-
		// elevations/" and "/internal/v1/break-glass/" entries there);
		// tenant context here is always the internal tenant, sourced
		// from the actor JWT, never a header.
		platformJITAuth := []gin.HandlerFunc{
			serviceAuthMiddleware.ServiceAuth(),
			middleware.RequireScope("platform:jit-elevations"),
			authMiddleware.RequireActorAuth(),
			middleware.RequirePlatformInternalActor(),
		}

		internalJITElevations := internalV1.Group("/jit-elevations")
		internalJITElevations.Use(platformJITAuth...)
		{
			internalJITElevations.POST("", handlers.PlatformJIT.RequestElevation)
			internalJITElevations.GET("", handlers.PlatformJIT.ListElevations)
			internalJITElevations.POST("/:id/approve", handlers.PlatformJIT.ApproveElevation)
			internalJITElevations.POST("/:id/activate", handlers.PlatformJIT.ActivateElevation)
			internalJITElevations.POST("/:id/revoke", handlers.PlatformJIT.RevokeElevation)
			// Read-only audit view over the append-only hash-chain
			// transition log for one elevation (migration 0016's
			// iam_jit_elevation_transitions) — R1 lead-review requirement,
			// added alongside the GET list routes below.
			internalJITElevations.GET("/:id/transitions", handlers.PlatformJIT.ListTransitions)
		}

		internalBreakGlass := internalV1.Group("/break-glass")
		internalBreakGlass.Use(platformJITAuth...)
		{
			internalBreakGlass.POST("", handlers.PlatformJIT.RequestBreakGlass)
			internalBreakGlass.GET("", handlers.PlatformJIT.ListBreakGlass)
			internalBreakGlass.POST("/:id/retroactive-approve", handlers.PlatformJIT.RetroactivelyApprove)
		}

		// Standing platform-role admin (platform_viewer only — every
		// other role_key 403s with platform_role_not_standing_assignable,
		// enforced in services.PlatformJITService.GrantStandingRole AND
		// belt-and-suspenders by the iam_platform_roles_enforce() DB
		// trigger from migration 0016).
		internalPlatformRoles := internalV1.Group("/platform-roles")
		internalPlatformRoles.Use(platformJITAuth...)
		{
			internalPlatformRoles.POST("", handlers.PlatformJIT.GrantStandingRole)
			internalPlatformRoles.GET("", handlers.PlatformJIT.ListStandingRoles)
			// OPS_STRICT_PLATFORM_ROLES readiness: who relies on the legacy
			// tenant-role path (read-only) and the standing-viewer seed
			// (DRY-RUN unless the body says {"apply":true}).
			if handlers.PlatformAuth != nil {
				internalPlatformRoles.GET("/legacy-report", handlers.PlatformAuth.LegacyReport)
				internalPlatformRoles.POST("/seed-viewers", handlers.PlatformAuth.SeedViewers)
			}
		}

		// Staff console "people" surface on the operator chain (assertion-
		// verified actor, per-area scopes). Nil unless the operator exchange is on.
		registerOpsConsoleRoutes(internalV1, handlers, serviceAuthMiddleware.ServiceAuth())
	}

	// Register the same storage endpoint under /api/v1/internal/… so that
	// C# clients calling /api/v1/internal/storage/presigned-download hit the
	// correct handler without requiring an APISIX rewrite rule.
	// Uses ServiceAuth (OAuth2 client_credentials) — C# modules use ServiceAuthDelegatingHandler.
	apiV1Internal := router.Group("/api/v1/internal")
	apiV1Internal.Use(serviceAuthMiddleware.ServiceAuth())
	{
		apiV1InternalStorage := apiV1Internal.Group("/storage")
		apiV1InternalStorage.Use(middleware.RequireAnyScopeOrInternalKey(scopeServiceRegister))
		if handlers.InternalStorage != nil {
			apiV1InternalStorage.POST(pathPresignedDownload, handlers.InternalStorage.PresignedDownload)
		} else {
			apiV1InternalStorage.POST(pathPresignedDownload, func(c *gin.Context) {
				c.JSON(http.StatusServiceUnavailable, gin.H{
					"error": "storage handler not initialised — check MINIO_ENDPOINT configuration",
				})
			})
		}

		// Email domain management — cross-service (marketing → falcon-id)
		// Used by marketing module to sync sender domains to Workspace Email Domains.
		if handlers.EmailDomain != nil {
			apiV1InternalDomains := apiV1Internal.Group("/tenants/:tenant_id/domains")
			apiV1InternalDomains.Use(middleware.RequireAnyScopeOrInternalKey(scopeServiceRegister))
			{
				apiV1InternalDomains.GET("", handlers.EmailDomain.ListDomains)
				apiV1InternalDomains.POST("", handlers.EmailDomain.RegisterDomain)
				apiV1InternalDomains.DELETE(pathDomainID, handlers.EmailDomain.DeleteDomain)
			}
		}

		// OAuth-client management for service-to-service callers
		// (Crossplane ServiceClient Composition + future provisioners).
		// Authenticates via OAuth client_credentials JWT carrying scope
		// `admin:oauth-clients`; tenant comes from the JWT's tenant_id
		// claim, bridged into the canonical TenantIDKey so the existing
		// /api/v1/admin/oauth-clients handlers work without forking.
		//
		// /api/v1/admin/oauth-clients/* (browser admin, RequireAuth +
		// RequireRole) remains for human admins. Both surfaces share
		// the same handler logic; only the auth chain differs.
		apiV1InternalOAuthClients := apiV1Internal.Group("/oauth-clients")
		apiV1InternalOAuthClients.Use(middleware.RequireScope("admin:oauth-clients"))
		apiV1InternalOAuthClients.Use(middleware.BridgeServiceTenantToTenantID())
		// Mark this group as a trusted-registration surface: handlers
		// inspect the resulting context flag to decide whether to honor
		// is_first_party=true on Create/Update. The /api/v1/admin/* surface
		// (browser admin) deliberately does NOT mount this — see
		// middleware/trusted_registration.go for the threat model.
		apiV1InternalOAuthClients.Use(middleware.TrustedRegistration())
		{
			apiV1InternalOAuthClients.GET("", handlers.OAuthProvider.ListClients)
			apiV1InternalOAuthClients.POST("", handlers.OAuthProvider.CreateClient)
			// /by-client-id/:client_id MUST come before /:id so gin's
			// router matches the literal "by-client-id" segment ahead
			// of the UUID :id wildcard. Lets the provisioner resolve
			// "svc-accounts" → UUID for a true POST→409→PUT upsert
			// without storing the generated UUID anywhere.
			apiV1InternalOAuthClients.GET("/by-client-id/:client_id", handlers.OAuthProvider.GetClientByClientIDLookup)
			apiV1InternalOAuthClients.GET("/:id", handlers.OAuthProvider.GetClient)
			apiV1InternalOAuthClients.PUT("/:id", handlers.OAuthProvider.UpdateClient)
			apiV1InternalOAuthClients.DELETE("/:id", handlers.OAuthProvider.DeleteClient)
			apiV1InternalOAuthClients.POST("/:id/regenerate-secret", handlers.OAuthProvider.RegenerateSecret)

			// RFC 8693 trusted-external-issuer per-client grants
			// (provisioner reconcile path). The Crossplane
			// serviceclient-provisioner Job uses this to:
			//   - resolve issuer-name → UUID (List by ?name=)
			//   - enumerate existing (client, issuer) rows
			//     (GET /oauth-clients/:id/trusted-external-issuers)
			//   - upsert/revoke grants to drive the join table
			//     to match the SCC's externalJWTExchange.trustedIssuers
			//
			// Same handler logic as /api/v1/admin/* — only the auth
			// chain differs (ServiceAuth + admin:oauth-clients scope
			// instead of human admin + step-up). Step-up is not
			// applicable to s2s client_credentials callers.
			apiV1InternalOAuthClients.GET("/:id/trusted-external-issuers", handlers.OAuthTrustedExternalIssuer.ListClientGrants)
			apiV1InternalOAuthClients.POST("/:id/trusted-external-issuers", handlers.OAuthTrustedExternalIssuer.GrantClient)
			apiV1InternalOAuthClients.DELETE("/:id/trusted-external-issuers/:issuer_id", handlers.OAuthTrustedExternalIssuer.RevokeClient)
		}

		// Trusted-external-issuer registry (provisioner name→UUID lookup).
		// Same handler as /api/v1/admin/oauth-trusted-external-issuers
		// but mounted under the s2s ServiceAuth chain. Used by the
		// serviceclient-provisioner to resolve issuer names declared on
		// ServiceClientClaim.spec.externalJWTExchange.trustedIssuers
		// (e.g. "talon-iap") to row UUIDs needed for the grant upsert.
		apiV1InternalTrustedIssuers := apiV1Internal.Group("/oauth-trusted-external-issuers")
		apiV1InternalTrustedIssuers.Use(middleware.RequireScope("admin:oauth-clients"))
		apiV1InternalTrustedIssuers.Use(middleware.BridgeServiceTenantToTenantID())
		apiV1InternalTrustedIssuers.Use(middleware.TrustedRegistration())
		{
			apiV1InternalTrustedIssuers.GET("", handlers.OAuthTrustedExternalIssuer.List)
			apiV1InternalTrustedIssuers.POST("", handlers.OAuthTrustedExternalIssuer.Create)
			apiV1InternalTrustedIssuers.GET("/:id", handlers.OAuthTrustedExternalIssuer.Get)
			apiV1InternalTrustedIssuers.PUT("/:id", handlers.OAuthTrustedExternalIssuer.Update)
			apiV1InternalTrustedIssuers.DELETE("/:id", handlers.OAuthTrustedExternalIssuer.Delete)
		}
	}
}

// registerOAuthRoutes registers OAuth2/OIDC endpoints.
//
// dpopMW is the optional RFC 9449 DPoP middleware. When non-nil, its
// OptionalDPoP() handler is wired in front of /oauth/token so any
// presented DPoP proof is validated and the resulting JKT is stamped
// on the gin context — the Token handler then reads
// `c.Get("dpop_jkt")` and threads it into the issuance context so
// scope-driven DPoP enforcement (e.g. `admin:*` scopes per
// `dpopRequiredScopePrefix`) actually fires. Without this middleware
// every request to /oauth/token requesting a DPoP-required scope
// rejects with `invalid_dpop_proof: requested scope requires a
// DPoP-bound token` regardless of whether the client sent a proof
// — which broke every ServiceClientClaim using the
// `admin:oauth-clients` scope after c91c10d landed.
func registerOAuthRoutes(router *gin.Engine, handlers *Handlers, authMiddleware *middleware.AuthMiddleware, dpopMW *middleware.DPoPMiddleware, tokenPerUserClientIDs []string, authRateLimiter *middleware.AuthRateLimiter) {
	router.GET("/.well-known/openid-configuration", handlers.OAuthProvider.GetOpenIDConfiguration)
	router.GET("/.well-known/jwks.json", handlers.OAuthProvider.GetJWKS)
	// Unified platform JWKS: includes both OAuth keys and the platform RS256 session-token key.
	// Clients should prefer this endpoint for verifying any token issued by Falcon-ID.
	if handlers.JWKS != nil {
		router.GET("/.well-known/platform-jwks.json", handlers.JWKS.GetJWKS)
	}
	router.GET("/oauth/authorize", authMiddleware.OptionalAuth(), handlers.OAuthProvider.Authorize)
	// /oauth/token is the platform's single most expensive endpoint per
	// request (RS256 sign + DB write on every successful issuance), and
	// historically the cheapest DoS surface — a misconfigured client
	// looping refresh-token exchange can saturate the queue for every
	// other tenant. Per-client (or IP-fallback) rate limiter at 60 req/
	// 60s burst + 600 req/3600s sustained, sized for legitimate platform
	// traffic with comfortable headroom; see
	// middleware/oauth_token_rate_limit.go for sizing rationale.
	// /oauth/token middleware chain:
	//   1. OAuthTokenRateLimit  — DoS guard (per-client / IP fallback).
	//   2. OptionalDPoP          — when feature-flagged on, validates a
	//      presented DPoP proof per RFC 9449 §4 and stashes the JKT on
	//      the gin context. The Token handler reads `c.Get("dpop_jkt")`
	//      and passes it into the service's WithDPoPJKT context so
	//      scope-driven enforcement (oauth_provider_service.go's
	//      `dpopRequiredScopePrefix == "admin:"` gate) actually sees
	//      the bound key. Without this hop, EVERY admin: scope token
	//      request rejected with `invalid_dpop_proof: requested scope
	//      requires a DPoP-bound token` even when the client sent a
	//      perfectly-valid DPoP header — verified empirically
	//      2026-05-02 against the live ServiceClient provisioner Job.
	tokenMWs := []gin.HandlerFunc{middleware.OAuthTokenRateLimit(tokenPerUserClientIDs)}
	if dpopMW != nil {
		tokenMWs = append(tokenMWs, dpopMW.OptionalDPoP())
	}
	tokenMWs = append(tokenMWs, handlers.OAuthProvider.Token)
	router.POST("/oauth/token", tokenMWs...)
	router.GET("/oauth/userinfo", authMiddleware.RequireAuth(), handlers.OAuthProvider.UserInfo)
	router.POST("/oauth/userinfo", authMiddleware.RequireAuth(), handlers.OAuthProvider.UserInfo)
	router.POST("/oauth/revoke", handlers.OAuthProvider.Revoke)
	router.POST("/oauth/introspect", handlers.OAuthProvider.Introspect)
	// /oauth/consent (POST + GET below) is part of the OIDC browser
	// flow — same chain as /oauth/authorize. Uses OptionalAuth so the
	// SSO session cookie (falcon_idp_session) is accepted as the auth
	// signal, not just the access-token cookie. The handler redirects
	// to /oauth/login when no user_id is resolved (mirrors the
	// Authorize handler at oauth_provider_handler.go:300-310). Closes
	// the post-Bug-9 trap: sensitive-scope override sends first-party
	// clients to /oauth/consent, but a fresh user has only the SSO
	// marker — not yet a falcon_access_token cookie — and RequireAuth
	// would 401.
	router.POST("/oauth/consent", authMiddleware.OptionalAuth(), handlers.OAuthProvider.ApproveConsent)

	// RFC 9126: Pushed Authorization Requests.
	// No auth middleware: the handler authenticates the client via client credentials.
	router.POST("/oauth/par", handlers.OAuthProvider.PushAuthorization)

	// OAuth login/consent pages (browser flow)
	router.GET("/oauth/login", handlers.OAuthProvider.LoginPage)
	// Hosted login is a password-guessing surface just like /api/v1/auth/login:
	// same per-IP/per-account auth limiter (5/min/IP default).
	loginSubmitMWs := []gin.HandlerFunc{}
	if authRateLimiter != nil {
		loginSubmitMWs = append(loginSubmitMWs, authRateLimiter.Middleware())
	}
	router.POST("/oauth/login", append(loginSubmitMWs, handlers.OAuthProvider.LoginSubmit)...)
	router.GET("/oauth/consent", authMiddleware.OptionalAuth(), handlers.OAuthProvider.ConsentPage)

	// OIDC End-Session (RP-Initiated Logout)
	router.GET("/oauth/logout", handlers.OAuthProvider.EndSession)

	// Service Account OAuth2 token endpoint
	router.POST("/oauth/token/service-account", handlers.ServiceAccount.TokenEndpoint)

	// Tenant API key exchange (WO#20): lgk_live_ key -> 10-minute RS256 token.
	// The handler authenticates the key itself and 404s while the flag is off.
	if handlers.TenantAPIKey != nil {
		// Rate limited per parsed key_id + IP (never the raw client_id).
		router.POST("/oauth/token/api-key", handlers.TenantAPIKeyLimit, handlers.TenantAPIKey.TokenEndpoint)
	}

	// ZTNA Path B device-enrollment witness page (ADR 0043 §3.c.0).
	//
	// Browser-rendered HTML page the Tauri enrollment wizard deep-links
	// to during operator witness signing. The page validates the inbound
	// query parameters, requires an authenticated platform-admin session
	// (302 to /oauth/login on miss, 403 HTML page on wrong role), and
	// drives the W3C WebAuthn ceremony against
	// /api/v1/auth/webauthn/witness/{begin,finish}. On success it POSTs
	// the signed JWS to the operator-supplied 127.0.0.1:<port>/witness-
	// callback loopback target — strictly allowlisted via the page-side
	// regex.
	//
	// Mounted with OptionalAuth (NOT RequireAuth) so the handler can
	// choose between a 302 to /oauth/login on miss vs. rendering the
	// page on hit — RequireAuth would write a 401 JSON envelope, wrong
	// for a browser-loaded GET.
	if handlers.WebAuthn != nil {
		// OptionalAuth is already applied globally via applyGlobalMiddleware
		// (cmd/routes.go), so the page handler can read user from context
		// directly. RequireAuth would write 401 JSON — wrong for a browser
		// GET — so the handler does its own redirect/forbidden rendering.
		router.GET(witnessEnrollPagePath, handlers.WebAuthn.RenderWitnessEnrollPage)
	}
}

// witnessEnrollPagePath is a local copy of the canonical path constant
// from the handlers package. The handlers package exports it as
// `handlers.WitnessEnrollPagePath`; this file uses the local copy
// because the `handlers` identifier is already taken as the function
// parameter name (cmd/routes_admin.go's `registerOAuthRoutes(... handlers
// *Handlers, ...)`). A unit test in cmd/witness_enroll_path_test.go
// asserts the two stay in sync.
const witnessEnrollPagePath = "/auth/webauthn/witness/enroll"

// registerSAMLSPRoutes registers SAML SP (inbound federation) endpoints.
// These endpoints are used when the IAM service acts as a SAML Service Provider,
// allowing tenants to authenticate via external IDPs (Okta, Azure AD, etc.).
func registerSAMLSPRoutes(router *gin.Engine, handlers *Handlers, authMiddleware *middleware.AuthMiddleware) {
	samlSP := router.Group("/saml/sp")
	{
		samlSP.GET("/:tenant_id/:provider_id/metadata", handlers.SAMLSP.GetSPMetadata)
		samlSP.GET("/:tenant_id/:provider_id/login", handlers.SAMLSP.InitiateSSO)
		samlSP.POST("/:tenant_id/acs", handlers.SAMLSP.HandleACSPost)
		samlSP.GET("/:tenant_id/slo", handlers.SAMLSP.HandleSLO)
		samlSP.POST("/:tenant_id/slo", handlers.SAMLSP.HandleSLOPost)

		// SP-initiated SLO: requires authenticated user to initiate logout back to the IDP.
		samlSP.POST("/:tenant_id/:provider_id/slo/initiate", authMiddleware.RequireAuth(), handlers.SAMLSP.InitiateSLOHandler)
	}
}

// registerSAMLRoutes registers SAML IDP endpoints.
func registerSAMLRoutes(router *gin.Engine, handlers *Handlers, authMiddleware *middleware.AuthMiddleware) {
	saml := router.Group("/saml")
	{
		saml.GET("/:tenant_id/metadata", handlers.SAML.GetMetadata)
		saml.GET("/:tenant_id/metadata.json", handlers.SAML.GetMetadataJSON)
		saml.GET("/:tenant_id/sso", authMiddleware.OptionalAuth(), handlers.SAML.HandleSSORedirect)
		saml.POST("/:tenant_id/sso", authMiddleware.OptionalAuth(), handlers.SAML.HandleSSOPost)
		saml.POST("/:tenant_id/sso/complete", authMiddleware.RequireAuth(), handlers.SAML.CompleteSSOFlow)
		saml.GET("/:tenant_id/slo", handlers.SAML.HandleSLO)
	}
}

// registerSCIMRoutes registers SCIM 2.0 API endpoints.
func registerSCIMRoutes(router *gin.Engine, handlers *Handlers, scimAuthMiddleware *middleware.SCIMAuthMiddleware) {
	scim := router.Group("/scim/v2")
	{
		// Discovery endpoints (no auth required)
		scim.GET("/ServiceProviderConfig", handlers.SCIM.GetServiceProviderConfig)
		scim.GET("/Schemas", handlers.SCIM.GetSchemas)
		scim.GET("/ResourceTypes", handlers.SCIM.GetResourceTypes)

		// Protected SCIM endpoints
		scimProtected := scim.Group("")
		scimProtected.Use(scimAuthMiddleware.RequireSCIMAuth())
		{
			// User endpoints
			scimProtected.GET("/Users", handlers.SCIM.ListUsers)
			scimProtected.POST("/Users", handlers.SCIM.CreateUser)
			scimProtected.GET(pathSCIMUsersID, handlers.SCIM.GetUser)
			scimProtected.PUT(pathSCIMUsersID, handlers.SCIM.UpdateUser)
			scimProtected.PATCH(pathSCIMUsersID, handlers.SCIM.PatchUser)
			scimProtected.DELETE(pathSCIMUsersID, handlers.SCIM.DeleteUser)

			// Group endpoints
			scimProtected.GET("/Groups", handlers.SCIM.ListGroups)
			scimProtected.POST("/Groups", handlers.SCIM.CreateGroup)
			scimProtected.GET(pathSCIMGroupsID, handlers.SCIM.GetGroup)
			scimProtected.PUT(pathSCIMGroupsID, handlers.SCIM.UpdateGroup)
			scimProtected.PATCH(pathSCIMGroupsID, handlers.SCIM.PatchGroup)
			scimProtected.DELETE(pathSCIMGroupsID, handlers.SCIM.DeleteGroup)
		}
	}
}
