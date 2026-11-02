// SPDX-License-Identifier: AGPL-3.0-or-later

package middleware

import (
	"net/http"
	"os"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

const (
	// TenantIDKey is an exported identifier.
	TenantIDKey = "tenant_id"
)

// publicEndpoints lists endpoints that don't require X-Tenant-ID
// header context. The name predates the addition of service-to-service
// API surfaces — entries cover (a) public OIDC discovery + auth flows
// and (b) machine-to-machine endpoints whose tenant context is sourced
// from the JWT's tenant_id claim by route-level middleware (e.g. the
// /api/v1/internal/oauth-clients group's BridgeServiceTenantToTenantID).
//
// Adding a new prefix here means: "ExtractTenant() will not abort the
// request even though the path matches /api/* — the route group is
// expected to source tenant context from a downstream middleware".
var publicEndpoints = []string{
	// Scoped ServiceAuth endpoints derive tenant from the body and enforce act-as.
	"/api/v1/authorization/lookup-subjects",
	"/api/v1/authorization/check-batch",
	"/health",
	"/ready",
	"/metrics",
	"/.well-known/",
	"/oauth/",
	"/api/auth/",
	"/api/v1/auth/",
	// Identity-anchored self-service surface at /api/v1/users/me/* —
	// per-user preferences (gender/birthday/language/timezone), recovery
	// methods, onboarding state. Exactly like the /api/v1/auth/ entry
	// above: these are browser-tier endpoints whose tenant context is
	// sourced from the session JWT's tenant_id claim by
	// authMiddleware.RequireAuth() at the route-group level. The handlers
	// act on `users.me` (user_id from the JWT) and never read an
	// X-Tenant-ID header. Without this exemption, every preferences
	// read/write from the accounts portal fails in production with
	// `400 Tenant context required`, because the portal BFF forwards the
	// session JWT — not a tenant header. The `/me/` segment keeps the
	// admin /users/:id surface out of scope (it still requires tenant).
	"/api/v1/users/me/",
	"/api/users/me/",
	// Service-to-service OAuth-client management. Tenant context comes
	// from the service JWT's tenant_id claim, bridged into TenantIDKey
	// by middleware.BridgeServiceTenantToTenantID() at the route group
	// level (see cmd/routes_admin.go). The browser-tier admin surface
	// at /api/v1/admin/oauth-clients/* is unaffected and continues to
	// require X-Tenant-ID per the existing flow.
	"/api/v1/internal/oauth-clients",
	// Service-to-service RFC 8693 trusted-external-issuer registry +
	// per-client grant management. Same tenant-context model as
	// /api/v1/internal/oauth-clients above — BridgeServiceTenantToTenantID
	// at the route-group level sources tenant from the s2s JWT's
	// tenant_id claim, so the upstream ExtractTenant pass MUST allow
	// the request through without an X-Tenant-ID header. The
	// Crossplane serviceclient-provisioner Job authenticates straight
	// to the IAM Service with no API gateway in front of it.
	//
	// Per-client grant subpaths (/api/v1/internal/oauth-clients/:id/
	// trusted-external-issuers) are already covered by the
	// oauth-clients prefix above; this entry covers the top-level
	// issuer-registry routes (GET ?name=… lookup, etc.).
	"/api/v1/internal/oauth-trusted-external-issuers",
	// Service-to-service module-permission registration. The permission
	// catalog (module × resource × action) is a GLOBAL definition, not
	// a tenant-scoped artefact — tenants get role bindings to these
	// permissions later via separate tenant-scoped endpoints. Service
	// identity here is established by serviceAuthMiddleware.ServiceAuth()
	// via OAuth2 client_credentials Bearer JWT; tenant context is
	// neither needed nor meaningful for the register call.
	//
	// Without this exemption, every Hexxlock.Shared.ReBAC.Registration
	// .PermissionRegistrationService.StartAsync call from a downstream
	// service (business, marketing-automation, integration-bus, …)
	// fails with `400 Tenant context required` and zero permissions
	// land in iam_permissions for those modules.
	"/internal/permissions",
	// Module permission-catalogue self-registration on the route services
	// actually call: platform-shared permissions.Client posts to
	// /internal/v1/permissions/register (the bare /internal/permissions path
	// above is the legacy alias). Same GLOBAL-artefact model: the handler
	// registers platform-level module metadata and reads no tenant context,
	// and the route group is gated by ServiceAuth(). Services pinned to a
	// platform-shared release that predates the client sending X-Tenant-ID
	// otherwise fail at startup with `400 Tenant context required`.
	// Exact route only (no trailing slash): /internal/v1/permissions/<other>
	// would stay tenant-required.
	"/internal/v1/permissions/register",
	// Service-to-service ZTNA device-enrollment registry
	// (POST /internal/v1/iam-devices/enroll, GET .../by-ek-hash/:hash).
	// Same GLOBAL-artefact model as /internal/permissions above: iam_devices
	// is a global device registry keyed by device_uuid / ek_pubkey_hash (the
	// EK hash is a globally-unique hardware key) — the table has NO tenant_id
	// column and the handlers derive no tenant context; the owning user is
	// recorded via user_sub. Service identity is established by
	// serviceAuthMiddleware.ServiceAuth() (OAuth2 client_credentials Bearer
	// from the jess controller). Tenant context is neither needed nor
	// meaningful. Without this exemption every ZTNA device-cert attestation
	// fails at the jess→falcon-id lookup with `400 Tenant context required`.
	"/internal/v1/iam-devices/",
	// Service-to-service host→tenant discovery. The @hexxlock/falcon-id-client
	// SDK middleware calls GET /internal/v1/tenant-discovery?host=<host> from
	// inside the cluster to RESOLVE the tenant FROM the inbound host (custom /
	// vanity domains like webmail.<corp>.com). It has no tenant context yet —
	// that is precisely what it is looking up — and sends only the ServiceAuth
	// Bearer, never an X-Tenant-ID header. Requiring tenant context here is
	// circular and 400s every custom-domain resolution; the handler derives
	// everything from the ?host= query param and ServiceAuth gates the caller.
	// Latent until the first ACTIVE tenant host was resolved (webmail.example.com,
	// 2026-06-26) — every prior call fail-opened to the canonical host.
	"/internal/v1/tenant-discovery",
	// Service-to-service tenant-admin surface (GET .../users/count,
	// .../connection-info, .../smtp-config). Same model as
	// /internal/v1/iam-devices/ and /internal/v1/tenant-discovery above:
	// every handler in this ServiceAuth()-gated route group derives the
	// subject tenant strictly from the :id path parameter, never from
	// TenantIDKey/GetTenantID(c) — confirmed via `git grep TenantIDKey`
	// across internal/handlers/tenant_handler.go. The blanket X-Tenant-ID
	// gate here is redundant with, and orthogonal to, the actual
	// authorization (serviceAuthMiddleware.ServiceAuth()'s JWT
	// validation); it does not re-open header-trust authorization, it
	// only stops this global gate from rejecting well-authenticated
	// S2S calls before ServiceAuth() ever runs.
	//
	// Without this exemption every caller of
	// GET /internal/v1/tenants/:id/users/count (e.g. tenant-management's
	// ReapOrphanTenants reconciler, first exercised 2026-09-27) 400s with
	// `Tenant context required` regardless of Authorization header,
	// because ExtractTenant() runs before ServiceAuth() in cmd/routes.go
	// and this prefix was missing from publicEndpoints when the route
	// group was added (feat/seat-quota-enforcement).
	"/internal/v1/tenants/",
	// Role-template revoke (S2S): tenant comes from the ServiceAuth +
	// RequireScope-gated request body, never from X-Tenant-ID.
	"/internal/v1/role-templates/",

	// ADR-A10 delegated-admin guard action endpoint (POST
	// /internal/v1/roles/:id/actions/grant-permission). Same model as
	// /internal/v1/tenants/ above: ServiceAuth()-gated, and the handler
	// derives the tenant from the target role's own TenantID (looked up
	// server-side by :id), never from X-Tenant-ID. Without this exemption
	// every grant-permission call from a caller that only sends a
	// ServiceAuth Bearer (no X-Tenant-ID of its own to send) 400s with
	// `Tenant context required` before ServiceAuth() ever runs.
	"/internal/v1/roles/",

	// Internal SoD evaluation (POST /internal/v1/sod/evaluate).
	// ServiceAuth()-gated; the tenant being evaluated is named explicitly
	// in the request body (it evaluates a specific user's assignments,
	// which may not match the caller's own tenant context at all for a
	// platform-side scheduled job), not derived from X-Tenant-ID.
	"/internal/v1/sod/",
	// R1 platform plane: JIT elevation + break-glass. These routes are
	// gated by serviceAuthMiddleware.ServiceAuth() + RequireScope() (the
	// acmeweb BFF's S2S credential) PLUS authMiddleware.RequireActorAuth()
	// (the human operator's own session access token, forwarded in
	// X-Actor-Assertion — see internal/middleware/actor_auth.go). Neither
	// of those derives anything from TenantIDKey/GetTenantID(c): the
	// subject is always the Platform-internal tenant
	// (00000000-0000-0000-0000-000000000002), enforced by
	// RequirePlatformInternalActor() reading the validated actor JWT's own
	// tenant_id claim, never an X-Tenant-ID header. Same model as
	// /internal/v1/tenants/ above.
	//
	// Deliberately WITHOUT a trailing slash (unlike /internal/v1/tenants/
	// above, which keeps one to exclude its own bare list endpoint): the
	// bare create paths (POST /internal/v1/jit-elevations,
	// POST /internal/v1/break-glass, POST/GET /internal/v1/platform-roles,
	// registered via .POST("", ...) / .GET("", ...) in
	// cmd/routes_admin.go) have no trailing slash themselves, so a
	// trailing-slash prefix here would fail to match them via
	// strings.HasPrefix and 400 "Tenant context required" in
	// production/staging despite being fully authenticated by the
	// platformJITAuth chain. Every sub-path in all three route groups
	// shares that identical auth chain and none reads
	// TenantIDKey/GetTenantID(c), so widening the match to the bare path
	// is safe.
	"/internal/v1/jit-elevations",
	"/internal/v1/break-glass",
	"/internal/v1/platform-roles",
	// Staff console operator chain (/internal/v1/ops/* and
	// /internal/v1/ops-approvals/*): ServiceAuth + RequireScope + operatorauth
	// authenticate the calling service and the human operator; tenant context
	// is never taken from X-Tenant-ID (the actor is the internal tenant, the
	// subject tenant comes from the target user / path / query).
	"/internal/v1/ops",
}

// tenantRequiredPrefixes are the ONLY paths that require tenant context.
// Everything else (OIDC, health, root, static, SAML) is public.
var tenantRequiredPrefixes = []string{
	"/api/",
	"/internal/",
}

// isPublicEndpoint checks if the path is a public endpoint that doesn't need tenant context.
// Inverted logic: only /api/* paths require tenant; all others are public.
func isPublicEndpoint(path string) bool {
	for _, prefix := range publicEndpoints {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}
	for _, prefix := range tenantRequiredPrefixes {
		if strings.HasPrefix(path, prefix) {
			return false
		}
	}
	return true
}

// ExtractTenant middleware that extracts tenant ID from header or subdomain.
// SECURITY: In production/staging, tenant context is required for most endpoints.
// No default tenant fallback to prevent cross-tenant access.
func ExtractTenant() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Try to get tenant ID from header first
		tenantIDStr := c.GetHeader("X-Tenant-ID")

		if tenantIDStr == "" {
			env := os.Getenv("ENVIRONMENT")
			isProduction := env == envProductionName || env == envStagingName

			// SECURITY: In production, require explicit tenant context for most endpoints
			if isProduction && !isPublicEndpoint(c.Request.URL.Path) {
				c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
					"error":   "Tenant context required",
					"message": "X-Tenant-ID header is required. Configure your API gateway to set this header from subdomain.",
				})
				return
			}

			// Development only: allow requests without tenant context to proceed
			// The endpoint handlers must handle missing tenant context appropriately
			c.Next()
			return
		}

		tenantID, err := uuid.Parse(tenantIDStr)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "Invalid tenant ID format"})
			return
		}

		c.Set(TenantIDKey, tenantID)
		c.Next()
	}
}

// RequireTenant middleware that requires tenant context
func RequireTenant() gin.HandlerFunc {
	return func(c *gin.Context) {
		tenantVal, exists := c.Get(TenantIDKey)
		if !exists {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "Tenant context required"})
			return
		}

		_, ok := tenantVal.(uuid.UUID)
		if !ok {
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Invalid tenant context"})
			return
		}

		c.Next()
	}
}

// GetTenantID extracts tenant ID from context
func GetTenantID(c *gin.Context) uuid.UUID {
	tenantVal, exists := c.Get(TenantIDKey)
	if !exists {
		return uuid.Nil
	}

	tenantID, ok := tenantVal.(uuid.UUID)
	if !ok {
		return uuid.Nil
	}

	return tenantID
}
