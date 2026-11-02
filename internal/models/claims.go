// SPDX-License-Identifier: AGPL-3.0-or-later

package models

import (
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// Confirmation represents the RFC 7800 cnf (confirmation) claim embedded
// in access tokens to bind them to a sender. Today the platform uses two
// binding mechanisms in parallel — DPoP proof keys (RFC 9449) and SPIFFE
// identities supplied by the Linkerd service mesh — and both surface
// through this struct.
type Confirmation struct {
	// JKT is the JWK SHA-256 thumbprint (RFC 7638) of the DPoP proof key.
	// The value is base64url-encoded without padding and MUST match the
	// thumbprint derived from the DPoP proof header on every resource request.
	// Omitted when the token was not DPoP-bound (legacy bearer flow).
	JKT string `json:"jkt,omitempty"`

	// Spiffe is the SPIFFE URI (RFC 7800-style custom binding) of the
	// service that initiated the token-exchange. Populated only on tokens
	// issued via the RFC 8693 :jwt grant (IAP→BFF bridge), where the
	// Falcon-ID token endpoint extracts the requesting BFF's identity from
	// the Linkerd-set `l5d-client-id` HTTP header. Receivers MUST compare
	// this value against the incoming `l5d-client-id` header to detect
	// token replay from a workload other than the one the token was issued
	// to. Format: `spiffe://<trust-domain>/ns/<ns>/sa/<sa>`.
	//
	// Omitted on every non-token-exchange path (preserves backward compat
	// for client_credentials and authorization_code flows).
	Spiffe string `json:"spiffe,omitempty"`
}

// Token version constants for backward compatibility and migration
const (
	// TokenVersionLegacy (v0) includes full permissions array in the JWT (~4-6KB tokens)
	// This format is deprecated but still supported for existing tokens
	TokenVersionLegacy = 0

	// TokenVersionMinimal (v1) stores only essential claims in JWT (~400 bytes)
	// Full user context (permissions, username, email) is resolved from Redis session store
	// This is the new default format that dramatically reduces token size
	TokenVersionMinimal = 1

	// TokenVersionSpiceDB (v2) is the ultra-minimal token format (~500 bytes)
	// Contains only: sub (user_id), tid (tenant_id), sid (session_id), rid (realm_id)
	// No roles or permissions stored - ALL authorization resolved via SpiceDB at check time
	// Benefits:
	//   - Smallest possible token size
	//   - Real-time permission changes (no token refresh needed)
	//   - True Relationship-Based Access Control (ReBAC) support
	//   - User X can edit document Y (resource-level permissions)
	TokenVersionSpiceDB = 2
)

// MinimalClaims represents a lightweight JWT token format that stores only essential
// information needed for authentication and authorization. The full user context
// (permissions, profile info) is stored in Redis and retrieved using the session ID.
//
// Token Size Comparison:
//   - Legacy format (v0): 4-6KB with 100+ permissions
//   - Minimal format (v1): ~400 bytes (90%+ reduction)
//
// Benefits:
//   - Reduced network overhead
//   - Faster token validation
//   - Real-time permission updates (no token refresh needed)
//   - Better security (less data exposed in token)
//   - Support for token revocation via session blacklist
type MinimalClaims struct {
	jwt.RegisteredClaims

	// SessionID is the primary key for Redis session lookup
	// Format: hexxlock:session:{sid}
	// This allows us to:
	// - Resolve full user permissions on demand
	// - Revoke tokens by blacklisting session
	// - Update permissions without token refresh
	SessionID uuid.UUID `json:"sid"`

	// TenantID provides the current tenant context using the abbreviated claim name.
	// Required for multi-tenant data isolation.
	// Both "tid" (abbreviated) and "tenant_id" (verbose) are emitted for compatibility:
	// internal validators accept either form; external consumers (APISIX, third-party
	// relying parties) may look for the verbose name.
	TenantID uuid.UUID `json:"tid"`

	// TenantIDVerbose is the same value as TenantID emitted under the "tenant_id" key.
	// Kept in sync with TenantID at construction time so that consumers that inspect
	// the raw JWT payload and expect the "tenant_id" claim find a non-null value.
	TenantIDVerbose uuid.UUID `json:"tenant_id"`

	// RealmID provides the current realm context
	// Required for multi-realm architecture (platform/enterprise/shared/partner/sandbox)
	RealmID uuid.UUID `json:"rid"`

	// Roles contains high-level role names (e.g., "admin", "user", "manager")
	// Permissions are derived from roles and stored in Redis session
	// We keep roles in the token for quick role-based checks without Redis lookup
	Roles []string `json:"roles"`

	// Act is the RFC 8693 actor (set only on impersonation tokens: the operator
	// acting as the subject). ImpersonatorID / ImpersonationSessionID repeat it
	// under the legacy claim names so receivers can banner an impersonated session.
	Act                    *TokenActor `json:"act,omitempty"`
	ImpersonatorID         string      `json:"impersonator_id,omitempty"`
	ImpersonationSessionID string      `json:"impersonation_session_id,omitempty"`

	// Scope defines the authorization scope ("tenant" or "platform")
	// - "tenant": Normal tenant users with tenant-scoped permissions
	// - "platform": Platform administrators with cross-tenant access
	Scope string `json:"scp"`

	// AppRoles contains the application-specific role assignments (e.g., "ExampleSuite.Admin").
	// These are distinct from realm-level roles and are scoped to a specific application.
	// Included only when the token is issued in an app-role context (client-credentials flow
	// or when the user has roles assigned on the corresponding service principal).
	// Omitted when empty to keep the token compact.
	AppRoles []string `json:"app_roles,omitempty"`

	// ProductSubscriptions lists the active product subscriptions for the tenant.
	// Services can check this to verify product access without round-trips to falcon-id.
	// Each entry contains: pid (product ID), slug (product slug), plan (optional plan ID).
	// Omitted when empty to keep the token compact.
	ProductSubscriptions []ProductSubscriptionClaim `json:"products,omitempty"`

	// Version indicates the token format version for backward compatibility
	// - 0: Legacy format with permissions array
	// - 1: Minimal format with Redis session lookup
	Version int `json:"v"`

	// Confirmation carries the DPoP key binding (RFC 9449 §6).
	// When non-nil the token is DPoP-bound and resource servers MUST verify
	// that the incoming DPoP proof is signed with the key whose thumbprint
	// matches Confirmation.JKT.
	// Omitted when nil to keep regular bearer tokens compact.
	Confirmation *Confirmation `json:"cnf,omitempty"`

	// AuthTime is the Unix timestamp of the original authentication event
	// for the session — RFC 9470 §6.1 / OIDC Core §2 `auth_time`. Stable
	// across refresh-token rotations so resource servers gating on
	// freshness (RequireFreshAuth middleware → password change, MFA
	// disable, session revoke) measure elapsed time since the user
	// actually authenticated, not since the most recent token rotation.
	// Omitted when unknown (zero) — RequireFreshAuth fails closed in
	// that case.
	AuthTime int64 `json:"auth_time,omitempty"`
}

// ProductSubscriptionClaim represents a product subscription in JWT tokens.
type ProductSubscriptionClaim struct {
	ProductID   uuid.UUID `json:"pid"`
	ProductSlug string    `json:"slug"`
	PlanID      *string   `json:"plan,omitempty"`

	// State mirrors the row's ProvisioningState, collapsed to one of three
	// values the falcon-id-client Next.js product gate understands:
	//   - "" (omitted)  — active. The zero value, so every token minted
	//     before this field existed (and every already-active subscription)
	//     still reads as fully entitled with no gate behavior change.
	//   - "provisioning" — a row exists but hasn't reached 'active' yet
	//     (pending/creating/migrating/seeding/configuring_auth/
	//     registering_service). The gate treats this as "entitled, not
	//     ready yet" and routes to the provisioning interstitial instead
	//     of the hard 403 — see ProductSubscriptionResolver.Resolve and
	//     falcon-id-client's middleware.ts product-entitlement gate.
	//   - "failed" — provisioning hit a terminal failure. The gate still
	//     routes to the interstitial, which is responsible for showing the
	//     failure message + support contact (never a bare 403 for a paying
	//     customer whose provisioning broke).
	// A row in 'deleting'/'deleted' state (cancelled) is deliberately
	// excluded upstream by the resolver, so it never appears here at all —
	// it looks identical to "no subscription", which is correct: the gate
	// must give a cancelled subscription the same hard 403 as one that
	// never existed, not a "setting up your workspace" interstitial.
	State string `json:"state,omitempty"`
}

// SpiceDBClaims represents the ultra-minimal JWT token format for SpiceDB-based authorization.
// This is the smallest possible token format - all authorization is resolved via SpiceDB.
//
// Token Size: ~500 bytes (compared to 4-6KB for legacy, ~400 bytes for minimal)
//
// Key differences from MinimalClaims (v1):
//   - No Roles field (roles resolved from SpiceDB)
//   - No Scope field (permissions are all relationship-based)
//   - Authorization is 100% SpiceDB-backed
//
// Benefits:
//   - Real-time permission updates (change role -> immediately effective)
//   - Fine-grained resource-level permissions (user X can edit document Y)
//   - No permission data in Redis (reduced storage, simpler invalidation)
type SpiceDBClaims struct {
	jwt.RegisteredClaims

	// SessionID for session management (logout, activity tracking)
	// Note: This is NOT used for permission resolution - SpiceDB handles that
	SessionID uuid.UUID `json:"sid"`

	// TenantID for multi-tenant data isolation.
	// Both "tid" (abbreviated) and "tenant_id" (verbose) are emitted — see
	// MinimalClaims.TenantIDVerbose for the rationale.
	TenantID uuid.UUID `json:"tid"`

	// TenantIDVerbose mirrors TenantID under the "tenant_id" key for consumers
	// that expect the verbose claim name in the raw JWT payload.
	TenantIDVerbose uuid.UUID `json:"tenant_id"`

	// RealmID for multi-realm architecture
	RealmID uuid.UUID `json:"rid"`

	// Roles contains high-level role names (e.g., "admin", "platform_admin")
	// Included in v2 tokens because roles are small (2-5 strings), rarely change,
	// and are needed by role-based middleware guards across all services.
	// Permissions are still resolved via SpiceDB at check time.
	Roles []string `json:"roles,omitempty"`

	// ProductSubscriptions lists the tenant's active product subscriptions,
	// exactly like MinimalClaims.ProductSubscriptions. Services (and the
	// falcon-id-client Next.js middleware's product gate) check this array
	// to verify product access without a round trip to falcon-id.
	//
	// This field was MISSING from the v2 (SpiceDB) claims struct from the
	// day the format was introduced: GenerateAccessTokenV2 never called
	// productSubscriptionResolver at all, so every v2 token — 100% of
	// native logins per SPICEDB_TOKEN_V2_PERCENTAGE — omitted the
	// products claim regardless of entitlement state. Any tenant whose
	// user was on the v2 rollout was permanently redirected to
	// /unauthorized?reason=product_not_entitled, with no path to recover
	// short of forcing a v1 token. Root-caused 2026-09-11 via a self-
	// service AcmeWeb signup that had an ACTIVE iam_product_instances row
	// but still 403'd — see GenerateAccessTokenV2's resolver call and
	// signup_post_provisioner.go's HandleSubscriptionActivatedSync for
	// the accompanying fix to the mint-before-provisioning race.
	// Omitted when empty to keep the token compact.
	ProductSubscriptions []ProductSubscriptionClaim `json:"products,omitempty"`

	// Version indicates v2 (SpiceDB) token format
	Version int `json:"v"`

	// Confirmation carries the DPoP key binding (RFC 9449 §6).
	// Omitted when nil to keep regular bearer tokens compact.
	Confirmation *Confirmation `json:"cnf,omitempty"`

	// AuthTime is the Unix timestamp of the original authentication
	// event for this session — RFC 9470 §6.1 / OIDC Core §2 `auth_time`.
	// Same semantics as MinimalClaims.AuthTime / Claims.AuthTime: powers
	// downstream RequireFreshAuth gates + /oauth/authorize max_age
	// enforcement. Omitted-when-zero to stay compact for backward-
	// compatible consumers that don't read the claim.
	//
	// Adding this field on the v2 SpiceDB token format is load-bearing:
	// the canonical mint path GenerateAccessTokenV2 previously had no
	// place to surface auth_time even when fillAuthTimeFromSession
	// resolved a value, so every v2 token was minted without the claim
	// → CurrentUser.AuthTime==0 on every request → every RFC 9470
	// max_age=N gate fired infinite-loop bounces immediately after the
	// user re-authenticated. Live repro 2026-05-25: dogukanturhal
	// passkey login on iOS Safari completed /webauthn/conditional/
	// complete successfully + minted fresh v2 JWT, but the very next
	// /oauth/authorize bounced back to /oauth/login on its max_age=300
	// check because the fresh JWT carried no auth_time.
	AuthTime int64 `json:"auth_time,omitempty"`
}

// SessionData represents the full user context stored in Redis
// This data is retrieved using the session ID from the JWT token
//
// Redis Key Format: hexxlock:session:{sessionID}
// TTL: Matches access token expiry + grace period for token refresh
type SessionData struct {
	// User identification
	UserID   uuid.UUID `json:"user_id"`
	TenantID uuid.UUID `json:"tenant_id"`
	Username string    `json:"username"`
	Email    string    `json:"email"`

	// Authorization context
	Roles       []string `json:"roles"`
	Permissions []string `json:"permissions"` // Full permissions list (100+ items)

	// Realm context for multi-realm architecture
	RealmID   uuid.UUID `json:"realm_id"`
	RealmSlug string    `json:"realm_slug,omitempty"`
	RealmType string    `json:"realm_type,omitempty"`

	// RoleVersion is used for cache invalidation
	// When roles/permissions change, this version is incremented
	// Services can detect stale sessions and force re-authentication
	RoleVersion int64 `json:"role_version"`

	// Session metadata for security and auditing
	DeviceInfo string `json:"device_info,omitempty"`
	IPAddress  string `json:"ip_address,omitempty"`
	CreatedAt  int64  `json:"created_at"` // Unix timestamp

	// Impersonation context (optional)
	ImpersonatorID         *uuid.UUID `json:"impersonator_id,omitempty"`
	ImpersonationSessionID *uuid.UUID `json:"impersonation_session_id,omitempty"`
}

// IsImpersonated returns true if this session represents an impersonated user
func (s *SessionData) IsImpersonated() bool {
	return s.ImpersonatorID != nil
}
