// SPDX-License-Identifier: AGPL-3.0-or-later

package models

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// TenantHostStatus is the lifecycle state of a registered tenant host.
// Mirrors the CHECK constraint on iam_tenant_hosts.status — keep in sync
// when adding values; the discovery handler maps unknown states to 503.
type TenantHostStatus string

const (
	// TenantHostStatusPendingVerification — admin claimed the host
	// but the TXT challenge has not yet been observed. Discovery
	// handler returns 503 (DNS propagation window).
	TenantHostStatusPendingVerification TenantHostStatus = "pending_verification"
	// TenantHostStatusActive — TXT verified, traffic accepted.
	// Discovery handler returns 200 with full payload.
	TenantHostStatusActive TenantHostStatus = "active"
	// TenantHostStatusSuspended — manually disabled or 14-day
	// re-verification failure. Discovery handler returns 410 Gone
	// so the client can render a differentiated error UX.
	TenantHostStatusSuspended TenantHostStatus = "suspended"
)

// TenantHostVerificationMethod enumerates how a domain proves control.
// `txt` is the default and currently the only fully-implemented path —
// `cname` and `http01` are reserved for future cert-manager integration
// (cf. research summary §8: DNS-based proof is the universal precondition).
type TenantHostVerificationMethod string

const (
	// TenantHostVerificationMethodTXT — TXT record under
	// `_hexxlock-verify.<host>` containing the verification_token.
	// Default.
	TenantHostVerificationMethodTXT TenantHostVerificationMethod = "txt"
	// TenantHostVerificationMethodCNAME — CNAME from <host> to a
	// platform-issued challenge subdomain (Auth0 / Cognito pattern).
	TenantHostVerificationMethodCNAME TenantHostVerificationMethod = "cname"
	// TenantHostVerificationMethodHTTP01 — RFC 8555 HTTP-01 file
	// challenge (Let's Encrypt-compatible). Reserved.
	TenantHostVerificationMethodHTTP01 TenantHostVerificationMethod = "http01"
)

// TenantHost is a single host→tenant binding in the iam_tenant_hosts
// registry. It powers host-based discovery for multi-tenant SaaS app
// custom domains (e.g. crm.acme-corp.com → tenant Acme + canonical_url).
//
// Layered against the existing realm_domains table: realm_domains
// scopes to AUTH-level custom domains (auth.acme-corp.com for the IdP
// itself); TenantHost scopes to APP-level custom domains (crm.acme-
// corp.com for the SaaS app the IdP fronts).
type TenantHost struct {
	ID uuid.UUID `json:"id" db:"id"`
	// Lowercase + IDNA-encoded (xn--…) form per RFC 4343 / RFC 3492.
	// Normalize at the service layer before any read/write.
	Host         string    `json:"host" db:"host"`
	TenantID     uuid.UUID `json:"tenant_id" db:"tenant_id"`
	CanonicalURL string    `json:"canonical_url" db:"canonical_url"`
	// Lifecycle state — see TenantHostStatus constants.
	Status TenantHostStatus `json:"status" db:"status"`
	// 64-char random token written by the customer to TXT
	// `_hexxlock-verify.<host>`. Kept on suspended rows so an admin
	// can re-issue verification without rolling the token.
	VerificationToken  string                       `json:"verification_token" db:"verification_token"`
	VerificationMethod TenantHostVerificationMethod `json:"verification_method" db:"verification_method"`
	// First time TXT proof was observed. Once set + status flipped to
	// active, NEVER cleared on transient re-verification failures
	// (those increment VerificationFailures instead). Cleared only
	// when an admin explicitly re-issues the challenge.
	VerifiedAt *time.Time `json:"verified_at,omitempty" db:"verified_at"`
	// Most recent successful re-verification (daily cron). Same as
	// VerifiedAt on the first success.
	LastVerifiedAt *time.Time `json:"last_verified_at,omitempty" db:"last_verified_at"`
	// Increments on failed re-verification. Reset to 0 on success.
	// Cron suspends the host at 14 (~14 days at daily cadence).
	VerificationFailures int `json:"verification_failures" db:"verification_failures"`
	// Optional OAuth client pin: discovery response exposes this as
	// `default_client_id` so the SDK can skip a separate tenant→
	// client lookup. Nil when the tenant has multiple apps and lets
	// the consumer pick.
	DefaultClientID *string `json:"default_client_id,omitempty" db:"default_client_id"`
	// JSONB override merged on top of the tenant-level branding row.
	// Same shape as iam_tenant_branding.branding for simple deep-merge.
	BrandingOverride json.RawMessage `json:"branding_override,omitempty" db:"branding_override"`
	CreatedAt        time.Time       `json:"created_at" db:"created_at"`
	UpdatedAt        time.Time       `json:"updated_at" db:"updated_at"`
}

// HostDiscoveryResponse is the public-but-internal-only payload served
// by `GET /internal/v1/tenant-discovery?host=<host>`. The Next.js SDK
// middleware calls this from inside the cluster (falcon-id.svc) on
// every inbound request that needs tenant context, with response cached
// in-process for the TTL listed in the service layer.
//
// Schema synthesized from cross-vendor research:
//   - Auth0 Custom Domains
//   - Okta Custom URL Domains
//   - Microsoft Entra B2C custom domains
//   - AWS Cognito custom domains
//   - Cloudflare Access SaaS apps
//
// Industry pattern is to collapse host→tenant resolution into the OIDC
// .well-known endpoint (host-mirrored issuer). We expose this richer
// payload only on the internal-cluster path; the SDK uses it to build
// the OIDC authorize URL + branding without an extra trip to /tenants.
type HostDiscoveryResponse struct {
	TenantID        uuid.UUID        `json:"tenant_id"`
	Host            string           `json:"host"`
	CanonicalURL    string           `json:"canonical_url"`
	Issuer          string           `json:"issuer"`
	Status          TenantHostStatus `json:"status"`
	DefaultClientID *string          `json:"default_client_id,omitempty"`
	Branding        map[string]any   `json:"branding,omitempty"`
	VerifiedAt      *time.Time       `json:"verified_at,omitempty"`
}

// TenantSlugDiscoveryResponse is the payload served by
// `GET /internal/v1/tenant-discovery/by-slug?slug=<slug>` — the
// companion of HostDiscoveryResponse above, but resolving against
// iam_tenants (the tenant slug namespace) rather than iam_tenant_hosts
// (the custom/vanity-host registry).
//
// This exists because iam_tenant_hosts does NOT hold an entry for every
// tenant's `<slug>.<baseDomain>` subdomain — only tenants that went
// through the onboarding "choose your subdomain" step (see
// OnboardingSlugService) get a row there. Existing tenants provisioned
// before that step existed do not, so a subdomain fail-closed check MUST
// resolve against the tenant-slug namespace directly rather than routing
// through host-discovery, or every one of those tenants' subdomains
// would incorrectly 404.
//
// Deliberately minimal — this is an existence + servability check for
// the edge middleware, not a branding/OIDC payload, so it carries none
// of HostDiscoveryResponse's canonical_url/issuer/branding fields.
type TenantSlugDiscoveryResponse struct {
	TrialAccessExpired bool      `json:"trial_access_expired,omitempty"`
	RecoveryOnly       bool      `json:"recovery_only,omitempty"`
	TenantID           uuid.UUID `json:"tenant_id"`
	Slug               string    `json:"slug"`
	Status             string    `json:"status"`
}
