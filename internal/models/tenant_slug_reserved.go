// SPDX-License-Identifier: AGPL-3.0-or-later

package models

import (
	"strings"
)

// ReservedTenantSlugs — slugs that MUST NOT be assignable to customer
// tenants. The list mixes three categories:
//
//  1. Brand reservation: hexxlock and trivial variants. Squatting our
//     own brand prevents customer onboarding from claiming the slug
//     and impersonating the platform.
//
//  2. Operator/internal namespaces: any slug that overlaps with
//     reserved subdomain conventions (admin, api, www, mail, support,
//     login, oauth, sso, …). These are functional path/subdomain
//     identifiers across the platform — letting a tenant claim them
//     would create routing ambiguity.
//
//  3. Tenant-enumeration mitigation: the public registration endpoint
//     returns a generic "slug unavailable" 4xx for both reserved and
//     already-taken slugs (no leak about which path triggered the
//     rejection). This blocks the slug-tenant-enumeration class
//     documented in Push Security's SaaS-attacks catalog
//     (techniques/slug_tenant_enumeration).
//
// The set is intentionally small + closed; expansion is an admin-MR,
// never runtime-configurable. New entries should map to either
// brand-reserve or operator-namespace, not "vague hunch".
//
// Authoritative references:
//   - Push Security SaaS-attacks: slug_tenant_enumeration/description.md
//   - WorkOS Organizations API — domain verification + slug uniqueness
//   - Microsoft Entra ID — verified-domain binding (separate from slug)
//   - Auth0 Organizations — name vs domain decoupling
var ReservedTenantSlugs = map[string]struct{}{
	// Brand reservation
	"hexxlock":  {},
	"hexx":      {},
	"example":   {},
	"falcon":    {},
	"falconid":  {},
	"falcon-id": {},

	// Platform operator namespaces (subdomain conventions)
	"admin":          {},
	"administrator":  {},
	"api":            {},
	"app":            {},
	"apps":           {},
	"auth":           {},
	"billing":        {},
	"console":        {},
	"dashboard":      {},
	"docs":           {},
	"ftp":            {},
	"help":           {},
	"login":          {},
	"logout":         {},
	"mail":           {},
	"oauth":          {},
	"oidc":           {},
	"ops":            {},
	"platform":       {},
	"platform-admin": {},
	"public":         {},
	"register":       {},
	"root":           {},
	"saml":           {},
	"signup":         {},
	"sso":            {},
	"status":         {},
	"support":        {},
	"system":         {},
	"webhook":        {},
	"webhooks":       {},
	"www":            {},

	// Common reserved technical names
	"default":   {},
	"global":    {},
	"internal":  {},
	"local":     {},
	"localhost": {},
	"master":    {},
	"null":      {},
	"shared":    {},
	"test":      {},
	"undefined": {},

	// Brand reservation — product names. hexxlock/falcon were already here;
	// these are the ones the estate gained since (acmeweb, and acmeapp as its
	// apex from the 2026-08 rename). A tenant serving its own content from
	// acmeweb.<apex> reads as the vendor speaking.
	"acmeweb":  {},
	"acmeapp": {},
	"talon":   {},

	// Identity and auth namespace. `id` is the sharpest entry in this file:
	// the production IdP is id.example.com, so a tenant holding `id` collides
	// with the identity provider's own hostname if auth ever moves apex.
	// login/logout/signup/auth/oauth/sso were already reserved; these are the
	// synonyms and adjacent identity nouns that were not.
	"id":       {},
	"signin":   {},
	"accounts": {},
	"account":  {},
	"secure":   {},
	"verify":   {},
	"session":  {},
	"token":    {},

	// Operator namespaces — hostnames the platform actually runs today, so a
	// tenant claiming one creates routing ambiguity as well as impersonation.
	"cdn":      {},
	"storage":  {},
	"static":   {},
	"assets":   {},
	"gateway":  {},
	"gw":       {},
	"vault":    {},
	"registry": {},
	"grafana":  {},
	"metrics":  {},
	"monitor":  {},
	"noc":      {},

	// Role accounts (RFC 2142 + the CA/Browser Forum email-validation set).
	// Reserved as operator namespaces: they are role names no customer needs
	// and every one reads as official. NOTE the rationale that does NOT apply
	// here, so it is not re-derived wrongly later — these are sometimes called
	// a certificate-issuance risk, but CA email validation uses mailboxes at
	// the APEX (webmaster@<apex>), and a tenant holding webmaster.<apex> as a
	// SUBDOMAIN gets no mailbox at the parent. The reason is impersonation.
	"webmaster":    {},
	"hostmaster":   {},
	"postmaster":   {},
	"sysadmin":     {},
	"ssladmin":     {},
	"sslwebmaster": {},
	"abuse":        {},
	"security":     {},

	// Financial paths, where a convincing hostname converts into fraud.
	// `billing` was already reserved; its synonyms were not.
	"pay":      {},
	"payment":  {},
	"payments": {},
	"checkout": {},
	"invoice":  {},
	"invoices": {},

	// track.<apex> is the click-tracking host (see apps/acmeweb's
	// apex-domains config) — a tenant slug must never collide with it,
	// since the tracking host is untrusted and reads any cookie scoped
	// to the apex.
	"track": {},
}

// IsReservedSlug reports whether the given slug is reserved and MUST NOT
// be assigned to a customer tenant. Comparison is lower-case to match
// canonical slug normalisation; callers should still trim whitespace
// and reject non-canonical forms via IsValidSlug separately.
func IsReservedSlug(slug string) bool {
	_, reserved := ReservedTenantSlugs[strings.ToLower(strings.TrimSpace(slug))]
	return reserved
}

// IsValidSlug enforces the canonical tenant-slug shape:
//
//   - 3..63 chars (matches RFC 1035 label length cap)
//   - lowercase ASCII letters, digits, hyphen
//   - cannot start/end with hyphen
//   - no consecutive hyphens (avoids xn-- punycode collision space)
//
// Reserved-list check is a separate concern — call IsReservedSlug
// after this returns true.
func IsValidSlug(slug string) bool {
	if len(slug) < 3 || len(slug) > 63 {
		return false
	}
	if slug[0] == '-' || slug[len(slug)-1] == '-' {
		return false
	}
	prevHyphen := false
	for _, r := range slug {
		switch {
		case r >= 'a' && r <= 'z':
			prevHyphen = false
		case r >= '0' && r <= '9':
			prevHyphen = false
		case r == '-':
			if prevHyphen {
				return false
			}
			prevHyphen = true
		default:
			// Anything outside [a-z0-9-] is rejected. This explicitly
			// excludes uppercase letters (slugs are lowercase by
			// convention) AND any non-ASCII rune to prevent IDN
			// homograph attacks at the slug layer.
			return false
		}
	}
	return true
}
