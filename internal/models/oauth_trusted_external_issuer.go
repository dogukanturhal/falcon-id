// SPDX-License-Identifier: AGPL-3.0-or-later

package models

import (
	"time"

	"github.com/google/uuid"
)

// OAuthTrustedExternalIssuer is a per-tenant registry entry of an
// external OIDC/JWT issuer that Falcon-ID's /oauth/token RFC 8693
// token-exchange endpoint will accept as a `subject_token` source
// when subject_token_type = `urn:ietf:params:oauth:token-type:jwt`.
//
// Distinct from WorkloadIdentityProvider (which targets SPIFFE /
// k8s / cloud workload-identity federation and issues service
// tokens): this table targets HUMAN delegation — the Identity-Aware
// Proxy (Talon) authenticated a user via OIDC and forwards a
// short-lived signed JWT to the BFF; the BFF exchanges it here for
// a user-bound access_token + refresh_token, exactly the way
// Microsoft Entra OBO / Keycloak 26.2 standard token-exchange /
// Auth0 / Duende BFF / Curity Token Handler ship.
//
// Trust is gated at TWO levels for least-privilege:
//
//  1. OAuthClient.AllowExternalJWTExchange (top-level cheap gate).
//  2. iam_oauth_client_trusted_external_issuers join — the calling
//     client must have a row pointing at THIS issuer for the
//     exchange to be permitted.
//
// AudienceMatch (cluster-wide) bounds which JWT `aud` values are
// honoured for THIS issuer at all; per-client narrowing lives in
// the join-table's per-row Audiences override.
type OAuthTrustedExternalIssuer struct {
	ID        uuid.UUID `json:"id"         db:"id"`
	TenantID  uuid.UUID `json:"tenant_id"  db:"tenant_id"`
	Name      string    `json:"name"       db:"name"`
	IssuerURL string    `json:"issuer_url" db:"issuer_url"`
	JWKSURL   string    `json:"jwks_url"   db:"jwks_url"`
	// Audiences is the list of `aud` claim values accepted for this
	// issuer at the issuer level. Empty list = aud-claim ignored
	// (caller-supplied audience still applies). Non-empty = JWT must
	// carry at least one matching entry.
	Audiences []string `json:"audiences" db:"audiences"`
	// MaxTokenAgeSeconds is a defense-in-depth ceiling on `exp - iat`
	// of accepted JWTs. Talon's IAP tokens are 60s but we cap the
	// configurable max at 1h via the schema-level CHECK constraint
	// (Migration 237) — 0 < x ≤ 3600.
	MaxTokenAgeSeconds int        `json:"max_token_age_seconds" db:"max_token_age_seconds"`
	IsActive           bool       `json:"is_active"             db:"is_active"`
	Description        *string    `json:"description,omitempty" db:"description"`
	CreatedAt          time.Time  `json:"created_at"            db:"created_at"`
	UpdatedAt          time.Time  `json:"updated_at"            db:"updated_at"`
	CreatedBy          *uuid.UUID `json:"created_by,omitempty"  db:"created_by"`
	UpdatedBy          *uuid.UUID `json:"updated_by,omitempty"  db:"updated_by"`
}

// OAuthClientTrustedExternalIssuer is the many-to-many row that
// authorises one specific OAuthClient to exchange JWTs from one
// specific external issuer. Row existence is the trust grant; row
// absence denies. Per-client Audiences (optional) narrows the
// issuer's cluster-wide Audiences further — when set, the JWT must
// carry an `aud` matching this narrowed list AND the issuer's list
// (intersection semantics).
type OAuthClientTrustedExternalIssuer struct {
	ClientID  uuid.UUID  `json:"client_id"            db:"client_id"`
	IssuerID  uuid.UUID  `json:"issuer_id"            db:"issuer_id"`
	Audiences []string   `json:"audiences,omitempty"  db:"audiences"`
	CreatedAt time.Time  `json:"created_at"           db:"created_at"`
	CreatedBy *uuid.UUID `json:"created_by,omitempty" db:"created_by"`
}
