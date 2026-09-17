// SPDX-License-Identifier: AGPL-3.0-or-later

package models

import (
	"fmt"
	"time"

	"github.com/google/uuid"
)

// OAuthClient represents an OAuth 2.0 client application
type OAuthClient struct {
	ID       uuid.UUID `json:"id" db:"id"`
	TenantID uuid.UUID `json:"tenant_id" db:"tenant_id"`

	ClientID     string `json:"client_id" db:"client_id"`
	ClientSecret string `json:"-" db:"client_secret"` // Encrypted, never exposed

	Name        string  `json:"name" db:"name"`
	Description *string `json:"description,omitempty" db:"description"`

	// OAuth 2.1 Settings (IAM-04 — implicit + password (ROPC) grants
	// removed per OAuth 2.1 BCP-225 / draft-ietf-oauth-v2-1: implicit
	// is inherently insecure (token-in-fragment, no PKCE, leak via
	// referer), ROPC defeats federation and forces credential proxying.
	// Server-side rejection lives in
	// OAuthProviderService.validateOAuth21GrantsAndResponses.
	GrantTypes    []string `json:"grant_types" db:"grant_types"`       // authorization_code, client_credentials, refresh_token
	ResponseTypes []string `json:"response_types" db:"response_types"` // code (only OAuth 2.1 conformant value)
	RedirectURIs  []string `json:"redirect_uris" db:"redirect_uris"`
	Scopes        []string `json:"scopes" db:"scopes"`

	// Token Settings
	AccessTokenLifetime  int `json:"access_token_lifetime" db:"access_token_lifetime"`   // in seconds
	RefreshTokenLifetime int `json:"refresh_token_lifetime" db:"refresh_token_lifetime"` // in seconds
	IDTokenLifetime      int `json:"id_token_lifetime" db:"id_token_lifetime"`           // in seconds

	// Client Type
	IsPublic       bool `json:"is_public" db:"is_public"`             // Public clients (SPAs, mobile apps) cannot keep secrets
	IsConfidential bool `json:"is_confidential" db:"is_confidential"` // Confidential clients (backend apps) can keep secrets
	IsFirstParty   bool `json:"is_first_party" db:"is_first_party"`   // First-party clients (owned by us)

	// PKCE Settings
	RequirePKCE bool `json:"require_pkce" db:"require_pkce"` // Require PKCE for authorization code flow

	// FAPI 2.0 Baseline / RFC 9126 §2.1: when true, /oauth/authorize
	// rejects this client's requests that did NOT arrive via PAR.
	// Operators flip this on for high-trust clients (banking, gov,
	// regulated-industry RPs). Default false — existing clients
	// unaffected. Migration 223. Enforced in
	// internal/handlers/oauth_provider_handler.go continueAuthorize
	// via the viaPAR flag.
	RequirePushedAuthorizationRequests bool `json:"require_pushed_authorization_requests" db:"require_pushed_authorization_requests"`

	// RAR Settings (RFC 9396)
	// AuthorizationDetailTypes lists the authorization_detail type values that
	// this client is permitted to request. An empty slice means all types are
	// allowed. Stored as a text[] column in the database.
	AuthorizationDetailTypes []string `json:"authorization_detail_types,omitempty" db:"authorization_detail_types"`

	// App Access Control
	AppCategory       string `json:"app_category,omitempty" db:"app_category"`   // general, platform, business, etc.
	RequireAssignment bool   `json:"require_assignment" db:"require_assignment"` // Require explicit app role assignment

	// Status
	IsActive  bool       `json:"is_active" db:"is_active"`
	RevokedAt *time.Time `json:"revoked_at,omitempty" db:"revoked_at"`
	RevokedBy *uuid.UUID `json:"revoked_by,omitempty" db:"revoked_by"`

	// Metadata — RFC 7591 §2 client metadata. All *_uri fields are
	// HTTPS-only and rendered on the consent screen so end-users can
	// verify the relying party they are authorising. ClientURI was
	// added in migration 227; the older LogoURL / TosURL / PolicyURL
	// are persisted with `_url` column names for backward compat (the
	// RFC name is `_uri` in the spec but renaming the columns in-place
	// would force every test fixture and OpenAPI consumer to churn).
	LogoURL      *string `json:"logo_url,omitempty" db:"logo_url"`
	ClientURI    *string `json:"client_uri,omitempty" db:"client_uri"`
	TosURL       *string `json:"tos_url,omitempty" db:"tos_url"`
	PolicyURL    *string `json:"policy_url,omitempty" db:"policy_url"`
	ContactEmail *string `json:"contact_email,omitempty" db:"contact_email"`

	// OIDC-specific fields
	Contacts                         []string `json:"contacts,omitempty" db:"contacts"`
	TokenEndpointAuthMethod          string   `json:"token_endpoint_auth_method" db:"token_endpoint_auth_method"`     // client_secret_basic, client_secret_post, none, tls_client_auth
	IDTokenSignedResponseAlg         string   `json:"id_token_signed_response_alg" db:"id_token_signed_response_alg"` // RS256, RS384, RS512, ES256

	// TLSClientAuthSubjectDN — RFC 8705 §2.1 PKI-mode mTLS client
	// authentication. When non-nil AND TokenEndpointAuthMethod ==
	// "tls_client_auth", the OAuth token endpoint verifies that the
	// proxy-forwarded client certificate's Subject DN (per RFC 4514
	// string form) exactly matches this value. Subject DN matching
	// is the canonical PKI-mode contract that Auth0 / Okta / Duende
	// all implement; SAN matching (§2.1.2) and self-signed mode
	// (§2.2) are deferred to future MRs without changing this field.
	//
	// Wiring: APISIX in front of falcon-id MUST forward the verified
	// leaf certificate via the X-Forwarded-Client-Cert header (PEM
	// block, URL-encoded). The chain is trusted to be validated at
	// the proxy boundary; falcon-id does NOT re-validate.
	//
	// Nullable: clients that don't use mTLS leave this NULL and
	// continue to authenticate via client_secret_basic /
	// client_secret_post per their TokenEndpointAuthMethod.
	TLSClientAuthSubjectDN *string `json:"tls_client_auth_subject_dn,omitempty" db:"tls_client_auth_subject_dn"`
	PostLogoutRedirectURIs           []string `json:"post_logout_redirect_uris,omitempty" db:"post_logout_redirect_uris"`
	AllowedCORSOrigins               []string `json:"allowed_cors_origins,omitempty" db:"allowed_cors_origins"`
	BackchannelLogoutURI              *string `json:"backchannel_logout_uri,omitempty" db:"backchannel_logout_uri"`
	BackchannelLogoutSessionRequired  bool    `json:"backchannel_logout_session_required" db:"backchannel_logout_session_required"`
	FrontchannelLogoutURI             *string `json:"frontchannel_logout_uri,omitempty" db:"frontchannel_logout_uri"`
	FrontchannelLogoutSessionRequired bool    `json:"frontchannel_logout_session_required" db:"frontchannel_logout_session_required"`

	// RFC 9101 JWT-Secured Authorization Request — per-client signing key
	// + permitted alg. NULL Jwks means the client has not opted into JAR
	// (legacy clients are unaffected). Persisted as raw JSON so the JWKS
	// shape is forwarded verbatim to the JWS verifier.
	Jwks                    *string `json:"jwks,omitempty" db:"jwks"`
	RequestObjectSigningAlg string  `json:"request_object_signing_alg,omitempty" db:"request_object_signing_alg"`

	// AllowExternalJWTExchange gates the RFC 8693 `subject_token_type=
	// urn:ietf:params:oauth:token-type:jwt` path of TokenExchangeGrant
	// — when true, the client is permitted to exchange JWTs signed by
	// EXTERNAL issuers (registered in iam_oauth_trusted_external_issuers)
	// for user-bound Falcon-ID access + refresh tokens. Per-issuer trust
	// is further gated by rows in iam_oauth_client_trusted_external_issuers
	// (deny-by-default many-to-many). False (default) → only legacy
	// :access_token subject types are accepted. Backing column added by
	// migration v0.232.237.
	AllowExternalJWTExchange bool `json:"allow_external_jwt_exchange" db:"allow_external_jwt_exchange"`

	// RefreshTokenRotationPolicy controls what happens to the inbound
	// refresh_token on grant_type=refresh_token calls. Two values, with
	// the DB CHECK constraint enforcing the set (migration v0.232.242):
	//
	//   "rotate" (default) — the canonical OAuth 2.0 / Public-Client
	//     pattern. The old refresh_token is revoked on issuance of the
	//     new pair. Stays the default for every client; new public
	//     clients inherit it without further configuration.
	//
	//   "reuse"           — the BFF pattern recommended by Duende BFF
	//     (the .NET tier-1 reference) and IETF draft-ietf-oauth-first-
	//     party-apps for CONFIDENTIAL first-party clients. The old
	//     refresh_token is NOT revoked; the same refresh_token string
	//     is returned alongside a freshly-minted access_token. Closes
	//     the cross-pod parallel-refresh revoke-the-old race observed
	//     on internal.example.com (2026-05-14). Safe ONLY for
	//     clients whose refresh_token cannot be exfiltrated by the
	//     browser (server-side __Host- prefixed cookies behind the
	//     BFF cookie domain) — explicit per-client opt-in required.
	RefreshTokenRotationPolicy string `json:"refresh_token_rotation_policy" db:"refresh_token_rotation_policy"`

	CreatedAt time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt time.Time  `json:"updated_at" db:"updated_at"`
	CreatedBy *uuid.UUID `json:"created_by,omitempty" db:"created_by"`
	UpdatedBy *uuid.UUID `json:"updated_by,omitempty" db:"updated_by"`
}

// OAuthAuthorizationCode represents an OAuth 2.0 authorization code
type OAuthAuthorizationCode struct {
	ID       uuid.UUID `json:"id" db:"id"`
	TenantID uuid.UUID `json:"tenant_id" db:"tenant_id"`
	ClientID uuid.UUID `json:"client_id" db:"client_id"`
	UserID   uuid.UUID `json:"user_id" db:"user_id"`

	Code        string   `json:"code" db:"code"`
	RedirectURI string   `json:"redirect_uri" db:"redirect_uri"`
	Scopes      []string `json:"scopes" db:"scopes"`
	State       *string  `json:"state,omitempty" db:"state"`
	Nonce       *string  `json:"nonce,omitempty" db:"nonce"`

	// PKCE
	CodeChallenge       *string `json:"code_challenge,omitempty" db:"code_challenge"`
	CodeChallengeMethod *string `json:"code_challenge_method,omitempty" db:"code_challenge_method"` // S256, plain

	// RAR (RFC 9396): validated authorization_details bound to this code.
	// Stored in-memory during the authorization flow and propagated to the
	// token response when the code is exchanged.
	AuthorizationDetails []AuthorizationDetail `json:"authorization_details,omitempty" db:"-"`

	// Status
	IsUsed    bool       `json:"is_used" db:"is_used"`
	UsedAt    *time.Time `json:"used_at,omitempty" db:"used_at"`
	ExpiresAt time.Time  `json:"expires_at" db:"expires_at"`

	CreatedAt time.Time `json:"created_at" db:"created_at"`

	// RFC 8176 authentication-method snapshot copied from the originating
	// session at /authorize time; propagated to OAuthToken at /token time
	// and preserved across refresh-token rotations (migration 211).
	AuthMethodsUsed []string `json:"auth_methods_used,omitempty" db:"auth_methods_used"`

	// IdpSessionID — the falcon_idp_session UUID captured at /oauth/authorize
	// time. Propagated to OAuthToken at /token time and preserved across
	// refresh-token rotations so id_tokens emit the OIDC Session Management
	// 1.0 §5 `sid` claim consistently across the session lifetime
	// (migration 220). NULL for sessions that pre-date the migration and for
	// flows like client_credentials that have no IdP session.
	IdpSessionID *uuid.UUID `json:"idp_session_id,omitempty" db:"idp_session_id"`
}

// OAuthToken represents an OAuth 2.0 access/refresh token
type OAuthToken struct {
	ID       uuid.UUID  `json:"id" db:"id"`
	TenantID uuid.UUID  `json:"tenant_id" db:"tenant_id"`
	ClientID uuid.UUID  `json:"client_id" db:"client_id"`
	UserID   *uuid.UUID `json:"user_id,omitempty" db:"user_id"` // Null for client_credentials grant

	TokenType    string   `json:"token_type" db:"token_type"` // access_token, refresh_token
	Token        string   `json:"token" db:"token"`           // Hashed token
	Scopes       []string `json:"scopes" db:"scopes"`
	RefreshToken *string  `json:"refresh_token,omitempty" db:"refresh_token"` // Hashed refresh token

	// Token Metadata
	IPAddress *string `json:"ip_address,omitempty" db:"ip_address"`
	UserAgent *string `json:"user_agent,omitempty" db:"user_agent"`

	// Status
	IsRevoked bool       `json:"is_revoked" db:"is_revoked"`
	RevokedAt *time.Time `json:"revoked_at,omitempty" db:"revoked_at"`
	ExpiresAt time.Time  `json:"expires_at" db:"expires_at"`

	CreatedAt time.Time `json:"created_at" db:"created_at"`
	UpdatedAt time.Time `json:"updated_at" db:"updated_at"`

	// RFC 8176 authentication-method snapshot carried from the authorization
	// code (or the prior refresh token on rotation) so id_tokens issued from
	// refresh flows preserve the original login event's `amr` (migration 211).
	AuthMethodsUsed []string `json:"auth_methods_used,omitempty" db:"auth_methods_used"`

	// IdpSessionID — falcon_idp_session UUID propagated from the authorization
	// code (or the prior refresh token on rotation) so id_tokens emit the
	// OIDC Session Management 1.0 §5 `sid` claim consistently across the
	// session lifetime (migration 220). NULL for client_credentials grants
	// and pre-migration tokens.
	IdpSessionID *uuid.UUID `json:"idp_session_id,omitempty" db:"idp_session_id"`

	// TokenFamilyID — RFC 9700 §4.14 refresh-token family/lineage id
	// (migration 0009). Every rotation descended from one authorization grant
	// shares this id; a ROOT token (first issuance) carries
	// TokenFamilyID == ID. On detected reuse of a rotated (revoked) refresh
	// token the whole family is revoked (RevokeRefreshTokenFamily). NULL only
	// for pre-migration rows before the backfill runs; generateTokens always
	// stamps it on new rows.
	TokenFamilyID *uuid.UUID `json:"token_family_id,omitempty" db:"token_family_id"`
}

// OAuthState represents OAuth 2.0 state parameter for CSRF protection
type OAuthState struct {
	ID       uuid.UUID  `json:"id" db:"id"`
	TenantID uuid.UUID  `json:"tenant_id" db:"tenant_id"`
	ClientID uuid.UUID  `json:"client_id" db:"client_id"`
	UserID   *uuid.UUID `json:"user_id,omitempty" db:"user_id"`

	State       string  `json:"state" db:"state"`
	RedirectURI string  `json:"redirect_uri" db:"redirect_uri"`
	Nonce       *string `json:"nonce,omitempty" db:"nonce"`

	// PKCE
	CodeChallenge       *string `json:"code_challenge,omitempty" db:"code_challenge"`
	CodeChallengeMethod *string `json:"code_challenge_method,omitempty" db:"code_challenge_method"`

	IsUsed    bool       `json:"is_used" db:"is_used"`
	UsedAt    *time.Time `json:"used_at,omitempty" db:"used_at"`
	ExpiresAt time.Time  `json:"expires_at" db:"expires_at"`

	CreatedAt time.Time `json:"created_at" db:"created_at"`
}

// ==================== Request/Response DTOs ====================

// CreateOAuthClientRequest for creating a new OAuth client
type CreateOAuthClientRequest struct {
	// ClientID is OPTIONAL. When supplied, the server uses the
	// caller-chosen identifier verbatim (subject to format + uniqueness
	// validation) instead of generating a random one. This is the
	// contract the platform's ServiceClient provisioner relies on so
	// its Vault entry (`svc-<service>`) and the DB row's client_id
	// stay in lockstep without an extra round-trip to discover the
	// generated id. RFC 7591 §3.1 explicitly permits the AS to honor
	// or override a registration request's client_id; we honor when
	// the supplied value passes validation and is not already taken.
	//
	// Format: 1–128 chars, [a-zA-Z0-9._-], must start with alnum.
	// Conflicts return 409 (the caller is expected to rotate the
	// secret of the existing client via /:id/regenerate-secret rather
	// than re-create).
	ClientID    *string `json:"client_id,omitempty" binding:"omitempty,min=1,max=128"`
	Name        string  `json:"name" binding:"required,min=2,max=255"`
	Description *string `json:"description"`

	GrantTypes []string `json:"grant_types" binding:"required,min=1"`
	// ResponseTypes + RedirectURIs are CONDITIONAL on grant_types per
	// RFC 6749 §3.1.2 — the spec ties redirect_uri to the
	// authorization_code and implicit flows; client_credentials grant
	// has no /authorize round-trip and no callback. Pre-2026-04-29 the
	// schema enforced `binding:"required,min=1"` on both fields, which
	// blocked every machine-to-machine client registration. The
	// grant-type-aware validator below replaces the static binding;
	// see Validate() and the matching admin/internal handler call sites.
	ResponseTypes []string `json:"response_types"`
	RedirectURIs  []string `json:"redirect_uris"`
	Scopes        []string `json:"scopes"`

	AccessTokenLifetime  *int `json:"access_token_lifetime"`  // defaults to 3600 (1 hour)
	RefreshTokenLifetime *int `json:"refresh_token_lifetime"` // defaults to 2592000 (30 days)
	IDTokenLifetime      *int `json:"id_token_lifetime"`      // defaults to 3600 (1 hour)

	IsPublic       bool `json:"is_public"`
	IsConfidential bool `json:"is_confidential"`
	IsFirstParty   bool `json:"is_first_party"`
	RequirePKCE    bool `json:"require_pkce"`

	// FAPI 2.0 Baseline / RFC 9126 §2.1 — opt-in PAR mandate per client.
	RequirePushedAuthorizationRequests bool `json:"require_pushed_authorization_requests"`

	LogoURL      *string `json:"logo_url"`
	ClientURI    *string `json:"client_uri"`
	TosURL       *string `json:"tos_url"`
	PolicyURL    *string `json:"policy_url"`
	ContactEmail *string `json:"contact_email" binding:"omitempty,email"`

	// OIDC-specific fields
	Contacts                 []string `json:"contacts"`
	TokenEndpointAuthMethod  string   `json:"token_endpoint_auth_method"`   // defaults to client_secret_basic
	IDTokenSignedResponseAlg string   `json:"id_token_signed_response_alg"` // defaults to RS256
	PostLogoutRedirectURIs   []string `json:"post_logout_redirect_uris"`
	AllowedCORSOrigins       []string `json:"allowed_cors_origins"`
	BackchannelLogoutURI     *string  `json:"backchannel_logout_uri"`
	FrontchannelLogoutURI    *string  `json:"frontchannel_logout_uri"`

	// RAR (RFC 9396): list of authorization_detail type strings this client is
	// permitted to request. An empty list means all types are allowed.
	AuthorizationDetailTypes []string `json:"authorization_detail_types"`

	// RFC 8693 :jwt token-exchange permission. When true, this client is
	// allowed to call /oauth/token with subject_token_type=urn:ietf:
	// params:oauth:token-type:jwt — bridging an EXTERNAL IdP's signed
	// JWT (e.g. Talon's IAP JWT) into a Falcon-ID user-bound
	// access_token + refresh_token. Per-issuer trust is further gated
	// by separate iam_oauth_client_trusted_external_issuers grants
	// (see admin endpoints /oauth-clients/:id/trusted-external-issuers).
	// Deny-by-default (false). Backing column added in v0.232.237.
	AllowExternalJWTExchange bool `json:"allow_external_jwt_exchange"`
}

// Validate runs grant-type-aware checks the JSON-tag binding can't express
// directly. Per RFC 6749 §3.1.2, redirect_uri is required only for the
// authorization_code and implicit grants; client_credentials-only and
// password-grant clients have no callback. response_types similarly only
// applies when /authorize is involved.
//
// Callers MUST invoke this after ShouldBindJSON in handler code (both
// /api/v1/admin/oauth-clients and /api/v1/internal/oauth-clients).
func (r *CreateOAuthClientRequest) Validate() error {
	needsCallback := false
	for _, g := range r.GrantTypes {
		if g == "authorization_code" || g == "implicit" {
			needsCallback = true
			break
		}
	}
	if needsCallback {
		if len(r.RedirectURIs) == 0 {
			return fmt.Errorf("redirect_uris is required when grant_types contains authorization_code or implicit (RFC 6749 §3.1.2)")
		}
		// response_types intentionally NOT validated here. Per RFC 7591
		// §2 it is registration metadata with defaults that can be
		// derived from grant_types (authorization_code → "code",
		// implicit → "token id_token"); the service layer below
		// applies that default. Forcing callers to compute it pushes
		// boilerplate into every client (provisioner, UI, scripts) and
		// drifts from the OIDC discovery contract where the OP
		// advertises response_types_supported and clients pick from
		// that list at /authorize, not at registration.

		// Branding requirement for non-first-party (third-party)
		// clients on interactive flows. The OIDC consent screen
		// renders client_name + logo_url so users can recognize *who*
		// is asking for access; "accounts service" alone with no logo
		// is the kind of bare-string a phishing app would gladly
		// impersonate. We enforce only when:
		//   - needsCallback=true → a consent screen could actually
		//     be shown (client_credentials/password flows skip this).
		//   - is_first_party=false → consent WILL be shown
		//     (is_first_party=true skips it entirely, so the field
		//     has no UX surface).
		// Future-proofs the consent UI: onboarding a real third-party
		// integration refuses to land without the branding metadata
		// that makes the consent page meaningful.
		if !r.IsFirstParty {
			if r.LogoURL == nil || *r.LogoURL == "" {
				return fmt.Errorf("logo_url is required for non-first-party clients on interactive flows so the consent screen can identify the requester")
			}
		}
	}
	return nil
}

// UpdateOAuthClientRequest for updating an OAuth client
type UpdateOAuthClientRequest struct {
	Name        *string `json:"name" binding:"omitempty,min=2,max=255"`
	Description *string `json:"description"`

	GrantTypes    []string `json:"grant_types" binding:"omitempty,min=1"`
	ResponseTypes []string `json:"response_types" binding:"omitempty,min=1"`
	RedirectURIs  []string `json:"redirect_uris" binding:"omitempty,min=1"`
	Scopes        []string `json:"scopes"`

	AccessTokenLifetime  *int `json:"access_token_lifetime"`
	RefreshTokenLifetime *int `json:"refresh_token_lifetime"`
	IDTokenLifetime      *int `json:"id_token_lifetime"`

	IsPublic       *bool `json:"is_public"`
	IsConfidential *bool `json:"is_confidential"`
	IsFirstParty   *bool `json:"is_first_party"`
	RequirePKCE    *bool `json:"require_pkce"`
	IsActive       *bool `json:"is_active"`

	// FAPI 2.0 Baseline / RFC 9126 §2.1 — opt-in PAR mandate per client.
	// Pointer so an unset field in the JSON request body means "no change"
	// rather than "set to false".
	RequirePushedAuthorizationRequests *bool `json:"require_pushed_authorization_requests"`

	LogoURL      *string `json:"logo_url"`
	ClientURI    *string `json:"client_uri"`
	TosURL       *string `json:"tos_url"`
	PolicyURL    *string `json:"policy_url"`
	ContactEmail *string `json:"contact_email" binding:"omitempty,email"`

	// OIDC-specific fields
	Contacts                 []string `json:"contacts"`
	TokenEndpointAuthMethod  *string  `json:"token_endpoint_auth_method"`
	IDTokenSignedResponseAlg *string  `json:"id_token_signed_response_alg"`
	PostLogoutRedirectURIs   []string `json:"post_logout_redirect_uris"`
	AllowedCORSOrigins       []string `json:"allowed_cors_origins"`
	BackchannelLogoutURI     *string  `json:"backchannel_logout_uri"`
	FrontchannelLogoutURI    *string  `json:"frontchannel_logout_uri"`

	// RAR (RFC 9396): replaces or extends the current authorization_detail_types list.
	AuthorizationDetailTypes []string `json:"authorization_detail_types"`

	// RFC 8693 :jwt token-exchange permission. Pointer so omission
	// means "no change" rather than "set false". See migration v0.232.237.
	AllowExternalJWTExchange *bool `json:"allow_external_jwt_exchange"`
}

// OAuthClientResponse for API responses
type OAuthClientResponse struct {
	ID       uuid.UUID `json:"id"`
	TenantID uuid.UUID `json:"tenant_id"`
	ClientID string    `json:"client_id"`

	// ClientSecret only returned on creation
	ClientSecret *string `json:"client_secret,omitempty"`

	Name        string  `json:"name"`
	Description *string `json:"description,omitempty"`

	GrantTypes    []string `json:"grant_types"`
	ResponseTypes []string `json:"response_types"`
	RedirectURIs  []string `json:"redirect_uris"`
	Scopes        []string `json:"scopes"`

	AccessTokenLifetime  int `json:"access_token_lifetime"`
	RefreshTokenLifetime int `json:"refresh_token_lifetime"`
	IDTokenLifetime      int `json:"id_token_lifetime"`

	IsPublic          bool   `json:"is_public"`
	IsConfidential    bool   `json:"is_confidential"`
	IsFirstParty      bool   `json:"is_first_party"`
	RequirePKCE       bool   `json:"require_pkce"`
	RequireAssignment bool   `json:"require_assignment"`
	AppCategory       string `json:"app_category,omitempty"`
	IsActive          bool   `json:"is_active"`

	LogoURL      *string `json:"logo_url,omitempty"`
	ClientURI    *string `json:"client_uri,omitempty"`
	TosURL       *string `json:"tos_url,omitempty"`
	PolicyURL    *string `json:"policy_url,omitempty"`
	ContactEmail *string `json:"contact_email,omitempty"`

	// OIDC-specific fields
	Contacts                 []string `json:"contacts,omitempty"`
	TokenEndpointAuthMethod  string   `json:"token_endpoint_auth_method"`
	IDTokenSignedResponseAlg string   `json:"id_token_signed_response_alg"`
	PostLogoutRedirectURIs   []string `json:"post_logout_redirect_uris,omitempty"`
	AllowedCORSOrigins       []string `json:"allowed_cors_origins,omitempty"`
	BackchannelLogoutURI     *string  `json:"backchannel_logout_uri,omitempty"`
	FrontchannelLogoutURI    *string  `json:"frontchannel_logout_uri,omitempty"`

	// RAR (RFC 9396)
	AuthorizationDetailTypes []string `json:"authorization_detail_types,omitempty"`

	// RFC 8693 :jwt token-exchange permission (migration v0.232.237).
	// Surfaced on GET so the activator runbook + admin UIs can read it.
	AllowExternalJWTExchange bool `json:"allow_external_jwt_exchange"`

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// OAuthClientListResponse for list endpoints
type OAuthClientListResponse struct {
	Clients    []OAuthClientResponse `json:"clients"`
	Total      int64                 `json:"total"`
	Page       int                   `json:"page"`
	PageSize   int                   `json:"page_size"`
	TotalPages int                   `json:"total_pages"`
}

// OAuthAuthorizeRequest for OAuth authorization endpoint
type OAuthAuthorizeRequest struct {
	ResponseType string `form:"response_type" binding:"required,oneof=code token id_token"`
	ClientID     string `form:"client_id" binding:"required"`
	RedirectURI  string `form:"redirect_uri" binding:"required,url"`
	Scope        string `form:"scope"`
	State        string `form:"state"`
	Nonce        string `form:"nonce"`

	// PKCE
	CodeChallenge       string `form:"code_challenge"`
	CodeChallengeMethod string `form:"code_challenge_method" binding:"omitempty,oneof=S256"`

	// Display and prompts
	Display string `form:"display"` // page, popup, touch, wap
	Prompt  string `form:"prompt"`  // none, login, consent, select_account

	// LoginHint — OIDC Core 1.0 §3.1.2.1. OPTIONAL hint to the
	// authorization server about the login identifier the End-User might
	// use (email, username, or phone — the spec leaves the format to the
	// RP/OP pair). Purely a UX pre-fill signal for the login screen: the
	// server MUST NOT treat it as an asserted identity and MUST still
	// require full credentials. Forwarded by LoginPage as the `email=`
	// query param apps/login already consumes for pre-fill (see
	// useLoginFlow's `initialEmail`). Length-capped defensively since it
	// rides through a redirect chain and ends up in a URL.
	LoginHint string `form:"login_hint" binding:"omitempty,max=254"`

	// LoginContext — NOT part of any OIDC/OAuth spec. A HexxLock-local
	// extension, in the same non-standard "hint" family as Auth0's
	// screen_hint (https://auth0.com/docs/authenticate/login/auth0-universal-login),
	// that lets an RP tell apps/login's hosted login screen *why* the
	// user landed there so it can pick presentation copy accordingly
	// (e.g. "signup" swaps the default "Welcome back" copy for
	// signup-completion copy). Deliberately a closed enum, deliberately
	// presentation-only: it must never gate auth, skip a check, or
	// change server-side behavior — only which strings render on a page
	// that still requires real credentials.
	LoginContext string `form:"login_context" binding:"omitempty,oneof=signup"`

	// RAR (RFC 9396): JSON-encoded array of authorization_detail objects.
	// When present, the server validates each detail against the client's
	// AuthorizationDetailTypes and embeds the validated details in the
	// issued access token.
	AuthorizationDetails string `form:"authorization_details"`

	// Tenant hint — resolves the target tenant before the user authenticates,
	// enabling tenant-specific branding and IDP routing without requiring the
	// client to know the tenant UUID. Accepts a slug (e.g. "bilenlegez") or
	// UUID string. Functionally equivalent to the X-Tenant-ID header for
	// browser-initiated flows where headers are not available.
	Tenant string `form:"tenant" json:"tenant"`

	// RFC 8707 — Resource Indicators. Optional. When supplied on the
	// /authorize request, the resource MUST also be presented on the
	// matching /token request (or be a subset of it). Today the AS
	// records the resource on the issued token's `aud` claim only;
	// authorize-vs-token cross-validation lives in a future commit
	// once we move the auth-code state into Redis (currently
	// in-memory). See Resource on OAuthTokenRequest for validation
	// rules.
	Resource string `form:"resource" json:"resource"`

	// AcrValues — OIDC Core 1.0 §3.1.2.1 + RFC 9470 step-up challenge.
	// Space-separated list of Authentication Context Class Reference
	// values the client requests. The IdP MUST satisfy at least one
	// before issuing a token. Examples (HexxLock-defined):
	//   urn:hexxlock:aal1   — password only
	//   urn:hexxlock:aal2   — password + a second factor (TOTP/WebAuthn)
	//   urn:hexxlock:aal3   — phishing-resistant (WebAuthn UV) only
	// Plus the legacy `mfa` keyword for compatibility with IAPs that
	// pass the bare token (Talon's startAuthWithMFA does this).
	//
	// When the requested ACR exceeds what the user's current session
	// asserts, the IdP must drive a step-up flow:
	//   - User has the factor → MFA challenge UI.
	//   - User has zero MFA factors → MFA enrollment UI.
	// Both flows resume back into /oauth/authorize once complete.
	AcrValues string `form:"acr_values" json:"acr_values"`

	// MaxAge — OIDC Core 1.0 §3.1.2.1 + RFC 9470 §3. The maximum
	// allowed age (in seconds) since the user's last authentication.
	// When set, the IdP MUST verify the current session's `auth_time`
	// is within `MaxAge` seconds of now; otherwise the user MUST be
	// prompted to re-authenticate. Returning a silent-SSO auth code
	// against a stale session here causes RP step-up gates (RFC 9470
	// freshAuth) to loop: the new access token still carries the old
	// auth_time, so the RP rejects it again and re-issues the same
	// max_age challenge. Pointer-typed to distinguish "not requested"
	// (nil, never enforce) from "requested with 0" (always re-auth).
	//
	// Binding: form:"max_age" so both query params and form POSTs map
	// the same field. Decoder uses Go zero-value semantics for missing
	// keys, so the pointer stays nil unless the param is present.
	MaxAge *int `form:"max_age" json:"max_age,omitempty"`

	// AuthMethodsUsed is populated by the /oauth/authorize handler from the
	// current session's auth_methods_used column (migration 211). It is NOT
	// bound from form/query input — only the server can set it — and it
	// snapshots the RFC 8176 authentication-method references onto the
	// resulting authorization code so downstream id_tokens can emit `amr`
	// consistent with the original login event.
	AuthMethodsUsed []string `form:"-" json:"-"`

	// IdpSessionID is populated by the /oauth/authorize handler from the
	// falcon_idp_session cookie. NOT bound from form/query input — only
	// the server can set it. Snapshots the IdP session UUID onto the
	// authorization code so the resulting id_token can emit the OIDC
	// Session Management 1.0 §5 `sid` claim, which OIDC Front-Channel
	// Logout 1.0 §3 receivers use to scope cascade-revocation to a single
	// browser session.
	IdpSessionID *uuid.UUID `form:"-" json:"-"`
}

// OAuthAuthorizeResponse for OAuth authorization response
type OAuthAuthorizeResponse struct {
	Code  string `json:"code,omitempty"`
	State string `json:"state,omitempty"`

	// For implicit flow
	AccessToken string `json:"access_token,omitempty"`
	TokenType   string `json:"token_type,omitempty"`
	ExpiresIn   int64  `json:"expires_in,omitempty"`
	Scope       string `json:"scope,omitempty"`
	IDToken     string `json:"id_token,omitempty"`
}

// OAuthTokenRequest for OAuth token endpoint
type OAuthTokenRequest struct {
	// GrantType accepted values include the RFC 8628 device_code grant
	// and the RFC 8693 token-exchange grant.
	GrantType string `form:"grant_type" binding:"required,oneof=authorization_code client_credentials refresh_token password urn:ietf:params:oauth:grant-type:device_code urn:ietf:params:oauth:grant-type:token-exchange"`

	// RFC 8693 — Token Exchange. The token presented for exchange.
	// MUST be a token previously issued by this OP (we validate by
	// parsing as JWT signed by our active key + cross-checking the
	// iam_oauth_tokens row is non-revoked).
	SubjectToken string `form:"subject_token"`

	// RFC 8693 §2.1 — type of `subject_token`. Today we accept only
	// `urn:ietf:params:oauth:token-type:access_token`. Refresh-token
	// and id_token exchange are out of scope; the spec permits the
	// AS to reject any combination it doesn't support per §2.2.
	SubjectTokenType string `form:"subject_token_type"`

	// RFC 8693 §2.1 — type of token the caller wants back. Optional;
	// defaults to the same type as `subject_token_type`. We accept
	// only access_token for now.
	RequestedTokenType string `form:"requested_token_type"`

	// RFC 8693 §2.1 — `audience` is an alternative shape to RFC 8707
	// `resource`. When both are sent we honour `resource` (RFC 8707
	// takes precedence; matches Auth0/Okta conventions). The value is
	// stamped into the issued access-token `aud` claim same as the
	// resource path.
	Audience string `form:"audience"`

	// For authorization_code grant
	Code         string `form:"code"`
	RedirectURI  string `form:"redirect_uri"`
	CodeVerifier string `form:"code_verifier"` // PKCE

	// For client_credentials and password grants
	Scope string `form:"scope"`

	// For password grant
	Username string `form:"username"`
	Password string `form:"password"`

	// For refresh_token grant
	RefreshToken string `form:"refresh_token"`

	// For device_code grant (RFC 8628)
	DeviceCode string `form:"device_code"`

	// Client authentication
	ClientID     string `form:"client_id"`
	ClientSecret string `form:"client_secret"`

	// RFC 8707 — Resource Indicators. Optional. When supplied, the
	// access-token `aud` claim carries this URI instead of the
	// caller's client_id, restricting the token to a specific
	// resource server. Validation: absolute URI, no fragment, scheme
	// is https or http (http permitted for in-cluster service URLs;
	// the platform's network policy is the second line of defence).
	// Multiple `resource` values per RFC 8707 §2 are accepted by
	// repeating the form field; gin parses the last one — for now we
	// accept only single-resource requests, matching FAPI 2.0
	// recommendation and avoiding the array-vs-string `aud` shape
	// ambiguity downstream consumers have to handle.
	Resource string `form:"resource"`
}

// OAuthTokenResponse for OAuth token endpoint response
type OAuthTokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
	IDToken      string `json:"id_token,omitempty"`

	// RFC 8693 §2.2.1 — `issued_token_type` is REQUIRED in token-
	// exchange responses; we always set it to access_token (we don't
	// issue refresh_tokens or id_tokens through the exchange grant).
	// Omitted from non-exchange responses via omitempty for backward
	// compatibility with existing consumers.
	IssuedTokenType string `json:"issued_token_type,omitempty"`

	// AuthorizationDetails is included in the token response when the
	// request contained a valid authorization_details parameter (RFC 9396 §4).
	// Omitted entirely when no RAR details were requested.
	AuthorizationDetails []AuthorizationDetail `json:"authorization_details,omitempty"`
}

// OAuthIntrospectRequest for token introspection
type OAuthIntrospectRequest struct {
	Token         string `form:"token" binding:"required"`
	TokenTypeHint string `form:"token_type_hint"` // access_token, refresh_token
}

// OAuthIntrospectResponse for token introspection response
type OAuthIntrospectResponse struct {
	Active    bool     `json:"active"`
	Scope     string   `json:"scope,omitempty"`
	ClientID  string   `json:"client_id,omitempty"`
	Username  string   `json:"username,omitempty"`
	TokenType string   `json:"token_type,omitempty"`
	ExpiresAt int64    `json:"exp,omitempty"`
	IssuedAt  int64    `json:"iat,omitempty"`
	Subject   string   `json:"sub,omitempty"`
	Audience  []string `json:"aud,omitempty"`
	Issuer    string   `json:"iss,omitempty"`
}

// OAuthRevokeRequest for token revocation
type OAuthRevokeRequest struct {
	Token         string `form:"token" binding:"required"`
	TokenTypeHint string `form:"token_type_hint"` // access_token, refresh_token
}

// OAuthErrorResponse for OAuth error responses
type OAuthErrorResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description,omitempty"`
	ErrorURI         string `json:"error_uri,omitempty"`
	State            string `json:"state,omitempty"`
}

// ToResponse converts OAuthClient to OAuthClientResponse (without secret)
func (c *OAuthClient) ToResponse() *OAuthClientResponse {
	return &OAuthClientResponse{
		ID:                       c.ID,
		TenantID:                 c.TenantID,
		ClientID:                 c.ClientID,
		Name:                     c.Name,
		Description:              c.Description,
		GrantTypes:               c.GrantTypes,
		ResponseTypes:            c.ResponseTypes,
		RedirectURIs:             c.RedirectURIs,
		Scopes:                   c.Scopes,
		AccessTokenLifetime:      c.AccessTokenLifetime,
		RefreshTokenLifetime:     c.RefreshTokenLifetime,
		IDTokenLifetime:          c.IDTokenLifetime,
		IsPublic:                 c.IsPublic,
		IsConfidential:           c.IsConfidential,
		IsFirstParty:             c.IsFirstParty,
		RequirePKCE:              c.RequirePKCE,
		RequireAssignment:        c.RequireAssignment,
		AppCategory:              c.AppCategory,
		IsActive:                 c.IsActive,
		LogoURL:                  c.LogoURL,
		ClientURI:                c.ClientURI,
		TosURL:                   c.TosURL,
		PolicyURL:                c.PolicyURL,
		ContactEmail:             c.ContactEmail,
		Contacts:                 c.Contacts,
		TokenEndpointAuthMethod:  c.TokenEndpointAuthMethod,
		IDTokenSignedResponseAlg: c.IDTokenSignedResponseAlg,
		PostLogoutRedirectURIs:   c.PostLogoutRedirectURIs,
		AllowedCORSOrigins:       c.AllowedCORSOrigins,
		BackchannelLogoutURI:     c.BackchannelLogoutURI,
		FrontchannelLogoutURI:    c.FrontchannelLogoutURI,
		AuthorizationDetailTypes: c.AuthorizationDetailTypes,
		// RFC 8693 :jwt token-exchange permission (migration v0.232.237).
		// Surfacing it in the response is required for the activator
		// runbook script + admin UI to reflect the right state on GET.
		AllowExternalJWTExchange: c.AllowExternalJWTExchange,
		CreatedAt:                c.CreatedAt,
		UpdatedAt:                c.UpdatedAt,
	}
}

// ToResponseWithSecret converts OAuthClient to OAuthClientResponse (with secret for creation)
func (c *OAuthClient) ToResponseWithSecret(clientSecret string) *OAuthClientResponse {
	resp := c.ToResponse()
	resp.ClientSecret = &clientSecret
	return resp
}

// IsExpired checks if the authorization code is expired
func (c *OAuthAuthorizationCode) IsExpired() bool {
	return time.Now().After(c.ExpiresAt)
}

// IsExpired checks if the token is expired
func (t *OAuthToken) IsExpired() bool {
	return time.Now().After(t.ExpiresAt)
}

// IsExpired checks if the state is expired
func (s *OAuthState) IsExpired() bool {
	return time.Now().After(s.ExpiresAt)
}

// ==================== OIDC Types ====================

// OIDCDiscoveryDocument represents the OpenID Connect Discovery document
// per OpenID Connect Discovery 1.0 §3 + the conformance pack required by
// the third-party-RP onboarding story (introspection/revocation auth methods,
// front-channel logout flags, request_parameter capability flags).
type OIDCDiscoveryDocument struct {
	Issuer                            string   `json:"issuer"`
	AuthorizationEndpoint             string   `json:"authorization_endpoint"`
	TokenEndpoint                     string   `json:"token_endpoint"`
	UserinfoEndpoint                  string   `json:"userinfo_endpoint"`
	JwksURI                           string   `json:"jwks_uri"`
	RegistrationEndpoint              string   `json:"registration_endpoint,omitempty"`
	ScopesSupported                   []string `json:"scopes_supported"`
	ResponseTypesSupported            []string `json:"response_types_supported"`
	ResponseModesSupported            []string `json:"response_modes_supported,omitempty"`
	GrantTypesSupported               []string `json:"grant_types_supported"`
	SubjectTypesSupported             []string `json:"subject_types_supported"`
	IDTokenSigningAlgValuesSupported  []string `json:"id_token_signing_alg_values_supported"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
	ClaimsSupported                   []string `json:"claims_supported"`
	// AcrValuesSupported lists the Authentication Context Class Reference
	// values the IdP can advertise on issued ID tokens. Tier-1 publishes
	// "urn:hexxlock:aal2" (password+TOTP/email-OTP) and "urn:hexxlock:aal3"
	// (passkey / FIDO2 / WebAuthn — phishing-resistant). RPs gate sensitive
	// operations on AAL3 by adding `acr_values=urn:hexxlock:aal3` to their
	// authorization request; the IdP then forces a passkey re-auth. Empty
	// in deployments with passkeys disabled.
	AcrValuesSupported            []string `json:"acr_values_supported,omitempty"`
	CodeChallengeMethodsSupported []string `json:"code_challenge_methods_supported,omitempty"`
	IntrospectionEndpoint             string   `json:"introspection_endpoint,omitempty"`
	RevocationEndpoint                string   `json:"revocation_endpoint,omitempty"`
	EndSessionEndpoint                string   `json:"end_session_endpoint,omitempty"`

	// RFC 7662 §6.2 / RFC 7009 §4.1.2 — advertise the client-authentication
	// methods accepted at /oauth/introspect and /oauth/revoke. Required so
	// third-party RP SDKs (panva/openid-client, oidc-client-ts) pick the
	// right Authorization scheme without trial-and-error.
	IntrospectionEndpointAuthMethodsSupported []string `json:"introspection_endpoint_auth_methods_supported,omitempty"`
	RevocationEndpointAuthMethodsSupported    []string `json:"revocation_endpoint_auth_methods_supported,omitempty"`

	// OIDC Discovery 1.0 §3 — describe how aggregated/distributed claims
	// are returned. Falcon-ID returns claims inline only, so "normal" is
	// the only supported type.
	ClaimTypesSupported []string `json:"claim_types_supported,omitempty"`

	// OIDC Discovery 1.0 §3 / RFC 9101 — request-object support
	// advertisement. /oauth/authorize accepts the `request` parameter
	// (JAR JWS) when the client has registered a JWKS via migration
	// 226; verification path lives in
	// internal/handlers/oauth_provider_handler.go applyJARRequestObject.
	// `request_uri` is NOT advertised — PAR is the supported pattern
	// for request-by-reference; advertising request_uri here would
	// invite conformance suites to probe an unimplemented surface.
	RequestParameterSupported     bool `json:"request_parameter_supported"`
	RequestURIParameterSupported  bool `json:"request_uri_parameter_supported"`
	RequireRequestURIRegistration bool `json:"require_request_uri_registration"`

	// RFC 9101 §10.5 — `request_object_signing_alg_values_supported`
	// MUST list every JWS alg the AS accepts on a JAR request object.
	// Mirrors VerifyJARRequestObject's accept-list (RS256/RS384/RS512).
	// Without this advertisement, FAPI 2.0 + spec-aware RP SDKs refuse
	// to send signed authorize requests because they have no
	// declared-supported alg to pick.
	RequestObjectSigningAlgValuesSupported []string `json:"request_object_signing_alg_values_supported,omitempty"`

	// RFC 9449 §5.1 — `dpop_signing_alg_values_supported` MUST list the
	// JWS algs the AS accepts on a DPoP proof JWT when DPoP is
	// supported. Falcon-ID accepts proofs whose JWK kty is RSA (any
	// RS/PS variant) or EC P-256 (ES256). FAPI 2.0 Baseline MUST
	// advertise this list when the AS issues sender-constrained
	// tokens via DPoP.
	DPoPSigningAlgValuesSupported []string `json:"dpop_signing_alg_values_supported,omitempty"`

	// OIDC Discovery 1.0 §3 — `claims` parameter capability. Currently
	// false; advertising explicitly so RP SDKs don't attempt to send it.
	ClaimsParameterSupported bool `json:"claims_parameter_supported"`

	// RFC 9126: Pushed Authorization Requests
	PushedAuthorizationRequestEndpoint string `json:"pushed_authorization_request_endpoint,omitempty"`
	RequirePushedAuthorizationRequests bool   `json:"require_pushed_authorization_requests,omitempty"`

	// OIDC Back-Channel Logout 1.0
	BackchannelLogoutSupported        bool `json:"backchannel_logout_supported"`
	BackchannelLogoutSessionSupported bool `json:"backchannel_logout_session_supported"`

	// OIDC Front-Channel Logout 1.0 — Falcon-ID supports both back-channel
	// (preferred) and front-channel logout cascades; we advertise both so
	// RPs that cannot host a back-channel listener can fall back to the
	// iframe-based front-channel pattern. `*_session_supported=true` means
	// we include `iss` + `sid` in the logout token / front-channel URL so
	// the RP can scope the logout to a specific session.
	FrontchannelLogoutSupported        bool `json:"frontchannel_logout_supported"`
	FrontchannelLogoutSessionSupported bool `json:"frontchannel_logout_session_supported"`

	// RFC 8705 — TLS-bound access tokens. Not supported today; advertising
	// explicitly false so token-binding-aware RPs don't attempt to bind.
	TLSClientCertificateBoundAccessTokens bool `json:"tls_client_certificate_bound_access_tokens"`

	// RFC 9207 — `iss` parameter in authorization response. Mitigates the
	// IdP mix-up attack where an attacker tricks an honest RP into sending
	// the auth_code received from a malicious IdP to the honest IdP's
	// /oauth/token endpoint. Setting this true MUST be paired with
	// emitting `iss=<issuer>` alongside `code` and `state` on the
	// authorization-response redirect (handled in
	// internal/handlers/oauth_provider_handler.go continueAuthorize).
	// Required by FAPI 2.0 Baseline §5.4.
	AuthorizationResponseIssParameterSupported bool `json:"authorization_response_iss_parameter_supported"`
}

// ==================== PAR Types (RFC 9126) ====================

// PARRequest stores the parameters of a pushed authorization request.
// The request_uri is computed as "urn:ietf:params:oauth:request_uri:<reference>" where
// reference is a cryptographically-random 32-byte value encoded as base64url.
type PARRequest struct {
	// Reference is the random token used to build the request_uri.
	Reference string `json:"reference"`

	// ClientID is the OAuth client that submitted the request.
	ClientID string `json:"client_id"`

	// The full authorization request parameters submitted by the client.
	ResponseType        string `json:"response_type"`
	RedirectURI         string `json:"redirect_uri"`
	Scope               string `json:"scope"`
	State               string `json:"state,omitempty"`
	Nonce               string `json:"nonce,omitempty"`
	CodeChallenge       string `json:"code_challenge,omitempty"`
	CodeChallengeMethod string `json:"code_challenge_method,omitempty"`
	Display             string `json:"display,omitempty"`
	Prompt              string `json:"prompt,omitempty"`

	// ExpiresAt is when this PAR entry expires (default: 60 seconds from creation).
	ExpiresAt int64 `json:"expires_at"`
}

// IsExpired returns true if the PAR entry is past its expiry time.
func (p *PARRequest) IsExpired() bool {
	return time.Now().Unix() > p.ExpiresAt
}

// RequestURI returns the full RFC 9126 request_uri value for this PAR entry.
func (p *PARRequest) RequestURI() string {
	return "urn:ietf:params:oauth:request_uri:" + p.Reference
}

// PARResponse is the JSON body returned from POST /oauth/par (RFC 9126 §2.2).
type PARResponse struct {
	// RequestURI is the reference to the pushed authorization request.
	// The client passes this as request_uri to the authorization endpoint.
	RequestURI string `json:"request_uri"`

	// ExpiresIn is the number of seconds until the request_uri expires.
	ExpiresIn int `json:"expires_in"`
}

// OAuthAuthorizeWithPARRequest extends OAuthAuthorizeRequest to also accept a
// request_uri parameter for the PAR flow (RFC 9126 §4).
// When request_uri is present the other parameters are optional because they
// were already submitted and validated at the PAR endpoint.
type OAuthAuthorizeWithPARRequest struct {
	// ClientID is always required even in the PAR flow (RFC 9126 §4).
	ClientID string `form:"client_id" binding:"required"`

	// RequestURI is set when the client uses PAR.
	RequestURI string `form:"request_uri"`

	// Standard parameters — used when request_uri is absent.
	ResponseType        string `form:"response_type"`
	RedirectURI         string `form:"redirect_uri"`
	Scope               string `form:"scope"`
	State               string `form:"state"`
	Nonce               string `form:"nonce"`
	CodeChallenge       string `form:"code_challenge"`
	CodeChallengeMethod string `form:"code_challenge_method"`
	Display             string `form:"display"`
	Prompt              string `form:"prompt"`

	// RAR (RFC 9396)
	AuthorizationDetails string `form:"authorization_details"`
}

// UserInfoResponse represents the OIDC UserInfo response
type UserInfoResponse struct {
	Sub               string   `json:"sub"`
	Name              string   `json:"name,omitempty"`
	GivenName         string   `json:"given_name,omitempty"`
	FamilyName        string   `json:"family_name,omitempty"`
	PreferredUsername string   `json:"preferred_username,omitempty"`
	Email             string   `json:"email,omitempty"`
	EmailVerified     bool     `json:"email_verified,omitempty"`
	Picture           string   `json:"picture,omitempty"`
	Locale            string   `json:"locale,omitempty"`
	ZoneInfo          string   `json:"zoneinfo,omitempty"`
	UpdatedAt         int64    `json:"updated_at,omitempty"`
	Groups            []string `json:"groups,omitempty"`
	Roles             []string `json:"roles,omitempty"`
}

// JWKSet represents a JSON Web Key Set
type JWKSet struct {
	Keys []JWK `json:"keys"`
}

// JWK represents a JSON Web Key
type JWK struct {
	Kty string `json:"kty"`           // Key type (e.g., "RSA")
	Use string `json:"use,omitempty"` // Key use (e.g., "sig" for signature)
	Kid string `json:"kid,omitempty"` // Key ID
	Alg string `json:"alg,omitempty"` // Algorithm (e.g., "RS256")
	N   string `json:"n,omitempty"`   // RSA public key modulus (base64url)
	E   string `json:"e,omitempty"`   // RSA public key exponent (base64url)
	X   string `json:"x,omitempty"`   // EC x coordinate (for EC keys)
	Y   string `json:"y,omitempty"`   // EC y coordinate (for EC keys)
	Crv string `json:"crv,omitempty"` // EC curve name (for EC keys)
}

// OAuthConsent represents a user's consent for an OAuth client
type OAuthConsent struct {
	ID        uuid.UUID  `json:"id" db:"id"`
	UserID    uuid.UUID  `json:"user_id" db:"user_id"`
	ClientID  uuid.UUID  `json:"client_id" db:"client_id"`
	Scopes    []string   `json:"scopes" db:"scopes"`
	GrantedAt time.Time  `json:"granted_at" db:"granted_at"`
	ExpiresAt *time.Time `json:"expires_at,omitempty" db:"expires_at"`
	RevokedAt *time.Time `json:"revoked_at,omitempty" db:"revoked_at"`
}

// OAuthConsentEnriched is the wire shape returned by
// GET /api/v1/auth/oauth-consents — joins iam_oauth_consents with
// iam_oauth_clients + iam_oauth_tokens so the user-facing "Connected
// Apps" page can render name / icon / category / last-used without
// chasing client-by-client lookups.
//
// `ClientUUID` is the canonical key for the revoke endpoint
// (DELETE /api/v1/auth/oauth-consents/:client_uuid). `ClientID` keeps
// the human-readable slug ("svc-accounts") for display. Category is
// derived from iam_oauth_clients.is_first_party (true→official,
// false→third_party) — the table doesn't store a per-app developer
// string, so the page falls back to the client_name for that field.
type OAuthConsentEnriched struct {
	ID         uuid.UUID  `json:"id"`
	ClientUUID uuid.UUID  `json:"client_uuid"`
	ClientID   string     `json:"client_id"`
	Name       string     `json:"name"`
	IconURL    *string    `json:"icon_url"`
	Category   string     `json:"category"` // "official" | "third_party"
	Scopes     []string   `json:"scopes"`
	GrantedAt  time.Time  `json:"granted_at"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`
	LastUsedAt *time.Time `json:"last_used_at"`
}

// ConsentRequest represents a consent request shown to the user
type ConsentRequest struct {
	ClientID            string   `json:"client_id"`
	ClientName          string   `json:"client_name"`
	ClientLogo          string   `json:"client_logo,omitempty"`
	RedirectURI         string   `json:"redirect_uri"`
	RequestedScopes     []string `json:"requested_scopes"`
	State               string   `json:"state"`
	Nonce               string   `json:"nonce,omitempty"`
	CodeChallenge       string   `json:"code_challenge,omitempty"`
	CodeChallengeMethod string   `json:"code_challenge_method,omitempty"`
}

// ConsentResponse represents the user's consent decision
type ConsentResponse struct {
	Approved bool     `json:"approved"`
	Scopes   []string `json:"scopes"` // Scopes the user approved
	State    string   `json:"state"`
}
