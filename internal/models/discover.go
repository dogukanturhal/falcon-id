// SPDX-License-Identifier: AGPL-3.0-or-later

package models

import "github.com/google/uuid"

// DiscoverRequest is the input for the Home Realm Discovery endpoint.
// Given a user's email (and optional client context), the system determines
// which tenant the user belongs to and how they should authenticate.
type DiscoverRequest struct {
	Email    string `json:"email" binding:"required,email"`
	ClientID string `json:"client_id,omitempty"`

	// RealmID scopes the IDP lookup to a specific realm. Populated by
	// the handler from gin context (`realm_id` key, set by
	// middleware.RealmMiddleware) AFTER ShouldBindJSON — the `json:"-"`
	// tag prevents the client from injecting a realm via the request
	// body, which would let an attacker probe IDPs in arbitrary realms.
	// uuid.Nil means "no realm-scoped lookup" (tenant-scoped only),
	// matching the pre-realm behaviour.
	RealmID uuid.UUID `json:"-"`
}

// DiscoverProvider represents an identity provider available for a tenant.
// Only redirect-based providers (OAuth, SAML, OIDC) are included — directory
// providers (LDAP) authenticate transparently via the password form.
type DiscoverProvider struct {
	ID          string `json:"id"`
	Type        string `json:"type"`         // saml, oidc, google, microsoft, github, etc.
	Name        string `json:"name"`         // Internal provider name / slug
	DisplayName string `json:"display_name"` // Human-readable name shown in UI
}

// DiscoverBranding contains visual customisation for the login screen.
// All fields are optional; nil means use platform defaults.
type DiscoverBranding struct {
	LogoURL         *string `json:"logo_url,omitempty"`
	PrimaryColor    string  `json:"primary_color"`
	BackgroundColor string  `json:"background_color"`
	LoginTitle      *string `json:"login_title,omitempty"`
	LoginSubtitle   *string `json:"login_subtitle,omitempty"`
	LoginMessage    *string `json:"login_message,omitempty"`
}

// DiscoverResponse is the output of the Home Realm Discovery endpoint.
// The login UI uses this to decide which screen or redirect to show.
//
// AuthMethod values:
//   - "sso"           — redirect to SSO provider immediately (SAML/OIDC enforced)
//   - "password"      — show password field; user account exists
//   - "signup"        — user is unknown; show sign-up flow
//   - "contact_admin" — domain is claimed but auto-enrol is off; user must contact IT
type DiscoverResponse struct {
	// User context
	Email      string `json:"email"`
	EmailKnown bool   `json:"email_known"`

	// Tenant context (set when domain or user maps to a specific tenant)
	TenantID   *string `json:"tenant_id,omitempty"`
	TenantName *string `json:"tenant_name,omitempty"`
	TenantSlug *string `json:"tenant_slug,omitempty"`

	// Auth method to use
	AuthMethod string `json:"auth_method"` // "password", "sso", "signup", "contact_admin"

	// SSO fields (populated when auth_method == "sso")
	SSOProviderID   *string `json:"sso_provider_id,omitempty"`
	SSOProviderType *string `json:"sso_provider_type,omitempty"` // "saml", "oidc", "google", "microsoft"
	SSOProviderName *string `json:"sso_provider_name,omitempty"`

	// All providers available to the tenant (for showing social login buttons, etc.)
	AvailableProviders []DiscoverProvider `json:"available_providers,omitempty"`

	// Login screen customisation (populated when tenant branding exists)
	Branding *DiscoverBranding `json:"branding,omitempty"`

	// IDP routing (populated when email domain maps to an IDP via routing rules)
	IdentityProviderID   *string `json:"identity_provider_id,omitempty"`
	IdentityProviderType *string `json:"identity_provider_type,omitempty"`
	LocalAuthDisabled    bool    `json:"local_auth_disabled,omitempty"`

	// Sign-up context (populated when auth_method == "signup")
	AccountType   *string `json:"account_type,omitempty"` // "personal" | "business"
	SignupAllowed bool    `json:"signup_allowed"`

	// Available authenticators on the user's record (populated when
	// EmailKnown=true). The login UI uses these to render the correct
	// input controls:
	//   - HasPasskey  → show "Sign in with passkey / Face ID / Touch ID"
	//     button alongside (or instead of) the password field.
	//   - HasPassword → render the password input.
	// Both false on a known active user means the account is in a
	// degenerate state (no usable credential); the UI should surface
	// "Reset password" + an admin-recovery hint.
	//
	// AuthMethod stays as the PRIMARY suggestion for backwards
	// compatibility, but UIs should prefer these explicit flags when
	// present — they convey "what's actually available" rather than
	// "what we recommend you try first".
	HasPasskey  bool `json:"has_passkey,omitempty"`
	HasPassword bool `json:"has_password,omitempty"`
}
