// SPDX-License-Identifier: AGPL-3.0-or-later

package models

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// socialProviderTypes is the set of provider types that default to showing as a
// login button when no explicit override is set.
var socialProviderTypes = map[string]bool{
	"google":    true,
	"microsoft": true,
	"github":    true,
	"apple":     true,
	"linkedin":  true,
	"oauth":     true,
	"oidc":      true,
}

// IDPTenantOverride is an exported identifier.
// IDPTenantOverride stores per-tenant customisation for a shared/platform identity
// provider.  Fields are nullable: NULL means "inherit the underlying provider
// default".  This follows the Auth0 Organization Connections pattern.
type IDPTenantOverride struct {
	ID         uuid.UUID `json:"id"          db:"id"`
	TenantID   uuid.UUID `json:"tenant_id"   db:"tenant_id"`
	ProviderID uuid.UUID `json:"provider_id" db:"provider_id"`
	IsEnabled  bool      `json:"is_enabled"  db:"is_enabled"`
	// DisplayName overrides the provider's display name for this tenant.
	// NULL means use the provider's own display_name.
	DisplayName *string `json:"display_name,omitempty" db:"display_name"`
	Priority    int     `json:"priority"    db:"priority"`
	// ConfigOverrides holds arbitrary per-tenant JSON config (e.g. custom scopes).
	ConfigOverrides json.RawMessage `json:"config_overrides" db:"config_overrides"`

	// Auth0 Organization Connections pattern fields — NULL = inherit default.

	// AssignMembershipOnLogin: when TRUE, Falcon-ID automatically adds the
	// authenticating user to this tenant on first login via this IDP.
	// When FALSE, the user must already exist in the tenant before login is
	// allowed.  When NULL, the underlying provider's auto_provision_users flag
	// applies.
	AssignMembershipOnLogin *bool `json:"assign_membership_on_login,omitempty" db:"assign_membership_on_login"`

	// IsSignupEnabled: when TRUE, brand-new users may self-register via this
	// IDP for this tenant.  When FALSE, only pre-existing users can log in.
	// When NULL, the provider default applies.
	IsSignupEnabled *bool `json:"is_signup_enabled,omitempty" db:"is_signup_enabled"`

	// ShowAsButton: when TRUE, a login button for this IDP is rendered on the
	// tenant's login page.  When FALSE, the IDP is hidden from the UI (still
	// reachable via HRD or direct link).  When NULL, social providers default
	// to true and enterprise/LDAP providers default to false.
	ShowAsButton *bool `json:"show_as_button,omitempty" db:"show_as_button"`

	CreatedAt time.Time `json:"created_at" db:"created_at"`
	UpdatedAt time.Time `json:"updated_at" db:"updated_at"`
}

// IDPWithOverride is an exported identifier.
// IDPWithOverride is a composite that pairs an IdentityProvider with its optional
// per-tenant override record.  Callers use the Effective* helpers to obtain the
// resolved value, which always applies the NULL-means-inherit rule.
type IDPWithOverride struct {
	Provider *IdentityProvider
	Override *IDPTenantOverride
}

// EffectiveDisplayName returns the display name that should be shown for this
// provider in the context of the given tenant.
func (c *IDPWithOverride) EffectiveDisplayName() string {
	if c.Override != nil && c.Override.DisplayName != nil && *c.Override.DisplayName != "" {
		return *c.Override.DisplayName
	}
	return c.Provider.DisplayName
}

// EffectivePriority returns the sort priority for this provider in the context
// of the given tenant.
func (c *IDPWithOverride) EffectivePriority() int {
	if c.Override != nil {
		return c.Override.Priority
	}
	return c.Provider.Priority
}

// EffectiveIsEnabled returns whether this provider is active for the tenant.
// If an override exists, its IsEnabled field governs.  Otherwise the provider's
// own IsEnabled flag is used.
func (c *IDPWithOverride) EffectiveIsEnabled() bool {
	if c.Override != nil {
		return c.Override.IsEnabled
	}
	return c.Provider.IsEnabled
}

// EffectiveShowAsButton returns whether this IDP should be rendered as a
// button on the login page.  Resolution order:
//  1. Override.ShowAsButton (if non-nil)
//  2. Provider type default: social providers → true, enterprise/LDAP → false
func (c *IDPWithOverride) EffectiveShowAsButton() bool {
	if c.Override != nil && c.Override.ShowAsButton != nil {
		return *c.Override.ShowAsButton
	}
	// NULL: inherit based on provider type
	return socialProviderTypes[c.Provider.Type]
}

// EffectiveSignupEnabled returns whether new-user self-registration is allowed
// via this IDP for the tenant.  Resolution order:
//  1. Override.IsSignupEnabled (if non-nil)
//  2. Provider.AutoProvisionUsers as a reasonable proxy default
func (c *IDPWithOverride) EffectiveSignupEnabled() bool {
	if c.Override != nil && c.Override.IsSignupEnabled != nil {
		return *c.Override.IsSignupEnabled
	}
	// NULL: inherit the provider's AutoProvisionUsers flag as a sensible default
	return c.Provider.AutoProvisionUsers
}

// EffectiveAssignMembership returns whether users should automatically be added
// to the tenant on login via this IDP.  Resolution order:
//  1. Override.AssignMembershipOnLogin (if non-nil)
//  2. Provider.AutoProvisionUsers
func (c *IDPWithOverride) EffectiveAssignMembership() bool {
	if c.Override != nil && c.Override.AssignMembershipOnLogin != nil {
		return *c.Override.AssignMembershipOnLogin
	}
	return c.Provider.AutoProvisionUsers
}

// --- DTOs ---

// UpsertIDPTenantOverrideRequest is the body for both create and update operations
// (the repository implements an upsert on (tenant_id, provider_id)).
type UpsertIDPTenantOverrideRequest struct {
	ProviderID      uuid.UUID       `json:"provider_id"  binding:"required"`
	IsEnabled       bool            `json:"is_enabled"`
	DisplayName     *string         `json:"display_name,omitempty"  binding:"omitempty,max=255"`
	Priority        int             `json:"priority"                binding:"omitempty,min=0,max=1000"`
	ConfigOverrides json.RawMessage `json:"config_overrides,omitempty"`

	AssignMembershipOnLogin *bool `json:"assign_membership_on_login,omitempty"`
	IsSignupEnabled         *bool `json:"is_signup_enabled,omitempty"`
	ShowAsButton            *bool `json:"show_as_button,omitempty"`
}

// IDPTenantOverrideResponse is an exported identifier.
// IDPTenantOverrideResponse is the API response shape for an override record.
type IDPTenantOverrideResponse struct {
	ID              uuid.UUID       `json:"id"`
	TenantID        uuid.UUID       `json:"tenant_id"`
	ProviderID      uuid.UUID       `json:"provider_id"`
	IsEnabled       bool            `json:"is_enabled"`
	DisplayName     *string         `json:"display_name,omitempty"`
	Priority        int             `json:"priority"`
	ConfigOverrides json.RawMessage `json:"config_overrides"`

	AssignMembershipOnLogin *bool `json:"assign_membership_on_login,omitempty"`
	IsSignupEnabled         *bool `json:"is_signup_enabled,omitempty"`
	ShowAsButton            *bool `json:"show_as_button,omitempty"`

	// Resolved effective values for convenience
	EffectiveShowAsButton  bool `json:"effective_show_as_button"`
	EffectiveSignupEnabled bool `json:"effective_signup_enabled"`
	EffectiveAssignMember  bool `json:"effective_assign_membership"`

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// ToResponse converts an IDPWithOverride composite into the API response DTO.
func (c *IDPWithOverride) ToResponse() *IDPTenantOverrideResponse {
	r := &IDPTenantOverrideResponse{
		ProviderID:             c.Provider.ID,
		EffectiveShowAsButton:  c.EffectiveShowAsButton(),
		EffectiveSignupEnabled: c.EffectiveSignupEnabled(),
		EffectiveAssignMember:  c.EffectiveAssignMembership(),
	}

	if c.Override != nil {
		r.ID = c.Override.ID
		r.TenantID = c.Override.TenantID
		r.IsEnabled = c.Override.IsEnabled
		r.DisplayName = c.Override.DisplayName
		r.Priority = c.Override.Priority
		r.ConfigOverrides = c.Override.ConfigOverrides
		r.AssignMembershipOnLogin = c.Override.AssignMembershipOnLogin
		r.IsSignupEnabled = c.Override.IsSignupEnabled
		r.ShowAsButton = c.Override.ShowAsButton
		r.CreatedAt = c.Override.CreatedAt
		r.UpdatedAt = c.Override.UpdatedAt
	}

	return r
}
