// SPDX-License-Identifier: AGPL-3.0-or-later

package models

import (
	"time"

	"github.com/google/uuid"
)

// IAMSettings represents the IAM service configuration
type IAMSettings struct {
	ID       uuid.UUID `json:"id" db:"id"`
	TenantID uuid.UUID `json:"tenant_id" db:"tenant_id"`

	// LDAP/AD Configuration for HR (Employee Management)
	HRLDAPEnabled      bool   `json:"hr_ldap_enabled" db:"hr_ldap_enabled"`
	HRLDAPServer       string `json:"hr_ldap_server" db:"hr_ldap_server"`
	HRLDAPPort         int    `json:"hr_ldap_port" db:"hr_ldap_port"`
	HRLDAPUseTLS       bool   `json:"hr_ldap_use_tls" db:"hr_ldap_use_tls"`
	HRLDAPBindDN       string `json:"hr_ldap_bind_dn" db:"hr_ldap_bind_dn"`
	HRLDAPBindPassword string `json:"-" db:"hr_ldap_bind_password"` // Never expose in JSON
	HRLDAPBaseDN       string `json:"hr_ldap_base_dn" db:"hr_ldap_base_dn"`
	HRLDAPUserFilter   string `json:"hr_ldap_user_filter" db:"hr_ldap_user_filter"`
	HRLDAPGroupBaseDN  string `json:"hr_ldap_group_base_dn" db:"hr_ldap_group_base_dn"`
	HRLDAPGroupFilter  string `json:"hr_ldap_group_filter" db:"hr_ldap_group_filter"`

	// ABAC/OPA Configuration
	ABACEnabled           bool `json:"abac_enabled" db:"abac_enabled"` // Deprecated: read-only, ignored by authorization; never written
	ABACFallbackRBAC      bool `json:"abac_fallback_rbac" db:"abac_fallback_rbac"`
	RoleExpirationEnabled bool `json:"role_expiration_enabled" db:"role_expiration_enabled"`

	// Metadata
	CreatedAt time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt time.Time  `json:"updated_at" db:"updated_at"`
	UpdatedBy *uuid.UUID `json:"updated_by,omitempty" db:"updated_by"`
}

// GetIAMSettingsResponse represents the response for getting IAM settings
type GetIAMSettingsResponse struct {
	ID       uuid.UUID `json:"id"`
	TenantID uuid.UUID `json:"tenant_id"`

	// LDAP/AD Configuration for HR
	HRLDAPEnabled     bool   `json:"hr_ldap_enabled"`
	HRLDAPServer      string `json:"hr_ldap_server"`
	HRLDAPPort        int    `json:"hr_ldap_port"`
	HRLDAPUseTLS      bool   `json:"hr_ldap_use_tls"`
	HRLDAPBindDN      string `json:"hr_ldap_bind_dn"`
	HRLDAPBaseDN      string `json:"hr_ldap_base_dn"`
	HRLDAPUserFilter  string `json:"hr_ldap_user_filter"`
	HRLDAPGroupBaseDN string `json:"hr_ldap_group_base_dn"`
	HRLDAPGroupFilter string `json:"hr_ldap_group_filter"`
	HasBindPassword   bool   `json:"has_bind_password"` // Indicates if password is set

	// ABAC/OPA Configuration
	ABACEnabled           bool `json:"abac_enabled"` // Deprecated: read-only, ignored
	ABACFallbackRBAC      bool `json:"abac_fallback_rbac"`
	RoleExpirationEnabled bool `json:"role_expiration_enabled"`

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// UpdateIAMSettingsRequest represents a request to update IAM settings
type UpdateIAMSettingsRequest struct {
	// LDAP/AD Configuration for HR
	HRLDAPEnabled      *bool   `json:"hr_ldap_enabled,omitempty"`
	HRLDAPServer       *string `json:"hr_ldap_server,omitempty"`
	HRLDAPPort         *int    `json:"hr_ldap_port,omitempty"`
	HRLDAPUseTLS       *bool   `json:"hr_ldap_use_tls,omitempty"`
	HRLDAPBindDN       *string `json:"hr_ldap_bind_dn,omitempty"`
	HRLDAPBindPassword *string `json:"hr_ldap_bind_password,omitempty"`
	HRLDAPBaseDN       *string `json:"hr_ldap_base_dn,omitempty"`
	HRLDAPUserFilter   *string `json:"hr_ldap_user_filter,omitempty"`
	HRLDAPGroupBaseDN  *string `json:"hr_ldap_group_base_dn,omitempty"`
	HRLDAPGroupFilter  *string `json:"hr_ldap_group_filter,omitempty"`

	// ABAC/OPA Configuration
	ABACEnabled           *bool `json:"abac_enabled,omitempty"` // Deprecated: ignored
	ABACFallbackRBAC      *bool `json:"abac_fallback_rbac,omitempty"`
	RoleExpirationEnabled *bool `json:"role_expiration_enabled,omitempty"`
}

// ToResponse converts IAMSettings to a response (hiding sensitive data)
func (s *IAMSettings) ToResponse() *GetIAMSettingsResponse {
	return &GetIAMSettingsResponse{
		ID:                    s.ID,
		TenantID:              s.TenantID,
		HRLDAPEnabled:         s.HRLDAPEnabled,
		HRLDAPServer:          s.HRLDAPServer,
		HRLDAPPort:            s.HRLDAPPort,
		HRLDAPUseTLS:          s.HRLDAPUseTLS,
		HRLDAPBindDN:          s.HRLDAPBindDN,
		HRLDAPBaseDN:          s.HRLDAPBaseDN,
		HRLDAPUserFilter:      s.HRLDAPUserFilter,
		HRLDAPGroupBaseDN:     s.HRLDAPGroupBaseDN,
		HRLDAPGroupFilter:     s.HRLDAPGroupFilter,
		HasBindPassword:       s.HRLDAPBindPassword != "",
		ABACEnabled:           s.ABACEnabled,
		ABACFallbackRBAC:      s.ABACFallbackRBAC,
		RoleExpirationEnabled: s.RoleExpirationEnabled,
		CreatedAt:             s.CreatedAt,
		UpdatedAt:             s.UpdatedAt,
	}
}
