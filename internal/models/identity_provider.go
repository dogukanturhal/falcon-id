// SPDX-License-Identifier: AGPL-3.0-or-later

package models

import (
	"fmt"
	"time"

	"github.com/google/uuid"
)

// IdentityProvider represents an external identity provider (LDAP/AD, SAML, OAuth, etc.)
type IdentityProvider struct {
	ID          uuid.UUID `json:"id" db:"id"`
	TenantID    uuid.UUID `json:"tenant_id" db:"tenant_id"`
	Type        string    `json:"type" db:"provider_type"` // ldap, saml, oauth, oidc, google, microsoft, github, apple, oauth2
	Name        string    `json:"name" db:"provider_name"`
	DisplayName string    `json:"display_name" db:"display_name"`
	IsEnabled   bool      `json:"is_enabled" db:"is_active"`
	Priority    int       `json:"priority" db:"priority"` // Order of authentication attempt

	// Scope & Realm (IDP consolidation — migration 122)
	Scope     string     `json:"scope" db:"scope"`                 // 'tenant' or 'realm'
	RealmID   *uuid.UUID `json:"realm_id,omitempty" db:"realm_id"` // Set for realm-scoped providers
	IsDefault bool       `json:"is_default" db:"is_default"`       // Auto-select for login

	// OAuth2/OIDC Configuration
	ClientID              *string  `json:"client_id,omitempty" db:"client_id"`
	ClientSecretEncrypted *string  `json:"client_secret_encrypted,omitempty" db:"client_secret_encrypted"`
	AuthorizationURL      *string  `json:"authorization_url,omitempty" db:"authorization_url"`
	TokenURL              *string  `json:"token_url,omitempty" db:"token_url"`
	UserInfoURL           *string  `json:"userinfo_url,omitempty" db:"userinfo_url"`
	Scopes                []string `json:"scopes,omitempty" db:"scopes"`

	// LDAP Configuration (stored as JSON)
	LDAPConfig *LDAPConfig `json:"ldap_config,omitempty" db:"ldap_config"`

	// SAML SP Configuration (stored as JSON) — for inbound SAML federation
	SAMLSPConfig *SAMLSPConfig `json:"saml_sp_config,omitempty" db:"saml_sp_config"`

	// Apple Sign In Configuration (stored as JSON)
	AppleConfig *AppleConfig `json:"apple_config,omitempty" db:"apple_config"`

	// Attribute Mapping for user provisioning
	AttributeMapping map[string]string `json:"attribute_mapping,omitempty" db:"attribute_mapping"`

	// User Provisioning
	AutoProvisionUsers bool        `json:"auto_provision_users" db:"auto_provision_users"`
	DefaultRoleIDs     []uuid.UUID `json:"default_role_ids,omitempty" db:"default_role_ids"`

	// Metadata
	CreatedAt time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt time.Time  `json:"updated_at" db:"updated_at"`
	CreatedBy *uuid.UUID `json:"created_by,omitempty" db:"created_by"`
}

// LDAPConfig represents LDAP-specific configuration
type LDAPConfig struct {
	// Connection
	Host          string `json:"host"`
	Port          int    `json:"port"`
	UseTLS        bool   `json:"use_tls"`
	UseStartTLS   bool   `json:"use_start_tls"`
	SkipTLSVerify bool   `json:"skip_tls_verify"`
	// AllowLegacyTLS opts a single provider OUT of the TLS 1.2 floor down to
	// TLS 1.0, for genuinely legacy AD servers (Windows Server 2012/2012 R2)
	// that cannot negotiate TLS 1.2 over LDAPS. OFF by default — the default
	// floor is TLS 1.2 (negotiating 1.3 when both sides support it). This is
	// an explicit, per-provider, audited escape hatch, NOT a silent global
	// downgrade. SUNSET: remove after 2027-01-01 (Windows Server 2012/2012 R2
	// reached end of extended support 2023-10-10; any provider still requiring
	// this is unpatched and must be upgraded before then).
	AllowLegacyTLS        bool   `json:"allow_legacy_tls,omitempty"`
	BindDN                string `json:"bind_dn"`
	BindPassword          string `json:"bind_password,omitempty"`
	BindPasswordEncrypted string `json:"bind_password_encrypted,omitempty"`
	ServerName            string `json:"server_name,omitempty"` // For TLS certificate verification

	// Search Configuration
	BaseDN          string `json:"base_dn"`
	UserFilter      string `json:"user_filter"`       // e.g., "(&(objectClass=user)(sAMAccountName=%s))"
	UserSearchBase  string `json:"user_search_base"`  // Optional, defaults to BaseDN
	GroupFilter     string `json:"group_filter"`      // e.g., "(&(objectClass=group)(member=%s))"
	GroupSearchBase string `json:"group_search_base"` // Optional, defaults to BaseDN

	// Attribute Mapping
	// UserIDAttr names the IMMUTABLE directory attribute to anchor federation on
	// -- "objectGUID" for Active Directory, "entryUUID" for OpenLDAP. Leave empty
	// to keep anchoring on the DN, which is what this did before.
	//
	// A DN is not a stable identifier: it changes on any rename or OU move, which
	// is routine directory administration. Anchoring on it means a moved user is
	// not recognised (duplicate account, or a silent downgrade to email linking),
	// and a DN later reissued to a different person resolves to the first
	// person's account. The AD-sync subsystem in this repo already anchors on
	// ADObjectGUID; this brings the login path into line.
	UserIDAttr      string `json:"user_id_attr"`      // e.g., "objectGUID" (AD), "entryUUID" (OpenLDAP)
	UsernameAttr    string `json:"username_attr"`     // e.g., "sAMAccountName"
	EmailAttr       string `json:"email_attr"`        // e.g., "mail"
	FirstNameAttr   string `json:"first_name_attr"`   // e.g., "givenName"
	LastNameAttr    string `json:"last_name_attr"`    // e.g., "sn"
	DisplayNameAttr string `json:"display_name_attr"` // e.g., "displayName"
	PhoneAttr       string `json:"phone_attr"`        // e.g., "telephoneNumber"
	DepartmentAttr  string `json:"department_attr"`   // e.g., "department"
	TitleAttr       string `json:"title_attr"`        // e.g., "title"
	GroupAttr       string `json:"group_attr"`        // e.g., "memberOf"

	// Sync Settings
	SyncEnabled      bool              `json:"sync_enabled"`
	SyncInterval     int               `json:"sync_interval"` // In minutes
	SyncGroups       bool              `json:"sync_groups"`
	GroupMappings    map[string]string `json:"group_mappings,omitempty"` // AD group -> Role mapping
	CreateUsers      bool              `json:"create_users"`             // Auto-create users on first login
	UpdateUsers      bool              `json:"update_users"`             // Update user info on login
	DisableLocalAuth bool              `json:"disable_local_auth"`       // Force LDAP authentication
	AutoLinkByEmail  bool              `json:"auto_link_by_email"`       // Link existing local users by email on first LDAP login
}

// OAuth2Config represents OAuth2/OIDC-specific configuration
type OAuth2Config struct {
	// OAuth2 Endpoints
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	AuthURL      string `json:"auth_url"`
	TokenURL     string `json:"token_url"`
	UserInfoURL  string `json:"user_info_url,omitempty"`
	RedirectURI  string `json:"redirect_uri"`

	// Scopes
	Scopes []string `json:"scopes"`

	// Provider-specific settings
	ProviderName string `json:"provider_name"` // "google", "microsoft", "github", "custom"

	// Attribute Mapping
	UserIDAttr      string `json:"user_id_attr"`      // e.g., "sub" for OIDC, "id" for GitHub
	EmailAttr       string `json:"email_attr"`        // e.g., "email"
	FirstNameAttr   string `json:"first_name_attr"`   // e.g., "given_name"
	LastNameAttr    string `json:"last_name_attr"`    // e.g., "family_name"
	DisplayNameAttr string `json:"display_name_attr"` // e.g., "name"
	AvatarAttr      string `json:"avatar_attr"`       // e.g., "picture"

	// User Creation
	CreateUsers bool `json:"create_users"` // Auto-create users on first login
	UpdateUsers bool `json:"update_users"` // Update user info on login
}

// LDAPSyncResult represents the result of an LDAP sync operation
type LDAPSyncResult struct {
	Success       bool      `json:"success"`
	StartedAt     time.Time `json:"started_at"`
	CompletedAt   time.Time `json:"completed_at"`
	Duration      string    `json:"duration"`
	UsersFound    int       `json:"users_found"`
	UsersCreated  int       `json:"users_created"`
	UsersUpdated  int       `json:"users_updated"`
	UsersDisabled int       `json:"users_disabled"`
	GroupsFound   int       `json:"groups_found"`
	GroupsCreated int       `json:"groups_created"`
	GroupsUpdated int       `json:"groups_updated"`
	Errors        []string  `json:"errors,omitempty"`
	Message       string    `json:"message"`
}

// LDAPSyncHistory represents a stored LDAP sync history record
type LDAPSyncHistory struct {
	ID            uuid.UUID  `json:"id"`
	TenantID      uuid.UUID  `json:"tenant_id"`
	ProviderID    uuid.UUID  `json:"provider_id"`
	ProviderName  string     `json:"provider_name"`
	SyncType      string     `json:"sync_type"` // manual, scheduled, full
	Status        string     `json:"status"`    // running, completed, failed
	StartedAt     time.Time  `json:"started_at"`
	CompletedAt   *time.Time `json:"completed_at,omitempty"`
	DurationMs    int64      `json:"duration_ms"`
	UsersFound    int        `json:"users_found"`
	UsersCreated  int        `json:"users_created"`
	UsersUpdated  int        `json:"users_updated"`
	UsersDisabled int        `json:"users_disabled"`
	GroupsFound   int        `json:"groups_found"`
	Errors        []string   `json:"errors,omitempty"`
	Message       string     `json:"message,omitempty"`
	TriggeredBy   *uuid.UUID `json:"triggered_by,omitempty"`
	CreatedAt     time.Time  `json:"created_at"`
}

// CreateIdentityProviderRequest represents a request to create an identity provider
type CreateIdentityProviderRequest struct {
	TenantID    uuid.UUID  `json:"tenant_id"`
	Scope       string     `json:"scope,omitempty"`    // 'tenant' (default) or 'realm'
	RealmID     *uuid.UUID `json:"realm_id,omitempty"` // Required when scope='realm'
	Type        string     `json:"type" binding:"required,oneof=ldap saml oauth oidc google microsoft github apple oauth2"`
	Name        string     `json:"name" binding:"required,min=3,max=255"`
	DisplayName string     `json:"display_name" binding:"required,min=1,max=255"`
	IsEnabled   bool       `json:"is_enabled"`
	IsDefault   bool       `json:"is_default"`
	Priority    int        `json:"priority" binding:"omitempty,min=0,max=1000"`

	// OAuth2/OIDC Configuration
	ClientID         *string  `json:"client_id,omitempty" binding:"omitempty,max=512"`
	ClientSecret     *string  `json:"client_secret,omitempty" binding:"omitempty,max=1024"` // Will be encrypted before storage
	AuthorizationURL *string  `json:"authorization_url,omitempty" binding:"omitempty,url,max=2048"`
	TokenURL         *string  `json:"token_url,omitempty" binding:"omitempty,url,max=2048"`
	UserInfoURL      *string  `json:"userinfo_url,omitempty" binding:"omitempty,url,max=2048"`
	Scopes           []string `json:"scopes,omitempty" binding:"omitempty,max=20"`

	// LDAP Configuration
	LDAPConfig *LDAPConfig `json:"ldap_config,omitempty"`

	// Attribute Mapping
	AttributeMapping map[string]string `json:"attribute_mapping,omitempty"`

	// User Provisioning
	AutoProvisionUsers bool        `json:"auto_provision_users"`
	DefaultRoleIDs     []uuid.UUID `json:"default_role_ids,omitempty" binding:"omitempty,max=50"`
}

// UpdateIdentityProviderRequest represents a request to update an identity provider
type UpdateIdentityProviderRequest struct {
	DisplayName *string `json:"display_name" binding:"omitempty,min=1,max=255"`
	IsEnabled   *bool   `json:"is_enabled"`
	Priority    *int    `json:"priority" binding:"omitempty,min=0,max=1000"`

	// OAuth2/OIDC Configuration
	ClientID         *string  `json:"client_id,omitempty" binding:"omitempty,max=512"`
	ClientSecret     *string  `json:"client_secret,omitempty" binding:"omitempty,max=1024"` // Will be encrypted before storage
	AuthorizationURL *string  `json:"authorization_url,omitempty" binding:"omitempty,url,max=2048"`
	TokenURL         *string  `json:"token_url,omitempty" binding:"omitempty,url,max=2048"`
	UserInfoURL      *string  `json:"userinfo_url,omitempty" binding:"omitempty,url,max=2048"`
	Scopes           []string `json:"scopes,omitempty" binding:"omitempty,max=20"`

	// LDAP Configuration
	LDAPConfig *LDAPConfig `json:"ldap_config,omitempty"`

	// Attribute Mapping
	AttributeMapping map[string]string `json:"attribute_mapping,omitempty"`

	// User Provisioning
	AutoProvisionUsers *bool       `json:"auto_provision_users,omitempty"`
	DefaultRoleIDs     []uuid.UUID `json:"default_role_ids,omitempty" binding:"omitempty,max=50"`
}

// IdentityProviderResponse represents an identity provider response
type IdentityProviderResponse struct {
	ID                 uuid.UUID           `json:"id"`
	TenantID           uuid.UUID           `json:"tenant_id"`
	Scope              string              `json:"scope"`
	RealmID            *uuid.UUID          `json:"realm_id,omitempty"`
	Type               string              `json:"type"`
	Name               string              `json:"name"`
	DisplayName        string              `json:"display_name"`
	IsEnabled          bool                `json:"is_enabled"`
	IsDefault          bool                `json:"is_default"`
	Priority           int                 `json:"priority"`
	AutoProvisionUsers bool                `json:"auto_provision_users"`
	LDAPConfig         *LDAPConfigResponse `json:"ldap_config,omitempty"`
	AttributeMapping   map[string]string   `json:"attribute_mapping,omitempty"`
	CreatedAt          time.Time           `json:"created_at"`
	UpdatedAt          time.Time           `json:"updated_at"`
}

// LDAPConfigResponse is the sanitized LDAP config for responses (no passwords)
type LDAPConfigResponse struct {
	// Connection
	Host          string `json:"host"`
	Port          int    `json:"port"`
	UseTLS        bool   `json:"use_tls"`
	UseStartTLS   bool   `json:"use_start_tls"`
	SkipTLSVerify bool   `json:"skip_tls_verify"`
	ServerName    string `json:"server_name,omitempty"`

	// Search Configuration
	BaseDN          string `json:"base_dn"`
	UserFilter      string `json:"user_filter"`
	UserSearchBase  string `json:"user_search_base,omitempty"`
	GroupFilter     string `json:"group_filter,omitempty"`
	GroupSearchBase string `json:"group_search_base,omitempty"`

	// Attribute Mapping
	UsernameAttr    string `json:"username_attr"`
	EmailAttr       string `json:"email_attr"`
	FirstNameAttr   string `json:"first_name_attr,omitempty"`
	LastNameAttr    string `json:"last_name_attr,omitempty"`
	DisplayNameAttr string `json:"display_name_attr,omitempty"`
	PhoneAttr       string `json:"phone_attr,omitempty"`
	DepartmentAttr  string `json:"department_attr,omitempty"`
	TitleAttr       string `json:"title_attr,omitempty"`
	GroupAttr       string `json:"group_attr,omitempty"`

	// Sync Settings
	SyncEnabled      bool              `json:"sync_enabled"`
	SyncInterval     int               `json:"sync_interval"`
	SyncGroups       bool              `json:"sync_groups"`
	GroupMappings    map[string]string `json:"group_mappings,omitempty"`
	CreateUsers      bool              `json:"create_users"`
	UpdateUsers      bool              `json:"update_users"`
	DisableLocalAuth bool              `json:"disable_local_auth"`
}

// ToResponse converts an IdentityProvider to a response (sanitizing secrets)
func (ip *IdentityProvider) ToResponse() *IdentityProviderResponse {
	resp := &IdentityProviderResponse{
		ID:                 ip.ID,
		TenantID:           ip.TenantID,
		Scope:              ip.Scope,
		RealmID:            ip.RealmID,
		Type:               ip.Type,
		Name:               ip.Name,
		DisplayName:        ip.DisplayName,
		IsEnabled:          ip.IsEnabled,
		IsDefault:          ip.IsDefault,
		Priority:           ip.Priority,
		AutoProvisionUsers: ip.AutoProvisionUsers,
		AttributeMapping:   ip.AttributeMapping,
		CreatedAt:          ip.CreatedAt,
		UpdatedAt:          ip.UpdatedAt,
	}

	// Sanitize LDAP config (remove bind password)
	if ip.LDAPConfig != nil {
		resp.LDAPConfig = &LDAPConfigResponse{
			Host:             ip.LDAPConfig.Host,
			Port:             ip.LDAPConfig.Port,
			UseTLS:           ip.LDAPConfig.UseTLS,
			UseStartTLS:      ip.LDAPConfig.UseStartTLS,
			SkipTLSVerify:    ip.LDAPConfig.SkipTLSVerify,
			ServerName:       ip.LDAPConfig.ServerName,
			BaseDN:           ip.LDAPConfig.BaseDN,
			UserFilter:       ip.LDAPConfig.UserFilter,
			UserSearchBase:   ip.LDAPConfig.UserSearchBase,
			GroupFilter:      ip.LDAPConfig.GroupFilter,
			GroupSearchBase:  ip.LDAPConfig.GroupSearchBase,
			UsernameAttr:     ip.LDAPConfig.UsernameAttr,
			EmailAttr:        ip.LDAPConfig.EmailAttr,
			FirstNameAttr:    ip.LDAPConfig.FirstNameAttr,
			LastNameAttr:     ip.LDAPConfig.LastNameAttr,
			DisplayNameAttr:  ip.LDAPConfig.DisplayNameAttr,
			PhoneAttr:        ip.LDAPConfig.PhoneAttr,
			DepartmentAttr:   ip.LDAPConfig.DepartmentAttr,
			TitleAttr:        ip.LDAPConfig.TitleAttr,
			GroupAttr:        ip.LDAPConfig.GroupAttr,
			SyncEnabled:      ip.LDAPConfig.SyncEnabled,
			SyncInterval:     ip.LDAPConfig.SyncInterval,
			SyncGroups:       ip.LDAPConfig.SyncGroups,
			GroupMappings:    ip.LDAPConfig.GroupMappings,
			CreateUsers:      ip.LDAPConfig.CreateUsers,
			UpdateUsers:      ip.LDAPConfig.UpdateUsers,
			DisableLocalAuth: ip.LDAPConfig.DisableLocalAuth,
		}
	}

	return resp
}

// LoginConfigurationError reports why this provider cannot be used to start a
// login, or nil if it is completely configured.
//
// ONE definition, consulted by both the list that renders login buttons and the
// service that builds the outbound redirect, so the two cannot drift into
// disagreeing about what "usable" means.
//
// The polarity is deliberate: types that legitimately carry no OAuth client
// credentials are EXEMPTED by name, and everything else must be credentialed. A
// provider type added later therefore has to prove it is configured rather than
// being silently exempted by an enumeration nobody updated.
func (p *IdentityProvider) LoginConfigurationError() error {
	switch p.Type {
	case "ldap", "saml":
		// Credentials live in LDAPConfig / SAMLSPConfig, not client_id.
		return nil
	}
	if p.ClientID == nil || *p.ClientID == "" {
		return fmt.Errorf("identity provider %q (%s) has no client_id configured", p.Name, p.Type)
	}
	if p.AuthorizationURL == nil || *p.AuthorizationURL == "" {
		return fmt.Errorf("identity provider %q (%s) has no authorization_url configured", p.Name, p.Type)
	}
	return nil
}

// IsLoginReady reports whether this provider can start a login.
func (p *IdentityProvider) IsLoginReady() bool { return p.LoginConfigurationError() == nil }
