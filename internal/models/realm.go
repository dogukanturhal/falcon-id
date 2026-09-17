// SPDX-License-Identifier: AGPL-3.0-or-later

package models

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// RealmType represents the type of authentication realm
type RealmType string

const (
	// RealmTypePlatform is an exported identifier.
	RealmTypePlatform RealmType = "platform" // HexxLock internal administration
	// RealmTypeEnterprise is an exported identifier.
	RealmTypeEnterprise RealmType = "enterprise" // Large customers with dedicated realm
	// RealmTypeShared is an exported identifier.
	RealmTypeShared RealmType = "shared" // Multiple SMB tenants in single realm
	// RealmTypePartner is an exported identifier.
	RealmTypePartner RealmType = "partner" // Partner organizations with co-managed users
	// RealmTypeSandbox is an exported identifier.
	RealmTypeSandbox RealmType = "sandbox" // Development/testing realms
)

// RealmStatus represents the operational status of a realm
type RealmStatus string

const (
	// RealmStatusActive is an exported identifier.
	RealmStatusActive RealmStatus = "active" // Operational
	// RealmStatusSuspended is an exported identifier.
	RealmStatusSuspended RealmStatus = "suspended" // Temporarily disabled
	// RealmStatusMigrating is an exported identifier.
	RealmStatusMigrating RealmStatus = "migrating" // In transition
	// RealmStatusArchived is an exported identifier.
	RealmStatusArchived RealmStatus = "archived" // Soft deleted
)

// RealmAdminRole represents the role of an admin within a realm
type RealmAdminRole string

const (
	// RealmAdminRoleOwner is an exported identifier.
	RealmAdminRoleOwner RealmAdminRole = "realm_owner" // Full control
	// RealmAdminRoleAdmin is an exported identifier.
	RealmAdminRoleAdmin RealmAdminRole = "realm_admin" // Manage realm settings
	// RealmAdminRoleViewer is an exported identifier.
	RealmAdminRoleViewer RealmAdminRole = "realm_viewer" // Read-only access
)

// Realm represents an authentication domain with complete isolation
type Realm struct {
	ID          uuid.UUID   `json:"id" db:"id"`
	Slug        string      `json:"slug" db:"slug"`
	DisplayName string      `json:"display_name" db:"display_name"`
	Type        RealmType   `json:"type" db:"type"`
	Status      RealmStatus `json:"status" db:"status"`

	// Isolation configuration
	DatabaseConnectionID *uuid.UUID `json:"database_connection_id,omitempty" db:"database_connection_id"`
	SchemaName           *string    `json:"schema_name,omitempty" db:"schema_name"`

	// Realm settings
	Settings json.RawMessage `json:"settings" db:"settings"`
	Branding json.RawMessage `json:"branding" db:"branding"`
	Features json.RawMessage `json:"features" db:"features"`

	// Limits and quotas
	MaxTenants        *int `json:"max_tenants,omitempty" db:"max_tenants"`
	MaxUsersPerTenant *int `json:"max_users_per_tenant,omitempty" db:"max_users_per_tenant"`
	MaxTotalUsers     *int `json:"max_total_users,omitempty" db:"max_total_users"`

	// Metadata
	CreatedAt time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt time.Time  `json:"updated_at" db:"updated_at"`
	CreatedBy *uuid.UUID `json:"created_by,omitempty" db:"created_by"`

	// Related data (not in DB)
	SecurityPolicy    *RealmSecurityPolicy    `json:"security_policy,omitempty"`
	IdentityProviders []RealmIdentityProvider `json:"identity_providers,omitempty"`
	TenantCount       int                     `json:"tenant_count,omitempty"`
	UserCount         int                     `json:"user_count,omitempty"`
}

// RealmBranding represents the visual customization for a realm
type RealmBranding struct {
	LogoURL            *string `json:"logo_url,omitempty"`
	FaviconURL         *string `json:"favicon_url,omitempty"`
	PrimaryColor       string  `json:"primary_color"`
	SecondaryColor     string  `json:"secondary_color"`
	LoginBackgroundURL *string `json:"login_background_url,omitempty"`
	CustomCSS          *string `json:"custom_css,omitempty"`
}

// RealmFeatures represents the feature flags for a realm
type RealmFeatures struct {
	MFAAvailable  bool `json:"mfa_available"`
	SSOAvailable  bool `json:"sso_available"`
	APIAccess     bool `json:"api_access"`
	CustomDomain  bool `json:"custom_domain"`
	AdvancedAudit bool `json:"advanced_audit"`
}

// RealmSecurityPolicy represents the security configuration for a realm
type RealmSecurityPolicy struct {
	ID      uuid.UUID `json:"id" db:"id"`
	RealmID uuid.UUID `json:"realm_id" db:"realm_id"`

	// Password policy
	PasswordMinLength        int     `json:"password_min_length" db:"password_min_length"`
	PasswordMaxLength        int     `json:"password_max_length" db:"password_max_length"`
	PasswordRequireUppercase bool    `json:"password_require_uppercase" db:"password_require_uppercase"`
	PasswordRequireLowercase bool    `json:"password_require_lowercase" db:"password_require_lowercase"`
	PasswordRequireDigits    bool    `json:"password_require_digits" db:"password_require_digits"`
	PasswordRequireSpecial   bool    `json:"password_require_special" db:"password_require_special"`
	PasswordSpecialChars     *string `json:"password_special_chars,omitempty" db:"password_special_chars"`
	PasswordMaxAgeDays       *int    `json:"password_max_age_days,omitempty" db:"password_max_age_days"`
	PasswordHistoryCount     *int    `json:"password_history_count,omitempty" db:"password_history_count"`
	PasswordMinAgeHours      *int    `json:"password_min_age_hours,omitempty" db:"password_min_age_hours"`

	// MFA policy
	MFARequired           bool            `json:"mfa_required" db:"mfa_required"`
	MFARequiredForAdmins  bool            `json:"mfa_required_for_admins" db:"mfa_required_for_admins"`
	MFAMethods            json.RawMessage `json:"mfa_methods" db:"mfa_methods"`
	MFAGracePeriodDays    *int            `json:"mfa_grace_period_days,omitempty" db:"mfa_grace_period_days"`
	MFARememberDeviceDays *int            `json:"mfa_remember_device_days,omitempty" db:"mfa_remember_device_days"`
	// Per-user "Remind me later" skip budget during the grace period.
	// 0 (default) = no skip button rendered (grace counts down on calendar
	// time only). > 0 = user may bypass the enrollment interrupt up to N
	// times before hard-block. Matches Entra Registration Campaign's
	// "snooze count" pattern. See migration 235.
	MFAEnrollmentMaxSkips int `json:"mfa_enrollment_max_skips" db:"mfa_enrollment_max_skips"`

	// Session policy
	SessionMaxLifetimeHours     int  `json:"session_max_lifetime_hours" db:"session_max_lifetime_hours"`
	SessionIdleTimeoutMinutes   int  `json:"session_idle_timeout_minutes" db:"session_idle_timeout_minutes"`
	SessionAbsoluteTimeoutHours *int `json:"session_absolute_timeout_hours,omitempty" db:"session_absolute_timeout_hours"`
	ConcurrentSessionsLimit     *int `json:"concurrent_sessions_limit,omitempty" db:"concurrent_sessions_limit"`
	SingleSessionPerDevice      bool `json:"single_session_per_device" db:"single_session_per_device"`

	// Refresh-token rotation grace window (migration 209). Auth0's "leeway"
	// / Okta's "grace period". NULL = use global REFRESH_TOKEN_ROTATION_GRACE.
	// Positive value overrides per-realm. See isWithinRotationGrace in
	// internal/services/token_service_validation.go.
	RefreshTokenRotationGraceSeconds *int `json:"refresh_token_rotation_grace_seconds,omitempty" db:"refresh_token_rotation_grace_seconds"`

	// Lockout policy
	MaxFailedAttempts             int  `json:"max_failed_attempts" db:"max_failed_attempts"`
	LockoutDurationMinutes        int  `json:"lockout_duration_minutes" db:"lockout_duration_minutes"`
	LockoutThresholdWindowMinutes int  `json:"lockout_threshold_window_minutes" db:"lockout_threshold_window_minutes"`
	ProgressiveLockout            bool `json:"progressive_lockout" db:"progressive_lockout"`

	// IP restrictions
	IPWhitelist     json.RawMessage `json:"ip_whitelist,omitempty" db:"ip_whitelist"`
	IPBlacklist     json.RawMessage `json:"ip_blacklist,omitempty" db:"ip_blacklist"`
	GeoRestrictions json.RawMessage `json:"geo_restrictions,omitempty" db:"geo_restrictions"`

	// Risk-based authentication
	RiskAuthenticationEnabled bool `json:"risk_authentication_enabled" db:"risk_authentication_enabled"`
	RiskThresholdLow          int  `json:"risk_threshold_low" db:"risk_threshold_low"`
	RiskThresholdMedium       int  `json:"risk_threshold_medium" db:"risk_threshold_medium"`
	RiskThresholdHigh         int  `json:"risk_threshold_high" db:"risk_threshold_high"`

	// Audit settings
	AuditRetentionDays       int  `json:"audit_retention_days" db:"audit_retention_days"`
	AuditLogFailedLogins     bool `json:"audit_log_failed_logins" db:"audit_log_failed_logins"`
	AuditLogSuccessfulLogins bool `json:"audit_log_successful_logins" db:"audit_log_successful_logins"`
	AuditLogAdminActions     bool `json:"audit_log_admin_actions" db:"audit_log_admin_actions"`

	CreatedAt time.Time `json:"created_at" db:"created_at"`
	UpdatedAt time.Time `json:"updated_at" db:"updated_at"`
}

// RealmIdentityProvider represents an identity provider configured for a realm
type RealmIdentityProvider struct {
	ID          uuid.UUID `json:"id" db:"id"`
	RealmID     uuid.UUID `json:"realm_id" db:"realm_id"`
	Name        string    `json:"name" db:"name"`
	DisplayName string    `json:"display_name" db:"display_name"`
	Type        string    `json:"type" db:"type"` // ldap, oauth2, saml, oidc
	IsEnabled   bool      `json:"is_enabled" db:"is_enabled"`
	IsDefault   bool      `json:"is_default" db:"is_default"`
	Priority    int       `json:"priority" db:"priority"`

	// Configuration (sensitive values encrypted)
	Config           json.RawMessage `json:"config" db:"config"`
	AttributeMapping json.RawMessage `json:"attribute_mapping" db:"attribute_mapping"`

	// Sync settings
	SyncEnabled     bool       `json:"sync_enabled" db:"sync_enabled"`
	SyncInterval    *int       `json:"sync_interval_minutes,omitempty" db:"sync_interval_minutes"`
	LastSyncAt      *time.Time `json:"last_sync_at,omitempty" db:"last_sync_at"`
	LastSyncStatus  *string    `json:"last_sync_status,omitempty" db:"last_sync_status"`
	LastSyncMessage *string    `json:"last_sync_message,omitempty" db:"last_sync_message"`

	// Provisioning
	AutoProvisionUsers  bool `json:"auto_provision_users" db:"auto_provision_users"`
	AutoUpdateUsers     bool `json:"auto_update_users" db:"auto_update_users"`
	AutoDeactivateUsers bool `json:"auto_deactivate_users" db:"auto_deactivate_users"`

	CreatedAt time.Time `json:"created_at" db:"created_at"`
	UpdatedAt time.Time `json:"updated_at" db:"updated_at"`
}

// TenantIdentityProviderSummary represents a tenant-scoped IDP shown in realm context.
type TenantIdentityProviderSummary struct {
	ID          uuid.UUID `json:"id"`
	TenantID    uuid.UUID `json:"tenant_id"`
	TenantName  string    `json:"tenant_name"`
	TenantSlug  string    `json:"tenant_slug"`
	Type        string    `json:"type"`
	Name        string    `json:"name"`
	DisplayName string    `json:"display_name"`
	IsEnabled   bool      `json:"is_enabled"`
	Priority    int       `json:"priority"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// RealmTenant represents the mapping between a tenant and its realm
type RealmTenant struct {
	RealmID         uuid.UUID  `json:"realm_id" db:"realm_id"`
	TenantID        uuid.UUID  `json:"tenant_id" db:"tenant_id"`
	AssignedAt      time.Time  `json:"assigned_at" db:"assigned_at"`
	AssignedBy      *uuid.UUID `json:"assigned_by,omitempty" db:"assigned_by"`
	PreviousRealmID *uuid.UUID `json:"previous_realm_id,omitempty" db:"previous_realm_id"`
	MigratedAt      *time.Time `json:"migrated_at,omitempty" db:"migrated_at"`
}

// RealmAdminAssignment represents a platform admin's permissions within a realm
type RealmAdminAssignment struct {
	ID               uuid.UUID       `json:"id" db:"id"`
	RealmID          uuid.UUID       `json:"realm_id" db:"realm_id"`
	AdminID          uuid.UUID       `json:"admin_id" db:"admin_id"`
	Role             RealmAdminRole  `json:"role" db:"role"`
	Permissions      json.RawMessage `json:"permissions" db:"permissions"`
	AllowedTenantIDs json.RawMessage `json:"allowed_tenant_ids,omitempty" db:"allowed_tenant_ids"`
	CreatedAt        time.Time       `json:"created_at" db:"created_at"`
	CreatedBy        *uuid.UUID      `json:"created_by,omitempty" db:"created_by"`
}

// RealmAuditLog represents an audit entry for realm operations
type RealmAuditLog struct {
	ID             uuid.UUID  `json:"id" db:"id"`
	RealmID        uuid.UUID  `json:"realm_id" db:"realm_id"`
	AdminID        *uuid.UUID `json:"admin_id,omitempty" db:"admin_id"`
	AdminEmail     *string    `json:"admin_email,omitempty" db:"admin_email"`
	Action         string     `json:"action" db:"action"`
	ActionCategory *string    `json:"action_category,omitempty" db:"action_category"`
	TargetType     *string    `json:"target_type,omitempty" db:"target_type"`
	TargetID       *uuid.UUID `json:"target_id,omitempty" db:"target_id"`
	TenantID       *uuid.UUID `json:"tenant_id,omitempty" db:"tenant_id"`
	RequestIP      *string    `json:"request_ip,omitempty" db:"request_ip"`
	UserAgent      *string    `json:"user_agent,omitempty" db:"user_agent"`
	RequestMethod  *string    `json:"request_method,omitempty" db:"request_method"`
	RequestPath    *string    `json:"request_path,omitempty" db:"request_path"`
	Details        *string    `json:"details,omitempty" db:"details"`
	PreviousValue  *string    `json:"previous_value,omitempty" db:"previous_value"`
	NewValue       *string    `json:"new_value,omitempty" db:"new_value"`
	CreatedAt      time.Time  `json:"created_at" db:"created_at"`
}

// RealmDomain represents a custom domain mapped to a realm
type RealmDomain struct {
	ID                      uuid.UUID  `json:"id" db:"id"`
	RealmID                 uuid.UUID  `json:"realm_id" db:"realm_id"`
	Domain                  string     `json:"domain" db:"domain"`
	IsPrimary               bool       `json:"is_primary" db:"is_primary"`
	IsVerified              bool       `json:"is_verified" db:"is_verified"`
	VerificationToken       *string    `json:"verification_token,omitempty" db:"verification_token"`
	VerificationMethod      *string    `json:"verification_method,omitempty" db:"verification_method"`
	VerifiedAt              *time.Time `json:"verified_at,omitempty" db:"verified_at"`
	SSLEnabled              bool       `json:"ssl_enabled" db:"ssl_enabled"`
	SSLCertificateExpiresAt *time.Time `json:"ssl_certificate_expires_at,omitempty" db:"ssl_certificate_expires_at"`
	CreatedAt               time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt               time.Time  `json:"updated_at" db:"updated_at"`
}

// ==================== Request/Response DTOs ====================

// CreateRealmRequest represents a request to create a new realm
type CreateRealmRequest struct {
	Slug              string         `json:"slug" binding:"required,min=2,max=63"`
	DisplayName       string         `json:"display_name" binding:"required,min=1,max=255"`
	Type              RealmType      `json:"type" binding:"required,oneof=platform enterprise shared partner sandbox"`
	Settings          *RealmSettings `json:"settings,omitempty"`
	Branding          *RealmBranding `json:"branding,omitempty"`
	MaxTenants        *int           `json:"max_tenants,omitempty"`
	MaxUsersPerTenant *int           `json:"max_users_per_tenant,omitempty"`
	MaxTotalUsers     *int           `json:"max_total_users,omitempty"`
}

// RealmSettings represents configurable settings for a realm
type RealmSettings struct {
	Description       string `json:"description,omitempty"`
	DefaultLanguage   string `json:"default_language,omitempty"`
	DefaultTimezone   string `json:"default_timezone,omitempty"`
	SupportEmail      string `json:"support_email,omitempty"`
	TermsOfServiceURL string `json:"terms_of_service_url,omitempty"`
	PrivacyPolicyURL  string `json:"privacy_policy_url,omitempty"`
}

// UpdateRealmRequest represents a request to update an existing realm
type UpdateRealmRequest struct {
	DisplayName       *string        `json:"display_name,omitempty"`
	Settings          *RealmSettings `json:"settings,omitempty"`
	Branding          *RealmBranding `json:"branding,omitempty"`
	Features          *RealmFeatures `json:"features,omitempty"`
	MaxTenants        *int           `json:"max_tenants,omitempty"`
	MaxUsersPerTenant *int           `json:"max_users_per_tenant,omitempty"`
	MaxTotalUsers     *int           `json:"max_total_users,omitempty"`
}

// UpdateRealmSecurityPolicyRequest represents a request to update realm security policy
type UpdateRealmSecurityPolicyRequest struct {
	// Password policy
	PasswordMinLength        *int    `json:"password_min_length,omitempty"`
	PasswordMaxLength        *int    `json:"password_max_length,omitempty"`
	PasswordRequireUppercase *bool   `json:"password_require_uppercase,omitempty"`
	PasswordRequireLowercase *bool   `json:"password_require_lowercase,omitempty"`
	PasswordRequireDigits    *bool   `json:"password_require_digits,omitempty"`
	PasswordRequireSpecial   *bool   `json:"password_require_special,omitempty"`
	PasswordSpecialChars     *string `json:"password_special_chars,omitempty"`
	PasswordMaxAgeDays       *int    `json:"password_max_age_days,omitempty"`
	PasswordHistoryCount     *int    `json:"password_history_count,omitempty"`

	// MFA policy
	MFARequired           *bool    `json:"mfa_required,omitempty"`
	MFARequiredForAdmins  *bool    `json:"mfa_required_for_admins,omitempty"`
	MFAMethods            []string `json:"mfa_methods,omitempty"`
	MFAGracePeriodDays    *int     `json:"mfa_grace_period_days,omitempty"`
	MFARememberDeviceDays *int     `json:"mfa_remember_device_days,omitempty"`
	MFAEnrollmentMaxSkips *int     `json:"mfa_enrollment_max_skips,omitempty"`

	// Session policy
	SessionMaxLifetimeHours   *int  `json:"session_max_lifetime_hours,omitempty"`
	SessionIdleTimeoutMinutes *int  `json:"session_idle_timeout_minutes,omitempty"`
	ConcurrentSessionsLimit   *int  `json:"concurrent_sessions_limit,omitempty"`
	SingleSessionPerDevice    *bool `json:"single_session_per_device,omitempty"`

	// Lockout policy
	MaxFailedAttempts      *int  `json:"max_failed_attempts,omitempty"`
	LockoutDurationMinutes *int  `json:"lockout_duration_minutes,omitempty"`
	ProgressiveLockout     *bool `json:"progressive_lockout,omitempty"`

	// IP restrictions
	IPWhitelist     []string `json:"ip_whitelist,omitempty"`
	IPBlacklist     []string `json:"ip_blacklist,omitempty"`
	GeoRestrictions []string `json:"geo_restrictions,omitempty"`
}

// CreateRealmIdentityProviderRequest represents a request to add an IDP to a realm
type CreateRealmIdentityProviderRequest struct {
	Name               string                 `json:"name" binding:"required"`
	DisplayName        string                 `json:"display_name" binding:"required"`
	Type               string                 `json:"type" binding:"required,oneof=ldap oauth2 saml oidc"`
	IsEnabled          *bool                  `json:"is_enabled,omitempty"`
	IsDefault          *bool                  `json:"is_default,omitempty"`
	Priority           *int                   `json:"priority,omitempty"`
	Config             map[string]interface{} `json:"config" binding:"required"`
	AttributeMapping   map[string]string      `json:"attribute_mapping,omitempty"`
	SyncEnabled        *bool                  `json:"sync_enabled,omitempty"`
	SyncInterval       *int                   `json:"sync_interval_minutes,omitempty"`
	AutoProvisionUsers *bool                  `json:"auto_provision_users,omitempty"`
	AutoUpdateUsers    *bool                  `json:"auto_update_users,omitempty"`
}

// AssignTenantToRealmRequest represents a request to assign a tenant to a realm
type AssignTenantToRealmRequest struct {
	TenantID uuid.UUID `json:"tenant_id" binding:"required"`
}

// MigrateTenantRequest represents a request to migrate a tenant between realms
type MigrateTenantRequest struct {
	TenantID      uuid.UUID `json:"tenant_id" binding:"required"`
	TargetRealmID uuid.UUID `json:"target_realm_id" binding:"required"`
}

// AssignRealmAdminRequest represents a request to assign an admin to a realm
type AssignRealmAdminRequest struct {
	AdminID          uuid.UUID      `json:"admin_id" binding:"required"`
	Role             RealmAdminRole `json:"role" binding:"required,oneof=realm_owner realm_admin realm_viewer"`
	Permissions      []string       `json:"permissions,omitempty"`
	AllowedTenantIDs []uuid.UUID    `json:"allowed_tenant_ids,omitempty"`
}

// UpdateRealmIdentityProviderRequest represents a request to update an IDP in a realm
type UpdateRealmIdentityProviderRequest struct {
	Name                *string                `json:"name,omitempty"`
	DisplayName         *string                `json:"display_name,omitempty"`
	IsEnabled           *bool                  `json:"is_enabled,omitempty"`
	IsDefault           *bool                  `json:"is_default,omitempty"`
	Priority            *int                   `json:"priority,omitempty"`
	Config              map[string]interface{} `json:"config,omitempty"`
	AttributeMapping    map[string]string      `json:"attribute_mapping,omitempty"`
	SyncEnabled         *bool                  `json:"sync_enabled,omitempty"`
	SyncInterval        *int                   `json:"sync_interval_minutes,omitempty"`
	AutoProvisionUsers  *bool                  `json:"auto_provision_users,omitempty"`
	AutoUpdateUsers     *bool                  `json:"auto_update_users,omitempty"`
	AutoDeactivateUsers *bool                  `json:"auto_deactivate_users,omitempty"`
}

// AddRealmDomainRequest represents a request to add a custom domain to a realm
type AddRealmDomainRequest struct {
	Domain             string `json:"domain" binding:"required"`
	IsPrimary          *bool  `json:"is_primary,omitempty"`
	VerificationMethod string `json:"verification_method,omitempty"` // dns_txt, dns_cname, http_file
}

// ==================== Response DTOs ====================

// RealmResponse represents the API response for a realm
type RealmResponse struct {
	ID                uuid.UUID                    `json:"id"`
	Slug              string                       `json:"slug"`
	DisplayName       string                       `json:"display_name"`
	Type              RealmType                    `json:"type"`
	Status            RealmStatus                  `json:"status"`
	Settings          json.RawMessage              `json:"settings,omitempty"`
	Branding          json.RawMessage              `json:"branding,omitempty"`
	Features          json.RawMessage              `json:"features,omitempty"`
	MaxTenants        *int                         `json:"max_tenants,omitempty"`
	MaxUsersPerTenant *int                         `json:"max_users_per_tenant,omitempty"`
	MaxTotalUsers     *int                         `json:"max_total_users,omitempty"`
	TenantCount       int                          `json:"tenant_count"`
	UserCount         int                          `json:"user_count"`
	SecurityPolicy    *RealmSecurityPolicyResponse `json:"security_policy,omitempty"`
	CreatedAt         time.Time                    `json:"created_at"`
	UpdatedAt         time.Time                    `json:"updated_at"`
}

// RealmSecurityPolicyResponse represents the API response for realm security policy
type RealmSecurityPolicyResponse struct {
	PasswordMinLength        int  `json:"password_min_length"`
	PasswordRequireUppercase bool `json:"password_require_uppercase"`
	PasswordRequireLowercase bool `json:"password_require_lowercase"`
	PasswordRequireDigits    bool `json:"password_require_digits"`
	PasswordRequireSpecial   bool `json:"password_require_special"`
	PasswordMaxAgeDays       *int `json:"password_max_age_days,omitempty"`
	PasswordHistoryCount     *int `json:"password_history_count,omitempty"`

	MFARequired           bool     `json:"mfa_required"`
	MFARequiredForAdmins  bool     `json:"mfa_required_for_admins"`
	MFAMethods            []string `json:"mfa_methods"`
	MFAGracePeriodDays    *int     `json:"mfa_grace_period_days,omitempty"`
	MFAEnrollmentMaxSkips int      `json:"mfa_enrollment_max_skips"`

	SessionMaxLifetimeHours   int  `json:"session_max_lifetime_hours"`
	SessionIdleTimeoutMinutes int  `json:"session_idle_timeout_minutes"`
	ConcurrentSessionsLimit   *int `json:"concurrent_sessions_limit,omitempty"`

	MaxFailedAttempts      int  `json:"max_failed_attempts"`
	LockoutDurationMinutes int  `json:"lockout_duration_minutes"`
	ProgressiveLockout     bool `json:"progressive_lockout"`
}

// RealmListResponse represents a paginated list of realms
type RealmListResponse struct {
	Realms     []RealmResponse `json:"realms"`
	Total      int64           `json:"total"`
	Page       int             `json:"page"`
	PageSize   int             `json:"page_size"`
	TotalPages int             `json:"total_pages"`
}

// ToResponse converts a Realm to its API response
func (r *Realm) ToResponse() *RealmResponse {
	resp := &RealmResponse{
		ID:                r.ID,
		Slug:              r.Slug,
		DisplayName:       r.DisplayName,
		Type:              r.Type,
		Status:            r.Status,
		Settings:          r.Settings,
		Branding:          r.Branding,
		Features:          r.Features,
		MaxTenants:        r.MaxTenants,
		MaxUsersPerTenant: r.MaxUsersPerTenant,
		MaxTotalUsers:     r.MaxTotalUsers,
		TenantCount:       r.TenantCount,
		UserCount:         r.UserCount,
		CreatedAt:         r.CreatedAt,
		UpdatedAt:         r.UpdatedAt,
	}

	if r.SecurityPolicy != nil {
		resp.SecurityPolicy = r.SecurityPolicy.ToResponse()
	}

	return resp
}

// ToResponse converts a RealmSecurityPolicy to its API response
func (p *RealmSecurityPolicy) ToResponse() *RealmSecurityPolicyResponse {
	var mfaMethods []string
	if p.MFAMethods != nil {
		_ = json.Unmarshal(p.MFAMethods, &mfaMethods)
	}

	return &RealmSecurityPolicyResponse{
		PasswordMinLength:        p.PasswordMinLength,
		PasswordRequireUppercase: p.PasswordRequireUppercase,
		PasswordRequireLowercase: p.PasswordRequireLowercase,
		PasswordRequireDigits:    p.PasswordRequireDigits,
		PasswordRequireSpecial:   p.PasswordRequireSpecial,
		PasswordMaxAgeDays:       p.PasswordMaxAgeDays,
		PasswordHistoryCount:     p.PasswordHistoryCount,

		MFARequired:           p.MFARequired,
		MFARequiredForAdmins:  p.MFARequiredForAdmins,
		MFAMethods:            mfaMethods,
		MFAGracePeriodDays:    p.MFAGracePeriodDays,
		MFAEnrollmentMaxSkips: p.MFAEnrollmentMaxSkips,

		SessionMaxLifetimeHours:   p.SessionMaxLifetimeHours,
		SessionIdleTimeoutMinutes: p.SessionIdleTimeoutMinutes,
		ConcurrentSessionsLimit:   p.ConcurrentSessionsLimit,

		MaxFailedAttempts:      p.MaxFailedAttempts,
		LockoutDurationMinutes: p.LockoutDurationMinutes,
		ProgressiveLockout:     p.ProgressiveLockout,
	}
}

// IsDefault returns true if this is the default shared realm
func (r *Realm) IsDefault() bool {
	return r.ID == DefaultRealmID
}

// CanBeDeleted returns true if the realm can be deleted (not default, no tenants)
func (r *Realm) CanBeDeleted() bool {
	return !r.IsDefault() && r.TenantCount == 0
}
