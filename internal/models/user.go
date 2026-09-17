// SPDX-License-Identifier: AGPL-3.0-or-later

package models

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// User is an exported type.
type User struct {
	ID           uuid.UUID `json:"id" db:"id"`
	TenantID     uuid.UUID `json:"tenant_id" db:"tenant_id"`
	RealmID      uuid.UUID `json:"realm_id" db:"realm_id"` // Realm context for multi-realm authentication
	Username     string    `json:"username" db:"username"`
	Email        string    `json:"email" db:"email"`
	EmailHash    string    `json:"-" db:"email_hash"` // SHA-256 hash of lowercased email for efficient lookup
	PasswordHash *string   `json:"-" db:"password_hash"`
	FirstName    *string   `json:"first_name,omitempty" db:"first_name"`
	LastName     *string   `json:"last_name,omitempty" db:"last_name"`
	DisplayName  *string   `json:"display_name,omitempty" db:"display_name"`
	Phone        *string   `json:"phone,omitempty" db:"phone"`
	Department   *string   `json:"department,omitempty" db:"department"`
	Title        *string   `json:"title,omitempty" db:"title"`
	AvatarURL    *string   `json:"avatar_url,omitempty" db:"avatar_url"`

	// Federation fields
	FederationType   *string `json:"federation_type,omitempty" db:"federation_type"`
	FederationID     *string `json:"federation_id,omitempty" db:"federation_id"`
	FederationSource *string `json:"federation_source,omitempty" db:"federation_source"`

	// Status fields
	IsActive         bool       `json:"is_active" db:"is_active"`
	IsEmailVerified  bool       `json:"is_email_verified" db:"is_email_verified"`
	IsLocked         bool       `json:"is_locked" db:"is_locked"`
	LockReason       *string    `json:"lock_reason,omitempty" db:"lock_reason"`
	LockedAt         *time.Time `json:"locked_at,omitempty" db:"locked_at"`
	LockedUntil      *time.Time `json:"locked_until,omitempty" db:"locked_until"`
	ActivationStatus string     `json:"activation_status" db:"activation_status"` // pending_invitation, pending_activation, active, suspended, deactivated

	// RequiresAdminReview flags an account whose login was rejected for a
	// policy reason that leaves it in an ambiguous state needing a human
	// decision -- e.g. a valid local password under a tenant that has
	// disabled local auth (t-431, d-169 Q3). Never auto-cleared by login;
	// only an explicit admin action (UserRepository.ClearAdminReviewFlag)
	// resolves it. Not exposed via json by default -- deliberately not
	// `omitempty` on the bool since admin tooling needs to see `false`
	// explicitly, but the struct as a whole is not returned from login
	// responses (see buildLoginResponse), so this never reaches the user.
	RequiresAdminReview  bool       `json:"requires_admin_review" db:"requires_admin_review"`
	AdminReviewReason    *string    `json:"admin_review_reason,omitempty" db:"admin_review_reason"`
	AdminReviewFlaggedAt *time.Time `json:"admin_review_flagged_at,omitempty" db:"admin_review_flagged_at"`

	// MFA fields
	MFAEnabled         bool    `json:"mfa_enabled" db:"mfa_enabled"`
	MFASecret          *string `json:"-" db:"mfa_secret"`
	MFAType            *string `json:"mfa_type,omitempty" db:"mfa_type"`
	MFATOTPEnabled     bool    `json:"mfa_totp_enabled" db:"mfa_totp_enabled"`
	MFAEmailEnabled    bool    `json:"mfa_email_enabled" db:"mfa_email_enabled"`
	MFAPreferredMethod *string `json:"mfa_preferred_method,omitempty" db:"mfa_preferred_method"`

	// MFA enrollment grace tracking (migration 235).
	// Populated only when realm.mfa_grace_period_days > 0. NULL during the
	// pre-policy phase or after the user enrolls (skip_count is RESET to 0
	// on successful enrollment; the timestamps stay so we have a history
	// of how long enrollment took).
	MFAEnrollmentFirstPromptedAt *time.Time `json:"mfa_enrollment_first_prompted_at,omitempty" db:"mfa_enrollment_first_prompted_at"`
	MFAEnrollmentDeadline        *time.Time `json:"mfa_enrollment_deadline,omitempty" db:"mfa_enrollment_deadline"`
	MFAEnrollmentSkipCount       int        `json:"mfa_enrollment_skip_count" db:"mfa_enrollment_skip_count"`

	// Password fields
	PasswordChangedAt   *time.Time `json:"password_changed_at,omitempty" db:"password_changed_at"`
	MustChangePassword  bool       `json:"must_change_password" db:"must_change_password"`
	FailedLoginAttempts int        `json:"-" db:"failed_login_attempts"`
	LastFailedLoginAt   *time.Time `json:"-" db:"last_failed_login_at"`

	// Metadata
	LastLoginAt *time.Time `json:"last_login_at,omitempty" db:"last_login_at"`
	LastLoginIP *string    `json:"last_login_ip,omitempty" db:"last_login_ip"`
	CreatedAt   time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at" db:"updated_at"`
	CreatedBy   *uuid.UUID `json:"created_by,omitempty" db:"created_by"`
	UpdatedBy   *uuid.UUID `json:"updated_by,omitempty" db:"updated_by"`

	// GDPR Art. 17 / KVKK Art. 7 account-deletion scheduling (migration 240).
	// All three NULL means the account is not pending deletion. When the user
	// invokes /api/v1/users/me/delete-account, activation_status flips to
	// "pending_deletion" and these three are populated; the hourly purger
	// finalises rows where DeletionGracePeriodEndsAt <= NOW().
	DeletionScheduledAt       *time.Time `json:"deletion_scheduled_at,omitempty" db:"deletion_scheduled_at"`
	DeletionGracePeriodEndsAt *time.Time `json:"deletion_grace_period_ends_at,omitempty" db:"deletion_grace_period_ends_at"`
	DeletionReason            *string    `json:"deletion_reason,omitempty" db:"deletion_reason"`

	// Preferences — per-user opaque JSONB (migration 0003).
	// Namespaced under {global, products.<slug>} per the 2026-06-02 Option C
	// onboarding-architecture research (Microsoft Graph schema-extension +
	// Atlassian Forge Storage convention). Validation happens in
	// services/user_preferences_service.go against a registry of known
	// product slugs — NOT in Postgres, to keep product schemas evolvable
	// without DDL migrations. Use json.RawMessage so unmarshal is opaque
	// at the model layer; the handler layer owns the shape contract.
	Preferences json.RawMessage `json:"preferences,omitempty" db:"preferences"`

	// Related data (not in DB)
	Roles       []Role       `json:"roles,omitempty"`
	Permissions []Permission `json:"permissions,omitempty"`
}

// CreateUserRequest is an exported type.
type CreateUserRequest struct {
	TenantID uuid.UUID `json:"tenant_id" binding:"required"`
	// RealmID — optional explicit realm scope. When non-nil the
	// service uses it directly (fail-closed if the value doesn't
	// resolve to an existing realm). When nil the service falls
	// through to the realm resolver (tenant→realm via realm_tenants);
	// a missing assignment is also fail-closed, NOT defaulted. This
	// covers boot-time bootstrap paths where the resolver may not yet
	// be wired or the tenant assignment hasn't been seeded — see
	// cmd/admin_bootstrap.go for the canonical caller. Threading the
	// realm explicitly avoids the cross-realm-isolation anti-pattern
	// documented in OWASP Multi-Tenant Cheat Sheet and RFC 9700 §4.
	RealmID     *uuid.UUID `json:"realm_id,omitempty"`
	Username    string     `json:"username" binding:"required,min=3,max=255"`
	Email       string     `json:"email" binding:"required,email"`
	Password    string     `json:"password" binding:"omitempty,min=8"`
	FirstName   *string    `json:"first_name"`
	LastName    *string    `json:"last_name"`
	DisplayName *string    `json:"display_name"`
	Phone       *string    `json:"phone"`
	Department  *string    `json:"department"`
	Title       *string    `json:"title"`

	// Federation
	FederationType   *string `json:"federation_type"`
	FederationID     *string `json:"federation_id"`
	FederationSource *string `json:"federation_source"`

	// Roles to assign
	RoleIDs []uuid.UUID `json:"role_ids"`
}

// UpdateUserRequest is an exported type.
type UpdateUserRequest struct {
	FirstName          *string     `json:"first_name" binding:"omitempty,max=100"`
	LastName           *string     `json:"last_name" binding:"omitempty,max=100"`
	DisplayName        *string     `json:"display_name" binding:"omitempty,max=255"`
	Phone              *string     `json:"phone" binding:"omitempty,max=50"`
	Department         *string     `json:"department" binding:"omitempty,max=255"`
	Title              *string     `json:"title" binding:"omitempty,max=255"`
	AvatarURL          *string     `json:"avatar_url" binding:"omitempty,max=2048"`
	IsActive           *bool       `json:"is_active"`
	MustChangePassword *bool       `json:"must_change_password"`
	RoleIDs            []uuid.UUID `json:"role_ids"`
}

// UpdateProfileRequest is the request for users to update their own profile (self-service)
// This excludes admin-only fields like IsActive, MustChangePassword, and RoleIDs
type UpdateProfileRequest struct {
	FirstName   *string `json:"first_name" binding:"omitempty,max=100"`
	LastName    *string `json:"last_name" binding:"omitempty,max=100"`
	DisplayName *string `json:"display_name" binding:"omitempty,max=255"`
	Phone       *string `json:"phone" binding:"omitempty,max=50"`
	AvatarURL   *string `json:"avatar_url" binding:"omitempty,max=2048"`
}

// SetUserRolesRequest is the request to set roles for a user
// Note: User.AvatarURL stores a MinIO object key (e.g. "avatars/user-id/file.jpg"),
// not a full URL. The GET /auth/me/avatar endpoint proxies the image from MinIO.
type SetUserRolesRequest struct {
	RoleIDs []uuid.UUID `json:"role_ids" binding:"required"`
}

// UserResponse is an exported type.
type UserResponse struct {
	ID          uuid.UUID `json:"id"`
	TenantID    uuid.UUID `json:"tenant_id"`
	TenantSlug  string    `json:"tenant_slug,omitempty"` // For frontend tenant context persistence
	Username    string    `json:"username"`
	Email       string    `json:"email"`
	FirstName   *string   `json:"first_name,omitempty"`
	LastName    *string   `json:"last_name,omitempty"`
	DisplayName *string   `json:"display_name,omitempty"`
	Phone       *string   `json:"phone,omitempty"`
	Department  *string   `json:"department,omitempty"`
	Title       *string   `json:"title,omitempty"`
	AvatarURL   *string   `json:"avatar_url,omitempty"`

	FederationType *string `json:"federation_type,omitempty"`

	IsActive           bool    `json:"is_active"`
	IsEmailVerified    bool    `json:"is_email_verified"`
	IsLocked           bool    `json:"is_locked"`
	ActivationStatus   string  `json:"activation_status"`
	MFAEnabled         bool    `json:"mfa_enabled"`
	MFAType            *string `json:"mfa_type,omitempty"`
	MFATOTPEnabled     bool    `json:"mfa_totp_enabled"`
	MFAEmailEnabled    bool    `json:"mfa_email_enabled"`
	MFAPreferredMethod *string `json:"mfa_preferred_method,omitempty"`

	LastLoginAt *time.Time `json:"last_login_at,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`

	Roles          []RoleResponse       `json:"roles,omitempty"`
	Permissions    []PermissionResponse `json:"permissions,omitempty"`
	EffectiveRoles []*EffectiveRole     `json:"effective_roles,omitempty"` // Includes group-inherited roles

	// Modules lists the business modules this user is entitled to access.
	// Derived from roles and permissions by the auth layer; omitted when empty.
	Modules []string `json:"modules,omitempty"`
}

// UserListResponse is an exported type.
type UserListResponse struct {
	Users      []UserResponse `json:"users"`
	Total      int64          `json:"total"`
	Page       int            `json:"page"`
	PageSize   int            `json:"page_size"`
	TotalPages int            `json:"total_pages"`
}

// ToResponse is an exported function.
func (u *User) ToResponse() *UserResponse {
	resp := &UserResponse{
		ID:                 u.ID,
		TenantID:           u.TenantID,
		Username:           u.Username,
		Email:              u.Email,
		FirstName:          u.FirstName,
		LastName:           u.LastName,
		DisplayName:        u.DisplayName,
		Phone:              u.Phone,
		Department:         u.Department,
		Title:              u.Title,
		AvatarURL:          u.AvatarURL,
		FederationType:     u.FederationType,
		IsActive:           u.IsActive,
		IsEmailVerified:    u.IsEmailVerified,
		IsLocked:           u.IsLocked,
		ActivationStatus:   u.ActivationStatus,
		MFAEnabled:         u.MFAEnabled,
		MFAType:            u.MFAType,
		MFATOTPEnabled:     u.MFATOTPEnabled,
		MFAEmailEnabled:    u.MFAEmailEnabled,
		MFAPreferredMethod: u.MFAPreferredMethod,
		LastLoginAt:        u.LastLoginAt,
		CreatedAt:          u.CreatedAt,
		UpdatedAt:          u.UpdatedAt,
	}

	for _, role := range u.Roles {
		resp.Roles = append(resp.Roles, *role.ToResponse())
	}

	for _, perm := range u.Permissions {
		resp.Permissions = append(resp.Permissions, *perm.ToResponse())
	}

	return resp
}

// GetFullName is an exported function.
func (u *User) GetFullName() string {
	if u.DisplayName != nil && *u.DisplayName != "" {
		return *u.DisplayName
	}

	firstName := ""
	lastName := ""
	if u.FirstName != nil {
		firstName = *u.FirstName
	}
	if u.LastName != nil {
		lastName = *u.LastName
	}

	if firstName != "" || lastName != "" {
		return firstName + " " + lastName
	}

	return u.Username
}
