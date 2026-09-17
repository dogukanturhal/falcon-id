// SPDX-License-Identifier: AGPL-3.0-or-later

package models

import (
	"time"

	"github.com/google/uuid"
)

// PlatformAdminRole represents the role of a platform administrator
type PlatformAdminRole string

const (
	// PlatformAdminRoleSuperAdmin is an exported identifier.
	PlatformAdminRoleSuperAdmin PlatformAdminRole = "super_admin"
	// PlatformAdminRoleSupportAdmin is an exported identifier.
	PlatformAdminRoleSupportAdmin PlatformAdminRole = "support_admin"
	// PlatformAdminRoleBillingAdmin is an exported identifier.
	PlatformAdminRoleBillingAdmin PlatformAdminRole = "billing_admin"
	// PlatformAdminRoleOpsAdmin is an exported identifier.
	PlatformAdminRoleOpsAdmin PlatformAdminRole = "ops_admin"
	// PlatformAdminRoleDeveloper is an exported identifier.
	PlatformAdminRoleDeveloper PlatformAdminRole = "developer"
)

// PlatformAdmin represents a HexxLock platform administrator
// These are internal employees who manage the SaaS platform
type PlatformAdmin struct {
	ID           uuid.UUID         `json:"id" db:"id"`
	Email        string            `json:"email" db:"email"`
	PasswordHash string            `json:"-" db:"password_hash"`
	FirstName    *string           `json:"first_name,omitempty" db:"first_name"`
	LastName     *string           `json:"last_name,omitempty" db:"last_name"`
	Role         PlatformAdminRole `json:"role" db:"role"`
	Permissions  []string          `json:"permissions" db:"permissions"`

	// MFA
	MFAEnabled     bool     `json:"mfa_enabled" db:"mfa_enabled"`
	MFASecret      *string  `json:"-" db:"mfa_secret"`
	MFABackupCodes []string `json:"-" db:"mfa_backup_codes"`

	// Status
	IsActive    bool       `json:"is_active" db:"is_active"`
	IsLocked    bool       `json:"is_locked" db:"is_locked"`
	LockedUntil *time.Time `json:"locked_until,omitempty" db:"locked_until"`
	LockReason  *string    `json:"lock_reason,omitempty" db:"lock_reason"`

	// Login Tracking
	LastLoginAt         *time.Time `json:"last_login_at,omitempty" db:"last_login_at"`
	LastLoginIP         *string    `json:"last_login_ip,omitempty" db:"last_login_ip"`
	FailedLoginAttempts int        `json:"failed_login_attempts" db:"failed_login_attempts"`

	// Audit
	CreatedAt time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt time.Time  `json:"updated_at" db:"updated_at"`
	CreatedBy *uuid.UUID `json:"created_by,omitempty" db:"created_by"`
	UpdatedBy *uuid.UUID `json:"updated_by,omitempty" db:"updated_by"`
}

// HasPermission checks if the admin has a specific permission
func (a *PlatformAdmin) HasPermission(permission string) bool {
	for _, p := range a.Permissions {
		if p == "*" || p == permission {
			return true
		}
		// Check wildcard permissions like "tenants.*"
		if len(p) > 1 && p[len(p)-1] == '*' {
			prefix := p[:len(p)-1]
			if len(permission) >= len(prefix) && permission[:len(prefix)] == prefix {
				return true
			}
		}
	}
	return false
}

// ToResponse converts PlatformAdmin to a safe response format
func (a *PlatformAdmin) ToResponse() *PlatformAdminResponse {
	return &PlatformAdminResponse{
		ID:          a.ID,
		Email:       a.Email,
		FirstName:   a.FirstName,
		LastName:    a.LastName,
		Role:        a.Role,
		Permissions: a.Permissions,
		MFAEnabled:  a.MFAEnabled,
		IsActive:    a.IsActive,
		LastLoginAt: a.LastLoginAt,
		CreatedAt:   a.CreatedAt,
	}
}

// PlatformAdminSession represents an active session for a platform admin
type PlatformAdminSession struct {
	ID               uuid.UUID  `json:"id" db:"id"`
	AdminID          uuid.UUID  `json:"admin_id" db:"admin_id"`
	SessionTokenHash string     `json:"-" db:"session_token_hash"`
	RefreshTokenHash *string    `json:"-" db:"refresh_token_hash"`
	IPAddress        *string    `json:"ip_address,omitempty" db:"ip_address"`
	UserAgent        *string    `json:"user_agent,omitempty" db:"user_agent"`
	DeviceInfo       *string    `json:"device_info,omitempty" db:"device_info"`
	ExpiresAt        time.Time  `json:"expires_at" db:"expires_at"`
	RefreshExpiresAt *time.Time `json:"refresh_expires_at,omitempty" db:"refresh_expires_at"`
	IsRevoked        bool       `json:"is_revoked" db:"is_revoked"`
	RevokedAt        *time.Time `json:"revoked_at,omitempty" db:"revoked_at"`
	RevokedReason    *string    `json:"revoked_reason,omitempty" db:"revoked_reason"`
	CreatedAt        time.Time  `json:"created_at" db:"created_at"`
}

// PlatformAdminAuditLog represents an audit entry for platform admin actions
type PlatformAdminAuditLog struct {
	ID             uuid.UUID  `json:"id" db:"id"`
	AdminID        *uuid.UUID `json:"admin_id,omitempty" db:"admin_id"`
	AdminEmail     string     `json:"admin_email" db:"admin_email"`
	Action         string     `json:"action" db:"action"`
	ActionCategory *string    `json:"action_category,omitempty" db:"action_category"`
	TargetType     *string    `json:"target_type,omitempty" db:"target_type"`
	TargetID       *uuid.UUID `json:"target_id,omitempty" db:"target_id"`
	TenantID       *uuid.UUID `json:"tenant_id,omitempty" db:"tenant_id"`
	RequestMethod  *string    `json:"request_method,omitempty" db:"request_method"`
	RequestPath    *string    `json:"request_path,omitempty" db:"request_path"`
	RequestBody    *string    `json:"request_body,omitempty" db:"request_body"`
	ResponseStatus *int       `json:"response_status,omitempty" db:"response_status"`
	IPAddress      *string    `json:"ip_address,omitempty" db:"ip_address"`
	UserAgent      *string    `json:"user_agent,omitempty" db:"user_agent"`
	Details        *string    `json:"details,omitempty" db:"details"`
	CreatedAt      time.Time  `json:"created_at" db:"created_at"`
	DurationMs     *int       `json:"duration_ms,omitempty" db:"duration_ms"`
}

// PlatformAdminImpersonation represents an impersonation session
type PlatformAdminImpersonation struct {
	ID                     uuid.UUID  `json:"id" db:"id"`
	AdminID                uuid.UUID  `json:"admin_id" db:"admin_id"`
	TenantID               uuid.UUID  `json:"tenant_id" db:"tenant_id"`
	ImpersonatedUserID     uuid.UUID  `json:"impersonated_user_id" db:"impersonated_user_id"`
	ImpersonatedUserEmail  string     `json:"impersonated_user_email" db:"impersonated_user_email"`
	ImpersonationTokenHash string     `json:"-" db:"impersonation_token_hash"`
	ExpiresAt              time.Time  `json:"expires_at" db:"expires_at"`
	IsRevoked              bool       `json:"is_revoked" db:"is_revoked"`
	RevokedAt              *time.Time `json:"revoked_at,omitempty" db:"revoked_at"`
	Reason                 *string    `json:"reason,omitempty" db:"reason"`
	TicketID               *string    `json:"ticket_id,omitempty" db:"ticket_id"`
	CreatedAt              time.Time  `json:"created_at" db:"created_at"`
	ActionsPerformed       *string    `json:"actions_performed,omitempty" db:"actions_performed"`
}

// ==================== Request/Response DTOs ====================

// PlatformAdminLoginRequest represents a platform admin login request
type PlatformAdminLoginRequest struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required"`
	MFACode  string `json:"mfa_code,omitempty"`
}

// PlatformAdminLoginResponse represents a successful platform admin login
type PlatformAdminLoginResponse struct {
	AccessToken      string                 `json:"access_token,omitempty"`
	RefreshToken     string                 `json:"refresh_token,omitempty"`
	TokenType        string                 `json:"token_type,omitempty"`
	ExpiresIn        int64                  `json:"expires_in,omitempty"`
	RefreshExpiresIn int64                  `json:"refresh_expires_in,omitempty"`
	Admin            *PlatformAdminResponse `json:"admin,omitempty"`
	RequiresMFA      bool                   `json:"requires_mfa,omitempty"`
	SessionID        string                 `json:"session_id,omitempty"`
}

// PlatformAdminResponse is the safe response format for platform admin
type PlatformAdminResponse struct {
	ID          uuid.UUID         `json:"id"`
	Email       string            `json:"email"`
	FirstName   *string           `json:"first_name,omitempty"`
	LastName    *string           `json:"last_name,omitempty"`
	Role        PlatformAdminRole `json:"role"`
	Permissions []string          `json:"permissions"`
	MFAEnabled  bool              `json:"mfa_enabled"`
	IsActive    bool              `json:"is_active"`
	LastLoginAt *time.Time        `json:"last_login_at,omitempty"`
	CreatedAt   time.Time         `json:"created_at"`
}

// PlatformAdminRefreshRequest represents a token refresh request
type PlatformAdminRefreshRequest struct {
	RefreshToken string `json:"refresh_token" binding:"required"`
}

// ImpersonateRequest represents a request to impersonate a tenant user
type ImpersonateRequest struct {
	TenantID uuid.UUID  `json:"tenant_id" binding:"required"`
	UserID   *uuid.UUID `json:"user_id,omitempty"` // Optional - if nil, impersonate tenant admin
	Reason   string     `json:"reason" binding:"required"`
	TicketID *string    `json:"ticket_id,omitempty"` // Support ticket reference
}

// ImpersonateResponse represents a successful impersonation
type ImpersonateResponse struct {
	ImpersonationToken string    `json:"impersonation_token"`
	TenantID           string    `json:"tenant_id"`
	UserID             string    `json:"user_id"`
	UserEmail          string    `json:"user_email"`
	ExpiresIn          int64     `json:"expires_in"` // Seconds
	ExpiresAt          time.Time `json:"expires_at"`
}

// PlatformAdminClaims represents JWT claims for platform admin tokens
type PlatformAdminClaims struct {
	AdminID     uuid.UUID         `json:"admin_id"`
	Email       string            `json:"email"`
	Role        PlatformAdminRole `json:"role"`
	Permissions []string          `json:"permissions"`
	SessionID   uuid.UUID         `json:"session_id"`
	Scope       string            `json:"scope"` // Always "platform"
}

// ImpersonationClaims represents JWT claims for impersonation tokens
type ImpersonationClaims struct {
	// Original admin info
	AdminID    uuid.UUID `json:"admin_id"`
	AdminEmail string    `json:"admin_email"`

	// Impersonated user info
	UserID   uuid.UUID `json:"user_id"`
	TenantID uuid.UUID `json:"tenant_id"`

	// Marker
	IsImpersonation bool   `json:"is_impersonation"`
	Scope           string `json:"scope"` // "impersonation"
}
