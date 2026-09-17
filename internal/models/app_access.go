// SPDX-License-Identifier: AGPL-3.0-or-later

package models

import (
	"time"

	"github.com/google/uuid"
)

// AppAccessRoleAssignment represents a per-application role assignment for a user
// in the legacy OAuth client-based app access control system.
// This binds (user, oauth_client, role) to enable application-scoped authorization.
type AppAccessRoleAssignment struct {
	ID         uuid.UUID  `json:"id" db:"id"`
	TenantID   uuid.UUID  `json:"tenant_id" db:"tenant_id"`
	UserID     uuid.UUID  `json:"user_id" db:"user_id"`
	ClientID   uuid.UUID  `json:"client_id" db:"client_id"`
	RoleID     uuid.UUID  `json:"role_id" db:"role_id"`
	AssignedBy *uuid.UUID `json:"assigned_by,omitempty" db:"assigned_by"`
	CreatedAt  time.Time  `json:"created_at" db:"created_at"`

	// Joined fields (not stored in DB, populated by queries)
	RoleName      string `json:"role_name,omitempty" db:"role_name"`
	Username      string `json:"username,omitempty" db:"username"`
	OAuthClientID string `json:"oauth_client_id,omitempty" db:"oauth_client_id"`
	AppName       string `json:"app_name,omitempty" db:"app_name"`
}

// AppAuthPolicy represents per-application authentication requirements.
type AppAuthPolicy struct {
	ID                        uuid.UUID `json:"id" db:"id"`
	ClientID                  uuid.UUID `json:"client_id" db:"client_id"`
	TenantID                  uuid.UUID `json:"tenant_id" db:"tenant_id"`
	RequireMFA                bool      `json:"require_mfa" db:"require_mfa"`
	RequireAssignment         bool      `json:"require_assignment" db:"require_assignment"`
	AllowedIPRanges           []string  `json:"allowed_ip_ranges,omitempty" db:"allowed_ip_ranges"`
	MaxSessionDurationSeconds *int      `json:"max_session_duration_seconds,omitempty" db:"max_session_duration_seconds"`
	CreatedAt                 time.Time `json:"created_at" db:"created_at"`
	UpdatedAt                 time.Time `json:"updated_at" db:"updated_at"`
}

// CreateAppRoleAssignmentRequest is the request to assign a role to a user for an application.
type CreateAppRoleAssignmentRequest struct {
	UserID   uuid.UUID `json:"user_id" binding:"required"`
	RoleID   uuid.UUID `json:"role_id" binding:"required"`
	TenantID uuid.UUID `json:"tenant_id" binding:"required"`
}

// AppAccessRoleAssignmentResponse is the API response for an app access role assignment.
type AppAccessRoleAssignmentResponse struct {
	ID            uuid.UUID  `json:"id"`
	TenantID      uuid.UUID  `json:"tenant_id"`
	UserID        uuid.UUID  `json:"user_id"`
	ClientID      uuid.UUID  `json:"client_id"`
	RoleID        uuid.UUID  `json:"role_id"`
	RoleName      string     `json:"role_name,omitempty"`
	Username      string     `json:"username,omitempty"`
	OAuthClientID string     `json:"oauth_client_id,omitempty"`
	AppName       string     `json:"app_name,omitempty"`
	AssignedBy    *uuid.UUID `json:"assigned_by,omitempty"`
	CreatedAt     time.Time  `json:"created_at"`
}

// CreateAppAuthPolicyRequest is the request to create an app auth policy.
type CreateAppAuthPolicyRequest struct {
	TenantID                  uuid.UUID `json:"tenant_id" binding:"required"`
	RequireMFA                bool      `json:"require_mfa"`
	RequireAssignment         bool      `json:"require_assignment"`
	AllowedIPRanges           []string  `json:"allowed_ip_ranges,omitempty"`
	MaxSessionDurationSeconds *int      `json:"max_session_duration_seconds,omitempty"`
}

// UpdateAppAuthPolicyRequest is the request to update an app auth policy.
type UpdateAppAuthPolicyRequest struct {
	RequireMFA                *bool    `json:"require_mfa,omitempty"`
	RequireAssignment         *bool    `json:"require_assignment,omitempty"`
	AllowedIPRanges           []string `json:"allowed_ip_ranges,omitempty"`
	MaxSessionDurationSeconds *int     `json:"max_session_duration_seconds,omitempty"`
}

// AppAuthPolicyResponse is the API response for an app auth policy.
type AppAuthPolicyResponse struct {
	ID                        uuid.UUID `json:"id"`
	ClientID                  uuid.UUID `json:"client_id"`
	TenantID                  uuid.UUID `json:"tenant_id"`
	RequireMFA                bool      `json:"require_mfa"`
	RequireAssignment         bool      `json:"require_assignment"`
	AllowedIPRanges           []string  `json:"allowed_ip_ranges,omitempty"`
	MaxSessionDurationSeconds *int      `json:"max_session_duration_seconds,omitempty"`
	CreatedAt                 time.Time `json:"created_at"`
	UpdatedAt                 time.Time `json:"updated_at"`
}
