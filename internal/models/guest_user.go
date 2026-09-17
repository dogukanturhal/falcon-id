// SPDX-License-Identifier: AGPL-3.0-or-later

package models

import (
	"time"

	"github.com/google/uuid"
)

// GuestUserStatus represents the lifecycle status of a B2B guest user.
type GuestUserStatus string

const (
	// GuestUserStatusPending is an exported identifier.
	GuestUserStatusPending GuestUserStatus = "pending"
	// GuestUserStatusActive is an exported identifier.
	GuestUserStatusActive GuestUserStatus = "active"
	// GuestUserStatusSuspended is an exported identifier.
	GuestUserStatusSuspended GuestUserStatus = "suspended"
	// GuestUserStatusRevoked is an exported identifier.
	GuestUserStatusRevoked GuestUserStatus = "revoked"
	// GuestUserStatusExpired is an exported identifier.
	GuestUserStatusExpired GuestUserStatus = "expired"
)

// GuestUserType controls the permission scope granted to the guest within the host tenant.
type GuestUserType string

const (
	// GuestUserTypeMember is an exported identifier.
	GuestUserTypeMember GuestUserType = "member"
	// GuestUserTypeRestricted is an exported identifier.
	GuestUserTypeRestricted GuestUserType = "restricted"
	// GuestUserTypeElevated is an exported identifier.
	GuestUserTypeElevated GuestUserType = "elevated"
)

// GuestUser represents a cross-tenant guest identity.
// A guest is a user from one tenant (home) who has been granted access to
// resources in another tenant (host).
type GuestUser struct {
	ID uuid.UUID `json:"id" db:"id"`

	// Host context
	HostTenantID uuid.UUID  `json:"host_tenant_id" db:"host_tenant_id"`
	HostRealmID  *uuid.UUID `json:"host_realm_id,omitempty" db:"host_realm_id"`

	// Home context
	HomeTenantID uuid.UUID `json:"home_tenant_id" db:"home_tenant_id"`
	HomeUserID   uuid.UUID `json:"home_user_id" db:"home_user_id"`

	// Guest identity
	Email       string  `json:"email" db:"email"`
	DisplayName *string `json:"display_name,omitempty" db:"display_name"`

	// Configuration
	GuestType GuestUserType   `json:"guest_type" db:"guest_type"`
	Status    GuestUserStatus `json:"status" db:"status"`

	// Invitation
	InvitedBy         uuid.UUID  `json:"invited_by" db:"invited_by"`
	InvitationMessage *string    `json:"invitation_message,omitempty" db:"invitation_message"`
	AcceptedAt        *time.Time `json:"accepted_at,omitempty" db:"accepted_at"`
	ExpiresAt         *time.Time `json:"expires_at,omitempty" db:"expires_at"`

	// Access tracking
	LastAccessAt *time.Time `json:"last_access_at,omitempty" db:"last_access_at"`
	AccessCount  int64      `json:"access_count" db:"access_count"`

	CreatedAt time.Time `json:"created_at" db:"created_at"`
	UpdatedAt time.Time `json:"updated_at" db:"updated_at"`
}

// GuestRoleAssignment represents a role within the host tenant granted to a guest.
type GuestRoleAssignment struct {
	ID          uuid.UUID  `json:"id" db:"id"`
	GuestUserID uuid.UUID  `json:"guest_user_id" db:"guest_user_id"`
	RoleID      uuid.UUID  `json:"role_id" db:"role_id"`
	AssignedBy  uuid.UUID  `json:"assigned_by" db:"assigned_by"`
	AssignedAt  time.Time  `json:"assigned_at" db:"assigned_at"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty" db:"expires_at"`
}

// GuestAccessLog is an immutable entry recording a guest's resource access.
type GuestAccessLog struct {
	ID           uuid.UUID `json:"id" db:"id"`
	GuestUserID  uuid.UUID `json:"guest_user_id" db:"guest_user_id"`
	HostTenantID uuid.UUID `json:"host_tenant_id" db:"host_tenant_id"`
	Action       string    `json:"action" db:"action"`
	ResourceType *string   `json:"resource_type,omitempty" db:"resource_type"`
	ResourceID   *string   `json:"resource_id,omitempty" db:"resource_id"`
	IPAddress    *string   `json:"ip_address,omitempty" db:"ip_address"`
	UserAgent    *string   `json:"user_agent,omitempty" db:"user_agent"`
	Details      *string   `json:"details,omitempty" db:"details"` // raw JSONB stored as string
	CreatedAt    time.Time `json:"created_at" db:"created_at"`
}

// ==================== Request / Response DTOs ====================

// InviteGuestRequest creates a new cross-tenant guest invitation.
type InviteGuestRequest struct {
	Email             string        `json:"email" binding:"required,email"`
	GuestType         GuestUserType `json:"guest_type" binding:"omitempty,oneof=member restricted elevated"`
	RoleIDs           []uuid.UUID   `json:"role_ids,omitempty"`
	InvitationMessage string        `json:"invitation_message,omitempty"`
	ExpiryDays        int           `json:"expiry_days,omitempty"` // 0 = no expiry
}

// UpdateGuestRequest carries mutable fields for a guest record.
type UpdateGuestRequest struct {
	GuestType   *GuestUserType   `json:"guest_type,omitempty" binding:"omitempty,oneof=member restricted elevated"`
	Status      *GuestUserStatus `json:"status,omitempty" binding:"omitempty,oneof=active suspended"`
	DisplayName *string          `json:"display_name,omitempty"`
	ExpiresAt   *time.Time       `json:"expires_at,omitempty"`
}

// SetGuestRolesRequest replaces all role assignments for a guest.
type SetGuestRolesRequest struct {
	RoleIDs []uuid.UUID `json:"role_ids" binding:"required"`
}

// GuestUserListFilter controls which guest records are returned.
type GuestUserListFilter struct {
	Status   *GuestUserStatus
	Email    string
	Page     int
	PageSize int
}

// GuestUserResponse is the safe public representation of a guest user.
type GuestUserResponse struct {
	ID           uuid.UUID       `json:"id"`
	HostTenantID uuid.UUID       `json:"host_tenant_id"`
	HostRealmID  *uuid.UUID      `json:"host_realm_id,omitempty"`
	HomeTenantID uuid.UUID       `json:"home_tenant_id"`
	HomeUserID   uuid.UUID       `json:"home_user_id"`
	Email        string          `json:"email"`
	DisplayName  *string         `json:"display_name,omitempty"`
	GuestType    GuestUserType   `json:"guest_type"`
	Status       GuestUserStatus `json:"status"`
	InvitedBy    uuid.UUID       `json:"invited_by"`
	AcceptedAt   *time.Time      `json:"accepted_at,omitempty"`
	ExpiresAt    *time.Time      `json:"expires_at,omitempty"`
	LastAccessAt *time.Time      `json:"last_access_at,omitempty"`
	AccessCount  int64           `json:"access_count"`
	CreatedAt    time.Time       `json:"created_at"`
	UpdatedAt    time.Time       `json:"updated_at"`
}

// GuestUserListResponse wraps a page of guest user records.
type GuestUserListResponse struct {
	Guests     []*GuestUserResponse `json:"guests"`
	Total      int64                `json:"total"`
	Page       int                  `json:"page"`
	PageSize   int                  `json:"page_size"`
	TotalPages int                  `json:"total_pages"`
}

// IsActive reports whether the guest can currently access host resources.
func (g *GuestUser) IsActive() bool {
	return g.Status == GuestUserStatusActive
}

// IsExpired reports whether the guest's access window has passed.
func (g *GuestUser) IsExpired() bool {
	if g.ExpiresAt == nil {
		return false
	}
	return time.Now().After(*g.ExpiresAt)
}

// ToResponse converts GuestUser to the API-safe response DTO.
func (g *GuestUser) ToResponse() *GuestUserResponse {
	return &GuestUserResponse{
		ID:           g.ID,
		HostTenantID: g.HostTenantID,
		HostRealmID:  g.HostRealmID,
		HomeTenantID: g.HomeTenantID,
		HomeUserID:   g.HomeUserID,
		Email:        g.Email,
		DisplayName:  g.DisplayName,
		GuestType:    g.GuestType,
		Status:       g.Status,
		InvitedBy:    g.InvitedBy,
		AcceptedAt:   g.AcceptedAt,
		ExpiresAt:    g.ExpiresAt,
		LastAccessAt: g.LastAccessAt,
		AccessCount:  g.AccessCount,
		CreatedAt:    g.CreatedAt,
		UpdatedAt:    g.UpdatedAt,
	}
}
