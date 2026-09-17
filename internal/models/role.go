// SPDX-License-Identifier: AGPL-3.0-or-later

package models

import (
	"time"

	"github.com/google/uuid"
)

// RoleSource identifies whether a role can be managed through the tenant role
// catalogue or is retained only as an existing grant reference.
type RoleSource string

const (
	RoleSourceTenantCatalogue RoleSource = "tenant_catalogue"
	RoleSourceSystem          RoleSource = "system"
	RoleSourceExternal        RoleSource = "external"
	RoleSourceUnknown         RoleSource = "unknown"
)

// Role is an exported type.
type Role struct {
	ID          uuid.UUID `json:"id" db:"id"`
	TenantID    uuid.UUID `json:"tenant_id" db:"tenant_id"`
	Name        string    `json:"name" db:"name"`
	DisplayName string    `json:"display_name" db:"display_name"`
	Description *string   `json:"description,omitempty" db:"description"`
	IsSystem    bool      `json:"is_system" db:"is_system"`
	IsDefault   bool      `json:"is_default" db:"is_default"`
	Priority    int       `json:"priority" db:"priority"`

	CreatedAt time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt time.Time  `json:"updated_at" db:"updated_at"`
	CreatedBy *uuid.UUID `json:"created_by,omitempty" db:"created_by"`
	UpdatedBy *uuid.UUID `json:"updated_by,omitempty" db:"updated_by"`

	// Related data (not in DB)
	Permissions []Permission `json:"permissions,omitempty"`
}

// CreateRoleRequest is an exported type.
type CreateRoleRequest struct {
	TenantID      uuid.UUID   `json:"tenant_id"`
	Name          string      `json:"name" binding:"required,min=2,max=100"`
	DisplayName   string      `json:"display_name" binding:"required,min=2,max=255"`
	Description   *string     `json:"description"`
	IsDefault     bool        `json:"is_default"`
	Priority      int         `json:"priority"`
	PermissionIDs []uuid.UUID `json:"permission_ids"`
}

// UpdateRoleRequest is an exported type.
type UpdateRoleRequest struct {
	DisplayName   *string     `json:"display_name"`
	Description   *string     `json:"description"`
	IsDefault     *bool       `json:"is_default"`
	Priority      *int        `json:"priority"`
	PermissionIDs []uuid.UUID `json:"permission_ids"`
}

// RoleResponse is an exported type.
type RoleResponse struct {
	ID          uuid.UUID            `json:"id"`
	TenantID    uuid.UUID            `json:"tenant_id"`
	Name        string               `json:"name"`
	DisplayName string               `json:"display_name"`
	Description *string              `json:"description,omitempty"`
	IsSystem    bool                 `json:"is_system"`
	IsDefault   bool                 `json:"is_default"`
	Priority    int                  `json:"priority"`
	CreatedAt   time.Time            `json:"created_at"`
	UpdatedAt   time.Time            `json:"updated_at"`
	Source      RoleSource           `json:"source"`
	Editable    bool                 `json:"editable"`
	Locked      bool                 `json:"locked"`
	Reason      string               `json:"reason,omitempty"`
	Permissions []PermissionResponse `json:"permissions,omitempty"`
}

// RoleListResponse is an exported type.
type RoleListResponse struct {
	Roles      []RoleResponse `json:"roles"`
	Total      int64          `json:"total"`
	Page       int            `json:"page"`
	PageSize   int            `json:"page_size"`
	TotalPages int            `json:"total_pages"`
}

// RoleMember represents a user who has been assigned a specific role.
type RoleMember struct {
	UserID   uuid.UUID `json:"user_id"`
	UserName string    `json:"user_name"`
	Email    string    `json:"email"`
}

// RoleMembersResponse is the paginated response for GET /roles/:id/members.
type RoleMembersResponse struct {
	Data     []RoleMember `json:"data"`
	Total    int          `json:"total"`
	Page     int          `json:"page"`
	PageSize int          `json:"page_size"`
}

// ToResponse is an exported function.
func (r *Role) ToResponse() *RoleResponse {
	source := RoleSourceTenantCatalogue
	if r.IsSystem {
		source = RoleSourceSystem
	}
	resp := &RoleResponse{
		ID:          r.ID,
		TenantID:    r.TenantID,
		Name:        r.Name,
		DisplayName: r.DisplayName,
		Description: r.Description,
		IsSystem:    r.IsSystem,
		IsDefault:   r.IsDefault,
		Priority:    r.Priority,
		CreatedAt:   r.CreatedAt,
		UpdatedAt:   r.UpdatedAt,
		Source:      source,
		Editable:    !r.IsSystem,
		Locked:      r.IsSystem,
	}

	for _, perm := range r.Permissions {
		resp.Permissions = append(resp.Permissions, *perm.ToResponse())
	}

	return resp
}
