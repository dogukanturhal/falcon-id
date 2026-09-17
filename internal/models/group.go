// SPDX-License-Identifier: AGPL-3.0-or-later

package models

import (
	"time"

	"github.com/google/uuid"
)

// Group represents a user group for organizing users and assigning permissions
type Group struct {
	ID            uuid.UUID              `json:"id"`
	TenantID      uuid.UUID              `json:"tenant_id"`
	Name          string                 `json:"name"`
	DisplayName   *string                `json:"display_name,omitempty"`
	Description   *string                `json:"description,omitempty"`
	ParentGroupID *uuid.UUID             `json:"parent_group_id,omitempty"`
	IsSystem      bool                   `json:"is_system"`
	Metadata      map[string]interface{} `json:"metadata,omitempty"`
	CreatedAt     time.Time              `json:"created_at"`
	UpdatedAt     time.Time              `json:"updated_at"`
	CreatedBy     *uuid.UUID             `json:"created_by,omitempty"`

	// Populated fields (not stored directly)
	MemberCount int      `json:"member_count,omitempty"`
	RoleCount   int      `json:"role_count,omitempty"`
	Members     []*User  `json:"members,omitempty"`
	Roles       []*Role  `json:"roles,omitempty"`
	ParentGroup *Group   `json:"parent_group,omitempty"`
	ChildGroups []*Group `json:"child_groups,omitempty"`
}

// GroupMember represents a user's membership in a group
type GroupMember struct {
	ID      uuid.UUID  `json:"id"`
	GroupID uuid.UUID  `json:"group_id"`
	UserID  uuid.UUID  `json:"user_id"`
	AddedAt time.Time  `json:"added_at"`
	AddedBy *uuid.UUID `json:"added_by,omitempty"`

	// Populated fields
	User  *User  `json:"user,omitempty"`
	Group *Group `json:"group,omitempty"`
}

// GroupRole represents a role assignment to a group
type GroupRole struct {
	ID         uuid.UUID  `json:"id"`
	GroupID    uuid.UUID  `json:"group_id"`
	RoleID     uuid.UUID  `json:"role_id"`
	AssignedAt time.Time  `json:"assigned_at"`
	AssignedBy *uuid.UUID `json:"assigned_by,omitempty"`

	// Populated fields
	Role  *Role  `json:"role,omitempty"`
	Group *Group `json:"group,omitempty"`
}

// EffectiveRole represents a role with its source (direct, group, or organization)
type EffectiveRole struct {
	RoleID     uuid.UUID  `json:"role_id"`
	RoleName   string     `json:"role_name"`
	Source     string     `json:"source"`                // "direct", "group", or "organization"
	SourceID   *uuid.UUID `json:"source_id,omitempty"`   // group or org ID if inherited
	SourceName *string    `json:"source_name,omitempty"` // human-readable name of the source
}

// CreateGroupRequest represents a request to create a new group
type CreateGroupRequest struct {
	Name          string                 `json:"name" binding:"required,min=1,max=100"`
	DisplayName   *string                `json:"display_name,omitempty"`
	Description   *string                `json:"description,omitempty"`
	ParentGroupID *uuid.UUID             `json:"parent_group_id,omitempty"`
	Metadata      map[string]interface{} `json:"metadata,omitempty"`
	RoleIDs       []uuid.UUID            `json:"role_ids,omitempty"`
	MemberIDs     []uuid.UUID            `json:"member_ids,omitempty"`
}

// UpdateGroupRequest represents a request to update a group
type UpdateGroupRequest struct {
	Name          *string                `json:"name,omitempty"`
	DisplayName   *string                `json:"display_name,omitempty"`
	Description   *string                `json:"description,omitempty"`
	ParentGroupID *uuid.UUID             `json:"parent_group_id,omitempty"`
	Metadata      map[string]interface{} `json:"metadata,omitempty"`
}

// AddMembersRequest represents a request to add members to a group
type AddMembersRequest struct {
	UserIDs []uuid.UUID `json:"user_ids" binding:"required,min=1"`
}

// RemoveMembersRequest represents a request to remove members from a group
type RemoveMembersRequest struct {
	UserIDs []uuid.UUID `json:"user_ids" binding:"required,min=1"`
}

// AssignGroupRolesRequest is an exported identifier.
// AssignRolesRequest is an exported identifier.
// AssignRolesRequest is an exported identifier.
// AssignRolesRequest represents a request to assign roles to a group
type AssignGroupRolesRequest struct {
	RoleIDs []uuid.UUID `json:"role_ids" binding:"required,min=1"`
}

// RemoveGroupRolesRequest is an exported identifier.
// RemoveRolesRequest is an exported identifier.
// RemoveRolesRequest is an exported identifier.
// RemoveRolesRequest represents a request to remove roles from a group
type RemoveGroupRolesRequest struct {
	RoleIDs []uuid.UUID `json:"role_ids" binding:"required,min=1"`
}

// IAMGroupListResponse represents the response for listing IAM groups
type IAMGroupListResponse struct {
	Groups     []*Group `json:"groups"`
	Total      int      `json:"total"`
	Page       int      `json:"page"`
	PageSize   int      `json:"page_size"`
	TotalPages int      `json:"total_pages"`
}

// GroupMembersResponse represents the response for listing group members
type GroupMembersResponse struct {
	Members    []*GroupMember `json:"members"`
	Total      int            `json:"total"`
	Page       int            `json:"page"`
	PageSize   int            `json:"page_size"`
	TotalPages int            `json:"total_pages"`
}
