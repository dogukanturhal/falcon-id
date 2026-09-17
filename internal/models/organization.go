// SPDX-License-Identifier: AGPL-3.0-or-later

package models

import (
	"time"

	"github.com/google/uuid"
)

// Organization types
const (
	OrgTypeCompany    = "company"
	OrgTypeDivision   = "division"
	OrgTypeDepartment = "department"
	OrgTypeTeam       = "team"
	OrgTypeProject    = "project"
)

// Organization member roles
const (
	OrgRoleMember  = "member"
	OrgRoleManager = "manager"
	OrgRoleLead    = "lead"
	OrgRoleOwner   = "owner"
)

// Organization represents an organizational unit (department, team, etc.)
type Organization struct {
	ID          uuid.UUID              `json:"id"`
	TenantID    uuid.UUID              `json:"tenant_id"`
	ParentID    *uuid.UUID             `json:"parent_id,omitempty"`
	Name        string                 `json:"name"`
	DisplayName *string                `json:"display_name,omitempty"`
	Description *string                `json:"description,omitempty"`
	OrgType     string                 `json:"org_type"`
	Code        *string                `json:"code,omitempty"`
	Path        *string                `json:"path,omitempty"`
	Level       int                    `json:"level"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
	IsActive    bool                   `json:"is_active"`
	CreatedAt   time.Time              `json:"created_at"`
	UpdatedAt   time.Time              `json:"updated_at"`
	CreatedBy   *uuid.UUID             `json:"created_by,omitempty"`

	// Populated fields (not stored directly)
	MemberCount int             `json:"member_count,omitempty"`
	ChildCount  int             `json:"child_count,omitempty"`
	Parent      *Organization   `json:"parent,omitempty"`
	Children    []*Organization `json:"children,omitempty"`
	Members     []*OrgMember    `json:"members,omitempty"`
	Ancestors   []*Organization `json:"ancestors,omitempty"`
}

// OrgMember represents a user's membership in an organization
type OrgMember struct {
	ID             uuid.UUID  `json:"id"`
	OrganizationID uuid.UUID  `json:"organization_id"`
	UserID         uuid.UUID  `json:"user_id"`
	Role           string     `json:"role"` // member, manager, lead, owner
	Title          *string    `json:"title,omitempty"`
	IsPrimary      bool       `json:"is_primary"`
	JoinedAt       time.Time  `json:"joined_at"`
	JoinedBy       *uuid.UUID `json:"joined_by,omitempty"`

	// Populated fields
	User         *User         `json:"user,omitempty"`
	Organization *Organization `json:"organization,omitempty"`
}

// CreateOrganizationRequest represents a request to create a new organization
type CreateOrganizationRequest struct {
	Name        string                 `json:"name" binding:"required,min=1,max=100"`
	DisplayName *string                `json:"display_name,omitempty"`
	Description *string                `json:"description,omitempty"`
	ParentID    *uuid.UUID             `json:"parent_id,omitempty"`
	OrgType     string                 `json:"org_type,omitempty"`
	Code        *string                `json:"code,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// UpdateOrganizationRequest represents a request to update an organization
type UpdateOrganizationRequest struct {
	Name        *string                `json:"name,omitempty"`
	DisplayName *string                `json:"display_name,omitempty"`
	Description *string                `json:"description,omitempty"`
	ParentID    *uuid.UUID             `json:"parent_id,omitempty"`
	OrgType     *string                `json:"org_type,omitempty"`
	Code        *string                `json:"code,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
	IsActive    *bool                  `json:"is_active,omitempty"`
}

// AddOrgMemberRequest represents a request to add a member to an organization
type AddOrgMemberRequest struct {
	UserID    uuid.UUID `json:"user_id" binding:"required"`
	Role      string    `json:"role,omitempty"`
	Title     *string   `json:"title,omitempty"`
	IsPrimary bool      `json:"is_primary,omitempty"`
}

// UpdateOrgMemberRequest represents a request to update a member's role/title
type UpdateOrgMemberRequest struct {
	Role      *string `json:"role,omitempty"`
	Title     *string `json:"title,omitempty"`
	IsPrimary *bool   `json:"is_primary,omitempty"`
}

// AddOrgMembersRequest represents a request to add multiple members
type AddOrgMembersRequest struct {
	UserIDs []uuid.UUID `json:"user_ids" binding:"required,min=1"`
	Role    string      `json:"role,omitempty"`
}

// RemoveOrgMembersRequest represents a request to remove members
type RemoveOrgMembersRequest struct {
	UserIDs []uuid.UUID `json:"user_ids" binding:"required,min=1"`
}

// OrganizationListResponse represents the response for listing organizations
type OrganizationListResponse struct {
	Organizations []*Organization `json:"organizations"`
	Total         int             `json:"total"`
	Page          int             `json:"page"`
	PageSize      int             `json:"page_size"`
	TotalPages    int             `json:"total_pages"`
}

// OrgMembersResponse represents the response for listing organization members
type OrgMembersResponse struct {
	Members    []*OrgMember `json:"members"`
	Total      int          `json:"total"`
	Page       int          `json:"page"`
	PageSize   int          `json:"page_size"`
	TotalPages int          `json:"total_pages"`
}

// OrganizationTreeNode represents a node in the organization tree
type OrganizationTreeNode struct {
	*Organization
	Children []*OrganizationTreeNode `json:"children,omitempty"`
}

// OrgRoleAssignment represents a role assigned to an organization.
type OrgRoleAssignment struct {
	ID              uuid.UUID  `json:"id"`
	OrganizationID  uuid.UUID  `json:"organization_id"`
	RoleID          uuid.UUID  `json:"role_id"`
	RoleName        string     `json:"role_name,omitempty"`
	RoleDisplayName string     `json:"role_display_name,omitempty"`
	Inherit         bool       `json:"inherit"`
	AssignedAt      time.Time  `json:"assigned_at"`
	AssignedBy      *uuid.UUID `json:"assigned_by,omitempty"`
}

// AssignOrgRolesRequest represents a request to assign roles to an org.
type AssignOrgRolesRequest struct {
	RoleIDs []uuid.UUID `json:"role_ids" binding:"required"`
	Inherit *bool       `json:"inherit,omitempty"`
}

// UnassignOrgRolesRequest represents a request to remove roles from an org.
type UnassignOrgRolesRequest struct {
	RoleIDs []uuid.UUID `json:"role_ids" binding:"required"`
}

// ValidOrgTypes returns valid organization types
func ValidOrgTypes() []string {
	return []string{
		OrgTypeCompany,
		OrgTypeDivision,
		OrgTypeDepartment,
		OrgTypeTeam,
		OrgTypeProject,
	}
}

// ValidOrgRoles returns valid organization member roles
func ValidOrgRoles() []string {
	return []string{
		OrgRoleMember,
		OrgRoleManager,
		OrgRoleLead,
		OrgRoleOwner,
	}
}

// IsValidOrgType checks if an org type is valid
func IsValidOrgType(orgType string) bool {
	for _, t := range ValidOrgTypes() {
		if t == orgType {
			return true
		}
	}
	return false
}

// IsValidOrgRole checks if an org role is valid
func IsValidOrgRole(role string) bool {
	for _, r := range ValidOrgRoles() {
		if r == role {
			return true
		}
	}
	return false
}
