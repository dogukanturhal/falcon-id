// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

// organizationServiceOrgRepo defines the organization repository methods needed by OrganizationService.
type organizationServiceOrgRepo interface {
	Create(ctx context.Context, org *models.Organization) error
	GetByID(ctx context.Context, id uuid.UUID) (*models.Organization, error)
	GetByName(ctx context.Context, tenantID uuid.UUID, name string, parentID *uuid.UUID) (*models.Organization, error)
	List(ctx context.Context, tenantID uuid.UUID, page, pageSize int, search string, orgType string) ([]*models.Organization, int, error)
	Update(ctx context.Context, org *models.Organization) error
	Delete(ctx context.Context, id uuid.UUID) error
	AddMember(ctx context.Context, orgID, userID uuid.UUID, role string, title *string, isPrimary bool, addedBy *uuid.UUID) error
	RemoveMember(ctx context.Context, orgID, userID uuid.UUID) error
	UpdateMember(ctx context.Context, orgID, userID uuid.UUID, role *string, title *string, isPrimary *bool) error
	GetMembers(ctx context.Context, orgID uuid.UUID, page, pageSize int) ([]*models.OrgMember, int, error)
	GetUserOrganizations(ctx context.Context, userID uuid.UUID) ([]*models.OrgMember, error)
	GetUserPrimaryOrganization(ctx context.Context, userID uuid.UUID) (*models.OrgMember, error)
	GetChildren(ctx context.Context, parentID uuid.UUID) ([]*models.Organization, error)
	GetRootOrganizations(ctx context.Context, tenantID uuid.UUID) ([]*models.Organization, error)
	GetDescendants(ctx context.Context, orgID uuid.UUID) ([]*models.Organization, error)
	GetAncestors(ctx context.Context, orgID uuid.UUID) ([]*models.Organization, error)
	GetOrgRoleAssignments(ctx context.Context, orgID uuid.UUID) ([]models.OrgRoleAssignment, error)
	AssignOrgRole(ctx context.Context, orgID, roleID uuid.UUID, inherit bool, assignedBy *uuid.UUID) error
	RemoveOrgRole(ctx context.Context, orgID, roleID uuid.UUID) error
}

// organizationServiceUserRepo defines the user repository methods needed by OrganizationService.
type organizationServiceUserRepo interface {
	GetByID(ctx context.Context, id uuid.UUID) (*models.User, error)
}

// OrganizationService handles organization business logic
type OrganizationService struct {
	orgRepo  organizationServiceOrgRepo
	userRepo organizationServiceUserRepo
}

// NewOrganizationService creates a new OrganizationService
func NewOrganizationService(
	orgRepo organizationServiceOrgRepo,
	userRepo organizationServiceUserRepo,
) *OrganizationService {
	return &OrganizationService{
		orgRepo:  orgRepo,
		userRepo: userRepo,
	}
}

// ==================== Organization CRUD ====================

// CreateOrganization creates a new organization
func (s *OrganizationService) CreateOrganization(ctx context.Context, tenantID uuid.UUID, req *models.CreateOrganizationRequest, createdBy *uuid.UUID) (*models.Organization, error) {
	// Check if organization name already exists at this level
	_, err := s.orgRepo.GetByName(ctx, tenantID, req.Name, req.ParentID)
	if err == nil {
		return nil, fmt.Errorf("organization with name '%s' already exists at this level", req.Name)
	}

	// Validate parent if specified
	if req.ParentID != nil {
		parent, err := s.orgRepo.GetByID(ctx, *req.ParentID)
		if err != nil {
			return nil, fmt.Errorf("parent organization not found")
		}
		if parent.TenantID != tenantID {
			return nil, fmt.Errorf("parent organization belongs to different tenant")
		}
	}

	// Set default org type
	orgType := req.OrgType
	if orgType == "" {
		orgType = models.OrgTypeDepartment
	}
	if !models.IsValidOrgType(orgType) {
		return nil, fmt.Errorf("invalid organization type: %s", orgType)
	}

	now := time.Now()
	org := &models.Organization{
		ID:          uuid.New(),
		TenantID:    tenantID,
		ParentID:    req.ParentID,
		Name:        req.Name,
		DisplayName: req.DisplayName,
		Description: req.Description,
		OrgType:     orgType,
		Code:        req.Code,
		Metadata:    req.Metadata,
		IsActive:    true,
		CreatedAt:   now,
		UpdatedAt:   now,
		CreatedBy:   createdBy,
	}

	if err := s.orgRepo.Create(ctx, org); err != nil {
		return nil, fmt.Errorf("CreateOrganization: %w", err)
	}

	return s.orgRepo.GetByID(ctx, org.ID)
}

// GetOrganization retrieves an organization by ID
func (s *OrganizationService) GetOrganization(ctx context.Context, orgID uuid.UUID) (*models.Organization, error) {
	return s.orgRepo.GetByID(ctx, orgID)
}

// GetOrganizationWithDetails retrieves an organization with ancestors and children
func (s *OrganizationService) GetOrganizationWithDetails(ctx context.Context, orgID uuid.UUID) (*models.Organization, error) {
	org, err := s.orgRepo.GetByID(ctx, orgID)
	if err != nil {
		return nil, fmt.Errorf("GetOrganizationWithDetails: %w", err)
	}

	// Load ancestors
	ancestors, err := s.orgRepo.GetAncestors(ctx, orgID)
	if err == nil {
		org.Ancestors = ancestors
	}

	// Load children
	children, err := s.orgRepo.GetChildren(ctx, orgID)
	if err == nil {
		org.Children = children
	}

	// Load parent
	if org.ParentID != nil {
		parent, err := s.orgRepo.GetByID(ctx, *org.ParentID)
		if err == nil {
			org.Parent = parent
		}
	}

	return org, nil
}

// ListOrganizations lists all organizations for a tenant
func (s *OrganizationService) ListOrganizations(ctx context.Context, tenantID uuid.UUID, page, pageSize int, search, orgType string) (*models.OrganizationListResponse, error) {
	orgs, total, err := s.orgRepo.List(ctx, tenantID, page, pageSize, search, orgType)
	if err != nil {
		return nil, fmt.Errorf("ListOrganizations: %w", err)
	}

	totalPages := (total + pageSize - 1) / pageSize

	return &models.OrganizationListResponse{
		Organizations: orgs,
		Total:         total,
		Page:          page,
		PageSize:      pageSize,
		TotalPages:    totalPages,
	}, nil
}

// UpdateOrganization updates an organization
func (s *OrganizationService) UpdateOrganization(ctx context.Context, orgID uuid.UUID, req *models.UpdateOrganizationRequest) (*models.Organization, error) {
	org, err := s.orgRepo.GetByID(ctx, orgID)
	if err != nil {
		return nil, fmt.Errorf("UpdateOrganization: %w", err)
	}

	// Check name uniqueness if changing
	if req.Name != nil && *req.Name != org.Name {
		_, err := s.orgRepo.GetByName(ctx, org.TenantID, *req.Name, org.ParentID)
		if err == nil {
			return nil, fmt.Errorf("organization with name '%s' already exists at this level", *req.Name)
		}
		org.Name = *req.Name
	}

	// Validate parent if changing
	if req.ParentID != nil {
		if *req.ParentID == orgID {
			return nil, fmt.Errorf("organization cannot be its own parent")
		}
		// Check for circular reference
		descendants, _ := s.orgRepo.GetDescendants(ctx, orgID)
		for _, desc := range descendants {
			if desc.ID == *req.ParentID {
				return nil, fmt.Errorf("cannot set a descendant as parent (circular reference)")
			}
		}
		// Validate parent exists
		parent, err := s.orgRepo.GetByID(ctx, *req.ParentID)
		if err != nil {
			return nil, fmt.Errorf("parent organization not found")
		}
		if parent.TenantID != org.TenantID {
			return nil, fmt.Errorf("parent organization belongs to different tenant")
		}
		org.ParentID = req.ParentID
	}

	if req.DisplayName != nil {
		org.DisplayName = req.DisplayName
	}
	if req.Description != nil {
		org.Description = req.Description
	}
	if req.OrgType != nil {
		if !models.IsValidOrgType(*req.OrgType) {
			return nil, fmt.Errorf("invalid organization type: %s", *req.OrgType)
		}
		org.OrgType = *req.OrgType
	}
	if req.Code != nil {
		org.Code = req.Code
	}
	if req.Metadata != nil {
		org.Metadata = req.Metadata
	}
	if req.IsActive != nil {
		org.IsActive = *req.IsActive
	}

	org.UpdatedAt = time.Now()

	if err := s.orgRepo.Update(ctx, org); err != nil {
		return nil, fmt.Errorf("UpdateOrganization: %w", err)
	}

	return s.orgRepo.GetByID(ctx, orgID)
}

// DeleteOrganization deletes an organization
func (s *OrganizationService) DeleteOrganization(ctx context.Context, orgID uuid.UUID) error {
	org, err := s.orgRepo.GetByID(ctx, orgID)
	if err != nil {
		return fmt.Errorf("DeleteOrganization: %w", err)
	}

	// Check if organization has children
	children, err := s.orgRepo.GetChildren(ctx, orgID)
	if err != nil {
		return fmt.Errorf("DeleteOrganization: %w", err)
	}
	if len(children) > 0 {
		return fmt.Errorf("cannot delete organization with child organizations")
	}

	// Check if organization has members
	if org.MemberCount > 0 {
		return fmt.Errorf("cannot delete organization with members")
	}

	return s.orgRepo.Delete(ctx, orgID)
}

// ==================== Member Management ====================

// AddMember adds a user to an organization
func (s *OrganizationService) AddMember(ctx context.Context, orgID uuid.UUID, req *models.AddOrgMemberRequest, addedBy *uuid.UUID) error {
	org, err := s.orgRepo.GetByID(ctx, orgID)
	if err != nil {
		return fmt.Errorf("AddMember: %w", err)
	}

	// Verify user exists and belongs to same tenant
	user, err := s.userRepo.GetByID(ctx, req.UserID)
	if err != nil {
		return fmt.Errorf("user not found")
	}
	if user.TenantID != org.TenantID {
		return fmt.Errorf("user belongs to different tenant")
	}

	// Validate role
	role := req.Role
	if role == "" {
		role = models.OrgRoleMember
	}
	if !models.IsValidOrgRole(role) {
		return fmt.Errorf("invalid role: %s", role)
	}

	return s.orgRepo.AddMember(ctx, orgID, req.UserID, role, req.Title, req.IsPrimary, addedBy)
}

// AddMembers adds multiple users to an organization
func (s *OrganizationService) AddMembers(ctx context.Context, orgID uuid.UUID, req *models.AddOrgMembersRequest, addedBy *uuid.UUID) error {
	org, err := s.orgRepo.GetByID(ctx, orgID)
	if err != nil {
		return fmt.Errorf("AddMembers: %w", err)
	}

	role := req.Role
	if role == "" {
		role = models.OrgRoleMember
	}
	if !models.IsValidOrgRole(role) {
		return fmt.Errorf("invalid role: %s", role)
	}

	for _, userID := range req.UserIDs {
		user, err := s.userRepo.GetByID(ctx, userID)
		if err != nil {
			continue // Skip non-existent users
		}
		if user.TenantID != org.TenantID {
			continue // Skip users from different tenant
		}

		if err := s.orgRepo.AddMember(ctx, orgID, userID, role, nil, false, addedBy); err != nil {
			continue
		}
	}

	return nil
}

// RemoveMembers removes users from an organization
func (s *OrganizationService) RemoveMembers(ctx context.Context, orgID uuid.UUID, userIDs []uuid.UUID) error {
	for _, userID := range userIDs {
		if err := s.orgRepo.RemoveMember(ctx, orgID, userID); err != nil {
			continue
		}
	}
	return nil
}

// UpdateMember updates a member's role/title
func (s *OrganizationService) UpdateMember(ctx context.Context, orgID, userID uuid.UUID, req *models.UpdateOrgMemberRequest) error {
	// Validate role if provided
	if req.Role != nil && !models.IsValidOrgRole(*req.Role) {
		return fmt.Errorf("invalid role: %s", *req.Role)
	}

	return s.orgRepo.UpdateMember(ctx, orgID, userID, req.Role, req.Title, req.IsPrimary)
}

// GetMembers gets all members of an organization
func (s *OrganizationService) GetMembers(ctx context.Context, orgID uuid.UUID, page, pageSize int) (*models.OrgMembersResponse, error) {
	members, total, err := s.orgRepo.GetMembers(ctx, orgID, page, pageSize)
	if err != nil {
		return nil, fmt.Errorf("GetMembers: %w", err)
	}

	totalPages := (total + pageSize - 1) / pageSize

	return &models.OrgMembersResponse{
		Members:    members,
		Total:      total,
		Page:       page,
		PageSize:   pageSize,
		TotalPages: totalPages,
	}, nil
}

// GetUserOrganizations gets all organizations a user belongs to
func (s *OrganizationService) GetUserOrganizations(ctx context.Context, userID uuid.UUID) ([]*models.OrgMember, error) {
	return s.orgRepo.GetUserOrganizations(ctx, userID)
}

// GetUserPrimaryOrganization gets a user's primary organization
func (s *OrganizationService) GetUserPrimaryOrganization(ctx context.Context, userID uuid.UUID) (*models.OrgMember, error) {
	return s.orgRepo.GetUserPrimaryOrganization(ctx, userID)
}

// ==================== Hierarchy Operations ====================

// GetOrganizationTree gets the full organization tree for a tenant
func (s *OrganizationService) GetOrganizationTree(ctx context.Context, tenantID uuid.UUID) ([]*models.OrganizationTreeNode, error) {
	roots, err := s.orgRepo.GetRootOrganizations(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("GetOrganizationTree: %w", err)
	}

	var tree []*models.OrganizationTreeNode
	for _, root := range roots {
		node := &models.OrganizationTreeNode{
			Organization: root,
		}
		s.loadChildNodes(ctx, node)
		tree = append(tree, node)
	}

	return tree, nil
}

func (s *OrganizationService) loadChildNodes(ctx context.Context, node *models.OrganizationTreeNode) {
	children, err := s.orgRepo.GetChildren(ctx, node.ID)
	if err != nil {
		return
	}

	for _, child := range children {
		childNode := &models.OrganizationTreeNode{
			Organization: child,
		}
		s.loadChildNodes(ctx, childNode)
		node.Children = append(node.Children, childNode)
	}
}

// GetAncestors gets all ancestors of an organization
func (s *OrganizationService) GetAncestors(ctx context.Context, orgID uuid.UUID) ([]*models.Organization, error) {
	return s.orgRepo.GetAncestors(ctx, orgID)
}

// GetDescendants gets all descendants of an organization
func (s *OrganizationService) GetDescendants(ctx context.Context, orgID uuid.UUID) ([]*models.Organization, error) {
	return s.orgRepo.GetDescendants(ctx, orgID)
}

// GetOrgTypes returns valid organization types
func (s *OrganizationService) GetOrgTypes() []string {
	return models.ValidOrgTypes()
}

// GetOrgRoles returns valid organization member roles
func (s *OrganizationService) GetOrgRoles() []string {
	return models.ValidOrgRoles()
}

// ==================== Organization IAM Role Assignments ====================

// GetAssignedRoles returns all IAM roles assigned to the given organization.
func (s *OrganizationService) GetAssignedRoles(ctx context.Context, orgID uuid.UUID) ([]models.OrgRoleAssignment, error) {
	return s.orgRepo.GetOrgRoleAssignments(ctx, orgID)
}

// AssignRoles assigns one or more IAM roles to an organization.
func (s *OrganizationService) AssignRoles(ctx context.Context, orgID uuid.UUID, req *models.AssignOrgRolesRequest, assignedBy *uuid.UUID) error {
	inherit := true
	if req.Inherit != nil {
		inherit = *req.Inherit
	}
	for _, roleID := range req.RoleIDs {
		if err := s.orgRepo.AssignOrgRole(ctx, orgID, roleID, inherit, assignedBy); err != nil {
			return fmt.Errorf("AssignRoles: role %s: %w", roleID, err)
		}
	}
	return nil
}

// UnassignRoles removes one or more IAM roles from an organization.
func (s *OrganizationService) UnassignRoles(ctx context.Context, orgID uuid.UUID, roleIDs []uuid.UUID) error {
	for _, roleID := range roleIDs {
		if err := s.orgRepo.RemoveOrgRole(ctx, orgID, roleID); err != nil {
			return fmt.Errorf("UnassignRoles: role %s: %w", roleID, err)
		}
	}
	return nil
}
