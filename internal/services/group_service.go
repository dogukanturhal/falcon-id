// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

// groupServiceGroupRepo defines the group repository methods needed by GroupService.
type groupServiceGroupRepo interface {
	GetByName(ctx context.Context, tenantID uuid.UUID, name string) (*models.Group, error)
	GetByID(ctx context.Context, id uuid.UUID) (*models.Group, error)
	Create(ctx context.Context, group *models.Group) error
	AssignRole(ctx context.Context, groupID, roleID uuid.UUID, assignedBy *uuid.UUID) error
	AddMember(ctx context.Context, groupID, userID uuid.UUID, addedBy *uuid.UUID) error
	Update(ctx context.Context, group *models.Group) error
	Delete(ctx context.Context, id uuid.UUID) error
	GetRoles(ctx context.Context, groupID uuid.UUID) ([]*models.Role, error)
	GetChildGroups(ctx context.Context, parentID uuid.UUID) ([]*models.Group, error)
	List(ctx context.Context, tenantID uuid.UUID, page, pageSize int, search string) ([]*models.Group, int, error)
	GetMembers(ctx context.Context, groupID uuid.UUID, page, pageSize int) ([]*models.GroupMember, int, error)
	GetUserGroups(ctx context.Context, userID uuid.UUID) ([]*models.Group, error)
	RemoveMember(ctx context.Context, groupID, userID uuid.UUID) error
	RemoveRole(ctx context.Context, groupID, roleID uuid.UUID) error
	GetUserEffectiveRoles(ctx context.Context, userID uuid.UUID) ([]*models.EffectiveRole, error)
	GetRootGroups(ctx context.Context, tenantID uuid.UUID) ([]*models.Group, error)
}

// groupServiceUserRepo defines the user repository methods needed by GroupService.
type groupServiceUserRepo interface {
	GetByID(ctx context.Context, id uuid.UUID) (*models.User, error)
}

// groupServiceRoleRepo defines the role repository methods needed by GroupService.
type groupServiceRoleRepo interface {
	GetByID(ctx context.Context, id uuid.UUID) (*models.Role, error)
}

// GroupService handles group business logic
type GroupService struct {
	groupRepo  groupServiceGroupRepo
	userRepo   groupServiceUserRepo
	roleRepo   groupServiceRoleRepo
	sodService userServiceSoDEvaluator // Optional: ADR-A10 SoD warn-mode evaluation on group role-set writes
}

// SetSoDService wires ADR-A10 SoD evaluation into GroupService. Safe to
// call with nil (evaluation is then simply skipped). A group's role set
// change affects every member's effective permissions, so SetRoles
// evaluates SoD per member — see SetRoles.
func (s *GroupService) SetSoDService(svc userServiceSoDEvaluator) {
	s.sodService = svc
}

// NewGroupService creates a new GroupService
func NewGroupService(
	groupRepo groupServiceGroupRepo,
	userRepo groupServiceUserRepo,
	roleRepo groupServiceRoleRepo,
) *GroupService {
	return &GroupService{
		groupRepo: groupRepo,
		userRepo:  userRepo,
		roleRepo:  roleRepo,
	}
}

// ==================== Group CRUD ====================

// CreateGroup creates a new group
func (s *GroupService) CreateGroup(ctx context.Context, tenantID uuid.UUID, req *models.CreateGroupRequest, createdBy *uuid.UUID) (*models.Group, error) {
	// Check if group name already exists
	_, err := s.groupRepo.GetByName(ctx, tenantID, req.Name)
	if err == nil {
		return nil, fmt.Errorf("group with name '%s' already exists", req.Name)
	}

	// Validate parent group if specified
	if req.ParentGroupID != nil {
		parentGroup, err := s.groupRepo.GetByID(ctx, *req.ParentGroupID)
		if err != nil {
			return nil, fmt.Errorf("parent group not found")
		}
		if parentGroup.TenantID != tenantID {
			return nil, fmt.Errorf("parent group belongs to different tenant")
		}
	}

	now := time.Now()
	group := &models.Group{
		ID:            uuid.New(),
		TenantID:      tenantID,
		Name:          req.Name,
		DisplayName:   req.DisplayName,
		Description:   req.Description,
		ParentGroupID: req.ParentGroupID,
		IsSystem:      false,
		Metadata:      req.Metadata,
		CreatedAt:     now,
		UpdatedAt:     now,
		CreatedBy:     createdBy,
	}

	if err := s.groupRepo.Create(ctx, group); err != nil {
		return nil, fmt.Errorf("CreateGroup: %w", err)
	}

	// Assign initial roles if specified
	if len(req.RoleIDs) > 0 {
		for _, roleID := range req.RoleIDs {
			if err := s.groupRepo.AssignRole(ctx, group.ID, roleID, createdBy); err != nil {
				// Log error but continue
				continue
			}
		}
	}

	// Add initial members if specified
	if len(req.MemberIDs) > 0 {
		for _, userID := range req.MemberIDs {
			if err := s.groupRepo.AddMember(ctx, group.ID, userID, createdBy); err != nil {
				// Log error but continue
				continue
			}
		}
	}

	// Reload to get counts
	return s.groupRepo.GetByID(ctx, group.ID)
}

// GetGroup retrieves a group by ID
func (s *GroupService) GetGroup(ctx context.Context, groupID uuid.UUID) (*models.Group, error) {
	group, err := s.groupRepo.GetByID(ctx, groupID)
	if err != nil {
		return nil, fmt.Errorf("GetGroup: %w", err)
	}

	// Load roles
	roles, err := s.groupRepo.GetRoles(ctx, groupID)
	if err == nil {
		group.Roles = roles
	}

	return group, nil
}

// GetGroupWithDetails retrieves a group with all details (members, roles, children)
func (s *GroupService) GetGroupWithDetails(ctx context.Context, groupID uuid.UUID) (*models.Group, error) {
	group, err := s.groupRepo.GetByID(ctx, groupID)
	if err != nil {
		return nil, fmt.Errorf("GetGroupWithDetails: %w", err)
	}

	// Load roles
	roles, err := s.groupRepo.GetRoles(ctx, groupID)
	if err == nil {
		group.Roles = roles
	}

	// Load child groups
	children, err := s.groupRepo.GetChildGroups(ctx, groupID)
	if err == nil {
		group.ChildGroups = children
	}

	// Load parent group if exists
	if group.ParentGroupID != nil {
		parent, err := s.groupRepo.GetByID(ctx, *group.ParentGroupID)
		if err == nil {
			group.ParentGroup = parent
		}
	}

	return group, nil
}

// ListGroups lists all groups for a tenant
func (s *GroupService) ListGroups(ctx context.Context, tenantID uuid.UUID, page, pageSize int, search string) (*models.IAMGroupListResponse, error) {
	groups, total, err := s.groupRepo.List(ctx, tenantID, page, pageSize, search)
	if err != nil {
		return nil, fmt.Errorf("ListGroups: %w", err)
	}

	totalPages := (total + pageSize - 1) / pageSize

	return &models.IAMGroupListResponse{
		Groups:     groups,
		Total:      total,
		Page:       page,
		PageSize:   pageSize,
		TotalPages: totalPages,
	}, nil
}

// UpdateGroup updates a group
func (s *GroupService) UpdateGroup(ctx context.Context, groupID uuid.UUID, req *models.UpdateGroupRequest) (*models.Group, error) {
	group, err := s.groupRepo.GetByID(ctx, groupID)
	if err != nil {
		return nil, fmt.Errorf("UpdateGroup: %w", err)
	}

	if group.IsSystem {
		return nil, fmt.Errorf("cannot modify system group")
	}

	// Check name uniqueness if changing
	if req.Name != nil && *req.Name != group.Name {
		_, err := s.groupRepo.GetByName(ctx, group.TenantID, *req.Name)
		if err == nil {
			return nil, fmt.Errorf("group with name '%s' already exists", *req.Name)
		}
		group.Name = *req.Name
	}

	// Validate parent group if changing
	if req.ParentGroupID != nil {
		// Prevent setting self as parent
		if *req.ParentGroupID == groupID {
			return nil, fmt.Errorf("group cannot be its own parent")
		}
		// Validate parent exists and belongs to same tenant
		parentGroup, err := s.groupRepo.GetByID(ctx, *req.ParentGroupID)
		if err != nil {
			return nil, fmt.Errorf("parent group not found")
		}
		if parentGroup.TenantID != group.TenantID {
			return nil, fmt.Errorf("parent group belongs to different tenant")
		}
		// Check for circular references
		// SECURITY: Prevent circular parent-child relationships which could cause infinite loops
		if err := s.detectCircularReference(ctx, groupID, *req.ParentGroupID); err != nil {
			return nil, fmt.Errorf("UpdateGroup: %w", err)
		}
		group.ParentGroupID = req.ParentGroupID
	}

	if req.DisplayName != nil {
		group.DisplayName = req.DisplayName
	}
	if req.Description != nil {
		group.Description = req.Description
	}
	if req.Metadata != nil {
		group.Metadata = req.Metadata
	}

	group.UpdatedAt = time.Now()

	if err := s.groupRepo.Update(ctx, group); err != nil {
		return nil, fmt.Errorf("UpdateGroup: %w", err)
	}

	return s.groupRepo.GetByID(ctx, groupID)
}

// DeleteGroup deletes a group
func (s *GroupService) DeleteGroup(ctx context.Context, groupID uuid.UUID) error {
	group, err := s.groupRepo.GetByID(ctx, groupID)
	if err != nil {
		return fmt.Errorf("DeleteGroup: %w", err)
	}

	if group.IsSystem {
		return fmt.Errorf("cannot delete system group")
	}

	return s.groupRepo.Delete(ctx, groupID)
}

// ==================== Member Management ====================

// AddMembers adds users to a group
func (s *GroupService) AddMembers(ctx context.Context, groupID uuid.UUID, userIDs []uuid.UUID, addedBy *uuid.UUID) error {
	group, err := s.groupRepo.GetByID(ctx, groupID)
	if err != nil {
		return fmt.Errorf("AddMembers: %w", err)
	}

	for _, userID := range userIDs {
		// Verify user exists and belongs to same tenant
		user, err := s.userRepo.GetByID(ctx, userID)
		if err != nil || user == nil {
			continue // Skip non-existent users
		}
		if user.TenantID != group.TenantID {
			continue // Skip users from different tenant
		}

		if err := s.groupRepo.AddMember(ctx, groupID, userID, addedBy); err != nil {
			// Log error but continue
			continue
		}
	}

	return nil
}

// RemoveMembers removes users from a group
func (s *GroupService) RemoveMembers(ctx context.Context, groupID uuid.UUID, userIDs []uuid.UUID) error {
	for _, userID := range userIDs {
		if err := s.groupRepo.RemoveMember(ctx, groupID, userID); err != nil {
			// Log error but continue
			continue
		}
	}
	return nil
}

// GetMembers gets all members of a group
func (s *GroupService) GetMembers(ctx context.Context, groupID uuid.UUID, page, pageSize int) (*models.GroupMembersResponse, error) {
	members, total, err := s.groupRepo.GetMembers(ctx, groupID, page, pageSize)
	if err != nil {
		return nil, fmt.Errorf("GetMembers: %w", err)
	}

	totalPages := (total + pageSize - 1) / pageSize

	return &models.GroupMembersResponse{
		Members:    members,
		Total:      total,
		Page:       page,
		PageSize:   pageSize,
		TotalPages: totalPages,
	}, nil
}

// GetUserGroups gets all groups a user belongs to
func (s *GroupService) GetUserGroups(ctx context.Context, userID uuid.UUID) ([]*models.Group, error) {
	return s.groupRepo.GetUserGroups(ctx, userID)
}

// GetUserGroupPaths returns the `/parent/child` hierarchy path for each group
// the user is a direct member of. Used as the source for the OIDC `groups`
// claim (see docs/oidc-claims-groups-amr.md). The format matches Keycloak's
// default OIDC group membership mapper (`Full group path = true`) so the
// emitted claim is consumable by Argo CD / Grafana / oauth2-proxy /
// Pomerium / Kubernetes `--oidc-groups-claim` without additional mapping.
//
// Top-level groups render as `/<name>`. Nested groups render as
// `/<ancestor>/<parent>/<name>`. The parent walk is bounded to
// maxGroupHierarchyDepth hops as defence against pathological data
// (the schema forbids cycles, but we never want token issuance to loop).
// Fetched ancestors are memoised per call so repeated lookups within the
// same user's group set cost one repo call each.
func (s *GroupService) GetUserGroupPaths(ctx context.Context, userID uuid.UUID) ([]string, error) {
	groups, err := s.groupRepo.GetUserGroups(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("GetUserGroupPaths: %w", err)
	}
	cache := make(map[uuid.UUID]*models.Group, len(groups))
	for _, g := range groups {
		if g != nil {
			cache[g.ID] = g
		}
	}
	paths := make([]string, 0, len(groups))
	for _, g := range groups {
		if g == nil {
			continue
		}
		paths = append(paths, s.buildGroupPath(ctx, g, cache))
	}
	return paths, nil
}

// buildGroupPath walks ParentGroupID up to maxGroupHierarchyDepth levels,
// stopping when a cycle is detected (the same group appears twice) or a
// parent cannot be loaded. Any interruption yields a best-effort prefix so
// the resulting claim is always rooted.
func (s *GroupService) buildGroupPath(
	ctx context.Context,
	start *models.Group,
	cache map[uuid.UUID]*models.Group,
) string {
	names := []string{start.Name}
	seen := map[uuid.UUID]struct{}{start.ID: {}}
	current := start
	for i := 0; i < maxGroupHierarchyDepth && current.ParentGroupID != nil; i++ {
		pid := *current.ParentGroupID
		if _, cycle := seen[pid]; cycle {
			break
		}
		parent, ok := cache[pid]
		if !ok {
			p, err := s.groupRepo.GetByID(ctx, pid)
			if err != nil || p == nil {
				break
			}
			cache[pid] = p
			parent = p
		}
		names = append([]string{parent.Name}, names...)
		seen[parent.ID] = struct{}{}
		current = parent
	}
	return "/" + strings.Join(names, "/")
}

// ==================== Role Management ====================

// AssignRoles assigns roles to a group
func (s *GroupService) AssignRoles(ctx context.Context, groupID uuid.UUID, roleIDs []uuid.UUID, assignedBy *uuid.UUID) error {
	group, err := s.groupRepo.GetByID(ctx, groupID)
	if err != nil {
		return fmt.Errorf("AssignRoles: %w", err)
	}

	for _, roleID := range roleIDs {
		// Verify role exists and belongs to same tenant
		role, err := s.roleRepo.GetByID(ctx, roleID)
		if err != nil || role == nil {
			continue // Skip non-existent roles
		}
		if role.TenantID != group.TenantID {
			continue // Skip roles from different tenant
		}

		if err := s.groupRepo.AssignRole(ctx, groupID, roleID, assignedBy); err != nil {
			continue
		}
	}

	return nil
}

// RemoveRoles removes roles from a group
func (s *GroupService) RemoveRoles(ctx context.Context, groupID uuid.UUID, roleIDs []uuid.UUID) error {
	for _, roleID := range roleIDs {
		if err := s.groupRepo.RemoveRole(ctx, groupID, roleID); err != nil {
			continue
		}
	}
	return nil
}

// GetGroupRoles gets all roles assigned to a group
func (s *GroupService) GetGroupRoles(ctx context.Context, groupID uuid.UUID) ([]*models.Role, error) {
	return s.groupRepo.GetRoles(ctx, groupID)
}

// SetRoles replaces all roles for a group
func (s *GroupService) SetRoles(ctx context.Context, groupID uuid.UUID, roleIDs []uuid.UUID, assignedBy *uuid.UUID) error {
	group, err := s.groupRepo.GetByID(ctx, groupID)
	if err != nil {
		return fmt.Errorf("SetRoles: %w", err)
	}

	// Get current roles
	currentRoles, err := s.groupRepo.GetRoles(ctx, groupID)
	if err != nil {
		return fmt.Errorf("SetRoles: %w", err)
	}

	// Create maps for comparison
	currentRoleMap := make(map[uuid.UUID]bool)
	for _, role := range currentRoles {
		currentRoleMap[role.ID] = true
	}

	newRoleMap := make(map[uuid.UUID]bool)
	for _, roleID := range roleIDs {
		newRoleMap[roleID] = true
	}

	// Remove roles that are no longer needed
	for _, role := range currentRoles {
		if !newRoleMap[role.ID] {
			_ = s.groupRepo.RemoveRole(ctx, groupID, role.ID)
		}
	}

	// Add new roles
	for _, roleID := range roleIDs {
		if !currentRoleMap[roleID] {
			// Verify role belongs to same tenant
			role, err := s.roleRepo.GetByID(ctx, roleID)
			if err != nil || role == nil || role.TenantID != group.TenantID {
				continue
			}
			_ = s.groupRepo.AssignRole(ctx, groupID, roleID, assignedBy)
		}
	}

	// ADR-A10 SoD (23-authorization-rbac-abac-rebac.md §5.2): a group's
	// role set is itself a "role-assignment write" affecting every
	// member's effective permissions — evaluate each member. Best-effort:
	// paginated, warn-mode only, never fails this write.
	if s.sodService != nil {
		s.evaluateSoDForMembers(ctx, group.TenantID, groupID, roleIDs)
	}

	return nil
}

// evaluateSoDForMembers walks every member of groupID and triggers an
// async, non-blocking ADR-A10 SoD evaluation for each — see SetRoles.
func (s *GroupService) evaluateSoDForMembers(ctx context.Context, tenantID, groupID uuid.UUID, roleIDs []uuid.UUID) {
	const pageSize = 200
	page := 1
	for {
		members, total, err := s.groupRepo.GetMembers(ctx, groupID, page, pageSize)
		if err != nil || len(members) == 0 {
			return
		}
		for _, m := range members {
			s.sodService.EvaluateUserAsync(ctx, tenantID, m.UserID, roleIDs)
		}
		if page*pageSize >= total {
			return
		}
		page++
	}
}

// ==================== Effective Permissions ====================

// GetUserEffectiveRoles gets all roles for a user including inherited from groups
func (s *GroupService) GetUserEffectiveRoles(ctx context.Context, userID uuid.UUID) ([]*models.EffectiveRole, error) {
	return s.groupRepo.GetUserEffectiveRoles(ctx, userID)
}

// ==================== Hierarchy ====================

// GetGroupTree gets the full group tree for a tenant
func (s *GroupService) GetGroupTree(ctx context.Context, tenantID uuid.UUID) ([]*models.Group, error) {
	rootGroups, err := s.groupRepo.GetRootGroups(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("GetGroupTree: %w", err)
	}

	// Recursively load children for each root group
	for _, group := range rootGroups {
		s.loadChildGroups(ctx, group)
	}

	return rootGroups, nil
}

func (s *GroupService) loadChildGroups(ctx context.Context, group *models.Group) {
	children, err := s.groupRepo.GetChildGroups(ctx, group.ID)
	if err != nil {
		return
	}

	group.ChildGroups = children

	for _, child := range children {
		s.loadChildGroups(ctx, child)
	}
}

// detectCircularReference checks if setting newParentID as parent of groupID would create a cycle
// This traverses up the parent chain from newParentID to ensure groupID is not an ancestor
func (s *GroupService) detectCircularReference(ctx context.Context, groupID, newParentID uuid.UUID) error {
	// Track visited groups to prevent infinite loops (defense in depth)
	visited := make(map[uuid.UUID]bool)
	path := []uuid.UUID{newParentID}

	currentID := newParentID

	// Traverse up the parent chain from the proposed parent
	for currentID != uuid.Nil {
		// Check if we've visited this group already (shouldn't happen with valid data)
		if visited[currentID] {
			return fmt.Errorf("circular reference detected: existing loop in group hierarchy at %s", currentID)
		}
		visited[currentID] = true

		// Check if the current group in the chain is the group we're trying to update
		if currentID == groupID {
			// Build a readable path for the error message
			pathStr := ""
			for i, id := range path {
				if i > 0 {
					pathStr += " -> "
				}
				pathStr += id.String()
			}
			pathStr += " -> " + groupID.String()

			return fmt.Errorf("circular reference detected: setting this parent would create cycle: %s", pathStr)
		}

		// Get the parent of current group
		currentGroup, err := s.groupRepo.GetByID(ctx, currentID)
		if err != nil {
			return fmt.Errorf("failed to verify parent hierarchy: %w", err)
		}

		// If no parent, we've reached the root
		if currentGroup.ParentGroupID == nil {
			break
		}

		// Move up to the parent
		path = append(path, *currentGroup.ParentGroupID)
		currentID = *currentGroup.ParentGroupID

		// Safety limit: prevent excessive traversal (should never reach this)
		if len(path) > 100 {
			return fmt.Errorf("group hierarchy too deep (>100 levels), possible data corruption")
		}
	}

	return nil
}
