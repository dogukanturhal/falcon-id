// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/dogukanturhal/falcon-id/internal/middleware"
	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/internal/services"
)

const (
	msgTenantIDNotFoundGroup = "Tenant ID not found in context"
	msgInternalErrorGroup    = "An internal error occurred"
	msgInvalidGroupID        = "Invalid group ID"
	msgUserNotFoundGroup     = "User not found"
)

// GroupHandler handles group-related HTTP requests
type GroupHandler struct {
	groupService *services.GroupService
	userService  *services.UserService
}

// NewGroupHandler creates a new GroupHandler
func NewGroupHandler(groupService *services.GroupService, userService *services.UserService) *GroupHandler {
	return &GroupHandler{
		groupService: groupService,
		userService:  userService,
	}
}

// validateGroupTenantAccess verifies the group belongs to the caller's tenant
func (h *GroupHandler) validateGroupTenantAccess(c *gin.Context, groupID uuid.UUID) bool {
	tenantID, exists := c.Get("tenant_id")
	if !exists {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgTenantIDNotFoundGroup})
		return false
	}

	group, err := h.groupService.GetGroup(c.Request.Context(), groupID)
	if err != nil || group == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Group not found"})
		return false
	}

	tenantUID, ok := tenantID.(uuid.UUID)
	if !ok || group.TenantID != tenantUID {
		c.JSON(http.StatusNotFound, gin.H{"error": "Group not found"})
		return false
	}

	return true
}

// ==================== Group CRUD Endpoints ====================

// ListGroups handles GET /api/admin/groups
func (h *GroupHandler) ListGroups(c *gin.Context) {
	tenantID, exists := c.Get("tenant_id")
	if !exists {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgTenantIDNotFoundGroup})
		return
	}

	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "20"))
	search := c.Query("search")

	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 100 {
		pageSize = 20
	}

	response, err := h.groupService.ListGroups(c.Request.Context(), tenantID.(uuid.UUID), page, pageSize, search)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": msgInternalErrorGroup})
		return
	}

	c.JSON(http.StatusOK, response)
}

// GetGroup handles GET /api/admin/groups/:id
func (h *GroupHandler) GetGroup(c *gin.Context) {
	groupID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgInvalidGroupID})
		return
	}

	// Validate tenant access
	if !h.validateGroupTenantAccess(c, groupID) {
		return
	}

	// Check for detailed=true query param
	detailed := c.Query("detailed") == queryBoolTrue

	var group *models.Group
	if detailed {
		group, err = h.groupService.GetGroupWithDetails(c.Request.Context(), groupID)
	} else {
		group, err = h.groupService.GetGroup(c.Request.Context(), groupID)
	}

	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, group)
}

// CreateGroup handles POST /api/admin/groups
func (h *GroupHandler) CreateGroup(c *gin.Context) {
	tenantID, exists := c.Get("tenant_id")
	if !exists {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgTenantIDNotFoundGroup})
		return
	}

	var req models.CreateGroupRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Get user ID from context
	var createdBy *uuid.UUID
	if userID, exists := c.Get("user_id"); exists {
		uid := userID.(uuid.UUID)
		createdBy = &uid
	}

	group, err := h.groupService.CreateGroup(c.Request.Context(), tenantID.(uuid.UUID), &req, createdBy)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, group)
}

// UpdateGroup handles PUT /api/admin/groups/:id
func (h *GroupHandler) UpdateGroup(c *gin.Context) {
	groupID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgInvalidGroupID})
		return
	}

	// Validate tenant access
	if !h.validateGroupTenantAccess(c, groupID) {
		return
	}

	var req models.UpdateGroupRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	group, err := h.groupService.UpdateGroup(c.Request.Context(), groupID, &req)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, group)
}

// DeleteGroup handles DELETE /api/admin/groups/:id
func (h *GroupHandler) DeleteGroup(c *gin.Context) {
	groupID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgInvalidGroupID})
		return
	}

	// Validate tenant access
	if !h.validateGroupTenantAccess(c, groupID) {
		return
	}

	if err := h.groupService.DeleteGroup(c.Request.Context(), groupID); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Group deleted successfully"})
}

// ==================== Member Management Endpoints ====================

// GetMembers handles GET /api/admin/groups/:id/members
func (h *GroupHandler) GetMembers(c *gin.Context) {
	groupID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgInvalidGroupID})
		return
	}

	// Validate tenant access
	if !h.validateGroupTenantAccess(c, groupID) {
		return
	}

	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "20"))

	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 100 {
		pageSize = 20
	}

	response, err := h.groupService.GetMembers(c.Request.Context(), groupID, page, pageSize)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": msgInternalErrorGroup})
		return
	}

	c.JSON(http.StatusOK, response)
}

// AddMembers handles POST /api/admin/groups/:id/members
func (h *GroupHandler) AddMembers(c *gin.Context) {
	groupID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgInvalidGroupID})
		return
	}

	// Validate tenant access
	if !h.validateGroupTenantAccess(c, groupID) {
		return
	}

	var req models.AddMembersRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var addedBy *uuid.UUID
	if userID, exists := c.Get("user_id"); exists {
		uid := userID.(uuid.UUID)
		addedBy = &uid
	}

	if err := h.groupService.AddMembers(c.Request.Context(), groupID, req.UserIDs, addedBy); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Members added successfully"})
}

// RemoveMembers handles DELETE /api/admin/groups/:id/members
func (h *GroupHandler) RemoveMembers(c *gin.Context) {
	groupID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgInvalidGroupID})
		return
	}

	// Validate tenant access
	if !h.validateGroupTenantAccess(c, groupID) {
		return
	}

	var req models.RemoveMembersRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := h.groupService.RemoveMembers(c.Request.Context(), groupID, req.UserIDs); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Members removed successfully"})
}

// ==================== Role Management Endpoints ====================

// GetGroupRoles handles GET /api/admin/groups/:id/roles
func (h *GroupHandler) GetGroupRoles(c *gin.Context) {
	groupID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgInvalidGroupID})
		return
	}

	// Validate tenant access
	if !h.validateGroupTenantAccess(c, groupID) {
		return
	}

	roles, err := h.groupService.GetGroupRoles(c.Request.Context(), groupID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": msgInternalErrorGroup})
		return
	}

	c.JSON(http.StatusOK, gin.H{"roles": roles})
}

// AssignRoles handles POST /api/admin/groups/:id/roles
func (h *GroupHandler) AssignRoles(c *gin.Context) {
	groupID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgInvalidGroupID})
		return
	}

	// Validate tenant access
	if !h.validateGroupTenantAccess(c, groupID) {
		return
	}

	var req models.AssignGroupRolesRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var assignedBy *uuid.UUID
	if userID, exists := c.Get("user_id"); exists {
		uid := userID.(uuid.UUID)
		assignedBy = &uid
	}

	if err := h.groupService.AssignRoles(c.Request.Context(), groupID, req.RoleIDs, assignedBy); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Roles assigned successfully"})
}

// RemoveRoles handles DELETE /api/admin/groups/:id/roles
func (h *GroupHandler) RemoveRoles(c *gin.Context) {
	groupID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgInvalidGroupID})
		return
	}

	// Validate tenant access
	if !h.validateGroupTenantAccess(c, groupID) {
		return
	}

	var req models.RemoveGroupRolesRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := h.groupService.RemoveRoles(c.Request.Context(), groupID, req.RoleIDs); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Roles removed successfully"})
}

// SetRoles handles PUT /api/admin/groups/:id/roles
func (h *GroupHandler) SetRoles(c *gin.Context) {
	groupID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgInvalidGroupID})
		return
	}

	// Validate tenant access
	if !h.validateGroupTenantAccess(c, groupID) {
		return
	}

	var req models.AssignGroupRolesRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var assignedBy *uuid.UUID
	if userID, exists := c.Get("user_id"); exists {
		uid := userID.(uuid.UUID)
		assignedBy = &uid
	}

	if err := h.groupService.SetRoles(c.Request.Context(), groupID, req.RoleIDs, assignedBy); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Roles updated successfully"})
}

// ==================== Tree/Hierarchy Endpoints ====================

// GetGroupTree handles GET /api/admin/groups/tree
func (h *GroupHandler) GetGroupTree(c *gin.Context) {
	tenantID, exists := c.Get("tenant_id")
	if !exists {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgTenantIDNotFoundGroup})
		return
	}

	tree, err := h.groupService.GetGroupTree(c.Request.Context(), tenantID.(uuid.UUID))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": msgInternalErrorGroup})
		return
	}

	c.JSON(http.StatusOK, gin.H{"groups": tree})
}

// ==================== User Group Endpoints ====================

// GetUserGroups handles GET /api/admin/users/:id/groups
func (h *GroupHandler) GetUserGroups(c *gin.Context) {
	userID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID"})
		return
	}

	// Verify target user belongs to the caller's tenant
	currentUser := middleware.GetCurrentUser(c)
	if currentUser == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	if h.userService != nil {
		targetUser, err := h.userService.GetByID(c.Request.Context(), userID)
		if err != nil || targetUser == nil {
			c.JSON(http.StatusNotFound, gin.H{"error": msgUserNotFoundGroup})
			return
		}
		if targetUser.TenantID != currentUser.TenantID {
			c.JSON(http.StatusNotFound, gin.H{"error": msgUserNotFoundGroup})
			return
		}
	}

	groups, err := h.groupService.GetUserGroups(c.Request.Context(), userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": msgInternalErrorGroup})
		return
	}

	c.JSON(http.StatusOK, gin.H{"groups": groups})
}

// GetUserEffectiveRoles handles GET /api/admin/users/:id/effective-roles
func (h *GroupHandler) GetUserEffectiveRoles(c *gin.Context) {
	userID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID"})
		return
	}

	// Verify target user belongs to the caller's tenant
	currentUser := middleware.GetCurrentUser(c)
	if currentUser == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	if h.userService != nil {
		targetUser, err := h.userService.GetByID(c.Request.Context(), userID)
		if err != nil || targetUser == nil {
			c.JSON(http.StatusNotFound, gin.H{"error": msgUserNotFoundGroup})
			return
		}
		if targetUser.TenantID != currentUser.TenantID {
			c.JSON(http.StatusNotFound, gin.H{"error": msgUserNotFoundGroup})
			return
		}
	}

	roles, err := h.groupService.GetUserEffectiveRoles(c.Request.Context(), userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": msgInternalErrorGroup})
		return
	}

	c.JSON(http.StatusOK, gin.H{"roles": roles})
}
