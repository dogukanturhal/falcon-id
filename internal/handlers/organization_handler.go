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
	msgOrgTenantIDNotFound = "Tenant ID not found in context"
	msgOrgInternalError    = "An internal error occurred"
	msgOrgInvalidOrgID     = "Invalid organization ID"
	msgOrgInvalidUserID    = "Invalid user ID"
	msgOrgUserNotFound     = "User not found"
)

// OrganizationHandler handles organization-related HTTP requests
type OrganizationHandler struct {
	orgService  *services.OrganizationService
	userService *services.UserService
}

// NewOrganizationHandler creates a new OrganizationHandler
func NewOrganizationHandler(orgService *services.OrganizationService, userService *services.UserService) *OrganizationHandler {
	return &OrganizationHandler{
		orgService:  orgService,
		userService: userService,
	}
}

// validateOrgTenantAccess verifies an organization belongs to the given tenant.
func (h *OrganizationHandler) validateOrgTenantAccess(c *gin.Context, orgID uuid.UUID) bool {
	tenantID, exists := c.Get("tenant_id")
	if !exists {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgOrgTenantIDNotFound})
		return false
	}

	org, err := h.orgService.GetOrganization(c.Request.Context(), orgID)
	if err != nil || org == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Organization not found"})
		return false
	}

	tenantUID, ok := tenantID.(uuid.UUID)
	if !ok || org.TenantID != tenantUID {
		c.JSON(http.StatusNotFound, gin.H{"error": "Organization not found"})
		return false
	}

	return true
}

// ==================== Organization CRUD Endpoints ====================

// ListOrganizations handles GET /api/admin/organizations
func (h *OrganizationHandler) ListOrganizations(c *gin.Context) {
	tenantID, exists := c.Get("tenant_id")
	if !exists {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgOrgTenantIDNotFound})
		return
	}

	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "20"))
	search := c.Query("search")
	orgType := c.Query("org_type")

	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 100 {
		pageSize = 20
	}

	response, err := h.orgService.ListOrganizations(c.Request.Context(), tenantID.(uuid.UUID), page, pageSize, search, orgType)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": msgOrgInternalError})
		return
	}

	c.JSON(http.StatusOK, response)
}

// GetOrganization handles GET /api/admin/organizations/:id
func (h *OrganizationHandler) GetOrganization(c *gin.Context) {
	orgID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgOrgInvalidOrgID})
		return
	}

	// Verify the organization belongs to the current tenant
	if !h.validateOrgTenantAccess(c, orgID) {
		return
	}

	detailed := c.Query("detailed") == queryBoolTrue

	var org *models.Organization
	if detailed {
		org, err = h.orgService.GetOrganizationWithDetails(c.Request.Context(), orgID)
	} else {
		org, err = h.orgService.GetOrganization(c.Request.Context(), orgID)
	}

	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, org)
}

// CreateOrganization handles POST /api/admin/organizations
func (h *OrganizationHandler) CreateOrganization(c *gin.Context) {
	tenantID, exists := c.Get("tenant_id")
	if !exists {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgOrgTenantIDNotFound})
		return
	}

	var req models.CreateOrganizationRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var createdBy *uuid.UUID
	if userID, exists := c.Get("user_id"); exists {
		uid := userID.(uuid.UUID)
		createdBy = &uid
	}

	org, err := h.orgService.CreateOrganization(c.Request.Context(), tenantID.(uuid.UUID), &req, createdBy)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, org)
}

// UpdateOrganization handles PUT /api/admin/organizations/:id
func (h *OrganizationHandler) UpdateOrganization(c *gin.Context) {
	orgID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgOrgInvalidOrgID})
		return
	}

	// Verify the organization belongs to the current tenant
	if !h.validateOrgTenantAccess(c, orgID) {
		return
	}

	var req models.UpdateOrganizationRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	org, err := h.orgService.UpdateOrganization(c.Request.Context(), orgID, &req)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, org)
}

// DeleteOrganization handles DELETE /api/admin/organizations/:id
func (h *OrganizationHandler) DeleteOrganization(c *gin.Context) {
	orgID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgOrgInvalidOrgID})
		return
	}

	// Verify the organization belongs to the current tenant
	if !h.validateOrgTenantAccess(c, orgID) {
		return
	}

	if err := h.orgService.DeleteOrganization(c.Request.Context(), orgID); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Organization deleted successfully"})
}

// ==================== Member Management Endpoints ====================

// GetMembers handles GET /api/admin/organizations/:id/members
func (h *OrganizationHandler) GetMembers(c *gin.Context) {
	orgID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgOrgInvalidOrgID})
		return
	}

	// Verify the organization belongs to the current tenant
	if !h.validateOrgTenantAccess(c, orgID) {
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

	response, err := h.orgService.GetMembers(c.Request.Context(), orgID, page, pageSize)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": msgOrgInternalError})
		return
	}

	c.JSON(http.StatusOK, response)
}

// AddMember handles POST /api/admin/organizations/:id/members (single member)
func (h *OrganizationHandler) AddMember(c *gin.Context) {
	orgID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgOrgInvalidOrgID})
		return
	}

	// Verify the organization belongs to the current tenant
	if !h.validateOrgTenantAccess(c, orgID) {
		return
	}

	var req models.AddOrgMemberRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var addedBy *uuid.UUID
	if userID, exists := c.Get("user_id"); exists {
		uid := userID.(uuid.UUID)
		addedBy = &uid
	}

	if err := h.orgService.AddMember(c.Request.Context(), orgID, &req, addedBy); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Member added successfully"})
}

// AddMembers handles POST /api/admin/organizations/:id/members/batch (multiple members)
func (h *OrganizationHandler) AddMembers(c *gin.Context) {
	orgID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgOrgInvalidOrgID})
		return
	}

	// Verify the organization belongs to the current tenant
	if !h.validateOrgTenantAccess(c, orgID) {
		return
	}

	var req models.AddOrgMembersRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var addedBy *uuid.UUID
	if userID, exists := c.Get("user_id"); exists {
		uid := userID.(uuid.UUID)
		addedBy = &uid
	}

	if err := h.orgService.AddMembers(c.Request.Context(), orgID, &req, addedBy); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Members added successfully"})
}

// RemoveMembers handles DELETE /api/admin/organizations/:id/members
func (h *OrganizationHandler) RemoveMembers(c *gin.Context) {
	orgID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgOrgInvalidOrgID})
		return
	}

	// Verify the organization belongs to the current tenant
	if !h.validateOrgTenantAccess(c, orgID) {
		return
	}

	var req models.RemoveOrgMembersRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := h.orgService.RemoveMembers(c.Request.Context(), orgID, req.UserIDs); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Members removed successfully"})
}

// UpdateMember handles PUT /api/admin/organizations/:id/members/:user_id
func (h *OrganizationHandler) UpdateMember(c *gin.Context) {
	orgID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgOrgInvalidOrgID})
		return
	}

	// Verify the organization belongs to the current tenant
	if !h.validateOrgTenantAccess(c, orgID) {
		return
	}

	userID, err := uuid.Parse(c.Param("user_id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgOrgInvalidUserID})
		return
	}

	var req models.UpdateOrgMemberRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := h.orgService.UpdateMember(c.Request.Context(), orgID, userID, &req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Member updated successfully"})
}

// ==================== Tree/Hierarchy Endpoints ====================

// GetOrganizationTree handles GET /api/admin/organizations/tree
func (h *OrganizationHandler) GetOrganizationTree(c *gin.Context) {
	tenantID, exists := c.Get("tenant_id")
	if !exists {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgOrgTenantIDNotFound})
		return
	}

	tree, err := h.orgService.GetOrganizationTree(c.Request.Context(), tenantID.(uuid.UUID))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": msgOrgInternalError})
		return
	}

	c.JSON(http.StatusOK, gin.H{"tree": tree})
}

// GetAncestors handles GET /api/admin/organizations/:id/ancestors
func (h *OrganizationHandler) GetAncestors(c *gin.Context) {
	orgID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgOrgInvalidOrgID})
		return
	}

	// Verify the organization belongs to the current tenant
	if !h.validateOrgTenantAccess(c, orgID) {
		return
	}

	ancestors, err := h.orgService.GetAncestors(c.Request.Context(), orgID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": msgOrgInternalError})
		return
	}

	c.JSON(http.StatusOK, gin.H{"ancestors": ancestors})
}

// GetDescendants handles GET /api/admin/organizations/:id/descendants
func (h *OrganizationHandler) GetDescendants(c *gin.Context) {
	orgID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgOrgInvalidOrgID})
		return
	}

	// Verify the organization belongs to the current tenant
	if !h.validateOrgTenantAccess(c, orgID) {
		return
	}

	descendants, err := h.orgService.GetDescendants(c.Request.Context(), orgID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": msgOrgInternalError})
		return
	}

	c.JSON(http.StatusOK, gin.H{"descendants": descendants})
}

// ==================== User Organization Endpoints ====================

// GetMyOrganizations handles GET /api/v1/auth/me/organizations — the
// self-service variant of GetUserOrganizations. Returns the OrgMember
// list for the authenticated user, with each member's Organization
// populated for direct rendering on the accounts portal.
//
// Industry alignment (Clerk / WorkOS / Auth0 Organizations): users hold
// memberships in zero-or-more organizations within a tenant. This
// endpoint surfaces those memberships at the /me prefix so the BFF
// doesn't need an admin-tier credential to list "orgs you belong to".
// Admin-scoped /api/admin/users/:id/organizations remains for operator
// flows (managing OTHER users).
//
//	@Summary List My Organizations
//	@Description Returns the authenticated user's organization memberships.
//	@Tags Auth
//	@Produce json
//	@Security BearerAuth
//	@Success 200 {object} map[string]interface{}
//	@Failure 401 {object} map[string]string
//	@Failure 500 {object} map[string]string
//	@Router /api/v1/auth/me/organizations [get]
func (h *OrganizationHandler) GetMyOrganizations(c *gin.Context) {
	user := middleware.GetCurrentUser(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Not authenticated"})
		return
	}

	orgs, err := h.orgService.GetUserOrganizations(c.Request.Context(), user.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": msgOrgInternalError})
		return
	}

	// Always return a non-nil array so the JSON shape is stable for the
	// BFF — `{organizations: []}` for the no-memberships case instead of
	// `{organizations: null}`, which the frontend would have to defend
	// against on every render.
	if orgs == nil {
		orgs = []*models.OrgMember{}
	}

	c.JSON(http.StatusOK, gin.H{"organizations": orgs})
}

// GetUserOrganizations handles GET /api/admin/users/:id/organizations
func (h *OrganizationHandler) GetUserOrganizations(c *gin.Context) {
	tenantID, exists := c.Get("tenant_id")
	if !exists {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgOrgTenantIDNotFound})
		return
	}

	userID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgOrgInvalidUserID})
		return
	}

	// Verify the target user belongs to the current tenant
	if h.userService != nil {
		targetUser, err := h.userService.GetByID(c.Request.Context(), userID)
		if err != nil || targetUser == nil {
			c.JSON(http.StatusNotFound, gin.H{"error": msgOrgUserNotFound})
			return
		}
		if tenantUID, ok := tenantID.(uuid.UUID); !ok || targetUser.TenantID != tenantUID {
			c.JSON(http.StatusNotFound, gin.H{"error": msgOrgUserNotFound})
			return
		}
	}

	orgs, err := h.orgService.GetUserOrganizations(c.Request.Context(), userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": msgOrgInternalError})
		return
	}

	c.JSON(http.StatusOK, gin.H{"organizations": orgs})
}

// GetUserPrimaryOrganization handles GET /api/admin/users/:id/primary-organization
func (h *OrganizationHandler) GetUserPrimaryOrganization(c *gin.Context) {
	tenantID, exists := c.Get("tenant_id")
	if !exists {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgOrgTenantIDNotFound})
		return
	}

	userID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgOrgInvalidUserID})
		return
	}

	// Verify the target user belongs to the current tenant
	if h.userService != nil {
		targetUser, err := h.userService.GetByID(c.Request.Context(), userID)
		if err != nil || targetUser == nil {
			c.JSON(http.StatusNotFound, gin.H{"error": msgOrgUserNotFound})
			return
		}
		if tenantUID, ok := tenantID.(uuid.UUID); !ok || targetUser.TenantID != tenantUID {
			c.JSON(http.StatusNotFound, gin.H{"error": msgOrgUserNotFound})
			return
		}
	}

	org, err := h.orgService.GetUserPrimaryOrganization(c.Request.Context(), userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": msgOrgInternalError})
		return
	}

	if org == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "No primary organization found"})
		return
	}

	c.JSON(http.StatusOK, org)
}

// ==================== IAM Role Assignment Endpoints ====================

// GetAssignedRoles handles GET /api/admin/organizations/:id/iam-roles
func (h *OrganizationHandler) GetAssignedRoles(c *gin.Context) {
	orgID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgOrgInvalidOrgID})
		return
	}

	if !h.validateOrgTenantAccess(c, orgID) {
		return
	}

	roles, err := h.orgService.GetAssignedRoles(c.Request.Context(), orgID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get organization roles"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"roles": roles, "total": len(roles)})
}

// AssignRoles handles POST /api/admin/organizations/:id/iam-roles
func (h *OrganizationHandler) AssignRoles(c *gin.Context) {
	orgID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgOrgInvalidOrgID})
		return
	}

	if !h.validateOrgTenantAccess(c, orgID) {
		return
	}

	var req models.AssignOrgRolesRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var assignedBy *uuid.UUID
	if currentUser := middleware.GetCurrentUser(c); currentUser != nil {
		assignedBy = &currentUser.ID
	}

	if err := h.orgService.AssignRoles(c.Request.Context(), orgID, &req, assignedBy); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to assign roles"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Roles assigned successfully"})
}

// UnassignRoles handles DELETE /api/admin/organizations/:id/iam-roles
func (h *OrganizationHandler) UnassignRoles(c *gin.Context) {
	orgID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgOrgInvalidOrgID})
		return
	}

	if !h.validateOrgTenantAccess(c, orgID) {
		return
	}

	var req models.UnassignOrgRolesRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := h.orgService.UnassignRoles(c.Request.Context(), orgID, req.RoleIDs); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to remove roles"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Roles removed successfully"})
}

// ==================== Metadata Endpoints ====================

// GetOrgTypes handles GET /api/admin/organizations/types
func (h *OrganizationHandler) GetOrgTypes(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"types": h.orgService.GetOrgTypes()})
}

// GetOrgRoles handles GET /api/admin/organizations/roles
func (h *OrganizationHandler) GetOrgRoles(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"roles": h.orgService.GetOrgRoles()})
}
