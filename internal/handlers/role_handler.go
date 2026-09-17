// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	goredis "github.com/redis/go-redis/v9"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/middleware"
	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/internal/services"
	"github.com/dogukanturhal/falcon-id/pkg/logger"
)

const (
	msgRoleInvalidRoleID = "Invalid role ID"
	msgRoleNotFound      = "Role not found"
	msgRoleInternalError = "An internal error occurred"
)

// RoleHandler is an exported type.
type RoleHandler struct {
	roleService *services.RoleService
	redis       *goredis.Client
}

// NewRoleHandler is an exported function.
func NewRoleHandler(roleService *services.RoleService) *RoleHandler {
	return &RoleHandler{roleService: roleService}
}

// SetRedisClient injects the Redis client for permission change notifications.
func (h *RoleHandler) SetRedisClient(client *goredis.Client) {
	h.redis = client
}

// notifyRoleMembers publishes permission_changed events to all users holding the given role.
func (h *RoleHandler) notifyRoleMembers(ctx context.Context, roleID uuid.UUID, tenantID uuid.UUID) {
	if h.redis == nil {
		return
	}
	members, err := h.roleService.GetRoleMembers(ctx, tenantID, roleID.String(), 1, 1000)
	if err != nil {
		logger.Log.Warn("Failed to fetch role members for notification", zap.Error(err))
		return
	}
	now := time.Now().UTC().Format(time.RFC3339)
	for _, member := range members.Data {
		channel := fmt.Sprintf("hexxlock:permissions:%s", member.UserID.String())
		msg := fmt.Sprintf(`{"type":"permission_changed","user_id":"%s","source":"role_permission_change","timestamp":"%s"}`,
			member.UserID.String(), now)
		if err := h.redis.Publish(ctx, channel, msg).Err(); err != nil {
			logger.Log.Warn("Failed to publish permission change to user",
				zap.String("user_id", member.UserID.String()), zap.Error(err))
		}
	}
}

// rejectIfImpersonated blocks mutation operations during impersonation sessions.
// An impersonator should only observe — never modify — the target user's context.
func rejectIfImpersonated(c *gin.Context) bool {
	if _, exists := c.Get("impersonator_id"); exists {
		c.JSON(http.StatusForbidden, gin.H{"error": "role mutations are not allowed during impersonation"})
		return true
	}
	return false
}

// Create creates a new role
// @Summary Create Role
// @Description Create a new role
// @Tags Roles
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param body body models.CreateRoleRequest true "Role data"
// @Success 201 {object} models.RoleResponse
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Failure 403 {object} map[string]string
// @Router /api/roles [post]
func (h *RoleHandler) Create(c *gin.Context) {
	if rejectIfImpersonated(c) {
		return
	}

	var req models.CreateRoleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// SECURITY: Always use tenant from authenticated context, never trust client-supplied TenantID
	req.TenantID = middleware.GetTenantID(c)

	currentUserID := middleware.GetCurrentUserID(c)

	role, err := h.roleService.Create(c.Request.Context(), &req, currentUserID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, role)
}

// GetByID gets a role by ID
// @Summary Get Role
// @Description Get role by ID
// @Tags Roles
// @Produce json
// @Security BearerAuth
// @Param id path string true "Role ID"
// @Success 200 {object} models.RoleResponse
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Failure 404 {object} map[string]string
// @Router /api/roles/{id} [get]
func (h *RoleHandler) GetByID(c *gin.Context) {
	idStr := c.Param("id")
	id, err := parseUUID(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgRoleInvalidRoleID})
		return
	}

	role, err := h.roleService.GetByID(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": msgRoleNotFound})
		return
	}

	// Verify the role belongs to the caller's tenant
	tenantID := middleware.GetTenantID(c)
	if role.TenantID != tenantID {
		c.JSON(http.StatusNotFound, gin.H{"error": msgRoleNotFound})
		return
	}

	c.JSON(http.StatusOK, role)
}

// Update updates a role
// @Summary Update Role
// @Description Update role by ID
// @Tags Roles
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param id path string true "Role ID"
// @Param body body models.UpdateRoleRequest true "Role data"
// @Success 200 {object} models.RoleResponse
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Failure 404 {object} map[string]string
// @Router /api/roles/{id} [put]
func (h *RoleHandler) Update(c *gin.Context) {
	if rejectIfImpersonated(c) {
		return
	}

	idStr := c.Param("id")
	id, err := parseUUID(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgRoleInvalidRoleID})
		return
	}

	// Verify the role belongs to the caller's tenant before updating
	existingRole, err := h.roleService.GetByID(c.Request.Context(), id)
	if err != nil || existingRole == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": msgRoleNotFound})
		return
	}
	tenantID := middleware.GetTenantID(c)
	if existingRole.TenantID != tenantID {
		c.JSON(http.StatusNotFound, gin.H{"error": msgRoleNotFound})
		return
	}

	var req models.UpdateRoleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	currentUserID := middleware.GetCurrentUserID(c)

	role, err := h.roleService.Update(c.Request.Context(), id, &req, currentUserID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, role)
}

// Delete deletes a role
// @Summary Delete Role
// @Description Delete role by ID
// @Tags Roles
// @Produce json
// @Security BearerAuth
// @Param id path string true "Role ID"
// @Success 200 {object} map[string]string
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Failure 404 {object} map[string]string
// @Router /api/roles/{id} [delete]
func (h *RoleHandler) Delete(c *gin.Context) {
	if rejectIfImpersonated(c) {
		return
	}

	idStr := c.Param("id")
	id, err := parseUUID(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgRoleInvalidRoleID})
		return
	}

	// Verify the role belongs to the caller's tenant before deleting
	existingRole, err := h.roleService.GetByID(c.Request.Context(), id)
	if err != nil || existingRole == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": msgRoleNotFound})
		return
	}
	tenantID := middleware.GetTenantID(c)
	if existingRole.TenantID != tenantID {
		c.JSON(http.StatusNotFound, gin.H{"error": msgRoleNotFound})
		return
	}

	currentUserID := middleware.GetCurrentUserID(c)

	err = h.roleService.Delete(c.Request.Context(), id, currentUserID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Role deleted successfully"})
}

// List lists roles
// @Summary List Roles
// @Description List the authenticated tenant's manageable role catalogue. Only non-system roles below the actor's effective priority are returned; the tenant is taken exclusively from the signed user context.
// @Tags Roles
// @Produce json
// @Security BearerAuth
// @Param page query int false "Page number" default(1)
// @Param page_size query int false "Page size" default(20)
// @Param search query string false "Search query"
// @Success 200 {object} models.RoleListResponse
// @Failure 401 {object} map[string]string
// @Router /api/v1/roles [get]
func (h *RoleHandler) List(c *gin.Context) {
	tenantID := middleware.GetTenantID(c)
	currentUser := middleware.GetCurrentUser(c)
	if currentUser == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	// This endpoint has shipped behind core:roles:read. Keep that concrete
	// contract instead of requiring a newly self-registered IAM permission.
	if !currentUser.HasPermission("core:roles:read") {
		c.JSON(http.StatusForbidden, gin.H{"error": "forbidden"})
		return
	}

	// SECURITY: Use GetPagination to enforce max page size of 100
	page, pageSize, _ := GetPagination(c)
	search := c.Query("search")

	// Tenant self-service picker (invite/edit-roles) — scope to the tenant's
	// entitled product modules so roles from products this tenant never
	// subscribed to (e.g. a different customer's product roles that were
	// provisioned under the wrong tenant) don't appear. See RoleService.
	// ListManageableSelfService. Platform-admin views that need every role a tenant
	// owns regardless of entitlement use RoleService.List/ListByTenant.
	response, err := h.roleService.ListManageableSelfService(c.Request.Context(), tenantID, currentUser.ID, page, pageSize, search)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": msgRoleInternalError})
		return
	}

	c.JSON(http.StatusOK, response)
}

// GetPermissions gets permissions for a role
// @Summary Get Role Permissions
// @Description Get permissions assigned to a role
// @Tags Roles
// @Produce json
// @Security BearerAuth
// @Param id path string true "Role ID"
// @Success 200 {object} []models.PermissionResponse
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Router /api/roles/{id}/permissions [get]
func (h *RoleHandler) GetPermissions(c *gin.Context) {
	idStr := c.Param("id")
	id, err := parseUUID(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgRoleInvalidRoleID})
		return
	}

	// Verify the role belongs to the caller's tenant
	role, err := h.roleService.GetByID(c.Request.Context(), id)
	if err != nil || role == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": msgRoleNotFound})
		return
	}
	tenantID := middleware.GetTenantID(c)
	if role.TenantID != tenantID {
		c.JSON(http.StatusNotFound, gin.H{"error": msgRoleNotFound})
		return
	}

	permissions, err := h.roleService.GetPermissions(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": msgRoleInternalError})
		return
	}

	c.JSON(http.StatusOK, gin.H{"permissions": permissions})
}

// AssignPermissions assigns permissions to a role
// @Summary Assign Permissions to Role
// @Description Assign permissions to a role
// @Tags Roles
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param id path string true "Role ID"
// @Param body body models.AssignPermissionsRequest true "Permission IDs"
// @Success 200 {object} map[string]string
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Router /api/roles/{id}/permissions [put]
func (h *RoleHandler) AssignPermissions(c *gin.Context) {
	if rejectIfImpersonated(c) {
		return
	}

	idStr := c.Param("id")
	id, err := parseUUID(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgRoleInvalidRoleID})
		return
	}

	// Verify the role belongs to the caller's tenant before modifying permissions
	role, err := h.roleService.GetByID(c.Request.Context(), id)
	if err != nil || role == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": msgRoleNotFound})
		return
	}
	tenantID := middleware.GetTenantID(c)
	if role.TenantID != tenantID {
		c.JSON(http.StatusNotFound, gin.H{"error": msgRoleNotFound})
		return
	}

	var req struct {
		PermissionIDs []uuid.UUID `json:"permission_ids"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	currentUserID := middleware.GetCurrentUserID(c)

	err = h.roleService.AssignPermissions(c.Request.Context(), id, req.PermissionIDs, currentUserID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Security audit: role permissions changed
	permIDStrs := make([]string, len(req.PermissionIDs))
	for i, pid := range req.PermissionIDs {
		permIDStrs[i] = pid.String()
	}
	actorID := ""
	if currentUserID != nil {
		actorID = currentUserID.String()
	}
	logger.SecurityAudit.Info("Security audit: role permissions changed",
		zap.String("event", "auth.permission.role_permissions_changed"),
		zap.String("actor_id", actorID),
		zap.String("role_id", id.String()),
		zap.Strings("new_permission_ids", permIDStrs),
		zap.String("ip", GetClientIP(c)),
		zap.Time("timestamp", time.Now().UTC()),
	)

	// Notify all users holding this role that their permissions changed
	go h.notifyRoleMembers(context.Background(), id, tenantID)

	c.JSON(http.StatusOK, gin.H{"message": "Permissions assigned successfully"})
}

// GetRoleMembers returns the users who hold a specific role.
// @Summary Get Role Members
// @Description Returns a paginated list of users who have been assigned the given role.
// @Tags Roles
// @Produce json
// @Security BearerAuth
// @Param id path string true "Role UUID or role name (e.g. crm:manager)"
// @Param page query int false "Page number" default(1)
// @Param page_size query int false "Page size (max 100)" default(100)
// @Success 200 {object} models.RoleMembersResponse
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Router /api/v1/admin/roles/{id}/members [get]
func (h *RoleHandler) GetRoleMembers(c *gin.Context) {
	roleIdentifier := c.Param("id")
	if roleIdentifier == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "role id or name is required"})
		return
	}

	tenantID := middleware.GetTenantID(c)
	page, pageSize, _ := GetPagination(c)

	// Override default page_size to 100 when not explicitly supplied.
	if c.Query("page_size") == "" {
		pageSize = 100
	}

	response, err := h.roleService.GetRoleMembers(c.Request.Context(), tenantID, roleIdentifier, page, pageSize)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": msgRoleInternalError})
		return
	}

	c.JSON(http.StatusOK, response)
}

// ListRoleMembers is an exported identifier.
// ListPermissions is an exported identifier.
// ListPermissions is an exported identifier.
// ListPermissions lists all available permissions
// @Summary List All Permissions
// @Description List all available permissions
// @Tags Permissions
// @Produce json
// @Security BearerAuth
// ListRoleMembers returns users assigned to a specific role.
func (h *RoleHandler) ListRoleMembers(c *gin.Context) {
	tenantID := middleware.GetTenantID(c)
	roleID := c.Param("id")
	if _, err := uuid.Parse(roleID); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgRoleInvalidRoleID})
		return
	}

	page, pageSize, _ := GetPagination(c)
	resp, err := h.roleService.GetRoleMembers(c.Request.Context(), tenantID, roleID, page, pageSize)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get role members"})
		return
	}

	c.JSON(http.StatusOK, resp)
}

// RoleHandler.ListPermissions (was GET /api/permissions) and
// RoleHandler.ListPermissionsByModule (was GET /api/permissions/by-module)
// were removed 2026-05-21. Both were stale aliases of PermissionHandler.
// List + ListGroupedByModule which are canonically wired in
// registerPermissionRoutes — the @Router annotations on these duplicated
// the same paths, surfacing repeatedly as false-positive unregistered
// handlers in docs/audits/2026-05-21-unregistered-handlers.md.
