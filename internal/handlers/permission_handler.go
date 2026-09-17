// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/dogukanturhal/falcon-id/internal/middleware"
	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/internal/services"
)

const (
	msgPermInternalError       = "An internal error occurred"
	msgPermNotFound            = "not found"
	msgPermissionNotFound      = "Permission not found"
	msgPermMutationsNotAllowed = "Permission mutations not allowed during impersonation"
)

// PermissionHandler handles permission-related HTTP requests
type PermissionHandler struct {
	permissionService *services.PermissionService
}

// NewPermissionHandler creates a new permission handler
func NewPermissionHandler(permissionService *services.PermissionService) *PermissionHandler {
	return &PermissionHandler{permissionService: permissionService}
}

// buildAuditLog creates a PlatformAuditLog from the gin context.
func (h *PermissionHandler) buildAuditLog(c *gin.Context) *models.PlatformAuditLog {
	user := middleware.GetCurrentUser(c)
	if user == nil {
		return &models.PlatformAuditLog{}
	}
	return &models.PlatformAuditLog{
		AdminUserID:   user.ID,
		AdminUsername: user.Username,
		IPAddress:     GetClientIP(c),
		UserAgent:     c.Request.UserAgent(),
		RequestID:     middleware.GetRequestID(c),
	}
}

// RegisterModule registers all permissions for a module
// @Summary Register Module Permissions
// @Description Register permissions for a module (used by services on startup)
// @Tags Permissions
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param body body models.RegisterModuleRequest true "Module permissions"
// @Success 200 {object} models.RegisterModuleResponse
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Router /api/permissions/register [post]
func (h *PermissionHandler) RegisterModule(c *gin.Context) {
	var req models.RegisterModuleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	result, err := h.permissionService.RegisterModule(c.Request.Context(), &req)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, result)
}

// List returns all permissions
// @Summary List Permissions
// @Description Get all registered permissions
// @Tags Permissions
// @Produce json
// @Security BearerAuth
// @Success 200 {object} models.PermissionListResponse
// @Failure 401 {object} map[string]string
// @Router /api/permissions [get]
func (h *PermissionHandler) List(c *gin.Context) {
	// Platform admins see all permissions (no subscription filtering).
	user := middleware.GetCurrentUser(c)
	if user != nil && user.IsPlatformAdmin {
		result, err := h.permissionService.List(c.Request.Context())
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": msgPermInternalError})
			return
		}
		c.JSON(http.StatusOK, result)
		return
	}

	// Tenant-aware filtering: only return permissions for subscribed modules.
	tenantID := middleware.GetTenantID(c)
	if tenantID != uuid.Nil {
		result, err := h.permissionService.ListForTenant(c.Request.Context(), tenantID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": msgPermInternalError})
			return
		}
		c.JSON(http.StatusOK, result)
		return
	}

	// Fallback: no tenant context — return all permissions.
	result, err := h.permissionService.List(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": msgPermInternalError})
		return
	}

	c.JSON(http.StatusOK, result)
}

// ListByModule returns permissions for a specific module
// @Summary List Permissions by Module
// @Description Get permissions for a specific module
// @Tags Permissions
// @Produce json
// @Security BearerAuth
// @Param module path string true "Module name"
// @Success 200 {object} models.PermissionListResponse
// @Failure 401 {object} map[string]string
// @Router /api/permissions/module/{module} [get]
func (h *PermissionHandler) ListByModule(c *gin.Context) {
	module := c.Param("module")
	if module == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "module is required"})
		return
	}

	result, err := h.permissionService.ListByModule(c.Request.Context(), module)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": msgPermInternalError})
		return
	}

	c.JSON(http.StatusOK, result)
}

// ListModules returns all registered modules
// @Summary List Modules
// @Description Get all registered module names
// @Tags Permissions
// @Produce json
// @Security BearerAuth
// @Success 200 {object} []string
// @Failure 401 {object} map[string]string
// @Router /api/permissions/modules [get]
func (h *PermissionHandler) ListModules(c *gin.Context) {
	var result []string
	var err error

	user := middleware.GetCurrentUser(c)
	tenantID := middleware.GetTenantID(c)

	switch {
	case user != nil && user.IsPlatformAdmin:
		result, err = h.permissionService.ListModules(c.Request.Context())
	case tenantID != uuid.Nil:
		result, err = h.permissionService.ListModulesForTenant(c.Request.Context(), tenantID)
	default:
		result, err = h.permissionService.ListModules(c.Request.Context())
	}

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": msgPermInternalError})
		return
	}

	c.JSON(http.StatusOK, gin.H{"modules": result})
}

// ListGroupedByModule returns permissions grouped by module
// @Summary List Permissions Grouped by Module
// @Description Get all permissions grouped by their module
// @Tags Permissions
// @Produce json
// @Security BearerAuth
// @Success 200 {array} models.PermissionsByModule
// @Failure 401 {object} map[string]string
// @Router /api/permissions/grouped [get]
func (h *PermissionHandler) ListGroupedByModule(c *gin.Context) {
	var result []models.PermissionsByModule
	var err error

	user := middleware.GetCurrentUser(c)
	tenantID := middleware.GetTenantID(c)

	switch {
	case user != nil && user.IsPlatformAdmin:
		result, err = h.permissionService.ListGroupedByModule(c.Request.Context())
	case tenantID != uuid.Nil:
		result, err = h.permissionService.ListGroupedByModuleForTenant(c.Request.Context(), tenantID)
	default:
		result, err = h.permissionService.ListGroupedByModule(c.Request.Context())
	}

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": msgPermInternalError})
		return
	}

	c.JSON(http.StatusOK, result)
}

// GetByID gets a permission by ID
// @Summary Get Permission
// @Description Get permission by ID
// @Tags Permissions
// @Produce json
// @Security BearerAuth
// @Param id path string true "Permission ID"
// @Success 200 {object} models.PermissionResponse
// @Failure 400 {object} map[string]string
// @Failure 404 {object} map[string]string
// @Router /api/permissions/{id} [get]
func (h *PermissionHandler) GetByID(c *gin.Context) {
	id, ok := ParseUUIDParam(c, "id")
	if !ok {
		return
	}

	result, err := h.permissionService.GetByID(c.Request.Context(), id)
	if err != nil {
		if strings.Contains(err.Error(), msgPermNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": msgPermissionNotFound})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": msgPermInternalError})
		return
	}

	c.JSON(http.StatusOK, result)
}

// Create creates a new permission
// @Summary Create Permission
// @Description Create a new permission (platform admin only)
// @Tags Permissions
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param body body models.CreatePermissionRequest true "Permission data"
// @Success 201 {object} models.PermissionResponse
// @Failure 400 {object} map[string]string
// @Failure 403 {object} map[string]string
// @Failure 409 {object} map[string]string
// @Router /api/permissions [post]
func (h *PermissionHandler) Create(c *gin.Context) {
	// Impersonation guard
	if _, impersonating := c.Get(middleware.ImpersonatorIDKey); impersonating {
		c.JSON(http.StatusForbidden, gin.H{"error": msgPermMutationsNotAllowed})
		return
	}

	var req models.CreatePermissionRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	auditLog := h.buildAuditLog(c)

	result, err := h.permissionService.Create(c.Request.Context(), &req, auditLog)
	if err != nil {
		errMsg := err.Error()
		if strings.Contains(errMsg, "already exists") {
			c.JSON(http.StatusConflict, gin.H{"error": errMsg})
			return
		}
		if strings.Contains(errMsg, "invalid") || strings.Contains(errMsg, "must be") || strings.Contains(errMsg, "cannot contain") || strings.Contains(errMsg, "required") {
			c.JSON(http.StatusBadRequest, gin.H{"error": errMsg})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": msgPermInternalError})
		return
	}

	c.JSON(http.StatusCreated, result)
}

// Update updates a permission
// @Summary Update Permission
// @Description Update a permission's display name and/or description (platform admin only)
// @Tags Permissions
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param id path string true "Permission ID"
// @Param body body models.UpdatePermissionRequest true "Permission data"
// @Success 200 {object} models.PermissionResponse
// @Failure 400 {object} map[string]string
// @Failure 403 {object} map[string]string
// @Failure 404 {object} map[string]string
// @Router /api/permissions/{id} [put]
func (h *PermissionHandler) Update(c *gin.Context) {
	// Impersonation guard
	if _, impersonating := c.Get(middleware.ImpersonatorIDKey); impersonating {
		c.JSON(http.StatusForbidden, gin.H{"error": msgPermMutationsNotAllowed})
		return
	}

	id, ok := ParseUUIDParam(c, "id")
	if !ok {
		return
	}

	var req models.UpdatePermissionRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	auditLog := h.buildAuditLog(c)

	result, err := h.permissionService.Update(c.Request.Context(), id, &req, auditLog)
	if err != nil {
		errMsg := err.Error()
		if strings.Contains(errMsg, msgPermNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": msgPermissionNotFound})
			return
		}
		if strings.Contains(errMsg, "must be") || strings.Contains(errMsg, "cannot be empty") {
			c.JSON(http.StatusBadRequest, gin.H{"error": errMsg})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": msgPermInternalError})
		return
	}

	c.JSON(http.StatusOK, result)
}

// Delete deletes a permission
// @Summary Delete Permission
// @Description Delete a permission if not system and not in use (platform admin only)
// @Tags Permissions
// @Produce json
// @Security BearerAuth
// @Param id path string true "Permission ID"
// @Success 200 {object} map[string]string
// @Failure 400 {object} map[string]string
// @Failure 403 {object} map[string]string
// @Failure 404 {object} map[string]string
// @Router /api/permissions/{id} [delete]
func (h *PermissionHandler) Delete(c *gin.Context) {
	// Impersonation guard
	if _, impersonating := c.Get(middleware.ImpersonatorIDKey); impersonating {
		c.JSON(http.StatusForbidden, gin.H{"error": msgPermMutationsNotAllowed})
		return
	}

	id, ok := ParseUUIDParam(c, "id")
	if !ok {
		return
	}

	auditLog := h.buildAuditLog(c)

	err := h.permissionService.Delete(c.Request.Context(), id, auditLog)
	if err != nil {
		errMsg := err.Error()
		if strings.Contains(errMsg, msgPermNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": msgPermissionNotFound})
			return
		}
		if strings.Contains(errMsg, "system permissions") {
			c.JSON(http.StatusForbidden, gin.H{"error": errMsg})
			return
		}
		if strings.Contains(errMsg, "assigned to") {
			c.JSON(http.StatusBadRequest, gin.H{"error": errMsg})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": msgPermInternalError})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Permission deleted successfully"})
}
