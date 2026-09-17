// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/middleware"
	"github.com/dogukanturhal/falcon-id/internal/models"
)

// ============================================================
// CROSS-TENANT ROLE MANAGEMENT
// ============================================================

// ListTenantRoles lists roles in a specific tenant
func (h *PlatformManagementHandler) ListTenantRoles(c *gin.Context) {
	currentUser := middleware.GetCurrentUser(c)
	if currentUser == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": msgPlatMgmtNotAuthenticated})
		return
	}

	tenantID, err := uuid.Parse(c.Param("tenant_id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgPlatMgmtInvalidTenantID})
		return
	}

	roles, err := h.roleService.ListByTenant(c.Request.Context(), tenantID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": msgPlatMgmtInternalError})
		return
	}

	c.JSON(http.StatusOK, gin.H{"roles": roles})
}

// CreateTenantRole creates a role in a specific tenant
func (h *PlatformManagementHandler) CreateTenantRole(c *gin.Context) {
	currentUser := middleware.GetCurrentUser(c)
	if currentUser == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": msgPlatMgmtNotAuthenticated})
		return
	}

	tenantID, err := uuid.Parse(c.Param("tenant_id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgPlatMgmtInvalidTenantID})
		return
	}

	var req models.CreateRoleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	req.TenantID = tenantID

	role, err := h.roleService.Create(c.Request.Context(), &req, &currentUser.ID)
	if err != nil {
		h.logger.Error("Failed to create tenant role", zap.String("tenant_id", tenantID.String()), zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to create role"})
		return
	}

	h.logPlatformAction(c, currentUser, "role_created", "role", &role.ID, map[string]interface{}{
		"name":      req.Name,
		"tenant_id": tenantID.String(),
	})

	c.JSON(http.StatusCreated, role)
}

// SetUserRoles sets roles for a user in a tenant
func (h *PlatformManagementHandler) SetUserRoles(c *gin.Context) {
	currentUser := middleware.GetCurrentUser(c)
	if currentUser == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": msgPlatMgmtNotAuthenticated})
		return
	}

	tenantID, err := uuid.Parse(c.Param("tenant_id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgPlatMgmtInvalidTenantID})
		return
	}

	userID, err := uuid.Parse(c.Param("user_id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID"})
		return
	}

	// SECURITY: Verify user belongs to the specified tenant before setting roles
	if !h.verifyUserInTenant(c, userID, tenantID) {
		return
	}

	var req models.SetUserRolesRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := h.userService.SetUserRoles(c.Request.Context(), userID, req.RoleIDs, &currentUser.ID); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgPlatMgmtInternalError})
		return
	}

	h.logPlatformAction(c, currentUser, "roles_assigned", "user", &userID, map[string]interface{}{
		"tenant_id": tenantID.String(),
		"role_ids":  req.RoleIDs,
	})

	c.JSON(http.StatusOK, gin.H{"message": "User roles updated successfully"})
}

// ============================================================
// PLATFORM PERMISSIONS
// ============================================================

// ListPlatformPermissions lists all platform permissions
func (h *PlatformManagementHandler) ListPlatformPermissions(c *gin.Context) {
	currentUser := middleware.GetCurrentUser(c)
	if currentUser == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": msgPlatMgmtNotAuthenticated})
		return
	}

	module := c.Query("module")

	permissions, err := h.permissionService.ListByModule(c.Request.Context(), module)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": msgPlatMgmtInternalError})
		return
	}

	c.JSON(http.StatusOK, gin.H{"permissions": permissions})
}

// ============================================================
// PLATFORM AUDIT LOG
// ============================================================

// GetPlatformAuditLog retrieves platform admin audit logs
func (h *PlatformManagementHandler) GetPlatformAuditLog(c *gin.Context) {
	currentUser := middleware.GetCurrentUser(c)
	if currentUser == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": msgPlatMgmtNotAuthenticated})
		return
	}

	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "50"))
	action := c.Query("action")
	targetTenantID := c.Query("tenant_id")
	fromStr := c.Query("from")
	toStr := c.Query("to")

	var from, to *time.Time
	if fromStr != "" {
		t, err := time.Parse(time.RFC3339, fromStr)
		if err == nil {
			from = &t
		}
	}
	if toStr != "" {
		t, err := time.Parse(time.RFC3339, toStr)
		if err == nil {
			to = &t
		}
	}

	var targetTenant *uuid.UUID
	if targetTenantID != "" {
		id, err := uuid.Parse(targetTenantID)
		if err == nil {
			targetTenant = &id
		}
	}

	filters := models.PlatformAuditFilters{
		Action:         action,
		TargetTenantID: targetTenant,
		From:           from,
		To:             to,
	}

	logs, total, err := h.auditService.GetPlatformAuditLog(c.Request.Context(), page, pageSize, filters)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": msgPlatMgmtInternalError})
		return
	}

	totalPages := int64(0)
	if total > 0 {
		totalPages = (total + int64(pageSize) - 1) / int64(pageSize)
	}

	// Return in PaginatedResponse format to match the SDK expectation
	c.JSON(http.StatusOK, gin.H{
		"data":        logs,
		"total":       total,
		"page":        page,
		"page_size":   pageSize,
		"total_pages": totalPages,
	})
}

// ============================================================
// STATISTICS
// ============================================================

// GetPlatformStatistics gets platform-wide statistics
func (h *PlatformManagementHandler) GetPlatformStatistics(c *gin.Context) {
	currentUser := middleware.GetCurrentUser(c)
	if currentUser == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": msgPlatMgmtNotAuthenticated})
		return
	}

	stats, err := h.tenantService.GetPlatformStatistics(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": msgPlatMgmtInternalError})
		return
	}

	c.JSON(http.StatusOK, stats)
}

// ============================================================
// HELPER METHODS
// ============================================================

func (h *PlatformManagementHandler) logPlatformAction(
	c *gin.Context,
	user *models.CurrentUser,
	action string,
	resourceType string,
	resourceID *uuid.UUID,
	details map[string]interface{},
) {
	log := &models.PlatformAuditLog{
		AdminUserID:        user.ID,
		AdminUsername:      user.Email,
		Action:             action,
		TargetResourceType: resourceType,
		IPAddress:          GetClientIP(c),
		UserAgent:          c.GetHeader("User-Agent"),
		Success:            true,
	}

	if resourceID != nil {
		log.TargetResourceID = resourceID
	}

	if details != nil {
		if tenantIDStr, ok := details["tenant_id"].(string); ok {
			tenantID, err := uuid.Parse(tenantIDStr)
			if err == nil {
				log.TargetTenantID = &tenantID
			}
		}
		log.Details = details
	}

	if err := h.auditService.LogPlatformAction(c.Request.Context(), log); err != nil {
		h.logger.Error("Failed to log platform action",
			zap.String("action", action),
			zap.Error(err),
		)
	}
}
