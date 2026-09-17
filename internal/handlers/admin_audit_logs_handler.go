// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/middleware"
)

// ListAuditLogs lists audit logs with pagination and filtering
// @Summary List Audit Logs
// @Description List audit logs for the tenant (admin only)
// @Tags Admin
// @Produce json
// @Security BearerAuth
// @Param page query int false "Page number" default(1)
// @Param page_size query int false "Page size" default(20)
// @Param user_id query string false "Filter by user ID"
// @Param action query string false "Filter by action"
// @Param success query string false "Filter by success (true/false)"
// @Success 200 {object} models.AuditLogListResponse
// @Failure 401 {object} map[string]string
// @Failure 403 {object} map[string]string
// @Router /api/admin/audit-logs [get]
func (h *AdminHandler) ListAuditLogs(c *gin.Context) {
	currentUser := middleware.GetCurrentUser(c)
	if currentUser == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Not authenticated"})
		return
	}

	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "20"))

	filters := make(map[string]interface{})
	if userID := c.Query("user_id"); userID != "" {
		if uid, err := uuid.Parse(userID); err == nil {
			filters["user_id"] = uid
		}
	}
	if action := c.Query("action"); action != "" {
		filters["action"] = action
	}
	if success := c.Query("success"); success != "" {
		filters["success"] = success == queryBoolTrue
	}

	response, err := h.auditService.GetAuditLogs(c.Request.Context(), currentUser.TenantID, page, pageSize, filters)
	if err != nil {
		h.logger.Error("Failed to get audit logs", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve audit logs"})
		return
	}

	c.JSON(http.StatusOK, response)
}

// GetAuditLog retrieves a specific audit log by ID
// @Summary Get Audit Log
// @Description Get a specific audit log entry (admin only)
// @Tags Admin
// @Produce json
// @Security BearerAuth
// @Param id path string true "Audit Log ID"
// @Success 200 {object} models.AuditLogResponse
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Failure 403 {object} map[string]string
// @Failure 404 {object} map[string]string
// @Router /api/admin/audit-logs/{id} [get]
func (h *AdminHandler) GetAuditLog(c *gin.Context) {
	currentUser := middleware.GetCurrentUser(c)
	if currentUser == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Not authenticated"})
		return
	}

	idStr := c.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid audit log ID"})
		return
	}

	auditLog, err := h.auditService.GetAuditLogByID(c.Request.Context(), id, currentUser.TenantID)
	if err != nil {
		h.logger.Error("Failed to get audit log", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve audit log"})
		return
	}

	if auditLog == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Audit log not found"})
		return
	}

	c.JSON(http.StatusOK, auditLog)
}
