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
	"github.com/dogukanturhal/falcon-id/internal/services"
)

const (
	msgNotAuthenticated = "Not authenticated"
)

// AdminAuditHandler handles admin audit log endpoints
type AdminAuditHandler struct {
	auditService *services.AdminAuditService
	logger       *zap.Logger
}

// NewAdminAuditHandler creates a new admin audit handler
func NewAdminAuditHandler(auditService *services.AdminAuditService, logger *zap.Logger) *AdminAuditHandler {
	return &AdminAuditHandler{
		auditService: auditService,
		logger:       logger,
	}
}

// ListAdminAuditLogs lists admin audit logs with filtering
// @Summary List Admin Audit Logs
// @Description List admin audit logs for the tenant with filtering and pagination
// @Tags Admin - Audit
// @Produce json
// @Security BearerAuth
// @Param actor_id query string false "Filter by actor (admin user) ID"
// @Param action query string false "Filter by action (e.g., user.create)"
// @Param resource query string false "Filter by resource type (e.g., user, role)"
// @Param resource_id query string false "Filter by resource ID"
// @Param success query boolean false "Filter by success status"
// @Param from query string false "Filter by from date (RFC3339)"
// @Param to query string false "Filter by to date (RFC3339)"
// @Param page query int false "Page number" default(1)
// @Param page_size query int false "Page size" default(50)
// @Success 200 {object} map[string]interface{}
// @Failure 401 {object} map[string]string
// @Failure 403 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /api/admin/audit/admin-actions [get]
func (h *AdminAuditHandler) ListAdminAuditLogs(c *gin.Context) {
	currentUser := middleware.GetCurrentUser(c)
	if currentUser == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": msgNotAuthenticated})
		return
	}

	filters := h.buildAuditQueryFilters(c, &currentUser.TenantID)

	events, total, err := h.auditService.QueryEvents(c.Request.Context(), filters)
	if err != nil {
		h.logger.Error("Failed to query admin audit logs", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve audit logs"})
		return
	}

	totalPages := int(total) / filters.PageSize
	if int(total)%filters.PageSize > 0 {
		totalPages++
	}

	c.JSON(http.StatusOK, gin.H{
		"events":      events,
		"total":       total,
		"page":        filters.Page,
		"page_size":   filters.PageSize,
		"total_pages": totalPages,
	})
}

// buildAuditQueryFilters parses query parameters into AuditQueryFilters.
func (h *AdminAuditHandler) buildAuditQueryFilters(c *gin.Context, tenantID *uuid.UUID) services.AuditQueryFilters {
	filters := services.AuditQueryFilters{
		TenantID: tenantID,
		Page:     1,
		PageSize: 50,
	}

	if actorIDStr := c.Query("actor_id"); actorIDStr != "" {
		if actorID, err := uuid.Parse(actorIDStr); err == nil {
			filters.ActorID = &actorID
		}
	}
	if action := c.Query("action"); action != "" {
		filters.Action = action
	}
	if resource := c.Query("resource"); resource != "" {
		filters.Resource = resource
	}
	if resourceIDStr := c.Query("resource_id"); resourceIDStr != "" {
		if resourceID, err := uuid.Parse(resourceIDStr); err == nil {
			filters.ResourceID = &resourceID
		}
	}
	if successStr := c.Query("success"); successStr != "" {
		if success, err := strconv.ParseBool(successStr); err == nil {
			filters.Success = &success
		}
	}
	if fromStr := c.Query("from"); fromStr != "" {
		if from, err := time.Parse(time.RFC3339, fromStr); err == nil {
			filters.FromDate = &from
		}
	}
	if toStr := c.Query("to"); toStr != "" {
		if to, err := time.Parse(time.RFC3339, toStr); err == nil {
			filters.ToDate = &to
		}
	}
	if pageStr := c.Query("page"); pageStr != "" {
		if page, err := strconv.Atoi(pageStr); err == nil && page > 0 {
			filters.Page = page
		}
	}
	if pageSizeStr := c.Query("page_size"); pageSizeStr != "" {
		if pageSize, err := strconv.Atoi(pageSizeStr); err == nil && pageSize > 0 && pageSize <= 100 {
			filters.PageSize = pageSize
		}
	}
	return filters
}

// GetAdminAuditLog retrieves a specific admin audit log by ID
// @Summary Get Admin Audit Log
// @Description Get a specific admin audit log entry by ID
// @Tags Admin - Audit
// @Produce json
// @Security BearerAuth
// @Param id path string true "Audit event ID"
// @Success 200 {object} services.AdminAuditEvent
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Failure 403 {object} map[string]string
// @Failure 404 {object} map[string]string
// @Router /api/admin/audit/admin-actions/{id} [get]
func (h *AdminAuditHandler) GetAdminAuditLog(c *gin.Context) {
	currentUser := middleware.GetCurrentUser(c)
	if currentUser == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": msgNotAuthenticated})
		return
	}

	idStr := c.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid audit event ID"})
		return
	}

	event, err := h.auditService.GetEventByID(c.Request.Context(), id)
	if err != nil {
		h.logger.Error("Failed to get admin audit log", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve audit log"})
		return
	}

	if event == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Audit log not found"})
		return
	}

	// Verify the audit event belongs to the caller's tenant
	if event.TenantID != currentUser.TenantID {
		c.JSON(http.StatusNotFound, gin.H{"error": "Audit log not found"})
		return
	}

	c.JSON(http.StatusOK, event)
}

// GetAdminAuditStats retrieves statistics about admin actions
// @Summary Get Admin Audit Statistics
// @Description Get statistics about admin actions (by actor, action type, resource, etc.)
// @Tags Admin - Audit
// @Produce json
// @Security BearerAuth
// @Param from query string false "From date (RFC3339)"
// @Param to query string false "To date (RFC3339)"
// @Success 200 {object} map[string]interface{}
// @Failure 401 {object} map[string]string
// @Failure 403 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /api/admin/audit/admin-actions/stats [get]
func (h *AdminAuditHandler) GetAdminAuditStats(c *gin.Context) {
	currentUser := middleware.GetCurrentUser(c)
	if currentUser == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": msgNotAuthenticated})
		return
	}

	// Parse date range
	var fromDate, toDate *time.Time
	if fromStr := c.Query("from"); fromStr != "" {
		if from, err := time.Parse(time.RFC3339, fromStr); err == nil {
			fromDate = &from
		}
	}
	if toStr := c.Query("to"); toStr != "" {
		if to, err := time.Parse(time.RFC3339, toStr); err == nil {
			toDate = &to
		}
	}

	// Default to last 30 days if not specified
	if fromDate == nil {
		from := time.Now().AddDate(0, 0, -30)
		fromDate = &from
	}
	if toDate == nil {
		to := time.Now()
		toDate = &to
	}

	// Query all events in the date range (scoped to tenant)
	filters := services.AuditQueryFilters{
		TenantID: &currentUser.TenantID,
		FromDate: fromDate,
		ToDate:   toDate,
		Page:     1,
		PageSize: 10000, // Get all events (for stats calculation)
	}

	events, total, err := h.auditService.QueryEvents(c.Request.Context(), filters)
	if err != nil {
		h.logger.Error("Failed to query admin audit logs for stats", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve audit statistics"})
		return
	}

	// Calculate statistics
	stats := calculateAuditStats(events, total)

	c.JSON(http.StatusOK, stats)
}

// calculateAuditStats calculates statistics from audit events
func calculateAuditStats(events []services.AdminAuditEvent, total int64) map[string]interface{} {
	stats := make(map[string]interface{})

	// Total events
	stats["total_events"] = total

	// Count by action
	actionCounts := make(map[string]int)
	for _, event := range events {
		actionCounts[event.Action]++
	}
	stats["by_action"] = actionCounts

	// Count by resource
	resourceCounts := make(map[string]int)
	for _, event := range events {
		resourceCounts[event.Resource]++
	}
	stats["by_resource"] = resourceCounts

	// Count by actor
	actorCounts := make(map[string]int)
	for _, event := range events {
		actorCounts[event.ActorEmail]++
	}
	stats["by_actor"] = actorCounts

	// Count successes vs failures
	successCount := 0
	failureCount := 0
	for _, event := range events {
		if event.Success {
			successCount++
		} else {
			failureCount++
		}
	}
	stats["success_count"] = successCount
	stats["failure_count"] = failureCount

	// Average duration (if available)
	totalDuration := int64(0)
	countWithDuration := 0
	for _, event := range events {
		if event.Duration > 0 {
			totalDuration += event.Duration
			countWithDuration++
		}
	}
	if countWithDuration > 0 {
		stats["average_duration_ms"] = totalDuration / int64(countWithDuration)
	}

	return stats
}
