// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"context"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

// threatEventService defines the service interface used by ThreatCorrelationHandler.
type threatEventService interface {
	ListEvents(ctx context.Context, params models.ThreatEventListParams) ([]models.ThreatEvent, int64, error)
	GetEventByID(ctx context.Context, id uuid.UUID) (*models.ThreatEvent, error)
	UpdateEventStatus(ctx context.Context, id uuid.UUID, status models.ThreatEventStatus, resolvedBy *uuid.UUID) error
}

// ThreatCorrelationHandler handles threat event HTTP endpoints.
type ThreatCorrelationHandler struct {
	svc    threatEventService
	logger *zap.Logger
}

// NewThreatCorrelationHandler creates a new ThreatCorrelationHandler.
func NewThreatCorrelationHandler(svc threatEventService, logger *zap.Logger) *ThreatCorrelationHandler {
	return &ThreatCorrelationHandler{svc: svc, logger: logger}
}

// ListEvents handles GET /api/v1/admin/threats.
//
// @Summary List threat events
// @Description Returns a paginated list of correlated threat events with optional filters
// @Tags Security
// @Produce json
// @Param page query int false "Page number" default(1)
// @Param page_size query int false "Results per page" default(20)
// @Param severity query string false "Filter by severity (low, medium, high, critical)"
// @Param status query string false "Filter by status (open, resolved, false_positive)"
// @Param type query string false "Filter by threat type"
// @Param tenant_id query string false "Filter by tenant UUID"
// @Param user_id query string false "Filter by user UUID"
// @Param from query string false "Start time filter (RFC3339)"
// @Param to query string false "End time filter (RFC3339)"
// @Success 200 {object} map[string]interface{} "Paginated list of threat events"
// @Failure 500 {object} map[string]string "Internal server error"
// @Router /api/v1/admin/threats [get]
func (h *ThreatCorrelationHandler) ListEvents(c *gin.Context) {
	params := parseThreatEventListParams(c)

	events, total, err := h.svc.ListEvents(c.Request.Context(), params)
	if err != nil {
		h.logger.Error("Failed to list threat events", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list threat events"})
		return
	}

	responses := make([]*models.ThreatEventResponse, 0, len(events))
	for i := range events {
		responses = append(responses, events[i].ToResponse())
	}

	totalPages := int(total) / params.PageSize
	if int(total)%params.PageSize > 0 {
		totalPages++
	}

	c.JSON(http.StatusOK, gin.H{
		"data":        responses,
		"total":       total,
		"page":        params.Page,
		"page_size":   params.PageSize,
		"total_pages": totalPages,
	})
}

// parseThreatEventListParams builds a ThreatEventListParams from query string values.
func parseThreatEventListParams(c *gin.Context) models.ThreatEventListParams {
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "20"))
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 100 {
		pageSize = 20
	}

	params := models.ThreatEventListParams{
		Page:     page,
		PageSize: pageSize,
		Severity: c.Query("severity"),
		Status:   c.Query("status"),
		Type:     c.Query("type"),
	}

	if tid := c.Query("tenant_id"); tid != "" {
		if id, err := uuid.Parse(tid); err == nil {
			params.TenantID = &id
		}
	}
	if uid := c.Query("user_id"); uid != "" {
		if id, err := uuid.Parse(uid); err == nil {
			params.UserID = &id
		}
	}
	if from := c.Query("from"); from != "" {
		if t, err := time.Parse(time.RFC3339, from); err == nil {
			params.From = &t
		}
	}
	if to := c.Query("to"); to != "" {
		if t, err := time.Parse(time.RFC3339, to); err == nil {
			params.To = &t
		}
	}

	return params
}

// GetEvent handles GET /api/v1/admin/threats/:id.
//
// @Summary Get threat event
// @Description Retrieves a single threat event by its UUID
// @Tags Security
// @Produce json
// @Param id path string true "Threat event UUID"
// @Success 200 {object} models.ThreatEventResponse "Threat event details"
// @Failure 400 {object} map[string]string "Invalid threat event ID"
// @Failure 404 {object} map[string]string "Threat event not found"
// @Router /api/v1/admin/threats/{id} [get]
func (h *ThreatCorrelationHandler) GetEvent(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid threat event ID"})
		return
	}

	event, err := h.svc.GetEventByID(c.Request.Context(), id)
	if err != nil {
		h.logger.Error("Failed to get threat event", zap.Error(err))
		c.JSON(http.StatusNotFound, gin.H{"error": "threat event not found"})
		return
	}

	c.JSON(http.StatusOK, event.ToResponse())
}

// UpdateEventStatus handles PUT /api/v1/admin/threats/:id.
//
// @Summary Update threat event status
// @Description Updates the status of a threat event (e.g. resolve or mark as false positive)
// @Tags Security
// @Accept json
// @Produce json
// @Param id path string true "Threat event UUID"
// @Param request body models.UpdateThreatEventRequest true "New status"
// @Success 200 {object} models.ThreatEventResponse "Updated threat event"
// @Failure 400 {object} map[string]string "Invalid threat event ID or validation error"
// @Failure 500 {object} map[string]string "Internal server error"
// @Router /api/v1/admin/threats/{id} [put]
func (h *ThreatCorrelationHandler) UpdateEventStatus(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid threat event ID"})
		return
	}

	var req models.UpdateThreatEventRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Extract current user for resolved_by tracking
	var resolvedBy *uuid.UUID
	if req.Status == models.ThreatEventStatusResolved || req.Status == models.ThreatEventStatusFalsePositive {
		currentUser, ok := RequireCurrentUser(c)
		if ok && currentUser != nil {
			resolvedBy = &currentUser.ID
		}
	}

	if err := h.svc.UpdateEventStatus(c.Request.Context(), id, req.Status, resolvedBy); err != nil {
		h.logger.Error("Failed to update threat event status", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update threat event status"})
		return
	}

	// Re-fetch and return updated event
	event, err := h.svc.GetEventByID(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"message": "status updated"})
		return
	}

	c.JSON(http.StatusOK, event.ToResponse())
}
