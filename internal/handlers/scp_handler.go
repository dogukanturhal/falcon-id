// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/internal/services"
)

const (
	msgSCPInvalidID = "invalid SCP ID"
)

// SCPHandler exposes HTTP endpoints for managing service control policies.
// All mutating endpoints require platform-admin level access; enforcement is
// applied by router-level middleware rather than inside the handler.
type SCPHandler struct {
	scpService *services.SCPService
	logger     *zap.Logger
}

// NewSCPHandler creates a new SCPHandler.
func NewSCPHandler(scpService *services.SCPService, logger *zap.Logger) *SCPHandler {
	return &SCPHandler{
		scpService: scpService,
		logger:     logger,
	}
}

// Create handles POST /api/v1/admin/scps.
//
// @Summary Create service control policy
// @Description Creates a new service control policy with allow/deny rules for platform or tenant scope
// @Tags Service Control Policies
// @Accept json
// @Produce json
// @Param request body models.CreateSCPRequest true "SCP configuration"
// @Success 201 {object} models.SCPResponse "Created service control policy"
// @Failure 400 {object} map[string]string "Validation error"
// @Router /api/v1/admin/scps [post]
func (h *SCPHandler) Create(c *gin.Context) {
	var req models.CreateSCPRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	scp, err := h.scpService.Create(c.Request.Context(), &req)
	if err != nil {
		h.logger.Error("failed to create SCP", zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, scp.ToResponse())
}

// List handles GET /api/v1/admin/scps.
//
// @Summary List service control policies
// @Description Returns a paginated list of service control policies with optional scope filter
// @Tags Service Control Policies
// @Produce json
// @Param scope query string false "Filter by scope (platform, realm, tenant)"
// @Param page query int false "Page number" default(1)
// @Param page_size query int false "Results per page" default(20)
// @Success 200 {object} models.SCPListResponse "Paginated list of service control policies"
// @Failure 500 {object} map[string]string "Internal server error"
// @Router /api/v1/admin/scps [get]
func (h *SCPHandler) List(c *gin.Context) {
	scope := c.Query("scope")
	page := parsePageParam(c.Query("page"), 1)
	pageSize := parsePageParam(c.Query("page_size"), 20)

	policies, total, err := h.scpService.List(c.Request.Context(), scope, page, pageSize)
	if err != nil {
		h.logger.Error("failed to list SCPs", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list service control policies"})
		return
	}

	responses := make([]models.SCPResponse, 0, len(policies))
	for _, p := range policies {
		responses = append(responses, *p.ToResponse())
	}

	totalPages := 0
	if pageSize > 0 {
		totalPages = int((total + int64(pageSize) - 1) / int64(pageSize))
	}

	c.JSON(http.StatusOK, models.SCPListResponse{
		Policies:   responses,
		Total:      total,
		Page:       page,
		PageSize:   pageSize,
		TotalPages: totalPages,
	})
}

// GetByID handles GET /api/v1/admin/scps/:id.
//
// @Summary Get service control policy
// @Description Returns a single service control policy by its UUID
// @Tags Service Control Policies
// @Produce json
// @Param id path string true "SCP UUID"
// @Success 200 {object} models.SCPResponse "Service control policy"
// @Failure 400 {object} map[string]string "Invalid SCP ID"
// @Failure 404 {object} map[string]string "Service control policy not found"
// @Failure 500 {object} map[string]string "Internal server error"
// @Router /api/v1/admin/scps/{id} [get]
func (h *SCPHandler) GetByID(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgSCPInvalidID})
		return
	}

	scp, err := h.scpService.GetByID(c.Request.Context(), id)
	if err != nil {
		h.logger.Error("failed to get SCP", zap.String("id", id.String()), zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to retrieve service control policy"})
		return
	}
	if scp == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "service control policy not found"})
		return
	}

	c.JSON(http.StatusOK, scp.ToResponse())
}

// Update handles PATCH /api/v1/admin/scps/:id.
//
// @Summary Update service control policy
// @Description Applies a partial update to an existing service control policy
// @Tags Service Control Policies
// @Accept json
// @Produce json
// @Param id path string true "SCP UUID"
// @Param request body models.UpdateSCPRequest true "Fields to update"
// @Success 200 {object} models.SCPResponse "Updated service control policy"
// @Failure 400 {object} map[string]string "Invalid SCP ID or validation error"
// @Router /api/v1/admin/scps/{id} [patch]
func (h *SCPHandler) Update(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgSCPInvalidID})
		return
	}

	var req models.UpdateSCPRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	scp, err := h.scpService.Update(c.Request.Context(), id, &req)
	if err != nil {
		h.logger.Error("failed to update SCP", zap.String("id", id.String()), zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, scp.ToResponse())
}

// Delete handles DELETE /api/v1/admin/scps/:id.
//
// @Summary Delete service control policy
// @Description Permanently removes a service control policy
// @Tags Service Control Policies
// @Produce json
// @Param id path string true "SCP UUID"
// @Success 200 {object} map[string]string "Service control policy deleted"
// @Failure 400 {object} map[string]string "Invalid SCP ID"
// @Failure 404 {object} map[string]string "Service control policy not found"
// @Router /api/v1/admin/scps/{id} [delete]
func (h *SCPHandler) Delete(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgSCPInvalidID})
		return
	}

	if err := h.scpService.Delete(c.Request.Context(), id); err != nil {
		h.logger.Error("failed to delete SCP", zap.String("id", id.String()), zap.Error(err))
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "service control policy deleted"})
}

// Enable handles POST /api/v1/admin/scps/:id/enable.
//
// @Summary Enable service control policy
// @Description Activates a disabled service control policy
// @Tags Service Control Policies
// @Produce json
// @Param id path string true "SCP UUID"
// @Success 200 {object} map[string]string "Service control policy enabled"
// @Failure 400 {object} map[string]string "Invalid SCP ID"
// @Failure 404 {object} map[string]string "Service control policy not found"
// @Router /api/v1/admin/scps/{id}/enable [post]
func (h *SCPHandler) Enable(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgSCPInvalidID})
		return
	}

	if err := h.scpService.Enable(c.Request.Context(), id); err != nil {
		h.logger.Error("failed to enable SCP", zap.String("id", id.String()), zap.Error(err))
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "service control policy enabled"})
}

// Disable handles POST /api/v1/admin/scps/:id/disable.
//
// @Summary Disable service control policy
// @Description Deactivates a service control policy without deleting it
// @Tags Service Control Policies
// @Produce json
// @Param id path string true "SCP UUID"
// @Success 200 {object} map[string]string "Service control policy disabled"
// @Failure 400 {object} map[string]string "Invalid SCP ID"
// @Failure 404 {object} map[string]string "Service control policy not found"
// @Router /api/v1/admin/scps/{id}/disable [post]
func (h *SCPHandler) Disable(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgSCPInvalidID})
		return
	}

	if err := h.scpService.Disable(c.Request.Context(), id); err != nil {
		h.logger.Error("failed to disable SCP", zap.String("id", id.String()), zap.Error(err))
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "service control policy disabled"})
}

// parsePageParam parses a query-string integer parameter with a fallback default.
func parsePageParam(raw string, defaultVal int) int {
	if raw == "" {
		return defaultVal
	}
	v, err := strconv.Atoi(raw)
	if err != nil || v < 1 {
		return defaultVal
	}
	return v
}
