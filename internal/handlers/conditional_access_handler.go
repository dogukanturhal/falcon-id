// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"context"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

const (
	msgInvalidPolicyID = "invalid policy ID"
	stateEnabled       = "enabled"
	stateDisabled      = "disabled"
)

// conditionalAccessService is the service interface used by ConditionalAccessHandler.
type conditionalAccessService interface {
	Create(ctx context.Context, req *models.CreateCAPRequest, createdBy uuid.UUID) (*models.ConditionalAccessPolicy, error)
	GetByID(ctx context.Context, id uuid.UUID) (*models.ConditionalAccessPolicy, error)
	List(ctx context.Context, tenantID *uuid.UUID) ([]models.ConditionalAccessPolicy, error)
	Update(ctx context.Context, id uuid.UUID, req *models.UpdateCAPRequest) (*models.ConditionalAccessPolicy, error)
	Delete(ctx context.Context, id uuid.UUID) error
	SetEnabled(ctx context.Context, id uuid.UUID, enabled bool) error
	EvaluateLogin(ctx context.Context, ctx2 models.CAPEvaluationContext) (*models.CAPEvaluationResult, error)
	Simulate(ctx context.Context, req *models.SimulateCAPRequest) (*models.CAPEvaluationResult, error)
	ListEvaluationLog(ctx context.Context, userID *uuid.UUID, tenantID *uuid.UUID, page, pageSize int) ([]map[string]interface{}, int64, error)
}

// ConditionalAccessHandler handles conditional access policy HTTP endpoints.
type ConditionalAccessHandler struct {
	svc    conditionalAccessService
	logger *zap.Logger
}

// NewConditionalAccessHandler creates a new ConditionalAccessHandler.
func NewConditionalAccessHandler(svc conditionalAccessService, log *zap.Logger) *ConditionalAccessHandler {
	if log == nil {
		log = zap.NewNop()
	}
	return &ConditionalAccessHandler{svc: svc, logger: log}
}

// List handles GET /api/v1/admin/conditional-access.
//
// @Summary List conditional access policies
// @Description Returns all conditional access policies, optionally filtered by tenant
// @Tags Conditional Access
// @Produce json
// @Param tenant_id query string false "Filter by tenant UUID"
// @Success 200 {object} map[string]interface{} "List of conditional access policies"
// @Failure 500 {object} map[string]string "Internal server error"
// @Router /api/v1/admin/conditional-access [get]
func (h *ConditionalAccessHandler) List(c *gin.Context) {
	var tenantID *uuid.UUID
	if tid := c.Query("tenant_id"); tid != "" {
		if id, err := uuid.Parse(tid); err == nil {
			tenantID = &id
		}
	}

	policies, err := h.svc.List(c.Request.Context(), tenantID)
	if err != nil {
		h.logger.Error("ConditionalAccessHandler.List failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list policies"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"policies": policies, "total": len(policies)})
}

// Create handles POST /api/v1/admin/conditional-access.
//
// @Summary Create conditional access policy
// @Description Creates a new conditional access policy
// @Tags Conditional Access
// @Accept json
// @Produce json
// @Param request body models.CreateCAPRequest true "Policy configuration"
// @Success 201 {object} models.ConditionalAccessPolicy "Created policy"
// @Failure 400 {object} map[string]string "Validation error"
// @Failure 401 {object} map[string]string "Not authenticated"
// @Failure 500 {object} map[string]string "Internal server error"
// @Router /api/v1/admin/conditional-access [post]
func (h *ConditionalAccessHandler) Create(c *gin.Context) {
	var req models.CreateCAPRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	currentUser, ok := RequireCurrentUser(c)
	if !ok || currentUser == nil {
		return
	}

	policy, err := h.svc.Create(c.Request.Context(), &req, currentUser.ID)
	if err != nil {
		h.logger.Error("ConditionalAccessHandler.Create failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create policy"})
		return
	}

	c.JSON(http.StatusCreated, policy)
}

// GetByID handles GET /api/v1/admin/conditional-access/:id.
//
// @Summary Get conditional access policy
// @Description Retrieves a conditional access policy by its UUID
// @Tags Conditional Access
// @Produce json
// @Param id path string true "Policy UUID"
// @Success 200 {object} models.ConditionalAccessPolicy "Conditional access policy"
// @Failure 400 {object} map[string]string "Invalid policy ID"
// @Failure 404 {object} map[string]string "Policy not found"
// @Router /api/v1/admin/conditional-access/{id} [get]
func (h *ConditionalAccessHandler) GetByID(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgInvalidPolicyID})
		return
	}

	policy, err := h.svc.GetByID(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "policy not found"})
		return
	}

	c.JSON(http.StatusOK, policy)
}

// Update handles PUT /api/v1/admin/conditional-access/:id.
//
// @Summary Update conditional access policy
// @Description Updates an existing conditional access policy
// @Tags Conditional Access
// @Accept json
// @Produce json
// @Param id path string true "Policy UUID"
// @Param request body models.UpdateCAPRequest true "Updated policy configuration"
// @Success 200 {object} models.ConditionalAccessPolicy "Updated policy"
// @Failure 400 {object} map[string]string "Invalid policy ID or validation error"
// @Failure 500 {object} map[string]string "Internal server error"
// @Router /api/v1/admin/conditional-access/{id} [put]
func (h *ConditionalAccessHandler) Update(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgInvalidPolicyID})
		return
	}

	var req models.UpdateCAPRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	policy, err := h.svc.Update(c.Request.Context(), id, &req)
	if err != nil {
		h.logger.Error("ConditionalAccessHandler.Update failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update policy"})
		return
	}

	c.JSON(http.StatusOK, policy)
}

// Delete handles DELETE /api/v1/admin/conditional-access/:id.
//
// @Summary Delete conditional access policy
// @Description Permanently removes a conditional access policy
// @Tags Conditional Access
// @Produce json
// @Param id path string true "Policy UUID"
// @Success 200 {object} map[string]string "Policy deleted"
// @Failure 400 {object} map[string]string "Invalid policy ID"
// @Failure 500 {object} map[string]string "Internal server error"
// @Router /api/v1/admin/conditional-access/{id} [delete]
func (h *ConditionalAccessHandler) Delete(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgInvalidPolicyID})
		return
	}

	if err := h.svc.Delete(c.Request.Context(), id); err != nil {
		h.logger.Error("ConditionalAccessHandler.Delete failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to delete policy"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "policy deleted"})
}

// Enable handles POST /api/v1/admin/conditional-access/:id/enable.
//
// @Summary Enable conditional access policy
// @Description Activates a disabled conditional access policy
// @Tags Conditional Access
// @Produce json
// @Param id path string true "Policy UUID"
// @Success 200 {object} map[string]string "Policy enabled"
// @Failure 400 {object} map[string]string "Invalid policy ID"
// @Failure 500 {object} map[string]string "Internal server error"
// @Router /api/v1/admin/conditional-access/{id}/enable [post]
func (h *ConditionalAccessHandler) Enable(c *gin.Context) {
	h.setEnabled(c, true)
}

// Disable handles POST /api/v1/admin/conditional-access/:id/disable.
//
// @Summary Disable conditional access policy
// @Description Deactivates a conditional access policy without deleting it
// @Tags Conditional Access
// @Produce json
// @Param id path string true "Policy UUID"
// @Success 200 {object} map[string]string "Policy disabled"
// @Failure 400 {object} map[string]string "Invalid policy ID"
// @Failure 500 {object} map[string]string "Internal server error"
// @Router /api/v1/admin/conditional-access/{id}/disable [post]
func (h *ConditionalAccessHandler) Disable(c *gin.Context) {
	h.setEnabled(c, false)
}

func (h *ConditionalAccessHandler) setEnabled(c *gin.Context, enabled bool) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgInvalidPolicyID})
		return
	}

	if err := h.svc.SetEnabled(c.Request.Context(), id, enabled); err != nil {
		h.logger.Error("ConditionalAccessHandler.setEnabled failed",
			zap.Bool("enabled", enabled),
			zap.Error(err),
		)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update policy state"})
		return
	}

	state := stateEnabled
	if !enabled {
		state = stateDisabled
	}
	c.JSON(http.StatusOK, gin.H{"message": "policy " + state})
}

// Simulate handles POST /api/v1/admin/conditional-access/simulate.
//
// @Summary Simulate conditional access evaluation
// @Description Performs a dry-run policy evaluation without writing an audit log entry
// @Tags Conditional Access
// @Accept json
// @Produce json
// @Param request body models.SimulateCAPRequest true "Simulation context"
// @Success 200 {object} models.CAPEvaluationResult "Simulation result"
// @Failure 400 {object} map[string]string "Validation error"
// @Failure 500 {object} map[string]string "Simulation failed"
// @Router /api/v1/admin/conditional-access/simulate [post]
func (h *ConditionalAccessHandler) Simulate(c *gin.Context) {
	var req models.SimulateCAPRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	result, err := h.svc.Simulate(c.Request.Context(), &req)
	if err != nil {
		h.logger.Error("ConditionalAccessHandler.Simulate failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "simulation failed"})
		return
	}

	c.JSON(http.StatusOK, result)
}

// ListEvaluationLog handles GET /api/v1/admin/conditional-access/evaluation-log.
//
// @Summary List conditional access evaluation log
// @Description Returns a paginated log of conditional access policy evaluations
// @Tags Conditional Access
// @Produce json
// @Param page query int false "Page number" default(1)
// @Param page_size query int false "Results per page" default(20)
// @Param user_id query string false "Filter by user UUID"
// @Param tenant_id query string false "Filter by tenant UUID"
// @Success 200 {object} map[string]interface{} "Paginated evaluation log"
// @Failure 500 {object} map[string]string "Internal server error"
// @Router /api/v1/admin/conditional-access/evaluation-log [get]
func (h *ConditionalAccessHandler) ListEvaluationLog(c *gin.Context) {
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "20"))

	var userID, tenantID *uuid.UUID
	if uid := c.Query("user_id"); uid != "" {
		if id, err := uuid.Parse(uid); err == nil {
			userID = &id
		}
	}
	if tid := c.Query("tenant_id"); tid != "" {
		if id, err := uuid.Parse(tid); err == nil {
			tenantID = &id
		}
	}

	entries, total, err := h.svc.ListEvaluationLog(c.Request.Context(), userID, tenantID, page, pageSize)
	if err != nil {
		h.logger.Error("ConditionalAccessHandler.ListEvaluationLog failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to fetch evaluation log"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"entries":   entries,
		"total":     total,
		"page":      page,
		"page_size": pageSize,
	})
}
