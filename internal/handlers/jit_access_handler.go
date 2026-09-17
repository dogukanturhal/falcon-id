// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/dogukanturhal/falcon-id/internal/middleware"
	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/internal/services"
	"go.uber.org/zap"
)

const (
	msgJITInvalidGrantID = "invalid grant ID"
)

// JITAccessHandler exposes HTTP endpoints for the just-in-time access workflow.
// The typical lifecycle is:
//  1. A user calls RequestAccess.
//  2. An approver calls ApproveAccess.
//  3. A background worker (or explicit call) triggers activation.
//  4. The grant expires automatically, or an admin calls RevokeGrant early.
type JITAccessHandler struct {
	jitService *services.JITAccessService
	logger     *zap.Logger
}

// NewJITAccessHandler creates a new JITAccessHandler.
func NewJITAccessHandler(jitService *services.JITAccessService, logger *zap.Logger) *JITAccessHandler {
	return &JITAccessHandler{
		jitService: jitService,
		logger:     logger,
	}
}

// RequestAccess handles POST /api/v1/jit/grants
//
// @Summary Request JIT access
// @Description Creates a new just-in-time access request in pending state
// @Tags JIT Access
// @Accept json
// @Produce json
// @Param request body models.CreateJITAccessRequest true "JIT access request details"
// @Success 201 {object} models.JITAccessGrantResponse "Created JIT access grant"
// @Failure 400 {object} map[string]string "Validation error or request failed"
// @Failure 401 {object} map[string]string "Not authenticated"
// @Router /api/v1/jit/grants [post]
func (h *JITAccessHandler) RequestAccess(c *gin.Context) {
	currentUser := middleware.GetCurrentUser(c)
	if currentUser == nil {
		return
	}

	var req models.CreateJITAccessRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	grant, err := h.jitService.RequestAccess(c.Request.Context(), currentUser.TenantID, &req)
	if err != nil {
		h.logger.Error("Failed to request JIT access",
			zap.String("user_id", currentUser.ID.String()),
			zap.Error(err),
		)
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, grant.ToResponse())
}

// ApproveAccess handles POST /api/v1/jit/grants/:id/approve
//
// @Summary Approve JIT access grant
// @Description Transitions a pending grant to the approved state; the caller becomes the approver
// @Tags JIT Access
// @Produce json
// @Param id path string true "Grant UUID"
// @Success 200 {object} models.JITAccessGrantResponse "Approved JIT access grant"
// @Failure 400 {object} map[string]string "Invalid grant ID or approval failed"
// @Failure 401 {object} map[string]string "Not authenticated"
// @Router /api/v1/jit/grants/{id}/approve [post]
func (h *JITAccessHandler) ApproveAccess(c *gin.Context) {
	currentUser := middleware.GetCurrentUser(c)
	if currentUser == nil {
		return
	}

	grantID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgJITInvalidGrantID})
		return
	}

	grant, err := h.jitService.ApproveAccess(c.Request.Context(), grantID, currentUser.ID, currentUser.TenantID)
	if err != nil {
		h.logger.Error("Failed to approve JIT access grant",
			zap.String("grant_id", grantID.String()),
			zap.String("approver_id", currentUser.ID.String()),
			zap.Error(err),
		)
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, grant.ToResponse())
}

// ActivateGrant handles POST /api/v1/jit/grants/:id/activate
//
// @Summary Activate JIT access grant
// @Description Transitions an approved grant to active and writes the SpiceDB relationship
// @Tags JIT Access
// @Produce json
// @Param id path string true "Grant UUID"
// @Success 200 {object} map[string]string "JIT access grant activated"
// @Failure 400 {object} map[string]string "Invalid grant ID or activation failed"
// @Router /api/v1/jit/grants/{id}/activate [post]
func (h *JITAccessHandler) ActivateGrant(c *gin.Context) {
	currentUser := middleware.GetCurrentUser(c)
	if currentUser == nil {
		return
	}

	grantID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgJITInvalidGrantID})
		return
	}

	if err := h.jitService.ActivateGrant(c.Request.Context(), grantID, currentUser.TenantID); err != nil {
		h.logger.Error("Failed to activate JIT access grant",
			zap.String("grant_id", grantID.String()),
			zap.Error(err),
		)
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "JIT access grant activated"})
}

// ListGrants handles GET /api/v1/jit/grants
//
// @Summary List JIT access grants
// @Description Returns a paginated list of JIT access grants for the current tenant
// @Tags JIT Access
// @Produce json
// @Param status query string false "Filter by status (pending, approved, active, expired, revoked)"
// @Param page query int false "Page number" default(1)
// @Param page_size query int false "Results per page" default(20)
// @Success 200 {object} models.JITAccessGrantListResponse "Paginated list of JIT grants"
// @Failure 401 {object} map[string]string "Not authenticated"
// @Failure 500 {object} map[string]string "Internal server error"
// @Router /api/v1/jit/grants [get]
func (h *JITAccessHandler) ListGrants(c *gin.Context) {
	currentUser := middleware.GetCurrentUser(c)
	if currentUser == nil {
		return
	}

	status := c.Query("status")
	page := parsePageParam(c.Query("page"), 1)
	pageSize := parsePageParam(c.Query("page_size"), 20)

	grants, total, err := h.jitService.ListGrants(c.Request.Context(), currentUser.TenantID, status, page, pageSize)
	if err != nil {
		h.logger.Error("Failed to list JIT access grants",
			zap.String("tenant_id", currentUser.TenantID.String()),
			zap.Error(err),
		)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list JIT access grants"})
		return
	}

	responses := make([]models.JITAccessGrantResponse, 0, len(grants))
	for _, g := range grants {
		responses = append(responses, *g.ToResponse())
	}

	totalPages := 0
	if pageSize > 0 {
		totalPages = int((total + int64(pageSize) - 1) / int64(pageSize))
	}

	c.JSON(http.StatusOK, models.JITAccessGrantListResponse{
		Grants:     responses,
		Total:      total,
		Page:       page,
		PageSize:   pageSize,
		TotalPages: totalPages,
	})
}

// RevokeGrant handles POST /api/v1/jit/grants/:id/revoke
//
// @Summary Revoke JIT access grant
// @Description Immediately revokes a pending, approved, or active grant; removes SpiceDB relationship if active
// @Tags JIT Access
// @Produce json
// @Param id path string true "Grant UUID"
// @Success 200 {object} map[string]string "JIT access grant revoked"
// @Failure 400 {object} map[string]string "Invalid grant ID or revocation failed"
// @Failure 401 {object} map[string]string "Not authenticated"
// @Router /api/v1/jit/grants/{id}/revoke [post]
func (h *JITAccessHandler) RevokeGrant(c *gin.Context) {
	currentUser := middleware.GetCurrentUser(c)
	if currentUser == nil {
		return
	}

	grantID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgJITInvalidGrantID})
		return
	}

	if err := h.jitService.RevokeGrant(c.Request.Context(), grantID, currentUser.ID, currentUser.TenantID); err != nil {
		h.logger.Error("Failed to revoke JIT access grant",
			zap.String("grant_id", grantID.String()),
			zap.String("revoker_id", currentUser.ID.String()),
			zap.Error(err),
		)
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "JIT access grant revoked"})
}
