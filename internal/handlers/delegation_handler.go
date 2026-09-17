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

// DelegationHandler is an exported type.
type DelegationHandler struct {
	delegationService *services.DelegationService
	logger            *zap.Logger
}

// NewDelegationHandler is an exported function.
func NewDelegationHandler(delegationService *services.DelegationService, logger *zap.Logger) *DelegationHandler {
	return &DelegationHandler{
		delegationService: delegationService,
		logger:            logger,
	}
}

// CreateDelegation creates a new delegation
// @Summary Create a new delegation
// @Tags Delegations
// @Accept json
// @Produce json
// @Param request body models.CreateDelegationRequest true "Delegation details"
// @Success 201 {object} models.DelegationResponse
// @Failure 400 {object} models.ErrorResponse
// @Failure 401 {object} models.ErrorResponse
// @Failure 403 {object} models.ErrorResponse
// @Router /api/delegations [post]
func (h *DelegationHandler) CreateDelegation(c *gin.Context) {
	currentUser := middleware.GetCurrentUser(c)
	if currentUser == nil {
		return
	}

	// Parse request
	var req models.CreateDelegationRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Create delegation
	delegation, err := h.delegationService.CreateDelegation(c.Request.Context(), currentUser.ID, currentUser.TenantID, &req)
	if err != nil {
		h.logger.Error("Failed to create delegation",
			zap.Error(err),
			zap.String("user_id", currentUser.ID.String()),
		)
		c.JSON(http.StatusForbidden, gin.H{"error": err.Error()})
		return
	}

	// Load response
	response, err := h.delegationService.GetDelegation(c.Request.Context(), delegation.ID, currentUser.ID, currentUser.TenantID)
	if err != nil {
		h.logger.Error("Failed to load delegation response",
			zap.Error(err),
			zap.String("delegation_id", delegation.ID.String()),
		)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to load delegation"})
		return
	}

	c.JSON(http.StatusCreated, response)
}

// ListMyDelegations lists delegations given and received by the current user
// @Summary List my delegations
// @Tags Delegations
// @Accept json
// @Produce json
// @Param include_revoked query bool false "Include revoked delegations"
// @Success 200 {array} models.DelegationResponse
// @Failure 401 {object} models.ErrorResponse
// @Router /api/delegations [get]
func (h *DelegationHandler) ListMyDelegations(c *gin.Context) {
	currentUser := middleware.GetCurrentUser(c)
	if currentUser == nil {
		return
	}

	// Parse query params
	includeRevoked := c.Query("include_revoked") == queryBoolTrue

	// List delegations
	delegations, err := h.delegationService.ListMyDelegations(c.Request.Context(), currentUser.ID, includeRevoked)
	if err != nil {
		h.logger.Error("Failed to list delegations",
			zap.Error(err),
			zap.String("user_id", currentUser.ID.String()),
		)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list delegations"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"delegations": delegations})
}

// GetDelegation retrieves a delegation by ID
// @Summary Get delegation details
// @Tags Delegations
// @Accept json
// @Produce json
// @Param id path string true "Delegation ID"
// @Success 200 {object} models.DelegationResponse
// @Failure 401 {object} models.ErrorResponse
// @Failure 404 {object} models.ErrorResponse
// @Router /api/delegations/{id} [get]
func (h *DelegationHandler) GetDelegation(c *gin.Context) {
	currentUser := middleware.GetCurrentUser(c)
	if currentUser == nil {
		return
	}

	// Parse delegation ID
	delegationID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid delegation ID"})
		return
	}

	// Get delegation
	delegation, err := h.delegationService.GetDelegation(c.Request.Context(), delegationID, currentUser.ID, currentUser.TenantID)
	if err != nil {
		h.logger.Error("Failed to get delegation",
			zap.Error(err),
			zap.String("delegation_id", delegationID.String()),
		)
		c.JSON(http.StatusNotFound, gin.H{"error": "delegation not found"})
		return
	}

	c.JSON(http.StatusOK, delegation)
}

// RevokeDelegation revokes a delegation
// @Summary Revoke a delegation
// @Tags Delegations
// @Accept json
// @Produce json
// @Param id path string true "Delegation ID"
// @Success 200 {object} models.SuccessResponse
// @Failure 401 {object} models.ErrorResponse
// @Failure 403 {object} models.ErrorResponse
// @Failure 404 {object} models.ErrorResponse
// @Router /api/delegations/{id} [delete]
func (h *DelegationHandler) RevokeDelegation(c *gin.Context) {
	currentUser := middleware.GetCurrentUser(c)
	if currentUser == nil {
		return
	}

	// Parse delegation ID
	delegationID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid delegation ID"})
		return
	}

	// Revoke delegation
	err = h.delegationService.RevokeDelegation(c.Request.Context(), delegationID, currentUser.ID, currentUser.TenantID)
	if err != nil {
		h.logger.Error("Failed to revoke delegation",
			zap.Error(err),
			zap.String("delegation_id", delegationID.String()),
		)
		c.JSON(http.StatusForbidden, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "delegation revoked successfully"})
}
