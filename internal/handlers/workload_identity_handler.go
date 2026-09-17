// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/middleware"
	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/internal/services"
)

// WorkloadIdentityHandler exposes HTTP endpoints for managing workload identity
// federation providers and for performing token exchange.
type WorkloadIdentityHandler struct {
	service *services.TokenExchangeService
	logger  *zap.Logger
}

// NewWorkloadIdentityHandler creates a WorkloadIdentityHandler.
func NewWorkloadIdentityHandler(service *services.TokenExchangeService, logger *zap.Logger) *WorkloadIdentityHandler {
	return &WorkloadIdentityHandler{
		service: service,
		logger:  logger,
	}
}

// ============================================================
// Admin CRUD endpoints
// ============================================================

// List returns all workload identity providers for the authenticated tenant.
//
// @Summary List workload identity providers
// @Description Returns all workload identity federation providers for the current tenant
// @Tags Workload Identity
// @Produce json
// @Param page query int false "Page number" default(1)
// @Param page_size query int false "Results per page" default(20)
// @Success 200 {object} map[string]interface{} "Paginated list of workload identity providers"
// @Failure 401 {object} map[string]string "Not authenticated"
// @Failure 500 {object} map[string]string "Internal server error"
// @Router /api/v1/admin/workload-identity-providers [get]
func (h *WorkloadIdentityHandler) List(c *gin.Context) {
	tenantID, ok := h.requireTenantID(c)
	if !ok {
		return
	}

	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "20"))

	resp, err := h.service.ListProviders(c.Request.Context(), tenantID, page, pageSize)
	if err != nil {
		h.logger.Error("Failed to list workload identity providers", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list providers"})
		return
	}

	c.JSON(http.StatusOK, resp)
}

// Create registers a new workload identity provider.
//
// @Summary Create workload identity provider
// @Description Registers a new OIDC/JWT workload identity federation provider for the current tenant
// @Tags Workload Identity
// @Accept json
// @Produce json
// @Param request body models.CreateWorkloadProviderRequest true "Provider configuration"
// @Success 201 {object} map[string]interface{} "Created workload identity provider"
// @Failure 400 {object} map[string]string "Validation error"
// @Failure 401 {object} map[string]string "Not authenticated"
// @Router /api/v1/admin/workload-identity-providers [post]
func (h *WorkloadIdentityHandler) Create(c *gin.Context) {
	tenantID, ok := h.requireTenantID(c)
	if !ok {
		return
	}

	var req models.CreateWorkloadProviderRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	createdBy := h.currentUserID(c)

	provider, err := h.service.CreateProvider(c.Request.Context(), tenantID, &req, createdBy)
	if err != nil {
		h.logger.Error("Failed to create workload identity provider",
			zap.String("tenant_id", tenantID.String()),
			zap.Error(err),
		)
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, provider)
}

// GetByID returns a single provider by ID.
//
// @Summary Get workload identity provider
// @Description Retrieves a workload identity provider by its UUID
// @Tags Workload Identity
// @Produce json
// @Param id path string true "Provider UUID"
// @Success 200 {object} map[string]interface{} "Workload identity provider"
// @Failure 400 {object} map[string]string "Invalid provider ID"
// @Failure 404 {object} map[string]string "Provider not found"
// @Failure 500 {object} map[string]string "Internal server error"
// @Router /api/v1/admin/workload-identity-providers/{id} [get]
func (h *WorkloadIdentityHandler) GetByID(c *gin.Context) {
	id, ok := h.parseProviderID(c)
	if !ok {
		return
	}

	provider, err := h.service.GetProvider(c.Request.Context(), id)
	if err != nil {
		h.logger.Error("Failed to get workload identity provider", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve provider"})
		return
	}
	if provider == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Provider not found"})
		return
	}

	c.JSON(http.StatusOK, provider)
}

// Update applies a partial update to a provider.
//
// @Summary Update workload identity provider
// @Description Applies a partial update to a workload identity provider
// @Tags Workload Identity
// @Accept json
// @Produce json
// @Param id path string true "Provider UUID"
// @Param request body models.UpdateWorkloadProviderRequest true "Fields to update"
// @Success 200 {object} map[string]interface{} "Updated provider"
// @Failure 400 {object} map[string]string "Invalid provider ID or validation error"
// @Router /api/v1/admin/workload-identity-providers/{id} [put]
func (h *WorkloadIdentityHandler) Update(c *gin.Context) {
	id, ok := h.parseProviderID(c)
	if !ok {
		return
	}

	var req models.UpdateWorkloadProviderRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	updatedBy := h.currentUserID(c)

	provider, err := h.service.UpdateProvider(c.Request.Context(), id, &req, updatedBy)
	if err != nil {
		h.logger.Error("Failed to update workload identity provider", zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, provider)
}

// Delete removes a workload identity provider.
//
// @Summary Delete workload identity provider
// @Description Permanently removes a workload identity provider
// @Tags Workload Identity
// @Produce json
// @Param id path string true "Provider UUID"
// @Success 200 {object} map[string]string "Provider deleted"
// @Failure 400 {object} map[string]string "Invalid provider ID"
// @Failure 500 {object} map[string]string "Internal server error"
// @Router /api/v1/admin/workload-identity-providers/{id} [delete]
func (h *WorkloadIdentityHandler) Delete(c *gin.Context) {
	id, ok := h.parseProviderID(c)
	if !ok {
		return
	}

	if err := h.service.DeleteProvider(c.Request.Context(), id); err != nil {
		h.logger.Error("Failed to delete workload identity provider", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete provider"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Provider deleted"})
}

// Test validates a workload token against a provider configuration.
//
// @Summary Test workload identity provider
// @Description Validates a workload token against the provider configuration without issuing a real token
// @Tags Workload Identity
// @Accept json
// @Produce json
// @Param id path string true "Provider UUID"
// @Param request body models.TestProviderRequest true "Workload token to validate"
// @Success 200 {object} models.TestProviderResponse "Validation result"
// @Failure 400 {object} map[string]string "Validation error"
// @Failure 404 {object} map[string]string "Provider not found"
// @Router /api/v1/admin/workload-identity-providers/{id}/test [post]
func (h *WorkloadIdentityHandler) Test(c *gin.Context) {
	id, ok := h.parseProviderID(c)
	if !ok {
		return
	}

	provider, err := h.service.GetProvider(c.Request.Context(), id)
	if err != nil || provider == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Provider not found"})
		return
	}

	var req models.TestProviderRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Perform a token exchange to validate the token.
	exchangeReq := &models.TokenExchangeRequest{
		GrantType:        "urn:ietf:params:oauth:grant-type:token-exchange",
		SubjectToken:     req.SubjectToken,
		SubjectTokenType: models.SubjectTokenTypeJWT,
	}

	_, err = h.service.ExchangeToken(c.Request.Context(), provider.TenantID, exchangeReq)
	if err != nil {
		c.JSON(http.StatusOK, models.TestProviderResponse{
			Success: false,
			Message: err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, models.TestProviderResponse{
		Success: true,
		Message: "Token validated successfully",
	})
}

// ============================================================
// Helpers
// ============================================================

func (h *WorkloadIdentityHandler) requireTenantID(c *gin.Context) (uuid.UUID, bool) {
	user := middleware.GetCurrentUser(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Not authenticated"})
		return uuid.Nil, false
	}
	return user.TenantID, true
}

func (h *WorkloadIdentityHandler) parseProviderID(c *gin.Context) (uuid.UUID, bool) {
	raw := c.Param("id")
	id, err := uuid.Parse(raw)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid provider id"})
		return uuid.Nil, false
	}
	return id, true
}

func (h *WorkloadIdentityHandler) currentUserID(c *gin.Context) *uuid.UUID {
	user := middleware.GetCurrentUser(c)
	if user == nil {
		return nil
	}
	id := user.ID
	return &id
}
