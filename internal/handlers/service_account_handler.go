// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/middleware"
	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/internal/services"
)

const (
	msgServiceAccountNotAuthenticated = "Not authenticated"
	msgServiceAccountInvalidID        = "Invalid service account ID"
)

// ServiceAccountHandler is an exported type.
type ServiceAccountHandler struct {
	saService *services.ServiceAccountService
	logger    *zap.Logger
}

// NewServiceAccountHandler is an exported function.
func NewServiceAccountHandler(saService *services.ServiceAccountService, logger *zap.Logger) *ServiceAccountHandler {
	return &ServiceAccountHandler{
		saService: saService,
		logger:    logger,
	}
}

// ListServiceAccounts lists all service accounts for the tenant
// @Summary List Service Accounts
// @Description Get all service accounts for the tenant
// @Tags Service Accounts
// @Produce json
// @Security BearerAuth
// @Success 200 {array} models.ServiceAccountResponse
// @Failure 401 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /api/admin/service-accounts [get]
func (h *ServiceAccountHandler) ListServiceAccounts(c *gin.Context) {
	currentUser := middleware.GetCurrentUser(c)
	if currentUser == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": msgServiceAccountNotAuthenticated})
		return
	}

	accounts, err := h.saService.List(c.Request.Context(), currentUser.TenantID)
	if err != nil {
		h.logger.Error("Failed to list service accounts", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list service accounts"})
		return
	}

	responses := make([]*models.ServiceAccountResponse, len(accounts))
	for i, sa := range accounts {
		responses[i] = sa.ToResponse()
	}

	c.JSON(http.StatusOK, responses)
}

// GetServiceAccount retrieves a single service account
// @Summary Get Service Account
// @Description Get a specific service account by ID
// @Tags Service Accounts
// @Produce json
// @Security BearerAuth
// @Param id path string true "Service Account ID"
// @Success 200 {object} models.ServiceAccountResponse
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Failure 404 {object} map[string]string
// @Router /api/admin/service-accounts/{id} [get]
func (h *ServiceAccountHandler) GetServiceAccount(c *gin.Context) {
	currentUser := middleware.GetCurrentUser(c)
	if currentUser == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": msgServiceAccountNotAuthenticated})
		return
	}

	idStr := c.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgServiceAccountInvalidID})
		return
	}

	sa, err := h.saService.GetByID(c.Request.Context(), id)
	if err != nil {
		h.logger.Error("Failed to get service account", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get service account"})
		return
	}

	if sa == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Service account not found"})
		return
	}

	// Verify tenant ownership
	if sa.TenantID != currentUser.TenantID {
		c.JSON(http.StatusNotFound, gin.H{"error": "Service account not found"})
		return
	}

	c.JSON(http.StatusOK, sa.ToResponse())
}

// CreateServiceAccount creates a new service account
// @Summary Create Service Account
// @Description Create a new service account for machine-to-machine authentication
// @Tags Service Accounts
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param body body models.CreateServiceAccountRequest true "Service account settings"
// @Success 201 {object} models.ServiceAccountCreatedResponse
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Router /api/admin/service-accounts [post]
func (h *ServiceAccountHandler) CreateServiceAccount(c *gin.Context) {
	currentUser := middleware.GetCurrentUser(c)
	if currentUser == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": msgServiceAccountNotAuthenticated})
		return
	}

	var req models.CreateServiceAccountRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	response, err := h.saService.Create(c.Request.Context(), currentUser.TenantID, currentUser.ID, &req)
	if err != nil {
		h.logger.Error("Failed to create service account", zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, response)
}

// UpdateServiceAccount updates an existing service account
// @Summary Update Service Account
// @Description Update a service account
// @Tags Service Accounts
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param id path string true "Service Account ID"
// @Param body body models.UpdateServiceAccountRequest true "Service account settings"
// @Success 200 {object} models.ServiceAccountResponse
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Failure 404 {object} map[string]string
// @Router /api/admin/service-accounts/{id} [put]
func (h *ServiceAccountHandler) UpdateServiceAccount(c *gin.Context) {
	currentUser := middleware.GetCurrentUser(c)
	if currentUser == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": msgServiceAccountNotAuthenticated})
		return
	}

	idStr := c.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgServiceAccountInvalidID})
		return
	}

	var req models.UpdateServiceAccountRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	sa, err := h.saService.Update(c.Request.Context(), currentUser.TenantID, id, &req)
	if err != nil {
		h.logger.Error("Failed to update service account", zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, sa.ToResponse())
}

// DeleteServiceAccount permanently deletes a service account
// @Summary Delete Service Account
// @Description Permanently delete a service account
// @Tags Service Accounts
// @Produce json
// @Security BearerAuth
// @Param id path string true "Service Account ID"
// @Success 204
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Failure 404 {object} map[string]string
// @Router /api/admin/service-accounts/{id} [delete]
func (h *ServiceAccountHandler) DeleteServiceAccount(c *gin.Context) {
	currentUser := middleware.GetCurrentUser(c)
	if currentUser == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": msgServiceAccountNotAuthenticated})
		return
	}

	idStr := c.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgServiceAccountInvalidID})
		return
	}

	if err := h.saService.Delete(c.Request.Context(), currentUser.TenantID, id); err != nil {
		h.logger.Error("Failed to delete service account", zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.Status(http.StatusNoContent)
}

// RegenerateSecret generates a new client secret for a service account
// @Summary Regenerate Client Secret
// @Description Generate a new client secret (revokes all existing tokens)
// @Tags Service Accounts
// @Produce json
// @Security BearerAuth
// @Param id path string true "Service Account ID"
// @Success 200 {object} models.ServiceAccountCreatedResponse
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Failure 404 {object} map[string]string
// @Router /api/admin/service-accounts/{id}/regenerate-secret [post]
func (h *ServiceAccountHandler) RegenerateSecret(c *gin.Context) {
	currentUser := middleware.GetCurrentUser(c)
	if currentUser == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": msgServiceAccountNotAuthenticated})
		return
	}

	idStr := c.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgServiceAccountInvalidID})
		return
	}

	response, err := h.saService.RegenerateSecret(c.Request.Context(), currentUser.TenantID, id)
	if err != nil {
		h.logger.Error("Failed to regenerate client secret", zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, response)
}

// RevokeTokens revokes all tokens for a service account
// @Summary Revoke All Tokens
// @Description Revoke all active tokens for a service account
// @Tags Service Accounts
// @Produce json
// @Security BearerAuth
// @Param id path string true "Service Account ID"
// @Success 200 {object} map[string]string
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Failure 404 {object} map[string]string
// @Router /api/admin/service-accounts/{id}/revoke-tokens [post]
func (h *ServiceAccountHandler) RevokeTokens(c *gin.Context) {
	currentUser := middleware.GetCurrentUser(c)
	if currentUser == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": msgServiceAccountNotAuthenticated})
		return
	}

	idStr := c.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgServiceAccountInvalidID})
		return
	}

	if err := h.saService.RevokeAllTokens(c.Request.Context(), currentUser.TenantID, id); err != nil {
		h.logger.Error("Failed to revoke tokens", zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "All tokens revoked successfully"})
}

// TokenEndpoint handles OAuth2 client_credentials grant
// @Summary Get Access Token (OAuth2 Client Credentials)
// @Description Exchange client credentials for an access token
// @Tags Service Accounts
// @Accept application/x-www-form-urlencoded
// @Accept json
// @Produce json
// @Param grant_type formData string true "Grant type" Enums(client_credentials)
// @Param client_id formData string true "Client ID"
// @Param client_secret formData string true "Client Secret"
// @Param scope formData string false "Scopes (space-separated)"
// @Success 200 {object} models.ServiceAccountTokenResponse
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Router /oauth/token [post]
func (h *ServiceAccountHandler) TokenEndpoint(c *gin.Context) {
	// Try to bind from form data first, then JSON
	var req models.ServiceAccountTokenRequest
	if err := c.ShouldBind(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_request",
			"error_description": err.Error(),
		})
		return
	}

	if req.GrantType != grantTypeClientCredentials {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "unsupported_grant_type",
			"error_description": "Only client_credentials grant type is supported",
		})
		return
	}

	clientIP := GetClientIP(c)
	response, err := h.saService.Authenticate(c.Request.Context(), req.ClientID, req.ClientSecret, clientIP)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error":             "invalid_client",
			"error_description": "Authentication failed",
		})
		return
	}

	c.JSON(http.StatusOK, response)
}
