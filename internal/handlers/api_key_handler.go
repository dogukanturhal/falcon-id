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
	msgNotAuthenticatedKey = "Not authenticated"
	msgFailedToListAPIKeys = "Failed to list API keys"
	msgInvalidAPIKeyID     = "Invalid API key ID" //nolint:gosec // not a credential, this is a route prefix constant
	msgAPIKeyNotFound      = "API key not found"  //nolint:gosec // not a credential, this is a route prefix constant
)

// APIKeyHandler is an exported type.
type APIKeyHandler struct {
	apiKeyService *services.APIKeyService
	logger        *zap.Logger
}

// NewAPIKeyHandler is an exported function.
func NewAPIKeyHandler(apiKeyService *services.APIKeyService, logger *zap.Logger) *APIKeyHandler {
	return &APIKeyHandler{
		apiKeyService: apiKeyService,
		logger:        logger,
	}
}

// ListAPIKeys lists all API keys for the tenant
// @Summary List API Keys
// @Description Get all API keys for the tenant
// @Tags API Keys
// @Produce json
// @Security BearerAuth
// @Success 200 {array} models.APIKeyResponse
// @Failure 401 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /api/admin/api-keys [get]
func (h *APIKeyHandler) ListAPIKeys(c *gin.Context) {
	currentUser := middleware.GetCurrentUser(c)
	if currentUser == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": msgNotAuthenticatedKey})
		return
	}

	keys, err := h.apiKeyService.List(c.Request.Context(), currentUser.TenantID)
	if err != nil {
		h.logger.Error("Failed to list API keys", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": msgFailedToListAPIKeys})
		return
	}

	responses := make([]*models.APIKeyResponse, len(keys))
	for i, key := range keys {
		responses[i] = key.ToResponse()
	}

	c.JSON(http.StatusOK, responses)
}

// GetAPIKey retrieves a single API key
// @Summary Get API Key
// @Description Get a specific API key by ID
// @Tags API Keys
// @Produce json
// @Security BearerAuth
// @Param id path string true "API Key ID"
// @Success 200 {object} models.APIKeyResponse
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Failure 404 {object} map[string]string
// @Router /api/admin/api-keys/{id} [get]
func (h *APIKeyHandler) GetAPIKey(c *gin.Context) {
	currentUser := middleware.GetCurrentUser(c)
	if currentUser == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": msgNotAuthenticatedKey})
		return
	}

	idStr := c.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgInvalidAPIKeyID})
		return
	}

	key, err := h.apiKeyService.GetByID(c.Request.Context(), id)
	if err != nil {
		h.logger.Error("Failed to get API key", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get API key"})
		return
	}

	if key == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": msgAPIKeyNotFound})
		return
	}

	// Verify tenant ownership
	if key.TenantID != currentUser.TenantID {
		c.JSON(http.StatusNotFound, gin.H{"error": msgAPIKeyNotFound})
		return
	}

	c.JSON(http.StatusOK, key.ToResponse())
}

// CreateAPIKey creates a new API key
// @Summary Create API Key
// @Description Create a new API key for the tenant
// @Tags API Keys
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param body body models.CreateAPIKeyRequest true "API key settings"
// @Success 201 {object} models.APIKeyCreatedResponse
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Router /api/admin/api-keys [post]
func (h *APIKeyHandler) CreateAPIKey(c *gin.Context) {
	currentUser := middleware.GetCurrentUser(c)
	if currentUser == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": msgNotAuthenticatedKey})
		return
	}

	var req models.CreateAPIKeyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	response, err := h.apiKeyService.Create(c.Request.Context(), currentUser.TenantID, currentUser.ID, &req)
	if err != nil {
		h.logger.Error("Failed to create API key", zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, response)
}

// UpdateAPIKey updates an existing API key
// @Summary Update API Key
// @Description Update an API key
// @Tags API Keys
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param id path string true "API Key ID"
// @Param body body models.UpdateAPIKeyRequest true "API key settings"
// @Success 200 {object} models.APIKeyResponse
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Failure 404 {object} map[string]string
// @Router /api/admin/api-keys/{id} [put]
func (h *APIKeyHandler) UpdateAPIKey(c *gin.Context) {
	currentUser := middleware.GetCurrentUser(c)
	if currentUser == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": msgNotAuthenticatedKey})
		return
	}

	idStr := c.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgInvalidAPIKeyID})
		return
	}

	var req models.UpdateAPIKeyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	key, err := h.apiKeyService.Update(c.Request.Context(), currentUser.TenantID, id, &req)
	if err != nil {
		h.logger.Error("Failed to update API key", zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, key.ToResponse())
}

// RevokeAPIKey revokes an API key
// @Summary Revoke API Key
// @Description Revoke an API key (soft delete)
// @Tags API Keys
// @Produce json
// @Security BearerAuth
// @Param id path string true "API Key ID"
// @Success 200 {object} map[string]string
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Failure 404 {object} map[string]string
// @Router /api/admin/api-keys/{id}/revoke [post]
func (h *APIKeyHandler) RevokeAPIKey(c *gin.Context) {
	currentUser := middleware.GetCurrentUser(c)
	if currentUser == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": msgNotAuthenticatedKey})
		return
	}

	idStr := c.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgInvalidAPIKeyID})
		return
	}

	if err := h.apiKeyService.Revoke(c.Request.Context(), currentUser.TenantID, id); err != nil {
		h.logger.Error("Failed to revoke API key", zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "API key revoked successfully"})
}

// DeleteAPIKey permanently deletes an API key
// @Summary Delete API Key
// @Description Permanently delete an API key
// @Tags API Keys
// @Produce json
// @Security BearerAuth
// @Param id path string true "API Key ID"
// @Success 204
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Failure 404 {object} map[string]string
// @Router /api/admin/api-keys/{id} [delete]
func (h *APIKeyHandler) DeleteAPIKey(c *gin.Context) {
	currentUser := middleware.GetCurrentUser(c)
	if currentUser == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": msgNotAuthenticatedKey})
		return
	}

	idStr := c.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgInvalidAPIKeyID})
		return
	}

	if err := h.apiKeyService.Delete(c.Request.Context(), currentUser.TenantID, id); err != nil {
		h.logger.Error("Failed to delete API key", zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.Status(http.StatusNoContent)
}

// RegenerateAPIKey regenerates an API key
// @Summary Regenerate API Key
// @Description Regenerate an API key (creates new key, revokes old)
// @Tags API Keys
// @Produce json
// @Security BearerAuth
// @Param id path string true "API Key ID"
// @Success 201 {object} models.APIKeyCreatedResponse
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Failure 404 {object} map[string]string
// @Router /api/admin/api-keys/{id}/regenerate [post]
func (h *APIKeyHandler) RegenerateAPIKey(c *gin.Context) {
	currentUser := middleware.GetCurrentUser(c)
	if currentUser == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": msgNotAuthenticatedKey})
		return
	}

	idStr := c.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgInvalidAPIKeyID})
		return
	}

	response, err := h.apiKeyService.Regenerate(c.Request.Context(), currentUser.TenantID, id)
	if err != nil {
		h.logger.Error("Failed to regenerate API key", zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, response)
}

// GetAPIKeyUsageStats retrieves usage statistics for an API key
// @Summary Get API Key Usage Stats
// @Description Get usage statistics for an API key
// @Tags API Keys
// @Produce json
// @Security BearerAuth
// @Param id path string true "API Key ID"
// @Success 200 {object} models.APIKeyUsageStats
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Failure 404 {object} map[string]string
// @Router /api/admin/api-keys/{id}/stats [get]
func (h *APIKeyHandler) GetAPIKeyUsageStats(c *gin.Context) {
	currentUser := middleware.GetCurrentUser(c)
	if currentUser == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": msgNotAuthenticatedKey})
		return
	}

	idStr := c.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgInvalidAPIKeyID})
		return
	}

	stats, err := h.apiKeyService.GetUsageStats(c.Request.Context(), currentUser.TenantID, id)
	if err != nil {
		h.logger.Error("Failed to get API key usage stats", zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, stats)
}

// ListMyAPIKeys lists API keys for the current user
// @Summary List My API Keys
// @Description Get all API keys for the current user
// @Tags API Keys
// @Produce json
// @Security BearerAuth
// @Success 200 {array} models.APIKeyResponse
// @Failure 401 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /api/v1/auth/api-keys [get]
func (h *APIKeyHandler) ListMyAPIKeys(c *gin.Context) {
	currentUser := middleware.GetCurrentUser(c)
	if currentUser == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": msgNotAuthenticatedKey})
		return
	}

	keys, err := h.apiKeyService.ListByUser(c.Request.Context(), currentUser.ID)
	if err != nil {
		h.logger.Error("Failed to list user API keys", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": msgFailedToListAPIKeys})
		return
	}

	responses := make([]*models.APIKeyResponse, len(keys))
	for i, key := range keys {
		responses[i] = key.ToResponse()
	}

	c.JSON(http.StatusOK, responses)
}

// CreateMyAPIKey creates a new API key for the current user.
// It delegates to CreateAPIKey since the creation logic is identical;
// the difference is only in the route group (/auth vs /admin).
// @Summary Create My API Key
// @Description Create a new API key for the current user
// @Tags API Keys
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param body body models.CreateAPIKeyRequest true "API key settings"
// @Success 201 {object} models.APIKeyCreatedResponse
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Router /api/v1/auth/api-keys [post]
func (h *APIKeyHandler) CreateMyAPIKey(c *gin.Context) {
	h.CreateAPIKey(c)
}

// RevokeMyAPIKey revokes one of the current user's API keys
// @Summary Revoke My API Key
// @Description Revoke one of the current user's API keys
// @Tags API Keys
// @Produce json
// @Security BearerAuth
// @Param id path string true "API Key ID"
// @Success 200 {object} map[string]string
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Failure 404 {object} map[string]string
// @Router /api/v1/auth/api-keys/{id}/revoke [post]
func (h *APIKeyHandler) RevokeMyAPIKey(c *gin.Context) {
	currentUser := middleware.GetCurrentUser(c)
	if currentUser == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": msgNotAuthenticatedKey})
		return
	}

	idStr := c.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgInvalidAPIKeyID})
		return
	}

	// Verify the key belongs to the user
	key, err := h.apiKeyService.GetByID(c.Request.Context(), id)
	if err != nil || key == nil || key.UserID != currentUser.ID {
		c.JSON(http.StatusNotFound, gin.H{"error": msgAPIKeyNotFound})
		return
	}

	if err := h.apiKeyService.Revoke(c.Request.Context(), currentUser.TenantID, id); err != nil {
		h.logger.Error("Failed to revoke API key", zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "API key revoked successfully"})
}
