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
	msgIDPOverrideNotAuthenticated = "Not authenticated"
)

// IDPTenantOverrideHandler is an exported identifier.
// IDPTenantOverrideHandler exposes CRUD endpoints for per-tenant IDP overrides.
// Mounting point: /api/v1/admin/idp-overrides  (tenant-scoped, auth required)
type IDPTenantOverrideHandler struct {
	service *services.IDPTenantOverrideService
	logger  *zap.Logger
}

// NewIDPTenantOverrideHandler is an exported identifier.
// NewIDPTenantOverrideHandler constructs a new IDPTenantOverrideHandler.
func NewIDPTenantOverrideHandler(
	service *services.IDPTenantOverrideService,
	log *zap.Logger,
) *IDPTenantOverrideHandler {
	return &IDPTenantOverrideHandler{
		service: service,
		logger:  log,
	}
}

// ListOverrides returns all per-tenant overrides for the authenticated tenant.
//
// GET /admin/idp-overrides
func (h *IDPTenantOverrideHandler) ListOverrides(c *gin.Context) {
	currentUser := middleware.GetCurrentUser(c)
	if currentUser == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": msgIDPOverrideNotAuthenticated})
		return
	}

	combos, err := h.service.ListWithProviders(c.Request.Context(), currentUser.TenantID)
	if err != nil {
		h.logger.Error("Failed to list IdP tenant overrides",
			zap.String("tenant_id", currentUser.TenantID.String()),
			zap.Error(err),
		)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list IdP overrides"})
		return
	}

	responses := make([]*models.IDPTenantOverrideResponse, 0, len(combos))
	for _, combo := range combos {
		responses = append(responses, combo.ToResponse())
	}

	c.JSON(http.StatusOK, gin.H{
		"overrides": responses,
		"total":     len(responses),
	})
}

// GetOverride returns a single override for a (tenant, provider) pair.
//
// GET /admin/idp-overrides/:provider_id
func (h *IDPTenantOverrideHandler) GetOverride(c *gin.Context) {
	currentUser := middleware.GetCurrentUser(c)
	if currentUser == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": msgIDPOverrideNotAuthenticated})
		return
	}

	providerID, err := uuid.Parse(c.Param("provider_id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid provider_id"})
		return
	}

	combo, err := h.service.GetOverride(c.Request.Context(), currentUser.TenantID, providerID)
	if err != nil {
		h.logger.Error("Failed to get IdP tenant override",
			zap.String("tenant_id", currentUser.TenantID.String()),
			zap.String("provider_id", providerID.String()),
			zap.Error(err),
		)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get IdP override"})
		return
	}

	if combo == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Provider not found"})
		return
	}

	c.JSON(http.StatusOK, combo.ToResponse())
}

// UpsertOverride creates or updates a per-tenant override.
//
// PUT /admin/idp-overrides
func (h *IDPTenantOverrideHandler) UpsertOverride(c *gin.Context) {
	currentUser := middleware.GetCurrentUser(c)
	if currentUser == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": msgIDPOverrideNotAuthenticated})
		return
	}

	var req models.UpsertIDPTenantOverrideRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	override, err := h.service.Upsert(c.Request.Context(), currentUser.TenantID, &req)
	if err != nil {
		h.logger.Error("Failed to upsert IdP tenant override",
			zap.String("tenant_id", currentUser.TenantID.String()),
			zap.String("provider_id", req.ProviderID.String()),
			zap.Error(err),
		)
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Re-fetch the composite so the response includes resolved effective values.
	combo, err := h.service.GetOverride(c.Request.Context(), currentUser.TenantID, override.ProviderID)
	if err != nil || combo == nil {
		// Fall back to a minimal response using the raw override.
		c.JSON(http.StatusOK, override)
		return
	}

	c.JSON(http.StatusOK, combo.ToResponse())
}

// DeleteOverride removes a per-tenant override by its primary key.
//
// DELETE /admin/idp-overrides/:id
func (h *IDPTenantOverrideHandler) DeleteOverride(c *gin.Context) {
	currentUser := middleware.GetCurrentUser(c)
	if currentUser == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": msgIDPOverrideNotAuthenticated})
		return
	}

	overrideID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid override id"})
		return
	}

	if err := h.service.DeleteOverride(c.Request.Context(), currentUser.TenantID, overrideID); err != nil {
		h.logger.Error("Failed to delete IdP tenant override",
			zap.String("tenant_id", currentUser.TenantID.String()),
			zap.String("override_id", overrideID.String()),
			zap.Error(err),
		)
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Override deleted successfully"})
}

// GetLoginProviders returns the providers that should appear as login buttons on
// the tenant's login page (i.e. enabled + show_as_button = true).
//
// GET /admin/idp-overrides/login-providers
func (h *IDPTenantOverrideHandler) GetLoginProviders(c *gin.Context) {
	currentUser := middleware.GetCurrentUser(c)
	if currentUser == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": msgIDPOverrideNotAuthenticated})
		return
	}

	combos, err := h.service.GetEnabledLoginProvidersWithOverrides(
		c.Request.Context(),
		currentUser.TenantID,
		true, // showButtonOnly
	)
	if err != nil {
		h.logger.Error("Failed to get login providers",
			zap.String("tenant_id", currentUser.TenantID.String()),
			zap.Error(err),
		)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve login providers"})
		return
	}

	responses := make([]*models.IDPTenantOverrideResponse, 0, len(combos))
	for _, combo := range combos {
		responses = append(responses, combo.ToResponse())
	}

	c.JSON(http.StatusOK, gin.H{
		"providers": responses,
		"total":     len(responses),
	})
}
