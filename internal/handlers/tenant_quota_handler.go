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

// TenantQuotaHandler handles admin HTTP endpoints for per-tenant quota management.
type TenantQuotaHandler struct {
	quotaService *services.TenantQuotaService
	logger       *zap.Logger
}

// NewTenantQuotaHandler creates a new TenantQuotaHandler.
func NewTenantQuotaHandler(quotaService *services.TenantQuotaService, logger *zap.Logger) *TenantQuotaHandler {
	return &TenantQuotaHandler{
		quotaService: quotaService,
		logger:       logger,
	}
}

// ============================================================
// Per-tenant endpoints
// ============================================================

// GetTenantQuota returns the effective quota for a tenant.
//
// GET /api/v1/admin/tenants/:tenant_id/quota
func (h *TenantQuotaHandler) GetTenantQuota(c *gin.Context) {
	tenantID, ok := h.parseTenantID(c)
	if !ok {
		return
	}

	resp, err := h.quotaService.GetQuota(c.Request.Context(), tenantID)
	if err != nil {
		h.logger.Error("Failed to get tenant quota",
			zap.String("tenant_id", tenantID.String()),
			zap.Error(err),
		)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve tenant quota"})
		return
	}

	c.JSON(http.StatusOK, resp)
}

// UpsertTenantQuota creates or replaces the quota for a tenant.
//
// PUT /api/v1/admin/tenants/:tenant_id/quota
func (h *TenantQuotaHandler) UpsertTenantQuota(c *gin.Context) {
	tenantID, ok := h.parseTenantID(c)
	if !ok {
		return
	}

	var req models.CreateQuotaRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	updatedBy := h.currentUserID(c)

	resp, err := h.quotaService.CreateOrUpdateQuota(c.Request.Context(), tenantID, &req, updatedBy)
	if err != nil {
		h.logger.Error("Failed to upsert tenant quota",
			zap.String("tenant_id", tenantID.String()),
			zap.Error(err),
		)
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, resp)
}

// DeleteTenantQuota removes the explicit quota for a tenant, reverting to tier defaults.
//
// DELETE /api/v1/admin/tenants/:tenant_id/quota
func (h *TenantQuotaHandler) DeleteTenantQuota(c *gin.Context) {
	tenantID, ok := h.parseTenantID(c)
	if !ok {
		return
	}

	if err := h.quotaService.DeleteQuota(c.Request.Context(), tenantID); err != nil {
		h.logger.Error("Failed to delete tenant quota",
			zap.String("tenant_id", tenantID.String()),
			zap.Error(err),
		)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete tenant quota"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Tenant quota deleted; defaults will apply"})
}

// ============================================================
// Tier defaults endpoints
// ============================================================

// GetTierDefaults returns all in-memory tier defaults.
//
// GET /api/v1/admin/quota/tiers
func (h *TenantQuotaHandler) GetTierDefaults(c *gin.Context) {
	resp := h.quotaService.GetTierDefaults()
	c.JSON(http.StatusOK, resp)
}

// UpdateTierDefault applies a partial update to a tier's in-memory defaults.
//
// PUT /api/v1/admin/quota/tiers/:tier
func (h *TenantQuotaHandler) UpdateTierDefault(c *gin.Context) {
	tierStr := c.Param("tier")
	tier := models.SubscriptionTier(tierStr)

	var req models.UpdateTierDefaultRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	updated, err := h.quotaService.UpdateTierDefault(tier, &req)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, updated)
}

// ============================================================
// Helpers
// ============================================================

func (h *TenantQuotaHandler) parseTenantID(c *gin.Context) (uuid.UUID, bool) {
	raw := c.Param("tenant_id")
	id, err := uuid.Parse(raw)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid tenant_id"})
		return uuid.Nil, false
	}
	return id, true
}

// currentUserID extracts the authenticated user's ID for audit purposes.
// Returns nil if not available (should not happen in admin routes).
func (h *TenantQuotaHandler) currentUserID(c *gin.Context) *uuid.UUID {
	user := middleware.GetCurrentUser(c)
	if user == nil {
		return nil
	}
	id := user.ID
	return &id
}
