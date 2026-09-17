// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/dogukanturhal/falcon-id/internal/middleware"
	"github.com/dogukanturhal/falcon-id/internal/services"
)

const (
	msgProviderNotFound  = "Provider not found"
	msgInvalidProviderID = "Invalid provider ID"
)

// ADSyncHandler handles AD synchronization API endpoints
type ADSyncHandler struct {
	syncService *services.ADSyncService
}

// NewADSyncHandler creates a new AD sync handler
func NewADSyncHandler(syncService *services.ADSyncService) *ADSyncHandler {
	return &ADSyncHandler{
		syncService: syncService,
	}
}

// TriggerSync handles manual sync trigger requests
// POST /api/admin/ad-sync/trigger
func (h *ADSyncHandler) TriggerSync(c *gin.Context) {
	var req services.TriggerSyncRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "Invalid request",
			"details": err.Error(),
		})
		return
	}

	// Verify provider belongs to caller's tenant
	tenantID := middleware.GetTenantID(c)
	if err := h.syncService.ValidateProviderTenant(c.Request.Context(), req.ProviderID, tenantID); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": msgProviderNotFound})
		return
	}

	// Get user ID from context if available
	if userID, exists := c.Get("user_id"); exists {
		if uid, ok := userID.(uuid.UUID); ok {
			req.TriggeredBy = &uid
		}
	}

	response, err := h.syncService.TriggerSync(c.Request.Context(), req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "Sync failed",
			"details": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, response)
}

// GetSyncStatus returns the current sync status for a provider
// GET /api/admin/ad-sync/status/:provider_id
func (h *ADSyncHandler) GetSyncStatus(c *gin.Context) {
	providerIDStr := c.Param("provider_id")
	providerID, err := uuid.Parse(providerIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": msgInvalidProviderID,
		})
		return
	}

	// Verify provider belongs to caller's tenant
	tenantID := middleware.GetTenantID(c)
	if err := h.syncService.ValidateProviderTenant(c.Request.Context(), providerID, tenantID); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": msgProviderNotFound})
		return
	}

	status, err := h.syncService.GetSyncStatus(c.Request.Context(), providerID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "Failed to get sync status",
			"details": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, status)
}

// GetSyncHistory returns paginated sync history for a provider
// GET /api/admin/ad-sync/history/:provider_id
func (h *ADSyncHandler) GetSyncHistory(c *gin.Context) {
	providerIDStr := c.Param("provider_id")
	providerID, err := uuid.Parse(providerIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": msgInvalidProviderID,
		})
		return
	}

	// Verify provider belongs to caller's tenant
	tenantID := middleware.GetTenantID(c)
	if err := h.syncService.ValidateProviderTenant(c.Request.Context(), providerID, tenantID); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": msgProviderNotFound})
		return
	}

	// Parse pagination params
	page := 1
	if p := c.Query("page"); p != "" {
		if parsed, err := strconv.Atoi(p); err == nil && parsed > 0 {
			page = parsed
		}
	}

	limit := 20
	if l := c.Query("limit"); l != "" {
		if parsed, err := strconv.Atoi(l); err == nil && parsed > 0 && parsed <= 100 {
			limit = parsed
		}
	}

	history, err := h.syncService.GetSyncHistory(c.Request.Context(), providerID, page, limit)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "Failed to get sync history",
			"details": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, history)
}

// GetSyncStats returns sync statistics for the current tenant
// GET /api/admin/ad-sync/stats
func (h *ADSyncHandler) GetSyncStats(c *gin.Context) {
	tenantID, exists := c.Get("tenant_id")
	if !exists {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Tenant ID not found in context",
		})
		return
	}

	tid, ok := tenantID.(uuid.UUID)
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid tenant ID",
		})
		return
	}

	stats, err := h.syncService.GetSyncStats(c.Request.Context(), tid)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "Failed to get sync stats",
			"details": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, stats)
}

// GetPendingConflicts returns unresolved sync conflicts
// GET /api/admin/ad-sync/conflicts/:provider_id
func (h *ADSyncHandler) GetPendingConflicts(c *gin.Context) {
	providerIDStr := c.Param("provider_id")
	providerID, err := uuid.Parse(providerIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": msgInvalidProviderID,
		})
		return
	}

	tid := middleware.GetTenantID(c)
	if tid == uuid.Nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Tenant ID not found in context",
		})
		return
	}

	// Verify provider belongs to caller's tenant
	if err := h.syncService.ValidateProviderTenant(c.Request.Context(), providerID, tid); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": msgProviderNotFound})
		return
	}

	conflicts, err := h.syncService.GetPendingConflicts(c.Request.Context(), tid, providerID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "Failed to get conflicts",
			"details": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"conflicts": conflicts,
		"total":     len(conflicts),
	})
}

// ResolveConflict resolves a sync conflict
// POST /api/admin/ad-sync/conflicts/:conflict_id/resolve
func (h *ADSyncHandler) ResolveConflict(c *gin.Context) {
	conflictIDStr := c.Param("conflict_id")
	conflictID, err := uuid.Parse(conflictIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid conflict ID",
		})
		return
	}

	// Verify conflict belongs to caller's tenant
	tenantID := middleware.GetTenantID(c)
	conflictTenantID, err := h.syncService.GetConflictTenantID(c.Request.Context(), conflictID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Conflict not found"})
		return
	}
	if conflictTenantID != tenantID {
		c.JSON(http.StatusNotFound, gin.H{"error": "Conflict not found"})
		return
	}

	var req struct {
		Resolution        string                 `json:"resolution" binding:"required"`
		ResolutionDetails map[string]interface{} `json:"resolution_details,omitempty"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "Invalid request",
			"details": err.Error(),
		})
		return
	}

	// Validate resolution value
	validResolutions := map[string]bool{
		"ad_wins":  true,
		"iam_wins": true,
		"merged":   true,
		"ignored":  true,
	}
	if !validResolutions[req.Resolution] {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid resolution. Must be one of: ad_wins, iam_wins, merged, ignored",
		})
		return
	}

	// Get user ID from context
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "User ID not found in context",
		})
		return
	}
	uid, ok := userID.(uuid.UUID)
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid user ID",
		})
		return
	}

	err = h.syncService.ResolveConflict(c.Request.Context(), conflictID, req.Resolution, req.ResolutionDetails, uid)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "Failed to resolve conflict",
			"details": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Conflict resolved successfully",
	})
}

// IsRunning returns whether a sync is currently in progress
// GET /api/admin/ad-sync/running
func (h *ADSyncHandler) IsRunning(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"is_running": h.syncService.IsRunning(),
	})
}
