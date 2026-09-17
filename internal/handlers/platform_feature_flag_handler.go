// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/middleware"
	"github.com/dogukanturhal/falcon-id/internal/models"
)

// platformFeatureFlagRepo is the subset of FeatureFlagRepository used by
// PlatformFeatureFlagHandler.  Defined as an interface so tests can inject a mock.
type platformFeatureFlagRepo interface {
	ListGlobal(ctx context.Context) ([]models.PlatformFeatureFlag, error)
	ListForTenant(ctx context.Context, tenantID uuid.UUID) ([]models.PlatformFeatureFlag, error)
	IsEnabled(ctx context.Context, tenantID uuid.UUID, featureKey string) (bool, error)
	Set(ctx context.Context, tenantID *uuid.UUID, featureKey string, enabled bool, metadata json.RawMessage) error
	Delete(ctx context.Context, tenantID *uuid.UUID, featureKey string) error
}

// PlatformFeatureFlagHandler serves the DB-backed, platform-admin feature-flag API.
// It is distinct from the in-memory FeatureFlagHandler (tenant admin, no persistence).
type PlatformFeatureFlagHandler struct {
	repo   platformFeatureFlagRepo
	logger *zap.Logger
}

// NewPlatformFeatureFlagHandler creates a new PlatformFeatureFlagHandler.
func NewPlatformFeatureFlagHandler(repo platformFeatureFlagRepo, logger *zap.Logger) *PlatformFeatureFlagHandler {
	return &PlatformFeatureFlagHandler{repo: repo, logger: logger}
}

// ListGlobal returns all global (tenant_id IS NULL) feature flags.
//
// GET /api/v1/platform/feature-flags
func (h *PlatformFeatureFlagHandler) ListGlobal(c *gin.Context) {
	flags, err := h.repo.ListGlobal(c.Request.Context())
	if err != nil {
		h.logger.Error("PlatformFeatureFlagHandler.ListGlobal", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list feature flags"})
		return
	}
	if flags == nil {
		flags = []models.PlatformFeatureFlag{}
	}
	c.JSON(http.StatusOK, gin.H{"flags": flags})
}

// ListForTenant returns resolved flags for a specific tenant (tenant overrides + globals).
//
// GET /api/v1/platform/feature-flags/tenant/:tenant_id
func (h *PlatformFeatureFlagHandler) ListForTenant(c *gin.Context) {
	tenantID, err := uuid.Parse(c.Param("tenant_id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid tenant_id"})
		return
	}

	raw, err := h.repo.ListForTenant(c.Request.Context(), tenantID)
	if err != nil {
		h.logger.Error("PlatformFeatureFlagHandler.ListForTenant", zap.Error(err), zap.String("tenant_id", tenantID.String()))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list feature flags"})
		return
	}

	// Deduplicate: for each feature_key take the first row (tenant override wins
	// because the repo orders tenant rows before global rows).
	seen := make(map[string]struct{}, len(raw))
	resolved := make([]models.PlatformFeatureFlag, 0, len(raw))
	for _, ff := range raw {
		if _, ok := seen[ff.FeatureKey]; !ok {
			seen[ff.FeatureKey] = struct{}{}
			resolved = append(resolved, ff)
		}
	}

	c.JSON(http.StatusOK, gin.H{"flags": resolved, "tenant_id": tenantID})
}

// Set creates or updates a feature flag (global or tenant-specific).
//
// PUT /api/v1/platform/feature-flags
func (h *PlatformFeatureFlagHandler) Set(c *gin.Context) {
	var req models.SetFeatureFlagRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := h.repo.Set(c.Request.Context(), req.TenantID, req.FeatureKey, req.Enabled, req.Metadata); err != nil {
		h.logger.Error("PlatformFeatureFlagHandler.Set", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to set feature flag"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"feature_key": req.FeatureKey,
		"enabled":     req.Enabled,
		"tenant_id":   req.TenantID,
	})
}

// DeleteGlobal removes a global feature flag by key.
//
// DELETE /api/v1/platform/feature-flags/:feature_key
func (h *PlatformFeatureFlagHandler) DeleteGlobal(c *gin.Context) {
	featureKey := c.Param("feature_key")
	if featureKey == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "feature_key is required"})
		return
	}

	if err := h.repo.Delete(c.Request.Context(), nil, featureKey); err != nil {
		h.logger.Error("PlatformFeatureFlagHandler.DeleteGlobal", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to delete feature flag"})
		return
	}

	c.Status(http.StatusNoContent)
}

// CheckFeature checks whether a specific feature is enabled for the calling tenant.
// The tenant is resolved from the authenticated JWT (via gin context "tenant_id").
//
// GET /api/v1/features/:feature_key
func (h *PlatformFeatureFlagHandler) CheckFeature(c *gin.Context) {
	featureKey := c.Param("feature_key")
	if featureKey == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "feature_key is required"})
		return
	}

	tenantID := middleware.GetTenantID(c)
	if tenantID == uuid.Nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "tenant context not found"})
		return
	}

	// IsEnabled resolves tenant-specific override first, then global default.
	// When the calling tenant has no override, and no global default exists,
	// it returns false (feature unknown = disabled).
	enabled, err := h.repo.IsEnabled(c.Request.Context(), tenantID, featureKey)
	if err != nil {
		h.logger.Error("PlatformFeatureFlagHandler.CheckFeature", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to check feature flag"})
		return
	}

	// Determine which source supplied the value (informational only).
	source := "global"
	flags, _ := h.repo.ListForTenant(c.Request.Context(), tenantID)
	for _, ff := range flags {
		if ff.FeatureKey == featureKey && ff.TenantID != nil {
			source = "tenant"
			break
		}
	}

	c.JSON(http.StatusOK, models.FeatureFlagCheckResponse{
		FeatureKey: featureKey,
		Enabled:    enabled,
		Source:     source,
	})
}
