// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/middleware"
)

const (
	msgTenantIDNotFound    = "Tenant ID not found in context"
	msgInvalidFlagID       = "invalid flag ID"
	msgFeatureFlagNotFound = "feature flag not found"
)

// FeatureFlagHandler handles feature flag endpoints
type FeatureFlagHandler struct {
	logger *zap.Logger
	mu     sync.RWMutex
	flags  map[uuid.UUID][]FeatureFlag // tenant-scoped in-memory store
}

// NewFeatureFlagHandler creates a new feature flag handler
func NewFeatureFlagHandler(logger *zap.Logger) *FeatureFlagHandler {
	return &FeatureFlagHandler{
		logger: logger,
		flags:  make(map[uuid.UUID][]FeatureFlag),
	}
}

// FeatureFlag represents a tenant-scoped feature flag
type FeatureFlag struct {
	ID           uuid.UUID `json:"id"`
	TenantID     uuid.UUID `json:"tenant_id"`
	Key          string    `json:"key"`
	Name         string    `json:"name"`
	Description  string    `json:"description"`
	Type         string    `json:"type"`
	DefaultValue bool      `json:"default_value"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// CreateFeatureFlagRequest represents create request
type CreateFeatureFlagRequest struct {
	Key          string `json:"key" binding:"required"`
	Name         string `json:"name" binding:"required"`
	Description  string `json:"description"`
	Type         string `json:"type" binding:"required"`
	DefaultValue bool   `json:"default_value"`
}

// UpdateFeatureFlagRequest represents update request
type UpdateFeatureFlagRequest struct {
	Name         *string `json:"name"`
	Description  *string `json:"description"`
	DefaultValue *bool   `json:"default_value"`
}

// defaultFlags returns the set of default feature flags for a new tenant.
func defaultFlags(tenantID uuid.UUID) []FeatureFlag {
	now := time.Now()
	return []FeatureFlag{
		{ID: uuid.New(), TenantID: tenantID, Key: "email_integration", Name: "Email Integration", Description: "Enable email integration features", Type: "release", DefaultValue: true, CreatedAt: now, UpdatedAt: now},
		{ID: uuid.New(), TenantID: tenantID, Key: "ad_integration", Name: "Active Directory Integration", Description: "Enable AD/LDAP integration features", Type: "release", DefaultValue: true, CreatedAt: now, UpdatedAt: now},
		{ID: uuid.New(), TenantID: tenantID, Key: "mfa_enabled", Name: "Multi-Factor Authentication", Description: "Enable MFA features", Type: "release", DefaultValue: true, CreatedAt: now, UpdatedAt: now},
		{ID: uuid.New(), TenantID: tenantID, Key: "sso_enabled", Name: "Single Sign-On", Description: "Enable SSO features", Type: "release", DefaultValue: true, CreatedAt: now, UpdatedAt: now},
		{ID: uuid.New(), TenantID: tenantID, Key: "api_access", Name: "API Access", Description: "Enable API access for external integrations", Type: "permission", DefaultValue: true, CreatedAt: now, UpdatedAt: now},
		{ID: uuid.New(), TenantID: tenantID, Key: "audit_logs", Name: "Audit Logs", Description: "Enable audit logging features", Type: "ops", DefaultValue: true, CreatedAt: now, UpdatedAt: now},
		{ID: uuid.New(), TenantID: tenantID, Key: "custom_branding", Name: "Custom Branding", Description: "Enable custom branding and theming", Type: "release", DefaultValue: false, CreatedAt: now, UpdatedAt: now},
		{ID: uuid.New(), TenantID: tenantID, Key: "advanced_reporting", Name: "Advanced Reporting", Description: "Enable advanced reporting features", Type: "release", DefaultValue: false, CreatedAt: now, UpdatedAt: now},
	}
}

// getTenantFlags returns the feature flags for a tenant, initializing defaults if needed.
func (h *FeatureFlagHandler) getTenantFlags(tenantID uuid.UUID) []FeatureFlag {
	h.mu.RLock()
	flags, ok := h.flags[tenantID]
	h.mu.RUnlock()
	if ok {
		return flags
	}

	// Initialize with defaults
	h.mu.Lock()
	defer h.mu.Unlock()
	// Double-check after acquiring write lock
	if flags, ok := h.flags[tenantID]; ok {
		return flags
	}
	h.flags[tenantID] = defaultFlags(tenantID)
	return h.flags[tenantID]
}

// List returns all feature flags for the caller's tenant
// @Summary List feature flags
// @Tags FeatureFlags
// @Security BearerAuth
// @Success 200 {object} map[string]interface{}
// @Router /api/admin/feature-flags [get]
func (h *FeatureFlagHandler) List(c *gin.Context) {
	tenantID := middleware.GetTenantID(c)
	if tenantID == uuid.Nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgTenantIDNotFound})
		return
	}

	flags := h.getTenantFlags(tenantID)
	c.JSON(http.StatusOK, gin.H{"flags": flags})
}

// GetByID returns a feature flag by ID
// @Summary Get feature flag
// @Tags FeatureFlags
// @Security BearerAuth
// @Param id path string true "Flag ID"
// @Success 200 {object} FeatureFlag
// @Router /api/admin/feature-flags/{id} [get]
func (h *FeatureFlagHandler) GetByID(c *gin.Context) {
	tenantID := middleware.GetTenantID(c)
	if tenantID == uuid.Nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgTenantIDNotFound})
		return
	}

	id := c.Param("id")
	flagID, err := uuid.Parse(id)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgInvalidFlagID})
		return
	}

	flags := h.getTenantFlags(tenantID)
	for _, flag := range flags {
		if flag.ID == flagID {
			c.JSON(http.StatusOK, flag)
			return
		}
	}

	c.JSON(http.StatusNotFound, gin.H{"error": msgFeatureFlagNotFound})
}

// Create creates a new feature flag
// @Summary Create feature flag
// @Tags FeatureFlags
// @Security BearerAuth
// @Param request body CreateFeatureFlagRequest true "Create request"
// @Success 201 {object} FeatureFlag
// @Router /api/admin/feature-flags [post]
func (h *FeatureFlagHandler) Create(c *gin.Context) {
	tenantID := middleware.GetTenantID(c)
	if tenantID == uuid.Nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgTenantIDNotFound})
		return
	}

	var req CreateFeatureFlagRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	// Ensure tenant has initialized flags
	if _, ok := h.flags[tenantID]; !ok {
		h.flags[tenantID] = defaultFlags(tenantID)
	}

	// Check for duplicate key within this tenant
	for _, flag := range h.flags[tenantID] {
		if flag.Key == req.Key {
			c.JSON(http.StatusConflict, gin.H{"error": "feature flag with this key already exists"})
			return
		}
	}

	newFlag := FeatureFlag{
		ID:           uuid.New(),
		TenantID:     tenantID,
		Key:          req.Key,
		Name:         req.Name,
		Description:  req.Description,
		Type:         req.Type,
		DefaultValue: req.DefaultValue,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}

	h.flags[tenantID] = append(h.flags[tenantID], newFlag)
	c.JSON(http.StatusCreated, newFlag)
}

// Update updates a feature flag
// @Summary Update feature flag
// @Tags FeatureFlags
// @Security BearerAuth
// @Param id path string true "Flag ID"
// @Param request body UpdateFeatureFlagRequest true "Update request"
// @Success 200 {object} FeatureFlag
// @Router /api/admin/feature-flags/{id} [put]
func (h *FeatureFlagHandler) Update(c *gin.Context) {
	tenantID := middleware.GetTenantID(c)
	if tenantID == uuid.Nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgTenantIDNotFound})
		return
	}

	id := c.Param("id")
	flagID, err := uuid.Parse(id)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgInvalidFlagID})
		return
	}

	var req UpdateFeatureFlagRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	if _, ok := h.flags[tenantID]; !ok {
		h.flags[tenantID] = defaultFlags(tenantID)
	}

	for i, flag := range h.flags[tenantID] {
		if flag.ID == flagID {
			applyFeatureFlagUpdates(&h.flags[tenantID][i], &req)
			c.JSON(http.StatusOK, h.flags[tenantID][i])
			return
		}
	}

	c.JSON(http.StatusNotFound, gin.H{"error": msgFeatureFlagNotFound})
}

// applyFeatureFlagUpdates merges non-nil request fields onto the flag.
func applyFeatureFlagUpdates(flag *FeatureFlag, req *UpdateFeatureFlagRequest) {
	if req.Name != nil {
		flag.Name = *req.Name
	}
	if req.Description != nil {
		flag.Description = *req.Description
	}
	if req.DefaultValue != nil {
		flag.DefaultValue = *req.DefaultValue
	}
	flag.UpdatedAt = time.Now()
}

// Delete deletes a feature flag
// @Summary Delete feature flag
// @Tags FeatureFlags
// @Security BearerAuth
// @Param id path string true "Flag ID"
// @Success 204
// @Router /api/admin/feature-flags/{id} [delete]
func (h *FeatureFlagHandler) Delete(c *gin.Context) {
	tenantID := middleware.GetTenantID(c)
	if tenantID == uuid.Nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgTenantIDNotFound})
		return
	}

	id := c.Param("id")
	flagID, err := uuid.Parse(id)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgInvalidFlagID})
		return
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	// Ensure tenant has initialized flags
	if _, ok := h.flags[tenantID]; !ok {
		h.flags[tenantID] = defaultFlags(tenantID)
	}

	for i, flag := range h.flags[tenantID] {
		if flag.ID == flagID {
			h.flags[tenantID] = append(h.flags[tenantID][:i], h.flags[tenantID][i+1:]...)
			c.Status(http.StatusNoContent)
			return
		}
	}

	c.JSON(http.StatusNotFound, gin.H{"error": msgFeatureFlagNotFound})
}
