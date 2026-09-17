// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/middleware"
	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/internal/repositories"
	"github.com/dogukanturhal/falcon-id/pkg/crypto"
)

var errSettingsEncryptionUnavailable = errors.New("encryption service not available")

const (
	msgSettingsTenantIDNotFound  = "Tenant ID not found in context"
	msgSettingsFailedGetSettings = "Failed to get settings"
)

// SettingsHandler handles IAM settings management
type SettingsHandler struct {
	settingsRepo      *repositories.SettingsRepository
	encryptionService *crypto.EncryptionService
	logger            *zap.Logger
}

// NewSettingsHandler creates a new settings handler.
// encryptionService may be nil in dev when ENCRYPTION_KEY is not set;
// LDAP bind password updates will be rejected in that case.
func NewSettingsHandler(settingsRepo *repositories.SettingsRepository, encryptionService *crypto.EncryptionService, logger *zap.Logger) *SettingsHandler {
	return &SettingsHandler{
		settingsRepo:      settingsRepo,
		encryptionService: encryptionService,
		logger:            logger,
	}
}

// GetSettings returns the current IAM settings.
//
// Deprecated: The hr_ldap_* settings in this handler are legacy. New features should use
// the per-tenant dynamic ConfigProvider and identity_providers table for IDP configuration.
// These settings remain functional for backward compatibility.
// @Summary Get IAM settings
// @Description Get the current IAM service settings
// @Tags settings
// @Security BearerAuth
// @Produce json
// @Success 200 {object} models.GetIAMSettingsResponse
// @Failure 500 {object} map[string]string
// @Router /api/admin/settings [get]
func (h *SettingsHandler) GetSettings(c *gin.Context) {
	tenantID := middleware.GetTenantID(c)
	if tenantID == uuid.Nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgSettingsTenantIDNotFound})
		return
	}

	settings, err := h.settingsRepo.GetByTenantID(c.Request.Context(), tenantID)
	if err != nil {
		h.logger.Error(msgSettingsFailedGetSettings, zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": msgSettingsFailedGetSettings})
		return
	}

	c.JSON(http.StatusOK, settings.ToResponse())
}

// UpdateSettings updates the IAM settings
// @Summary Update IAM settings
// @Description Update the IAM service settings
// @Tags settings
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param request body models.UpdateIAMSettingsRequest true "Settings update"
// @Success 200 {object} models.GetIAMSettingsResponse
// @Failure 400 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /api/admin/settings [put]
func (h *SettingsHandler) UpdateSettings(c *gin.Context) {
	var req models.UpdateIAMSettingsRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.logger.Error("Invalid request", zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}

	tenantID := middleware.GetTenantID(c)
	if tenantID == uuid.Nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgSettingsTenantIDNotFound})
		return
	}

	current, err := h.settingsRepo.GetByTenantID(c.Request.Context(), tenantID)
	if err != nil {
		h.logger.Error("Failed to get current settings", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get current settings"})
		return
	}

	if err := h.applySettingsUpdates(c, current, &req); err != nil {
		return // response already written
	}

	if userID, exists := c.Get("user_id"); exists {
		uid := userID.(uuid.UUID)
		current.UpdatedBy = &uid
	}

	if err := h.settingsRepo.Upsert(c.Request.Context(), current); err != nil {
		h.logger.Error("Failed to update settings", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update settings"})
		return
	}

	h.logger.Info("Settings updated", zap.String("tenant_id", tenantID.String()))
	c.JSON(http.StatusOK, current.ToResponse())
}

// applySettingsUpdates applies the non-nil fields from req to current.
// Returns an error (and writes the HTTP response) when encryption is needed but unavailable.
func (h *SettingsHandler) applySettingsUpdates(c *gin.Context, current *models.IAMSettings, req *models.UpdateIAMSettingsRequest) error {
	if req.HRLDAPEnabled != nil {
		current.HRLDAPEnabled = *req.HRLDAPEnabled
	}
	if req.HRLDAPServer != nil {
		current.HRLDAPServer = *req.HRLDAPServer
	}
	if req.HRLDAPPort != nil {
		current.HRLDAPPort = *req.HRLDAPPort
	}
	if req.HRLDAPUseTLS != nil {
		current.HRLDAPUseTLS = *req.HRLDAPUseTLS
	}
	if req.HRLDAPBindDN != nil {
		current.HRLDAPBindDN = *req.HRLDAPBindDN
	}
	if req.HRLDAPBindPassword != nil && *req.HRLDAPBindPassword != "" {
		if h.encryptionService == nil {
			h.logger.Error("LDAP bind password update rejected: encryption service not configured (set ENCRYPTION_KEY)")
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": "LDAP password encryption is not configured. Set ENCRYPTION_KEY to enable secure password storage."})
			return errSettingsEncryptionUnavailable
		}
		encrypted, err := h.encryptionService.Encrypt(*req.HRLDAPBindPassword)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to encrypt LDAP password"})
			return err
		}
		current.HRLDAPBindPassword = encrypted
	}
	if req.HRLDAPBaseDN != nil {
		current.HRLDAPBaseDN = *req.HRLDAPBaseDN
	}
	if req.HRLDAPUserFilter != nil {
		current.HRLDAPUserFilter = *req.HRLDAPUserFilter
	}
	if req.HRLDAPGroupBaseDN != nil {
		current.HRLDAPGroupBaseDN = *req.HRLDAPGroupBaseDN
	}
	if req.HRLDAPGroupFilter != nil {
		current.HRLDAPGroupFilter = *req.HRLDAPGroupFilter
	}
	if req.ABACEnabled != nil {
		current.ABACEnabled = *req.ABACEnabled
	}
	if req.ABACFallbackRBAC != nil {
		current.ABACFallbackRBAC = *req.ABACFallbackRBAC
	}
	if req.RoleExpirationEnabled != nil {
		current.RoleExpirationEnabled = *req.RoleExpirationEnabled
	}
	return nil
}

// TestLDAPSettings tests the LDAP connection with the current settings
// @Summary Test LDAP settings
// @Description Test the LDAP connection with the current or provided settings
// @Tags settings
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param request body models.UpdateIAMSettingsRequest false "Settings to test (uses current if not provided)"
// @Success 200 {object} map[string]string
// @Failure 400 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /api/admin/settings/test-ldap [post]
func (h *SettingsHandler) TestLDAPSettings(c *gin.Context) {
	var req models.UpdateIAMSettingsRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		// Body is optional; use current settings if not provided or invalid
		req = models.UpdateIAMSettingsRequest{}
	}

	tenantID := middleware.GetTenantID(c)
	if tenantID == uuid.Nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgSettingsTenantIDNotFound})
		return
	}

	// Get current settings
	settings, err := h.settingsRepo.GetByTenantID(c.Request.Context(), tenantID)
	if err != nil {
		h.logger.Error("Failed to get settings for test", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": msgSettingsFailedGetSettings})
		return
	}

	// Apply test overrides if provided
	if req.HRLDAPServer != nil {
		settings.HRLDAPServer = *req.HRLDAPServer
	}
	if req.HRLDAPPort != nil {
		settings.HRLDAPPort = *req.HRLDAPPort
	}
	if req.HRLDAPUseTLS != nil {
		settings.HRLDAPUseTLS = *req.HRLDAPUseTLS
	}
	if req.HRLDAPBindDN != nil {
		settings.HRLDAPBindDN = *req.HRLDAPBindDN
	}
	if req.HRLDAPBindPassword != nil && *req.HRLDAPBindPassword != "" {
		settings.HRLDAPBindPassword = *req.HRLDAPBindPassword
	}

	// LDAP connection test is not yet implemented
	c.JSON(http.StatusNotImplemented, gin.H{
		"success": false,
		"message": "LDAP connection test not yet implemented",
	})
}
