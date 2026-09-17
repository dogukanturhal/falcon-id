// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/middleware"
	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/internal/repositories"
	"github.com/dogukanturhal/falcon-id/internal/services"
	"github.com/dogukanturhal/falcon-id/pkg/apierrors"
)

const (
	msgTenantConfigInvalidBody  = "Invalid request body"
	msgTenantConfigProcessValue = "Failed to process configuration value"
	msgTenantConfigUpdateFailed = "Failed to update configuration"
)

// TenantConfigHandler handles admin API endpoints for per-tenant configuration.
type TenantConfigHandler struct {
	configProvider *services.ConfigProvider
	configRepo     *repositories.TenantConfigRepository
	emailService   *services.EmailService
	logger         *zap.Logger
}

// NewTenantConfigHandler creates a new TenantConfigHandler.
func NewTenantConfigHandler(
	configProvider *services.ConfigProvider,
	configRepo *repositories.TenantConfigRepository,
	logger *zap.Logger,
) *TenantConfigHandler {
	return &TenantConfigHandler{
		configProvider: configProvider,
		configRepo:     configRepo,
		logger:         logger,
	}
}

// SetEmailService wires the email service for SMTP testing.
func (h *TenantConfigHandler) SetEmailService(svc *services.EmailService) {
	h.emailService = svc
}

// TestSMTP sends a test email to verify SMTP connectivity.
// POST /api/v1/admin/tenant-config/smtp/test
func (h *TenantConfigHandler) TestSMTP(c *gin.Context) {
	currentUser := middleware.GetCurrentUser(c)
	if currentUser == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	if h.emailService == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "email service not configured"})
		return
	}

	if err := h.emailService.SendTestEmail(c.Request.Context(), currentUser.TenantID, currentUser.Email); err != nil {
		h.logger.Error("SMTP test failed",
			zap.String("tenant_id", currentUser.TenantID.String()),
			zap.Error(err),
		)
		c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("SMTP test failed: %s", err.Error())})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Test email sent successfully", "recipient": currentUser.Email})
}

// ListConfig returns all config keys with their current values (merged defaults + overrides).
// GET /api/admin/tenant-config
func (h *TenantConfigHandler) ListConfig(c *gin.Context) {
	user, ok := RequireCurrentUser(c)
	if !ok {
		return
	}

	overrides, err := h.configRepo.GetAllForTenant(c.Request.Context(), user.TenantID)
	if err != nil {
		h.logger.Error("Failed to get tenant configs", zap.Error(err))
		Error(c, apierrors.Internal("Failed to retrieve tenant configuration"))
		return
	}

	overrideMap := make(map[string]models.TenantConfig)
	for _, o := range overrides {
		overrideMap[o.ConfigKey] = o
	}

	registry := h.configProvider.GetKeyRegistry()
	result := make([]models.TenantConfigResponse, 0, len(registry))

	for _, def := range registry {
		entry := models.TenantConfigResponse{
			ConfigKey:    def.Key,
			ConfigValue:  def.DefaultValue,
			IsOverridden: false,
			Type:         def.Type,
			Category:     def.Category,
			Description:  def.Description,
		}

		if override, exists := overrideMap[def.Key]; exists {
			var w struct {
				V interface{} `json:"v"`
			}
			if err := json.Unmarshal(override.ConfigValue, &w); err == nil {
				if def.Sensitive {
					entry.ConfigValue = "********"
				} else {
					entry.ConfigValue = w.V
				}
			}
			entry.IsOverridden = true
			entry.UpdatedAt = &override.UpdatedAt
			entry.UpdatedBy = override.UpdatedBy
		}

		result = append(result, entry)
	}

	c.JSON(http.StatusOK, gin.H{"configs": result})
}

// UpsertConfig creates or updates a single config key.
// PUT /api/admin/tenant-config
func (h *TenantConfigHandler) UpsertConfig(c *gin.Context) {
	user, ok := RequireCurrentUser(c)
	if !ok {
		return
	}

	var req models.UpsertTenantConfigRequest
	// Fix 6: Return a generic error message instead of leaking ShouldBindJSON internals.
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgTenantConfigInvalidBody})
		return
	}

	if err := h.validateAndUpsert(c, user, req); err != nil {
		return // error already sent
	}

	Success(c, gin.H{"message": "Configuration updated successfully", "config_key": req.ConfigKey})
}

// BulkUpsertConfig creates or updates multiple config keys atomically.
// PUT /api/admin/tenant-config/bulk
func (h *TenantConfigHandler) BulkUpsertConfig(c *gin.Context) {
	user, ok := RequireCurrentUser(c)
	if !ok {
		return
	}

	var req models.BulkUpsertTenantConfigRequest
	// Fix 6: Return a generic error message instead of leaking ShouldBindJSON internals.
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgTenantConfigInvalidBody})
		return
	}

	// Validate all keys before writing
	configs := make([]models.TenantConfig, 0, len(req.Configs))
	for _, item := range req.Configs {
		configValue, err := h.validateConfigValue(item.ConfigKey, item.ConfigValue)
		if err != nil {
			Error(c, apierrors.BadRequest(fmt.Sprintf("Invalid value for %s: %s", item.ConfigKey, err.Error())))
			return
		}

		// Fix 4: Encrypt sensitive values before DB storage.
		configValue, err = h.configProvider.EncryptValueForStorage(item.ConfigKey, configValue)
		if err != nil {
			h.logger.Error("Failed to encrypt config value", zap.Error(err), zap.String("key", item.ConfigKey))
			Error(c, apierrors.Internal(msgTenantConfigProcessValue))
			return
		}

		configs = append(configs, models.TenantConfig{
			TenantID:    user.TenantID,
			ConfigKey:   item.ConfigKey,
			ConfigValue: configValue,
			Description: item.Description,
			UpdatedBy:   &user.ID,
		})
	}

	if err := h.configRepo.BulkUpsert(c.Request.Context(), configs); err != nil {
		h.logger.Error("Failed to bulk upsert tenant configs", zap.Error(err))
		Error(c, apierrors.Internal(msgTenantConfigUpdateFailed))
		return
	}

	// Invalidate caches for all updated keys
	for _, tc := range configs {
		_ = h.configProvider.InvalidateKey(c.Request.Context(), tc.TenantID, tc.ConfigKey)
	}

	Success(c, gin.H{"message": "Configuration updated successfully", "count": len(configs)})
}

// DeleteConfig reverts a config key to its static default.
// DELETE /api/admin/tenant-config/:key
func (h *TenantConfigHandler) DeleteConfig(c *gin.Context) {
	user, ok := RequireCurrentUser(c)
	if !ok {
		return
	}

	configKey := c.Param("key")
	if configKey == "" {
		Error(c, apierrors.BadRequest("Config key is required"))
		return
	}

	registry := h.configProvider.GetKeyRegistry()
	if _, exists := registry[configKey]; !exists {
		Error(c, apierrors.BadRequest("Unknown config key: "+configKey))
		return
	}

	if err := h.configRepo.Delete(c.Request.Context(), user.TenantID, configKey); err != nil {
		h.logger.Error("Failed to delete tenant config", zap.Error(err), zap.String("key", configKey))
		HandleError(c, err)
		return
	}

	_ = h.configProvider.InvalidateKey(c.Request.Context(), user.TenantID, configKey)

	Success(c, gin.H{"message": "Configuration reverted to default", "config_key": configKey})
}

// ListKeys returns all available config keys with their types, defaults, and categories.
// GET /api/admin/tenant-config/keys
func (h *TenantConfigHandler) ListKeys(c *gin.Context) {
	registry := h.configProvider.GetKeyRegistry()

	keys := make([]models.ConfigKeyDefinition, 0, len(registry))
	for _, def := range registry {
		entry := def
		if entry.Sensitive {
			entry.DefaultValue = "********"
		}
		keys = append(keys, entry)
	}

	c.JSON(http.StatusOK, gin.H{"keys": keys})
}

// validateAndUpsert validates a single config request and performs the upsert.
func (h *TenantConfigHandler) validateAndUpsert(c *gin.Context, user *models.CurrentUser, req models.UpsertTenantConfigRequest) error {
	configValue, err := h.validateConfigValue(req.ConfigKey, req.ConfigValue)
	if err != nil {
		Error(c, apierrors.BadRequest(err.Error()))
		return err
	}

	// Fix 4: Encrypt sensitive values before DB storage.
	configValue, err = h.configProvider.EncryptValueForStorage(req.ConfigKey, configValue)
	if err != nil {
		h.logger.Error("Failed to encrypt config value", zap.Error(err), zap.String("key", req.ConfigKey))
		Error(c, apierrors.Internal(msgTenantConfigProcessValue))
		return err
	}

	tc := &models.TenantConfig{
		TenantID:    user.TenantID,
		ConfigKey:   req.ConfigKey,
		ConfigValue: configValue,
		Description: req.Description,
		UpdatedBy:   &user.ID,
	}

	if err := h.configRepo.Upsert(c.Request.Context(), tc); err != nil {
		h.logger.Error("Failed to upsert tenant config", zap.Error(err))
		Error(c, apierrors.Internal(msgTenantConfigUpdateFailed))
		return err
	}

	_ = h.configProvider.InvalidateKey(c.Request.Context(), user.TenantID, req.ConfigKey)
	return nil
}

// GetScopedConfig retrieves a config value with hierarchical override resolution.
// GET /api/admin/tenant-config/scoped?key=X&realm_id=Y&application_id=Z
func (h *TenantConfigHandler) GetScopedConfig(c *gin.Context) {
	user, ok := RequireCurrentUser(c)
	if !ok {
		return
	}

	key := c.Query("key")
	if key == "" {
		Error(c, apierrors.BadRequest("key query parameter is required"))
		return
	}

	registry := h.configProvider.GetKeyRegistry()
	if _, exists := registry[key]; !exists {
		Error(c, apierrors.BadRequest("Unknown config key: "+key))
		return
	}

	realmID, appID, parseErr := parseScopedConfigIDs(c)
	if parseErr != nil {
		Error(c, apierrors.BadRequest(parseErr.Error()))
		return
	}

	val, err := h.configProvider.GetScopedConfig(c.Request.Context(), user.TenantID, realmID, appID, key)
	if err != nil {
		h.logger.Error("Failed to get scoped config", zap.Error(err))
		Error(c, apierrors.Internal("Failed to retrieve scoped configuration"))
		return
	}

	scope := h.resolveConfigScope(c, user.TenantID, realmID, appID, key, val)

	c.JSON(http.StatusOK, gin.H{
		"config_key":    key,
		"config_value":  val,
		"resolved_from": scope,
	})
}

// parseScopedConfigIDs parses the optional realm_id and application_id query parameters.
func parseScopedConfigIDs(c *gin.Context) (realmID *uuid.UUID, appID *uuid.UUID, err error) {
	if raw := c.Query("realm_id"); raw != "" {
		parsed, parseErr := uuid.Parse(raw)
		if parseErr != nil {
			return nil, nil, fmt.Errorf("invalid realm_id")
		}
		realmID = &parsed
	}
	if raw := c.Query("application_id"); raw != "" {
		parsed, parseErr := uuid.Parse(raw)
		if parseErr != nil {
			return nil, nil, fmt.Errorf("invalid application_id")
		}
		appID = &parsed
	}
	return realmID, appID, nil
}

// resolveConfigScope determines the most specific scope that has a value for the key.
func (h *TenantConfigHandler) resolveConfigScope(
	c *gin.Context,
	tenantID uuid.UUID,
	realmID *uuid.UUID,
	appID *uuid.UUID,
	key string,
	val interface{},
) string {
	if val == nil {
		return "static_default"
	}
	scope := "tenant"
	if realmID != nil {
		realmVal, _ := h.configProvider.GetRealmConfig(c.Request.Context(), tenantID, *realmID, key)
		if realmVal != nil {
			scope = "realm"
		}
	}
	if appID != nil {
		appVal, _ := h.configProvider.GetAppConfig(c.Request.Context(), tenantID, *appID, key)
		if appVal != nil {
			scope = "application"
		}
	}
	return scope
}

// UpsertScopedConfig creates or updates a config value at a specific scope.
// PUT /api/admin/tenant-config/scoped
func (h *TenantConfigHandler) UpsertScopedConfig(c *gin.Context) {
	user, ok := RequireCurrentUser(c)
	if !ok {
		return
	}

	var req struct {
		ConfigKey     string  `json:"config_key" binding:"required"`
		ConfigValue   string  `json:"config_value" binding:"required"`
		RealmID       *string `json:"realm_id"`
		ApplicationID *string `json:"application_id"`
		Description   string  `json:"description"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgTenantConfigInvalidBody})
		return
	}

	configValue, err := h.validateConfigValue(req.ConfigKey, req.ConfigValue)
	if err != nil {
		Error(c, apierrors.BadRequest(err.Error()))
		return
	}

	configValue, err = h.configProvider.EncryptValueForStorage(req.ConfigKey, configValue)
	if err != nil {
		h.logger.Error("Failed to encrypt scoped config value", zap.Error(err))
		Error(c, apierrors.Internal(msgTenantConfigProcessValue))
		return
	}

	if err := h.persistScopedConfig(c, user, req.ConfigKey, req.Description, configValue, req.RealmID, req.ApplicationID); err != nil {
		return // response already written
	}

	Success(c, gin.H{"message": "Scoped configuration updated successfully", "config_key": req.ConfigKey})
}

// persistScopedConfig writes the config value to the appropriate scope (realm, app, or tenant).
func (h *TenantConfigHandler) persistScopedConfig(
	c *gin.Context,
	user *models.CurrentUser,
	configKey, description string,
	configValue json.RawMessage,
	rawRealmID *string,
	rawAppID *string,
) error {
	switch {
	case rawRealmID != nil:
		realmID, err := uuid.Parse(*rawRealmID)
		if err != nil {
			Error(c, apierrors.BadRequest("Invalid realm_id"))
			return err
		}
		if err := h.configProvider.SetRealmConfig(c.Request.Context(), user.TenantID, realmID, configKey, configValue, &user.ID); err != nil {
			h.logger.Error("Failed to set realm config", zap.Error(err))
			Error(c, apierrors.Internal("Failed to update realm configuration"))
			return err
		}
	case rawAppID != nil:
		appID, err := uuid.Parse(*rawAppID)
		if err != nil {
			Error(c, apierrors.BadRequest("Invalid application_id"))
			return err
		}
		if err := h.configProvider.SetAppConfig(c.Request.Context(), user.TenantID, appID, configKey, configValue, &user.ID); err != nil {
			h.logger.Error("Failed to set app config", zap.Error(err))
			Error(c, apierrors.Internal("Failed to update application configuration"))
			return err
		}
	default:
		tc := &models.TenantConfig{
			TenantID:    user.TenantID,
			ConfigKey:   configKey,
			ConfigValue: configValue,
			Description: description,
			UpdatedBy:   &user.ID,
		}
		if err := h.configRepo.Upsert(c.Request.Context(), tc); err != nil {
			h.logger.Error("Failed to upsert tenant config", zap.Error(err))
			Error(c, apierrors.Internal(msgTenantConfigUpdateFailed))
			return err
		}
		_ = h.configProvider.InvalidateKey(c.Request.Context(), user.TenantID, configKey)
	}
	return nil
}

// GetInternalSMTPConfig returns the resolved SMTP configuration for a given tenant.
// This endpoint is for internal service-to-service use only and is protected by
// the internal API key middleware.
//
// GET /internal/v1/tenants/:tenant_id/smtp-config
func (h *TenantConfigHandler) GetInternalSMTPConfig(c *gin.Context) {
	tenantIDStr := c.Param("id")
	tenantID, err := uuid.Parse(tenantIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid tenant_id"})
		return
	}

	ctx := c.Request.Context()

	smtpConfig := struct {
		SMTPHost     string `json:"smtp_host"`
		SMTPPort     int    `json:"smtp_port"`
		SMTPUser     string `json:"smtp_user"`
		SMTPPassword string `json:"smtp_password"`
		SMTPFrom     string `json:"smtp_from"`
		SMTPFromName string `json:"smtp_from_name"`
		SMTPUseTLS   bool   `json:"smtp_use_tls"`
	}{
		SMTPHost:     h.configProvider.SMTPHost(ctx, tenantID),
		SMTPPort:     h.configProvider.SMTPPort(ctx, tenantID),
		SMTPUser:     h.configProvider.SMTPUsername(ctx, tenantID),
		SMTPPassword: h.configProvider.SMTPPassword(ctx, tenantID),
		SMTPFrom:     h.configProvider.SMTPFrom(ctx, tenantID),
		SMTPFromName: h.configProvider.SMTPFromName(ctx, tenantID),
		SMTPUseTLS:   h.configProvider.SMTPUseTLS(ctx, tenantID),
	}

	h.logger.Info("Internal SMTP config fetched",
		zap.String("tenant_id", tenantID.String()),
	)

	c.JSON(http.StatusOK, smtpConfig)
}

// validateConfigValue validates a config key and its raw string value, returning the JSON-encoded
// {"v": <typed_value>} representation.
func (h *TenantConfigHandler) validateConfigValue(key, rawValue string) (json.RawMessage, error) {
	registry := h.configProvider.GetKeyRegistry()
	def, exists := registry[key]
	if !exists {
		return nil, fmt.Errorf("unknown config key: %s", key)
	}

	typedValue, err := parseConfigTypedValue(key, rawValue, def.Type)
	if err != nil {
		return nil, err
	}

	wrapper := map[string]interface{}{"v": typedValue}
	data, err := json.Marshal(wrapper)
	if err != nil {
		return nil, fmt.Errorf("failed to encode config value: %w", err)
	}
	return json.RawMessage(data), nil
}

// parseConfigTypedValue converts rawValue to the correct typed value for the given config type.
func parseConfigTypedValue(key, rawValue, configType string) (interface{}, error) {
	switch configType {
	case "duration":
		return parseDurationConfigValue(key, rawValue)
	case "int":
		return parseIntConfigValue(key, rawValue)
	case "string":
		return parseStringConfigValue(key, rawValue)
	case "bool":
		return parseBoolConfigValue(rawValue)
	default:
		return nil, fmt.Errorf("unsupported type: %s", configType)
	}
}

func parseDurationConfigValue(key, rawValue string) (interface{}, error) {
	d, err := time.ParseDuration(rawValue)
	if err != nil {
		return nil, fmt.Errorf("invalid duration format: %s", rawValue)
	}
	if err := validateDurationBounds(key, d); err != nil {
		return nil, err
	}
	return rawValue, nil // store as string for parseability
}

func parseIntConfigValue(key, rawValue string) (interface{}, error) {
	var v int
	if _, err := fmt.Sscanf(rawValue, "%d", &v); err != nil {
		return nil, fmt.Errorf("invalid integer: %s", rawValue)
	}
	if err := validateIntBounds(key, v); err != nil {
		return nil, err
	}
	return v, nil
}

func parseStringConfigValue(key, rawValue string) (interface{}, error) {
	if len(rawValue) > 2048 {
		return nil, fmt.Errorf("string value exceeds maximum length of 2048 characters")
	}
	if err := validateStringFormat(key, rawValue); err != nil {
		return nil, err
	}
	return rawValue, nil
}

func parseBoolConfigValue(rawValue string) (interface{}, error) {
	switch rawValue {
	case queryBoolTrue:
		return true, nil
	case "false":
		return false, nil
	default:
		return nil, fmt.Errorf("invalid bool: %s (must be 'true' or 'false')", rawValue)
	}
}

// validateStringFormat performs format-specific validation for known string config keys.
func validateStringFormat(key, value string) error {
	switch key {
	case "frontend_url":
		u, err := url.ParseRequestURI(value)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return fmt.Errorf("frontend_url must be a valid HTTP or HTTPS URL")
		}
	case "smtp_host":
		// Reject values containing URL schemes, spaces, or path separators.
		if strings.ContainsAny(value, " /\\@") || strings.Contains(value, "://") {
			return fmt.Errorf("smtp_host must be a plain hostname or IP address (no scheme, path, or spaces)")
		}
	}
	return nil
}

// validateDurationBounds enforces min/max bounds on duration-type config keys.
// Fix 5: Added missing bounds for lockout_duration, trusted_device_*, mfa_email_code_ttl,
// and rate_limit_window.
func validateDurationBounds(key string, d time.Duration) error {
	type bound struct{ min, max time.Duration }
	bounds := map[string]bound{
		"access_token_expiry":           {1 * time.Minute, 1 * time.Hour},
		"refresh_token_expiry":          {1 * time.Hour, 90 * 24 * time.Hour},
		"session_expiry":                {5 * time.Minute, 30 * 24 * time.Hour},
		"mfa_totp_period":               {15 * time.Second, 60 * time.Second},
		"lockout_duration":              {1 * time.Minute, 24 * time.Hour},
		"trusted_device_refresh_expiry": {1 * time.Hour, 90 * 24 * time.Hour},
		"trusted_device_session_expiry": {5 * time.Minute, 30 * 24 * time.Hour},
		"mfa_email_code_ttl":            {1 * time.Minute, 15 * time.Minute},
		"rate_limit_window":             {1 * time.Second, 1 * time.Hour},
	}

	if b, ok := bounds[key]; ok {
		if d < b.min || d > b.max {
			return fmt.Errorf("%s must be between %s and %s, got %s", key, b.min, b.max, d)
		}
	}

	return nil
}

// validateIntBounds enforces min/max bounds on integer-type config keys.
// Fix 5: Added missing bounds for rate_limit_requests.
func validateIntBounds(key string, v int) error {
	type bound struct{ min, max int }
	bounds := map[string]bound{
		"mfa_totp_digits":       {6, 8},
		"mfa_backup_code_count": {5, 20},
		"max_login_attempts":    {3, 20},
		"password_min_length":   {8, 128},
		"rate_limit_requests":   {10, 10000},
	}

	if b, ok := bounds[key]; ok {
		if v < b.min || v > b.max {
			return fmt.Errorf("%s must be between %d and %d, got %d", key, b.min, b.max, v)
		}
	}

	return nil
}
