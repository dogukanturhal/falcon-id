// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/middleware"
	"github.com/dogukanturhal/falcon-id/internal/models"
)

const (
	msgNotAuthenticatedIDP              = "Not authenticated"
	msgEncryptionServiceNotConfigured   = "encryption service not configured"
	msgFailedToEncryptClientSecret      = "Failed to encrypt client secret"      //nolint:gosec // not a credential, this is a route prefix constant
	msgFailedToEncryptLDAPBindPassword  = "Failed to encrypt LDAP bind password" //nolint:gosec // not a credential, this is a route prefix constant
	msgInvalidProviderIDIDP             = "Invalid provider ID"
	msgFailedToGetIdentityProvider      = "Failed to get identity provider"
	msgFailedToRetrieveIdentityProvider = "Failed to retrieve identity provider"
	msgIdentityProviderNotFound         = "Identity provider not found"
)

// ListIdentityProviders lists all identity providers for the tenant
// @Summary List Identity Providers
// @Description List all identity providers configured for the tenant
// @Tags Admin
// @Produce json
// @Security BearerAuth
// @Success 200 {object} []models.IdentityProviderResponse
// @Failure 401 {object} map[string]string
// @Failure 403 {object} map[string]string
// @Router /api/admin/identity-providers [get]
func (h *AdminHandler) ListIdentityProviders(c *gin.Context) {
	currentUser := middleware.GetCurrentUser(c)
	if currentUser == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": msgNotAuthenticatedIDP})
		return
	}

	providers, err := h.idpRepo.List(c.Request.Context(), currentUser.TenantID)
	if err != nil {
		h.logger.Error("Failed to list identity providers", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve identity providers"})
		return
	}

	responses := make([]models.IdentityProviderResponse, len(providers))
	for i, provider := range providers {
		responses[i] = *provider.ToResponse()
	}

	c.JSON(http.StatusOK, gin.H{
		"identity_providers": responses,
		"total":              len(responses),
	})
}

// CreateIdentityProvider creates a new identity provider
// @Summary Create Identity Provider
// @Description Create a new identity provider configuration
// @Tags Admin
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param body body models.CreateIdentityProviderRequest true "Identity provider configuration"
// @Success 201 {object} models.IdentityProviderResponse
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Failure 403 {object} map[string]string
// @Router /api/admin/identity-providers [post]
func (h *AdminHandler) CreateIdentityProvider(c *gin.Context) {
	currentUser := middleware.GetCurrentUser(c)
	if currentUser == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": msgNotAuthenticatedIDP})
		return
	}

	var req models.CreateIdentityProviderRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	req.TenantID = currentUser.TenantID

	provider := &models.IdentityProvider{
		TenantID:           req.TenantID,
		Type:               req.Type,
		Name:               req.Name,
		DisplayName:        req.DisplayName,
		IsEnabled:          req.IsEnabled,
		Priority:           req.Priority,
		ClientID:           req.ClientID,
		AuthorizationURL:   req.AuthorizationURL,
		TokenURL:           req.TokenURL,
		UserInfoURL:        req.UserInfoURL,
		Scopes:             req.Scopes,
		LDAPConfig:         req.LDAPConfig,
		AttributeMapping:   req.AttributeMapping,
		AutoProvisionUsers: req.AutoProvisionUsers,
		DefaultRoleIDs:     req.DefaultRoleIDs,
		CreatedBy:          &currentUser.ID,
	}

	if err := h.encryptProviderClientSecret(c, provider, req.ClientSecret); err != nil {
		return // response already written
	}

	if err := h.encryptProviderLDAPPassword(c, provider.LDAPConfig); err != nil {
		return // response already written
	}

	if err := h.idpRepo.Create(c.Request.Context(), provider); err != nil {
		h.logger.Error("Failed to create identity provider",
			zap.String("name", req.Name),
			zap.Error(err),
		)
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, provider.ToResponse())
}

// encryptProviderClientSecret encrypts the OAuth client secret onto the provider if provided.
// Writes an HTTP error response and returns a non-nil error when encryption is unavailable or fails.
func (h *AdminHandler) encryptProviderClientSecret(c *gin.Context, provider *models.IdentityProvider, clientSecret *string) error {
	if clientSecret == nil || *clientSecret == "" {
		return nil
	}
	if h.encryptionService == nil {
		h.logger.Error(msgEncryptionServiceNotConfigured)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Encryption service not available"})
		return errors.New(msgEncryptionServiceNotConfigured)
	}
	encrypted, err := h.encryptionService.Encrypt(*clientSecret)
	if err != nil {
		h.logger.Error(msgFailedToEncryptClientSecret, zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": msgFailedToEncryptClientSecret})
		return err
	}
	provider.ClientSecretEncrypted = &encrypted
	return nil
}

// encryptProviderLDAPPassword validates and encrypts the LDAP bind password in place.
// Writes an HTTP error response and returns a non-nil error when validation or encryption fails.
func (h *AdminHandler) encryptProviderLDAPPassword(c *gin.Context, cfg *models.LDAPConfig) error {
	if cfg == nil || cfg.BindPassword == "" {
		return nil
	}
	if err := h.validateLDAPConfig(cfg); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return err
	}
	if h.encryptionService == nil {
		h.logger.Error(msgEncryptionServiceNotConfigured)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Encryption service not available"})
		return errors.New(msgEncryptionServiceNotConfigured)
	}
	encrypted, err := h.encryptionService.Encrypt(cfg.BindPassword)
	if err != nil {
		h.logger.Error(msgFailedToEncryptLDAPBindPassword, zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": msgFailedToEncryptLDAPBindPassword})
		return err
	}
	cfg.BindPasswordEncrypted = encrypted
	cfg.BindPassword = ""
	return nil
}

// GetIdentityProvider retrieves a specific identity provider by ID
// @Summary Get Identity Provider
// @Description Get identity provider configuration by ID
// @Tags Admin
// @Produce json
// @Security BearerAuth
// @Param id path string true "Provider ID"
// @Success 200 {object} models.IdentityProviderResponse
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Failure 403 {object} map[string]string
// @Failure 404 {object} map[string]string
// @Router /api/admin/identity-providers/{id} [get]
func (h *AdminHandler) GetIdentityProvider(c *gin.Context) {
	currentUser := middleware.GetCurrentUser(c)
	if currentUser == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": msgNotAuthenticatedIDP})
		return
	}

	idStr := c.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgInvalidProviderIDIDP})
		return
	}

	provider, err := h.idpRepo.GetByID(c.Request.Context(), id)
	if err != nil {
		h.logger.Error(msgFailedToGetIdentityProvider, zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": msgFailedToRetrieveIdentityProvider})
		return
	}

	if provider == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": msgIdentityProviderNotFound})
		return
	}

	if provider.TenantID != currentUser.TenantID {
		c.JSON(http.StatusNotFound, gin.H{"error": msgIdentityProviderNotFound})
		return
	}

	c.JSON(http.StatusOK, provider.ToResponse())
}

// UpdateIdentityProvider updates an identity provider
// @Summary Update Identity Provider
// @Description Update identity provider configuration
// @Tags Admin
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param id path string true "Provider ID"
// @Param body body models.UpdateIdentityProviderRequest true "Updated configuration"
// @Success 200 {object} models.IdentityProviderResponse
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Failure 403 {object} map[string]string
// @Failure 404 {object} map[string]string
// @Router /api/admin/identity-providers/{id} [put]
func (h *AdminHandler) UpdateIdentityProvider(c *gin.Context) {
	currentUser := middleware.GetCurrentUser(c)
	if currentUser == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": msgNotAuthenticatedIDP})
		return
	}

	idStr := c.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgInvalidProviderIDIDP})
		return
	}

	var req models.UpdateIdentityProviderRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	provider, err := h.idpRepo.GetByID(c.Request.Context(), id)
	if err != nil {
		h.logger.Error(msgFailedToGetIdentityProvider, zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": msgFailedToRetrieveIdentityProvider})
		return
	}

	if provider == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": msgIdentityProviderNotFound})
		return
	}

	if provider.TenantID != currentUser.TenantID {
		c.JSON(http.StatusNotFound, gin.H{"error": msgIdentityProviderNotFound})
		return
	}

	updatedProvider := h.applyIdentityProviderUpdates(provider, &req, currentUser)
	if updatedProvider == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to apply updates"})
		return
	}

	if err := h.idpRepo.Update(c.Request.Context(), updatedProvider); err != nil {
		h.logger.Error("Failed to update identity provider",
			zap.String("provider_id", id.String()),
			zap.Error(err),
		)
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, updatedProvider.ToResponse())
}

func (h *AdminHandler) applyIdentityProviderUpdates(
	provider *models.IdentityProvider,
	req *models.UpdateIdentityProviderRequest,
	_ *models.CurrentUser,
) *models.IdentityProvider {
	updated := *provider

	applyIDPScalarFields(&updated, req)

	if err := h.applyIDPClientSecret(&updated, req.ClientSecret); err != nil {
		return nil
	}

	if req.LDAPConfig != nil {
		if err := h.applyIDPLDAPConfig(&updated, provider.LDAPConfig, req.LDAPConfig); err != nil {
			return nil
		}
	}

	return &updated
}

// applyIDPScalarFields copies all non-nil scalar fields from req onto updated.
func applyIDPScalarFields(updated *models.IdentityProvider, req *models.UpdateIdentityProviderRequest) {
	if req.DisplayName != nil {
		updated.DisplayName = *req.DisplayName
	}
	if req.IsEnabled != nil {
		updated.IsEnabled = *req.IsEnabled
	}
	if req.Priority != nil {
		updated.Priority = *req.Priority
	}
	if req.ClientID != nil {
		updated.ClientID = req.ClientID
	}
	if req.AuthorizationURL != nil {
		updated.AuthorizationURL = req.AuthorizationURL
	}
	if req.TokenURL != nil {
		updated.TokenURL = req.TokenURL
	}
	if req.UserInfoURL != nil {
		updated.UserInfoURL = req.UserInfoURL
	}
	if req.Scopes != nil {
		updated.Scopes = req.Scopes
	}
	if req.AttributeMapping != nil {
		updated.AttributeMapping = req.AttributeMapping
	}
	if req.AutoProvisionUsers != nil {
		updated.AutoProvisionUsers = *req.AutoProvisionUsers
	}
	if req.DefaultRoleIDs != nil {
		updated.DefaultRoleIDs = req.DefaultRoleIDs
	}
}

// applyIDPClientSecret encrypts and sets the client secret when a new one is provided.
func (h *AdminHandler) applyIDPClientSecret(updated *models.IdentityProvider, clientSecret *string) error {
	if clientSecret == nil || *clientSecret == "" {
		return nil
	}
	if h.encryptionService == nil {
		h.logger.Error(msgEncryptionServiceNotConfigured)
		return errors.New(msgEncryptionServiceNotConfigured)
	}
	encrypted, err := h.encryptionService.Encrypt(*clientSecret)
	if err != nil {
		h.logger.Error(msgFailedToEncryptClientSecret, zap.Error(err))
		return err
	}
	updated.ClientSecretEncrypted = &encrypted
	return nil
}

// applyIDPLDAPConfig merges the requested LDAP config with the existing one,
// preserving credentials when no new password is supplied, and encrypting when one is.
func (h *AdminHandler) applyIDPLDAPConfig(updated *models.IdentityProvider, existing, requested *models.LDAPConfig) error {
	mergeIDPLDAPCredentials(existing, requested)

	if requested.BindPassword != "" {
		if err := h.validateLDAPConfig(requested); err != nil {
			h.logger.Error("LDAP config validation failed", zap.Error(err))
			return err
		}
		if h.encryptionService != nil {
			encrypted, err := h.encryptionService.Encrypt(requested.BindPassword)
			if err != nil {
				h.logger.Error(msgFailedToEncryptLDAPBindPassword, zap.Error(err))
				return err
			}
			requested.BindPasswordEncrypted = encrypted
			requested.BindPassword = ""
		}
	}

	updated.LDAPConfig = requested
	return nil
}

// mergeIDPLDAPCredentials preserves existing credentials onto requested when no new ones are provided.
func mergeIDPLDAPCredentials(existing, requested *models.LDAPConfig) {
	if existing == nil {
		return
	}
	if requested.BindDN == "" {
		requested.BindDN = existing.BindDN
	}
	if requested.BindPassword == "" {
		requested.BindPasswordEncrypted = existing.BindPasswordEncrypted
		requested.BindPassword = existing.BindPassword
	}
}

// DeleteIdentityProvider deletes an identity provider
// @Summary Delete Identity Provider
// @Description Delete an identity provider configuration
// @Tags Admin
// @Produce json
// @Security BearerAuth
// @Param id path string true "Provider ID"
// @Success 200 {object} map[string]string
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Failure 403 {object} map[string]string
// @Failure 404 {object} map[string]string
// @Router /api/admin/identity-providers/{id} [delete]
func (h *AdminHandler) DeleteIdentityProvider(c *gin.Context) {
	currentUser := middleware.GetCurrentUser(c)
	if currentUser == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": msgNotAuthenticatedIDP})
		return
	}

	idStr := c.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgInvalidProviderIDIDP})
		return
	}

	provider, err := h.idpRepo.GetByID(c.Request.Context(), id)
	if err != nil {
		h.logger.Error(msgFailedToGetIdentityProvider, zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": msgFailedToRetrieveIdentityProvider})
		return
	}

	if provider == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": msgIdentityProviderNotFound})
		return
	}

	if provider.TenantID != currentUser.TenantID {
		c.JSON(http.StatusNotFound, gin.H{"error": msgIdentityProviderNotFound})
		return
	}

	if err := h.idpRepo.Delete(c.Request.Context(), id); err != nil {
		h.logger.Error("Failed to delete identity provider",
			zap.String("provider_id", id.String()),
			zap.Error(err),
		)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete identity provider"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Identity provider deleted successfully"})
}

// TestIdentityProvider tests the connection to an identity provider
// @Summary Test Identity Provider
// @Description Test connection to an identity provider
// @Tags Admin
// @Produce json
// @Security BearerAuth
// @Param id path string true "Provider ID"
// @Success 200 {object} map[string]string
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Failure 403 {object} map[string]string
// @Failure 404 {object} map[string]string
// @Router /api/admin/identity-providers/{id}/test [post]
func (h *AdminHandler) TestIdentityProvider(c *gin.Context) {
	currentUser := middleware.GetCurrentUser(c)
	if currentUser == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": msgNotAuthenticatedIDP})
		return
	}

	idStr := c.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgInvalidProviderIDIDP})
		return
	}

	provider, err := h.idpRepo.GetByID(c.Request.Context(), id)
	if err != nil {
		h.logger.Error(msgFailedToGetIdentityProvider, zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": msgFailedToRetrieveIdentityProvider})
		return
	}

	if provider == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": msgIdentityProviderNotFound})
		return
	}

	if provider.TenantID != currentUser.TenantID {
		c.JSON(http.StatusNotFound, gin.H{"error": msgIdentityProviderNotFound})
		return
	}

	var testErr error
	switch provider.Type {
	case "ldap":
		testErr = h.testLDAPConnectionForProvider(c.Request.Context(), provider)
	case "oauth", "oidc":
		c.JSON(http.StatusOK, gin.H{
			"message": "OAuth/OIDC providers cannot be tested without user authorization",
			"status":  "skipped",
		})
		return
	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": "Unsupported provider type for testing"})
		return
	}

	if testErr != nil {
		h.logger.Error("Identity provider test failed",
			zap.String("provider_id", id.String()),
			zap.String("type", provider.Type),
			zap.Error(testErr),
		)
		c.JSON(http.StatusBadRequest, gin.H{
			"message": "Connection test failed",
			"error":   testErr.Error(),
			"status":  "failed",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Connection test successful",
		"status":  "success",
		"success": true,
	})
}

func (h *AdminHandler) testLDAPConnectionForProvider(ctx context.Context, provider *models.IdentityProvider) error {
	if provider.LDAPConfig == nil {
		return fmt.Errorf("LDAP configuration not found for provider")
	}
	return h.ldapService.TestConnection(ctx, provider.LDAPConfig)
}

// TestLDAPConnection tests LDAP connection with provided configuration
// @Summary Test LDAP Connection
// @Description Test LDAP connection with provided configuration
// @Tags Admin
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param body body models.LDAPConfig true "LDAP configuration"
// @Success 200 {object} map[string]string
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Failure 403 {object} map[string]string
// @Router /api/admin/ldap/test-connection [post]
func (h *AdminHandler) TestLDAPConnection(c *gin.Context) {
	currentUser := middleware.GetCurrentUser(c)
	if currentUser == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": msgNotAuthenticatedIDP})
		return
	}

	// The frontend SDK sends { "ldap_config": { ... } } — unwrap the envelope.
	var req struct {
		LDAPConfig models.LDAPConfig `json:"ldap_config"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if req.LDAPConfig.Host == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "ldap_config.host is required"})
		return
	}

	err := h.ldapService.TestConnection(c.Request.Context(), &req.LDAPConfig)
	if err != nil {
		h.logger.Error("LDAP connection test failed", zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{
			"message": "Connection test failed",
			"error":   err.Error(),
			"status":  "failed",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "LDAP connection test successful",
		"status":  "success",
		"success": true,
	})
}

// SyncLDAPUsers triggers LDAP user synchronization
// @Summary Sync LDAP Users
// @Description Trigger synchronization of users from LDAP
// @Tags Admin
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param id path string true "Provider ID"
// @Param body body models.SyncLDAPRequest false "Sync options"
// @Success 200 {object} models.LDAPSyncResult
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Failure 403 {object} map[string]string
// @Failure 404 {object} map[string]string
// @Router /api/admin/identity-providers/{id}/sync [post]
func (h *AdminHandler) SyncLDAPUsers(c *gin.Context) {
	currentUser := middleware.GetCurrentUser(c)
	if currentUser == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": msgNotAuthenticatedIDP})
		return
	}

	idStr := c.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgInvalidProviderIDIDP})
		return
	}

	var req struct {
		FullSync bool `json:"full_sync"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		req.FullSync = false
	}

	provider, err := h.idpRepo.GetByID(c.Request.Context(), id)
	if err != nil {
		h.logger.Error(msgFailedToGetIdentityProvider, zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": msgFailedToRetrieveIdentityProvider})
		return
	}

	if provider == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": msgIdentityProviderNotFound})
		return
	}

	if provider.TenantID != currentUser.TenantID {
		c.JSON(http.StatusNotFound, gin.H{"error": msgIdentityProviderNotFound})
		return
	}

	if provider.Type != "ldap" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Provider is not an LDAP provider"})
		return
	}

	syncHistory := h.createLDAPSyncHistory(c.Request.Context(), id, provider.Name, currentUser, req.FullSync)

	result, err := h.ldapService.SyncUsers(c.Request.Context(), id, req.FullSync)
	if err != nil {
		h.logger.Error("LDAP sync failed",
			zap.String("provider_id", id.String()),
			zap.Error(err),
		)
		h.updateLDAPSyncHistory(c.Request.Context(), syncHistory, result)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "LDAP sync failed", "result": result})
		return
	}

	groupsCreated, groupsUpdated, groupErr := h.ldapService.SyncGroups(c.Request.Context(), id, currentUser.TenantID)
	if groupErr != nil {
		h.logger.Warn("LDAP group sync failed", zap.Error(groupErr))
		result.Errors = append(result.Errors, "Group sync: "+groupErr.Error())
	} else {
		result.GroupsFound = groupsCreated + groupsUpdated
		result.GroupsCreated = groupsCreated
		result.GroupsUpdated = groupsUpdated
		h.logger.Info("LDAP groups synced", zap.Int("created", groupsCreated), zap.Int("updated", groupsUpdated))
	}

	result.Message = fmt.Sprintf("Synced %d users (created: %d, updated: %d) and %d groups (created: %d, updated: %d)",
		result.UsersFound, result.UsersCreated, result.UsersUpdated,
		result.GroupsFound, result.GroupsCreated, result.GroupsUpdated)

	h.updateLDAPSyncHistory(c.Request.Context(), syncHistory, result)
	c.JSON(http.StatusOK, result)
}

func (h *AdminHandler) createLDAPSyncHistory(
	ctx context.Context,
	providerID uuid.UUID,
	providerName string,
	currentUser *models.CurrentUser,
	fullSync bool,
) *models.LDAPSyncHistory {
	if h.ldapSyncHistoryRepo == nil {
		return nil
	}

	syncType := "manual"
	if fullSync {
		syncType = "full"
	}

	syncHistory := &models.LDAPSyncHistory{
		TenantID:     currentUser.TenantID,
		ProviderID:   providerID,
		ProviderName: providerName,
		SyncType:     syncType,
		Status:       "running",
		StartedAt:    time.Now(),
		TriggeredBy:  &currentUser.ID,
	}

	if err := h.ldapSyncHistoryRepo.Create(ctx, syncHistory); err != nil {
		h.logger.Warn("Failed to create sync history record", zap.Error(err))
		return nil
	}

	return syncHistory
}

func (h *AdminHandler) updateLDAPSyncHistory(ctx context.Context, syncHistory *models.LDAPSyncHistory, result *models.LDAPSyncResult) {
	if syncHistory == nil || h.ldapSyncHistoryRepo == nil {
		return
	}

	completedAt := time.Now()
	syncHistory.CompletedAt = &completedAt
	syncHistory.DurationMs = completedAt.Sub(syncHistory.StartedAt).Milliseconds()
	syncHistory.UsersFound = result.UsersFound
	syncHistory.UsersCreated = result.UsersCreated
	syncHistory.UsersUpdated = result.UsersUpdated
	syncHistory.UsersDisabled = result.UsersDisabled
	syncHistory.GroupsFound = result.GroupsFound
	syncHistory.Errors = result.Errors
	syncHistory.Message = result.Message

	if result.Success {
		syncHistory.Status = "completed"
	} else {
		syncHistory.Status = "failed"
	}

	if updateErr := h.ldapSyncHistoryRepo.Update(ctx, syncHistory); updateErr != nil {
		h.logger.Warn("Failed to update sync history record", zap.Error(updateErr))
	}
}

// GetLDAPSyncHistory retrieves LDAP synchronization history
// @Summary Get LDAP Sync History
// @Description Get LDAP user synchronization history
// @Tags Admin
// @Produce json
// @Security BearerAuth
// @Param id path string true "Provider ID"
// @Param page query int false "Page number" default(1)
// @Param page_size query int false "Page size" default(20)
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Failure 403 {object} map[string]string
// @Failure 404 {object} map[string]string
// @Router /api/admin/identity-providers/{id}/sync-history [get]
func (h *AdminHandler) GetLDAPSyncHistory(c *gin.Context) {
	currentUser := middleware.GetCurrentUser(c)
	if currentUser == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": msgNotAuthenticatedIDP})
		return
	}

	idStr := c.Param("id")
	providerID, err := uuid.Parse(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgInvalidProviderIDIDP})
		return
	}

	if h.ldapSyncHistoryRepo == nil {
		c.JSON(http.StatusOK, gin.H{
			"history": []models.LDAPSyncHistory{},
			"total":   0,
			"page":    1,
			"limit":   20,
		})
		return
	}

	provider, err := h.idpRepo.GetByID(c.Request.Context(), providerID)
	if err != nil {
		h.logger.Error(msgFailedToGetIdentityProvider, zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": msgFailedToRetrieveIdentityProvider})
		return
	}

	if provider == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": msgIdentityProviderNotFound})
		return
	}

	if provider.TenantID != currentUser.TenantID {
		c.JSON(http.StatusNotFound, gin.H{"error": msgIdentityProviderNotFound})
		return
	}

	page := 1
	pageSize := 20

	if p := c.Query("page"); p != "" {
		if parsed, err := strconv.Atoi(p); err == nil && parsed > 0 {
			page = parsed
		}
	}
	if ps := c.Query("page_size"); ps != "" {
		if parsed, err := strconv.Atoi(ps); err == nil && parsed > 0 && parsed <= 100 {
			pageSize = parsed
		}
	}

	offset := (page - 1) * pageSize

	history, total, err := h.ldapSyncHistoryRepo.GetByProviderID(c.Request.Context(), providerID, pageSize, offset)
	if err != nil {
		h.logger.Error("Failed to get LDAP sync history", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve sync history"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"history": history,
		"total":   total,
		"page":    page,
		"limit":   pageSize,
	})
}

// validateLDAPConfig validates LDAP configuration for security issues
func (h *AdminHandler) validateLDAPConfig(cfg *models.LDAPConfig) error {
	env := os.Getenv("GO_ENV")
	// In production/staging, reject default Administrator bind DN — require a dedicated service account
	if env == "production" || env == "staging" {
		if strings.Contains(cfg.BindDN, "CN=Administrator") {
			return fmt.Errorf("LDAP bind DN must use a dedicated service account, not CN=Administrator (required in %s)", env)
		}
	}

	return nil
}
