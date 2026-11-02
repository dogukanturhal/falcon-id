// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/middleware"
	"github.com/dogukanturhal/falcon-id/internal/services"
	"github.com/dogukanturhal/falcon-id/pkg/config"
)

const (
	msgSocialAuthProviderRequired = "Provider is required"
	msgSocialAuthTenantIDRequired = "Tenant ID is required"
	msgSocialAuthNotAuthenticated = "Not authenticated"
)

// SocialAuthHandler is an exported type.
type SocialAuthHandler struct {
	socialAuthService *services.SocialAuthService
	config            *config.Config
	logger            *zap.Logger
}

// NewSocialAuthHandler is an exported function.
// hdrOAuthStateBinding carries the browser-binding secret from the front-end
// app back to the IdP on the callback hop (t-150 / d-064).
//
// A HEADER rather than a query parameter or form field on purpose: the secret
// must not land in an access log, a Referer, or browser history, and every
// caller of this endpoint is a server-side hop that can set headers freely.
// The browser never sends this header itself — it sends the __Host- cookie to
// the front-end app, which reads it and forwards the value here.
const hdrOAuthStateBinding = "X-OAuth-State-Binding"

func NewSocialAuthHandler(
	socialAuthService *services.SocialAuthService,
	cfg *config.Config,
	log *zap.Logger,
) *SocialAuthHandler {
	return &SocialAuthHandler{
		socialAuthService: socialAuthService,
		config:            cfg,
		logger:            log,
	}
}

// GetAuthorizationURL redirects to OAuth provider's authorization URL
// @Summary Get OAuth Authorization URL
// @Description Generate OAuth2 authorization URL for social login
// @Tags Social Auth
// @Accept json
// @Produce json
// @Param provider path string true "Provider name (google, github, microsoft, etc.)"
// @Param redirect_uri query string false "Custom redirect URI"
// @Param state query string false "State parameter for CSRF protection"
// @Success 200 {object} map[string]string
// @Failure 400 {object} map[string]string
// @Failure 404 {object} map[string]string
// @Router /api/v1/auth/social/{provider}/authorize [get]
func (h *SocialAuthHandler) GetAuthorizationURL(c *gin.Context) {
	provider := c.Param("provider")
	if provider == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgSocialAuthProviderRequired})
		return
	}

	tenantID := middleware.GetTenantID(c)
	if tenantID == uuid.Nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgSocialAuthTenantIDRequired})
		return
	}

	redirectURI := c.Query("redirect_uri")

	// Generate a cryptographically secure state parameter for CSRF protection.
	// Any client-supplied state is ignored; the authoritative state is always
	// generated server-side and must be validated in the callback.
	state, stateBinding, err := h.socialAuthService.GenerateOAuthState()
	if err != nil {
		h.logger.Error("Failed to generate OAuth state", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate state parameter"})
		return
	}

	// For now, we'll need to look up the provider by name
	// This is a simplified version - in production, you'd want to cache this
	providerID, err := uuid.Parse(c.Query("provider_id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Valid provider_id query parameter is required"})
		return
	}

	authURL, err := h.socialAuthService.GetAuthorizationURL(c.Request.Context(), tenantID, providerID, redirectURI, state)
	if err != nil {
		h.logger.Error("Failed to generate authorization URL",
			zap.String("provider", provider),
			zap.Error(err),
		)
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// state_binding is the browser-binding secret. The caller MUST store it in
	// a __Host--prefixed cookie and present it back on the callback via the
	// X-OAuth-State-Binding header; a callback that cannot is refused. It is
	// returned here and never put in the authorization URL, because the URL
	// travels through the IdP and the user's address bar.
	c.JSON(http.StatusOK, gin.H{
		"authorization_url": authURL,
		"state":             state,
		"state_binding":     stateBinding,
	})
}

// HandleCallback handles OAuth2 callback from provider
// @Summary Handle OAuth Callback
// @Description Handle OAuth2 callback and authenticate user
// @Tags Social Auth
// @Accept json
// @Produce json
// @Param provider path string true "Provider name"
// @Param code query string true "Authorization code"
// @Param state query string false "State parameter"
// @Success 200 {object} models.LoginResponse
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Router /api/v1/auth/social/{provider}/callback [get]
func (h *SocialAuthHandler) HandleCallback(c *gin.Context) {
	provider := c.Param("provider")
	if provider == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgSocialAuthProviderRequired})
		return
	}

	code := c.Query("code")
	if code == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Authorization code is required"})
		return
	}

	state := c.Query("state")

	// Validate CSRF state parameter against the server-side store.
	if err := h.socialAuthService.ValidateOAuthState(state, c.GetHeader(hdrOAuthStateBinding)); err != nil {
		// Logged with the specific reason so an operator can tell a genuine
		// cross-browser replay from a front-end that has stopped forwarding
		// the header; the response below stays deliberately generic.
		h.logger.Warn("OAuth callback state validation failed",
			zap.String("provider", provider),
			zap.Bool("binding_presented", c.GetHeader(hdrOAuthStateBinding) != ""),
			zap.Error(err),
		)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid or expired state parameter"})
		return
	}

	tenantID := middleware.GetTenantID(c)
	if tenantID == uuid.Nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgSocialAuthTenantIDRequired})
		return
	}

	// Handle OAuth callback
	ipAddress := GetClientIP(c)
	userAgent := c.GetHeader("User-Agent")
	deviceID := c.Query("device_id")

	response, err := h.socialAuthService.HandleCallback(c.Request.Context(), tenantID, provider, code, state, ipAddress, userAgent, deviceID)
	if err != nil {
		if respondIfTenantSuspended(c, err) {
			return
		}
		h.logger.Error("OAuth callback failed",
			zap.String("provider", provider),
			zap.Error(err),
		)
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, response)
}

// ListLinkedAccounts lists all linked social accounts for the authenticated user
// @Summary List Linked Accounts
// @Description Get all social accounts linked to the current user
// @Tags Social Auth
// @Produce json
// @Security BearerAuth
// @Success 200 {object} []models.FederatedAccountResponse
// @Failure 401 {object} map[string]string
// @Router /api/v1/auth/accounts [get]
func (h *SocialAuthHandler) ListLinkedAccounts(c *gin.Context) {
	user := middleware.GetCurrentUser(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": msgSocialAuthNotAuthenticated})
		return
	}

	accounts, err := h.socialAuthService.GetLinkedAccounts(c.Request.Context(), user.ID)
	if err != nil {
		h.logger.Error("Failed to get linked accounts",
			zap.String("user_id", user.ID.String()),
			zap.Error(err),
		)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve linked accounts"})
		return
	}

	// Convert to response format
	responses := make([]interface{}, len(accounts))
	for i, account := range accounts {
		responses[i] = account.ToResponse()
	}

	c.JSON(http.StatusOK, gin.H{
		"accounts": responses,
		"total":    len(responses),
	})
}

// LinkAccount links a social provider account to the authenticated user
// @Summary Link Social Account
// @Description Link a social provider account to the current user
// @Tags Social Auth
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param provider path string true "Provider name"
// @Param body body models.LinkSocialAccountRequest true "Link request"
// @Success 200 {object} map[string]string
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Router /api/v1/auth/accounts/{provider}/link [post]
func (h *SocialAuthHandler) LinkAccount(c *gin.Context) {
	user := middleware.GetCurrentUser(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": msgSocialAuthNotAuthenticated})
		return
	}

	provider := c.Param("provider")
	if provider == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgSocialAuthProviderRequired})
		return
	}

	var req struct {
		Code        string `json:"code" binding:"required"`
		ProviderID  string `json:"provider_id" binding:"required"`
		RedirectURI string `json:"redirect_uri"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	providerID, err := uuid.Parse(req.ProviderID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid provider ID"})
		return
	}

	err = h.socialAuthService.LinkAccount(c.Request.Context(), user.ID, providerID, req.Code, req.RedirectURI)
	if err != nil {
		h.logger.Error("Failed to link account",
			zap.String("user_id", user.ID.String()),
			zap.String("provider", provider),
			zap.Error(err),
		)
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Account linked successfully"})
}

// HandleAppleCallback handles Apple Sign In form_post callback
// Apple returns the authorization code via POST instead of GET redirect.
// @Summary Handle Apple Sign In Callback
// @Description Handle Apple Sign In form_post callback
// @Tags Social Auth
// @Accept application/x-www-form-urlencoded
// @Produce json
// @Param code formData string true "Authorization code"
// @Param state formData string false "State parameter"
// @Param user formData string false "User info (first login only)"
// @Success 200 {object} models.LoginResponse
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Router /api/v1/auth/social/apple/callback [post]
func (h *SocialAuthHandler) HandleAppleCallback(c *gin.Context) {
	code := c.PostForm("code")
	if code == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Authorization code is required"})
		return
	}

	state := c.PostForm("state")

	// Validate CSRF state parameter against the server-side store.
	if err := h.socialAuthService.ValidateOAuthState(state, c.GetHeader(hdrOAuthStateBinding)); err != nil {
		h.logger.Warn("Apple callback state validation failed",
			zap.Bool("binding_presented", c.GetHeader(hdrOAuthStateBinding) != ""),
			zap.Error(err),
		)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid or expired state parameter"})
		return
	}

	tenantID := middleware.GetTenantID(c)
	if tenantID == uuid.Nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgSocialAuthTenantIDRequired})
		return
	}

	ipAddress := GetClientIP(c)
	userAgent := c.GetHeader("User-Agent")
	deviceID := c.Query("device_id")

	response, err := h.socialAuthService.HandleCallback(c.Request.Context(), tenantID, "apple", code, state, ipAddress, userAgent, deviceID)
	if err != nil {
		if respondIfTenantSuspended(c, err) {
			return
		}
		h.logger.Error("Apple callback failed",
			zap.Error(err),
		)
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, response)
}

// UnlinkAccount unlinks a social provider account from the authenticated user
// @Summary Unlink Social Account
// @Description Unlink a social provider account from the current user
// @Tags Social Auth
// @Produce json
// @Security BearerAuth
// @Param provider path string true "Provider name"
// @Success 200 {object} map[string]string
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Router /api/v1/auth/accounts/{provider} [delete]
func (h *SocialAuthHandler) UnlinkAccount(c *gin.Context) {
	user := middleware.GetCurrentUser(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": msgSocialAuthNotAuthenticated})
		return
	}

	provider := c.Param("provider")
	if provider == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgSocialAuthProviderRequired})
		return
	}

	// Get provider_id from query parameter
	providerIDStr := c.Query("provider_id")
	if providerIDStr == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "provider_id query parameter is required"})
		return
	}

	providerID, err := uuid.Parse(providerIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid provider ID"})
		return
	}

	err = h.socialAuthService.UnlinkAccount(c.Request.Context(), user.ID, providerID)
	if err != nil {
		h.logger.Error("Failed to unlink account",
			zap.String("user_id", user.ID.String()),
			zap.String("provider", provider),
			zap.Error(err),
		)
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Account unlinked successfully"})
}
