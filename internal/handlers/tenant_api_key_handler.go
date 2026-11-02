// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"errors"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/middleware"
	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/internal/services"
)

// TenantAPIKeyHandler serves /api/v1/developer/api-keys (tenant API key
// management) and POST /oauth/token/api-key (the key exchange). The service is
// nil while DEVELOPER_KEYS_ENABLED is off, in which case every route answers
// 404 so the feature is invisible.
type TenantAPIKeyHandler struct {
	svc    *services.TenantAPIKeyService
	logger *zap.Logger
}

// NewTenantAPIKeyHandler builds the handler; svc may be nil.
func NewTenantAPIKeyHandler(svc *services.TenantAPIKeyService, logger *zap.Logger) *TenantAPIKeyHandler {
	return &TenantAPIKeyHandler{svc: svc, logger: logger}
}

// current resolves the signed-in user and rejects the request when developer
// keys are not enabled for the user's tenant.
func (h *TenantAPIKeyHandler) current(c *gin.Context) *models.CurrentUser {
	user := middleware.GetCurrentUser(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return nil
	}
	if h.svc == nil || !h.svc.Enabled(user.TenantID) {
		c.JSON(http.StatusNotFound, gin.H{"error": "api_keys_disabled"})
		return nil
	}
	return user
}

func (h *TenantAPIKeyHandler) writeError(c *gin.Context, op string, err error) {
	var verr *services.APIKeyValidationError
	switch {
	case errors.As(err, &verr):
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "message": verr.Msg})
	case errors.Is(err, services.ErrDeveloperKeysDisabled):
		c.JSON(http.StatusNotFound, gin.H{"error": "api_keys_disabled"})
	case errors.Is(err, services.ErrAPIKeyNotFound):
		c.JSON(http.StatusNotFound, gin.H{"error": "api_key_not_found"})
	case errors.Is(err, services.ErrAPIKeyRoleNotHeld):
		c.JSON(http.StatusForbidden, gin.H{"error": "role_not_held", "message": err.Error()})
	case errors.Is(err, services.ErrAPIKeyCompanyNotHeld):
		c.JSON(http.StatusForbidden, gin.H{"error": "company_not_held", "message": err.Error()})
	case errors.Is(err, services.ErrAPIKeyRoleExcluded):
		c.JSON(http.StatusUnprocessableEntity, gin.H{"error": "role_not_allowed", "message": err.Error()})
	case errors.Is(err, services.ErrAPIKeyCapReached):
		c.JSON(http.StatusConflict, gin.H{"error": "api_key_limit_reached", "limit": services.MaxActiveTenantAPIKeys})
	case errors.Is(err, services.ErrAPIKeyPlanLimit):
		c.JSON(http.StatusPaymentRequired, gin.H{"error": "plan_limit", "message": err.Error()})
	case errors.Is(err, services.ErrAPIKeyNotActive), errors.Is(err, services.ErrAPIKeyCompanySyncPending):
		c.JSON(http.StatusConflict, gin.H{"error": "invalid_state", "message": err.Error()})
	case errors.Is(err, services.ErrAPIKeyPepperMissing):
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "api_keys_unavailable"})
	default:
		h.logger.Error("tenant API key "+op+" failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal_error"})
	}
}

func parseKeyID(c *gin.Context) (uuid.UUID, bool) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "message": "invalid API key id"})
		return uuid.Nil, false
	}
	return id, true
}

// List returns the tenant's API keys (never any secret material).
// @Summary List tenant API keys
// @Tags Developer
// @Security BearerAuth
// @Router /api/v1/developer/api-keys [get]
func (h *TenantAPIKeyHandler) List(c *gin.Context) {
	user := h.current(c)
	if user == nil {
		return
	}
	items, err := h.svc.List(c.Request.Context(), user.TenantID)
	if err != nil {
		h.writeError(c, "list", err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"items": items, "limit": services.MaxActiveTenantAPIKeys})
}

// Get returns one API key.
// @Summary Get tenant API key
// @Tags Developer
// @Security BearerAuth
// @Router /api/v1/developer/api-keys/{id} [get]
func (h *TenantAPIKeyHandler) Get(c *gin.Context) {
	user := h.current(c)
	if user == nil {
		return
	}
	id, ok := parseKeyID(c)
	if !ok {
		return
	}
	item, err := h.svc.Get(c.Request.Context(), user.TenantID, id)
	if err != nil {
		h.writeError(c, "get", err)
		return
	}
	c.JSON(http.StatusOK, item)
}

// Create issues a key. The full key is in this response only.
// @Summary Create tenant API key
// @Tags Developer
// @Security BearerAuth
// @Router /api/v1/developer/api-keys [post]
func (h *TenantAPIKeyHandler) Create(c *gin.Context) {
	user := h.current(c)
	if user == nil {
		return
	}
	var req models.CreateTenantAPIKeyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "message": "malformed JSON body"})
		return
	}
	resp, err := h.svc.Create(c.Request.Context(), user.TenantID, user.ID, &req)
	if err != nil {
		h.writeError(c, "create", err)
		return
	}
	c.Header("Cache-Control", "no-store")
	c.JSON(http.StatusCreated, resp)
}

// Rotate replaces the key's secret; the response carries the new full key.
// @Summary Rotate tenant API key secret
// @Tags Developer
// @Security BearerAuth
// @Router /api/v1/developer/api-keys/{id}/rotate [post]
func (h *TenantAPIKeyHandler) Rotate(c *gin.Context) {
	user := h.current(c)
	if user == nil {
		return
	}
	id, ok := parseKeyID(c)
	if !ok {
		return
	}
	var req models.RotateTenantAPIKeyRequest
	if c.Request.ContentLength != 0 {
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "message": "malformed JSON body"})
			return
		}
	}
	var grace *time.Duration
	if req.GraceHours != nil {
		d := time.Duration(*req.GraceHours) * time.Hour
		grace = &d
	}
	resp, err := h.svc.Rotate(c.Request.Context(), user.TenantID, user.ID, id, grace)
	if err != nil {
		h.writeError(c, "rotate", err)
		return
	}
	c.Header("Cache-Control", "no-store")
	c.JSON(http.StatusOK, resp)
}

// Revoke disables a key immediately.
// @Summary Revoke tenant API key
// @Tags Developer
// @Security BearerAuth
// @Router /api/v1/developer/api-keys/{id}/revoke [post]
func (h *TenantAPIKeyHandler) Revoke(c *gin.Context) {
	user := h.current(c)
	if user == nil {
		return
	}
	id, ok := parseKeyID(c)
	if !ok {
		return
	}
	if err := h.svc.Revoke(c.Request.Context(), user.TenantID, user.ID, id); err != nil {
		h.writeError(c, "revoke", err)
		return
	}
	c.Status(http.StatusNoContent)
}

// Delete removes a revoked key.
// @Summary Delete revoked tenant API key
// @Tags Developer
// @Security BearerAuth
// @Router /api/v1/developer/api-keys/{id} [delete]
func (h *TenantAPIKeyHandler) Delete(c *gin.Context) {
	user := h.current(c)
	if user == nil {
		return
	}
	id, ok := parseKeyID(c)
	if !ok {
		return
	}
	if err := h.svc.Delete(c.Request.Context(), user.TenantID, user.ID, id); err != nil {
		h.writeError(c, "delete", err)
		return
	}
	c.Status(http.StatusNoContent)
}

// TokenEndpoint is POST /oauth/token/api-key: OAuth2 client_credentials with
// client_id=lgk_live_<key_id> and client_secret=<secret>.
// @Summary Exchange an API key for a short-lived access token
// @Tags Developer
// @Accept application/x-www-form-urlencoded
// @Accept json
// @Produce json
// @Router /oauth/token/api-key [post]
func (h *TenantAPIKeyHandler) TokenEndpoint(c *gin.Context) {
	c.Header("Cache-Control", "no-store")
	c.Header("Pragma", "no-cache")
	if h.svc == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "api_keys_disabled"})
		return
	}
	// Only the two formats the rate limiter parses for the per-key bucket.
	if ct := c.ContentType(); ct != "application/x-www-form-urlencoded" && ct != "application/json" {
		c.JSON(http.StatusUnsupportedMediaType, gin.H{
			"error":             "invalid_request",
			"error_description": "content type must be application/x-www-form-urlencoded or application/json",
		})
		return
	}
	var req models.APIKeyTokenRequest
	if err := c.ShouldBind(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "error_description": "malformed request"})
		return
	}
	if req.GrantType != grantTypeClientCredentials {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "unsupported_grant_type",
			"error_description": "Only client_credentials grant type is supported",
		})
		return
	}
	result, err := h.svc.Exchange(c.Request.Context(), req.ClientID, req.ClientSecret, GetClientIP(c))
	switch {
	case err == nil:
		c.JSON(http.StatusOK, result.Response)
	case errors.Is(err, services.ErrAPIKeyIPNotAllowed):
		c.JSON(http.StatusForbidden, gin.H{"error": "access_denied", "error_description": "IP address not allowed"})
	case errors.Is(err, services.ErrAPIKeyPlanLimit):
		c.JSON(http.StatusForbidden, gin.H{"error": "access_denied", "error_description": "plan does not include API access"})
	case errors.Is(err, services.ErrAPIKeyTenantSuspended):
		c.JSON(http.StatusForbidden, gin.H{"error": "access_denied", "error_description": "tenant suspended"})
	case errors.Is(err, services.ErrAPIKeyInvalidClient):
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_client", "error_description": "Authentication failed"})
	default:
		h.logger.Error("API key token exchange failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error"})
	}
}
