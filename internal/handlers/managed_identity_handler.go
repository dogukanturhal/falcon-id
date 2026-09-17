// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"context"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

// managedIdentityService is the service interface used by ManagedIdentityHandler.
type managedIdentityService interface {
	CreateBootstrapToken(ctx context.Context, req *models.CreateBootstrapTokenRequest, createdBy uuid.UUID) (*models.BootstrapToken, string, error)
	ListBootstrapTokens(ctx context.Context, serviceSlug string) ([]models.BootstrapToken, error)
	DeleteBootstrapToken(ctx context.Context, id uuid.UUID) error
	RegisterWithBootstrapToken(ctx context.Context, req *models.BootstrapTokenRequest) (*models.BootstrapRegistrationResponse, error)
	Heartbeat(ctx context.Context, req *models.ServiceHeartbeatRequest) error
	AutoSuspendStaleServices(ctx context.Context) (int64, error)
}

// ManagedIdentityHandler exposes HTTP endpoints for the managed service identity lifecycle.
type ManagedIdentityHandler struct {
	svc    managedIdentityService
	logger *zap.Logger
}

// NewManagedIdentityHandler creates a new ManagedIdentityHandler.
func NewManagedIdentityHandler(svc managedIdentityService, log *zap.Logger) *ManagedIdentityHandler {
	if log == nil {
		log = zap.NewNop()
	}
	return &ManagedIdentityHandler{svc: svc, logger: log}
}

// CreateBootstrapToken handles POST /api/v1/admin/managed-identities/bootstrap-tokens.
//
// @Summary Create managed identity bootstrap token
// @Description Creates a one-time bootstrap token for service self-registration; raw token shown once
// @Tags Managed Identities
// @Accept json
// @Produce json
// @Param request body models.CreateBootstrapTokenRequest true "Bootstrap token configuration"
// @Success 201 {object} models.BootstrapTokenResponse "Created bootstrap token with raw token value"
// @Failure 400 {object} map[string]string "Validation error"
// @Failure 401 {object} map[string]string "Not authenticated"
// @Failure 500 {object} map[string]string "Internal server error"
// @Router /api/v1/admin/managed-identities/bootstrap-tokens [post]
func (h *ManagedIdentityHandler) CreateBootstrapToken(c *gin.Context) {
	var req models.CreateBootstrapTokenRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	currentUser, ok := RequireCurrentUser(c)
	if !ok || currentUser == nil {
		return
	}

	token, rawToken, err := h.svc.CreateBootstrapToken(c.Request.Context(), &req, currentUser.ID)
	if err != nil {
		h.logger.Error("ManagedIdentityHandler.CreateBootstrapToken failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create bootstrap token"})
		return
	}

	resp := token.ToResponse()
	resp.RawToken = rawToken // included only in this response

	c.JSON(http.StatusCreated, resp)
}

// ListBootstrapTokens handles GET /api/v1/admin/managed-identities/bootstrap-tokens.
//
// @Summary List managed identity bootstrap tokens
// @Description Returns all bootstrap tokens, optionally filtered by service slug
// @Tags Managed Identities
// @Produce json
// @Param service_slug query string false "Filter by service slug"
// @Success 200 {object} map[string]interface{} "List of bootstrap tokens"
// @Failure 500 {object} map[string]string "Internal server error"
// @Router /api/v1/admin/managed-identities/bootstrap-tokens [get]
func (h *ManagedIdentityHandler) ListBootstrapTokens(c *gin.Context) {
	slug := c.Query("service_slug")

	tokens, err := h.svc.ListBootstrapTokens(c.Request.Context(), slug)
	if err != nil {
		h.logger.Error("ManagedIdentityHandler.ListBootstrapTokens failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list bootstrap tokens"})
		return
	}

	responses := make([]models.BootstrapTokenResponse, len(tokens))
	for i, t := range tokens {
		responses[i] = t.ToResponse()
	}

	c.JSON(http.StatusOK, gin.H{"bootstrap_tokens": responses, "total": len(responses)})
}

// DeleteBootstrapToken handles DELETE /api/v1/admin/managed-identities/bootstrap-tokens/:id.
//
// @Summary Delete managed identity bootstrap token
// @Description Deletes a bootstrap token, preventing any further service self-registration with it
// @Tags Managed Identities
// @Produce json
// @Param id path string true "Bootstrap token UUID"
// @Success 200 {object} map[string]string "Bootstrap token deleted"
// @Failure 400 {object} map[string]string "Invalid token ID"
// @Failure 500 {object} map[string]string "Internal server error"
// @Router /api/v1/admin/managed-identities/bootstrap-tokens/{id} [delete]
func (h *ManagedIdentityHandler) DeleteBootstrapToken(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid bootstrap token ID"})
		return
	}

	if err := h.svc.DeleteBootstrapToken(c.Request.Context(), id); err != nil {
		h.logger.Error("ManagedIdentityHandler.DeleteBootstrapToken failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to delete bootstrap token"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "bootstrap token deleted"})
}

// Register handles POST /api/v1/services/register.
//
// @Summary Register managed service
// @Description Called by a managed service at startup to self-register using a one-time bootstrap token
// @Tags Managed Identities
// @Accept json
// @Produce json
// @Param request body models.BootstrapTokenRequest true "Service registration request with bootstrap token"
// @Success 200 {object} models.BootstrapRegistrationResponse "Registration result with service credentials"
// @Failure 401 {object} map[string]string "Invalid or expired bootstrap token"
// @Router /api/v1/services/register [post]
func (h *ManagedIdentityHandler) Register(c *gin.Context) {
	var req models.BootstrapTokenRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	resp, err := h.svc.RegisterWithBootstrapToken(c.Request.Context(), &req)
	if err != nil {
		h.logger.Warn("ManagedIdentityHandler.Register failed",
			zap.String("service_slug", req.ServiceSlug),
			zap.Error(err),
		)
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, resp)
}

// Heartbeat handles POST /api/v1/services/heartbeat.
//
// @Summary Managed service heartbeat
// @Description Called by a managed service to signal it is alive and update last-seen timestamp
// @Tags Managed Identities
// @Accept json
// @Produce json
// @Param request body models.ServiceHeartbeatRequest true "Heartbeat payload"
// @Success 200 {object} map[string]string "Heartbeat acknowledged"
// @Failure 400 {object} map[string]string "Validation error"
// @Failure 500 {object} map[string]string "Heartbeat failed"
// @Router /api/v1/services/heartbeat [post]
func (h *ManagedIdentityHandler) Heartbeat(c *gin.Context) {
	var req models.ServiceHeartbeatRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := h.svc.Heartbeat(c.Request.Context(), &req); err != nil {
		h.logger.Warn("ManagedIdentityHandler.Heartbeat failed",
			zap.String("service_slug", req.ServiceSlug),
			zap.Error(err),
		)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "heartbeat failed"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

// TriggerAutoSuspend handles POST /api/v1/admin/managed-identities/auto-suspend.
//
// @Summary Trigger managed identity auto-suspend
// @Description Admin endpoint to manually trigger the stale service suspension background job
// @Tags Managed Identities
// @Produce json
// @Success 200 {object} map[string]int64 "Number of services suspended"
// @Failure 500 {object} map[string]string "Auto-suspend failed"
// @Router /api/v1/admin/managed-identities/auto-suspend [post]
func (h *ManagedIdentityHandler) TriggerAutoSuspend(c *gin.Context) {
	suspended, err := h.svc.AutoSuspendStaleServices(c.Request.Context())
	if err != nil {
		h.logger.Error("ManagedIdentityHandler.TriggerAutoSuspend failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "auto-suspend failed"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"suspended_count": suspended})
}
