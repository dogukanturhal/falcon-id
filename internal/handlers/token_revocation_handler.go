// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/services"
)

const (
	msgTokenRevocationReasonRequired = "reason is required" //nolint:gosec // not a credential, this is a route prefix constant
	msgTokenRevocationFailed         = "revocation failed"  //nolint:gosec // not a credential, this is a route prefix constant
)

// TokenRevocationHandler handles platform-level global token revocation endpoints.
type TokenRevocationHandler struct {
	svc    *services.GlobalTokenRevocationService
	logger *zap.Logger
}

// NewTokenRevocationHandler constructs a TokenRevocationHandler.
func NewTokenRevocationHandler(svc *services.GlobalTokenRevocationService, logger *zap.Logger) *TokenRevocationHandler {
	return &TokenRevocationHandler{svc: svc, logger: logger}
}

// RevokeUserTokens immediately invalidates all tokens for a given user.
//
// POST /api/v1/platform/security/revoke/user/:user_id
func (h *TokenRevocationHandler) RevokeUserTokens(c *gin.Context) {
	userID, err := uuid.Parse(c.Param("user_id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid user_id"})
		return
	}

	var req struct {
		Reason string `json:"reason" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgTokenRevocationReasonRequired})
		return
	}

	initiatedBy := h.extractOperatorID(c)

	if err := h.svc.RevokeByUser(c.Request.Context(), userID, req.Reason, initiatedBy); err != nil {
		h.logger.Error("TokenRevocation.RevokeUserTokens", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": msgTokenRevocationFailed})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "revoked", "scope": "user", "target": userID})
}

// RevokeTenantTokens immediately invalidates all tokens for every user in a tenant.
//
// POST /api/v1/platform/security/revoke/tenant/:tenant_id
func (h *TokenRevocationHandler) RevokeTenantTokens(c *gin.Context) {
	tenantID, err := uuid.Parse(c.Param("tenant_id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid tenant_id"})
		return
	}

	var req struct {
		Reason string `json:"reason" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgTokenRevocationReasonRequired})
		return
	}

	initiatedBy := h.extractOperatorID(c)

	if err := h.svc.RevokeByTenant(c.Request.Context(), tenantID, req.Reason, initiatedBy); err != nil {
		h.logger.Error("TokenRevocation.RevokeTenantTokens", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": msgTokenRevocationFailed})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "revoked", "scope": "tenant", "target": tenantID})
}

// RevokeClientTokens immediately invalidates all tokens issued to an OAuth client.
//
// POST /api/v1/platform/security/revoke/client/:client_id
func (h *TokenRevocationHandler) RevokeClientTokens(c *gin.Context) {
	clientID := c.Param("client_id")
	if clientID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing client_id"})
		return
	}

	var req struct {
		Reason string `json:"reason" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgTokenRevocationReasonRequired})
		return
	}

	initiatedBy := h.extractOperatorID(c)

	if err := h.svc.RevokeByClient(c.Request.Context(), clientID, req.Reason, initiatedBy); err != nil {
		h.logger.Error("TokenRevocation.RevokeClientTokens", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": msgTokenRevocationFailed})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "revoked", "scope": "client", "target": clientID})
}

func (h *TokenRevocationHandler) extractOperatorID(c *gin.Context) uuid.UUID {
	if v, exists := c.Get("user_id"); exists {
		if id, ok := v.(uuid.UUID); ok {
			return id
		}
	}
	return uuid.Nil
}
