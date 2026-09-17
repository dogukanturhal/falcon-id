// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/dogukanturhal/falcon-id/internal/middleware"
	"github.com/dogukanturhal/falcon-id/internal/services"
)

const msgNotAuthenticatedRecovery = "not authenticated"

// RecoveryHandler is the self-service surface for account-recovery methods
// (recovery email today). The subject is always taken from the session — never
// the path — so every action is owner-scoped by construction.
type RecoveryHandler struct {
	recoveryService *services.RecoveryService
}

// NewRecoveryHandler constructs the recovery handler.
func NewRecoveryHandler(recoveryService *services.RecoveryService) *RecoveryHandler {
	return &RecoveryHandler{recoveryService: recoveryService}
}

// GetStatus handles GET /users/me/recovery — masked recovery view.
func (h *RecoveryHandler) GetStatus(c *gin.Context) {
	cu := middleware.GetCurrentUser(c)
	if cu == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": msgNotAuthenticatedRecovery})
		return
	}
	status, err := h.recoveryService.GetStatus(c.Request.Context(), cu.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to load recovery settings"})
		return
	}
	c.JSON(http.StatusOK, status)
}

type setRecoveryEmailRequest struct {
	Email string `json:"email" binding:"required"`
}

// SetEmail handles POST /users/me/recovery/email — starts verification of a new
// recovery email (sends a one-time code; does not persist until verified).
func (h *RecoveryHandler) SetEmail(c *gin.Context) {
	cu := middleware.GetCurrentUser(c)
	if cu == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": msgNotAuthenticatedRecovery})
		return
	}
	var req setRecoveryEmailRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "email is required"})
		return
	}
	if err := h.recoveryService.SetRecoveryEmail(c.Request.Context(), cu.ID, req.Email, GetClientIP(c), c.GetHeader("User-Agent")); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"pending": true,
		"message": "We sent a verification code to that address.",
	})
}

type verifyRecoveryEmailRequest struct {
	Code string `json:"code" binding:"required"`
}

// VerifyEmail handles POST /users/me/recovery/email/verify — confirms the code
// and persists the recovery email as verified.
func (h *RecoveryHandler) VerifyEmail(c *gin.Context) {
	cu := middleware.GetCurrentUser(c)
	if cu == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": msgNotAuthenticatedRecovery})
		return
	}
	var req verifyRecoveryEmailRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "code is required"})
		return
	}
	if err := h.recoveryService.VerifyRecoveryEmail(c.Request.Context(), cu.ID, req.Code, GetClientIP(c), c.GetHeader("User-Agent")); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"verified": true})
}

// RemoveEmail handles DELETE /users/me/recovery/email.
func (h *RecoveryHandler) RemoveEmail(c *gin.Context) {
	cu := middleware.GetCurrentUser(c)
	if cu == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": msgNotAuthenticatedRecovery})
		return
	}
	if err := h.recoveryService.RemoveRecoveryEmail(c.Request.Context(), cu.ID, GetClientIP(c), c.GetHeader("User-Agent")); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to remove recovery email"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"removed": true})
}
