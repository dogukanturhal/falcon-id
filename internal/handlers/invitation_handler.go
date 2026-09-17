// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/internal/services"
	"github.com/dogukanturhal/falcon-id/pkg/logger"
	"go.uber.org/zap"
)

const (
	msgInvitationInvalidUserID = "invalid user ID"
)

// InvitationHandler is an exported type.
type InvitationHandler struct {
	invitationService *services.InvitationService
}

// NewInvitationHandler is an exported function.
func NewInvitationHandler(invitationService *services.InvitationService) *InvitationHandler {
	return &InvitationHandler{
		invitationService: invitationService,
	}
}

// ValidateInvitation validates an invitation token
// @Summary Validate Invitation
// @Description Validates an invitation token and returns invitation details
// @Tags Invitation
// @Accept json
// @Produce json
// @Param token query string true "Invitation token"
// @Success 200 {object} models.ValidateInvitationResponse
// @Failure 400 {object} map[string]interface{}
// @Router /api/v1/auth/validate-invitation [get]
func (h *InvitationHandler) ValidateInvitation(c *gin.Context) {
	token := c.Query("token")
	if token == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"error":   "token is required",
		})
		return
	}

	resp, err := h.invitationService.ValidateToken(c.Request.Context(), token)
	if err != nil {
		logger.Error("Failed to validate invitation", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"error":   "failed to validate invitation",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    resp,
	})
}

// SetupAccount completes account setup using an invitation token
// @Summary Setup Account
// @Description Sets up a user account using an invitation token
// @Tags Invitation
// @Accept json
// @Produce json
// @Param request body models.SetupAccountRequest true "Setup account request"
// @Success 200 {object} models.LoginResponse
// @Failure 400 {object} map[string]interface{}
// @Failure 401 {object} map[string]interface{}
// @Router /api/v1/auth/setup-account [post]
func (h *InvitationHandler) SetupAccount(c *gin.Context) {
	var req models.SetupAccountRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"error":   err.Error(),
		})
		return
	}

	// Get client IP
	ipAddress := GetClientIP(c)
	userAgent := c.GetHeader("User-Agent")

	resp, err := h.invitationService.AcceptInvitation(c.Request.Context(), &req, ipAddress, userAgent)
	if err != nil {
		logger.Error("Failed to setup account", zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"error":   err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    resp,
	})
}

// ResendInvitation resends an invitation email
// @Summary Resend Invitation
// @Description Resends an invitation email to a user
// @Tags Invitation
// @Accept json
// @Produce json
// @Param user_id path string true "User ID"
// @Param force query bool false "Force new token generation"
// @Success 200 {object} models.InvitationResponse
// @Failure 400 {object} map[string]interface{}
// @Failure 404 {object} map[string]interface{}
// @Router /api/platform/users/{user_id}/resend-invitation [post]
func (h *InvitationHandler) ResendInvitation(c *gin.Context) {
	userIDStr := c.Param("user_id")
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"error":   msgInvitationInvalidUserID,
		})
		return
	}

	force := c.Query("force") == queryBoolTrue

	resp, err := h.invitationService.ResendInvitation(c.Request.Context(), userID, force)
	if err != nil {
		logger.Error("Failed to resend invitation", zap.Error(err), zap.String("user_id", userIDStr))
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"error":   err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    resp,
	})
}

// RevokeInvitation revokes an invitation
// @Summary Revoke Invitation
// @Description Revokes a pending invitation for a user
// @Tags Invitation
// @Produce json
// @Param user_id path string true "User ID"
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} map[string]interface{}
// @Router /api/platform/users/{user_id}/invitation [delete]
func (h *InvitationHandler) RevokeInvitation(c *gin.Context) {
	userIDStr := c.Param("user_id")
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"error":   msgInvitationInvalidUserID,
		})
		return
	}

	if err := h.invitationService.RevokeInvitation(c.Request.Context(), userID); err != nil {
		logger.Error("Failed to revoke invitation", zap.Error(err), zap.String("user_id", userIDStr))
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"error":   err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "invitation revoked",
	})
}

// GetPendingInvitation gets the pending invitation for a user
// @Summary Get Pending Invitation
// @Description Gets the pending invitation for a user
// @Tags Invitation
// @Produce json
// @Param user_id path string true "User ID"
// @Success 200 {object} models.InvitationResponse
// @Failure 400 {object} map[string]interface{}
// @Failure 404 {object} map[string]interface{}
// @Router /api/platform/users/{user_id}/invitation [get]
func (h *InvitationHandler) GetPendingInvitation(c *gin.Context) {
	userIDStr := c.Param("user_id")
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"error":   msgInvitationInvalidUserID,
		})
		return
	}

	resp, err := h.invitationService.GetPendingInvitation(c.Request.Context(), userID)
	if err != nil {
		logger.Error("Failed to get invitation", zap.Error(err), zap.String("user_id", userIDStr))
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"error":   "failed to get invitation",
		})
		return
	}

	if resp == nil {
		c.JSON(http.StatusNotFound, gin.H{
			"success": false,
			"error":   "no pending invitation found",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    resp,
	})
}

// CreateInvitation creates a new invitation for a user (platform admin only)
// @Summary Create Invitation
// @Description Creates a new invitation for a user
// @Tags Invitation
// @Accept json
// @Produce json
// @Param request body models.CreateInvitationRequest true "Create invitation request"
// @Success 200 {object} models.InvitationResponse
// @Failure 400 {object} map[string]interface{}
// @Router /api/platform/invitations [post]
func (h *InvitationHandler) CreateInvitation(c *gin.Context) {
	var req models.CreateInvitationRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"error":   err.Error(),
		})
		return
	}

	// Default to sending email
	if !req.SendEmail {
		req.SendEmail = true
	}

	resp, _, err := h.invitationService.CreateInvitation(c.Request.Context(), &req)
	if err != nil {
		logger.Error("Failed to create invitation", zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"error":   err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    resp,
	})
}
