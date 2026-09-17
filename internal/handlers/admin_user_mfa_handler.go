// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/middleware"
	"github.com/dogukanturhal/falcon-id/internal/models"
)

const (
	msgNotAuthenticatedMFA = "Not authenticated"
	msgInvalidUserIDMFA    = "Invalid user ID"
	msgMFAServiceNotConfig = "MFA service not configured"
)

// SendUserVerificationEmail sends verification email to a user (admin action)
// @Summary Send User Verification Email
// @Description Send email verification to a specific user (admin only)
// @Tags Admin
// @Produce json
// @Security BearerAuth
// @Param id path string true "User ID"
// @Success 200 {object} map[string]string
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Failure 403 {object} map[string]string
// @Failure 404 {object} map[string]string
// @Router /api/admin/users/{id}/send-verification-email [post]
func (h *AdminHandler) SendUserVerificationEmail(c *gin.Context) {
	currentUser := middleware.GetCurrentUser(c)
	if currentUser == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": msgNotAuthenticatedMFA})
		return
	}

	userIDStr := c.Param("id")
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgInvalidUserIDMFA})
		return
	}

	if err := h.validateUserTenantAccess(c.Request.Context(), userID, currentUser); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}

	user, err := h.userService.GetByID(c.Request.Context(), userID)
	if err != nil {
		h.logger.Error("Failed to get user", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve user"})
		return
	}

	if user == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	if user.IsEmailVerified {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Email is already verified"})
		return
	}

	if h.mfaService == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": msgMFAServiceNotConfig})
		return
	}

	if err := h.mfaService.SendVerificationEmail(c.Request.Context(), userID); err != nil {
		h.logger.Error("Failed to send verification email",
			zap.String("user_id", userID.String()),
			zap.Error(err),
		)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to send verification email"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Verification email sent successfully"})
}

// ForceVerifyUserEmail allows admins to manually mark a user's email as verified
// without sending an actual verification email.
// @Summary Force Verify User Email
// @Description Immediately mark a user's email as verified (admin only). No email is sent.
// @Tags Admin
// @Produce json
// @Security BearerAuth
// @Param id path string true "User ID"
// @Success 200 {object} map[string]string
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Failure 403 {object} map[string]string
// @Failure 404 {object} map[string]string
// @Router /api/admin/users/{id}/force-verify-email [post]
func (h *AdminHandler) ForceVerifyUserEmail(c *gin.Context) {
	currentUser := middleware.GetCurrentUser(c)
	if currentUser == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": msgNotAuthenticatedMFA})
		return
	}

	userIDStr := c.Param("id")
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgInvalidUserIDMFA})
		return
	}

	if err := h.validateUserTenantAccess(c.Request.Context(), userID, currentUser); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}

	if err := h.userService.ForceVerifyEmail(c.Request.Context(), userID); err != nil {
		h.logger.Error("Failed to force-verify user email",
			zap.String("user_id", userID.String()),
			zap.Error(err),
		)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to verify email"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Email verified successfully"})
}

// SetUserMFA enables or disables MFA for a user (admin action)
// @Summary Set User MFA Status
// @Description Enable or disable MFA for a specific user (admin only)
// @Tags Admin
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param id path string true "User ID"
// @Param body body models.SetUserMFARequest true "MFA settings"
// @Success 200 {object} map[string]string
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Failure 403 {object} map[string]string
// @Failure 404 {object} map[string]string
// @Router /api/admin/users/{id}/mfa [put]
func (h *AdminHandler) SetUserMFA(c *gin.Context) {
	currentUser := middleware.GetCurrentUser(c)
	if currentUser == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": msgNotAuthenticatedMFA})
		return
	}

	userIDStr := c.Param("id")
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgInvalidUserIDMFA})
		return
	}

	if err := h.validateUserTenantAccess(c.Request.Context(), userID, currentUser); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}

	var req models.SetUserMFARequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	user, err := h.userService.GetByID(c.Request.Context(), userID)
	if err != nil {
		h.logger.Error("Failed to get user", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve user"})
		return
	}

	if user == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	if h.mfaService == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": msgMFAServiceNotConfig})
		return
	}

	if req.Enabled {
		if err := h.mfaService.AdminEnableMFA(c.Request.Context(), userID, req.Method); err != nil {
			h.logger.Error("Failed to enable MFA for user",
				zap.String("user_id", userID.String()),
				zap.Error(err),
			)
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, gin.H{"message": "MFA enabled for user"})
	} else {
		if err := h.mfaService.AdminDisableMFA(c.Request.Context(), userID); err != nil {
			h.logger.Error("Failed to disable MFA for user",
				zap.String("user_id", userID.String()),
				zap.Error(err),
			)
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, gin.H{"message": "MFA disabled for user"})
	}
}

// GetUserMFAStatus returns MFA status for a specific user (admin view)
// @Summary Get User MFA Status
// @Description Get MFA status for a specific user (admin only)
// @Tags Admin
// @Produce json
// @Security BearerAuth
// @Param id path string true "User ID"
// @Success 200 {object} models.MFAStatusResponse
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Failure 403 {object} map[string]string
// @Failure 404 {object} map[string]string
// @Router /api/admin/users/{id}/mfa [get]
func (h *AdminHandler) GetUserMFAStatus(c *gin.Context) {
	currentUser := middleware.GetCurrentUser(c)
	if currentUser == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": msgNotAuthenticatedMFA})
		return
	}

	userIDStr := c.Param("id")
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgInvalidUserIDMFA})
		return
	}

	if err := h.validateUserTenantAccess(c.Request.Context(), userID, currentUser); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}

	if h.mfaService == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": msgMFAServiceNotConfig})
		return
	}

	status, err := h.mfaService.GetMFAStatus(c.Request.Context(), userID)
	if err != nil {
		h.logger.Error("Failed to get MFA status", zap.String("user_id", userID.String()), zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get MFA status"})
		return
	}

	c.JSON(http.StatusOK, status)
}
