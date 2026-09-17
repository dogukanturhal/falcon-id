// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/middleware"
	"github.com/dogukanturhal/falcon-id/internal/models"
)

const (
	msgNotAuthenticatedSession = "Not authenticated"
	msgRevokedByAdmin          = "revoked by admin"
)

// ListAllSessions lists all active sessions across the tenant
// @Summary List All Sessions
// @Description List all active sessions for the tenant (admin only)
// @Tags Admin
// @Produce json
// @Security BearerAuth
// @Param user_id query string false "Filter by user ID"
// @Success 200 {object} models.SessionListResponse
// @Failure 401 {object} map[string]string
// @Failure 403 {object} map[string]string
// @Router /api/admin/sessions [get]
func (h *AdminHandler) ListAllSessions(c *gin.Context) {
	currentUser := middleware.GetCurrentUser(c)
	if currentUser == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": msgNotAuthenticatedSession})
		return
	}

	userIDStr := c.Query("user_id")

	responses, ok := h.loadSessionResponses(c, currentUser, userIDStr)
	if !ok {
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"sessions": responses,
		"total":    int64(len(responses)),
	})
}

// RevokeSession revokes a specific session by ID
// @Summary Revoke Session
// @Description Revoke a specific session (admin only)
// @Tags Admin
// @Produce json
// @Security BearerAuth
// @Param id path string true "Session ID"
// @Success 200 {object} map[string]string
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Failure 403 {object} map[string]string
// @Router /api/admin/sessions/{id} [delete]
func (h *AdminHandler) RevokeSession(c *gin.Context) {
	currentUser := middleware.GetCurrentUser(c)
	if currentUser == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": msgNotAuthenticatedSession})
		return
	}

	sessionIDStr := c.Param("id")
	sessionID, err := uuid.Parse(sessionIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid session ID"})
		return
	}

	// Verify the session belongs to a user in the current tenant
	session, err := h.sessionRepo.GetByID(c.Request.Context(), sessionID)
	if err != nil || session == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Session not found"})
		return
	}
	if err := h.validateUserTenantAccess(c.Request.Context(), session.UserID, currentUser); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Session not found"})
		return
	}

	err = h.sessionRepo.EndSession(c.Request.Context(), sessionID, msgRevokedByAdmin)
	if err != nil {
		h.logger.Error("Failed to revoke session",
			zap.String("session_id", sessionID.String()),
			zap.Error(err),
		)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to revoke session"})
		return
	}

	if h.tokenBlacklist != nil {
		if err := h.tokenBlacklist.BlacklistSession(c.Request.Context(), sessionID, msgRevokedByAdmin, 24*time.Hour); err != nil {
			h.logger.Warn("Failed to blacklist session in Redis",
				zap.String("session_id", sessionID.String()),
				zap.Error(err),
			)
		}
	}

	c.JSON(http.StatusOK, gin.H{"message": "Session revoked successfully"})
}

// RevokeUserSessions revokes all sessions for a specific user
// @Summary Revoke All User Sessions
// @Description Revoke all active sessions for a user (admin only)
// @Tags Admin
// @Produce json
// @Security BearerAuth
// @Param id path string true "User ID"
// @Success 200 {object} map[string]string
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Failure 403 {object} map[string]string
// @Router /api/admin/users/{id}/sessions [delete]
func (h *AdminHandler) RevokeUserSessions(c *gin.Context) {
	currentUser := middleware.GetCurrentUser(c)
	if currentUser == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": msgNotAuthenticatedSession})
		return
	}

	userIDStr := c.Param("id")
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID"})
		return
	}

	if err := h.validateUserTenantAccess(c.Request.Context(), userID, currentUser); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}

	sessions, _ := h.sessionRepo.GetActiveSessions(c.Request.Context(), userID)

	err = h.sessionRepo.EndAllUserSessions(c.Request.Context(), userID, msgRevokedByAdmin)
	if err != nil {
		h.logger.Error("Failed to revoke user sessions",
			zap.String("user_id", userID.String()),
			zap.Error(err),
		)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to revoke sessions"})
		return
	}

	if h.tokenBlacklist != nil {
		for _, session := range sessions {
			if err := h.tokenBlacklist.BlacklistSession(c.Request.Context(), session.ID, msgRevokedByAdmin, 24*time.Hour); err != nil {
				h.logger.Warn("Failed to blacklist session in Redis",
					zap.String("session_id", session.ID.String()),
					zap.Error(err),
				)
			}
		}
		if err := h.tokenBlacklist.BlacklistUserTokens(c.Request.Context(), userID, msgRevokedByAdmin, 24*time.Hour); err != nil {
			h.logger.Warn("Failed to blacklist user tokens in Redis",
				zap.String("user_id", userID.String()),
				zap.Error(err),
			)
		}
	}

	c.JSON(http.StatusOK, gin.H{"message": "All user sessions revoked successfully"})
}

// loadSessionResponses retrieves session responses filtered by userIDStr (if non-empty).
// Returns (responses, true) on success; writes an error response and returns (nil, false) on failure.
func (h *AdminHandler) loadSessionResponses(c *gin.Context, currentUser *models.CurrentUser, userIDStr string) ([]models.SessionResponse, bool) {
	if userIDStr == "" {
		sessions, err := h.sessionRepo.GetAllActiveSessionsForTenant(c.Request.Context(), currentUser.TenantID)
		if err != nil {
			h.logger.Error("Failed to get sessions", zap.Error(err))
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve sessions"})
			return nil, false
		}
		responses := make([]models.SessionResponse, len(sessions))
		for i, session := range sessions {
			responses[i] = *session.ToResponse(nil)
		}
		return responses, true
	}

	userID, parseErr := uuid.Parse(userIDStr)
	if parseErr != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID"})
		return nil, false
	}

	if err := h.validateUserTenantAccess(c.Request.Context(), userID, currentUser); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return nil, false
	}

	sessions, err := h.sessionRepo.GetActiveSessions(c.Request.Context(), userID)
	if err != nil {
		h.logger.Error("Failed to get sessions", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve sessions"})
		return nil, false
	}
	responses := make([]models.SessionResponse, len(sessions))
	for i, session := range sessions {
		responses[i] = *session.ToResponse(nil)
	}
	return responses, true
}
