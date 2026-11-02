// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"context"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/middleware"
	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/internal/services"
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

	if h.accessTerminator != nil {
		// Ends the row, the tokens bound to it (by row id and by its IdP SSO
		// session id), the SSO cookie state and the session's access JWTs.
		if err := h.accessTerminator.TerminateSession(c.Request.Context(), session.UserID, h.targetTenantID(c.Request.Context(), session.UserID, currentUser), sessionID, msgRevokedByAdmin); err != nil {
			h.logger.Error("Failed to fully revoke session",
				zap.String("session_id", sessionID.String()),
				zap.Error(err),
			)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to revoke session"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"message": "Session revoked successfully"})
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

	// EndSession is idempotent and, for this explicit reason, also revoked the
	// refresh tokens bound to the session (and their families) in the same
	// statement, even when the row was already ended.

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

	if h.accessTerminator != nil {
		// Per-session blacklist only: the user-wide marker would block the
		// user's next login (and lock an admin out when revoking themselves).
		if err := h.accessTerminator.TerminateUserAccessWith(c.Request.Context(), userID, h.targetTenantID(c.Request.Context(), userID, currentUser), msgRevokedByAdmin, services.TerminateOptions{}); err != nil {
			h.logger.Error("Failed to fully revoke user access",
				zap.String("user_id", userID.String()),
				zap.Error(err),
			)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to revoke sessions"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"message": "All user sessions revoked successfully"})
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

	if h.tokenService != nil {
		if err := h.tokenService.RevokeAllUserOAuthTokens(c.Request.Context(), userID, msgRevokedByAdmin); err != nil {
			h.logger.Error("Failed to revoke user OAuth tokens",
				zap.String("user_id", userID.String()),
				zap.Error(err),
			)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to revoke session tokens"})
			return
		}
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

// targetTenantID resolves the tenant of the user whose access is being ended
// (a platform admin may act across tenants, and back-channel logout fans out
// per tenant). Falls back to the caller's tenant when the lookup fails.
func (h *AdminHandler) targetTenantID(ctx context.Context, userID uuid.UUID, currentUser *models.CurrentUser) uuid.UUID {
	if h.userService != nil {
		if u, err := h.userService.GetByID(ctx, userID); err == nil && u != nil {
			return u.TenantID
		}
	}
	return currentUser.TenantID
}
