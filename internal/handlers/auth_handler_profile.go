// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/middleware"
	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/pkg/logger"
)

const (
	msgNotAuthenticatedProfile = "Not authenticated"
	msgInternalErrorProfile    = "An internal error occurred"
)

// Me returns the current user's information
// @Summary Get Current User
// @Description Get current authenticated user information
// @Tags Auth
// @Produce json
// @Security BearerAuth
// @Success 200 {object} models.UserResponse
// @Failure 401 {object} map[string]string
// @Router /api/v1/auth/me [get]
func (h *AuthHandler) Me(c *gin.Context) {
	user := middleware.GetCurrentUser(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": msgNotAuthenticatedProfile})
		return
	}

	response, err := h.authService.GetCurrentUser(c.Request.Context(), user.ID)
	if err != nil {
		logger.Error("Failed to get current user", zap.Error(err), zap.String("user_id", user.ID.String()))
		c.JSON(http.StatusInternalServerError, gin.H{"error": msgInternalErrorProfile})
		return
	}

	c.JSON(http.StatusOK, response)
}

// UpdateProfile handles profile update
// @Summary Update Profile
// @Description Update current user's profile
// @Tags Auth
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param body body models.UpdateProfileRequest true "Profile update request"
// @Success 200 {object} models.UserResponse
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Router /api/v1/auth/profile [put]
func (h *AuthHandler) UpdateProfile(c *gin.Context) {
	user := middleware.GetCurrentUser(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": msgNotAuthenticatedProfile})
		return
	}

	var req models.UpdateProfileRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	response, err := h.authService.UpdateProfile(c.Request.Context(), user.ID, &req)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, response)
}

// ChangePassword handles password change
// @Summary Change Password
// @Description Change current user's password
// @Tags Auth
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param body body models.PasswordChangeRequest true "Password change request"
// @Success 200 {object} map[string]string
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Router /api/v1/auth/password/change [post]
func (h *AuthHandler) ChangePassword(c *gin.Context) {
	user := middleware.GetCurrentUser(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": msgNotAuthenticatedProfile})
		return
	}

	var req models.PasswordChangeRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	ipAddress := middleware.RealClientIP(c)

	err := h.authService.ChangePassword(c.Request.Context(), user.ID, user.SessionID, req.CurrentPassword, req.NewPassword)
	if err != nil {
		// Security audit: failed password change
		logger.SecurityAudit.Warn("Security audit: password change failed",
			zap.String("event", "auth.password.change_failed"),
			zap.String("username", user.Username),
			zap.String("user_id", user.ID.String()),
			zap.String("ip", ipAddress),
			zap.String("reason", err.Error()),
			zap.Time("timestamp", time.Now().UTC()),
		)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Password change failed. Please check your current password and try again."})
		return
	}

	// Security audit: successful password change
	logger.SecurityAudit.Info("Security audit: password changed",
		zap.String("event", "auth.password.changed"),
		zap.String("username", user.Username),
		zap.String("user_id", user.ID.String()),
		zap.String("ip", ipAddress),
		zap.Time("timestamp", time.Now().UTC()),
	)

	c.JSON(http.StatusOK, gin.H{"message": "Password changed successfully"})
}

// GetSessions returns active sessions for the current user
// @Summary Get Active Sessions
// @Description Get all active sessions for current user
// @Tags Auth
// @Produce json
// @Security BearerAuth
// @Success 200 {object} []models.SessionResponse
// @Failure 401 {object} map[string]string
// @Router /api/v1/auth/sessions [get]
func (h *AuthHandler) GetSessions(c *gin.Context) {
	user := middleware.GetCurrentUser(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": msgNotAuthenticatedProfile})
		return
	}

	sessions, err := h.authService.GetActiveSessions(c.Request.Context(), user.ID, &user.SessionID)
	if err != nil {
		logger.Error("Failed to get active sessions", zap.Error(err), zap.String("user_id", user.ID.String()))
		c.JSON(http.StatusInternalServerError, gin.H{"error": msgInternalErrorProfile})
		return
	}

	c.JSON(http.StatusOK, gin.H{"sessions": sessions})
}

// Heartbeat updates the session's last activity timestamp
// @Summary Session Heartbeat
// @Description Update session's last activity timestamp to keep it alive
// @Tags Auth
// @Produce json
// @Security BearerAuth
// @Success 200 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Router /api/v1/auth/heartbeat [post]
func (h *AuthHandler) Heartbeat(c *gin.Context) {
	user := middleware.GetCurrentUser(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": msgNotAuthenticatedProfile})
		return
	}

	err := h.authService.UpdateSessionActivity(c.Request.Context(), user.SessionID)
	if err != nil {
		logger.Error("Failed to update session activity", zap.Error(err), zap.String("session_id", user.SessionID.String()))
		c.JSON(http.StatusInternalServerError, gin.H{"error": msgInternalErrorProfile})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "ok"})
}

// RevokeSession revokes a specific session
// @Summary Revoke Session
// @Description Revoke a specific session
// @Tags Auth
// @Produce json
// @Security BearerAuth
// @Param id path string true "Session ID"
// @Success 200 {object} map[string]string
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Router /api/v1/auth/sessions/{id} [delete]
func (h *AuthHandler) RevokeSession(c *gin.Context) {
	user := middleware.GetCurrentUser(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": msgNotAuthenticatedProfile})
		return
	}

	sessionIDStr := c.Param("id")
	sessionID, err := parseUUID(sessionIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid session ID"})
		return
	}

	err = h.authService.RevokeSession(c.Request.Context(), user.ID, sessionID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Session revoked"})
}

// GetLoginHistory returns the user's login history
// @Summary Get Login History
// @Description Get current user's login history with pagination
// @Tags Auth
// @Produce json
// @Security BearerAuth
// @Param page query int false "Page number" default(1)
// @Param page_size query int false "Page size" default(20)
// @Success 200 {object} models.LoginHistoryResponse
// @Failure 401 {object} map[string]string
// @Router /api/v1/auth/login-history [get]
func (h *AuthHandler) GetLoginHistory(c *gin.Context) {
	user := middleware.GetCurrentUser(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": msgNotAuthenticatedProfile})
		return
	}

	page := 1
	pageSize := 20

	if p := c.Query("page"); p != "" {
		if parsed, err := parsePageNumber(p); err == nil && parsed > 0 {
			page = parsed
		}
	}
	if ps := c.Query("page_size"); ps != "" {
		if parsed, err := parsePageNumber(ps); err == nil && parsed > 0 {
			pageSize = parsed
		}
	}

	response, err := h.authService.GetLoginHistory(c.Request.Context(), user.ID, page, pageSize)
	if err != nil {
		logger.Error("Failed to get login history", zap.Error(err), zap.String("user_id", user.ID.String()))
		c.JSON(http.StatusInternalServerError, gin.H{"error": msgInternalErrorProfile})
		return
	}

	c.JSON(http.StatusOK, response)
}

// ForgotPassword initiates the password reset flow
// @Summary Request Password Reset
// @Description Send a password reset email to the user
// @Tags Auth
// @Accept json
// @Produce json
// @Param body body models.PasswordResetRequest true "Email address"
// @Success 200 {object} map[string]string
// @Failure 400 {object} map[string]string
// @Router /api/v1/auth/password/forgot [post]
func (h *AuthHandler) ForgotPassword(c *gin.Context) {
	if h.passwordResetService == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Password reset service not configured"})
		return
	}

	var req models.PasswordResetRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	tenantID := middleware.GetTenantID(c)
	ipAddress := middleware.RealClientIP(c)

	// Always return success to prevent email enumeration
	_ = h.passwordResetService.RequestPasswordReset(c.Request.Context(), tenantID, req.Email, ipAddress)

	// Security audit: password reset requested
	// Note: We log this for all requests (even for non-existent emails) to detect enumeration attempts
	logger.SecurityAudit.Info("Security audit: password reset requested",
		zap.String("event", "auth.password.reset_requested"),
		zap.String("email", req.Email),
		zap.String("ip", ipAddress),
		zap.Time("timestamp", time.Now().UTC()),
	)

	c.JSON(http.StatusOK, gin.H{
		"message": "If the email address is registered, you will receive a password reset link shortly.",
	})
}

// ResetPassword completes the password reset flow
// @Summary Reset Password
// @Description Reset password using the token from email
// @Tags Auth
// @Accept json
// @Produce json
// @Param body body models.PasswordResetConfirmRequest true "Reset token and new password"
// @Success 200 {object} map[string]string
// @Failure 400 {object} map[string]string
// @Router /api/v1/auth/password/reset [post]
func (h *AuthHandler) ResetPassword(c *gin.Context) {
	if h.passwordResetService == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Password reset service not configured"})
		return
	}

	var req models.PasswordResetConfirmRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	ipAddress := middleware.RealClientIP(c)

	err := h.passwordResetService.ResetPassword(c.Request.Context(), req.Token, req.NewPassword, ipAddress)
	if err != nil {
		// Security audit: password reset failed
		logger.SecurityAudit.Warn("Security audit: password reset failed",
			zap.String("event", "auth.password.reset_failed"),
			zap.String("ip", ipAddress),
			zap.String("reason", err.Error()),
			zap.Time("timestamp", time.Now().UTC()),
		)
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Security audit: password reset completed
	logger.SecurityAudit.Info("Security audit: password reset completed",
		zap.String("event", "auth.password.reset_completed"),
		zap.String("ip", ipAddress),
		zap.Time("timestamp", time.Now().UTC()),
	)

	c.JSON(http.StatusOK, gin.H{
		"message": "Password has been reset successfully. You can now log in with your new password.",
	})
}

// GetCSRFToken returns a CSRF token for the current authenticated
// session. The token is bound to the session ID in Redis (CSRFRedis
// KeyPrefix:<sessionID>) and validated on every state-changing
// request by the CSRF middleware. Caller must be authenticated —
// the handler 401s if middleware.GetCurrentUser returns nil.
//
// @Summary Get CSRF Token
// @Description Get CSRF token for authenticated session.
//
//	Canonical mount: /api/v1/auth/csrf-token (Falcon-ID v1 API).
//	The legacy /api/auth/csrf-token alias is also registered for
//	backward compatibility (see registerAPIRoutes in cmd/routes.go)
//	but will be removed in v2.0.0; new callers should use the
//	versioned path. Misleading annotation in earlier versions of
//	this file pointed callers at the legacy alias, which in
//	production goes through an APISIX route to Next.js (frontend-
//	login) and returns 404 — frontend!N (2026-05-12) updated the
//	id.example.com login app's CSRF_TOKEN_PATH constant after
//	live repro of "csrf token fetch failed: HTTP 404" on the
//	step-up MFA enrollment page.
//
// @Tags Auth
// @Produce json
// @Security BearerAuth
// @Success 200 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Router /api/v1/auth/csrf-token [get]
func (h *AuthHandler) GetCSRFToken(c *gin.Context) {
	user := middleware.GetCurrentUser(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": msgNotAuthenticatedProfile})
		return
	}

	if h.csrfMiddleware == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "CSRF middleware not configured"})
		return
	}

	token, err := h.csrfMiddleware.GenerateTokenForSession(c, user.SessionID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate CSRF token"})
		return
	}

	// Also write the hexxlock_csrf cookie so the validator's cookie
	// double-submit fallback (CSRFMiddleware.validateToken Path 2) has
	// a value to compare against. Without this the cookie path was
	// dead code — no other site of the codebase issued the cookie,
	// so when CSRF middleware ran BEFORE auth and couldn't find a
	// session-bound Redis token, it fell through to a missing-cookie
	// 403. Belt-and-braces alongside the Path 1 Redis lookup.
	h.csrfMiddleware.WriteCookie(c, token)

	c.JSON(http.StatusOK, gin.H{
		"token":      token,
		"expires_at": time.Now().Add(defaultAccessTokenTTL).Unix(),
	})
}

func parsePageNumber(s string) (int, error) {
	return strconv.Atoi(s)
}

// Validate validates the JWT token and returns user info in headers
// This endpoint is used by API Gateway (APISIX) forward-auth plugin
// Supports both Authorization header and HttpOnly cookie
// @Summary Validate Token
// @Description Validate JWT token for API Gateway forward-auth
// @Tags Auth
// @Produce json
// @Param Authorization header string false "Bearer token"
// @Success 200 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Router /api/v1/auth/validate [get]
func (h *AuthHandler) Validate(c *gin.Context) {
	tokenString := extractBearerToken(c)
	if tokenString == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization required"})
		return
	}

	claims, err := h.tokenService.ValidateAccessTokenWithContext(c.Request.Context(), tokenString)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid or expired token"})
		return
	}

	setClaimsResponseHeaders(c, claims)

	c.JSON(http.StatusOK, gin.H{
		"valid":      true,
		"user_id":    claims.UserID.String(),
		"tenant_id":  claims.TenantID.String(),
		"username":   claims.Username,
		"realm_id":   claims.RealmID.String(),
		"realm_slug": claims.RealmSlug,
		"realm_type": claims.RealmType,
	})
}

// extractBearerToken returns the JWT string from the Authorization header or
// the HttpOnly access-token cookie, in that order.
func extractBearerToken(c *gin.Context) string {
	const bearerPrefix = "Bearer "
	authHeader := c.GetHeader("Authorization")
	if len(authHeader) >= len(bearerPrefix) && authHeader[:len(bearerPrefix)] == bearerPrefix {
		return authHeader[len(bearerPrefix):]
	}
	cookie, err := c.Cookie(accessTokenCookieName)
	if err == nil && cookie != "" {
		return cookie
	}
	return ""
}

// setClaimsResponseHeaders writes the X-* forwarded-auth headers that upstream
// services (e.g., APISIX) expect to identify the caller.
func setClaimsResponseHeaders(c *gin.Context, claims *models.Claims) {
	c.Header("X-User-ID", claims.UserID.String())
	c.Header("X-Tenant-ID", claims.TenantID.String())
	c.Header("X-Username", claims.Username)
	c.Header("X-User-Email", claims.Email)

	if len(claims.Roles) > 0 {
		c.Header("X-User-Role", primaryRoleFromClaims(claims.Roles))
	}
	if claims.RealmID != uuid.Nil {
		c.Header("X-Realm-ID", claims.RealmID.String())
	}
	if claims.RealmSlug != "" {
		c.Header("X-Realm-Slug", claims.RealmSlug)
	}
	if claims.RealmType != "" {
		c.Header("X-Realm-Type", claims.RealmType)
	}
}

// primaryRoleFromClaims returns the most privileged role from the list, preferring
// platform_admin or super_admin when present.
func primaryRoleFromClaims(roles []string) string {
	primary := roles[0]
	for _, r := range roles {
		if r == "platform_admin" || r == "super_admin" {
			return r
		}
	}
	return primary
}
