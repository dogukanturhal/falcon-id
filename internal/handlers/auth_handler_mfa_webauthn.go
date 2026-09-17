// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/middleware"
	"github.com/dogukanturhal/falcon-id/pkg/logger"
)

// BeginMFAWebAuthn POST /api/v1/auth/mfa/webauthn/begin
//
// Issues a WebAuthn assertion challenge for a user already mid-login —
// password verified, temp MFA session live (returned by /login when
// the user has mfa_method=webauthn in available methods). Companion
// to FinishMFAWebAuthn. Matches the canonical Microsoft Entra / Auth0
// / Okta "WebAuthn as MFA factor" UX.
//
// Request body:
//
//	{ "session_id": "<temp MFA session id from /api/v1/auth/login>" }
//
// Response:
//
//	{ "publicKey": {...}, "wa_session_id": "<webauthn ceremony id>" }
//
// 503 when webauthn service unwired. 400 on malformed body / session
// errors.
type beginMFAWebAuthnRequest struct {
	SessionID string `json:"session_id" binding:"required,uuid"`
}

func (h *AuthHandler) BeginMFAWebAuthn(c *gin.Context) {
	var req beginMFAWebAuthnRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	out, err := h.authService.BeginWebAuthnMFA(c.Request.Context(), req.SessionID)
	if err != nil {
		logger.Warn("BeginMFAWebAuthn failed",
			zap.String("session_id", req.SessionID),
			zap.Error(err),
		)
		// Distinguish "service not wired" (503) from other failures (400).
		if strings.Contains(err.Error(), "webauthn service not configured") {
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": "WebAuthn not configured"})
			return
		}
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, out)
}

// FinishMFAWebAuthn POST /api/v1/auth/mfa/webauthn/finish
//   ?session_id=<temp MFA session id>
//   &wa_session_id=<webauthn ceremony id from /begin>
//   &remember_me=true|false        (optional)
//   &device_id=<client device id>  (optional)
//
// Request body: raw assertion JSON output by
// @simplewebauthn/browser.startAuthentication() — passed through to
// the webauthn library via c.Request. ID parameters travel on the
// query string so the body remains the assertion-only payload the
// library expects (mirrors /webauthn/login/finish convention).
//
// Response: full LoginResponse with tokens (200) on success. On
// verification failure the temp MFA session is preserved up to the
// per-session attempts cap so the user can retry the assertion
// without re-entering their password.
func (h *AuthHandler) FinishMFAWebAuthn(c *gin.Context) {
	sessionID := strings.TrimSpace(c.Query("session_id"))
	waSessionID := strings.TrimSpace(c.Query("wa_session_id"))
	if sessionID == "" || waSessionID == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "session_id and wa_session_id query parameters are required",
		})
		return
	}

	rememberMe := c.Query("remember_me") == "true"
	deviceID := strings.TrimSpace(c.Query("device_id"))
	ipAddress := middleware.RealClientIP(c)
	userAgent := c.GetHeader(hdrUserAgent)

	response, err := h.authService.CompleteWebAuthnMFA(
		c.Request.Context(),
		sessionID, waSessionID,
		c.Request,
		ipAddress, userAgent,
		rememberMe, deviceID,
	)
	if err != nil {
		logger.SecurityAudit.Warn("Security audit: WebAuthn MFA completion failed",
			zap.String("event", "auth.mfa.webauthn.failed"),
			zap.String("session_id", sessionID),
			zap.String("wa_session_id", waSessionID),
			zap.String("ip", ipAddress),
			zap.String("user_agent", userAgent),
			zap.String("reason", err.Error()),
			zap.Time("timestamp", time.Now().UTC()),
		)
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Mirror the cookie-set surface of the code-based MFA-complete path
	// so a successful WebAuthn-MFA login produces the same browser-side
	// auth-cookie footprint. Without this the LoginResponse JSON ships
	// access/refresh in the body but the user-agent never carries them
	// on the next /oauth/authorize → silent SSO breaks → step-up loop.
	h.SetLoginResponseCookies(c, response)

	c.JSON(http.StatusOK, response)
}
