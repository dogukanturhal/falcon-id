// SPDX-License-Identifier: AGPL-3.0-or-later

package middleware

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/services"
	"github.com/dogukanturhal/falcon-id/pkg/logger"
)

// ContinuousAuth returns a Gin middleware that re-evaluates the trust posture of
// every authenticated request using the ZeroTrustOrchestrator. It composes ITDR
// signals, CAEP events, and session context to produce a per-request allow /
// challenge / deny decision — enforcing Zero Trust beyond the initial login.
//
// The middleware is deliberately lightweight:
//   - Unauthenticated routes (no session_id in context) are passed through
//     immediately with zero Redis I/O.
//   - On orchestrator errors the middleware fails-open so transient Redis
//     unavailability never blocks legitimate users.
//   - On allow, the session's last-seen IP and User-Agent are recorded in Redis
//     for subsequent comparisons (single SET, fire-and-forget).
//
// The middleware MUST be placed after RequireAuth() in the router chain so that
// the "session_id" context key is populated.
func ContinuousAuth(orchestrator *services.ZeroTrustOrchestrator) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Extract session ID from context — set by RequireAuth.
		// Auth middleware stores the value as uuid.UUID; handle both uuid.UUID and
		// string representations to be defensive.
		sessionID := extractSessionID(c)
		if sessionID == "" {
			// No session means this is an unauthenticated route — skip evaluation.
			c.Next()
			return
		}

		ip := RealClientIP(c)
		ua := c.GetHeader("User-Agent")

		eval, err := orchestrator.EvaluateRequest(c.Request.Context(), sessionID, ip, ua)
		if err != nil {
			// Fail-open: do not block legitimate users on orchestrator errors.
			// Log at warn level so ops can detect sustained Redis issues.
			logger.Warn("ContinuousAuth: orchestrator error — failing open",
				zap.String("session_id", sessionID),
				zap.String("path", c.Request.URL.Path),
				zap.Error(err),
			)
			c.Next()
			return
		}

		switch eval.Action {
		case "deny":
			logger.Info("ContinuousAuth: request denied",
				zap.String("session_id", sessionID),
				zap.String("reason", eval.Reason),
				zap.Int("risk_score", eval.RiskScore),
				zap.String("path", c.Request.URL.Path),
			)
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error":   "Access denied by continuous evaluation",
				"reason":  eval.Reason,
				"signals": eval.Signals,
			})
			return

		case "challenge":
			logger.Info("ContinuousAuth: step-up required",
				zap.String("session_id", sessionID),
				zap.String("reason", eval.Reason),
				zap.Int("risk_score", eval.RiskScore),
				zap.String("path", c.Request.URL.Path),
			)
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error":  "Step-up authentication required",
				"reason": eval.Reason,
				"action": "step_up",
			})
			return

		default:
			// "allow" or "log" — record context for future comparisons and continue.
			orchestrator.RecordRequestContext(c.Request.Context(), sessionID, ip, ua)
			c.Next()
		}
	}
}

// extractSessionID retrieves the session_id value stored by RequireAuth.
// RequireAuth stores it as uuid.UUID; we return the canonical string form.
func extractSessionID(c *gin.Context) string {
	val, exists := c.Get("session_id")
	if !exists {
		return ""
	}
	switch v := val.(type) {
	case uuid.UUID:
		if v == uuid.Nil {
			return ""
		}
		return v.String()
	case string:
		return v
	default:
		return ""
	}
}
