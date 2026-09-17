// SPDX-License-Identifier: AGPL-3.0-or-later

package middleware

import (
	"context"
	"net/http"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/services"
	"github.com/dogukanturhal/falcon-id/pkg/logger"
)

// AdaptiveMFAEvaluator is the interface the middleware uses to obtain an MFA
// decision.  It is satisfied by *services.ConditionalAccessService.
//
// Using context.Context rather than *gin.Context keeps the services package
// free of HTTP framework dependencies.  The middleware extracts the AuthContext
// from the Gin request before calling the evaluator.
type AdaptiveMFAEvaluator interface {
	EvaluateAdaptiveMFAWithContext(ctx context.Context, authCtx services.AuthContext) (*services.MFADecisionResult, error)
}

// AdaptiveMFAMiddleware intercepts authenticated requests, derives an
// AuthContext from the request signals, and enforces the MFA decision returned
// by the AdaptiveMFAEvaluator.
//
// Decision enforcement:
//   - "allow"        → c.Next()
//   - "mfa_required" → HTTP 401 with X-MFA-Required: true header
//   - "step_up"      → HTTP 401 with X-Step-Up-Required: true header
//   - "block"        → HTTP 403
type AdaptiveMFAMiddleware struct {
	evaluator AdaptiveMFAEvaluator
}

// NewAdaptiveMFAMiddleware creates a new AdaptiveMFAMiddleware.
func NewAdaptiveMFAMiddleware(evaluator AdaptiveMFAEvaluator) *AdaptiveMFAMiddleware {
	return &AdaptiveMFAMiddleware{evaluator: evaluator}
}

// Enforce returns a Gin handler that applies the adaptive MFA policy to every
// request.  It must be placed after RequireAuth so that the current user is
// available in the context.
func (m *AdaptiveMFAMiddleware) Enforce() gin.HandlerFunc {
	return func(c *gin.Context) {
		authCtx := m.buildAuthContext(c)

		decision, err := m.evaluator.EvaluateAdaptiveMFAWithContext(c.Request.Context(), authCtx)
		if err != nil {
			// Fail-open: infrastructure errors must not block legitimate users,
			// but they are logged at error level for alerting.
			logger.Error("AdaptiveMFAMiddleware: evaluation error; failing open",
				zap.String("user_id", authCtx.UserID.String()),
				zap.String("ip", authCtx.IPAddress),
				zap.Error(err),
			)
			c.Next()
			return
		}

		logger.Debug("AdaptiveMFAMiddleware: decision",
			zap.String("user_id", authCtx.UserID.String()),
			zap.String("action", decision.Action),
			zap.String("risk_level", decision.RiskLevel),
			zap.Int("score", decision.ComputedRiskScore),
		)

		switch decision.Action {
		case "allow":
			c.Next()

		case "mfa_required":
			c.Header("X-MFA-Required", "true")
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error":       "mfa_required",
				"message":     decision.Reason,
				"mfa_methods": decision.RequiredMethods,
				"risk_level":  decision.RiskLevel,
			})

		case "step_up":
			c.Header("X-Step-Up-Required", "true")
			// RFC 9470 §3 (IAM-05): pair the existing 401 with a
			// `WWW-Authenticate: Bearer
			// error="insufficient_user_authentication"` challenge so
			// spec-aware RP SDKs (panva/openid-client v6+, Authlib,
			// Keycloak adapter) auto-trigger fresh authentication.
			// max_age is omitted because adaptive_mfa decisions are
			// risk-based rather than time-based; acr_values is omitted
			// for the same reason — the requested method ladder is
			// surfaced via the body's mfa_methods field, not the acr
			// channel.
			c.Header("WWW-Authenticate", `Bearer error="insufficient_user_authentication", error_description="adaptive risk evaluation requires fresh MFA"`)
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error":       "step_up_required",
				"message":     decision.Reason,
				"mfa_methods": decision.RequiredMethods,
				"risk_level":  decision.RiskLevel,
			})

		case "block":
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error":      "access_blocked",
				"message":    decision.Reason,
				"risk_level": decision.RiskLevel,
			})

		default:
			// Unknown action — fail-open with a warning.
			logger.Warn("AdaptiveMFAMiddleware: unknown decision action; failing open",
				zap.String("action", decision.Action),
				zap.String("user_id", authCtx.UserID.String()),
			)
			c.Next()
		}
	}
}

// buildAuthContext constructs an AuthContext from the Gin request context.
// It reads the authenticated user set by RequireAuth and the raw HTTP request.
func (m *AdaptiveMFAMiddleware) buildAuthContext(c *gin.Context) services.AuthContext {
	// Risk engine consumes the real client public IP so impossible-travel
	// / new-location / geo-velocity scoring works against the user's
	// actual public IP, not the APISIX pod IP (identical across all users).
	authCtx := services.AuthContext{
		IPAddress: ClientIP(c.Request),
		UserAgent: c.GetHeader("User-Agent"),
	}

	// Populate identity fields from the authenticated session.
	if user := GetCurrentUser(c); user != nil {
		authCtx.UserID = user.ID
		authCtx.TenantID = user.TenantID
	}

	// Device fingerprint: prefer X-Device-ID header, fall back to a stable
	// hash of the User-Agent (the engine treats an empty DeviceID as
	// "unmanaged").
	if deviceID := c.GetHeader("X-Device-ID"); deviceID != "" {
		authCtx.DeviceID = deviceID
	}

	// New-device signal: injected by the login flow via a context key set in
	// the auth handler when the user-agent has not been seen before.
	if newDevice, exists := c.Get("is_new_device"); exists {
		if v, ok := newDevice.(bool); ok {
			authCtx.IsNewDevice = v
		}
	}

	// Pre-computed risk score: the auth handler or risk scoring service may
	// have already scored this login and stored it in the context.
	if rs, exists := c.Get("risk_score"); exists {
		if v, ok := rs.(int); ok {
			authCtx.RiskScore = v
		}
	}

	// Geo-location hint: populated by geo-IP middleware when present.
	if geo, exists := c.Get("geo_location"); exists {
		if v, ok := geo.(*services.GeoLocation); ok {
			authCtx.GeoLocation = v
		}
	}

	return authCtx
}
