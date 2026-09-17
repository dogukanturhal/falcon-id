// SPDX-License-Identifier: AGPL-3.0-or-later

package middleware

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

// StepUpVerificationRepo is the persistence interface required by StepUpMiddleware.
// Implementations must query the iam_step_up_verifications table.
type StepUpVerificationRepo interface {
	// HasRecentVerification returns true when there is at least one verification
	// row for the given sessionID and action whose expires_at is still in the
	// future and whose verified_at is no older than maxAge from now.
	HasRecentVerification(ctx context.Context, sessionID uuid.UUID, action string, maxAge time.Duration) (bool, error)
}

// StepUpMiddleware protects sensitive endpoints by requiring the current
// session to have completed a fresh MFA verification for a specific action.
// If the session does not have a sufficiently recent verification the request
// is aborted with HTTP 401 + a `WWW-Authenticate: Bearer
// error="insufficient_user_authentication"` header (RFC 9470 §3 — IAM-05)
// AND a HexxLock-shape JSON body that signals to the in-house frontend
// SDKs (apps/accounts/src/components/security/step-up-dialog.tsx,
// apps/platform-admin/src/hooks/use-step-up-mfa.ts) that they must drive
// the user through a step-up MFA flow. The dual surface lets third-party
// RP SDKs that implement RFC 9470 (panva/openid-client v6+, Authlib,
// Keycloak adapter) auto-trigger fresh authentication while the
// existing in-house body-based detection continues to work unchanged.
//
// The 401 status (was 403 through 2026-04-29) aligns with the sibling
// adaptive_mfa.go middleware, which has used 401 for `step_up` since it
// shipped, and matches RFC 6750 §3 / RFC 9470 §3 which both require 401
// for any response that includes a `WWW-Authenticate: Bearer`
// challenge.
type StepUpMiddleware struct {
	repo     StepUpVerificationRepo
	logger   *zap.Logger
	disabled bool
}

// NewStepUpMiddleware creates a new StepUpMiddleware.
// Set STEP_UP_DISABLED=true to bypass step-up checks in development/testing.
// SECURITY: STEP_UP_DISABLED is silently ignored when ENVIRONMENT=production
// to prevent accidental deployment of insecure configurations.
func NewStepUpMiddleware(repo StepUpVerificationRepo, logger *zap.Logger) *StepUpMiddleware {
	requestedDisable := os.Getenv("STEP_UP_DISABLED") == "true"
	isProduction := os.Getenv("ENVIRONMENT") == envProductionName

	disabled := requestedDisable && !isProduction
	if requestedDisable && isProduction {
		logger.Error("STEP_UP_DISABLED is set to 'true' in production — ignoring for security; step-up MFA will be enforced")
	}
	if disabled {
		logger.Warn("StepUp MFA middleware is DISABLED via STEP_UP_DISABLED env var — do NOT use in production")
	}
	return &StepUpMiddleware{
		repo:     repo,
		logger:   logger,
		disabled: disabled,
	}
}

// RequireStepUp returns a gin.HandlerFunc that enforces step-up MFA for the
// given action. The handler extracts the session_id from the gin context (set
// by RequireAuth), queries the verification store, and either continues the
// chain or aborts with:
//
//	HTTP 401
//	WWW-Authenticate: Bearer error="insufficient_user_authentication",
//	    error_description="Recent MFA verification required for action: <action>",
//	    max_age=<seconds>
//	{
//	  "error":             "step_up_required",
//	  "step_up_required":  true,
//	  "action":            "<action>",
//	  "message":           "Recent MFA verification required for this action"
//	}
//
// maxAge controls how long a verification remains fresh. A verification older
// than maxAge is treated as absent. The action SHOULD be a snake_case
// identifier; the value is interpolated into the WWW-Authenticate header
// without escaping (RFC 9470 quoted-string per RFC 9110 §5.6.4 — quotes
// and backslashes inside action would corrupt the header). Current
// callers use literals like "role_mutation"; do not pass user-controlled
// strings without sanitisation.
func (m *StepUpMiddleware) RequireStepUp(action string, maxAge time.Duration) gin.HandlerFunc {
	return func(c *gin.Context) {
		if m.disabled {
			c.Next()
			return
		}

		// Extract session_id from context — set by RequireAuth.
		sessionVal, exists := c.Get("session_id")
		if !exists {
			m.logger.Warn("StepUp: session_id not found in context",
				zap.String("action", action),
				zap.String("path", c.Request.URL.Path),
			)
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "unauthorized",
			})
			return
		}

		sessionID, ok := sessionVal.(uuid.UUID)
		if !ok {
			m.logger.Error("StepUp: session_id has unexpected type",
				zap.String("action", action),
			)
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
				"error": "invalid session context",
			})
			return
		}

		verified, err := m.repo.HasRecentVerification(c.Request.Context(), sessionID, action, maxAge)
		if err != nil {
			m.logger.Error("StepUp: failed to check verification",
				zap.String("session_id", sessionID.String()),
				zap.String("action", action),
				zap.Error(err),
			)
			// Fail-closed: if we cannot verify, deny access.
			c.AbortWithStatusJSON(http.StatusServiceUnavailable, gin.H{
				"error": "unable to verify step-up authentication status",
			})
			return
		}

		if !verified {
			m.logger.Info("StepUp: recent MFA verification required but not present",
				zap.String("session_id", sessionID.String()),
				zap.String("action", action),
			)
			// RFC 9470 §3: emit `WWW-Authenticate: Bearer
			// error="insufficient_user_authentication"` so spec-aware RP
			// SDKs (panva/openid-client v6+, Authlib, Keycloak adapter)
			// auto-drive a fresh authentication. error_description and
			// max_age are OPTIONAL but useful for operator + SDK clarity.
			// acr_values is intentionally omitted — step-up here demands
			// freshness, not a higher AAL; if a future call site needs
			// AAL3 (passkey-required) the helper can be extended to
			// accept an acr parameter.
			c.Header("WWW-Authenticate", fmt.Sprintf(
				`Bearer error="insufficient_user_authentication", error_description="Recent MFA verification required for action: %s", max_age=%d`,
				action, int(maxAge.Seconds()),
			))
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error":            "step_up_required",
				"step_up_required": true,
				"action":           action,
				"message":          "Recent MFA verification required for this action",
			})
			return
		}

		c.Next()
	}
}
