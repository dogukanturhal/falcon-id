// SPDX-License-Identifier: AGPL-3.0-or-later

package middleware

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

// Context keys for the human "actor" identity established by
// RequireActorAuth. Deliberately distinct from the browser-session keys
// (see auth.go's ContextKeyUser etc.) and from the ServiceAuth keys
// (CtxKeyServiceSlug etc.) in service_auth.go — three independent
// identities can be present on the same request: the calling service, the
// human operator acting through it, and (on browser-tier routes) the
// logged-in session user.
const (
	ctxKeyActorUserID   = "actor_user_id"
	ctxKeyActorTenantID = "actor_tenant_id"
)

// RequireActorAuth validates a human platform operator's OWN session
// access token, carried in the X-Actor-Assertion header, on routes that
// are otherwise gated by ServiceAuth() + RequireScope() (i.e. the caller
// is an authenticated SERVICE — the acmeweb BFF — acting on behalf of a
// human, not a human calling directly).
//
// Why this exists (platform-plane JIT elevation + break-glass,
// /internal/v1/jit-elevations and /internal/v1/break-glass): those routes
// MUST use ServiceAuth()+RequireScope() per the R1 brief (every
// /internal/v1/* endpoint does), but ServiceAuth's JWT authenticates the
// calling SERVICE PRINCIPAL only — it carries service_slug/service_scopes/
// service_tenant_id, never a per-human-user claim (see service_auth.go's
// context keys). The requester_id/approver_id on a JIT elevation is
// security-critical identity (two-person rule, break-glass self-grant,
// audit trail) and per this rollout's hard rule, "tenant/user from the
// validated JWT only" — a body-supplied user_id, or trusting a raw
// X-User-ID header, is exactly the header-trust footgun that rule exists
// to prevent.
//
// So the BFF forwards the operator's own already-validated session access
// token unchanged in a SECOND header (X-Actor-Assertion) alongside its own
// service-to-service Authorization Bearer token. This mirrors the existing
// RFC 8693 `act` delegation-chain claim this codebase already logs
// (logDelegationActor in auth.go) — same "acting party" concept, just
// carried as a header instead of an `act` claim, because the outer token
// here is a client_credentials service JWT that has no room for one.
//
// On success, sets ctxKeyActorUserID / ctxKeyActorTenantID from the
// validated claims — GetActorUserID/GetActorTenantID read them back.
// Handlers MUST use these, never a body field, for requester_id/
// approver_id. Must be mounted AFTER ServiceAuth()+RequireScope() in the
// chain (same ordering requirement scope_enforcement.go documents for
// RequireScope itself).
func (m *AuthMiddleware) RequireActorAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		clientIP := ClientIP(c.Request)

		header := c.GetHeader("X-Actor-Assertion")
		if header == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error":   "Actor assertion required",
				"message": "X-Actor-Assertion header (the operator's own bearer access token) is required on this endpoint.",
			})
			return
		}

		parts := strings.SplitN(header, " ", 2)
		var tokenString string
		if len(parts) == 2 && strings.EqualFold(parts[0], "bearer") {
			tokenString = parts[1]
		} else {
			tokenString = header
		}

		if m.isCircuitBreakerOpen() {
			c.AbortWithStatusJSON(http.StatusServiceUnavailable, gin.H{
				"error":  "Service temporarily unavailable",
				"detail": "Session validation service is experiencing issues. Please try again in a few moments.",
			})
			return
		}

		claims, err := m.tokenService.ValidateAccessTokenWithContext(c.Request.Context(), tokenString)
		if err != nil {
			m.handleTokenValidationError(c, err, clientIP)
			return
		}

		c.Set(ctxKeyActorUserID, claims.UserID)
		c.Set(ctxKeyActorTenantID, claims.TenantID)
		c.Next()
	}
}

// GetActorUserID returns the human operator's user ID established by
// RequireActorAuth, or uuid.Nil if absent.
func GetActorUserID(c *gin.Context) uuid.UUID {
	v, exists := c.Get(ctxKeyActorUserID)
	if !exists {
		return uuid.Nil
	}
	id, ok := v.(uuid.UUID)
	if !ok {
		return uuid.Nil
	}
	return id
}

// GetActorTenantID returns the human operator's tenant ID established by
// RequireActorAuth, or uuid.Nil if absent.
func GetActorTenantID(c *gin.Context) uuid.UUID {
	v, exists := c.Get(ctxKeyActorTenantID)
	if !exists {
		return uuid.Nil
	}
	id, ok := v.(uuid.UUID)
	if !ok {
		return uuid.Nil
	}
	return id
}

// RequirePlatformInternalActor MUST run after RequireActorAuth. It
// enforces that the actor's own tenant is the Platform-internal tenant —
// the application-layer mirror of the DB trigger
// (iam_platform_roles_enforce) and the SpiceDB tenant->is_platform_internal
// permission. Fail-closed: an actor from any other tenant is rejected
// before the handler runs, regardless of what ServiceAuth/RequireScope
// already allowed (a compromised or misconfigured BFF service credential
// must not be able to smuggle a non-platform human into a platform-plane
// grant).
func RequirePlatformInternalActor() gin.HandlerFunc {
	return func(c *gin.Context) {
		tenantID := GetActorTenantID(c)
		if tenantID == uuid.Nil || tenantID.String() != models.HexxlockInternalTenantID {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error": "platform_role_requires_internal_tenant",
			})
			return
		}
		c.Next()
	}
}

// SetOperatorActor records the identity of an operator verified by
// platform-shared/operatorauth under the same context keys RequireActorAuth
// uses, so handlers written against GetActorUserID/GetActorTenantID (the JIT
// and platform-role handlers) serve the operator chain unchanged. Call it only
// after operatorauth.RequireOperator has succeeded.
func SetOperatorActor(c *gin.Context, userID, tenantID uuid.UUID) {
	c.Set(ctxKeyActorUserID, userID)
	c.Set(ctxKeyActorTenantID, tenantID)
}
