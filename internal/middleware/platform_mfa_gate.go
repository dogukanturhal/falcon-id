// SPDX-License-Identifier: AGPL-3.0-or-later

package middleware

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/internal/services"
	"github.com/dogukanturhal/falcon-id/pkg/logger"
)

// ErrCodePhishingResistantMFARequired is the machine-readable error returned
// when the platform admin plane demands a passkey-authenticated session.
const ErrCodePhishingResistantMFARequired = "phishing_resistant_mfa_required"

// phishingResistantPolicy enforces PLATFORM_ADMIN_REQUIRE_PHISHING_RESISTANT_MFA.
// It applies ONLY to verified platform admins; tenant owners/admins and normal
// users are never affected. The zero value (required=false) is a no-op.
type phishingResistantPolicy struct {
	required bool
	sessions idpSessionReader
}

// IsPasskeyBoundPlatformAdmin reports whether the user is a verified platform
// admin who is subject to the passkey requirement (i.e. not the break-glass
// account). Callers still gate on the config flag.
func IsPasskeyBoundPlatformAdmin(user *models.CurrentUser) bool {
	if user == nil || !isVerifiedPlatformAdmin(user) {
		return false
	}
	return !platformAuthorityPtr.Load().IsBreakGlassAccount(user.Email)
}

// deny aborts the request and returns true when the policy is on, the caller is
// a platform admin (other than the break-glass account, which is exempt by
// design so recovery never depends on a passkey) and the session's AMR does not
// contain a passkey. Fail-closed on any lookup problem.
func (p phishingResistantPolicy) deny(c *gin.Context, user *models.CurrentUser, action string) bool {
	if !p.required || !IsPasskeyBoundPlatformAdmin(user) {
		return false
	}
	ok, err := p.sessionIsPhishingResistant(c, user)
	if err != nil {
		// Lookup failure is an availability problem, not a missing passkey:
		// the client must not be told to re-authenticate.
		logger.Log.Error("Platform admin phishing-resistant MFA check failed",
			zap.String("user_id", user.ID.String()),
			zap.String("path", c.Request.URL.Path),
			zap.Error(err),
		)
		c.AbortWithStatusJSON(http.StatusServiceUnavailable, gin.H{
			"error":   "mfa_check_unavailable",
			"message": "Unable to verify session assurance, try again",
		})
		return true
	}
	if ok {
		return false
	}
	logger.Log.Warn("Platform admin denied: phishing-resistant MFA required",
		zap.String("user_id", user.ID.String()),
		zap.String("path", c.Request.URL.Path),
		zap.String("action", action),
	)
	// RFC 9470 §3: ask the client for a higher-assurance (AAL3 / passkey)
	// authentication. 403 + machine-readable code is what the admin SPA keys on.
	c.Header("WWW-Authenticate", `Bearer error="insufficient_user_authentication", error_description="Passkey authentication required for the platform admin plane", acr_values="`+services.ACRValueAAL3+`"`)
	c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
		"error":      ErrCodePhishingResistantMFARequired,
		"message":    "Platform admin access requires passkey (WebAuthn) authentication",
		"acr_values": services.ACRValueAAL3,
	})
	return true
}

// sessionIsPhishingResistant returns an error only for a lookup failure; a
// missing session or missing passkey AMR is (false, nil).
func (p phishingResistantPolicy) sessionIsPhishingResistant(c *gin.Context, user *models.CurrentUser) (bool, error) {
	if p.sessions == nil || user.SessionID == uuid.Nil {
		return false, nil
	}
	ctx := c.Request.Context()
	var (
		sess *models.Session
		err  error
	)
	if user.RealmID != uuid.Nil {
		sess, err = p.sessions.GetByIDWithRealmContext(ctx, user.SessionID, user.RealmID)
	} else {
		sess, err = p.sessions.GetByID(ctx, user.SessionID)
	}
	if err != nil {
		return false, err
	}
	if sess == nil {
		return false, nil
	}
	return services.IsPhishingResistantAMR(sess.AuthMethodsUsed), nil
}

// requireUserFromContextQuiet returns the current user or nil without aborting.
func requireUserFromContextQuiet(c *gin.Context) *models.CurrentUser {
	v, ok := c.Get(CurrentUserKey)
	if !ok {
		return nil
	}
	u, _ := v.(*models.CurrentUser)
	return u
}
