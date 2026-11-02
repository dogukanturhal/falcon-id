// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/dogukanturhal/falcon-id/internal/middleware"
	"github.com/dogukanturhal/falcon-id/internal/services"
	redispkg "github.com/dogukanturhal/falcon-id/pkg/redis"
	"time"
)

func refreshStepUpIdpSession(c *gin.Context, cache *redispkg.SessionCache) bool {
	if cache == nil {
		return true
	}
	cookie, err := c.Cookie("falcon_idp_session")
	if err != nil || cookie == "" {
		return true
	}
	id, err := uuid.Parse(cookie)
	if err != nil {
		respondMFAFlowError(c, &services.MFAFlowError{Code: "mfa_session_expired"})
		return false
	}
	user := middleware.GetCurrentUser(c)
	sid, ok := c.Get("session_id")
	sessionID, valid := sid.(uuid.UUID)
	if user == nil || !ok || !valid {
		respondMFAFlowError(c, &services.MFAFlowError{Code: "mfa_session_expired"})
		return false
	}
	updated, err := cache.RefreshIdpSessionAuthTime(c.Request.Context(), id, user.ID, sessionID, time.Now().Unix())
	if err != nil {
		respondMFAFlowError(c, err)
		return false
	}
	if !updated {
		respondMFAFlowError(c, &services.MFAFlowError{Code: "mfa_session_expired"})
		return false
	}
	return true
}
