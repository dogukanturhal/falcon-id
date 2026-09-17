// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/middleware"
	"github.com/dogukanturhal/falcon-id/internal/services"
	"github.com/dogukanturhal/falcon-id/pkg/logger"
)

// OnboardingStatusHandler backs the onboarding wizard's entry-time
// re-entry guard: GET .../onboarding/status. Any authenticated user may
// call it (unlike OnboardingSlugHandler.ConfirmSlug, this is a read of
// the caller's own tenant, not a mutation, so it is not admin-gated) —
// it always answers for the caller's OWN tenant.
type OnboardingStatusHandler struct {
	service *services.OnboardingStatusService
	logger  *zap.Logger
}

// NewOnboardingStatusHandler exported constructor.
func NewOnboardingStatusHandler(service *services.OnboardingStatusService) *OnboardingStatusHandler {
	return &OnboardingStatusHandler{
		service: service,
		logger:  logger.Log,
	}
}

// GetStatus reports whether the signed-in user's tenant has already
// confirmed its onboarding subdomain slug. This is the real, server-side
// signal the onboarding wizard should key re-entry on, replacing the
// client-only draft.completedAt flag it previously trusted alone.
//
// FAILURE MODE (deliberate, matches ConfirmSlug's own precedent): any
// tenant-management read failure is surfaced as a plain error response,
// not silently swallowed into a default value. The frontend must treat
// this as a transient condition and offer the user a manual retry — it
// must never fall back to a client-side flag, and it must never retry
// automatically in a loop (an auto-retrying spinner with no exit is
// functionally the same hard block a fail-open default would avoid).
// @Summary Get the tenant's onboarding status
// @Description Returns whether the caller's own tenant has already
// @Description confirmed its onboarding subdomain slug.
// @Tags Onboarding
// @Produce json
// @Security BearerAuth
// @Success 200 {object} map[string]bool
// @Failure 401 {object} map[string]string
// @Failure 502 {object} map[string]string
// @Router /api/v1/auth/onboarding/status [get]
func (h *OnboardingStatusHandler) GetStatus(c *gin.Context) {
	user := middleware.GetCurrentUser(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	status, err := h.service.GetStatus(c.Request.Context(), user.TenantID)
	if err != nil {
		h.logger.Warn("onboarding: get status failed",
			zap.String("tenant_id", user.TenantID.String()),
			zap.String("user_id", user.ID.String()),
			zap.Error(err),
		)
		// Fail-closed: a transient upstream error, not a default answer.
		// The frontend must offer a manual retry at wizard entry rather
		// than either hard-blocking forever or silently trusting
		// draft.completedAt.
		c.JSON(http.StatusBadGateway, gin.H{"error": "unable to determine onboarding status, please retry"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"slugConfirmed": status.SlugConfirmed,
	})
}
