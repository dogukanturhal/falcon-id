// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/authorization"
	"github.com/dogukanturhal/falcon-id/internal/middleware"
	"github.com/dogukanturhal/falcon-id/internal/services"
	"github.com/dogukanturhal/falcon-id/pkg/logger"
)

// OnboardingSlugHandler backs the onboarding wizard's "choose your
// subdomain" step.
type OnboardingSlugHandler struct {
	service *services.OnboardingSlugService
	logger  *zap.Logger
}

// NewOnboardingSlugHandler exported constructor.
func NewOnboardingSlugHandler(service *services.OnboardingSlugService) *OnboardingSlugHandler {
	return &OnboardingSlugHandler{
		service: service,
		logger:  logger.Log,
	}
}

// onboardingSlugRequest is the body for PATCH .../onboarding/slug.
type onboardingSlugRequest struct {
	Slug string `json:"slug" binding:"required"`
}

// ConfirmSlug renames the signed-in user's tenant's subdomain slug and
// activates it in host-discovery.
// @Summary Confirm/change the tenant's onboarding subdomain slug
// @Description Requires a tenant-admin-level role. Rejects malformed or
// @Description reserved slugs and refuses the rename once the tenant's
// @Description slug has already been confirmed once.
// @Tags Onboarding
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param body body onboardingSlugRequest true "Requested slug"
// @Success 200 {object} map[string]string
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Failure 403 {object} map[string]string
// @Router /api/v1/auth/onboarding/slug [patch]
func (h *OnboardingSlugHandler) ConfirmSlug(c *gin.Context) {
	user := middleware.GetCurrentUser(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	if !user.IsPlatformAdmin && !hasAnyTenantSlugAdminRole(user.Roles) {
		c.JSON(http.StatusForbidden, gin.H{"error": "Tenant admin access required"})
		return
	}

	var req onboardingSlugRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	slug := strings.ToLower(strings.TrimSpace(req.Slug))

	result, err := h.service.ConfirmSlug(c.Request.Context(), user.TenantID, slug)
	if err != nil {
		h.logger.Warn("onboarding: confirm slug failed",
			zap.String("tenant_id", user.TenantID.String()),
			zap.String("user_id", user.ID.String()),
			zap.Error(err),
		)
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"tenant_id": result.TenantID,
		"slug":      result.Slug,
		"host":      result.Host,
	})
}

func hasAnyTenantSlugAdminRole(roles []string) bool {
	for _, role := range roles {
		if authorization.IsTenantAdministratorRole(role) {
			return true
		}
	}
	return false
}
