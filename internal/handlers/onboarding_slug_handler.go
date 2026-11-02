// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/services"
	"github.com/dogukanturhal/falcon-id/pkg/logger"
)

// OnboardingSlugHandler formerly backed the onboarding wizard's "choose
// your subdomain" step, RETIRED 2026-09-17. The struct and constructor are
// kept so cmd/services.go's wiring and routes.go's non-nil mount guard are
// unchanged; ConfirmSlug now answers 410 Gone.
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
	// RETIRED 2026-09-17. The onboarding wizard no longer asks for a slug:
	// signup claims it directly, with live availability checking, so asking
	// again renamed the tenant a SECOND time and orphaned the subdomain the
	// browser had already been redirected to. A real user was stranded on a
	// host that resolved to no tenant (frontend !362 removed the UI + BFF
	// route).
	//
	// Kept registered rather than deleted, matching the /derive-token
	// precedent above: a straggling client gets a deterministic 410 + a
	// Deprecation header instead of a 404 that looks like a routing bug.
	//
	// There is deliberately no replacement. The slug is immutable after
	// signup — settings/general renders it read-only and no rename mutation
	// exists anywhere. If a post-signup rename is ever wanted it needs a
	// host-migration story (redirect + session handoff to the new host),
	// not a bare UPDATE.
	c.Header("Deprecation", "true")
	c.JSON(http.StatusGone, gin.H{
		"error":             "endpoint_removed",
		"error_description": "PATCH /api/v1/auth/onboarding/slug was retired on 2026-09-17. The tenant slug is claimed during signup and is immutable afterwards; renaming it orphaned the tenant subdomain the browser was already on.",
	})
}
