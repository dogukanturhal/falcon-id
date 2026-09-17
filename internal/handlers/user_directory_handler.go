// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/middleware"
	"github.com/dogukanturhal/falcon-id/pkg/logger"
)

// ListMemberDirectory handles GET /api/v1/users/me/directory — the
// visibility-filtered directory of other members in the caller's tenant. The
// tenant + viewer are taken from the session (never the path), so it is
// peer-scoped by construction and needs no admin permission. The service
// enforces each member's profile-visibility prefs, so this never leaks a field
// a member chose to hide.
func (h *UserHandler) ListMemberDirectory(c *gin.Context) {
	cu := middleware.GetCurrentUser(c)
	if cu == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "not authenticated"})
		return
	}
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "50"))

	cards, total, err := h.userService.ListMemberDirectory(c.Request.Context(), cu.TenantID, cu.ID, page, pageSize)
	if err != nil {
		logger.Error("member directory failed",
			zap.Error(err),
			zap.String("tenant_id", cu.TenantID.String()),
			zap.String("user_id", cu.ID.String()),
		)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to load member directory"})
		return
	}
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 100 {
		pageSize = 50
	}
	c.JSON(http.StatusOK, gin.H{
		"members":   cards,
		"total":     total,
		"page":      page,
		"page_size": pageSize,
		"has_more":  page*pageSize < total,
	})
}
