// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/services"
)

// BackchannelLogoutHandler handles the OAuth back-channel logout receive endpoint.
// It acts as a relying party receiving logout notifications from upstream IDPs.
type BackchannelLogoutHandler struct {
	svc    *services.BackchannelLogoutService
	logger *zap.Logger
}

// NewBackchannelLogoutHandler constructs a BackchannelLogoutHandler.
func NewBackchannelLogoutHandler(svc *services.BackchannelLogoutService, logger *zap.Logger) *BackchannelLogoutHandler {
	return &BackchannelLogoutHandler{svc: svc, logger: logger}
}

// Receive processes an incoming back-channel logout token.
// The token is expected as a form parameter named "logout_token" per
// OpenID Connect Back-Channel Logout 1.0 §2.4.
//
// POST /api/v1/oauth/backchannel-logout
func (h *BackchannelLogoutHandler) Receive(c *gin.Context) {
	logoutToken := c.PostForm("logout_token")
	if logoutToken == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing logout_token"})
		return
	}

	sub, err := h.svc.Receive(c.Request.Context(), logoutToken)
	if err != nil {
		h.logger.Warn("BackchannelLogout.Receive: token validation failed",
			zap.Error(err),
		)
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid logout_token"})
		return
	}

	h.logger.Info("Back-channel logout processed", zap.String("sub", sub))
	c.Status(http.StatusOK)
}
