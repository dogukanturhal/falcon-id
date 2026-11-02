// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/dogukanturhal/falcon-id/internal/middleware"
	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/internal/services"
)

const (
	hdrMagicLinkUserAgent = "User-Agent"
)

// MagicLinkHandler is an exported type.
type MagicLinkHandler struct {
	magicLinkService *services.MagicLinkService
}

// NewMagicLinkHandler is an exported function.
func NewMagicLinkHandler(magicLinkService *services.MagicLinkService) *MagicLinkHandler {
	return &MagicLinkHandler{
		magicLinkService: magicLinkService,
	}
}

// RequestMagicLink sends a magic link to the user's email
// @Summary Request Magic Link
// @Description Send a magic link to the user's email for passwordless login
// @Tags Auth
// @Accept json
// @Produce json
// @Param body body models.MagicLinkRequest true "Email address"
// @Success 200 {object} map[string]string
// @Failure 400 {object} map[string]string
// @Router /api/v1/auth/magic-link/request [post]
func (h *MagicLinkHandler) RequestMagicLink(c *gin.Context) {
	var req models.MagicLinkRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Valid email is required"})
		return
	}

	tenantID := middleware.GetTenantID(c)

	ipAddress := GetClientIP(c)
	userAgent := c.GetHeader(hdrMagicLinkUserAgent)

	// Always return success to prevent email enumeration
	_ = h.magicLinkService.RequestMagicLink(c.Request.Context(), tenantID, req.Email, ipAddress, userAgent)

	c.JSON(http.StatusOK, gin.H{
		"message": "If the email address is registered, you will receive a magic link shortly.",
	})
}

// VerifyMagicLink verifies a magic link token and logs the user in
// @Summary Verify Magic Link
// @Description Verify a magic link token and return authentication tokens
// @Tags Auth
// @Accept json
// @Produce json
// @Param body body models.MagicLinkVerifyRequest true "Magic link token"
// @Success 200 {object} models.LoginResponse
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Router /api/v1/auth/magic-link/verify [post]
func (h *MagicLinkHandler) VerifyMagicLink(c *gin.Context) {
	var req models.MagicLinkVerifyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Token is required"})
		return
	}

	ipAddress := GetClientIP(c)
	userAgent := c.GetHeader(hdrMagicLinkUserAgent)

	response, err := h.magicLinkService.VerifyMagicLink(c.Request.Context(), req.Token, ipAddress, userAgent)
	if err != nil {
		if respondIfTenantSuspended(c, err) {
			return
		}
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, response)
}

// VerifyMagicLinkFromQuery verifies a magic link token from URL query parameter
// @Summary Verify Magic Link (GET)
// @Description Verify a magic link token from URL and return authentication tokens
// @Tags Auth
// @Produce json
// @Param token query string true "Magic link token"
// @Success 200 {object} models.LoginResponse
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Router /api/v1/auth/magic-link/verify [get]
func (h *MagicLinkHandler) VerifyMagicLinkFromQuery(c *gin.Context) {
	token := c.Query("token")
	if token == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Token is required"})
		return
	}

	ipAddress := GetClientIP(c)
	userAgent := c.GetHeader(hdrMagicLinkUserAgent)

	response, err := h.magicLinkService.VerifyMagicLink(c.Request.Context(), token, ipAddress, userAgent)
	if err != nil {
		if respondIfTenantSuspended(c, err) {
			return
		}
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, response)
}
