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

// OnboardingVerifyHandler backs the AcmeWeb onboarding wizard's contact-
// verification steps ("Add your mobile number" / "Confirm your mobile
// number" in the Brevo-mirrored flow). IMPORTANT: the code is delivered by
// EMAIL, not SMS — see services.MFAService's onboarding-verify doc comment
// for why. The phone number itself is plain onboarding-profile data
// collected by the frontend BFF; falcon-id never dials or texts it.
type OnboardingVerifyHandler struct {
	mfaService *services.MFAService
	logger     *zap.Logger
}

// NewOnboardingVerifyHandler exported function.
func NewOnboardingVerifyHandler(mfaService *services.MFAService) *OnboardingVerifyHandler {
	return &OnboardingVerifyHandler{
		mfaService: mfaService,
		logger:     logger.Log,
	}
}

// onboardingConfirmCodeRequest is the body for POST .../verify/confirm.
type onboardingConfirmCodeRequest struct {
	Code string `json:"code" binding:"required"`
}

// SendCode emails a one-time verification code to the signed-in user's
// address for the onboarding wizard's contact-confirmation step.
// @Summary Send onboarding verification code (email)
// @Description Emails a 6-digit one-time code. No SMS is sent — this
// @Description deployment has no SMS provider configured.
// @Tags Onboarding
// @Produce json
// @Security BearerAuth
// @Success 200 {object} map[string]string
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Router /api/v1/auth/onboarding/verify/send [post]
func (h *OnboardingVerifyHandler) SendCode(c *gin.Context) {
	user := middleware.GetCurrentUser(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	if err := h.mfaService.SendOnboardingVerificationCode(c.Request.Context(), user.ID); err != nil {
		h.logger.Error("failed to send onboarding verification code",
			zap.String("user_id", user.ID.String()),
			zap.Error(err),
		)
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Verification code sent to your email"})
}

// Confirm verifies the code sent by SendCode.
// @Summary Confirm onboarding verification code
// @Tags Onboarding
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param body body onboardingConfirmCodeRequest true "Verification code"
// @Success 200 {object} map[string]bool
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Router /api/v1/auth/onboarding/verify/confirm [post]
func (h *OnboardingVerifyHandler) Confirm(c *gin.Context) {
	user := middleware.GetCurrentUser(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	var req onboardingConfirmCodeRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	valid, err := h.mfaService.ConfirmOnboardingVerificationCode(c.Request.Context(), user.ID, req.Code)
	if err != nil {
		h.logger.Error("failed to confirm onboarding verification code",
			zap.String("user_id", user.ID.String()),
			zap.Error(err),
		)
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"valid": valid})
}
