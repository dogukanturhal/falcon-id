// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/middleware"
	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/internal/services"
	"github.com/dogukanturhal/falcon-id/pkg/logger"
)

const (
	msgPushMFAInvalidRequest = "Invalid request: "
)

// PushMFAHandler exposes REST endpoints for push-notification MFA.
// Routes (registered externally in routes.go):
//
//	POST   /api/v1/auth/mfa/push/register           — RegisterDevice
//	DELETE /api/v1/auth/mfa/push/devices/:id        — UnregisterDevice
//	GET    /api/v1/auth/mfa/push/devices             — ListDevices
//	POST   /api/v1/auth/mfa/push/challenge           — InitiateChallenge
//	POST   /api/v1/auth/mfa/push/respond             — RespondToChallenge
//	GET    /api/v1/auth/mfa/push/challenge/:id/status — GetChallengeStatus
type PushMFAHandler struct {
	pushSvc *services.PushMFAService
	logger  *zap.Logger
}

// NewPushMFAHandler creates a new PushMFAHandler.
func NewPushMFAHandler(pushSvc *services.PushMFAService) *PushMFAHandler {
	return &PushMFAHandler{
		pushSvc: pushSvc,
		logger:  logger.Log,
	}
}

// RegisterDevice registers a new push-MFA device for the authenticated user.
//
//	POST /api/v1/auth/mfa/push/register
//	Body: models.RegisterDeviceRequest
//
//	200: models.RegisterDeviceResponse
//	400: invalid request
//	401: unauthorized
//	500: internal error
func (h *PushMFAHandler) RegisterDevice(c *gin.Context) {
	user := middleware.GetCurrentUser(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	var req models.RegisterDeviceRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgPushMFAInvalidRequest + err.Error()})
		return
	}

	dev, err := h.pushSvc.RegisterDevice(
		c.Request.Context(),
		user.ID,
		req.DeviceName, req.Platform, req.PushToken, req.PublicKey,
	)
	if err != nil {
		h.logger.Error("Failed to register push MFA device",
			zap.String("user_id", user.ID.String()),
			zap.Error(err),
		)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to register device"})
		return
	}

	c.JSON(http.StatusOK, models.RegisterDeviceResponse{
		DeviceID:     dev.ID,
		DeviceName:   dev.DeviceName,
		Platform:     dev.Platform,
		RegisteredAt: dev.RegisteredAt,
	})
}

// UnregisterDevice removes a push-MFA device from the authenticated user's
// account.
//
//	DELETE /api/v1/auth/mfa/push/devices/:id
//
//	200: { "message": "Device removed" }
//	400: invalid device id
//	401: unauthorized
//	404: device not found
//	500: internal error
func (h *PushMFAHandler) UnregisterDevice(c *gin.Context) {
	user := middleware.GetCurrentUser(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	deviceID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid device ID"})
		return
	}

	if err := h.pushSvc.UnregisterDevice(c.Request.Context(), deviceID, user.ID); err != nil {
		if err.Error() == msgDeviceNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "Device not found"})
			return
		}
		h.logger.Error("Failed to unregister push MFA device",
			zap.String("user_id", user.ID.String()),
			zap.String("device_id", deviceID.String()),
			zap.Error(err),
		)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to remove device"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Device removed"})
}

// ListDevices returns all push-MFA devices registered by the authenticated user.
//
//	GET /api/v1/auth/mfa/push/devices
//
//	200: models.DeviceListResponse
//	401: unauthorized
//	500: internal error
func (h *PushMFAHandler) ListDevices(c *gin.Context) {
	user := middleware.GetCurrentUser(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	devices, err := h.pushSvc.ListDevices(c.Request.Context(), user.ID)
	if err != nil {
		h.logger.Error("Failed to list push MFA devices",
			zap.String("user_id", user.ID.String()),
			zap.Error(err),
		)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list devices"})
		return
	}

	resp := models.PushDeviceListResponse{
		Devices: make([]models.PushDeviceResponse, 0, len(devices)),
		Total:   len(devices),
	}
	for _, d := range devices {
		resp.Devices = append(resp.Devices, models.PushDeviceResponse{
			ID:           d.ID,
			DeviceName:   d.DeviceName,
			Platform:     d.Platform,
			RegisteredAt: d.RegisteredAt,
			LastUsedAt:   d.LastUsedAt,
		})
	}

	c.JSON(http.StatusOK, resp)
}

// InitiateChallenge creates a push MFA challenge and delivers a notification
// to the user's registered devices. This endpoint is typically called by the
// login flow (server-side) on behalf of a partially-authenticated user and
// therefore accepts userID/tenantID in the request body rather than relying
// on an authenticated session.
//
// The calling code is responsible for validating the MFA session (e.g. the
// temporary session_id from the password-check step) before invoking this.
//
//	POST /api/v1/auth/mfa/push/challenge
//	Body: models.InitiatePushChallengeRequest
//
//	200: models.PushChallengeResponse
//	400: invalid request / no devices registered
//	500: internal error
func (h *PushMFAHandler) InitiateChallenge(c *gin.Context) {
	var req models.InitiatePushChallengeRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgPushMFAInvalidRequest + err.Error()})
		return
	}

	userID, err := uuid.Parse(req.UserID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user_id"})
		return
	}
	tenantID, err := uuid.Parse(req.TenantID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid tenant_id"})
		return
	}

	ipAddress := GetClientIP(c)
	userAgent := c.Request.UserAgent()

	challenge, err := h.pushSvc.SendPushChallenge(
		c.Request.Context(),
		userID, tenantID,
		ipAddress, userAgent, "",
	)
	if err != nil {
		h.logger.Error("Failed to create push MFA challenge",
			zap.String("user_id", userID.String()),
			zap.Error(err),
		)
		// Surface "no devices registered" as 400 so the login UI can fall back
		// to another MFA method.
		if err.Error() == "no push MFA devices registered for this user" {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to initiate push challenge"})
		return
	}

	c.JSON(http.StatusOK, models.PushChallengeResponse{
		ChallengeID: challenge.ID,
		ExpiresAt:   challenge.ExpiresAt,
		Message:     "Push notification sent. Approve the login request on your device.",
	})
}

// RespondToChallenge is called by the mobile authenticator app to approve or
// deny a push challenge. It does not require a bearer token — the challenge ID
// itself is the secret shared with the device.
//
//	POST /api/v1/auth/mfa/push/respond
//	Body: models.RespondToChallengeRequest
//
//	200: { "message": "Response recorded" }
//	400: invalid request / challenge already resolved
//	404: challenge not found
//	500: internal error
func (h *PushMFAHandler) RespondToChallenge(c *gin.Context) {
	var req models.RespondToChallengeRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgPushMFAInvalidRequest + err.Error()})
		return
	}

	challengeID, err := uuid.Parse(req.ChallengeID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid challenge_id"})
		return
	}

	if err := h.pushSvc.RespondToChallenge(c.Request.Context(), challengeID, req.Approved, req.Signature); err != nil {
		h.logger.Warn("Push MFA challenge response rejected",
			zap.String("challenge_id", challengeID.String()),
			zap.Error(err),
		)
		if err.Error() == "challenge not found" {
			c.JSON(http.StatusNotFound, gin.H{"error": "Challenge not found"})
			return
		}
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Response recorded"})
}

// GetChallengeStatus returns the current status of a push challenge. The login
// page polls this endpoint after sending the push notification.
//
// For production, prefer using WaitForResponse with server-sent events or
// a long-polling variant to reduce HTTP round-trips.
//
//	GET /api/v1/auth/mfa/push/challenge/:id/status
//
//	200: models.ChallengeStatusResponse
//	400: invalid challenge ID
//	404: challenge not found
//	500: internal error
func (h *PushMFAHandler) GetChallengeStatus(c *gin.Context) {
	challengeID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid challenge ID"})
		return
	}

	challenge, err := h.pushSvc.GetChallengeStatus(c.Request.Context(), challengeID)
	if err != nil {
		if err.Error() == "challenge not found" {
			c.JSON(http.StatusNotFound, gin.H{"error": "Challenge not found"})
			return
		}
		h.logger.Error("Failed to get push MFA challenge status",
			zap.String("challenge_id", challengeID.String()),
			zap.Error(err),
		)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get challenge status"})
		return
	}

	c.JSON(http.StatusOK, models.ChallengeStatusResponse{
		ChallengeID: challenge.ID,
		Status:      challenge.Status,
		ExpiresAt:   challenge.ExpiresAt,
		RespondedAt: challenge.RespondedAt,
	})
}

// WaitForChallengeResponse is a long-poll variant of GetChallengeStatus. The
// request blocks until the challenge is resolved or up to 30 seconds, whichever
// comes first. This reduces polling frequency for login-page implementations.
//
//	GET /api/v1/auth/mfa/push/challenge/:id/wait
//
//	200: models.ChallengeStatusResponse
//	400: invalid challenge ID
//	408: timeout (challenge still pending)
//	500: internal error
func (h *PushMFAHandler) WaitForChallengeResponse(c *gin.Context) {
	challengeID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid challenge ID"})
		return
	}

	const longPollTimeout = 30 * time.Second
	challenge, err := h.pushSvc.WaitForResponse(c.Request.Context(), challengeID, longPollTimeout)
	if err != nil {
		h.logger.Warn("Push MFA long-poll ended",
			zap.String("challenge_id", challengeID.String()),
			zap.Error(err),
		)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to wait for challenge response"})
		return
	}

	if challenge.Status == models.PushChallengeStatusPending {
		// Timeout reached without a response.
		c.JSON(http.StatusRequestTimeout, models.ChallengeStatusResponse{
			ChallengeID: challenge.ID,
			Status:      challenge.Status,
			ExpiresAt:   challenge.ExpiresAt,
		})
		return
	}

	c.JSON(http.StatusOK, models.ChallengeStatusResponse{
		ChallengeID: challenge.ID,
		Status:      challenge.Status,
		ExpiresAt:   challenge.ExpiresAt,
		RespondedAt: challenge.RespondedAt,
	})
}
