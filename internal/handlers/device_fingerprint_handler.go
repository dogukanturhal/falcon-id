// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"context"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/middleware"
	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/pkg/logger"
)

const (
	msgNotAuthenticatedFingerprint = "Not authenticated"
	msgInternalErrorFingerprint    = "An internal error occurred"
)

// deviceFingerprintServiceIface is the narrow interface consumed by
// DeviceFingerprintHandler. Declaring an interface here lets tests inject
// a mock without depending on the concrete service type.
type deviceFingerprintServiceIface interface {
	ListUserDevices(ctx context.Context, userID, tenantID uuid.UUID) ([]models.DeviceFingerprintRecord, error)
	TrustDevice(ctx context.Context, deviceID, userID uuid.UUID) error
	RevokeDevice(ctx context.Context, deviceID, userID uuid.UUID) error
}

// DeviceFingerprintHandler exposes user-facing endpoints for the richer
// iam_device_fingerprints store introduced in migration 157.
//
// Routes (registered externally in cmd/routes.go):
//
//	GET    /api/v1/auth/fingerprints         — list my fingerprinted devices
//	DELETE /api/v1/auth/fingerprints/:id     — revoke a fingerprinted device
//	POST   /api/v1/auth/fingerprints/:id/trust — explicitly trust a device
type DeviceFingerprintHandler struct {
	fpService deviceFingerprintServiceIface
}

// NewDeviceFingerprintHandler creates a new DeviceFingerprintHandler.
func NewDeviceFingerprintHandler(fpService deviceFingerprintServiceIface) *DeviceFingerprintHandler {
	return &DeviceFingerprintHandler{fpService: fpService}
}

// ListDeviceFingerprints returns all fingerprint records for the authenticated user.
//
// @Summary List device fingerprints
// @Description Returns all known device fingerprints for the current user.
// @Tags Devices
// @Produce json
// @Security BearerAuth
// @Success 200 {object} models.DeviceFingerprintListResponse
// @Failure 401 {object} map[string]string
// @Router /api/v1/auth/fingerprints [get]
func (h *DeviceFingerprintHandler) ListDeviceFingerprints(c *gin.Context) {
	user := middleware.GetCurrentUser(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": msgNotAuthenticatedFingerprint})
		return
	}

	records, err := h.fpService.ListUserDevices(c.Request.Context(), user.ID, user.TenantID)
	if err != nil {
		logger.Log.Error("ListDeviceFingerprints: failed to list",
			zap.String("user_id", user.ID.String()),
			zap.Error(err),
		)
		c.JSON(http.StatusInternalServerError, gin.H{"error": msgInternalErrorFingerprint})
		return
	}

	responses := make([]models.DeviceFingerprintRecordResponse, len(records))
	for i := range records {
		responses[i] = records[i].ToResponse()
	}

	c.JSON(http.StatusOK, models.DeviceFingerprintListResponse{
		Devices: responses,
		Total:   len(responses),
	})
}

// TrustDeviceFingerprint marks a fingerprint record as explicitly trusted.
// The user typically calls this after a successful MFA challenge so future
// logins from the same device skip the challenge.
//
// @Summary Trust a device fingerprint
// @Description Mark a device fingerprint as trusted (bypasses adaptive MFA on subsequent logins).
// @Tags Devices
// @Produce json
// @Security BearerAuth
// @Param id path string true "Device fingerprint ID"
// @Success 200 {object} map[string]string
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Failure 404 {object} map[string]string
// @Router /api/v1/auth/fingerprints/{id}/trust [post]
func (h *DeviceFingerprintHandler) TrustDeviceFingerprint(c *gin.Context) {
	user := middleware.GetCurrentUser(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": msgNotAuthenticatedFingerprint})
		return
	}

	deviceID, err := parseUUID(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid device fingerprint ID"})
		return
	}

	if err := h.fpService.TrustDevice(c.Request.Context(), deviceID, user.ID); err != nil {
		if isFingerprintNotFound(err) {
			c.JSON(http.StatusNotFound, gin.H{"error": "Device fingerprint not found"})
			return
		}
		logger.Log.Error("TrustDeviceFingerprint: failed",
			zap.String("device_id", deviceID.String()),
			zap.String("user_id", user.ID.String()),
			zap.Error(err),
		)
		c.JSON(http.StatusInternalServerError, gin.H{"error": msgInternalErrorFingerprint})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Device fingerprint trusted successfully"})
}

// RevokeDeviceFingerprint removes a fingerprint record for the authenticated
// user. Subsequent logins from the same device will be treated as "new" and
// may trigger an MFA challenge.
//
// @Summary Revoke a device fingerprint
// @Description Remove a device fingerprint from the trust store. The device will be treated as new on next login.
// @Tags Devices
// @Produce json
// @Security BearerAuth
// @Param id path string true "Device fingerprint ID"
// @Success 200 {object} map[string]string
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Failure 404 {object} map[string]string
// @Router /api/v1/auth/fingerprints/{id} [delete]
func (h *DeviceFingerprintHandler) RevokeDeviceFingerprint(c *gin.Context) {
	user := middleware.GetCurrentUser(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": msgNotAuthenticatedFingerprint})
		return
	}

	deviceID, err := parseUUID(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid device fingerprint ID"})
		return
	}

	if err := h.fpService.RevokeDevice(c.Request.Context(), deviceID, user.ID); err != nil {
		if isFingerprintNotFound(err) {
			c.JSON(http.StatusNotFound, gin.H{"error": "Device fingerprint not found"})
			return
		}
		logger.Log.Error("RevokeDeviceFingerprint: failed",
			zap.String("device_id", deviceID.String()),
			zap.String("user_id", user.ID.String()),
			zap.Error(err),
		)
		c.JSON(http.StatusInternalServerError, gin.H{"error": msgInternalErrorFingerprint})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Device fingerprint revoked successfully"})
}

// isFingerprintNotFound returns true for the sentinel "not found" errors
// returned by DeviceFingerprintService (both "not found" and ownership checks).
func isFingerprintNotFound(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return msg == "TrustDevice: device fingerprint not found" ||
		msg == "RevokeDevice: device fingerprint not found"
}
