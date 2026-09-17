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
	msgNotAuthenticatedDevice = "Not authenticated"
	msgInternalErrorDevice    = "An internal error occurred"
	msgInvalidDeviceID        = "Invalid device ID"
	msgDeviceNotFound         = "device not found"
	msgDeviceNotBelongToUser  = "device does not belong to user"
)

// DeviceHandler is an exported type.
type DeviceHandler struct {
	deviceService *services.DeviceService
}

// NewDeviceHandler is an exported function.
func NewDeviceHandler(deviceService *services.DeviceService) *DeviceHandler {
	return &DeviceHandler{
		deviceService: deviceService,
	}
}

// ListDevices returns all devices for the current user
// @Summary List Devices
// @Description Get all devices for the current user
// @Tags Devices
// @Produce json
// @Security BearerAuth
// @Param page query int false "Page number" default(1)
// @Param page_size query int false "Page size" default(20)
// @Success 200 {object} models.DeviceListResponse
// @Failure 401 {object} map[string]string
// @Router /api/v1/auth/devices [get]
func (h *DeviceHandler) ListDevices(c *gin.Context) {
	user := middleware.GetCurrentUser(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": msgNotAuthenticatedDevice})
		return
	}

	// SECURITY: Use GetPagination to enforce max page size of 100
	page, pageSize, _ := GetPagination(c)

	response, err := h.deviceService.GetUserDevices(c.Request.Context(), user.ID, page, pageSize)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": msgInternalErrorDevice})
		return
	}

	c.JSON(http.StatusOK, response)
}

// GetDevice returns a specific device
// @Summary Get Device
// @Description Get a specific device by ID
// @Tags Devices
// @Produce json
// @Security BearerAuth
// @Param id path string true "Device ID"
// @Success 200 {object} models.DeviceResponse
// @Failure 401 {object} map[string]string
// @Failure 404 {object} map[string]string
// @Router /api/v1/auth/devices/{id} [get]
func (h *DeviceHandler) GetDevice(c *gin.Context) {
	user := middleware.GetCurrentUser(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": msgNotAuthenticatedDevice})
		return
	}

	deviceID, err := parseUUID(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgInvalidDeviceID})
		return
	}

	device, err := h.deviceService.GetDevice(c.Request.Context(), deviceID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": msgInternalErrorDevice})
		return
	}
	if device == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Device not found"})
		return
	}
	if device.UserID != user.ID {
		c.JSON(http.StatusNotFound, gin.H{"error": "Device not found"})
		return
	}

	c.JSON(http.StatusOK, device.ToResponse())
}

// TrustDevice marks a device as trusted
// @Summary Trust Device
// @Description Mark a device as trusted (can skip MFA)
// @Tags Devices
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param id path string true "Device ID"
// @Param body body models.TrustDeviceRequest false "Trust options"
// @Success 200 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Failure 404 {object} map[string]string
// @Router /api/v1/auth/devices/{id}/trust [post]
func (h *DeviceHandler) TrustDevice(c *gin.Context) {
	user := middleware.GetCurrentUser(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": msgNotAuthenticatedDevice})
		return
	}

	deviceID, err := parseUUID(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgInvalidDeviceID})
		return
	}

	var req models.TrustDeviceRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request: " + err.Error()})
		return
	}

	err = h.deviceService.TrustDevice(c.Request.Context(), user.ID, deviceID, req.TrustDuration)
	if err != nil {
		if err.Error() == msgDeviceNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
			return
		}
		if err.Error() == msgDeviceNotBelongToUser {
			c.JSON(http.StatusForbidden, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": msgInternalErrorDevice})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Device trusted successfully"})
}

// UntrustDevice removes trust from a device
// @Summary Untrust Device
// @Description Remove trust from a device (will require MFA again)
// @Tags Devices
// @Produce json
// @Security BearerAuth
// @Param id path string true "Device ID"
// @Success 200 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Failure 404 {object} map[string]string
// @Router /api/v1/auth/devices/{id}/trust [delete]
func (h *DeviceHandler) UntrustDevice(c *gin.Context) {
	user := middleware.GetCurrentUser(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": msgNotAuthenticatedDevice})
		return
	}

	deviceID, err := parseUUID(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgInvalidDeviceID})
		return
	}

	err = h.deviceService.UntrustDevice(c.Request.Context(), user.ID, deviceID)
	if err != nil {
		if err.Error() == msgDeviceNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
			return
		}
		if err.Error() == msgDeviceNotBelongToUser {
			c.JSON(http.StatusForbidden, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": msgInternalErrorDevice})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Device trust removed"})
}

// DeleteDevice removes a device from the user's account
// @Summary Delete Device
// @Description Remove a device from your account
// @Tags Devices
// @Produce json
// @Security BearerAuth
// @Param id path string true "Device ID"
// @Success 200 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Failure 404 {object} map[string]string
// @Router /api/v1/auth/devices/{id} [delete]
func (h *DeviceHandler) DeleteDevice(c *gin.Context) {
	user := middleware.GetCurrentUser(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": msgNotAuthenticatedDevice})
		return
	}

	deviceID, err := parseUUID(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgInvalidDeviceID})
		return
	}

	err = h.deviceService.DeleteDevice(c.Request.Context(), user.ID, deviceID)
	if err != nil {
		if err.Error() == msgDeviceNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
			return
		}
		if err.Error() == msgDeviceNotBelongToUser {
			c.JSON(http.StatusForbidden, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": msgInternalErrorDevice})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Device removed successfully"})
}

// RenameDevice updates the device name
// @Summary Rename Device
// @Description Update the device name
// @Tags Devices
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param id path string true "Device ID"
// @Param body body map[string]string true "Device name"
// @Success 200 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Failure 404 {object} map[string]string
// @Router /api/v1/auth/devices/{id}/rename [put]
func (h *DeviceHandler) RenameDevice(c *gin.Context) {
	user := middleware.GetCurrentUser(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": msgNotAuthenticatedDevice})
		return
	}

	deviceID, err := parseUUID(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgInvalidDeviceID})
		return
	}

	var req struct {
		Name string `json:"name" binding:"required,min=1,max=255"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request: name is required (max 255 characters)"})
		return
	}

	err = h.deviceService.RenameDevice(c.Request.Context(), user.ID, deviceID, req.Name)
	if err != nil {
		if err.Error() == msgDeviceNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
			return
		}
		if err.Error() == msgDeviceNotBelongToUser {
			c.JSON(http.StatusForbidden, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": msgInternalErrorDevice})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Device renamed successfully"})
}
