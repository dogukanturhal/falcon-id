// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/middleware"
)

const (
	msgDeviceServiceNotConfigured = "Device service not configured"
	msgNotAuthenticatedDev        = "Not authenticated"
	msgInvalidUserIDDev           = "Invalid user ID"
)

// GetUserDevices returns all devices for a specific user (admin)
// @Summary Get User Devices
// @Description Get all devices for a specific user (admin only)
// @Tags Admin
// @Produce json
// @Security BearerAuth
// @Param id path string true "User ID"
// @Param page query int false "Page number" default(1)
// @Param page_size query int false "Page size" default(20)
// @Success 200 {object} models.DeviceListResponse
// @Failure 401 {object} map[string]string
// @Failure 404 {object} map[string]string
// @Router /api/admin/users/{id}/devices [get]
func (h *AdminHandler) GetUserDevices(c *gin.Context) {
	if h.deviceService == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": msgDeviceServiceNotConfigured})
		return
	}

	currentUser := middleware.GetCurrentUser(c)
	if currentUser == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": msgNotAuthenticatedDev})
		return
	}

	userID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgInvalidUserIDDev})
		return
	}

	if err := h.validateUserTenantAccess(c.Request.Context(), userID, currentUser); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}

	page := 1
	pageSize := 20

	if p := c.Query("page"); p != "" {
		if parsed, err := strconv.Atoi(p); err == nil && parsed > 0 {
			page = parsed
		}
	}
	if ps := c.Query("page_size"); ps != "" {
		if parsed, err := strconv.Atoi(ps); err == nil && parsed > 0 {
			pageSize = parsed
		}
	}

	response, err := h.deviceService.GetUserDevices(c.Request.Context(), userID, page, pageSize)
	if err != nil {
		h.logger.Error("Failed to get user devices", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get user devices"})
		return
	}

	c.JSON(http.StatusOK, response)
}

// AdminDeleteUserDevice removes a device from a user's account (admin)
// @Summary Delete User Device
// @Description Remove a device from a user's account (admin only)
// @Tags Admin
// @Produce json
// @Security BearerAuth
// @Param id path string true "User ID"
// @Param device_id path string true "Device ID"
// @Success 200 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Failure 404 {object} map[string]string
// @Router /api/admin/users/{id}/devices/{device_id} [delete]
func (h *AdminHandler) AdminDeleteUserDevice(c *gin.Context) {
	if h.deviceService == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": msgDeviceServiceNotConfigured})
		return
	}

	currentUser := middleware.GetCurrentUser(c)
	if currentUser == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": msgNotAuthenticatedDev})
		return
	}

	userID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgInvalidUserIDDev})
		return
	}

	if err := h.validateUserTenantAccess(c.Request.Context(), userID, currentUser); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}

	deviceID, err := uuid.Parse(c.Param("device_id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid device ID"})
		return
	}

	err = h.deviceService.DeleteDevice(c.Request.Context(), userID, deviceID)
	if err != nil {
		if err.Error() == msgDeviceNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "Device not found"})
			return
		}
		h.logger.Error("Failed to delete user device", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete device"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Device removed successfully"})
}

// AdminUntrustUserDevice removes trust from a user's device (admin)
// @Summary Untrust User Device
// @Description Remove trust from a user's device (admin only)
// @Tags Admin
// @Produce json
// @Security BearerAuth
// @Param id path string true "User ID"
// @Param device_id path string true "Device ID"
// @Success 200 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Failure 404 {object} map[string]string
// @Router /api/admin/users/{id}/devices/{device_id}/untrust [post]
func (h *AdminHandler) AdminUntrustUserDevice(c *gin.Context) {
	if h.deviceService == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": msgDeviceServiceNotConfigured})
		return
	}

	currentUser := middleware.GetCurrentUser(c)
	if currentUser == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": msgNotAuthenticatedDev})
		return
	}

	userID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgInvalidUserIDDev})
		return
	}

	if err := h.validateUserTenantAccess(c.Request.Context(), userID, currentUser); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}

	deviceID, err := uuid.Parse(c.Param("device_id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid device ID"})
		return
	}

	err = h.deviceService.UntrustDevice(c.Request.Context(), userID, deviceID)
	if err != nil {
		if err.Error() == msgDeviceNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "Device not found"})
			return
		}
		h.logger.Error("Failed to untrust user device", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to untrust device"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Device trust removed"})
}
