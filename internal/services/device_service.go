// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/pkg/logger"
	"go.uber.org/zap"
)

// deviceServiceDeviceRepo defines the device repository methods needed by DeviceService.
type deviceServiceDeviceRepo interface {
	UpsertDevice(ctx context.Context, device *models.Device) error
	GetByUserID(ctx context.Context, userID uuid.UUID, page, pageSize int) ([]models.Device, int64, error)
	GetByID(ctx context.Context, id uuid.UUID) (*models.Device, error)
	TrustDevice(ctx context.Context, id uuid.UUID, expiresAt *time.Time) error
	UntrustDevice(ctx context.Context, id uuid.UUID) error
	Delete(ctx context.Context, id uuid.UUID) error
	IsTrustedDevice(ctx context.Context, userID uuid.UUID, fingerprintHash string) (bool, error)
	CleanupExpiredTrust(ctx context.Context) (int64, error)
	Update(ctx context.Context, device *models.Device) error
	GetByFingerprint(ctx context.Context, userID uuid.UUID, fingerprintHash string) (*models.Device, error)
}

// DeviceService is an exported type.
type DeviceService struct {
	deviceRepo deviceServiceDeviceRepo
}

// NewDeviceService is an exported function.
func NewDeviceService(deviceRepo deviceServiceDeviceRepo) *DeviceService {
	return &DeviceService{
		deviceRepo: deviceRepo,
	}
}

// GenerateFingerprint creates a hash from device fingerprint data
func (s *DeviceService) GenerateFingerprint(fp *models.DeviceFingerprint) string {
	// Combine relevant fingerprint attributes
	data := fmt.Sprintf("%s|%d|%d|%d|%s|%s|%s|%s|%s|%s|%s|%d|%d",
		fp.UserAgent,
		fp.ScreenWidth,
		fp.ScreenHeight,
		fp.ColorDepth,
		fp.Timezone,
		fp.Language,
		fp.Platform,
		fp.CanvasHash,
		fp.WebGLVendor,
		fp.WebGLRenderer,
		fp.FontsHash,
		fp.HardwareConcurrency,
		fp.DeviceMemory,
	)

	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}

// GenerateSimpleFingerprint creates a simpler fingerprint from user agent
// Used when full fingerprint data is not available
func (s *DeviceService) GenerateSimpleFingerprint(userAgent, _ string) string {
	// Simple fingerprint based on user agent components
	data := fmt.Sprintf("%s|%s", userAgent, s.extractStableUA(userAgent))
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}

// extractStableUA extracts stable components from user agent (browser, OS)
func (s *DeviceService) extractStableUA(userAgent string) string {
	// Extract OS and browser info that won't change frequently
	var os, browser string

	// Detect OS
	switch {
	case strings.Contains(userAgent, "Windows"):
		os = devicePlatformWindows
	case strings.Contains(userAgent, "Mac OS X"):
		os = devicePlatformMacOS
	case strings.Contains(userAgent, "Linux"):
		os = devicePlatformLinux
	case strings.Contains(userAgent, "Android"):
		os = devicePlatformAndroid
	case strings.Contains(userAgent, "iPhone"), strings.Contains(userAgent, "iPad"):
		os = devicePlatformIOS
	default:
		os = deviceValueUnknown
	}

	// Detect Browser
	switch {
	case strings.Contains(userAgent, "Edg/"):
		browser = deviceBrowserEdge
	case strings.Contains(userAgent, "Chrome/"):
		browser = deviceBrowserChrome
	case strings.Contains(userAgent, "Firefox/"):
		browser = deviceBrowserFirefox
	case strings.Contains(userAgent, "Safari/") && !strings.Contains(userAgent, "Chrome"):
		browser = deviceBrowserSafari
	default:
		browser = deviceValueUnknown
	}

	return fmt.Sprintf("%s|%s", os, browser)
}

// ParseUserAgent extracts device info from user agent string
func (s *DeviceService) ParseUserAgent(userAgent string) (deviceType, browser, os string) {
	deviceType = string(models.DeviceTypeDesktop)
	browser = deviceValueUnknown
	os = deviceValueUnknown

	// Detect OS — check mobile/tablet tokens first because Android UAs contain
	// "Linux" and iOS UAs contain "Mac OS X", which would otherwise match first.
	switch {
	case strings.Contains(userAgent, "Android"):
		os = devicePlatformAndroid
		deviceType = string(models.DeviceTypeMobile)
	case strings.Contains(userAgent, "iPhone"):
		os = devicePlatformIOS
		deviceType = string(models.DeviceTypeMobile)
	case strings.Contains(userAgent, "iPad"):
		os = "iPadOS"
		deviceType = string(models.DeviceTypeTablet)
	case strings.Contains(userAgent, "Windows NT 10"):
		os = "Windows 10/11"
	case strings.Contains(userAgent, "Windows NT 6.3"):
		os = "Windows 8.1"
	case strings.Contains(userAgent, "Windows"):
		os = devicePlatformWindows
	case strings.Contains(userAgent, "Mac OS X"):
		os = devicePlatformMacOS
	case strings.Contains(userAgent, "Linux"):
		os = devicePlatformLinux
	}

	// Detect Browser
	switch {
	case strings.Contains(userAgent, "Edg/"):
		browser = deviceBrowserEdge
	case strings.Contains(userAgent, "Chrome/"):
		browser = deviceBrowserChrome
	case strings.Contains(userAgent, "Firefox/"):
		browser = deviceBrowserFirefox
	case strings.Contains(userAgent, "Safari/") && !strings.Contains(userAgent, "Chrome"):
		browser = deviceBrowserSafari
	case strings.Contains(userAgent, "Opera"), strings.Contains(userAgent, "OPR/"):
		browser = "Opera"
	}

	return deviceType, browser, os
}

// RecordDevice records or updates a device for a user
func (s *DeviceService) RecordDevice(ctx context.Context, userID uuid.UUID, userAgent, ip string, fingerprint *models.DeviceFingerprint) (*models.Device, error) {
	var fingerprintHash string
	if fingerprint != nil {
		fingerprintHash = s.GenerateFingerprint(fingerprint)
	} else {
		fingerprintHash = s.GenerateSimpleFingerprint(userAgent, ip)
	}

	deviceType, browser, os := s.ParseUserAgent(userAgent)
	deviceName := fmt.Sprintf("%s on %s", browser, os)

	device := &models.Device{
		UserID:          userID,
		FingerprintHash: fingerprintHash,
		DeviceName:      &deviceName,
		DeviceType:      &deviceType,
		Browser:         &browser,
		OS:              &os,
		LastIP:          &ip,
	}

	err := s.deviceRepo.UpsertDevice(ctx, device)
	if err != nil {
		return nil, fmt.Errorf("failed to record device: %w", err)
	}

	return device, nil
}

// GetUserDevices retrieves all devices for a user
func (s *DeviceService) GetUserDevices(ctx context.Context, userID uuid.UUID, page, pageSize int) (*models.DeviceListResponse, error) {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 100 {
		pageSize = 20
	}

	devices, total, err := s.deviceRepo.GetByUserID(ctx, userID, page, pageSize)
	if err != nil {
		return nil, fmt.Errorf("failed to get devices: %w", err)
	}

	responses := make([]models.DeviceResponse, len(devices))
	for i, device := range devices {
		responses[i] = *device.ToResponse()
	}

	totalPages := int((total + int64(pageSize) - 1) / int64(pageSize))

	return &models.DeviceListResponse{
		Devices:    responses,
		Total:      total,
		Page:       page,
		PageSize:   pageSize,
		TotalPages: totalPages,
	}, nil
}

// GetDevice retrieves a specific device
func (s *DeviceService) GetDevice(ctx context.Context, deviceID uuid.UUID) (*models.Device, error) {
	return s.deviceRepo.GetByID(ctx, deviceID)
}

// TrustDevice marks a device as trusted
func (s *DeviceService) TrustDevice(ctx context.Context, userID, deviceID uuid.UUID, duration string) error {
	device, err := s.deviceRepo.GetByID(ctx, deviceID)
	if err != nil {
		return fmt.Errorf("failed to get device: %w", err)
	}
	if device == nil {
		return fmt.Errorf("device not found")
	}
	if device.UserID != userID {
		return fmt.Errorf("device does not belong to user")
	}

	var expiresAt *time.Time
	switch duration {
	case "30d":
		t := time.Now().Add(30 * 24 * time.Hour)
		expiresAt = &t
	case "90d":
		t := time.Now().Add(90 * 24 * time.Hour)
		expiresAt = &t
	case "180d":
		t := time.Now().Add(180 * 24 * time.Hour)
		expiresAt = &t
	case "365d", "1y":
		t := time.Now().Add(365 * 24 * time.Hour)
		expiresAt = &t
	case "forever", "":
		// No expiration
		expiresAt = nil
	default:
		// Default to 30 days
		t := time.Now().Add(30 * 24 * time.Hour)
		expiresAt = &t
	}

	err = s.deviceRepo.TrustDevice(ctx, deviceID, expiresAt)
	if err != nil {
		return fmt.Errorf("failed to trust device: %w", err)
	}

	logger.Info("Device trusted",
		zap.String("device_id", deviceID.String()),
		zap.String("user_id", userID.String()),
	)

	return nil
}

// UntrustDevice removes trust from a device
func (s *DeviceService) UntrustDevice(ctx context.Context, userID, deviceID uuid.UUID) error {
	device, err := s.deviceRepo.GetByID(ctx, deviceID)
	if err != nil {
		return fmt.Errorf("failed to get device: %w", err)
	}
	if device == nil {
		return fmt.Errorf("device not found")
	}
	if device.UserID != userID {
		return fmt.Errorf("device does not belong to user")
	}

	err = s.deviceRepo.UntrustDevice(ctx, deviceID)
	if err != nil {
		return fmt.Errorf("failed to untrust device: %w", err)
	}

	logger.Info("Device untrusted",
		zap.String("device_id", deviceID.String()),
		zap.String("user_id", userID.String()),
	)

	return nil
}

// DeleteDevice removes a device
func (s *DeviceService) DeleteDevice(ctx context.Context, userID, deviceID uuid.UUID) error {
	device, err := s.deviceRepo.GetByID(ctx, deviceID)
	if err != nil {
		return fmt.Errorf("failed to get device: %w", err)
	}
	if device == nil {
		return fmt.Errorf("device not found")
	}
	if device.UserID != userID {
		return fmt.Errorf("device does not belong to user")
	}

	err = s.deviceRepo.Delete(ctx, deviceID)
	if err != nil {
		return fmt.Errorf("failed to delete device: %w", err)
	}

	logger.Info("Device deleted",
		zap.String("device_id", deviceID.String()),
		zap.String("user_id", userID.String()),
	)

	return nil
}

// IsTrustedDevice checks if the current device is trusted for the user
func (s *DeviceService) IsTrustedDevice(ctx context.Context, userID uuid.UUID, userAgent, ip string, fingerprint *models.DeviceFingerprint) (bool, error) {
	var fingerprintHash string
	if fingerprint != nil {
		fingerprintHash = s.GenerateFingerprint(fingerprint)
	} else {
		fingerprintHash = s.GenerateSimpleFingerprint(userAgent, ip)
	}

	return s.deviceRepo.IsTrustedDevice(ctx, userID, fingerprintHash)
}

// CleanupExpiredTrust removes trust from devices with expired trust
func (s *DeviceService) CleanupExpiredTrust(ctx context.Context) (int64, error) {
	count, err := s.deviceRepo.CleanupExpiredTrust(ctx)
	if err != nil {
		return 0, fmt.Errorf("failed to cleanup expired trust: %w", err)
	}

	if count > 0 {
		logger.Info("Cleaned up expired device trust", zap.Int64("count", count))
	}

	return count, nil
}

// RenameDevice updates the device name
func (s *DeviceService) RenameDevice(ctx context.Context, userID, deviceID uuid.UUID, name string) error {
	device, err := s.deviceRepo.GetByID(ctx, deviceID)
	if err != nil {
		return fmt.Errorf("failed to get device: %w", err)
	}
	if device == nil {
		return fmt.Errorf("device not found")
	}
	if device.UserID != userID {
		return fmt.Errorf("device does not belong to user")
	}

	device.DeviceName = &name
	err = s.deviceRepo.Update(ctx, device)
	if err != nil {
		return fmt.Errorf("failed to update device: %w", err)
	}

	return nil
}

// CheckDeviceIsNew checks if a device fingerprint is new for the user
// Returns (isNew, device, error)
func (s *DeviceService) CheckDeviceIsNew(ctx context.Context, userID uuid.UUID, userAgent, ip string) (bool, *models.Device, error) {
	fingerprintHash := s.GenerateSimpleFingerprint(userAgent, ip)

	device, err := s.deviceRepo.GetByFingerprint(ctx, userID, fingerprintHash)
	if err != nil {
		return false, nil, fmt.Errorf("failed to check device: %w", err)
	}

	if device == nil {
		// Device is new - record it and return
		newDevice, err := s.RecordDevice(ctx, userID, userAgent, ip, nil)
		if err != nil {
			return true, nil, fmt.Errorf("CheckDeviceIsNew: RecordDevice failed: %w", err)
		}
		return true, newDevice, nil
	}

	// Device exists - update last seen
	device.LastIP = &ip
	device.LastSeenAt = time.Now()
	if err := s.deviceRepo.Update(ctx, device); err != nil {
		logger.Error("Failed to update device last seen", zap.Error(err))
	}

	return false, device, nil
}

// GetDeviceByFingerprint retrieves a device by its fingerprint hash (client device ID)
func (s *DeviceService) GetDeviceByFingerprint(ctx context.Context, userID uuid.UUID, fingerprintHash string) (*models.Device, error) {
	return s.deviceRepo.GetByFingerprint(ctx, userID, fingerprintHash)
}

// TrustDeviceByFingerprint marks a device as trusted using its fingerprint hash
// If the device doesn't exist, it creates a new one and trusts it
// Returns the device and any error
func (s *DeviceService) TrustDeviceByFingerprint(ctx context.Context, userID uuid.UUID, fingerprintHash, userAgent, ip string, trustDurationDays int) (*models.Device, error) {
	// Try to get existing device
	device, err := s.deviceRepo.GetByFingerprint(ctx, userID, fingerprintHash)
	if err != nil {
		return nil, fmt.Errorf("failed to check device: %w", err)
	}

	if device == nil {
		// Create new device with the provided fingerprint
		deviceType, browser, os := s.ParseUserAgent(userAgent)
		deviceName := fmt.Sprintf("%s on %s", browser, os)

		device = &models.Device{
			UserID:          userID,
			FingerprintHash: fingerprintHash,
			DeviceName:      &deviceName,
			DeviceType:      &deviceType,
			Browser:         &browser,
			OS:              &os,
			LastIP:          &ip,
		}

		err = s.deviceRepo.UpsertDevice(ctx, device)
		if err != nil {
			return nil, fmt.Errorf("failed to create device: %w", err)
		}

		// Fetch the device to get the ID
		device, err = s.deviceRepo.GetByFingerprint(ctx, userID, fingerprintHash)
		if err != nil || device == nil {
			return nil, fmt.Errorf("failed to get created device: %w", err)
		}
	}

	// Calculate trust expiration
	var expiresAt *time.Time
	if trustDurationDays > 0 {
		t := time.Now().Add(time.Duration(trustDurationDays) * 24 * time.Hour)
		expiresAt = &t
	}

	// Trust the device
	err = s.deviceRepo.TrustDevice(ctx, device.ID, expiresAt)
	if err != nil {
		return nil, fmt.Errorf("failed to trust device: %w", err)
	}

	device.IsTrusted = true
	device.TrustExpiresAt = expiresAt

	logger.Info("Device trusted by fingerprint",
		zap.String("device_id", device.ID.String()),
		zap.String("user_id", userID.String()),
		zap.Int("trust_days", trustDurationDays),
	)

	return device, nil
}
