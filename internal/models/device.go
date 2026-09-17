// SPDX-License-Identifier: AGPL-3.0-or-later

package models

import (
	"time"

	"github.com/google/uuid"
)

// DeviceType represents the type of device
type DeviceType string

const (
	// DeviceTypeDesktop is an exported identifier.
	DeviceTypeDesktop DeviceType = "desktop"
	// DeviceTypeMobile is an exported identifier.
	DeviceTypeMobile DeviceType = "mobile"
	// DeviceTypeTablet is an exported identifier.
	DeviceTypeTablet DeviceType = "tablet"
	// DeviceTypeUnknown is an exported identifier.
	DeviceTypeUnknown DeviceType = "unknown"

	deviceFieldUnknown = "Unknown"
)

// Device represents a user's device
type Device struct {
	ID              uuid.UUID  `json:"id" db:"id"`
	UserID          uuid.UUID  `json:"user_id" db:"user_id"`
	FingerprintHash string     `json:"-" db:"fingerprint_hash"`
	DeviceName      *string    `json:"device_name,omitempty" db:"device_name"`
	DeviceType      *string    `json:"device_type,omitempty" db:"device_type"`
	Browser         *string    `json:"browser,omitempty" db:"browser"`
	OS              *string    `json:"os,omitempty" db:"os"`
	IsTrusted       bool       `json:"is_trusted" db:"is_trusted"`
	FirstSeenAt     time.Time  `json:"first_seen_at" db:"first_seen_at"`
	LastSeenAt      time.Time  `json:"last_seen_at" db:"last_seen_at"`
	LastIP          *string    `json:"last_ip,omitempty" db:"last_ip"`
	TrustExpiresAt  *time.Time `json:"trust_expires_at,omitempty" db:"trust_expires_at"`
	CreatedAt       time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt       time.Time  `json:"updated_at" db:"updated_at"`
}

// DeviceResponse is the API response for a device
type DeviceResponse struct {
	ID             uuid.UUID  `json:"id"`
	DeviceName     string     `json:"device_name"`
	DeviceType     string     `json:"device_type"`
	Browser        string     `json:"browser"`
	OS             string     `json:"os"`
	IsTrusted      bool       `json:"is_trusted"`
	FirstSeenAt    time.Time  `json:"first_seen_at"`
	LastSeenAt     time.Time  `json:"last_seen_at"`
	LastIP         string     `json:"last_ip"`
	TrustExpiresAt *time.Time `json:"trust_expires_at,omitempty"`
}

// DeviceListResponse is the paginated list response
type DeviceListResponse struct {
	Devices    []DeviceResponse `json:"devices"`
	Total      int64            `json:"total"`
	Page       int              `json:"page"`
	PageSize   int              `json:"page_size"`
	TotalPages int              `json:"total_pages"`
}

// TrustDeviceRequest is the request to trust a device
type TrustDeviceRequest struct {
	TrustDuration string `json:"trust_duration,omitempty" binding:"omitempty,oneof=30d 60d 90d 180d 365d forever"` // e.g., "30d", "90d", "forever"
}

// DeviceFingerprint contains the raw fingerprint data from the client
type DeviceFingerprint struct {
	UserAgent           string `json:"user_agent"`
	ScreenWidth         int    `json:"screen_width,omitempty"`
	ScreenHeight        int    `json:"screen_height,omitempty"`
	ColorDepth          int    `json:"color_depth,omitempty"`
	Timezone            string `json:"timezone,omitempty"`
	Language            string `json:"language,omitempty"`
	Platform            string `json:"platform,omitempty"`
	CookiesEnabled      bool   `json:"cookies_enabled,omitempty"`
	DoNotTrack          bool   `json:"do_not_track,omitempty"`
	CanvasHash          string `json:"canvas_hash,omitempty"`
	WebGLVendor         string `json:"webgl_vendor,omitempty"`
	WebGLRenderer       string `json:"webgl_renderer,omitempty"`
	AudioHash           string `json:"audio_hash,omitempty"`
	FontsHash           string `json:"fonts_hash,omitempty"`
	PluginsHash         string `json:"plugins_hash,omitempty"`
	TouchSupport        bool   `json:"touch_support,omitempty"`
	HardwareConcurrency int    `json:"hardware_concurrency,omitempty"`
	DeviceMemory        int    `json:"device_memory,omitempty"`
}

// ToResponse converts a Device to DeviceResponse
func (d *Device) ToResponse() *DeviceResponse {
	resp := &DeviceResponse{
		ID:             d.ID,
		IsTrusted:      d.IsTrusted,
		FirstSeenAt:    d.FirstSeenAt,
		LastSeenAt:     d.LastSeenAt,
		TrustExpiresAt: d.TrustExpiresAt,
	}

	if d.DeviceName != nil {
		resp.DeviceName = *d.DeviceName
	} else {
		resp.DeviceName = "Unknown Device"
	}

	if d.DeviceType != nil {
		resp.DeviceType = *d.DeviceType
	} else {
		resp.DeviceType = string(DeviceTypeUnknown)
	}

	if d.Browser != nil {
		resp.Browser = *d.Browser
	} else {
		resp.Browser = deviceFieldUnknown
	}

	if d.OS != nil {
		resp.OS = *d.OS
	} else {
		resp.OS = deviceFieldUnknown
	}

	if d.LastIP != nil {
		resp.LastIP = *d.LastIP
	} else {
		resp.LastIP = deviceFieldUnknown
	}

	return resp
}
