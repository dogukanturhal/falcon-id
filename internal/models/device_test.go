// SPDX-License-Identifier: AGPL-3.0-or-later

package models

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testDeviceMacBook = "MacBook Pro"

// ==================== DeviceType constants ====================

func TestDeviceTypeConstants(t *testing.T) {
	assert.Equal(t, DeviceType("desktop"), DeviceTypeDesktop)
	assert.Equal(t, DeviceType("mobile"), DeviceTypeMobile)
	assert.Equal(t, DeviceType("tablet"), DeviceTypeTablet)
	assert.Equal(t, DeviceType("unknown"), DeviceTypeUnknown)
}

func TestDeviceTypeConstants_AreDistinct(t *testing.T) {
	types := []DeviceType{
		DeviceTypeDesktop,
		DeviceTypeMobile,
		DeviceTypeTablet,
		DeviceTypeUnknown,
	}

	seen := make(map[DeviceType]bool)
	for _, dt := range types {
		assert.False(t, seen[dt], "duplicate DeviceType constant value: %s", dt)
		seen[dt] = true
	}
}

// ==================== buildDevice helper ====================

func buildDevice() *Device {
	now := time.Now().Truncate(time.Second)
	deviceName := testDeviceMacBook
	deviceType := string(DeviceTypeDesktop)
	browser := "Chrome"
	os := "macOS"
	ip := "192.168.1.50"
	expires := now.Add(30 * 24 * time.Hour)

	return &Device{
		ID:              uuid.New(),
		UserID:          uuid.New(),
		FingerprintHash: "hashed-fingerprint-value",
		DeviceName:      &deviceName,
		DeviceType:      &deviceType,
		Browser:         &browser,
		OS:              &os,
		IsTrusted:       true,
		FirstSeenAt:     now.Add(-7 * 24 * time.Hour),
		LastSeenAt:      now,
		LastIP:          &ip,
		TrustExpiresAt:  &expires,
		CreatedAt:       now.Add(-7 * 24 * time.Hour),
		UpdatedAt:       now,
	}
}

// ==================== Device.ToResponse — null field defaults ====================

func TestDevice_ToResponse_NullFieldDefaults(t *testing.T) {
	tests := []struct {
		name           string
		device         *Device
		wantDeviceName string
		wantDeviceType string
		wantBrowser    string
		wantOS         string
		wantLastIP     string
	}{
		{
			name:           "all pointer fields set should pass through values",
			device:         buildDevice(),
			wantDeviceName: testDeviceMacBook,
			wantDeviceType: string(DeviceTypeDesktop),
			wantBrowser:    "Chrome",
			wantOS:         "macOS",
			wantLastIP:     "192.168.1.50",
		},
		{
			name: "nil DeviceName should default to 'Unknown Device'",
			device: func() *Device {
				d := buildDevice()
				d.DeviceName = nil
				return d
			}(),
			wantDeviceName: "Unknown Device",
			wantDeviceType: string(DeviceTypeDesktop),
			wantBrowser:    "Chrome",
			wantOS:         "macOS",
			wantLastIP:     "192.168.1.50",
		},
		{
			name: "nil DeviceType should default to 'unknown'",
			device: func() *Device {
				d := buildDevice()
				d.DeviceType = nil
				return d
			}(),
			wantDeviceName: testDeviceMacBook,
			wantDeviceType: string(DeviceTypeUnknown),
			wantBrowser:    "Chrome",
			wantOS:         "macOS",
			wantLastIP:     "192.168.1.50",
		},
		{
			name: "nil Browser should default to 'Unknown'",
			device: func() *Device {
				d := buildDevice()
				d.Browser = nil
				return d
			}(),
			wantDeviceName: testDeviceMacBook,
			wantDeviceType: string(DeviceTypeDesktop),
			wantBrowser:    "Unknown",
			wantOS:         "macOS",
			wantLastIP:     "192.168.1.50",
		},
		{
			name: "nil OS should default to 'Unknown'",
			device: func() *Device {
				d := buildDevice()
				d.OS = nil
				return d
			}(),
			wantDeviceName: testDeviceMacBook,
			wantDeviceType: string(DeviceTypeDesktop),
			wantBrowser:    "Chrome",
			wantOS:         "Unknown",
			wantLastIP:     "192.168.1.50",
		},
		{
			name: "nil LastIP should default to 'Unknown'",
			device: func() *Device {
				d := buildDevice()
				d.LastIP = nil
				return d
			}(),
			wantDeviceName: testDeviceMacBook,
			wantDeviceType: string(DeviceTypeDesktop),
			wantBrowser:    "Chrome",
			wantOS:         "macOS",
			wantLastIP:     "Unknown",
		},
		{
			name: "all pointer fields nil should all default to unknown values",
			device: &Device{
				ID:          uuid.New(),
				UserID:      uuid.New(),
				IsTrusted:   false,
				FirstSeenAt: time.Now(),
				LastSeenAt:  time.Now(),
			},
			wantDeviceName: "Unknown Device",
			wantDeviceType: string(DeviceTypeUnknown),
			wantBrowser:    "Unknown",
			wantOS:         "Unknown",
			wantLastIP:     "Unknown",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := tt.device.ToResponse()

			require.NotNil(t, resp)
			assert.Equal(t, tt.wantDeviceName, resp.DeviceName)
			assert.Equal(t, tt.wantDeviceType, resp.DeviceType)
			assert.Equal(t, tt.wantBrowser, resp.Browser)
			assert.Equal(t, tt.wantOS, resp.OS)
			assert.Equal(t, tt.wantLastIP, resp.LastIP)
		})
	}
}

// ==================== Device.ToResponse — field mapping ====================

func TestDevice_ToResponse_FieldMapping(t *testing.T) {
	t.Run("should map all fields correctly", func(t *testing.T) {
		d := buildDevice()

		resp := d.ToResponse()

		require.NotNil(t, resp)
		assert.Equal(t, d.ID, resp.ID)
		assert.Equal(t, testDeviceMacBook, resp.DeviceName)
		assert.Equal(t, string(DeviceTypeDesktop), resp.DeviceType)
		assert.Equal(t, "Chrome", resp.Browser)
		assert.Equal(t, "macOS", resp.OS)
		assert.True(t, resp.IsTrusted)
		assert.Equal(t, d.FirstSeenAt, resp.FirstSeenAt)
		assert.Equal(t, d.LastSeenAt, resp.LastSeenAt)
		assert.Equal(t, "192.168.1.50", resp.LastIP)
		assert.Equal(t, d.TrustExpiresAt, resp.TrustExpiresAt)
	})

	t.Run("TrustExpiresAt should be nil when not trusted", func(t *testing.T) {
		d := &Device{
			ID:          uuid.New(),
			UserID:      uuid.New(),
			IsTrusted:   false,
			FirstSeenAt: time.Now(),
			LastSeenAt:  time.Now(),
		}

		resp := d.ToResponse()

		require.NotNil(t, resp)
		assert.False(t, resp.IsTrusted)
		assert.Nil(t, resp.TrustExpiresAt)
	})

	t.Run("should produce a distinct instance on each call", func(t *testing.T) {
		d := buildDevice()

		resp1 := d.ToResponse()
		resp2 := d.ToResponse()

		assert.NotSame(t, resp1, resp2)
		assert.Equal(t, resp1, resp2)
	})
}

// ==================== Device.ToResponse — each DeviceType value ====================

func TestDevice_ToResponse_DeviceTypeValues(t *testing.T) {
	tests := []struct {
		name           string
		deviceType     *string
		wantDeviceType string
	}{
		{
			name:           "desktop type passes through",
			deviceType:     strPtr(string(DeviceTypeDesktop)),
			wantDeviceType: string(DeviceTypeDesktop),
		},
		{
			name:           "mobile type passes through",
			deviceType:     strPtr(string(DeviceTypeMobile)),
			wantDeviceType: string(DeviceTypeMobile),
		},
		{
			name:           "tablet type passes through",
			deviceType:     strPtr(string(DeviceTypeTablet)),
			wantDeviceType: string(DeviceTypeTablet),
		},
		{
			name:           "explicit unknown type passes through",
			deviceType:     strPtr(string(DeviceTypeUnknown)),
			wantDeviceType: string(DeviceTypeUnknown),
		},
		{
			name:           "nil type defaults to 'unknown'",
			deviceType:     nil,
			wantDeviceType: string(DeviceTypeUnknown),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := &Device{
				ID:          uuid.New(),
				UserID:      uuid.New(),
				DeviceType:  tt.deviceType,
				FirstSeenAt: time.Now(),
				LastSeenAt:  time.Now(),
			}

			resp := d.ToResponse()

			require.NotNil(t, resp)
			assert.Equal(t, tt.wantDeviceType, resp.DeviceType)
		})
	}
}

// ==================== FingerprintHash json:"-" tag ====================

func TestDevice_FingerprintHash_JSONTag(t *testing.T) {
	t.Run("FingerprintHash must be absent from JSON serialisation", func(t *testing.T) {
		d := buildDevice()
		d.FingerprintHash = "extremely-sensitive-fingerprint-hash"

		data, err := json.Marshal(d)
		require.NoError(t, err)

		var raw map[string]interface{}
		require.NoError(t, json.Unmarshal(data, &raw))

		_, exists := raw["fingerprint_hash"]
		assert.False(t, exists, "fingerprint_hash must not appear in JSON due to json:\"-\" tag")

		_, exists = raw["FingerprintHash"]
		assert.False(t, exists, "FingerprintHash must not appear under any key")
	})
}

// ==================== TrustDeviceRequest ====================

func TestTrustDeviceRequest_ValidDurations(t *testing.T) {
	// Verify that the struct accepts the documented valid duration values.
	// The binding tag "oneof=30d 60d 90d 180d 365d forever" is enforced by the
	// Gin validator at runtime; here we confirm the struct fields hold the values.
	validDurations := []string{"30d", "60d", "90d", "180d", "365d", "forever"}

	for _, duration := range validDurations {
		t.Run("should accept duration: "+duration, func(t *testing.T) {
			req := TrustDeviceRequest{TrustDuration: duration}
			assert.Equal(t, duration, req.TrustDuration)
		})
	}
}

func TestTrustDeviceRequest_EmptyDuration(t *testing.T) {
	t.Run("zero value should have empty TrustDuration", func(t *testing.T) {
		req := TrustDeviceRequest{}
		assert.Empty(t, req.TrustDuration)
	})
}

// ==================== DeviceFingerprint struct ====================

func TestDeviceFingerprint_Fields(t *testing.T) {
	t.Run("should hold all fingerprint attributes", func(t *testing.T) {
		fp := DeviceFingerprint{
			UserAgent:           "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
			ScreenWidth:         1440,
			ScreenHeight:        900,
			ColorDepth:          24,
			Timezone:            "Europe/Istanbul",
			Language:            "tr-TR",
			Platform:            "MacIntel",
			CookiesEnabled:      true,
			DoNotTrack:          false,
			CanvasHash:          "canvas-fingerprint-hash",
			WebGLVendor:         "Apple Inc.",
			WebGLRenderer:       "Apple GPU",
			AudioHash:           "audio-fingerprint-hash",
			FontsHash:           "fonts-fingerprint-hash",
			PluginsHash:         "plugins-fingerprint-hash",
			TouchSupport:        false,
			HardwareConcurrency: 8,
			DeviceMemory:        16,
		}

		assert.Equal(t, "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)", fp.UserAgent)
		assert.Equal(t, 1440, fp.ScreenWidth)
		assert.Equal(t, 900, fp.ScreenHeight)
		assert.Equal(t, 24, fp.ColorDepth)
		assert.Equal(t, "Europe/Istanbul", fp.Timezone)
		assert.Equal(t, "tr-TR", fp.Language)
		assert.Equal(t, "MacIntel", fp.Platform)
		assert.True(t, fp.CookiesEnabled)
		assert.False(t, fp.DoNotTrack)
		assert.Equal(t, "canvas-fingerprint-hash", fp.CanvasHash)
		assert.Equal(t, "Apple Inc.", fp.WebGLVendor)
		assert.Equal(t, "Apple GPU", fp.WebGLRenderer)
		assert.Equal(t, "audio-fingerprint-hash", fp.AudioHash)
		assert.Equal(t, "fonts-fingerprint-hash", fp.FontsHash)
		assert.Equal(t, "plugins-fingerprint-hash", fp.PluginsHash)
		assert.False(t, fp.TouchSupport)
		assert.Equal(t, 8, fp.HardwareConcurrency)
		assert.Equal(t, 16, fp.DeviceMemory)
	})

	t.Run("zero value should have sensible defaults", func(t *testing.T) {
		fp := DeviceFingerprint{}

		assert.Empty(t, fp.UserAgent)
		assert.Equal(t, 0, fp.ScreenWidth)
		assert.Equal(t, 0, fp.ScreenHeight)
		assert.False(t, fp.CookiesEnabled)
		assert.False(t, fp.TouchSupport)
		assert.Equal(t, 0, fp.HardwareConcurrency)
		assert.Equal(t, 0, fp.DeviceMemory)
	})

	t.Run("mobile device fingerprint", func(t *testing.T) {
		fp := DeviceFingerprint{
			UserAgent:           "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0)",
			ScreenWidth:         390,
			ScreenHeight:        844,
			ColorDepth:          32,
			Timezone:            "America/New_York",
			Language:            "en-US",
			Platform:            "iPhone",
			CookiesEnabled:      true,
			TouchSupport:        true,
			HardwareConcurrency: 6,
			DeviceMemory:        4,
		}

		assert.Equal(t, "iPhone", fp.Platform)
		assert.True(t, fp.TouchSupport)
		assert.Equal(t, 390, fp.ScreenWidth)
	})
}

// ==================== DeviceResponse field coverage ====================

func TestDeviceResponse_Fields(t *testing.T) {
	t.Run("should carry all expected fields", func(t *testing.T) {
		id := uuid.New()
		now := time.Now().Truncate(time.Second)
		expires := now.Add(90 * 24 * time.Hour)

		resp := &DeviceResponse{
			ID:             id,
			DeviceName:     "iPhone 15",
			DeviceType:     string(DeviceTypeMobile),
			Browser:        "Safari",
			OS:             "iOS 17",
			IsTrusted:      true,
			FirstSeenAt:    now.Add(-30 * 24 * time.Hour),
			LastSeenAt:     now,
			LastIP:         "203.0.113.10",
			TrustExpiresAt: &expires,
		}

		assert.Equal(t, id, resp.ID)
		assert.Equal(t, "iPhone 15", resp.DeviceName)
		assert.Equal(t, string(DeviceTypeMobile), resp.DeviceType)
		assert.Equal(t, "Safari", resp.Browser)
		assert.Equal(t, "iOS 17", resp.OS)
		assert.True(t, resp.IsTrusted)
		assert.Equal(t, now, resp.LastSeenAt)
		assert.Equal(t, "203.0.113.10", resp.LastIP)
		assert.Equal(t, &expires, resp.TrustExpiresAt)
	})
}
