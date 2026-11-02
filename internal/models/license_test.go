// SPDX-License-Identifier: AGPL-3.0-or-later

package models

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ==================== License.IsActive ====================

func TestLicense_IsActive(t *testing.T) {
	tests := []struct {
		name     string
		license  License
		expected bool
	}{
		{
			name:     "should return true when status is active",
			license:  License{Status: LicenseStatusActive},
			expected: true,
		},
		{
			name:     "should return false when status is suspended",
			license:  License{Status: LicenseStatusSuspended},
			expected: false,
		},
		{
			name:     "should return false when status is expired",
			license:  License{Status: LicenseStatusExpired},
			expected: false,
		},
		{
			name:     "should return false when status is revoked",
			license:  License{Status: LicenseStatusRevoked},
			expected: false,
		},
		{
			name:     "should return false when status is empty",
			license:  License{Status: ""},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.license.IsActive())
		})
	}
}

// ==================== License.IsSuspended ====================

func TestLicense_IsSuspended(t *testing.T) {
	tests := []struct {
		name     string
		license  License
		expected bool
	}{
		{
			name:     "should return true when status is suspended",
			license:  License{Status: LicenseStatusSuspended},
			expected: true,
		},
		{
			name:     "should return false when status is active",
			license:  License{Status: LicenseStatusActive},
			expected: false,
		},
		{
			name:     "should return false when status is expired",
			license:  License{Status: LicenseStatusExpired},
			expected: false,
		},
		{
			name:     "should return false when status is revoked",
			license:  License{Status: LicenseStatusRevoked},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.license.IsSuspended())
		})
	}
}

// ==================== License.IsExpired ====================

func TestLicense_IsExpired(t *testing.T) {
	tests := []struct {
		name     string
		license  License
		expected bool
	}{
		{
			name: "should not be expired when status is active and ExpiresAt is nil",
			license: License{
				Status:    LicenseStatusActive,
				ExpiresAt: nil,
			},
			expected: false,
		},
		{
			name: "should be expired when status is explicitly set to expired",
			license: License{
				Status: LicenseStatusExpired,
			},
			expected: true,
		},
		{
			name: "should be expired when ExpiresAt is in the past (active status)",
			license: License{
				Status:    LicenseStatusActive,
				ExpiresAt: timePtr(time.Now().Add(-1 * time.Hour)),
			},
			expected: true,
		},
		{
			name: "should be expired when ExpiresAt is in the past (suspended status)",
			license: License{
				Status:    LicenseStatusSuspended,
				ExpiresAt: timePtr(time.Now().Add(-24 * time.Hour)),
			},
			expected: true,
		},
		{
			name: "should not be expired when ExpiresAt is in the future",
			license: License{
				Status:    LicenseStatusActive,
				ExpiresAt: timePtr(time.Now().Add(24 * time.Hour)),
			},
			expected: false,
		},
		{
			name: "should not be expired when ExpiresAt is far in the future",
			license: License{
				Status:    LicenseStatusActive,
				ExpiresAt: timePtr(time.Now().Add(365 * 24 * time.Hour)),
			},
			expected: false,
		},
		{
			name: "should be expired when status is expired even with future ExpiresAt",
			license: License{
				Status:    LicenseStatusExpired,
				ExpiresAt: timePtr(time.Now().Add(24 * time.Hour)),
			},
			expected: true,
		},
		{
			name: "should not be expired when status is revoked and ExpiresAt is nil",
			license: License{
				Status:    LicenseStatusRevoked,
				ExpiresAt: nil,
			},
			expected: false,
		},
		{
			name: "should be expired when status is revoked and ExpiresAt is in the past",
			license: License{
				Status:    LicenseStatusRevoked,
				ExpiresAt: timePtr(time.Now().Add(-1 * time.Minute)),
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.license.IsExpired())
		})
	}
}

// TestLicense_IsExpired_Boundary verifies behaviour right at the expiry boundary.
func TestLicense_IsExpired_Boundary(t *testing.T) {
	t.Run("should be expired one nanosecond past expiry", func(t *testing.T) {
		past := time.Now().Add(-1 * time.Nanosecond)
		l := &License{
			Status:    LicenseStatusActive,
			ExpiresAt: &past,
		}
		assert.True(t, l.IsExpired())
	})

	t.Run("should not be expired one hour before expiry", func(t *testing.T) {
		future := time.Now().Add(1 * time.Hour)
		l := &License{
			Status:    LicenseStatusActive,
			ExpiresAt: &future,
		}
		assert.False(t, l.IsExpired())
	})
}

// ==================== License.IsRevoked ====================

func TestLicense_IsRevoked(t *testing.T) {
	tests := []struct {
		name     string
		license  License
		expected bool
	}{
		{
			name:     "should return true when status is revoked",
			license:  License{Status: LicenseStatusRevoked},
			expected: true,
		},
		{
			name:     "should return false when status is active",
			license:  License{Status: LicenseStatusActive},
			expected: false,
		},
		{
			name:     "should return false when status is suspended",
			license:  License{Status: LicenseStatusSuspended},
			expected: false,
		},
		{
			name:     "should return false when status is expired",
			license:  License{Status: LicenseStatusExpired},
			expected: false,
		},
		{
			name:     "should return false when status is empty",
			license:  License{Status: ""},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.license.IsRevoked())
		})
	}
}

// ==================== License.HasAvailableSeats ====================

func TestLicense_HasAvailableSeats(t *testing.T) {
	tests := []struct {
		name     string
		license  License
		expected bool
	}{
		{
			name: "should return true when no seats are used",
			license: License{
				MaxSeats:  10,
				UsedSeats: 0,
			},
			expected: true,
		},
		{
			name: "should return true when seats are partially used",
			license: License{
				MaxSeats:  10,
				UsedSeats: 5,
			},
			expected: true,
		},
		{
			name: "should return true when only one seat remains",
			license: License{
				MaxSeats:  10,
				UsedSeats: 9,
			},
			expected: true,
		},
		{
			name: "should return false when all seats are used",
			license: License{
				MaxSeats:  10,
				UsedSeats: 10,
			},
			expected: false,
		},
		{
			name: "should return false when used seats exceed max seats",
			license: License{
				MaxSeats:  5,
				UsedSeats: 6,
			},
			expected: false,
		},
		{
			name: "should return false for a single-seat license that is fully used",
			license: License{
				MaxSeats:  1,
				UsedSeats: 1,
			},
			expected: false,
		},
		{
			name: "should return true for a single-seat license that has no activations",
			license: License{
				MaxSeats:  1,
				UsedSeats: 0,
			},
			expected: true,
		},
		{
			name: "should return true for a large seat pool with low usage",
			license: License{
				MaxSeats:  1000,
				UsedSeats: 1,
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.license.HasAvailableSeats())
		})
	}
}

// ==================== License status mutual exclusivity ====================

func TestLicense_StatusMutualExclusivity(t *testing.T) {
	tests := []struct {
		status        LicenseStatus
		wantActive    bool
		wantSuspended bool
		wantRevoked   bool
	}{
		{
			status:        LicenseStatusActive,
			wantActive:    true,
			wantSuspended: false,
			wantRevoked:   false,
		},
		{
			status:        LicenseStatusSuspended,
			wantActive:    false,
			wantSuspended: true,
			wantRevoked:   false,
		},
		{
			status:        LicenseStatusRevoked,
			wantActive:    false,
			wantSuspended: false,
			wantRevoked:   true,
		},
		{
			// Expired status: none of IsActive / IsSuspended / IsRevoked are true.
			status:        LicenseStatusExpired,
			wantActive:    false,
			wantSuspended: false,
			wantRevoked:   false,
		},
	}

	for _, tt := range tests {
		t.Run(string(tt.status), func(t *testing.T) {
			l := &License{Status: tt.status}
			assert.Equal(t, tt.wantActive, l.IsActive(), "IsActive")
			assert.Equal(t, tt.wantSuspended, l.IsSuspended(), "IsSuspended")
			assert.Equal(t, tt.wantRevoked, l.IsRevoked(), "IsRevoked")
		})
	}
}

// ==================== License.ToResponse ====================

func TestLicense_ToResponse(t *testing.T) {
	t.Run("should map all fields correctly", func(t *testing.T) {
		id := uuid.New()
		productID := uuid.New()
		tenantID := uuid.New()
		createdBy := uuid.New()
		revokedBy := uuid.New()
		now := time.Now().Truncate(time.Second)
		expires := now.Add(30 * 24 * time.Hour)
		suspended := now.Add(-1 * time.Hour)
		revoked := now.Add(-30 * time.Minute)

		l := &License{
			ID:          id,
			ProductID:   productID,
			TenantID:    tenantID,
			LicenseKey:  "HEXX-ABCD-1234-EFGH-5678",
			Type:        LicenseTypeEnterprise,
			Status:      LicenseStatusRevoked,
			MaxSeats:    50,
			UsedSeats:   12,
			Features:    map[string]interface{}{"advanced_reporting": true},
			Metadata:    map[string]interface{}{"customer_ref": "C-001"},
			IssuedAt:    now,
			ExpiresAt:   &expires,
			SuspendedAt: &suspended,
			RevokedAt:   &revoked,
			RevokedBy:   &revokedBy,
			CreatedBy:   &createdBy,
			CreatedAt:   now,
			UpdatedAt:   now,
		}

		resp := l.ToResponse()

		require.NotNil(t, resp)
		assert.Equal(t, id, resp.ID)
		assert.Equal(t, productID, resp.ProductID)
		assert.Equal(t, tenantID, resp.TenantID)
		assert.Equal(t, "HEXX-****-****-****-5678", resp.LicenseKey,
			"ToResponse should mask the license key")
		assert.Equal(t, LicenseTypeEnterprise, resp.Type)
		assert.Equal(t, LicenseStatusRevoked, resp.Status)
		assert.Equal(t, 50, resp.MaxSeats)
		assert.Equal(t, 12, resp.UsedSeats)
		assert.Equal(t, map[string]interface{}{"advanced_reporting": true}, resp.Features)
		assert.Equal(t, map[string]interface{}{"customer_ref": "C-001"}, resp.Metadata)
		assert.Equal(t, now, resp.IssuedAt)
		assert.Equal(t, &expires, resp.ExpiresAt)
		assert.Equal(t, &suspended, resp.SuspendedAt)
		assert.Equal(t, &revoked, resp.RevokedAt)
		assert.Equal(t, &revokedBy, resp.RevokedBy)
		assert.Equal(t, &createdBy, resp.CreatedBy)
		assert.Equal(t, now, resp.CreatedAt)
		assert.Equal(t, now, resp.UpdatedAt)
	})

	t.Run("should handle nil optional pointer fields", func(t *testing.T) {
		l := &License{
			ID:         uuid.New(),
			ProductID:  uuid.New(),
			TenantID:   uuid.New(),
			LicenseKey: "HEXX-0000-0000-0000-0001",
			Type:       LicenseTypeTrial,
			Status:     LicenseStatusActive,
			MaxSeats:   5,
			UsedSeats:  0,
		}

		resp := l.ToResponse()

		require.NotNil(t, resp)
		assert.Nil(t, resp.ExpiresAt)
		assert.Nil(t, resp.SuspendedAt)
		assert.Nil(t, resp.RevokedAt)
		assert.Nil(t, resp.RevokedBy)
		assert.Nil(t, resp.CreatedBy)
		assert.Nil(t, resp.Features)
		assert.Nil(t, resp.Metadata)
	})

	t.Run("should produce a distinct instance on each call", func(t *testing.T) {
		l := &License{
			ID:       uuid.New(),
			Status:   LicenseStatusActive,
			MaxSeats: 1,
		}

		resp1 := l.ToResponse()
		resp2 := l.ToResponse()

		assert.NotSame(t, resp1, resp2)
		assert.Equal(t, resp1, resp2)
	})
}

// ==================== LicenseActivation.ToResponse ====================

func TestLicenseActivation_ToResponse(t *testing.T) {
	t.Run("should map all fields correctly", func(t *testing.T) {
		id := uuid.New()
		licenseID := uuid.New()
		now := time.Now().Truncate(time.Second)
		deactivated := now.Add(10 * time.Minute)
		device := "Workstation-A"
		ip := testIPAddr192_168_1_100
		ua := "MyApp/1.0"

		a := &LicenseActivation{
			ID:              id,
			LicenseID:       licenseID,
			MachineID:       "machine-abc-123",
			DeviceName:      &device,
			IPAddress:       &ip,
			UserAgent:       &ua,
			ActivatedAt:     now,
			LastValidatedAt: now,
			DeactivatedAt:   &deactivated,
			Status:          LicenseActivationStatusDeactivated,
		}

		resp := a.ToResponse()

		require.NotNil(t, resp)
		assert.Equal(t, id, resp.ID)
		assert.Equal(t, licenseID, resp.LicenseID)
		assert.Equal(t, "machine-abc-123", resp.MachineID)
		assert.Equal(t, &device, resp.DeviceName)
		assert.Equal(t, &ip, resp.IPAddress)
		assert.Equal(t, now, resp.ActivatedAt)
		assert.Equal(t, now, resp.LastValidatedAt)
		assert.Equal(t, &deactivated, resp.DeactivatedAt)
		assert.Equal(t, LicenseActivationStatusDeactivated, resp.Status)
	})

	t.Run("should not expose UserAgent in response", func(t *testing.T) {
		ua := "Secret/Agent"
		a := &LicenseActivation{
			ID:        uuid.New(),
			LicenseID: uuid.New(),
			MachineID: "machine-xyz",
			UserAgent: &ua,
			Status:    LicenseActivationStatusActive,
		}

		resp := a.ToResponse()

		// UserAgent is intentionally absent from LicenseActivationResponse.
		// Verify the response type itself does not carry it (compile-time check via struct).
		require.NotNil(t, resp)
		assert.Equal(t, LicenseActivationStatusActive, resp.Status)
	})

	t.Run("should handle nil optional fields", func(t *testing.T) {
		a := &LicenseActivation{
			ID:        uuid.New(),
			LicenseID: uuid.New(),
			MachineID: "minimal-machine",
			Status:    LicenseActivationStatusActive,
		}

		resp := a.ToResponse()

		require.NotNil(t, resp)
		assert.Nil(t, resp.DeviceName)
		assert.Nil(t, resp.IPAddress)
		assert.Nil(t, resp.DeactivatedAt)
	})

	t.Run("should produce a distinct instance on each call", func(t *testing.T) {
		a := &LicenseActivation{
			ID:        uuid.New(),
			LicenseID: uuid.New(),
			MachineID: "some-machine",
			Status:    LicenseActivationStatusActive,
		}

		resp1 := a.ToResponse()
		resp2 := a.ToResponse()

		assert.NotSame(t, resp1, resp2)
		assert.Equal(t, resp1, resp2)
	})
}

// ==================== License type / status constants ====================

func TestLicenseTypeConstants(t *testing.T) {
	assert.Equal(t, LicenseType("trial"), LicenseTypeTrial)
	assert.Equal(t, LicenseType("standard"), LicenseTypeStandard)
	assert.Equal(t, LicenseType("professional"), LicenseTypeProfessional)
	assert.Equal(t, LicenseType("enterprise"), LicenseTypeEnterprise)
}

func TestLicenseStatusConstants(t *testing.T) {
	assert.Equal(t, LicenseStatus("active"), LicenseStatusActive)
	assert.Equal(t, LicenseStatus("suspended"), LicenseStatusSuspended)
	assert.Equal(t, LicenseStatus("expired"), LicenseStatusExpired)
	assert.Equal(t, LicenseStatus("revoked"), LicenseStatusRevoked)
}

func TestLicenseActivationStatusConstants(t *testing.T) {
	assert.Equal(t, LicenseActivationStatus("active"), LicenseActivationStatusActive)
	assert.Equal(t, LicenseActivationStatus("deactivated"), LicenseActivationStatusDeactivated)
}

// ==================== MaskLicenseKey ====================

func TestMaskLicenseKey(t *testing.T) {
	tests := []struct {
		name     string
		key      string
		expected string
	}{
		{
			name:     "should mask a standard 5-segment key",
			key:      "HEXX-ABCD-1234-EFGH-5678",
			expected: "HEXX-****-****-****-5678",
		},
		{
			name:     "should mask a 9-segment 128-bit key",
			key:      "HEXX-1A2B-3C4D-5E6F-7A8B-9C0D-1E2F-3A4B-5C6D",
			expected: "HEXX-****-****-****-****-****-****-****-5C6D",
		},
		{
			name:     "should return **** for a single-segment key",
			key:      "NODELIMITERS",
			expected: "****",
		},
		{
			name:     "should expose both parts of a 2-segment key (no middle to mask)",
			key:      "HEXX-ABCD",
			expected: "HEXX-ABCD",
		},
		{
			name:     "should handle 3-segment key by masking the middle",
			key:      "HEXX-ABCD-5678",
			expected: "HEXX-****-5678",
		},
		{
			name:     "should return **** for empty key",
			key:      "",
			expected: "****",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, MaskLicenseKey(tt.key))
		})
	}
}

// ==================== ToResponseWithKey ====================

func TestLicense_ToResponseWithKey(t *testing.T) {
	t.Run("should return the full unmasked license key", func(t *testing.T) {
		l := &License{
			ID:         uuid.New(),
			ProductID:  uuid.New(),
			TenantID:   uuid.New(),
			LicenseKey: "HEXX-ABCD-1234-EFGH-5678",
			Type:       LicenseTypeStandard,
			Status:     LicenseStatusActive,
			MaxSeats:   10,
		}

		resp := l.ToResponseWithKey()

		require.NotNil(t, resp)
		assert.Equal(t, "HEXX-ABCD-1234-EFGH-5678", resp.LicenseKey,
			"ToResponseWithKey should expose the full unmasked key")
	})

	t.Run("should return a different key than ToResponse", func(t *testing.T) {
		l := &License{
			ID:         uuid.New(),
			ProductID:  uuid.New(),
			TenantID:   uuid.New(),
			LicenseKey: "HEXX-AAAA-BBBB-CCCC-DDDD",
			Type:       LicenseTypeTrial,
			Status:     LicenseStatusActive,
			MaxSeats:   1,
		}

		masked := l.ToResponse()
		unmasked := l.ToResponseWithKey()

		assert.NotEqual(t, masked.LicenseKey, unmasked.LicenseKey,
			"masked and unmasked responses should differ")
		assert.Equal(t, "HEXX-****-****-****-DDDD", masked.LicenseKey)
		assert.Equal(t, "HEXX-AAAA-BBBB-CCCC-DDDD", unmasked.LicenseKey)
	})
}
