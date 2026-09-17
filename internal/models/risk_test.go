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

// ==================== RiskSignalType constants ====================

func TestRiskSignalTypeConstants(t *testing.T) {
	assert.Equal(t, RiskSignalType("impossible_travel"), RiskSignalImpossibleTravel)
	assert.Equal(t, RiskSignalType("new_device"), RiskSignalNewDevice)
	assert.Equal(t, RiskSignalType("unusual_time"), RiskSignalUnusualTime)
	assert.Equal(t, RiskSignalType("multiple_failed_attempts"), RiskSignalMultipleFailedAttempts)
	assert.Equal(t, RiskSignalType("new_location"), RiskSignalNewLocation)
	assert.Equal(t, RiskSignalType("suspicious_user_agent"), RiskSignalSuspiciousUserAgent)
	assert.Equal(t, RiskSignalType("first_federation"), RiskSignalFirstFederation)
	assert.Equal(t, RiskSignalType("sso_attribute_mismatch"), RiskSignalSSOAttributeMismatch)
}

// ==================== RiskLevel constants ====================

func TestRiskLevelConstants(t *testing.T) {
	assert.Equal(t, RiskLevel("low"), RiskLevelLow)
	assert.Equal(t, RiskLevel("medium"), RiskLevelMedium)
	assert.Equal(t, RiskLevel("high"), RiskLevelHigh)
	assert.Equal(t, RiskLevel("critical"), RiskLevelCritical)
}

// ==================== RiskSignal.ToResponse ====================

func TestRiskSignal_ToResponse(t *testing.T) {
	t.Run("should map all fields correctly", func(t *testing.T) {
		id := uuid.New()
		userID := uuid.New()
		sessionID := uuid.New()
		resolvedBy := uuid.New()
		now := time.Now().Truncate(time.Second)
		resolved := now.Add(10 * time.Minute)
		ipAddr := "192.168.1.1"
		ua := testUserAgentMozilla
		note := "Investigated and resolved"
		details := map[string]interface{}{"distance_km": 1000.0}

		signal := &RiskSignal{
			ID:             id,
			UserID:         userID,
			SessionID:      &sessionID,
			SignalType:     RiskSignalImpossibleTravel,
			RiskScore:      80,
			IPAddress:      &ipAddr,
			UserAgent:      &ua,
			AuthMethod:     "password",
			SSOProvider:    "",
			Details:        details,
			ResolvedAt:     &resolved,
			ResolvedBy:     &resolvedBy,
			ResolutionNote: &note,
			CreatedAt:      now,
		}

		resp := signal.ToResponse()

		require.NotNil(t, resp)
		assert.Equal(t, id.String(), resp.ID)
		assert.Equal(t, userID.String(), resp.UserID)
		assert.Equal(t, string(RiskSignalImpossibleTravel), resp.SignalType)
		assert.Equal(t, 80, resp.RiskScore)
		assert.Equal(t, ipAddr, resp.IPAddress)
		assert.Equal(t, details, resp.Details)
		assert.Equal(t, &resolved, resp.ResolvedAt)
		assert.Equal(t, note, resp.ResolutionNote)
		assert.Equal(t, now, resp.CreatedAt)
	})

	t.Run("should return empty string for IPAddress when nil", func(t *testing.T) {
		signal := &RiskSignal{
			ID:         uuid.New(),
			UserID:     uuid.New(),
			SignalType: RiskSignalNewDevice,
			RiskScore:  30,
			IPAddress:  nil,
			CreatedAt:  time.Now(),
		}

		resp := signal.ToResponse()

		require.NotNil(t, resp)
		assert.Equal(t, "", resp.IPAddress)
	})

	t.Run("should return empty string for ResolutionNote when nil", func(t *testing.T) {
		signal := &RiskSignal{
			ID:             uuid.New(),
			UserID:         uuid.New(),
			SignalType:     RiskSignalUnusualTime,
			RiskScore:      20,
			ResolutionNote: nil,
			CreatedAt:      time.Now(),
		}

		resp := signal.ToResponse()

		require.NotNil(t, resp)
		assert.Equal(t, "", resp.ResolutionNote)
	})

	t.Run("should return nil ResolvedAt when not set", func(t *testing.T) {
		signal := &RiskSignal{
			ID:         uuid.New(),
			UserID:     uuid.New(),
			SignalType: RiskSignalMultipleFailedAttempts,
			RiskScore:  50,
			CreatedAt:  time.Now(),
		}

		resp := signal.ToResponse()

		require.NotNil(t, resp)
		assert.Nil(t, resp.ResolvedAt)
	})

	t.Run("should produce a distinct instance on each call", func(t *testing.T) {
		signal := &RiskSignal{
			ID:         uuid.New(),
			UserID:     uuid.New(),
			SignalType: RiskSignalNewLocation,
			RiskScore:  25,
			CreatedAt:  time.Now(),
		}

		resp1 := signal.ToResponse()
		resp2 := signal.ToResponse()

		assert.NotSame(t, resp1, resp2)
		assert.Equal(t, resp1, resp2)
	})
}

func TestRiskSignal_ToResponse_IDConversion(t *testing.T) {
	tests := []struct {
		name       string
		signalType RiskSignalType
	}{
		{"impossible travel", RiskSignalImpossibleTravel},
		{"new device", RiskSignalNewDevice},
		{"unusual time", RiskSignalUnusualTime},
		{"multiple failed attempts", RiskSignalMultipleFailedAttempts},
		{"new location", RiskSignalNewLocation},
		{"suspicious user agent", RiskSignalSuspiciousUserAgent},
		{"first federation", RiskSignalFirstFederation},
		{"sso attribute mismatch", RiskSignalSSOAttributeMismatch},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			id := uuid.New()
			userID := uuid.New()

			signal := &RiskSignal{
				ID:         id,
				UserID:     userID,
				SignalType: tt.signalType,
				CreatedAt:  time.Now(),
			}

			resp := signal.ToResponse()

			assert.Equal(t, id.String(), resp.ID)
			assert.Equal(t, userID.String(), resp.UserID)
			assert.Equal(t, string(tt.signalType), resp.SignalType)
		})
	}
}

// ==================== RiskPolicy.ToResponse ====================

func TestRiskPolicy_ToResponse(t *testing.T) {
	t.Run("should map all fields correctly including description", func(t *testing.T) {
		id := uuid.New()
		tenantID := uuid.New()
		now := time.Now().Truncate(time.Second)
		desc := "Block on critical risk"
		conditions := map[string]interface{}{"min_score": 90}
		actions := map[string]interface{}{"action": "block"}

		policy := &RiskPolicy{
			ID:          id,
			TenantID:    tenantID,
			Name:        "Critical Block",
			Description: &desc,
			Conditions:  conditions,
			Actions:     actions,
			Priority:    1,
			IsActive:    true,
			CreatedAt:   now,
			UpdatedAt:   now,
		}

		resp := policy.ToResponse()

		require.NotNil(t, resp)
		assert.Equal(t, id.String(), resp.ID)
		assert.Equal(t, "Critical Block", resp.Name)
		assert.Equal(t, desc, resp.Description)
		assert.Equal(t, conditions, resp.Conditions)
		assert.Equal(t, actions, resp.Actions)
		assert.Equal(t, 1, resp.Priority)
		assert.True(t, resp.IsActive)
		assert.Equal(t, now, resp.CreatedAt)
		assert.Equal(t, now, resp.UpdatedAt)
	})

	t.Run("should return empty string for Description when nil", func(t *testing.T) {
		policy := &RiskPolicy{
			ID:          uuid.New(),
			TenantID:    uuid.New(),
			Name:        "No Desc Policy",
			Description: nil,
			Conditions:  map[string]interface{}{"score": 50},
			Actions:     map[string]interface{}{"action": "notify"},
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
		}

		resp := policy.ToResponse()

		require.NotNil(t, resp)
		assert.Equal(t, "", resp.Description)
	})

	t.Run("should convert ID to string", func(t *testing.T) {
		id := uuid.New()
		policy := &RiskPolicy{
			ID:         id,
			TenantID:   uuid.New(),
			Name:       "Policy",
			Conditions: map[string]interface{}{},
			Actions:    map[string]interface{}{},
		}

		resp := policy.ToResponse()

		assert.Equal(t, id.String(), resp.ID)
	})

	t.Run("should produce distinct instances on each call", func(t *testing.T) {
		policy := &RiskPolicy{
			ID:         uuid.New(),
			TenantID:   uuid.New(),
			Name:       "Policy",
			Conditions: map[string]interface{}{"x": 1},
			Actions:    map[string]interface{}{"a": "b"},
		}

		resp1 := policy.ToResponse()
		resp2 := policy.ToResponse()

		assert.NotSame(t, resp1, resp2)
		assert.Equal(t, resp1, resp2)
	})
}

// ==================== RiskThreshold.ToResponse ====================

func TestRiskThreshold_ToResponse(t *testing.T) {
	t.Run("should map all fields correctly", func(t *testing.T) {
		now := time.Now().Truncate(time.Second)

		threshold := &RiskThreshold{
			ID:                    uuid.New(),
			TenantID:              uuid.New(),
			LowThreshold:          20,
			MediumThreshold:       40,
			HighThreshold:         70,
			CriticalThreshold:     90,
			AutoBlockOnCritical:   true,
			BlockDurationMinutes:  60,
			NotifyUserOnHighRisk:  true,
			NotifyAdminOnCritical: true,
			CreatedAt:             now,
			UpdatedAt:             now,
		}

		resp := threshold.ToResponse()

		require.NotNil(t, resp)
		assert.Equal(t, 20, resp.LowThreshold)
		assert.Equal(t, 40, resp.MediumThreshold)
		assert.Equal(t, 70, resp.HighThreshold)
		assert.Equal(t, 90, resp.CriticalThreshold)
		assert.True(t, resp.AutoBlockOnCritical)
		assert.Equal(t, 60, resp.BlockDurationMinutes)
		assert.True(t, resp.NotifyUserOnHighRisk)
		assert.True(t, resp.NotifyAdminOnCritical)
	})

	t.Run("should map zero threshold values correctly", func(t *testing.T) {
		threshold := &RiskThreshold{
			ID:                    uuid.New(),
			TenantID:              uuid.New(),
			LowThreshold:          0,
			MediumThreshold:       0,
			HighThreshold:         0,
			CriticalThreshold:     0,
			AutoBlockOnCritical:   false,
			BlockDurationMinutes:  0,
			NotifyUserOnHighRisk:  false,
			NotifyAdminOnCritical: false,
		}

		resp := threshold.ToResponse()

		require.NotNil(t, resp)
		assert.Equal(t, 0, resp.LowThreshold)
		assert.Equal(t, 0, resp.MediumThreshold)
		assert.Equal(t, 0, resp.HighThreshold)
		assert.Equal(t, 0, resp.CriticalThreshold)
		assert.False(t, resp.AutoBlockOnCritical)
		assert.Equal(t, 0, resp.BlockDurationMinutes)
		assert.False(t, resp.NotifyUserOnHighRisk)
		assert.False(t, resp.NotifyAdminOnCritical)
	})

	t.Run("should produce distinct instances on each call", func(t *testing.T) {
		threshold := &RiskThreshold{
			ID:                uuid.New(),
			TenantID:          uuid.New(),
			LowThreshold:      10,
			MediumThreshold:   30,
			HighThreshold:     60,
			CriticalThreshold: 85,
		}

		resp1 := threshold.ToResponse()
		resp2 := threshold.ToResponse()

		assert.NotSame(t, resp1, resp2)
		assert.Equal(t, resp1, resp2)
	})
}

// ==================== RiskAssessment struct ====================

func TestRiskAssessment_Instantiation(t *testing.T) {
	t.Run("should represent a blocked high-risk assessment", func(t *testing.T) {
		signal := RiskSignal{
			ID:         uuid.New(),
			UserID:     uuid.New(),
			SignalType: RiskSignalImpossibleTravel,
			RiskScore:  80,
			CreatedAt:  time.Now(),
		}

		action := RiskAction{
			Type:        "block",
			Description: "Block on critical risk",
		}

		assessment := &RiskAssessment{
			TotalScore:   95,
			Level:        RiskLevelCritical,
			Signals:      []RiskSignal{signal},
			Actions:      []RiskAction{action},
			RequiresMFA:  true,
			Blocked:      true,
			BlockReason:  "Critical risk score exceeded threshold",
			Warnings:     []string{"Impossible travel detected"},
			DelaySeconds: 0,
		}

		assert.Equal(t, 95, assessment.TotalScore)
		assert.Equal(t, RiskLevelCritical, assessment.Level)
		assert.Len(t, assessment.Signals, 1)
		assert.Len(t, assessment.Actions, 1)
		assert.True(t, assessment.RequiresMFA)
		assert.True(t, assessment.Blocked)
		assert.Equal(t, "Critical risk score exceeded threshold", assessment.BlockReason)
		assert.Len(t, assessment.Warnings, 1)
	})

	t.Run("should represent a low-risk clean assessment", func(t *testing.T) {
		assessment := &RiskAssessment{
			TotalScore:  5,
			Level:       RiskLevelLow,
			Signals:     []RiskSignal{},
			Actions:     []RiskAction{},
			RequiresMFA: false,
			Blocked:     false,
		}

		assert.Equal(t, 5, assessment.TotalScore)
		assert.Equal(t, RiskLevelLow, assessment.Level)
		assert.Empty(t, assessment.Signals)
		assert.Empty(t, assessment.Actions)
		assert.False(t, assessment.RequiresMFA)
		assert.False(t, assessment.Blocked)
		assert.Empty(t, assessment.BlockReason)
	})

	t.Run("should represent an MFA-required medium-risk assessment", func(t *testing.T) {
		assessment := &RiskAssessment{
			TotalScore:  55,
			Level:       RiskLevelMedium,
			RequiresMFA: true,
			Blocked:     false,
			Warnings:    []string{"New device detected", "Unusual login time"},
		}

		assert.Equal(t, RiskLevelMedium, assessment.Level)
		assert.True(t, assessment.RequiresMFA)
		assert.False(t, assessment.Blocked)
		assert.Len(t, assessment.Warnings, 2)
	})
}

// ==================== RiskContext struct ====================

func TestRiskContext_Instantiation(t *testing.T) {
	t.Run("should create risk context with all fields", func(t *testing.T) {
		userID := uuid.New()
		tenantID := uuid.New()
		now := time.Now().Truncate(time.Second)
		lastLoginTime := now.Add(-24 * time.Hour)
		lastLoginIP := testIPAddrTen

		ctx := &RiskContext{
			UserID:            userID,
			TenantID:          tenantID,
			IPAddress:         "203.0.113.1",
			UserAgent:         testUserAgentMozilla,
			LoginTime:         now,
			IsNewDevice:       true,
			FailedAttempts:    3,
			LastLoginIP:       &lastLoginIP,
			LastLoginTime:     &lastLoginTime,
			AuthMethod:        "password",
			SSOProvider:       "",
			IsFirstFederation: false,
		}

		assert.Equal(t, userID, ctx.UserID)
		assert.Equal(t, tenantID, ctx.TenantID)
		assert.Equal(t, "203.0.113.1", ctx.IPAddress)
		assert.Equal(t, testUserAgentMozilla, ctx.UserAgent)
		assert.Equal(t, now, ctx.LoginTime)
		assert.True(t, ctx.IsNewDevice)
		assert.Equal(t, 3, ctx.FailedAttempts)
		assert.Equal(t, &lastLoginIP, ctx.LastLoginIP)
		assert.Equal(t, &lastLoginTime, ctx.LastLoginTime)
		assert.Equal(t, "password", ctx.AuthMethod)
		assert.False(t, ctx.IsFirstFederation)
	})

	t.Run("should create context for SSO federation", func(t *testing.T) {
		ctx := &RiskContext{
			UserID:            uuid.New(),
			TenantID:          uuid.New(),
			IPAddress:         "1.2.3.4",
			UserAgent:         "App/1.0",
			LoginTime:         time.Now(),
			AuthMethod:        "sso",
			SSOProvider:       "google",
			IsFirstFederation: true,
		}

		assert.Equal(t, "sso", ctx.AuthMethod)
		assert.Equal(t, "google", ctx.SSOProvider)
		assert.True(t, ctx.IsFirstFederation)
		assert.Nil(t, ctx.LastLoginIP)
		assert.Nil(t, ctx.LastLoginTime)
	})
}

// ==================== TrustedDevice.IsValid ====================

func TestTrustedDevice_IsValid(t *testing.T) {
	tests := []struct {
		name     string
		device   TrustedDevice
		expected bool
	}{
		{
			name: "should be valid when not revoked and not expired",
			device: TrustedDevice{
				RevokedAt: nil,
				ExpiresAt: nil,
			},
			expected: true,
		},
		{
			name: "should be valid when ExpiresAt is in the future",
			device: TrustedDevice{
				RevokedAt: nil,
				ExpiresAt: func() *time.Time { t := time.Now().Add(24 * time.Hour); return &t }(),
			},
			expected: true,
		},
		{
			name: "should be invalid when revoked",
			device: TrustedDevice{
				RevokedAt: func() *time.Time { t := time.Now().Add(-1 * time.Hour); return &t }(),
				ExpiresAt: nil,
			},
			expected: false,
		},
		{
			name: "should be invalid when expired",
			device: TrustedDevice{
				RevokedAt: nil,
				ExpiresAt: func() *time.Time { t := time.Now().Add(-1 * time.Hour); return &t }(),
			},
			expected: false,
		},
		{
			name: "should be invalid when both revoked and expired",
			device: TrustedDevice{
				RevokedAt: func() *time.Time { t := time.Now().Add(-2 * time.Hour); return &t }(),
				ExpiresAt: func() *time.Time { t := time.Now().Add(-1 * time.Hour); return &t }(),
			},
			expected: false,
		},
		{
			name: "revocation takes priority over non-expired status",
			device: TrustedDevice{
				RevokedAt: func() *time.Time { t := time.Now().Add(-1 * time.Minute); return &t }(),
				ExpiresAt: func() *time.Time { t := time.Now().Add(24 * time.Hour); return &t }(),
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.device.IsValid())
		})
	}
}

func TestTrustedDevice_IsValid_Boundary(t *testing.T) {
	t.Run("should be invalid one nanosecond past expiry", func(t *testing.T) {
		past := time.Now().Add(-1 * time.Nanosecond)
		device := &TrustedDevice{ExpiresAt: &past}
		assert.False(t, device.IsValid())
	})

	t.Run("should be valid one hour before expiry", func(t *testing.T) {
		future := time.Now().Add(1 * time.Hour)
		device := &TrustedDevice{ExpiresAt: &future}
		assert.True(t, device.IsValid())
	})
}

// ==================== TrustedDevice.ToResponse ====================

func TestTrustedDevice_ToResponse(t *testing.T) {
	t.Run("should map all fields correctly", func(t *testing.T) {
		id := uuid.New()
		userID := uuid.New()
		now := time.Now().Truncate(time.Second)
		expires := now.Add(30 * 24 * time.Hour)
		info := "MacBook Pro"
		ip := "192.168.1.100"

		device := &TrustedDevice{
			ID:         id,
			UserID:     userID,
			DeviceID:   "fp-abc123def456",
			DeviceInfo: &info,
			IPAddress:  &ip,
			LastUsedAt: now,
			TrustedAt:  now,
			ExpiresAt:  &expires,
		}

		resp := device.ToResponse()

		require.NotNil(t, resp)
		assert.Equal(t, id.String(), resp.ID)
		assert.Equal(t, "fp-abc123def456", resp.DeviceID)
		assert.Equal(t, info, resp.DeviceInfo)
		assert.Equal(t, ip, resp.IPAddress)
		assert.Equal(t, now, resp.LastUsedAt)
		assert.Equal(t, now, resp.TrustedAt)
		assert.Equal(t, &expires, resp.ExpiresAt)
	})

	t.Run("should return empty strings for nil DeviceInfo and IPAddress", func(t *testing.T) {
		device := &TrustedDevice{
			ID:         uuid.New(),
			UserID:     uuid.New(),
			DeviceID:   "fp-xyz",
			DeviceInfo: nil,
			IPAddress:  nil,
			LastUsedAt: time.Now(),
			TrustedAt:  time.Now(),
		}

		resp := device.ToResponse()

		require.NotNil(t, resp)
		assert.Equal(t, "", resp.DeviceInfo)
		assert.Equal(t, "", resp.IPAddress)
		assert.Nil(t, resp.ExpiresAt)
	})

	t.Run("should produce distinct instances on each call", func(t *testing.T) {
		device := &TrustedDevice{
			ID:         uuid.New(),
			UserID:     uuid.New(),
			DeviceID:   "fp-test",
			LastUsedAt: time.Now(),
			TrustedAt:  time.Now(),
		}

		resp1 := device.ToResponse()
		resp2 := device.ToResponse()

		assert.NotSame(t, resp1, resp2)
		assert.Equal(t, resp1, resp2)
	})
}

// ==================== RiskAction struct ====================

func TestRiskAction_Instantiation(t *testing.T) {
	tests := []struct {
		name        string
		actionType  string
		description string
		policyID    string
	}{
		{
			name:        "block action",
			actionType:  "block",
			description: "Block user due to critical risk",
			policyID:    "policy-001",
		},
		{
			name:        "require_mfa action",
			actionType:  "require_mfa",
			description: "Step-up authentication required",
			policyID:    "",
		},
		{
			name:        "notify_admin action",
			actionType:  "notify_admin",
			description: "Notify security team",
			policyID:    "policy-002",
		},
		{
			name:        "delay action",
			actionType:  "delay",
			description: "Introduce artificial delay",
			policyID:    "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			action := RiskAction{
				Type:        tt.actionType,
				Description: tt.description,
				PolicyID:    tt.policyID,
			}

			assert.Equal(t, tt.actionType, action.Type)
			assert.Equal(t, tt.description, action.Description)
			assert.Equal(t, tt.policyID, action.PolicyID)
		})
	}
}

// ==================== Request DTOs ====================

func TestCreateRiskPolicyRequest_Fields(t *testing.T) {
	t.Run("should populate all fields", func(t *testing.T) {
		req := CreateRiskPolicyRequest{
			Name:        "Critical Block",
			Description: "Block on critical risk",
			Conditions:  map[string]interface{}{"min_score": 90},
			Actions:     map[string]interface{}{"action": "block"},
			Priority:    1,
			IsActive:    true,
		}

		assert.Equal(t, "Critical Block", req.Name)
		assert.Equal(t, "Block on critical risk", req.Description)
		assert.Equal(t, map[string]interface{}{"min_score": 90}, req.Conditions)
		assert.Equal(t, map[string]interface{}{"action": "block"}, req.Actions)
		assert.Equal(t, 1, req.Priority)
		assert.True(t, req.IsActive)
	})
}

func TestUpdateRiskPolicyRequest_Fields(t *testing.T) {
	t.Run("all fields nil represents a no-op update", func(t *testing.T) {
		req := UpdateRiskPolicyRequest{}

		assert.Nil(t, req.Name)
		assert.Nil(t, req.Description)
		assert.Nil(t, req.Conditions)
		assert.Nil(t, req.Actions)
		assert.Nil(t, req.Priority)
		assert.Nil(t, req.IsActive)
	})

	t.Run("should allow partial update", func(t *testing.T) {
		name := "Updated Policy"
		isActive := false

		req := UpdateRiskPolicyRequest{
			Name:     &name,
			IsActive: &isActive,
		}

		assert.Equal(t, &name, req.Name)
		assert.Equal(t, &isActive, req.IsActive)
		assert.Nil(t, req.Description)
		assert.Nil(t, req.Conditions)
	})
}

func TestUpdateRiskThresholdRequest_Fields(t *testing.T) {
	t.Run("all fields nil represents a no-op update", func(t *testing.T) {
		req := UpdateRiskThresholdRequest{}

		assert.Nil(t, req.LowThreshold)
		assert.Nil(t, req.MediumThreshold)
		assert.Nil(t, req.HighThreshold)
		assert.Nil(t, req.CriticalThreshold)
		assert.Nil(t, req.AutoBlockOnCritical)
		assert.Nil(t, req.BlockDurationMinutes)
		assert.Nil(t, req.NotifyUserOnHighRisk)
		assert.Nil(t, req.NotifyAdminOnCritical)
	})

	t.Run("should allow partial threshold update", func(t *testing.T) {
		critical := 95
		autoBlock := true

		req := UpdateRiskThresholdRequest{
			CriticalThreshold:   &critical,
			AutoBlockOnCritical: &autoBlock,
		}

		assert.Equal(t, &critical, req.CriticalThreshold)
		assert.Equal(t, &autoBlock, req.AutoBlockOnCritical)
		assert.Nil(t, req.LowThreshold)
	})
}

// ==================== JSON marshaling ====================

func TestRiskAssessment_JSONMarshal(t *testing.T) {
	t.Run("should marshal and unmarshal RiskAssessment", func(t *testing.T) {
		assessment := &RiskAssessment{
			TotalScore:  75,
			Level:       RiskLevelHigh,
			RequiresMFA: true,
			Blocked:     false,
			Warnings:    []string{"New location detected"},
		}

		data, err := json.Marshal(assessment)
		require.NoError(t, err)

		var decoded RiskAssessment
		err = json.Unmarshal(data, &decoded)
		require.NoError(t, err)

		assert.Equal(t, assessment.TotalScore, decoded.TotalScore)
		assert.Equal(t, assessment.Level, decoded.Level)
		assert.Equal(t, assessment.RequiresMFA, decoded.RequiresMFA)
		assert.Equal(t, assessment.Blocked, decoded.Blocked)
		assert.Equal(t, assessment.Warnings, decoded.Warnings)
	})
}
