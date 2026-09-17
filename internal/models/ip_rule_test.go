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

// ==================== IPRuleType constants ====================

func TestIPRuleTypeConstants(t *testing.T) {
	assert.Equal(t, IPRuleType("allow"), IPRuleTypeAllow)
	assert.Equal(t, IPRuleType("deny"), IPRuleTypeDeny)
}

// ==================== IPRuleAppliesTo constants ====================

func TestIPRuleAppliesToConstants(t *testing.T) {
	assert.Equal(t, IPRuleAppliesTo("all"), IPRuleAppliesToAll)
	assert.Equal(t, IPRuleAppliesTo("admin"), IPRuleAppliesToAdmin)
	assert.Equal(t, IPRuleAppliesTo("api"), IPRuleAppliesToAPI)
	assert.Equal(t, IPRuleAppliesTo("user"), IPRuleAppliesToUser)
}

// ==================== IPRule struct instantiation ====================

func TestIPRule_Instantiation(t *testing.T) {
	t.Run("should create rule with all fields set", func(t *testing.T) {
		id := uuid.New()
		tenantID := uuid.New()
		createdBy := uuid.New()
		updatedBy := uuid.New()
		now := time.Now().Truncate(time.Second)
		desc := "Block known bad actors"
		expires := now.Add(30 * 24 * time.Hour)
		lastHit := now.Add(-1 * time.Hour)

		rule := &IPRule{
			ID:          id,
			TenantID:    tenantID,
			Name:        "Block Bad IPs",
			Description: &desc,
			IPPattern:   "192.168.1.0/24",
			RuleType:    IPRuleTypeDeny,
			Priority:    100,
			IsActive:    true,
			AppliesTo:   IPRuleAppliesToAll,
			ExpiresAt:   &expires,
			HitCount:    42,
			LastHitAt:   &lastHit,
			CreatedAt:   now,
			UpdatedAt:   now,
			CreatedBy:   &createdBy,
			UpdatedBy:   &updatedBy,
		}

		assert.Equal(t, id, rule.ID)
		assert.Equal(t, tenantID, rule.TenantID)
		assert.Equal(t, "Block Bad IPs", rule.Name)
		assert.Equal(t, &desc, rule.Description)
		assert.Equal(t, "192.168.1.0/24", rule.IPPattern)
		assert.Equal(t, IPRuleTypeDeny, rule.RuleType)
		assert.Equal(t, 100, rule.Priority)
		assert.True(t, rule.IsActive)
		assert.Equal(t, IPRuleAppliesToAll, rule.AppliesTo)
		assert.Equal(t, &expires, rule.ExpiresAt)
		assert.Equal(t, int64(42), rule.HitCount)
		assert.Equal(t, &lastHit, rule.LastHitAt)
		assert.Equal(t, now, rule.CreatedAt)
		assert.Equal(t, now, rule.UpdatedAt)
		assert.Equal(t, &createdBy, rule.CreatedBy)
		assert.Equal(t, &updatedBy, rule.UpdatedBy)
	})

	t.Run("should create rule with nil optional fields", func(t *testing.T) {
		rule := &IPRule{
			ID:        uuid.New(),
			TenantID:  uuid.New(),
			Name:      "Allow Office",
			IPPattern: "10.0.0.1",
			RuleType:  IPRuleTypeAllow,
			IsActive:  true,
			AppliesTo: IPRuleAppliesToAPI,
		}

		assert.Nil(t, rule.Description)
		assert.Nil(t, rule.ExpiresAt)
		assert.Nil(t, rule.LastHitAt)
		assert.Nil(t, rule.CreatedBy)
		assert.Nil(t, rule.UpdatedBy)
		assert.Equal(t, int64(0), rule.HitCount)
	})
}

// ==================== IPRule.ToResponse ====================

func TestIPRule_ToResponse(t *testing.T) {
	t.Run("should map all fields correctly", func(t *testing.T) {
		id := uuid.New()
		tenantID := uuid.New()
		now := time.Now().Truncate(time.Second)
		desc := "Office network"
		expires := now.Add(365 * 24 * time.Hour)
		lastHit := now.Add(-2 * time.Hour)

		rule := &IPRule{
			ID:          id,
			TenantID:    tenantID,
			Name:        "Allow Office",
			Description: &desc,
			IPPattern:   "203.0.113.0/24",
			RuleType:    IPRuleTypeAllow,
			Priority:    10,
			IsActive:    true,
			AppliesTo:   IPRuleAppliesToAdmin,
			ExpiresAt:   &expires,
			HitCount:    100,
			LastHitAt:   &lastHit,
			CreatedAt:   now,
			UpdatedAt:   now,
		}

		resp := rule.ToResponse()

		require.NotNil(t, resp)
		assert.Equal(t, id, resp.ID)
		assert.Equal(t, tenantID, resp.TenantID)
		assert.Equal(t, "Allow Office", resp.Name)
		assert.Equal(t, &desc, resp.Description)
		assert.Equal(t, "203.0.113.0/24", resp.IPPattern)
		assert.Equal(t, "allow", resp.RuleType)
		assert.Equal(t, 10, resp.Priority)
		assert.True(t, resp.IsActive)
		assert.Equal(t, "admin", resp.AppliesTo)
		assert.Equal(t, &expires, resp.ExpiresAt)
		assert.Equal(t, int64(100), resp.HitCount)
		assert.Equal(t, &lastHit, resp.LastHitAt)
		assert.Equal(t, now, resp.CreatedAt)
		assert.Equal(t, now, resp.UpdatedAt)
	})

	t.Run("should convert IPRuleType and IPRuleAppliesTo to strings", func(t *testing.T) {
		tests := []struct {
			name          string
			ruleType      IPRuleType
			appliesTo     IPRuleAppliesTo
			wantRuleType  string
			wantAppliesTo string
		}{
			{
				name:          "allow rule for all",
				ruleType:      IPRuleTypeAllow,
				appliesTo:     IPRuleAppliesToAll,
				wantRuleType:  "allow",
				wantAppliesTo: "all",
			},
			{
				name:          "deny rule for api",
				ruleType:      IPRuleTypeDeny,
				appliesTo:     IPRuleAppliesToAPI,
				wantRuleType:  "deny",
				wantAppliesTo: "api",
			},
			{
				name:          "allow rule for user",
				ruleType:      IPRuleTypeAllow,
				appliesTo:     IPRuleAppliesToUser,
				wantRuleType:  "allow",
				wantAppliesTo: "user",
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				rule := &IPRule{
					ID:        uuid.New(),
					TenantID:  uuid.New(),
					RuleType:  tt.ruleType,
					AppliesTo: tt.appliesTo,
				}

				resp := rule.ToResponse()

				assert.Equal(t, tt.wantRuleType, resp.RuleType)
				assert.Equal(t, tt.wantAppliesTo, resp.AppliesTo)
			})
		}
	})

	t.Run("should handle nil optional fields", func(t *testing.T) {
		rule := &IPRule{
			ID:        uuid.New(),
			TenantID:  uuid.New(),
			Name:      "Minimal Rule",
			IPPattern: "192.0.2.1",
			RuleType:  IPRuleTypeDeny,
			IsActive:  false,
			AppliesTo: IPRuleAppliesToAll,
		}

		resp := rule.ToResponse()

		require.NotNil(t, resp)
		assert.Nil(t, resp.Description)
		assert.Nil(t, resp.ExpiresAt)
		assert.Nil(t, resp.LastHitAt)
		assert.Equal(t, int64(0), resp.HitCount)
	})

	t.Run("should not include CreatedBy and UpdatedBy in response", func(t *testing.T) {
		createdBy := uuid.New()
		updatedBy := uuid.New()

		rule := &IPRule{
			ID:        uuid.New(),
			TenantID:  uuid.New(),
			Name:      "Rule",
			IPPattern: "1.2.3.4",
			RuleType:  IPRuleTypeAllow,
			AppliesTo: IPRuleAppliesToAll,
			CreatedBy: &createdBy,
			UpdatedBy: &updatedBy,
		}

		resp := rule.ToResponse()
		require.NotNil(t, resp)
		// IPRuleResponse does not expose CreatedBy/UpdatedBy — the struct has no
		// such fields. We just verify the response is valid and the conversion succeeds.
		assert.Equal(t, rule.ID, resp.ID)
	})

	t.Run("should produce a distinct instance on each call", func(t *testing.T) {
		rule := &IPRule{
			ID:        uuid.New(),
			TenantID:  uuid.New(),
			Name:      "Rule",
			IPPattern: "10.0.0.0/8",
			RuleType:  IPRuleTypeAllow,
			AppliesTo: IPRuleAppliesToAll,
		}

		resp1 := rule.ToResponse()
		resp2 := rule.ToResponse()

		assert.NotSame(t, resp1, resp2)
		assert.Equal(t, resp1, resp2)
	})
}

// ==================== IPRule IsExpired (via ExpiresAt field) ====================

func TestIPRule_IsExpired(t *testing.T) {
	tests := []struct {
		name      string
		expiresAt *time.Time
		wantPast  bool
	}{
		{
			name:      "should not be considered expired when ExpiresAt is nil",
			expiresAt: nil,
			wantPast:  false,
		},
		{
			name:      "should be considered expired when ExpiresAt is in the past",
			expiresAt: func() *time.Time { t := time.Now().Add(-1 * time.Hour); return &t }(),
			wantPast:  true,
		},
		{
			name:      "should not be considered expired when ExpiresAt is in the future",
			expiresAt: func() *time.Time { t := time.Now().Add(24 * time.Hour); return &t }(),
			wantPast:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := &IPRule{
				ID:        uuid.New(),
				TenantID:  uuid.New(),
				ExpiresAt: tt.expiresAt,
			}

			switch {
			case tt.expiresAt == nil:
				assert.Nil(t, rule.ExpiresAt)
			case tt.wantPast:
				assert.True(t, time.Now().After(*rule.ExpiresAt),
					"ExpiresAt should be in the past")
			default:
				assert.True(t, time.Now().Before(*rule.ExpiresAt),
					"ExpiresAt should be in the future")
			}
		})
	}
}

// ==================== CreateIPRuleRequest struct ====================

func TestCreateIPRuleRequest_Fields(t *testing.T) {
	t.Run("should populate all fields", func(t *testing.T) {
		desc := "Block malicious range"
		appliesTo := "api"
		expiresAt := "2027-01-01T00:00:00Z"
		priority := 50
		isActive := true

		req := CreateIPRuleRequest{
			Name:        "Block Range",
			Description: &desc,
			IPPattern:   "198.51.100.0/24",
			RuleType:    "deny",
			Priority:    &priority,
			AppliesTo:   &appliesTo,
			ExpiresAt:   &expiresAt,
			IsActive:    &isActive,
		}

		assert.Equal(t, "Block Range", req.Name)
		assert.Equal(t, &desc, req.Description)
		assert.Equal(t, "198.51.100.0/24", req.IPPattern)
		assert.Equal(t, "deny", req.RuleType)
		assert.Equal(t, &priority, req.Priority)
		assert.Equal(t, &appliesTo, req.AppliesTo)
		assert.Equal(t, &expiresAt, req.ExpiresAt)
		assert.Equal(t, &isActive, req.IsActive)
	})

	t.Run("should allow nil optional fields", func(t *testing.T) {
		req := CreateIPRuleRequest{
			Name:      "Minimal Rule",
			IPPattern: "10.0.0.1",
			RuleType:  "allow",
		}

		assert.Nil(t, req.Description)
		assert.Nil(t, req.Priority)
		assert.Nil(t, req.AppliesTo)
		assert.Nil(t, req.ExpiresAt)
		assert.Nil(t, req.IsActive)
	})
}

// ==================== UpdateIPRuleRequest struct ====================

func TestUpdateIPRuleRequest_Fields(t *testing.T) {
	t.Run("all fields nil represents a no-op update", func(t *testing.T) {
		req := UpdateIPRuleRequest{}

		assert.Nil(t, req.Name)
		assert.Nil(t, req.Description)
		assert.Nil(t, req.IPPattern)
		assert.Nil(t, req.RuleType)
		assert.Nil(t, req.Priority)
		assert.Nil(t, req.AppliesTo)
		assert.Nil(t, req.ExpiresAt)
		assert.Nil(t, req.IsActive)
	})

	t.Run("should allow partial update with only selected fields", func(t *testing.T) {
		name := "Updated Name"
		isActive := false

		req := UpdateIPRuleRequest{
			Name:     &name,
			IsActive: &isActive,
		}

		assert.Equal(t, &name, req.Name)
		assert.Equal(t, &isActive, req.IsActive)
		assert.Nil(t, req.Description)
		assert.Nil(t, req.IPPattern)
		assert.Nil(t, req.RuleType)
	})
}

// ==================== IPRuleLog struct ====================

func TestIPRuleLog_Instantiation(t *testing.T) {
	t.Run("should create log entry with all fields", func(t *testing.T) {
		id := uuid.New()
		ruleID := uuid.New()
		tenantID := uuid.New()
		now := time.Now().Truncate(time.Second)

		log := &IPRuleLog{
			ID:        id,
			RuleID:    &ruleID,
			TenantID:  &tenantID,
			IPAddress: "203.0.113.42",
			Action:    "denied",
			Endpoint:  "/api/v1/auth/login",
			UserAgent: "Mozilla/5.0",
			CreatedAt: now,
		}

		assert.Equal(t, id, log.ID)
		assert.Equal(t, &ruleID, log.RuleID)
		assert.Equal(t, &tenantID, log.TenantID)
		assert.Equal(t, "203.0.113.42", log.IPAddress)
		assert.Equal(t, "denied", log.Action)
		assert.Equal(t, "/api/v1/auth/login", log.Endpoint)
		assert.Equal(t, "Mozilla/5.0", log.UserAgent)
		assert.Equal(t, now, log.CreatedAt)
	})

	t.Run("should create log entry with nil optional fields", func(t *testing.T) {
		log := &IPRuleLog{
			ID:        uuid.New(),
			IPAddress: "192.0.2.5",
			Action:    "allowed",
			Endpoint:  "/health",
		}

		assert.Nil(t, log.RuleID)
		assert.Nil(t, log.TenantID)
	})
}

// ==================== IPCheckResult struct ====================

func TestIPCheckResult_Instantiation(t *testing.T) {
	tests := []struct {
		name      string
		result    IPCheckResult
		wantAllow bool
	}{
		{
			name: "allowed result",
			result: IPCheckResult{
				Allowed:   true,
				RuleID:    uuid.New(),
				RuleName:  "Office Allow",
				RuleType:  "allow",
				MatchedIP: "10.0.0.1",
			},
			wantAllow: true,
		},
		{
			name: "denied result",
			result: IPCheckResult{
				Allowed:   false,
				RuleID:    uuid.New(),
				RuleName:  "Blacklist",
				RuleType:  "deny",
				MatchedIP: "198.51.100.1",
			},
			wantAllow: false,
		},
		{
			name:      "default zero value is denied",
			result:    IPCheckResult{},
			wantAllow: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.wantAllow, tt.result.Allowed)
		})
	}
}

// ==================== JSON marshaling ====================

func TestIPRule_JSONMarshal(t *testing.T) {
	t.Run("should marshal to JSON and back", func(t *testing.T) {
		id := uuid.New()
		tenantID := uuid.New()
		now := time.Now().Truncate(time.Second)
		desc := "test description"

		rule := &IPRule{
			ID:          id,
			TenantID:    tenantID,
			Name:        "Test Rule",
			Description: &desc,
			IPPattern:   "10.0.0.0/8",
			RuleType:    IPRuleTypeAllow,
			Priority:    5,
			IsActive:    true,
			AppliesTo:   IPRuleAppliesToAll,
			HitCount:    0,
			CreatedAt:   now,
			UpdatedAt:   now,
		}

		data, err := json.Marshal(rule)
		require.NoError(t, err)

		var decoded IPRule
		err = json.Unmarshal(data, &decoded)
		require.NoError(t, err)

		assert.Equal(t, rule.ID, decoded.ID)
		assert.Equal(t, rule.Name, decoded.Name)
		assert.Equal(t, rule.IPPattern, decoded.IPPattern)
		assert.Equal(t, rule.RuleType, decoded.RuleType)
		assert.Equal(t, rule.IsActive, decoded.IsActive)
	})
}
