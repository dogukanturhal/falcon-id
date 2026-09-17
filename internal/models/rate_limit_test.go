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

// ==================== RateLimitScope constants ====================

func TestRateLimitScopeConstants(t *testing.T) {
	assert.Equal(t, RateLimitScope("ip"), RateLimitScopeIP)
	assert.Equal(t, RateLimitScope("user"), RateLimitScopeUser)
	assert.Equal(t, RateLimitScope("tenant"), RateLimitScopeTenant)
	assert.Equal(t, RateLimitScope("global"), RateLimitScopeGlobal)
}

// ==================== RateLimitRule struct instantiation ====================

func buildRateLimitRule() *RateLimitRule {
	tenantID := uuid.New()
	createdBy := uuid.New()
	updatedBy := uuid.New()
	now := time.Now().Truncate(time.Second)
	desc := "Login endpoint rate limit"
	method := "POST"

	return &RateLimitRule{
		ID:                   uuid.New(),
		TenantID:             &tenantID,
		Name:                 "Login Rate Limit",
		Description:          &desc,
		EndpointPattern:      "/api/v1/auth/login",
		Method:               &method,
		MaxRequests:          10,
		WindowSeconds:        60,
		BlockDurationSeconds: 300,
		Scope:                RateLimitScopeIP,
		IsActive:             true,
		Priority:             100,
		CreatedAt:            now,
		UpdatedAt:            now,
		CreatedBy:            &createdBy,
		UpdatedBy:            &updatedBy,
	}
}

func TestRateLimitRule_Instantiation(t *testing.T) {
	t.Run("should create rule with all fields set", func(t *testing.T) {
		r := buildRateLimitRule()

		assert.NotEqual(t, uuid.Nil, r.ID)
		assert.NotNil(t, r.TenantID)
		assert.Equal(t, "Login Rate Limit", r.Name)
		assert.NotNil(t, r.Description)
		assert.Equal(t, "/api/v1/auth/login", r.EndpointPattern)
		assert.NotNil(t, r.Method)
		assert.Equal(t, 10, r.MaxRequests)
		assert.Equal(t, 60, r.WindowSeconds)
		assert.Equal(t, 300, r.BlockDurationSeconds)
		assert.Equal(t, RateLimitScopeIP, r.Scope)
		assert.True(t, r.IsActive)
		assert.Equal(t, 100, r.Priority)
		assert.NotNil(t, r.CreatedBy)
		assert.NotNil(t, r.UpdatedBy)
	})

	t.Run("should create global rule without tenant", func(t *testing.T) {
		r := &RateLimitRule{
			ID:              uuid.New(),
			TenantID:        nil,
			Name:            "Global API Limit",
			EndpointPattern: "/api/*",
			MaxRequests:     1000,
			WindowSeconds:   60,
			Scope:           RateLimitScopeGlobal,
			IsActive:        true,
		}

		assert.Nil(t, r.TenantID)
		assert.Equal(t, RateLimitScopeGlobal, r.Scope)
		assert.Nil(t, r.Method)
		assert.Nil(t, r.Description)
	})
}

// ==================== RateLimitRule.ToResponse ====================

func TestRateLimitRule_ToResponse(t *testing.T) {
	t.Run("should map all fields correctly", func(t *testing.T) {
		r := buildRateLimitRule()

		resp := r.ToResponse()

		require.NotNil(t, resp)
		assert.Equal(t, r.ID, resp.ID)
		assert.Equal(t, r.TenantID, resp.TenantID)
		assert.Equal(t, r.Name, resp.Name)
		assert.Equal(t, r.Description, resp.Description)
		assert.Equal(t, r.EndpointPattern, resp.EndpointPattern)
		assert.Equal(t, r.Method, resp.Method)
		assert.Equal(t, r.MaxRequests, resp.MaxRequests)
		assert.Equal(t, r.WindowSeconds, resp.WindowSeconds)
		assert.Equal(t, r.BlockDurationSeconds, resp.BlockDurationSeconds)
		assert.Equal(t, string(r.Scope), resp.Scope)
		assert.Equal(t, r.IsActive, resp.IsActive)
		assert.Equal(t, r.Priority, resp.Priority)
		assert.Equal(t, r.CreatedAt, resp.CreatedAt)
		assert.Equal(t, r.UpdatedAt, resp.UpdatedAt)
	})

	t.Run("should convert RateLimitScope to string in response", func(t *testing.T) {
		tests := []struct {
			scope     RateLimitScope
			wantScope string
		}{
			{RateLimitScopeIP, "ip"},
			{RateLimitScopeUser, "user"},
			{RateLimitScopeTenant, "tenant"},
			{RateLimitScopeGlobal, "global"},
		}

		for _, tt := range tests {
			t.Run(string(tt.scope), func(t *testing.T) {
				r := &RateLimitRule{
					ID:    uuid.New(),
					Scope: tt.scope,
				}

				resp := r.ToResponse()

				assert.Equal(t, tt.wantScope, resp.Scope)
			})
		}
	})

	t.Run("should handle nil optional fields", func(t *testing.T) {
		r := &RateLimitRule{
			ID:              uuid.New(),
			Name:            "Minimal Rule",
			EndpointPattern: "/api/*",
			MaxRequests:     100,
			WindowSeconds:   60,
			Scope:           RateLimitScopeGlobal,
		}

		resp := r.ToResponse()

		require.NotNil(t, resp)
		assert.Nil(t, resp.TenantID)
		assert.Nil(t, resp.Description)
		assert.Nil(t, resp.Method)
	})

	t.Run("should produce a distinct instance on each call", func(t *testing.T) {
		r := buildRateLimitRule()

		resp1 := r.ToResponse()
		resp2 := r.ToResponse()

		assert.NotSame(t, resp1, resp2)
		assert.Equal(t, resp1, resp2)
	})

	t.Run("should not expose CreatedBy and UpdatedBy in response", func(t *testing.T) {
		r := buildRateLimitRule()

		resp := r.ToResponse()

		// RateLimitRuleResponse has no CreatedBy/UpdatedBy fields.
		// Just verify the conversion succeeds and the ID is correct.
		require.NotNil(t, resp)
		assert.Equal(t, r.ID, resp.ID)
	})
}

// ==================== RateLimitEvent struct ====================

func TestRateLimitEvent_Instantiation(t *testing.T) {
	t.Run("should create event with all fields set", func(t *testing.T) {
		id := uuid.New()
		ruleID := uuid.New()
		tenantID := uuid.New()
		now := time.Now().Truncate(time.Second)
		blockedUntil := now.Add(5 * time.Minute)

		event := &RateLimitEvent{
			ID:           id,
			RuleID:       &ruleID,
			TenantID:     &tenantID,
			Identifier:   "192.168.1.100",
			Endpoint:     "/api/v1/auth/login",
			RequestCount: 15,
			Blocked:      true,
			BlockedUntil: &blockedUntil,
			CreatedAt:    now,
		}

		assert.Equal(t, id, event.ID)
		assert.Equal(t, &ruleID, event.RuleID)
		assert.Equal(t, &tenantID, event.TenantID)
		assert.Equal(t, "192.168.1.100", event.Identifier)
		assert.Equal(t, "/api/v1/auth/login", event.Endpoint)
		assert.Equal(t, 15, event.RequestCount)
		assert.True(t, event.Blocked)
		assert.Equal(t, &blockedUntil, event.BlockedUntil)
		assert.Equal(t, now, event.CreatedAt)
	})

	t.Run("should create event with nil optional fields", func(t *testing.T) {
		event := &RateLimitEvent{
			ID:           uuid.New(),
			Identifier:   "user-abc123",
			Endpoint:     "/api/v1/data",
			RequestCount: 5,
			Blocked:      false,
		}

		assert.Nil(t, event.RuleID)
		assert.Nil(t, event.TenantID)
		assert.Nil(t, event.BlockedUntil)
		assert.False(t, event.Blocked)
	})
}

// ==================== RateLimitState struct ====================

func TestRateLimitState_Instantiation(t *testing.T) {
	t.Run("should represent an active non-blocked state", func(t *testing.T) {
		now := time.Now().Truncate(time.Second)
		windowEnd := now.Add(60 * time.Second)
		resetAt := windowEnd

		state := RateLimitState{
			Key:         "ip:192.168.1.1:/api/login",
			Requests:    3,
			WindowStart: now,
			WindowEnd:   windowEnd,
			Blocked:     false,
			Remaining:   7,
			ResetAt:     resetAt,
		}

		assert.Equal(t, "ip:192.168.1.1:/api/login", state.Key)
		assert.Equal(t, 3, state.Requests)
		assert.Equal(t, now, state.WindowStart)
		assert.Equal(t, windowEnd, state.WindowEnd)
		assert.False(t, state.Blocked)
		assert.Equal(t, 7, state.Remaining)
		assert.Equal(t, resetAt, state.ResetAt)
	})

	t.Run("should represent a blocked state", func(t *testing.T) {
		now := time.Now().Truncate(time.Second)
		blockedUntil := now.Add(5 * time.Minute)

		state := RateLimitState{
			Key:          "user:abc123:/api/data",
			Requests:     100,
			Blocked:      true,
			BlockedUntil: blockedUntil,
			Remaining:    0,
		}

		assert.True(t, state.Blocked)
		assert.Equal(t, blockedUntil, state.BlockedUntil)
		assert.Equal(t, 0, state.Remaining)
	})
}

// ==================== CreateRateLimitRuleRequest ====================

func TestCreateRateLimitRuleRequest_Fields(t *testing.T) {
	t.Run("should populate all fields", func(t *testing.T) {
		desc := "Login endpoint protection"
		method := "POST"
		blockDuration := 300
		priority := 100
		isActive := true

		req := CreateRateLimitRuleRequest{
			Name:                 "Login Rate Limit",
			Description:          &desc,
			EndpointPattern:      "/api/v1/auth/login",
			Method:               &method,
			MaxRequests:          10,
			WindowSeconds:        60,
			BlockDurationSeconds: &blockDuration,
			Scope:                "ip",
			Priority:             &priority,
			IsActive:             &isActive,
		}

		assert.Equal(t, "Login Rate Limit", req.Name)
		assert.Equal(t, &desc, req.Description)
		assert.Equal(t, "/api/v1/auth/login", req.EndpointPattern)
		assert.Equal(t, &method, req.Method)
		assert.Equal(t, 10, req.MaxRequests)
		assert.Equal(t, 60, req.WindowSeconds)
		assert.Equal(t, &blockDuration, req.BlockDurationSeconds)
		assert.Equal(t, "ip", req.Scope)
		assert.Equal(t, &priority, req.Priority)
		assert.Equal(t, &isActive, req.IsActive)
	})

	t.Run("should allow nil optional fields", func(t *testing.T) {
		req := CreateRateLimitRuleRequest{
			Name:            "Minimal Rule",
			EndpointPattern: "/api/*",
			MaxRequests:     100,
			WindowSeconds:   60,
			Scope:           "global",
		}

		assert.Nil(t, req.Description)
		assert.Nil(t, req.Method)
		assert.Nil(t, req.BlockDurationSeconds)
		assert.Nil(t, req.Priority)
		assert.Nil(t, req.IsActive)
	})
}

// ==================== UpdateRateLimitRuleRequest ====================

func TestUpdateRateLimitRuleRequest_Fields(t *testing.T) {
	t.Run("all fields nil represents a no-op update", func(t *testing.T) {
		req := UpdateRateLimitRuleRequest{}

		assert.Nil(t, req.Name)
		assert.Nil(t, req.Description)
		assert.Nil(t, req.EndpointPattern)
		assert.Nil(t, req.Method)
		assert.Nil(t, req.MaxRequests)
		assert.Nil(t, req.WindowSeconds)
		assert.Nil(t, req.BlockDurationSeconds)
		assert.Nil(t, req.Scope)
		assert.Nil(t, req.Priority)
		assert.Nil(t, req.IsActive)
	})

	t.Run("should allow partial updates", func(t *testing.T) {
		maxRequests := 50
		isActive := false

		req := UpdateRateLimitRuleRequest{
			MaxRequests: &maxRequests,
			IsActive:    &isActive,
		}

		assert.Equal(t, &maxRequests, req.MaxRequests)
		assert.Equal(t, &isActive, req.IsActive)
		assert.Nil(t, req.Name)
		assert.Nil(t, req.Scope)
	})
}

// ==================== JSON marshaling ====================

func TestRateLimitRule_JSONMarshal(t *testing.T) {
	t.Run("should marshal to JSON and back", func(t *testing.T) {
		r := buildRateLimitRule()

		data, err := json.Marshal(r)
		require.NoError(t, err)

		var decoded RateLimitRule
		err = json.Unmarshal(data, &decoded)
		require.NoError(t, err)

		assert.Equal(t, r.ID, decoded.ID)
		assert.Equal(t, r.Name, decoded.Name)
		assert.Equal(t, r.EndpointPattern, decoded.EndpointPattern)
		assert.Equal(t, r.MaxRequests, decoded.MaxRequests)
		assert.Equal(t, r.WindowSeconds, decoded.WindowSeconds)
		assert.Equal(t, r.Scope, decoded.Scope)
		assert.Equal(t, r.IsActive, decoded.IsActive)
	})
}

// ==================== RateLimitRuleResponse struct ====================

func TestRateLimitRuleResponse_Fields(t *testing.T) {
	t.Run("should hold all expected response fields", func(t *testing.T) {
		id := uuid.New()
		tenantID := uuid.New()
		now := time.Now().Truncate(time.Second)
		desc := "A response"
		method := "GET"

		resp := &RateLimitRuleResponse{
			ID:                   id,
			TenantID:             &tenantID,
			Name:                 "Test",
			Description:          &desc,
			EndpointPattern:      "/api/*",
			Method:               &method,
			MaxRequests:          100,
			WindowSeconds:        60,
			BlockDurationSeconds: 0,
			Scope:                "ip",
			IsActive:             true,
			Priority:             10,
			CreatedAt:            now,
			UpdatedAt:            now,
		}

		assert.Equal(t, id, resp.ID)
		assert.Equal(t, &tenantID, resp.TenantID)
		assert.Equal(t, "Test", resp.Name)
		assert.Equal(t, "ip", resp.Scope)
		assert.True(t, resp.IsActive)
	})
}
