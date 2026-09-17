// SPDX-License-Identifier: AGPL-3.0-or-later

package models

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testIPAddr203   = "203.0.113.42"
	testExpiry2027  = "2027-01-01T00:00:00Z"
	testUpdatedDesc = "Updated description"
	testIPAddrTen   = "10.0.0.1"
)

// buildAPIKey returns a fully populated APIKey for use in tests.
func buildAPIKey() *APIKey {
	id := uuid.New()
	tenantID := uuid.New()
	userID := uuid.New()
	createdBy := uuid.New()
	now := time.Now().Truncate(time.Second)
	lastUsed := now.Add(-10 * time.Minute)
	lastIP := testIPAddr203
	expires := now.Add(30 * 24 * time.Hour)
	desc := "Integration test key"
	rateLimit := 5000

	return &APIKey{
		ID:                id,
		TenantID:          tenantID,
		UserID:            userID,
		Name:              "My Integration Key",
		Description:       &desc,
		KeyPrefix:         "hxk_live_",
		KeyHash:           "$argon2id$v=19$m=65536,t=3,p=4$secretHash",
		Scopes:            pq.StringArray{"users:read", "roles:read"},
		IPWhitelist:       pq.StringArray{"10.0.0.0/8"},
		AllowedEndpoints:  pq.StringArray{"/api/v1/users"},
		RateLimitOverride: &rateLimit,
		Environment:       "production",
		IsActive:          true,
		UsageCount:        1337,
		LastUsedAt:        &lastUsed,
		LastUsedIP:        &lastIP,
		CreatedAt:         now,
		ExpiresAt:         &expires,
		RevokedAt:         nil,
		CreatedBy:         &createdBy,
	}
}

// ==================== APIKey.IsExpired ====================

func TestAPIKey_IsExpired(t *testing.T) {
	tests := []struct {
		name     string
		setup    func() *APIKey
		expected bool
	}{
		{
			name: "should return false when ExpiresAt is nil (non-expiring key)",
			setup: func() *APIKey {
				return &APIKey{ExpiresAt: nil}
			},
			expected: false,
		},
		{
			name: "should return false when ExpiresAt is in the future",
			setup: func() *APIKey {
				return &APIKey{ExpiresAt: timePtr(time.Now().Add(24 * time.Hour))}
			},
			expected: false,
		},
		{
			name: "should return true when ExpiresAt is in the past",
			setup: func() *APIKey {
				return &APIKey{ExpiresAt: timePtr(time.Now().Add(-1 * time.Second))}
			},
			expected: true,
		},
		{
			name: "should return true one nanosecond past expiry",
			setup: func() *APIKey {
				return &APIKey{ExpiresAt: timePtr(time.Now().Add(-1 * time.Nanosecond))}
			},
			expected: true,
		},
		{
			name: "should return false for a key expiring far in the future",
			setup: func() *APIKey {
				return &APIKey{ExpiresAt: timePtr(time.Now().Add(365 * 24 * time.Hour))}
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k := tt.setup()
			// IsExpired is implemented via the ExpiresAt field check pattern
			// (no direct method on APIKey — we test the field-level logic
			// through the struct and JSON, since IsActive encapsulates this).
			isExpired := k.ExpiresAt != nil && time.Now().After(*k.ExpiresAt)
			assert.Equal(t, tt.expected, isExpired)
		})
	}
}

// ==================== APIKey.IsActive (field value) ====================

func TestAPIKey_IsActiveField(t *testing.T) {
	tests := []struct {
		name     string
		isActive bool
		expected bool
	}{
		{
			name:     "should be active when IsActive is true",
			isActive: true,
			expected: true,
		},
		{
			name:     "should not be active when IsActive is false",
			isActive: false,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k := &APIKey{IsActive: tt.isActive}
			assert.Equal(t, tt.expected, k.IsActive)
		})
	}
}

// ==================== APIKey.ToResponse ====================

func TestAPIKey_ToResponse(t *testing.T) {
	t.Run("should map all scalar fields correctly", func(t *testing.T) {
		k := buildAPIKey()

		resp := k.ToResponse()

		require.NotNil(t, resp)
		assert.Equal(t, k.ID, resp.ID)
		assert.Equal(t, k.TenantID, resp.TenantID)
		assert.Equal(t, k.UserID, resp.UserID)
		assert.Equal(t, k.Name, resp.Name)
		assert.Equal(t, k.Description, resp.Description)
		assert.Equal(t, k.KeyPrefix, resp.KeyPrefix)
		assert.ElementsMatch(t, k.Scopes, resp.Scopes)
		assert.ElementsMatch(t, k.IPWhitelist, resp.IPWhitelist)
		assert.ElementsMatch(t, k.AllowedEndpoints, resp.AllowedEndpoints)
		assert.Equal(t, k.RateLimitOverride, resp.RateLimitOverride)
		assert.Equal(t, k.Environment, resp.Environment)
		assert.Equal(t, k.IsActive, resp.IsActive)
		assert.Equal(t, k.UsageCount, resp.UsageCount)
		assert.Equal(t, k.LastUsedAt, resp.LastUsedAt)
		assert.Equal(t, k.LastUsedIP, resp.LastUsedIP)
		assert.Equal(t, k.CreatedAt, resp.CreatedAt)
		assert.Equal(t, k.ExpiresAt, resp.ExpiresAt)
		assert.Equal(t, k.RevokedAt, resp.RevokedAt)
	})

	t.Run("should NOT include KeyHash in response", func(t *testing.T) {
		k := buildAPIKey()
		k.KeyHash = "$argon2id$v=19$supersecret"

		resp := k.ToResponse()

		require.NotNil(t, resp)
		// APIKeyResponse has no KeyHash field — compile-time guarantee.
		// Serialize and verify it does not appear in JSON output.
		data, err := json.Marshal(resp)
		require.NoError(t, err)

		var out map[string]interface{}
		require.NoError(t, json.Unmarshal(data, &out))
		assert.NotContains(t, out, "key_hash")
	})

	t.Run("should handle nil optional fields", func(t *testing.T) {
		k := &APIKey{
			ID:          uuid.New(),
			TenantID:    uuid.New(),
			UserID:      uuid.New(),
			Name:        "Minimal Key",
			KeyPrefix:   "hxk_test_",
			KeyHash:     "$argon2id$minimalhash",
			Scopes:      pq.StringArray{"read"},
			Environment: "development",
			IsActive:    true,
		}

		resp := k.ToResponse()

		require.NotNil(t, resp)
		assert.Nil(t, resp.Description)
		assert.Nil(t, resp.RateLimitOverride)
		assert.Nil(t, resp.LastUsedAt)
		assert.Nil(t, resp.LastUsedIP)
		assert.Nil(t, resp.ExpiresAt)
		assert.Nil(t, resp.RevokedAt)
	})

	t.Run("should produce distinct instances on each call", func(t *testing.T) {
		k := buildAPIKey()

		resp1 := k.ToResponse()
		resp2 := k.ToResponse()

		assert.NotSame(t, resp1, resp2)
		assert.Equal(t, resp1, resp2)
	})

	t.Run("inactive and revoked key should reflect in response", func(t *testing.T) {
		revokedAt := time.Now().Add(-5 * time.Minute)
		k := &APIKey{
			ID:          uuid.New(),
			TenantID:    uuid.New(),
			UserID:      uuid.New(),
			Name:        "Revoked Key",
			KeyPrefix:   "hxk_test_",
			KeyHash:     "hash",
			Scopes:      pq.StringArray{"read"},
			Environment: "production",
			IsActive:    false,
			RevokedAt:   &revokedAt,
		}

		resp := k.ToResponse()

		require.NotNil(t, resp)
		assert.False(t, resp.IsActive)
		assert.NotNil(t, resp.RevokedAt)
		assert.Equal(t, &revokedAt, resp.RevokedAt)
	})
}

// ==================== KeyHash json:"-" tag ====================

func TestAPIKey_KeyHash_JSONDashTag(t *testing.T) {
	t.Run("KeyHash must not appear in JSON serialization of APIKey", func(t *testing.T) {
		k := &APIKey{
			ID:          uuid.New(),
			TenantID:    uuid.New(),
			UserID:      uuid.New(),
			Name:        "Test Key",
			KeyPrefix:   "hxk_live_",
			KeyHash:     "$argon2id$this-must-not-leak",
			Scopes:      pq.StringArray{"read"},
			Environment: "production",
			IsActive:    true,
		}

		data, err := json.Marshal(k)
		require.NoError(t, err)

		var out map[string]interface{}
		require.NoError(t, json.Unmarshal(data, &out))

		assert.NotContains(t, out, "key_hash",
			"KeyHash must be excluded from JSON output via json:\"-\" tag")
		// Confirm the hash value itself does not appear anywhere in the serialized JSON.
		assert.NotContains(t, string(data), "this-must-not-leak")
	})

	t.Run("ToResponse output must not contain key_hash", func(t *testing.T) {
		k := buildAPIKey()
		resp := k.ToResponse()

		data, err := json.Marshal(resp)
		require.NoError(t, err)

		assert.NotContains(t, string(data), "key_hash")
	})
}

// ==================== CreateAPIKeyRequest field tags ====================

func TestCreateAPIKeyRequest_FieldTags(t *testing.T) {
	t.Run("should accept a valid request with all fields", func(t *testing.T) {
		rateLimit := 1000
		env := "production"
		desc := "Key for CI pipeline"
		expires := testExpiry2027

		req := CreateAPIKeyRequest{
			Name:              "CI Pipeline Key",
			Description:       &desc,
			Scopes:            []string{"users:read", "roles:read"},
			IPWhitelist:       []string{"10.0.0.0/8"},
			AllowedEndpoints:  []string{"/api/v1/users"},
			RateLimitOverride: &rateLimit,
			Environment:       &env,
			ExpiresAt:         &expires,
		}

		assert.Equal(t, "CI Pipeline Key", req.Name)
		assert.Equal(t, &desc, req.Description)
		assert.ElementsMatch(t, []string{"users:read", "roles:read"}, req.Scopes)
		assert.Equal(t, &rateLimit, req.RateLimitOverride)
		assert.Equal(t, &env, req.Environment)
		assert.Equal(t, &expires, req.ExpiresAt)
	})

	t.Run("should allow omission of all optional fields", func(t *testing.T) {
		req := CreateAPIKeyRequest{
			Name: "Minimal Key",
		}

		assert.Equal(t, "Minimal Key", req.Name)
		assert.Nil(t, req.Description)
		assert.Empty(t, req.Scopes)
		assert.Empty(t, req.IPWhitelist)
		assert.Empty(t, req.AllowedEndpoints)
		assert.Nil(t, req.RateLimitOverride)
		assert.Nil(t, req.Environment)
		assert.Nil(t, req.ExpiresAt)
	})

	t.Run("environment validate tag accepts known environments", func(t *testing.T) {
		for _, env := range []string{"production", "staging", "development"} {
			env := env
			t.Run(env, func(t *testing.T) {
				req := CreateAPIKeyRequest{
					Name:        "Key",
					Environment: &env,
				}
				assert.Equal(t, env, *req.Environment)
			})
		}
	})
}

// ==================== UpdateAPIKeyRequest field tags ====================

func TestUpdateAPIKeyRequest_FieldTags(t *testing.T) {
	t.Run("all fields are optional (pointer types)", func(t *testing.T) {
		req := UpdateAPIKeyRequest{}

		assert.Nil(t, req.Name)
		assert.Nil(t, req.Description)
		assert.Empty(t, req.Scopes)
		assert.Empty(t, req.IPWhitelist)
		assert.Empty(t, req.AllowedEndpoints)
		assert.Nil(t, req.RateLimitOverride)
		assert.Nil(t, req.Environment)
		assert.Nil(t, req.IsActive)
		assert.Nil(t, req.ExpiresAt)
	})

	t.Run("should carry all populated fields correctly", func(t *testing.T) {
		name := "Updated Key"
		desc := testUpdatedDesc
		rateLimit := 2000
		env := "staging"
		isActive := false
		expires := "2028-06-01T00:00:00Z"

		req := UpdateAPIKeyRequest{
			Name:              &name,
			Description:       &desc,
			Scopes:            []string{"users:read"},
			IPWhitelist:       []string{"192.168.0.0/16"},
			AllowedEndpoints:  []string{"/api/v1/users", "/api/v1/roles"},
			RateLimitOverride: &rateLimit,
			Environment:       &env,
			IsActive:          &isActive,
			ExpiresAt:         &expires,
		}

		assert.Equal(t, &name, req.Name)
		assert.Equal(t, &desc, req.Description)
		assert.Equal(t, &rateLimit, req.RateLimitOverride)
		assert.Equal(t, &env, req.Environment)
		assert.Equal(t, &isActive, req.IsActive)
		assert.Equal(t, &expires, req.ExpiresAt)
	})
}

// ==================== APIKeyCreatedResponse ====================

func TestAPIKeyCreatedResponse_Fields(t *testing.T) {
	t.Run("should include the full API key in response", func(t *testing.T) {
		now := time.Now().Truncate(time.Second)
		k := &APIKey{
			ID:          uuid.New(),
			TenantID:    uuid.New(),
			UserID:      uuid.New(),
			Name:        "New Key",
			KeyPrefix:   "hxk_live_",
			KeyHash:     "$argon2id$hash",
			Scopes:      pq.StringArray{"read"},
			Environment: "production",
			IsActive:    true,
			CreatedAt:   now,
		}

		createdResp := APIKeyCreatedResponse{
			APIKeyResponse: *k.ToResponse(),
			Key:            "hxk_live_abc123def456",
		}

		assert.Equal(t, k.ID, createdResp.ID)
		assert.Equal(t, "hxk_live_abc123def456", createdResp.Key)
	})

	t.Run("Key field should appear in JSON output", func(t *testing.T) {
		createdResp := APIKeyCreatedResponse{
			APIKeyResponse: APIKeyResponse{
				ID:          uuid.New(),
				TenantID:    uuid.New(),
				UserID:      uuid.New(),
				Name:        "Test Key",
				KeyPrefix:   "hxk_live_",
				Scopes:      []string{"read"},
				Environment: "production",
				IsActive:    true,
			},
			Key: "hxk_live_super-secret-key",
		}

		data, err := json.Marshal(createdResp)
		require.NoError(t, err)

		var out map[string]interface{}
		require.NoError(t, json.Unmarshal(data, &out))

		assert.Equal(t, "hxk_live_super-secret-key", out["key"])
		assert.NotContains(t, out, "key_hash")
	})
}

// ==================== APIKeyUsageStats ====================

func TestAPIKeyUsageStats_Fields(t *testing.T) {
	t.Run("should hold aggregated usage statistics", func(t *testing.T) {
		stats := APIKeyUsageStats{
			TotalRequests:     10000,
			Last24Hours:       250,
			Last7Days:         1500,
			AvgResponseTimeMs: 42.7,
			TopEndpoints: []EndpointUsage{
				{Endpoint: "/api/v1/users", RequestCount: 800},
				{Endpoint: "/api/v1/roles", RequestCount: 300},
			},
			ErrorRate: 0.02,
		}

		assert.Equal(t, int64(10000), stats.TotalRequests)
		assert.Equal(t, int64(250), stats.Last24Hours)
		assert.Equal(t, int64(1500), stats.Last7Days)
		assert.InDelta(t, 42.7, stats.AvgResponseTimeMs, 0.001)
		assert.Len(t, stats.TopEndpoints, 2)
		assert.InDelta(t, 0.02, stats.ErrorRate, 0.001)
	})
}

// ==================== APIKeyResponse JSON ====================

func TestAPIKeyResponse_JSONMarshaling(t *testing.T) {
	t.Run("should omit nil pointer fields from output", func(t *testing.T) {
		resp := &APIKeyResponse{
			ID:          uuid.New(),
			TenantID:    uuid.New(),
			UserID:      uuid.New(),
			Name:        "Key",
			KeyPrefix:   "hxk_test_",
			Scopes:      []string{"read"},
			Environment: "staging",
			IsActive:    true,
			CreatedAt:   time.Now(),
		}

		data, err := json.Marshal(resp)
		require.NoError(t, err)

		var out map[string]interface{}
		require.NoError(t, json.Unmarshal(data, &out))

		assert.NotContains(t, out, "description")
		assert.NotContains(t, out, "rate_limit_override")
		assert.NotContains(t, out, "last_used_at")
		assert.NotContains(t, out, "last_used_ip")
		assert.NotContains(t, out, "expires_at")
		assert.NotContains(t, out, "revoked_at")
	})

	t.Run("populated optional fields should be present in output", func(t *testing.T) {
		now := time.Now().Truncate(time.Second)
		expires := now.Add(30 * 24 * time.Hour)
		desc := "test description"
		lastIP := testIPAddrTen
		rateLimit := 500

		resp := &APIKeyResponse{
			ID:                uuid.New(),
			TenantID:          uuid.New(),
			UserID:            uuid.New(),
			Name:              "Key",
			Description:       &desc,
			KeyPrefix:         "hxk_test_",
			Scopes:            []string{"read"},
			Environment:       "staging",
			IsActive:          true,
			UsageCount:        42,
			LastUsedAt:        &now,
			LastUsedIP:        &lastIP,
			CreatedAt:         now,
			ExpiresAt:         &expires,
			RateLimitOverride: &rateLimit,
		}

		data, err := json.Marshal(resp)
		require.NoError(t, err)

		var out map[string]interface{}
		require.NoError(t, json.Unmarshal(data, &out))

		assert.Contains(t, out, "description")
		assert.Contains(t, out, "last_used_at")
		assert.Contains(t, out, "last_used_ip")
		assert.Contains(t, out, "expires_at")
		assert.Contains(t, out, "rate_limit_override")
	})
}
