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

const testUserAgentMozilla = "Mozilla/5.0"

// buildImpersonationSession returns a fully populated ImpersonationSession for tests.
func buildImpersonationSession() *ImpersonationSession {
	id := uuid.New()
	tenantID := uuid.New()
	adminUserID := uuid.New()
	targetUserID := uuid.New()
	origSessionID := uuid.New()
	impersonationSessionID := uuid.New()
	now := time.Now().Truncate(time.Second)
	ip := testIPAddrTen
	ua := testUserAgentMozilla
	endedAt := now.Add(30 * time.Minute)

	return &ImpersonationSession{
		ID:                     id,
		TenantID:               tenantID,
		AdminUserID:            adminUserID,
		TargetUserID:           targetUserID,
		Reason:                 "Support investigation for ticket #1234",
		IPAddress:              &ip,
		UserAgent:              &ua,
		StartedAt:              now,
		EndedAt:                &endedAt,
		OriginalSessionID:      &origSessionID,
		ImpersonationSessionID: &impersonationSessionID,
		CreatedAt:              now,
	}
}

// ==================== ImpersonationSession.IsActive ====================

func TestImpersonationSession_IsActive(t *testing.T) {
	tests := []struct {
		name     string
		endedAt  *time.Time
		expected bool
	}{
		{
			name:     "should return true when EndedAt is nil (session still running)",
			endedAt:  nil,
			expected: true,
		},
		{
			name:     "should return false when EndedAt is set (session terminated)",
			endedAt:  timePtr(time.Now().Add(-5 * time.Minute)),
			expected: false,
		},
		{
			name:     "should return false when EndedAt is set to a future time",
			endedAt:  timePtr(time.Now().Add(1 * time.Hour)),
			expected: false,
		},
		{
			name:     "should return false when EndedAt is the zero time value (set but zero)",
			endedAt:  timePtr(time.Time{}),
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &ImpersonationSession{
				ID:           uuid.New(),
				AdminUserID:  uuid.New(),
				TargetUserID: uuid.New(),
				StartedAt:    time.Now(),
				EndedAt:      tt.endedAt,
			}
			assert.Equal(t, tt.expected, s.IsActive())
		})
	}
}

func TestImpersonationSession_IsActive_Boundary(t *testing.T) {
	t.Run("transitions from active to inactive when EndedAt becomes set", func(t *testing.T) {
		s := &ImpersonationSession{
			ID:           uuid.New(),
			AdminUserID:  uuid.New(),
			TargetUserID: uuid.New(),
			StartedAt:    time.Now(),
			EndedAt:      nil,
		}

		assert.True(t, s.IsActive(), "should be active before EndedAt is set")

		endedAt := time.Now()
		s.EndedAt = &endedAt

		assert.False(t, s.IsActive(), "should be inactive once EndedAt is set")
	})
}

// ==================== ImpersonationSession struct field mapping ====================

func TestImpersonationSession_StructFields(t *testing.T) {
	t.Run("should hold all field values correctly", func(t *testing.T) {
		s := buildImpersonationSession()

		assert.NotEqual(t, uuid.Nil, s.ID)
		assert.NotEqual(t, uuid.Nil, s.TenantID)
		assert.NotEqual(t, uuid.Nil, s.AdminUserID)
		assert.NotEqual(t, uuid.Nil, s.TargetUserID)
		assert.NotEmpty(t, s.Reason)
		assert.NotNil(t, s.IPAddress)
		assert.NotNil(t, s.UserAgent)
		assert.False(t, s.StartedAt.IsZero())
		assert.NotNil(t, s.EndedAt)
		assert.NotNil(t, s.OriginalSessionID)
		assert.NotNil(t, s.ImpersonationSessionID)
		assert.False(t, s.CreatedAt.IsZero())
	})

	t.Run("should allow nil optional fields", func(t *testing.T) {
		s := &ImpersonationSession{
			ID:           uuid.New(),
			TenantID:     uuid.New(),
			AdminUserID:  uuid.New(),
			TargetUserID: uuid.New(),
			Reason:       "Testing access",
			StartedAt:    time.Now(),
			CreatedAt:    time.Now(),
		}

		assert.Nil(t, s.IPAddress)
		assert.Nil(t, s.UserAgent)
		assert.Nil(t, s.EndedAt)
		assert.Nil(t, s.OriginalSessionID)
		assert.Nil(t, s.ImpersonationSessionID)
		assert.Nil(t, s.AdminUser)
		assert.Nil(t, s.TargetUser)
	})
}

// ==================== ImpersonationSession JSON marshaling ====================

func TestImpersonationSession_JSONMarshaling(t *testing.T) {
	t.Run("should serialize all non-omitempty fields to JSON", func(t *testing.T) {
		now := time.Now().Truncate(time.Second)
		s := &ImpersonationSession{
			ID:           uuid.New(),
			TenantID:     uuid.New(),
			AdminUserID:  uuid.New(),
			TargetUserID: uuid.New(),
			Reason:       "Support ticket investigation",
			StartedAt:    now,
			CreatedAt:    now,
		}

		data, err := json.Marshal(s)
		require.NoError(t, err)

		var out map[string]interface{}
		require.NoError(t, json.Unmarshal(data, &out))

		assert.Contains(t, out, "id")
		assert.Contains(t, out, "tenant_id")
		assert.Contains(t, out, "admin_user_id")
		assert.Contains(t, out, "target_user_id")
		assert.Contains(t, out, "reason")
		assert.Contains(t, out, "started_at")
		assert.Contains(t, out, "created_at")
	})

	t.Run("omitempty fields should be absent when nil", func(t *testing.T) {
		s := &ImpersonationSession{
			ID:           uuid.New(),
			TenantID:     uuid.New(),
			AdminUserID:  uuid.New(),
			TargetUserID: uuid.New(),
			Reason:       "Audit check",
			StartedAt:    time.Now(),
			CreatedAt:    time.Now(),
		}

		data, err := json.Marshal(s)
		require.NoError(t, err)

		var out map[string]interface{}
		require.NoError(t, json.Unmarshal(data, &out))

		assert.NotContains(t, out, "ip_address")
		assert.NotContains(t, out, "user_agent")
		assert.NotContains(t, out, "ended_at")
		assert.NotContains(t, out, "original_session_id")
		assert.NotContains(t, out, "impersonation_session_id")
		assert.NotContains(t, out, "admin_user")
		assert.NotContains(t, out, "target_user")
	})

	t.Run("populated optional fields should appear in JSON", func(t *testing.T) {
		now := time.Now().Truncate(time.Second)
		endedAt := now.Add(1 * time.Hour)
		origSession := uuid.New()
		impersonationSession := uuid.New()
		ip := testIPAddr192_168_1_1
		ua := "curl/7.0"

		s := &ImpersonationSession{
			ID:                     uuid.New(),
			TenantID:               uuid.New(),
			AdminUserID:            uuid.New(),
			TargetUserID:           uuid.New(),
			Reason:                 "Debugging session",
			IPAddress:              &ip,
			UserAgent:              &ua,
			StartedAt:              now,
			EndedAt:                &endedAt,
			OriginalSessionID:      &origSession,
			ImpersonationSessionID: &impersonationSession,
			CreatedAt:              now,
		}

		data, err := json.Marshal(s)
		require.NoError(t, err)

		var out map[string]interface{}
		require.NoError(t, json.Unmarshal(data, &out))

		assert.Contains(t, out, "ip_address")
		assert.Contains(t, out, "user_agent")
		assert.Contains(t, out, "ended_at")
		assert.Contains(t, out, "original_session_id")
		assert.Contains(t, out, "impersonation_session_id")
	})
}

// ==================== StartImpersonationRequest validation tags ====================

func TestStartImpersonationRequest_FieldTags(t *testing.T) {
	t.Run("should accept a reason of exactly 10 characters", func(t *testing.T) {
		req := StartImpersonationRequest{
			Reason: "1234567890",
		}
		assert.Len(t, req.Reason, 10)
	})

	t.Run("should carry a long reason without truncation", func(t *testing.T) {
		longReason := "Investigating a customer-reported issue with login flow on production."
		req := StartImpersonationRequest{Reason: longReason}
		assert.Equal(t, longReason, req.Reason)
	})

	t.Run("empty reason field is settable (validation enforcement is via gin binding)", func(t *testing.T) {
		req := StartImpersonationRequest{Reason: ""}
		assert.Empty(t, req.Reason)
	})
}

// ==================== ImpersonationResponse struct ====================

func TestImpersonationResponse_Fields(t *testing.T) {
	t.Run("should hold all fields correctly", func(t *testing.T) {
		targetUser := &User{
			ID:       uuid.New(),
			Username: "target.user",
		}

		resp := ImpersonationResponse{ //nolint:gosec // test fixture value, not a real credential
			ImpersonationSessionID: uuid.New().String(),
			AccessToken:            "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.test",
			RefreshToken:           "refresh-token-value",
			ExpiresIn:              900,
			TokenType:              "Bearer",
			TargetUser:             targetUser,
			Message:                "Impersonation session started",
		}

		assert.NotEmpty(t, resp.ImpersonationSessionID)
		assert.NotEmpty(t, resp.AccessToken)
		assert.NotEmpty(t, resp.RefreshToken)
		assert.Equal(t, 900, resp.ExpiresIn)
		assert.Equal(t, "Bearer", resp.TokenType)
		assert.Equal(t, targetUser, resp.TargetUser)
		assert.NotEmpty(t, resp.Message)
	})

	t.Run("should serialize correctly to JSON", func(t *testing.T) {
		resp := ImpersonationResponse{
			ImpersonationSessionID: "sess-123",
			AccessToken:            "access-token",
			ExpiresIn:              900,
			TokenType:              "Bearer",
			Message:                "Started",
		}

		data, err := json.Marshal(resp) //nolint:gosec // test struct with token field, not real credentials
		require.NoError(t, err)

		var out map[string]interface{}
		require.NoError(t, json.Unmarshal(data, &out))

		assert.Equal(t, "sess-123", out["impersonation_session_id"])
		assert.Equal(t, "access-token", out["access_token"])
		assert.Equal(t, "Bearer", out["token_type"])
		assert.Equal(t, float64(900), out["expires_in"])
		// RefreshToken is omitempty, so it should be absent when empty.
		assert.NotContains(t, out, "refresh_token")
	})
}

// ==================== ImpersonationStatus struct ====================

func TestImpersonationStatus_Fields(t *testing.T) {
	t.Run("not-impersonating status should have all optional fields as nil", func(t *testing.T) {
		status := ImpersonationStatus{
			IsImpersonating: false,
		}

		assert.False(t, status.IsImpersonating)
		assert.Nil(t, status.ImpersonationSessionID)
		assert.Nil(t, status.AdminUserID)
		assert.Nil(t, status.AdminUsername)
		assert.Nil(t, status.AdminEmail)
		assert.Nil(t, status.TargetUserID)
		assert.Nil(t, status.TargetUsername)
		assert.Nil(t, status.StartedAt)
		assert.Nil(t, status.Reason)
	})

	t.Run("impersonating status should hold all populated fields", func(t *testing.T) {
		now := time.Now()
		sessID := "sess-abc"
		adminID := "admin-uuid"
		adminUser := "admin"
		adminEmail := "admin@example.com"
		targetID := "target-uuid"
		targetUser := "target.user"
		reason := "customer support"

		status := ImpersonationStatus{
			IsImpersonating:        true,
			ImpersonationSessionID: &sessID,
			AdminUserID:            &adminID,
			AdminUsername:          &adminUser,
			AdminEmail:             &adminEmail,
			TargetUserID:           &targetID,
			TargetUsername:         &targetUser,
			StartedAt:              &now,
			Reason:                 &reason,
		}

		assert.True(t, status.IsImpersonating)
		assert.Equal(t, &sessID, status.ImpersonationSessionID)
		assert.Equal(t, &adminID, status.AdminUserID)
		assert.Equal(t, &adminUser, status.AdminUsername)
		assert.Equal(t, &adminEmail, status.AdminEmail)
		assert.Equal(t, &targetID, status.TargetUserID)
		assert.Equal(t, &targetUser, status.TargetUsername)
		assert.Equal(t, &now, status.StartedAt)
		assert.Equal(t, &reason, status.Reason)
	})

	t.Run("JSON omitempty fields should be absent when nil", func(t *testing.T) {
		status := ImpersonationStatus{IsImpersonating: false}

		data, err := json.Marshal(status)
		require.NoError(t, err)

		var out map[string]interface{}
		require.NoError(t, json.Unmarshal(data, &out))

		assert.Equal(t, false, out["is_impersonating"])
		assert.NotContains(t, out, "impersonation_session_id")
		assert.NotContains(t, out, "admin_user_id")
		assert.NotContains(t, out, "admin_username")
		assert.NotContains(t, out, "admin_email")
		assert.NotContains(t, out, "target_user_id")
		assert.NotContains(t, out, "target_username")
		assert.NotContains(t, out, "started_at")
		assert.NotContains(t, out, "reason")
	})
}

// ==================== ImpersonationSessionListResponse ====================

func TestImpersonationSessionListResponse_Fields(t *testing.T) {
	t.Run("should hold sessions and pagination metadata", func(t *testing.T) {
		s1 := &ImpersonationSession{ID: uuid.New(), Reason: "reason 1"}
		s2 := &ImpersonationSession{ID: uuid.New(), Reason: "reason 2"}

		resp := ImpersonationSessionListResponse{
			Sessions:   []*ImpersonationSession{s1, s2},
			Total:      42,
			Page:       2,
			PageSize:   20,
			TotalPages: 3,
		}

		assert.Len(t, resp.Sessions, 2)
		assert.Equal(t, 42, resp.Total)
		assert.Equal(t, 2, resp.Page)
		assert.Equal(t, 20, resp.PageSize)
		assert.Equal(t, 3, resp.TotalPages)
	})

	t.Run("empty sessions list should serialize as empty JSON array", func(t *testing.T) {
		resp := ImpersonationSessionListResponse{
			Sessions:   []*ImpersonationSession{},
			Total:      0,
			Page:       1,
			PageSize:   20,
			TotalPages: 0,
		}

		data, err := json.Marshal(resp)
		require.NoError(t, err)

		var out map[string]interface{}
		require.NoError(t, json.Unmarshal(data, &out))

		sessions, ok := out["sessions"].([]interface{})
		require.True(t, ok)
		assert.Empty(t, sessions)
	})
}
