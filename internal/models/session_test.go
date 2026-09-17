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

// buildSession returns a fully populated Session for use in tests.
func buildSession() *Session {
	now := time.Now().Truncate(time.Second)
	deviceInfo := "Chrome 120 on macOS"
	ip := "203.0.113.42"
	ua := "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"
	location := "Istanbul, TR"

	return &Session{
		ID:               uuid.New(),
		UserID:           uuid.New(),
		SessionTokenHash: "hashed-session-token-value",
		DeviceInfo:       &deviceInfo,
		IPAddress:        &ip,
		UserAgent:        &ua,
		Location:         &location,
		IsActive:         true,
		CreatedAt:        now,
		LastActivityAt:   now.Add(5 * time.Minute),
		ExpiresAt:        now.Add(24 * time.Hour),
		EndedAt:          nil,
		EndReason:        nil,
	}
}

// ==================== Session.ToResponse — isCurrent flag ====================

func TestSession_ToResponse_IsCurrent(t *testing.T) {
	tests := []struct {
		name             string
		currentSessionID *uuid.UUID
		expectedCurrent  bool
	}{
		{
			name: "should be current when IDs match",
			currentSessionID: func() *uuid.UUID {
				// Returned below after building the session.
				id := uuid.New()
				return &id
			}(),
			expectedCurrent: true,
		},
		{
			name:             "should not be current when currentSessionID is nil",
			currentSessionID: nil,
			expectedCurrent:  false,
		},
		{
			name: "should not be current when IDs differ",
			currentSessionID: func() *uuid.UUID {
				other := uuid.New()
				return &other
			}(),
			expectedCurrent: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := buildSession()

			// Override the currentSessionID with the session's own ID for the
			// "match" case.
			if tt.expectedCurrent {
				tt.currentSessionID = &s.ID
			}

			resp := s.ToResponse(tt.currentSessionID)
			assert.Equal(t, tt.expectedCurrent, resp.IsCurrent)
		})
	}
}

// ==================== Session.ToResponse — field mapping ====================

func TestSession_ToResponse_FieldMapping(t *testing.T) {
	t.Run("should map all fields correctly", func(t *testing.T) {
		s := buildSession()
		currentID := s.ID // treat this session as current

		resp := s.ToResponse(&currentID)

		require.NotNil(t, resp)
		assert.Equal(t, s.ID, resp.ID)
		assert.Equal(t, s.UserID, resp.UserID)
		assert.Equal(t, s.DeviceInfo, resp.DeviceInfo)
		assert.Equal(t, s.IPAddress, resp.IPAddress)
		assert.Equal(t, s.UserAgent, resp.UserAgent)
		assert.Equal(t, s.Location, resp.Location)
		assert.Equal(t, s.IsActive, resp.IsActive)
		assert.True(t, resp.IsCurrent)
		assert.Equal(t, s.CreatedAt, resp.CreatedAt)
		assert.Equal(t, s.LastActivityAt, resp.LastActivityAt)
		assert.Equal(t, s.ExpiresAt, resp.ExpiresAt)
	})

	t.Run("should handle nil optional pointer fields", func(t *testing.T) {
		s := &Session{
			ID:               uuid.New(),
			UserID:           uuid.New(),
			SessionTokenHash: "hash-value",
			DeviceInfo:       nil,
			IPAddress:        nil,
			UserAgent:        nil,
			Location:         nil,
			IsActive:         false,
			CreatedAt:        time.Now(),
			LastActivityAt:   time.Now(),
			ExpiresAt:        time.Now().Add(1 * time.Hour),
		}

		resp := s.ToResponse(nil)

		require.NotNil(t, resp)
		assert.Nil(t, resp.DeviceInfo)
		assert.Nil(t, resp.IPAddress)
		assert.Nil(t, resp.UserAgent)
		assert.Nil(t, resp.Location)
		assert.False(t, resp.IsCurrent)
	})

	t.Run("Username should be empty string in base Session.ToResponse", func(t *testing.T) {
		s := buildSession()
		resp := s.ToResponse(nil)
		assert.Empty(t, resp.Username)
	})

	t.Run("should produce a distinct instance on each call", func(t *testing.T) {
		s := buildSession()

		resp1 := s.ToResponse(nil)
		resp2 := s.ToResponse(nil)

		assert.NotSame(t, resp1, resp2)
		assert.Equal(t, resp1, resp2)
	})
}

// ==================== Session.ToResponse — IsCurrent boundary ====================

func TestSession_ToResponse_IsCurrentBoundary(t *testing.T) {
	t.Run("two different sessions only one is current", func(t *testing.T) {
		s1 := buildSession()
		s2 := buildSession()

		currentID := s1.ID

		resp1 := s1.ToResponse(&currentID)
		resp2 := s2.ToResponse(&currentID)

		assert.True(t, resp1.IsCurrent, "s1 should be current")
		assert.False(t, resp2.IsCurrent, "s2 should not be current")
	})

	t.Run("same session ID: pointer value equality not pointer identity", func(t *testing.T) {
		s := buildSession()
		// Copy the UUID value (different pointer, same value).
		idCopy := s.ID
		currentID := idCopy

		resp := s.ToResponse(&currentID)
		assert.True(t, resp.IsCurrent)
	})
}

// ==================== Session.ToLoginHistoryEntry ====================

func TestSession_ToLoginHistoryEntry(t *testing.T) {
	t.Run("should map all fields correctly", func(t *testing.T) {
		// LoginHistoryEntry was rewritten in v0.232.241 to project from
		// risk events (per-attempt) rather than sessions (post-auth only).
		// Session.ToLoginHistoryEntry is now the legacy projection used in
		// edge cases; it sets Outcome='allowed' because a persisted session
		// implies authentication succeeded. The lifecycle fields
		// (is_active, ended_at, end_reason) no longer exist on the
		// LoginHistoryEntry shape — they're on Session itself when needed.
		now := time.Now().Truncate(time.Second)
		endedAt := now.Add(2 * time.Hour)
		endReason := "user_logout"
		s := buildSession()
		s.EndedAt = &endedAt
		s.EndReason = &endReason

		entry := s.ToLoginHistoryEntry()

		require.NotNil(t, entry)
		assert.Equal(t, s.ID, entry.ID)
		assert.Equal(t, s.DeviceInfo, entry.DeviceInfo)
		assert.Equal(t, s.IPAddress, entry.IPAddress)
		assert.Equal(t, s.UserAgent, entry.UserAgent)
		assert.Equal(t, s.Location, entry.Location)
		assert.Equal(t, "allowed", entry.Outcome, "session-sourced rows always represent successful auth")
		assert.Equal(t, s.CreatedAt, entry.LoginAt, "LoginAt must equal session CreatedAt")
	})

	t.Run("should handle nil optional fields", func(t *testing.T) {
		s := &Session{
			ID:             uuid.New(),
			UserID:         uuid.New(),
			IsActive:       true,
			CreatedAt:      time.Now(),
			LastActivityAt: time.Now(),
			ExpiresAt:      time.Now().Add(24 * time.Hour),
		}

		entry := s.ToLoginHistoryEntry()

		require.NotNil(t, entry)
		assert.Nil(t, entry.DeviceInfo)
		assert.Nil(t, entry.IPAddress)
		assert.Nil(t, entry.UserAgent)
		assert.Nil(t, entry.Location)
		assert.Equal(t, "allowed", entry.Outcome)
	})

	t.Run("LoginAt must equal CreatedAt not LastActivityAt", func(t *testing.T) {
		created := time.Date(2025, 1, 1, 9, 0, 0, 0, time.UTC)
		lastActivity := time.Date(2025, 1, 1, 17, 30, 0, 0, time.UTC)

		s := &Session{
			ID:             uuid.New(),
			UserID:         uuid.New(),
			IsActive:       false,
			CreatedAt:      created,
			LastActivityAt: lastActivity,
			ExpiresAt:      lastActivity.Add(24 * time.Hour),
		}

		entry := s.ToLoginHistoryEntry()

		require.NotNil(t, entry)
		assert.Equal(t, created, entry.LoginAt)
	})

	t.Run("should produce a distinct instance on each call", func(t *testing.T) {
		s := buildSession()

		e1 := s.ToLoginHistoryEntry()
		e2 := s.ToLoginHistoryEntry()

		assert.NotSame(t, e1, e2)
		assert.Equal(t, e1, e2)
	})
}

// ==================== SessionWithUser.ToResponse ====================

func TestSessionWithUser_ToResponse(t *testing.T) {
	t.Run("should include username in response", func(t *testing.T) {
		s := buildSession()
		sw := &SessionWithUser{
			Session:  *s,
			Username: "johndoe",
		}
		currentID := s.ID

		resp := sw.ToResponse(&currentID)

		require.NotNil(t, resp)
		assert.Equal(t, "johndoe", resp.Username)
		assert.Equal(t, s.ID, resp.ID)
		assert.Equal(t, s.UserID, resp.UserID)
		assert.True(t, resp.IsCurrent)
	})

	t.Run("should carry IsCurrent based on matching session ID", func(t *testing.T) {
		s := buildSession()
		sw := &SessionWithUser{
			Session:  *s,
			Username: "janedoe",
		}
		other := uuid.New()

		resp := sw.ToResponse(&other)

		require.NotNil(t, resp)
		assert.Equal(t, "janedoe", resp.Username)
		assert.False(t, resp.IsCurrent)
	})

	t.Run("should carry all base Session fields through", func(t *testing.T) {
		s := buildSession()
		sw := &SessionWithUser{
			Session:  *s,
			Username: "testuser",
		}

		resp := sw.ToResponse(nil)

		require.NotNil(t, resp)
		assert.Equal(t, s.DeviceInfo, resp.DeviceInfo)
		assert.Equal(t, s.IPAddress, resp.IPAddress)
		assert.Equal(t, s.UserAgent, resp.UserAgent)
		assert.Equal(t, s.Location, resp.Location)
		assert.Equal(t, s.IsActive, resp.IsActive)
		assert.Equal(t, s.CreatedAt, resp.CreatedAt)
		assert.Equal(t, s.LastActivityAt, resp.LastActivityAt)
		assert.Equal(t, s.ExpiresAt, resp.ExpiresAt)
	})

	t.Run("should produce a distinct instance on each call", func(t *testing.T) {
		s := buildSession()
		sw := &SessionWithUser{Session: *s, Username: "user"}

		resp1 := sw.ToResponse(nil)
		resp2 := sw.ToResponse(nil)

		assert.NotSame(t, resp1, resp2)
		assert.Equal(t, resp1, resp2)
	})
}

// ==================== SessionResponse fields ====================

func TestSessionResponse_Fields(t *testing.T) {
	t.Run("should carry all expected fields", func(t *testing.T) {
		id := uuid.New()
		userID := uuid.New()
		now := time.Now().Truncate(time.Second)
		deviceInfo := "Firefox on Windows"
		ip := "10.0.0.1"
		ua := "Mozilla/5.0"
		location := "Berlin, DE"

		resp := &SessionResponse{
			ID:             id,
			UserID:         userID,
			Username:       "testuser",
			DeviceInfo:     &deviceInfo,
			IPAddress:      &ip,
			UserAgent:      &ua,
			Location:       &location,
			IsActive:       true,
			IsCurrent:      true,
			CreatedAt:      now,
			LastActivityAt: now.Add(5 * time.Minute),
			ExpiresAt:      now.Add(24 * time.Hour),
		}

		assert.Equal(t, id, resp.ID)
		assert.Equal(t, userID, resp.UserID)
		assert.Equal(t, "testuser", resp.Username)
		assert.Equal(t, &deviceInfo, resp.DeviceInfo)
		assert.Equal(t, &ip, resp.IPAddress)
		assert.Equal(t, &ua, resp.UserAgent)
		assert.Equal(t, &location, resp.Location)
		assert.True(t, resp.IsActive)
		assert.True(t, resp.IsCurrent)
		assert.Equal(t, now, resp.CreatedAt)
		assert.Equal(t, now.Add(5*time.Minute), resp.LastActivityAt)
		assert.Equal(t, now.Add(24*time.Hour), resp.ExpiresAt)
	})
}

// ==================== SessionTokenHash json:"-" tag ====================

func TestSession_SessionTokenHash_JSONTag(t *testing.T) {
	t.Run("SessionTokenHash must be absent from JSON serialisation", func(t *testing.T) {
		s := buildSession()
		s.SessionTokenHash = "ultra-secret-token-hash"

		data, err := json.Marshal(s)
		require.NoError(t, err)

		var raw map[string]interface{}
		require.NoError(t, json.Unmarshal(data, &raw))

		_, exists := raw["session_token_hash"]
		assert.False(t, exists, "session_token_hash must not appear in JSON due to json:\"-\" tag")

		_, exists = raw["SessionTokenHash"]
		assert.False(t, exists, "SessionTokenHash must not appear under any key")
	})
}

// ==================== LoginHistoryEntry fields ====================

func TestLoginHistoryEntry_Fields(t *testing.T) {
	t.Run("should carry all expected fields", func(t *testing.T) {
		// LoginHistoryEntry was rewritten in v0.232.241 to project from
		// iam_login_risk_events (per-attempt) rather than iam_sessions
		// (post-auth only). New shape: outcome / mfa_trigger /
		// block_reason / risk_level + ip / location / user_agent /
		// device_info / login_at. Legacy lifecycle fields (is_active,
		// ended_at, end_reason, last_activity_at) are gone — those live
		// on the underlying Session for callers that need them.
		id := uuid.New()
		now := time.Now().Truncate(time.Second)
		deviceInfo := "Safari on iPhone"
		ip := "172.16.0.5"
		ua := "Safari/15.0"
		location := "FR"
		mfaTrigger := "risk_default_medium"

		entry := &LoginHistoryEntry{
			ID:         id,
			DeviceInfo: &deviceInfo,
			IPAddress:  &ip,
			UserAgent:  &ua,
			Location:   &location,
			Outcome:    "mfa_challenged",
			MFATrigger: &mfaTrigger,
			RiskLevel:  "medium",
			LoginAt:    now,
		}

		assert.Equal(t, id, entry.ID)
		assert.Equal(t, &deviceInfo, entry.DeviceInfo)
		assert.Equal(t, &ip, entry.IPAddress)
		assert.Equal(t, &ua, entry.UserAgent)
		assert.Equal(t, &location, entry.Location)
		assert.Equal(t, "mfa_challenged", entry.Outcome)
		assert.Equal(t, &mfaTrigger, entry.MFATrigger)
		assert.Equal(t, "medium", entry.RiskLevel)
		assert.Equal(t, now, entry.LoginAt)
	})
}
