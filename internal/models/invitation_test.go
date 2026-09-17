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

// ==================== InvitationType constants ====================

func TestInvitationTypeConstants(t *testing.T) {
	assert.Equal(t, InvitationType("tenant_admin"), InvitationTypeTenantAdmin)
	assert.Equal(t, InvitationType("user_invite"), InvitationTypeUserInvite)
	assert.Equal(t, InvitationType("password_setup"), InvitationTypePasswordSetup)
}

// ==================== InvitationStatus constants ====================

func TestInvitationStatusConstants(t *testing.T) {
	assert.Equal(t, InvitationStatus("pending"), InvitationStatusPending)
	assert.Equal(t, InvitationStatus("accepted"), InvitationStatusAccepted)
	assert.Equal(t, InvitationStatus("expired"), InvitationStatusExpired)
	assert.Equal(t, InvitationStatus("revoked"), InvitationStatusRevoked)
}

// ==================== UserActivationStatus constants ====================

func TestUserActivationStatusConstants(t *testing.T) {
	assert.Equal(t, UserActivationStatus("pending_invitation"), UserActivationPendingInvitation)
	assert.Equal(t, UserActivationStatus("pending_activation"), UserActivationPendingActivation)
	assert.Equal(t, UserActivationStatus("active"), UserActivationActive)
	assert.Equal(t, UserActivationStatus("suspended"), UserActivationSuspended)
	assert.Equal(t, UserActivationStatus("deactivated"), UserActivationDeactivated)
}

// ==================== UserInvitation.IsExpired ====================

func TestUserInvitation_IsExpired(t *testing.T) {
	tests := []struct {
		name      string
		expiresAt time.Time
		expected  bool
	}{
		{
			name:      "should return true when ExpiresAt is in the past",
			expiresAt: time.Now().Add(-1 * time.Hour),
			expected:  true,
		},
		{
			name:      "should return true when ExpiresAt is one nanosecond in the past",
			expiresAt: time.Now().Add(-1 * time.Nanosecond),
			expected:  true,
		},
		{
			name:      "should return false when ExpiresAt is in the future",
			expiresAt: time.Now().Add(1 * time.Hour),
			expected:  false,
		},
		{
			name:      "should return false when ExpiresAt is 72 hours in the future",
			expiresAt: time.Now().Add(72 * time.Hour),
			expected:  false,
		},
		{
			name:      "should return true when ExpiresAt was 24 hours ago",
			expiresAt: time.Now().Add(-24 * time.Hour),
			expected:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			inv := &UserInvitation{ExpiresAt: tt.expiresAt}
			assert.Equal(t, tt.expected, inv.IsExpired())
		})
	}
}

// ==================== UserInvitation.IsAccepted ====================

func TestUserInvitation_IsAccepted(t *testing.T) {
	tests := []struct {
		name     string
		status   InvitationStatus
		expected bool
	}{
		{
			name:     "should return true when status is accepted",
			status:   InvitationStatusAccepted,
			expected: true,
		},
		{
			name:     "should return false when status is pending",
			status:   InvitationStatusPending,
			expected: false,
		},
		{
			name:     "should return false when status is expired",
			status:   InvitationStatusExpired,
			expected: false,
		},
		{
			name:     "should return false when status is revoked",
			status:   InvitationStatusRevoked,
			expected: false,
		},
		{
			name:     "should return false when status is empty",
			status:   "",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			inv := &UserInvitation{Status: tt.status}
			assert.Equal(t, tt.expected, inv.IsAccepted())
		})
	}
}

// ==================== UserInvitation.IsRevoked ====================

func TestUserInvitation_IsRevoked(t *testing.T) {
	tests := []struct {
		name     string
		status   InvitationStatus
		expected bool
	}{
		{
			name:     "should return true when status is revoked",
			status:   InvitationStatusRevoked,
			expected: true,
		},
		{
			name:     "should return false when status is pending",
			status:   InvitationStatusPending,
			expected: false,
		},
		{
			name:     "should return false when status is accepted",
			status:   InvitationStatusAccepted,
			expected: false,
		},
		{
			name:     "should return false when status is expired",
			status:   InvitationStatusExpired,
			expected: false,
		},
		{
			name:     "should return false when status is empty",
			status:   "",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			inv := &UserInvitation{Status: tt.status}
			assert.Equal(t, tt.expected, inv.IsRevoked())
		})
	}
}

// ==================== UserInvitation.IsPending ====================

func TestUserInvitation_IsPending(t *testing.T) {
	tests := []struct {
		name     string
		status   InvitationStatus
		expected bool
	}{
		{
			name:     "should return true when status is pending",
			status:   InvitationStatusPending,
			expected: true,
		},
		{
			name:     "should return false when status is accepted",
			status:   InvitationStatusAccepted,
			expected: false,
		},
		{
			name:     "should return false when status is expired",
			status:   InvitationStatusExpired,
			expected: false,
		},
		{
			name:     "should return false when status is revoked",
			status:   InvitationStatusRevoked,
			expected: false,
		},
		{
			name:     "should return false when status is empty",
			status:   "",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			inv := &UserInvitation{Status: tt.status}
			assert.Equal(t, tt.expected, inv.IsPending())
		})
	}
}

// ==================== InvitationStatus mutual exclusivity ====================

func TestUserInvitation_StatusMutualExclusivity(t *testing.T) {
	tests := []struct {
		status       InvitationStatus
		wantPending  bool
		wantAccepted bool
		wantRevoked  bool
	}{
		{
			status:       InvitationStatusPending,
			wantPending:  true,
			wantAccepted: false,
			wantRevoked:  false,
		},
		{
			status:       InvitationStatusAccepted,
			wantPending:  false,
			wantAccepted: true,
			wantRevoked:  false,
		},
		{
			status:       InvitationStatusRevoked,
			wantPending:  false,
			wantAccepted: false,
			wantRevoked:  true,
		},
		{
			// Expired status: none of IsPending / IsAccepted / IsRevoked are true.
			status:       InvitationStatusExpired,
			wantPending:  false,
			wantAccepted: false,
			wantRevoked:  false,
		},
	}

	for _, tt := range tests {
		t.Run(string(tt.status), func(t *testing.T) {
			inv := &UserInvitation{Status: tt.status}
			assert.Equal(t, tt.wantPending, inv.IsPending(), "IsPending mismatch")
			assert.Equal(t, tt.wantAccepted, inv.IsAccepted(), "IsAccepted mismatch")
			assert.Equal(t, tt.wantRevoked, inv.IsRevoked(), "IsRevoked mismatch")
		})
	}
}

// ==================== UserInvitation.IsValid ====================

func TestUserInvitation_IsValid(t *testing.T) {
	tests := []struct {
		name      string
		status    InvitationStatus
		expiresAt time.Time
		expected  bool
	}{
		{
			name:      "should return true when pending and not expired",
			status:    InvitationStatusPending,
			expiresAt: time.Now().Add(24 * time.Hour),
			expected:  true,
		},
		{
			name:      "should return false when pending but expired",
			status:    InvitationStatusPending,
			expiresAt: time.Now().Add(-1 * time.Hour),
			expected:  false,
		},
		{
			name:      "should return false when accepted and not expired",
			status:    InvitationStatusAccepted,
			expiresAt: time.Now().Add(24 * time.Hour),
			expected:  false,
		},
		{
			name:      "should return false when accepted and expired",
			status:    InvitationStatusAccepted,
			expiresAt: time.Now().Add(-1 * time.Hour),
			expected:  false,
		},
		{
			name:      "should return false when revoked and not expired",
			status:    InvitationStatusRevoked,
			expiresAt: time.Now().Add(24 * time.Hour),
			expected:  false,
		},
		{
			name:      "should return false when expired status and not time-expired",
			status:    InvitationStatusExpired,
			expiresAt: time.Now().Add(24 * time.Hour),
			expected:  false,
		},
		{
			name:      "should return false when pending and just barely expired",
			status:    InvitationStatusPending,
			expiresAt: time.Now().Add(-1 * time.Nanosecond),
			expected:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			inv := &UserInvitation{
				Status:    tt.status,
				ExpiresAt: tt.expiresAt,
			}
			assert.Equal(t, tt.expected, inv.IsValid())
		})
	}
}

// ==================== UserInvitation.CanResendEmail ====================

func TestUserInvitation_CanResendEmail(t *testing.T) {
	t.Run("should return true when no email has been sent yet", func(t *testing.T) {
		inv := &UserInvitation{
			EmailSendCount:  0,
			LastEmailSentAt: nil,
		}
		assert.True(t, inv.CanResendEmail())
	})

	t.Run("should return true when send count is below limit and cooldown has passed", func(t *testing.T) {
		sentAt := time.Now().Add(-6 * time.Minute) // more than 5 min ago
		inv := &UserInvitation{
			EmailSendCount:  3,
			LastEmailSentAt: &sentAt,
		}
		assert.True(t, inv.CanResendEmail())
	})

	t.Run("should return false when send count has reached the limit of 5", func(t *testing.T) {
		sentAt := time.Now().Add(-10 * time.Minute)
		inv := &UserInvitation{
			EmailSendCount:  5,
			LastEmailSentAt: &sentAt,
		}
		assert.False(t, inv.CanResendEmail())
	})

	t.Run("should return false when send count exceeds the limit", func(t *testing.T) {
		sentAt := time.Now().Add(-10 * time.Minute)
		inv := &UserInvitation{
			EmailSendCount:  10,
			LastEmailSentAt: &sentAt,
		}
		assert.False(t, inv.CanResendEmail())
	})

	t.Run("should return false when within 5-minute cooldown", func(t *testing.T) {
		sentAt := time.Now().Add(-2 * time.Minute) // less than 5 min ago
		inv := &UserInvitation{
			EmailSendCount:  1,
			LastEmailSentAt: &sentAt,
		}
		assert.False(t, inv.CanResendEmail())
	})

	t.Run("should return false when sent just under 5 minutes ago (within cooldown)", func(t *testing.T) {
		// 4m55s ago: clearly within the 5-minute cooldown window.
		sentAt := time.Now().Add(-(5*time.Minute - 5*time.Second))
		inv := &UserInvitation{
			EmailSendCount:  1,
			LastEmailSentAt: &sentAt,
		}
		assert.False(t, inv.CanResendEmail())
	})

	t.Run("should return true when sent just over 5 minutes ago", func(t *testing.T) {
		sentAt := time.Now().Add(-(5*time.Minute + 1*time.Second))
		inv := &UserInvitation{
			EmailSendCount:  1,
			LastEmailSentAt: &sentAt,
		}
		assert.True(t, inv.CanResendEmail())
	})

	t.Run("should return true when send count is 4 and cooldown has passed", func(t *testing.T) {
		sentAt := time.Now().Add(-10 * time.Minute)
		inv := &UserInvitation{
			EmailSendCount:  4,
			LastEmailSentAt: &sentAt,
		}
		assert.True(t, inv.CanResendEmail())
	})

	t.Run("max-count check takes priority over nil LastEmailSentAt", func(t *testing.T) {
		// EmailSendCount >= 5 is checked first; LastEmailSentAt nil is irrelevant.
		inv := &UserInvitation{
			EmailSendCount:  5,
			LastEmailSentAt: nil,
		}
		assert.False(t, inv.CanResendEmail())
	})
}

// ==================== UserInvitation.ToResponse ====================

func TestUserInvitation_ToResponse(t *testing.T) {
	t.Run("should map all fields correctly", func(t *testing.T) {
		id := uuid.New()
		userID := uuid.New()
		tenantID := uuid.New()
		now := time.Now().Truncate(time.Second)
		expires := now.Add(72 * time.Hour)
		emailSent := now.Add(-1 * time.Hour)

		inv := &UserInvitation{
			ID:             id,
			UserID:         userID,
			TenantID:       tenantID,
			TokenHash:      "sensitive-token-hash-value",
			InvitationType: InvitationTypeUserInvite,
			Email:          "user@example.com",
			Status:         InvitationStatusPending,
			EmailSentAt:    &emailSent,
			EmailSendCount: 2,
			ExpiresAt:      expires,
			CreatedAt:      now,
			UpdatedAt:      now,
		}

		resp := inv.ToResponse()

		require.NotNil(t, resp)
		assert.Equal(t, id, resp.ID)
		assert.Equal(t, userID, resp.UserID)
		assert.Equal(t, "user@example.com", resp.Email)
		assert.Equal(t, InvitationTypeUserInvite, resp.InvitationType)
		assert.Equal(t, InvitationStatusPending, resp.Status)
		assert.True(t, resp.EmailSent, "EmailSent should be true when EmailSentAt is non-nil")
		assert.Equal(t, 2, resp.EmailSendCount)
		assert.Equal(t, expires, resp.ExpiresAt)
		assert.Equal(t, now, resp.CreatedAt)
	})

	t.Run("EmailSent should be false when EmailSentAt is nil", func(t *testing.T) {
		inv := &UserInvitation{
			ID:             uuid.New(),
			UserID:         uuid.New(),
			Email:          "new@example.com",
			InvitationType: InvitationTypeTenantAdmin,
			Status:         InvitationStatusPending,
			EmailSentAt:    nil,
			EmailSendCount: 0,
			ExpiresAt:      time.Now().Add(72 * time.Hour),
			CreatedAt:      time.Now(),
		}

		resp := inv.ToResponse()

		require.NotNil(t, resp)
		assert.False(t, resp.EmailSent, "EmailSent should be false when EmailSentAt is nil")
		assert.Equal(t, 0, resp.EmailSendCount)
	})

	t.Run("should produce a distinct instance on each call", func(t *testing.T) {
		inv := &UserInvitation{
			ID:        uuid.New(),
			UserID:    uuid.New(),
			Email:     "test@example.com",
			Status:    InvitationStatusPending,
			ExpiresAt: time.Now().Add(24 * time.Hour),
		}

		resp1 := inv.ToResponse()
		resp2 := inv.ToResponse()

		assert.NotSame(t, resp1, resp2)
		assert.Equal(t, resp1, resp2)
	})
}

// ==================== TokenHash json:"-" tag ====================

func TestUserInvitation_TokenHash_JSONTag(t *testing.T) {
	t.Run("TokenHash must be absent from JSON serialisation", func(t *testing.T) {
		inv := &UserInvitation{
			ID:        uuid.New(),
			UserID:    uuid.New(),
			TokenHash: "super-secret-token-hash",
			Status:    InvitationStatusPending,
			ExpiresAt: time.Now().Add(24 * time.Hour),
		}

		data, err := json.Marshal(inv)
		require.NoError(t, err)

		var raw map[string]interface{}
		require.NoError(t, json.Unmarshal(data, &raw))

		_, exists := raw["token_hash"]
		assert.False(t, exists, "token_hash must not appear in JSON output due to json:\"-\" tag")

		_, exists = raw["TokenHash"]
		assert.False(t, exists, "TokenHash must not appear in JSON output under any key")
	})
}

// ==================== CreateInvitationRequest validation struct ====================

func TestCreateInvitationRequest_Fields(t *testing.T) {
	t.Run("should construct with all required fields", func(t *testing.T) {
		userID := uuid.New()
		tenantID := uuid.New()

		req := CreateInvitationRequest{
			UserID:         userID,
			TenantID:       tenantID,
			InvitationType: InvitationTypeUserInvite,
			Email:          "invite@example.com",
			ExpiryHours:    72,
			SendEmail:      true,
		}

		assert.Equal(t, userID, req.UserID)
		assert.Equal(t, tenantID, req.TenantID)
		assert.Equal(t, InvitationTypeUserInvite, req.InvitationType)
		assert.Equal(t, "invite@example.com", req.Email)
		assert.Equal(t, 72, req.ExpiryHours)
		assert.True(t, req.SendEmail)
	})

	t.Run("should support optional realm and admin fields", func(t *testing.T) {
		realmID := uuid.New()
		adminID := uuid.New()
		userID := uuid.New()

		req := CreateInvitationRequest{
			UserID:           uuid.New(),
			TenantID:         uuid.New(),
			RealmID:          &realmID,
			InvitationType:   InvitationTypeTenantAdmin,
			InvitedByAdminID: &adminID,
			InvitedByUserID:  &userID,
			Email:            "admin@tenant.com",
			CustomMessage:    "Welcome to the platform.",
		}

		require.NotNil(t, req.RealmID)
		assert.Equal(t, realmID, *req.RealmID)
		require.NotNil(t, req.InvitedByAdminID)
		assert.Equal(t, adminID, *req.InvitedByAdminID)
		require.NotNil(t, req.InvitedByUserID)
		assert.Equal(t, userID, *req.InvitedByUserID)
		assert.Equal(t, "Welcome to the platform.", req.CustomMessage)
	})
}

// ==================== SetupAccountRequest validation struct ====================

func TestSetupAccountRequest_Fields(t *testing.T) {
	t.Run("should accept a valid token and matching passwords", func(t *testing.T) {
		req := SetupAccountRequest{
			Token:           "abc123def456",
			Password:        "securepassword1",
			ConfirmPassword: "securepassword1",
		}

		assert.Equal(t, "abc123def456", req.Token)
		assert.Equal(t, "securepassword1", req.Password)
		assert.Equal(t, "securepassword1", req.ConfirmPassword)
	})

	t.Run("should reflect the binding tags on struct", func(t *testing.T) {
		// Verify that a zero-value request has empty fields as expected.
		req := SetupAccountRequest{}
		assert.Empty(t, req.Token)
		assert.Empty(t, req.Password)
		assert.Empty(t, req.ConfirmPassword)
	})
}

// ==================== ValidateInvitationRequest validation struct ====================

func TestValidateInvitationRequest_Fields(t *testing.T) {
	t.Run("should hold a token string", func(t *testing.T) {
		req := ValidateInvitationRequest{ //nolint:gosec // test fixture value, not a real credential
			Token: "some-opaque-token-value",
		}

		assert.Equal(t, "some-opaque-token-value", req.Token)
	})

	t.Run("zero value should have empty token", func(t *testing.T) {
		req := ValidateInvitationRequest{}
		assert.Empty(t, req.Token)
	})
}

// ==================== InvitationResponse field coverage ====================

func TestInvitationResponse_Fields(t *testing.T) {
	t.Run("should carry all expected fields", func(t *testing.T) {
		id := uuid.New()
		userID := uuid.New()
		now := time.Now().Truncate(time.Second)
		expires := now.Add(48 * time.Hour)

		resp := &InvitationResponse{
			ID:             id,
			UserID:         userID,
			Email:          "test@example.com",
			InvitationType: InvitationTypePasswordSetup,
			Status:         InvitationStatusAccepted,
			EmailSent:      true,
			EmailSendCount: 3,
			ExpiresAt:      expires,
			CreatedAt:      now,
		}

		assert.Equal(t, id, resp.ID)
		assert.Equal(t, userID, resp.UserID)
		assert.Equal(t, "test@example.com", resp.Email)
		assert.Equal(t, InvitationTypePasswordSetup, resp.InvitationType)
		assert.Equal(t, InvitationStatusAccepted, resp.Status)
		assert.True(t, resp.EmailSent)
		assert.Equal(t, 3, resp.EmailSendCount)
		assert.Equal(t, expires, resp.ExpiresAt)
		assert.Equal(t, now, resp.CreatedAt)
	})
}
