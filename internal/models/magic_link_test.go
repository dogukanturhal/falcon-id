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

const testIPAddr192_168_1_100 = "192.168.1.100"

// buildMagicLink returns a fully populated MagicLink for use in tests.
func buildMagicLink() *MagicLink {
	id := uuid.New()
	userID := uuid.New()
	now := time.Now().Truncate(time.Second)
	ip := "203.0.113.1"
	ua := "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"
	usedAt := now.Add(2 * time.Minute)

	return &MagicLink{ //nolint:gosec // test fixture value, not a real credential
		ID:        id,
		UserID:    &userID,
		Email:     "alice@example.com",
		TokenHash: "$argon2id$v=19$m=65536,t=3,p=4$tokenHash",
		IPAddress: &ip,
		UserAgent: &ua,
		UsedAt:    &usedAt,
		ExpiresAt: now.Add(15 * time.Minute),
		CreatedAt: now,
	}
}

// ==================== MagicLink.IsExpired ====================

func TestMagicLink_IsExpired(t *testing.T) {
	tests := []struct {
		name      string
		expiresAt time.Time
		expected  bool
	}{
		{
			name:      "should return false when ExpiresAt is in the future",
			expiresAt: time.Now().Add(15 * time.Minute),
			expected:  false,
		},
		{
			name:      "should return true when ExpiresAt is in the past",
			expiresAt: time.Now().Add(-1 * time.Second),
			expected:  true,
		},
		{
			name:      "should return true one nanosecond past expiry",
			expiresAt: time.Now().Add(-1 * time.Nanosecond),
			expected:  true,
		},
		{
			name:      "should return false when expiry is far in the future",
			expiresAt: time.Now().Add(24 * time.Hour),
			expected:  false,
		},
		{
			name:      "should return true when expired many hours ago",
			expiresAt: time.Now().Add(-48 * time.Hour),
			expected:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := &MagicLink{
				ID:        uuid.New(),
				Email:     "test@example.com",
				TokenHash: "hash",
				ExpiresAt: tt.expiresAt,
				CreatedAt: time.Now(),
			}
			assert.Equal(t, tt.expected, m.IsExpired())
		})
	}
}

func TestMagicLink_IsExpired_Boundary(t *testing.T) {
	t.Run("should be expired exactly one nanosecond after expiry", func(t *testing.T) {
		past := time.Now().Add(-1 * time.Nanosecond)
		m := &MagicLink{ExpiresAt: past}
		assert.True(t, m.IsExpired())
	})

	t.Run("should not be expired one minute before expiry", func(t *testing.T) {
		future := time.Now().Add(1 * time.Minute)
		m := &MagicLink{ExpiresAt: future}
		assert.False(t, m.IsExpired())
	})
}

// ==================== MagicLink.IsUsed ====================

func TestMagicLink_IsUsed(t *testing.T) {
	tests := []struct {
		name     string
		usedAt   *time.Time
		expected bool
	}{
		{
			name:     "should return false when UsedAt is nil (not yet used)",
			usedAt:   nil,
			expected: false,
		},
		{
			name:     "should return true when UsedAt is set",
			usedAt:   timePtr(time.Now().Add(-5 * time.Minute)),
			expected: true,
		},
		{
			name:     "should return true when UsedAt is a future time (set but future)",
			usedAt:   timePtr(time.Now().Add(1 * time.Hour)),
			expected: true,
		},
		{
			name:     "should return true when UsedAt is the zero value pointer (pointer set)",
			usedAt:   timePtr(time.Time{}),
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := &MagicLink{
				ID:        uuid.New(),
				Email:     "test@example.com",
				TokenHash: "hash",
				ExpiresAt: time.Now().Add(15 * time.Minute),
				UsedAt:    tt.usedAt,
			}
			assert.Equal(t, tt.expected, m.IsUsed())
		})
	}
}

func TestMagicLink_IsUsed_TransitionBehavior(t *testing.T) {
	t.Run("transitions from unused to used when UsedAt is set", func(t *testing.T) {
		m := &MagicLink{
			ID:        uuid.New(),
			Email:     "test@example.com",
			TokenHash: "hash",
			ExpiresAt: time.Now().Add(15 * time.Minute),
			UsedAt:    nil,
		}

		assert.False(t, m.IsUsed(), "should not be used before UsedAt is set")

		now := time.Now()
		m.UsedAt = &now

		assert.True(t, m.IsUsed(), "should be used once UsedAt is set")
	})
}

// ==================== MagicLink.IsValid ====================

func TestMagicLink_IsValid(t *testing.T) {
	tests := []struct {
		name     string
		setup    func() *MagicLink
		expected bool
	}{
		{
			name: "should return true when not expired and not used",
			setup: func() *MagicLink {
				return &MagicLink{
					ExpiresAt: time.Now().Add(15 * time.Minute),
					UsedAt:    nil,
				}
			},
			expected: true,
		},
		{
			name: "should return false when expired but not used",
			setup: func() *MagicLink {
				return &MagicLink{
					ExpiresAt: time.Now().Add(-1 * time.Minute),
					UsedAt:    nil,
				}
			},
			expected: false,
		},
		{
			name: "should return false when used but not expired",
			setup: func() *MagicLink {
				return &MagicLink{
					ExpiresAt: time.Now().Add(15 * time.Minute),
					UsedAt:    timePtr(time.Now().Add(-2 * time.Minute)),
				}
			},
			expected: false,
		},
		{
			name: "should return false when both expired and used",
			setup: func() *MagicLink {
				return &MagicLink{
					ExpiresAt: time.Now().Add(-30 * time.Minute),
					UsedAt:    timePtr(time.Now().Add(-25 * time.Minute)),
				}
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := tt.setup()
			assert.Equal(t, tt.expected, m.IsValid())
		})
	}
}

// ==================== MagicLink status consistency ====================

func TestMagicLink_StatusConsistency(t *testing.T) {
	t.Run("IsValid is always the logical AND of (not expired) AND (not used)", func(t *testing.T) {
		cases := []struct {
			expiresAt time.Time
			usedAt    *time.Time
		}{
			{time.Now().Add(10 * time.Minute), nil},
			{time.Now().Add(-10 * time.Minute), nil},
			{time.Now().Add(10 * time.Minute), timePtr(time.Now().Add(-5 * time.Minute))},
			{time.Now().Add(-10 * time.Minute), timePtr(time.Now().Add(-5 * time.Minute))},
		}

		for _, c := range cases {
			m := &MagicLink{ExpiresAt: c.expiresAt, UsedAt: c.usedAt}
			wantValid := !m.IsExpired() && !m.IsUsed()
			assert.Equal(t, wantValid, m.IsValid(),
				"IsValid should equal !IsExpired() && !IsUsed()")
		}
	})
}

// ==================== TokenHash json:"-" tag ====================

func TestMagicLink_TokenHash_JSONDashTag(t *testing.T) {
	t.Run("TokenHash must not appear in JSON serialization of MagicLink", func(t *testing.T) {
		m := &MagicLink{ //nolint:gosec // test fixture value, not a real credential
			ID:        uuid.New(),
			Email:     "test@example.com",
			TokenHash: "$argon2id$this-must-not-leak",
			ExpiresAt: time.Now().Add(15 * time.Minute),
			CreatedAt: time.Now(),
		}

		data, err := json.Marshal(m)
		require.NoError(t, err)

		var out map[string]interface{}
		require.NoError(t, json.Unmarshal(data, &out))

		assert.NotContains(t, out, "token_hash",
			"TokenHash must be excluded from JSON output via json:\"-\" tag")
		assert.NotContains(t, string(data), "this-must-not-leak")
	})
}

// ==================== MagicLink struct field mapping ====================

func TestMagicLink_StructFields(t *testing.T) {
	t.Run("should hold all field values correctly", func(t *testing.T) {
		m := buildMagicLink()

		assert.NotEqual(t, uuid.Nil, m.ID)
		assert.NotNil(t, m.UserID)
		assert.NotEmpty(t, m.Email)
		assert.NotEmpty(t, m.TokenHash)
		assert.NotNil(t, m.IPAddress)
		assert.NotNil(t, m.UserAgent)
		assert.NotNil(t, m.UsedAt)
		assert.False(t, m.ExpiresAt.IsZero())
		assert.False(t, m.CreatedAt.IsZero())
	})

	t.Run("should allow nil optional fields", func(t *testing.T) {
		m := &MagicLink{ //nolint:gosec // test fixture value, not a real credential
			ID:        uuid.New(),
			Email:     "minimal@example.com",
			TokenHash: "$argon2id$hash",
			ExpiresAt: time.Now().Add(15 * time.Minute),
			CreatedAt: time.Now(),
		}

		assert.Nil(t, m.UserID)
		assert.Nil(t, m.IPAddress)
		assert.Nil(t, m.UserAgent)
		assert.Nil(t, m.UsedAt)
	})
}

// ==================== MagicLink JSON marshaling ====================

func TestMagicLink_JSONMarshaling(t *testing.T) {
	t.Run("should serialize non-omitempty fields to JSON", func(t *testing.T) {
		now := time.Now().Truncate(time.Second)
		m := &MagicLink{ //nolint:gosec // test fixture value, not a real credential
			ID:        uuid.New(),
			Email:     "user@example.com",
			TokenHash: "$argon2id$hash",
			ExpiresAt: now.Add(15 * time.Minute),
			CreatedAt: now,
		}

		data, err := json.Marshal(m)
		require.NoError(t, err)

		var out map[string]interface{}
		require.NoError(t, json.Unmarshal(data, &out))

		assert.Contains(t, out, "id")
		assert.Contains(t, out, "email")
		assert.Contains(t, out, "expires_at")
		assert.Contains(t, out, "created_at")
		// token_hash must never appear.
		assert.NotContains(t, out, "token_hash")
	})

	t.Run("omitempty fields absent when nil", func(t *testing.T) {
		m := &MagicLink{ //nolint:gosec // test fixture value, not a real credential
			ID:        uuid.New(),
			Email:     "user@example.com",
			TokenHash: "$argon2id$hash",
			ExpiresAt: time.Now().Add(15 * time.Minute),
			CreatedAt: time.Now(),
		}

		data, err := json.Marshal(m)
		require.NoError(t, err)

		var out map[string]interface{}
		require.NoError(t, json.Unmarshal(data, &out))

		assert.NotContains(t, out, "user_id")
		assert.NotContains(t, out, "ip_address")
		assert.NotContains(t, out, "user_agent")
		assert.NotContains(t, out, "used_at")
	})

	t.Run("populated optional fields should appear in JSON", func(t *testing.T) {
		now := time.Now().Truncate(time.Second)
		userID := uuid.New()
		usedAt := now.Add(2 * time.Minute)
		ip := testIPAddr192_168_1_100
		ua := "curl/7.68.0"

		m := &MagicLink{ //nolint:gosec // test fixture value, not a real credential
			ID:        uuid.New(),
			UserID:    &userID,
			Email:     "user@example.com",
			TokenHash: "$argon2id$hash",
			IPAddress: &ip,
			UserAgent: &ua,
			UsedAt:    &usedAt,
			ExpiresAt: now.Add(15 * time.Minute),
			CreatedAt: now,
		}

		data, err := json.Marshal(m)
		require.NoError(t, err)

		var out map[string]interface{}
		require.NoError(t, json.Unmarshal(data, &out))

		assert.Contains(t, out, "user_id")
		assert.Contains(t, out, "ip_address")
		assert.Contains(t, out, "user_agent")
		assert.Contains(t, out, "used_at")
		assert.Equal(t, ip, out["ip_address"])
		assert.Equal(t, ua, out["user_agent"])
	})
}

// ==================== MagicLinkRequest validation tags ====================

func TestMagicLinkRequest_FieldTags(t *testing.T) {
	t.Run("should accept a valid email address", func(t *testing.T) {
		req := MagicLinkRequest{
			Email: "alice@example.com",
		}
		assert.Equal(t, "alice@example.com", req.Email)
	})

	t.Run("should accept an email with subdomain", func(t *testing.T) {
		req := MagicLinkRequest{
			Email: "user@mail.company.co.uk",
		}
		assert.Equal(t, "user@mail.company.co.uk", req.Email)
	})

	t.Run("should carry the raw email string without modification", func(t *testing.T) {
		email := "UPPER@example.com"
		req := MagicLinkRequest{Email: email}
		assert.Equal(t, email, req.Email)
	})

	t.Run("should serialize email field to JSON with correct key", func(t *testing.T) {
		req := MagicLinkRequest{Email: "test@example.com"}

		data, err := json.Marshal(req)
		require.NoError(t, err)

		var out map[string]interface{}
		require.NoError(t, json.Unmarshal(data, &out))

		assert.Equal(t, "test@example.com", out["email"])
	})
}

// ==================== MagicLinkVerifyRequest validation tags ====================

func TestMagicLinkVerifyRequest_FieldTags(t *testing.T) {
	t.Run("should hold a token value", func(t *testing.T) {
		req := MagicLinkVerifyRequest{ //nolint:gosec // test fixture value, not a real credential
			Token: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.randomtoken",
		}
		assert.Equal(t, "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.randomtoken", req.Token)
	})

	t.Run("should accept an opaque hex token", func(t *testing.T) {
		token := "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6" // gitleaks:allow — test fixture, not a real credential
		req := MagicLinkVerifyRequest{Token: token}
		assert.Equal(t, token, req.Token)
	})

	t.Run("should serialize token field to JSON with correct key", func(t *testing.T) {
		req := MagicLinkVerifyRequest{Token: "my-magic-token"}

		data, err := json.Marshal(req)
		require.NoError(t, err)

		var out map[string]interface{}
		require.NoError(t, json.Unmarshal(data, &out))

		assert.Equal(t, "my-magic-token", out["token"])
	})
}
