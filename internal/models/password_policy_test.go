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

// intPtr is a local helper that returns a pointer to the given int.
// (Avoids collision with package-level intPtr defined elsewhere if any.)
func intPtrPP(i int) *int { return &i }

// boolPtr is a local helper that returns a pointer to the given bool.
func boolPtrPP(b bool) *bool { return &b }

// ==================== DefaultPasswordPolicy ====================

func TestDefaultPasswordPolicy(t *testing.T) {
	t.Run("should return a sensible default policy", func(t *testing.T) {
		tenantID := uuid.New()
		policy := DefaultPasswordPolicy(tenantID)

		require.NotNil(t, policy)
		assert.NotEqual(t, uuid.Nil, policy.ID)
		assert.Equal(t, tenantID, policy.TenantID)

		// Complexity defaults
		assert.Equal(t, 8, policy.MinLength)
		assert.Nil(t, policy.MaxLength)
		assert.True(t, policy.RequireUppercase)
		assert.True(t, policy.RequireLowercase)
		assert.True(t, policy.RequireNumbers)
		assert.False(t, policy.RequireSpecial)
		assert.True(t, policy.DisallowUsername)
		assert.True(t, policy.DisallowCommonPasswords)

		// Expiration defaults
		assert.Equal(t, 0, policy.MaxAgeDays)
		assert.Equal(t, 14, policy.WarningDaysBeforeExpiry)

		// History defaults
		assert.Equal(t, 5, policy.HistoryCount)

		// Lockout defaults
		assert.Equal(t, 5, policy.LockoutThreshold)
		assert.Equal(t, 30, policy.LockoutDurationMinutes)
		assert.Equal(t, 1.0, policy.LockoutIncrementFactor)

		// Session defaults
		assert.True(t, policy.RequirePasswordChangeOnFirstLogin)
	})

	t.Run("should generate a unique ID for each call", func(t *testing.T) {
		tenantID := uuid.New()

		p1 := DefaultPasswordPolicy(tenantID)
		p2 := DefaultPasswordPolicy(tenantID)

		assert.NotEqual(t, p1.ID, p2.ID,
			"each DefaultPasswordPolicy call should produce a new ID")
		assert.Equal(t, p1.TenantID, p2.TenantID)
	})

	t.Run("should bind the policy to the provided tenant", func(t *testing.T) {
		tenantA := uuid.New()
		tenantB := uuid.New()

		pA := DefaultPasswordPolicy(tenantA)
		pB := DefaultPasswordPolicy(tenantB)

		assert.Equal(t, tenantA, pA.TenantID)
		assert.Equal(t, tenantB, pB.TenantID)
		assert.NotEqual(t, pA.TenantID, pB.TenantID)
	})
}

// ==================== PasswordPolicy.ToResponse ====================

func TestPasswordPolicy_ToResponse(t *testing.T) {
	t.Run("should map all fields correctly", func(t *testing.T) {
		id := uuid.New()
		tenantID := uuid.New()
		createdBy := uuid.New()
		updatedBy := uuid.New()
		now := time.Now().Truncate(time.Second)
		maxLen := 128

		policy := &PasswordPolicy{
			ID:                                id,
			TenantID:                          tenantID,
			MinLength:                         10,
			MaxLength:                         &maxLen,
			RequireUppercase:                  true,
			RequireLowercase:                  true,
			RequireNumbers:                    true,
			RequireSpecial:                    true,
			DisallowUsername:                  true,
			DisallowCommonPasswords:           true,
			MaxAgeDays:                        90,
			WarningDaysBeforeExpiry:           14,
			HistoryCount:                      10,
			LockoutThreshold:                  5,
			LockoutDurationMinutes:            30,
			LockoutIncrementFactor:            1.5,
			RequirePasswordChangeOnFirstLogin: true,
			CreatedAt:                         now,
			UpdatedAt:                         now,
			CreatedBy:                         &createdBy,
			UpdatedBy:                         &updatedBy,
		}

		resp := policy.ToResponse()

		require.NotNil(t, resp)
		assert.Equal(t, id, resp.ID)
		assert.Equal(t, tenantID, resp.TenantID)
		assert.Equal(t, 10, resp.MinLength)
		assert.Equal(t, &maxLen, resp.MaxLength)
		assert.True(t, resp.RequireUppercase)
		assert.True(t, resp.RequireLowercase)
		assert.True(t, resp.RequireNumbers)
		assert.True(t, resp.RequireSpecial)
		assert.True(t, resp.DisallowUsername)
		assert.True(t, resp.DisallowCommonPasswords)
		assert.Equal(t, 90, resp.MaxAgeDays)
		assert.Equal(t, 14, resp.WarningDaysBeforeExpiry)
		assert.Equal(t, 10, resp.HistoryCount)
		assert.Equal(t, 5, resp.LockoutThreshold)
		assert.Equal(t, 30, resp.LockoutDurationMinutes)
		assert.Equal(t, 1.5, resp.LockoutIncrementFactor)
		assert.True(t, resp.RequirePasswordChangeOnFirstLogin)
		assert.Equal(t, now, resp.UpdatedAt)
	})

	t.Run("should handle nil MaxLength", func(t *testing.T) {
		policy := DefaultPasswordPolicy(uuid.New())

		resp := policy.ToResponse()

		require.NotNil(t, resp)
		assert.Nil(t, resp.MaxLength)
	})

	t.Run("should not expose CreatedBy and UpdatedBy in response", func(t *testing.T) {
		createdBy := uuid.New()
		policy := DefaultPasswordPolicy(uuid.New())
		policy.CreatedBy = &createdBy

		resp := policy.ToResponse()

		// PasswordPolicyResponse does not expose CreatedBy/UpdatedBy.
		// Confirm the conversion succeeds and ID is present.
		require.NotNil(t, resp)
		assert.NotEqual(t, uuid.Nil, resp.ID)
	})

	t.Run("should produce a distinct instance on each call", func(t *testing.T) {
		policy := DefaultPasswordPolicy(uuid.New())

		resp1 := policy.ToResponse()
		resp2 := policy.ToResponse()

		assert.NotSame(t, resp1, resp2)
		assert.Equal(t, resp1, resp2)
	})
}

// ==================== PasswordPolicy field validation rules ====================

func TestPasswordPolicy_ComplexityFields(t *testing.T) {
	tests := []struct {
		name                    string
		minLength               int
		maxLength               *int
		requireUppercase        bool
		requireLowercase        bool
		requireNumbers          bool
		requireSpecial          bool
		disallowUsername        bool
		disallowCommonPasswords bool
	}{
		{
			name:                    "strict policy with all requirements",
			minLength:               12,
			maxLength:               intPtrPP(64),
			requireUppercase:        true,
			requireLowercase:        true,
			requireNumbers:          true,
			requireSpecial:          true,
			disallowUsername:        true,
			disallowCommonPasswords: true,
		},
		{
			name:                    "minimal policy with only min length",
			minLength:               8,
			maxLength:               nil,
			requireUppercase:        false,
			requireLowercase:        false,
			requireNumbers:          false,
			requireSpecial:          false,
			disallowUsername:        false,
			disallowCommonPasswords: false,
		},
		{
			name:                    "policy with high max length",
			minLength:               6,
			maxLength:               intPtrPP(1024),
			requireUppercase:        true,
			requireLowercase:        true,
			requireNumbers:          true,
			requireSpecial:          false,
			disallowUsername:        true,
			disallowCommonPasswords: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policy := &PasswordPolicy{
				ID:                      uuid.New(),
				TenantID:                uuid.New(),
				MinLength:               tt.minLength,
				MaxLength:               tt.maxLength,
				RequireUppercase:        tt.requireUppercase,
				RequireLowercase:        tt.requireLowercase,
				RequireNumbers:          tt.requireNumbers,
				RequireSpecial:          tt.requireSpecial,
				DisallowUsername:        tt.disallowUsername,
				DisallowCommonPasswords: tt.disallowCommonPasswords,
			}

			assert.Equal(t, tt.minLength, policy.MinLength)
			assert.Equal(t, tt.maxLength, policy.MaxLength)
			assert.Equal(t, tt.requireUppercase, policy.RequireUppercase)
			assert.Equal(t, tt.requireLowercase, policy.RequireLowercase)
			assert.Equal(t, tt.requireNumbers, policy.RequireNumbers)
			assert.Equal(t, tt.requireSpecial, policy.RequireSpecial)
			assert.Equal(t, tt.disallowUsername, policy.DisallowUsername)
			assert.Equal(t, tt.disallowCommonPasswords, policy.DisallowCommonPasswords)
		})
	}
}

func TestPasswordPolicy_LockoutFields(t *testing.T) {
	tests := []struct {
		name                   string
		lockoutThreshold       int
		lockoutDurationMinutes int
		lockoutIncrementFactor float64
	}{
		{
			name:                   "standard lockout settings",
			lockoutThreshold:       5,
			lockoutDurationMinutes: 30,
			lockoutIncrementFactor: 1.0,
		},
		{
			name:                   "aggressive lockout with increment",
			lockoutThreshold:       3,
			lockoutDurationMinutes: 60,
			lockoutIncrementFactor: 2.0,
		},
		{
			name:                   "disabled lockout",
			lockoutThreshold:       0,
			lockoutDurationMinutes: 0,
			lockoutIncrementFactor: 0.0,
		},
		{
			name:                   "high threshold lenient lockout",
			lockoutThreshold:       20,
			lockoutDurationMinutes: 5,
			lockoutIncrementFactor: 1.5,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policy := &PasswordPolicy{
				ID:                     uuid.New(),
				TenantID:               uuid.New(),
				LockoutThreshold:       tt.lockoutThreshold,
				LockoutDurationMinutes: tt.lockoutDurationMinutes,
				LockoutIncrementFactor: tt.lockoutIncrementFactor,
			}

			assert.Equal(t, tt.lockoutThreshold, policy.LockoutThreshold)
			assert.Equal(t, tt.lockoutDurationMinutes, policy.LockoutDurationMinutes)
			assert.Equal(t, tt.lockoutIncrementFactor, policy.LockoutIncrementFactor)
		})
	}
}

func TestPasswordPolicy_ExpirationFields(t *testing.T) {
	tests := []struct {
		name                    string
		maxAgeDays              int
		warningDaysBeforeExpiry int
	}{
		{
			name:                    "standard expiry policy",
			maxAgeDays:              90,
			warningDaysBeforeExpiry: 14,
		},
		{
			name:                    "no expiry policy",
			maxAgeDays:              0,
			warningDaysBeforeExpiry: 0,
		},
		{
			name:                    "annual expiry with early warning",
			maxAgeDays:              365,
			warningDaysBeforeExpiry: 30,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policy := &PasswordPolicy{
				ID:                      uuid.New(),
				TenantID:                uuid.New(),
				MaxAgeDays:              tt.maxAgeDays,
				WarningDaysBeforeExpiry: tt.warningDaysBeforeExpiry,
			}

			assert.Equal(t, tt.maxAgeDays, policy.MaxAgeDays)
			assert.Equal(t, tt.warningDaysBeforeExpiry, policy.WarningDaysBeforeExpiry)
		})
	}
}

// ==================== PasswordPolicyRequest ====================

func TestPasswordPolicyRequest_Fields(t *testing.T) {
	t.Run("should allow all fields to be nil (no-op update)", func(t *testing.T) {
		req := PasswordPolicyRequest{}

		assert.Nil(t, req.MinLength)
		assert.Nil(t, req.MaxLength)
		assert.Nil(t, req.RequireUppercase)
		assert.Nil(t, req.RequireLowercase)
		assert.Nil(t, req.RequireNumbers)
		assert.Nil(t, req.RequireSpecial)
		assert.Nil(t, req.DisallowUsername)
		assert.Nil(t, req.DisallowCommonPasswords)
		assert.Nil(t, req.MaxAgeDays)
		assert.Nil(t, req.WarningDaysBeforeExpiry)
		assert.Nil(t, req.HistoryCount)
		assert.Nil(t, req.LockoutThreshold)
		assert.Nil(t, req.LockoutDurationMinutes)
		assert.Nil(t, req.LockoutIncrementFactor)
		assert.Nil(t, req.RequirePasswordChangeOnFirstLogin)
	})

	t.Run("should accept a full set of fields", func(t *testing.T) {
		minLen := 12
		maxLen := 128
		maxAge := 90
		warning := 14
		history := 5
		lockoutThresh := 5
		lockoutDur := 30
		incFactor := 1.5
		requireFirstChange := true

		req := PasswordPolicyRequest{
			MinLength:                         &minLen,
			MaxLength:                         &maxLen,
			RequireUppercase:                  boolPtrPP(true),
			RequireLowercase:                  boolPtrPP(true),
			RequireNumbers:                    boolPtrPP(true),
			RequireSpecial:                    boolPtrPP(false),
			DisallowUsername:                  boolPtrPP(true),
			DisallowCommonPasswords:           boolPtrPP(true),
			MaxAgeDays:                        &maxAge,
			WarningDaysBeforeExpiry:           &warning,
			HistoryCount:                      &history,
			LockoutThreshold:                  &lockoutThresh,
			LockoutDurationMinutes:            &lockoutDur,
			LockoutIncrementFactor:            &incFactor,
			RequirePasswordChangeOnFirstLogin: &requireFirstChange,
		}

		assert.Equal(t, &minLen, req.MinLength)
		assert.Equal(t, &maxLen, req.MaxLength)
		assert.NotNil(t, req.RequireUppercase)
		assert.True(t, *req.RequireUppercase)
		assert.NotNil(t, req.RequireSpecial)
		assert.False(t, *req.RequireSpecial)
		assert.Equal(t, &maxAge, req.MaxAgeDays)
		assert.Equal(t, &history, req.HistoryCount)
		assert.Equal(t, &lockoutThresh, req.LockoutThreshold)
		assert.Equal(t, &incFactor, req.LockoutIncrementFactor)
		assert.Equal(t, &requireFirstChange, req.RequirePasswordChangeOnFirstLogin)
	})
}

// ==================== PasswordHistory struct ====================

func TestPasswordHistory_Instantiation(t *testing.T) {
	t.Run("should create history entry with all fields", func(t *testing.T) {
		id := uuid.New()
		userID := uuid.New()
		now := time.Now().Truncate(time.Second)

		history := &PasswordHistory{ //nolint:gosec // test fixture value, not a real credential
			ID:           id,
			UserID:       userID,
			PasswordHash: "$2a$10$hashedPasswordValue",
			CreatedAt:    now,
		}

		assert.Equal(t, id, history.ID)
		assert.Equal(t, userID, history.UserID)
		assert.Equal(t, "$2a$10$hashedPasswordValue", history.PasswordHash)
		assert.Equal(t, now, history.CreatedAt)
	})

	t.Run("PasswordHash should have json dash tag (never marshaled)", func(t *testing.T) {
		history := &PasswordHistory{
			ID:           uuid.New(),
			UserID:       uuid.New(),
			PasswordHash: "should-not-appear",
			CreatedAt:    time.Now(),
		}

		data, err := json.Marshal(history)
		require.NoError(t, err)

		var decoded map[string]interface{}
		err = json.Unmarshal(data, &decoded)
		require.NoError(t, err)

		_, hasHash := decoded["password_hash"]
		assert.False(t, hasHash, "password_hash should be excluded from JSON via json:\"-\" tag")
	})
}

// ==================== JSON marshaling ====================

func TestPasswordPolicy_JSONMarshal(t *testing.T) {
	t.Run("should marshal and unmarshal PasswordPolicy", func(t *testing.T) {
		policy := DefaultPasswordPolicy(uuid.New())
		policy.CreatedAt = time.Now().Truncate(time.Second)
		policy.UpdatedAt = time.Now().Truncate(time.Second)

		data, err := json.Marshal(policy)
		require.NoError(t, err)

		var decoded PasswordPolicy
		err = json.Unmarshal(data, &decoded)
		require.NoError(t, err)

		assert.Equal(t, policy.ID, decoded.ID)
		assert.Equal(t, policy.TenantID, decoded.TenantID)
		assert.Equal(t, policy.MinLength, decoded.MinLength)
		assert.Equal(t, policy.RequireUppercase, decoded.RequireUppercase)
		assert.Equal(t, policy.HistoryCount, decoded.HistoryCount)
		assert.Equal(t, policy.LockoutThreshold, decoded.LockoutThreshold)
	})

	t.Run("should marshal PasswordPolicyResponse without sensitive metadata", func(t *testing.T) {
		policy := DefaultPasswordPolicy(uuid.New())
		resp := policy.ToResponse()

		data, err := json.Marshal(resp)
		require.NoError(t, err)

		var decoded map[string]interface{}
		err = json.Unmarshal(data, &decoded)
		require.NoError(t, err)

		assert.Contains(t, decoded, "id")
		assert.Contains(t, decoded, "min_length")
		assert.Contains(t, decoded, "require_uppercase")
		assert.Contains(t, decoded, "lockout_threshold")
		// CreatedBy/UpdatedBy are not on PasswordPolicyResponse, so absent.
		_, hasCreatedBy := decoded["created_by"]
		assert.False(t, hasCreatedBy)
		_, hasUpdatedBy := decoded["updated_by"]
		assert.False(t, hasUpdatedBy)
	})
}
