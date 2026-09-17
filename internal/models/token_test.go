// SPDX-License-Identifier: AGPL-3.0-or-later

package models

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ==================== Token version constants ====================

func TestTokenVersionConstants(t *testing.T) {
	tests := []struct {
		name     string
		constant int
		expected int
	}{
		{
			name:     "TokenVersionLegacy should be 0",
			constant: TokenVersionLegacy,
			expected: 0,
		},
		{
			name:     "TokenVersionMinimal should be 1",
			constant: TokenVersionMinimal,
			expected: 1,
		},
		{
			name:     "TokenVersionSpiceDB should be 2",
			constant: TokenVersionSpiceDB,
			expected: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.constant)
		})
	}
}

func TestTokenVersionConstants_Ordering(t *testing.T) {
	// Versions must be strictly increasing to support backward-compat logic.
	assert.Less(t, TokenVersionLegacy, TokenVersionMinimal,
		"Legacy must be less than Minimal")
	assert.Less(t, TokenVersionMinimal, TokenVersionSpiceDB,
		"Minimal must be less than SpiceDB")
}

func TestTokenVersionConstants_Uniqueness(t *testing.T) {
	versions := map[int]string{
		TokenVersionLegacy:  "TokenVersionLegacy",
		TokenVersionMinimal: "TokenVersionMinimal",
		TokenVersionSpiceDB: "TokenVersionSpiceDB",
	}
	assert.Len(t, versions, 3, "all three version constants must be distinct")
}

// ==================== MinimalClaims struct ====================

func TestMinimalClaims_Fields(t *testing.T) {
	t.Run("should round-trip through JSON", func(t *testing.T) {
		sessionID := uuid.New()
		tenantID := uuid.New()
		realmID := uuid.New()
		now := time.Now().Unix()

		claims := &MinimalClaims{
			RegisteredClaims: jwt.RegisteredClaims{
				Subject:   uuid.New().String(),
				IssuedAt:  jwt.NewNumericDate(time.Unix(now, 0)),
				ExpiresAt: jwt.NewNumericDate(time.Unix(now+3600, 0)),
			},
			SessionID:       sessionID,
			TenantID:        tenantID,
			TenantIDVerbose: tenantID, // backward-compat alias
			RealmID:         realmID,
			Roles:           []string{"admin", "user"},
			Scope:           "tenant",
			Version:         TokenVersionMinimal,
		}

		data, err := json.Marshal(claims)
		require.NoError(t, err)

		var restored MinimalClaims
		require.NoError(t, json.Unmarshal(data, &restored))

		assert.Equal(t, sessionID, restored.SessionID)
		assert.Equal(t, tenantID, restored.TenantID)
		assert.Equal(t, realmID, restored.RealmID)
		assert.Equal(t, []string{"admin", "user"}, restored.Roles)
		assert.Equal(t, "tenant", restored.Scope)
		assert.Equal(t, TokenVersionMinimal, restored.Version)
	})

	t.Run("should use short JSON keys for minimal token size", func(t *testing.T) {
		tenantID := uuid.New()
		claims := &MinimalClaims{
			SessionID:       uuid.New(),
			TenantID:        tenantID,
			TenantIDVerbose: tenantID, // backward-compat alias
			RealmID:         uuid.New(),
			Roles:           []string{"user"},
			Scope:           "tenant",
			Version:         TokenVersionMinimal,
		}

		data, err := json.Marshal(claims)
		require.NoError(t, err)

		var m map[string]interface{}
		require.NoError(t, json.Unmarshal(data, &m))

		// Verify short JSON field names are used.
		assert.Contains(t, m, "sid", "SessionID must marshal to 'sid'")
		assert.Contains(t, m, "tid", "TenantID must marshal to 'tid'")
		assert.Contains(t, m, "rid", "RealmID must marshal to 'rid'")
		assert.Contains(t, m, "roles", "Roles must marshal to 'roles'")
		assert.Contains(t, m, "scp", "Scope must marshal to 'scp'")
		assert.Contains(t, m, "v", "Version must marshal to 'v'")

		// tenant_id is intentionally emitted as a backward-compat alias alongside "tid"
		// so that external consumers (APISIX, third-party relying parties) that look for
		// the verbose claim name find a non-null value.
		assert.Contains(t, m, "tenant_id", "tenant_id backward-compat alias must be present")

		// Other long-form names that were never defined must remain absent.
		assert.NotContains(t, m, "session_id")
		assert.NotContains(t, m, "realm_id")
		assert.NotContains(t, m, "scope")
	})

	t.Run("should support platform scope", func(t *testing.T) {
		claims := &MinimalClaims{
			SessionID: uuid.New(),
			TenantID:  uuid.New(),
			RealmID:   uuid.New(),
			Roles:     []string{"platform_admin"},
			Scope:     "platform",
			Version:   TokenVersionMinimal,
		}

		assert.Equal(t, "platform", claims.Scope)
		assert.Equal(t, TokenVersionMinimal, claims.Version)
	})

	t.Run("Version field set to TokenVersionMinimal", func(t *testing.T) {
		claims := MinimalClaims{Version: TokenVersionMinimal}
		assert.Equal(t, 1, claims.Version)
	})
}

// ==================== SpiceDBClaims struct ====================

func TestSpiceDBClaims_Fields(t *testing.T) {
	t.Run("should round-trip through JSON", func(t *testing.T) {
		sessionID := uuid.New()
		tenantID := uuid.New()
		realmID := uuid.New()
		now := time.Now().Unix()

		claims := &SpiceDBClaims{
			RegisteredClaims: jwt.RegisteredClaims{
				Subject:   uuid.New().String(),
				IssuedAt:  jwt.NewNumericDate(time.Unix(now, 0)),
				ExpiresAt: jwt.NewNumericDate(time.Unix(now+3600, 0)),
			},
			SessionID: sessionID,
			TenantID:  tenantID,
			RealmID:   realmID,
			Roles:     []string{"admin"},
			Version:   TokenVersionSpiceDB,
		}

		data, err := json.Marshal(claims)
		require.NoError(t, err)

		var restored SpiceDBClaims
		require.NoError(t, json.Unmarshal(data, &restored))

		assert.Equal(t, sessionID, restored.SessionID)
		assert.Equal(t, tenantID, restored.TenantID)
		assert.Equal(t, realmID, restored.RealmID)
		assert.Equal(t, []string{"admin"}, restored.Roles)
		assert.Equal(t, TokenVersionSpiceDB, restored.Version)
	})

	t.Run("should use short JSON keys matching MinimalClaims conventions", func(t *testing.T) {
		claims := &SpiceDBClaims{
			SessionID: uuid.New(),
			TenantID:  uuid.New(),
			RealmID:   uuid.New(),
			Roles:     []string{"platform_admin"},
			Version:   TokenVersionSpiceDB,
		}

		data, err := json.Marshal(claims)
		require.NoError(t, err)

		var m map[string]interface{}
		require.NoError(t, json.Unmarshal(data, &m))

		assert.Contains(t, m, "sid", "SessionID must marshal to 'sid'")
		assert.Contains(t, m, "tid", "TenantID must marshal to 'tid'")
		assert.Contains(t, m, "rid", "RealmID must marshal to 'rid'")
		assert.Contains(t, m, "v", "Version must marshal to 'v'")

		// SpiceDBClaims has no 'scp' (scope) field - authorization is ReBAC only.
		assert.NotContains(t, m, "scp",
			"SpiceDBClaims must not have a 'scp' field (authorization is SpiceDB-only)")
	})

	t.Run("Roles field is omitted when empty (omitempty)", func(t *testing.T) {
		claims := &SpiceDBClaims{
			SessionID: uuid.New(),
			TenantID:  uuid.New(),
			RealmID:   uuid.New(),
			Roles:     nil,
			Version:   TokenVersionSpiceDB,
		}

		data, err := json.Marshal(claims)
		require.NoError(t, err)

		var m map[string]interface{}
		require.NoError(t, json.Unmarshal(data, &m))

		// Roles is tagged `json:"roles,omitempty"` so must be absent when nil.
		assert.NotContains(t, m, "roles",
			"empty Roles must be omitted with omitempty")
	})

	t.Run("Version field set to TokenVersionSpiceDB", func(t *testing.T) {
		claims := SpiceDBClaims{Version: TokenVersionSpiceDB}
		assert.Equal(t, 2, claims.Version)
	})
}

// ==================== SessionData.IsImpersonated ====================

func TestSessionData_IsImpersonated(t *testing.T) {
	impersonatorID := uuid.New()
	impersonationSessionID := uuid.New()

	tests := []struct {
		name     string
		session  SessionData
		expected bool
	}{
		{
			name: "should return false when ImpersonatorID is nil",
			session: SessionData{
				UserID:   uuid.New(),
				TenantID: uuid.New(),
				Username: "alice",
				Email:    "alice@example.com",
			},
			expected: false,
		},
		{
			name: "should return true when ImpersonatorID is set",
			session: SessionData{
				UserID:         uuid.New(),
				TenantID:       uuid.New(),
				Username:       "alice",
				Email:          "alice@example.com",
				ImpersonatorID: &impersonatorID,
			},
			expected: true,
		},
		{
			name: "should return true when both impersonator fields are set",
			session: SessionData{
				UserID:                 uuid.New(),
				TenantID:               uuid.New(),
				Username:               "alice",
				Email:                  "alice@example.com",
				ImpersonatorID:         &impersonatorID,
				ImpersonationSessionID: &impersonationSessionID,
			},
			expected: true,
		},
		{
			name: "should return false when ImpersonationSessionID is set but ImpersonatorID is nil",
			session: SessionData{
				UserID:                 uuid.New(),
				TenantID:               uuid.New(),
				Username:               "alice",
				Email:                  "alice@example.com",
				ImpersonationSessionID: &impersonationSessionID,
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.session.IsImpersonated())
		})
	}
}

// ==================== SessionData JSON marshaling ====================

func TestSessionData_JSONRoundTrip(t *testing.T) {
	t.Run("should round-trip all fields through JSON", func(t *testing.T) {
		impersonatorID := uuid.New()
		impersonationSessionID := uuid.New()
		realmID := uuid.New()
		now := time.Now().Unix()

		original := &SessionData{
			UserID:                 uuid.New(),
			TenantID:               uuid.New(),
			Username:               "alice",
			Email:                  "alice@example.com",
			Roles:                  []string{"admin", "user"},
			Permissions:            []string{"core:users:read", "core:roles:write"},
			RealmID:                realmID,
			RealmSlug:              "my-realm",
			RealmType:              "enterprise",
			RoleVersion:            42,
			DeviceInfo:             "Mozilla/5.0",
			IPAddress:              "192.168.1.1",
			CreatedAt:              now,
			ImpersonatorID:         &impersonatorID,
			ImpersonationSessionID: &impersonationSessionID,
		}

		data, err := json.Marshal(original)
		require.NoError(t, err)

		var restored SessionData
		require.NoError(t, json.Unmarshal(data, &restored))

		assert.Equal(t, original.UserID, restored.UserID)
		assert.Equal(t, original.TenantID, restored.TenantID)
		assert.Equal(t, original.Username, restored.Username)
		assert.Equal(t, original.Email, restored.Email)
		assert.Equal(t, original.Roles, restored.Roles)
		assert.Equal(t, original.Permissions, restored.Permissions)
		assert.Equal(t, original.RealmID, restored.RealmID)
		assert.Equal(t, original.RealmSlug, restored.RealmSlug)
		assert.Equal(t, original.RealmType, restored.RealmType)
		assert.Equal(t, original.RoleVersion, restored.RoleVersion)
		assert.Equal(t, original.DeviceInfo, restored.DeviceInfo)
		assert.Equal(t, original.IPAddress, restored.IPAddress)
		assert.Equal(t, original.CreatedAt, restored.CreatedAt)
		require.NotNil(t, restored.ImpersonatorID)
		assert.Equal(t, *original.ImpersonatorID, *restored.ImpersonatorID)
		require.NotNil(t, restored.ImpersonationSessionID)
		assert.Equal(t, *original.ImpersonationSessionID, *restored.ImpersonationSessionID)
	})

	t.Run("should omit optional fields when nil or empty", func(t *testing.T) {
		s := &SessionData{
			UserID:   uuid.New(),
			TenantID: uuid.New(),
			Username: "bob",
			Email:    "bob@example.com",
		}

		data, err := json.Marshal(s)
		require.NoError(t, err)

		var m map[string]interface{}
		require.NoError(t, json.Unmarshal(data, &m))

		// omitempty fields should be absent.
		assert.NotContains(t, m, "impersonator_id")
		assert.NotContains(t, m, "impersonation_session_id")
		assert.NotContains(t, m, "realm_slug",
			"empty RealmSlug (omitempty) must be absent")
		assert.NotContains(t, m, "realm_type",
			"empty RealmType (omitempty) must be absent")
		assert.NotContains(t, m, "device_info",
			"empty DeviceInfo (omitempty) must be absent")
		assert.NotContains(t, m, "ip_address",
			"empty IPAddress (omitempty) must be absent")
	})
}

// ==================== PasswordReset struct ====================

func TestPasswordReset_SensitiveFieldsExcludedFromJSON(t *testing.T) {
	t.Run("TokenHash must have json dash tag", func(t *testing.T) {
		pr := &PasswordReset{ //nolint:gosec // test fixture value, not a real credential
			ID:        uuid.New(),
			UserID:    uuid.New(),
			TokenHash: "sha256:resettokenhash",
			CreatedAt: time.Now(),
			ExpiresAt: time.Now().Add(15 * time.Minute),
		}

		data, err := json.Marshal(pr)
		require.NoError(t, err)

		var m map[string]interface{}
		require.NoError(t, json.Unmarshal(data, &m))

		assert.NotContains(t, m, "token_hash",
			"TokenHash (json:\"-\") must not appear in JSON output")
		assert.Contains(t, m, "id")
		assert.Contains(t, m, "user_id")
	})
}

// ==================== MFARecoveryCode struct ====================

func TestMFARecoveryCode_SensitiveFieldsExcludedFromJSON(t *testing.T) {
	t.Run("CodeHash must have json dash tag", func(t *testing.T) {
		rc := &MFARecoveryCode{
			ID:        uuid.New(),
			UserID:    uuid.New(),
			CodeHash:  "bcrypt:recoverycodehash",
			CreatedAt: time.Now(),
		}

		data, err := json.Marshal(rc)
		require.NoError(t, err)

		var m map[string]interface{}
		require.NoError(t, json.Unmarshal(data, &m))

		assert.NotContains(t, m, "code_hash",
			"CodeHash (json:\"-\") must not appear in JSON output")
		assert.Contains(t, m, "id")
		assert.Contains(t, m, "user_id")
	})
}

// ==================== SessionData.IsImpersonated boundary cases ====================

func TestSessionData_IsImpersonated_ZeroUUID(t *testing.T) {
	t.Run("nil pointer is not impersonated", func(t *testing.T) {
		s := &SessionData{
			UserID:         uuid.New(),
			ImpersonatorID: nil,
		}
		assert.False(t, s.IsImpersonated())
	})

	t.Run("pointer to zero UUID still counts as impersonated", func(t *testing.T) {
		// If the impersonator ID is set (even to zero UUID), the session is
		// considered impersonated - the nil check is purely on the pointer.
		zeroID := uuid.Nil
		s := &SessionData{
			UserID:         uuid.New(),
			ImpersonatorID: &zeroID,
		}
		assert.True(t, s.IsImpersonated(),
			"non-nil pointer to zero UUID is still considered impersonated")
	})
}

// ==================== MinimalClaims embeds jwt.RegisteredClaims ====================

func TestMinimalClaims_EmbeddsRegisteredClaims(t *testing.T) {
	// Verify that RegisteredClaims standard fields round-trip correctly.
	subject := uuid.New().String()
	iat := time.Now().Truncate(time.Second)
	exp := iat.Add(15 * time.Minute)

	claims := &MinimalClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "falcon-id",
			Subject:   subject,
			IssuedAt:  jwt.NewNumericDate(iat),
			ExpiresAt: jwt.NewNumericDate(exp),
		},
		SessionID: uuid.New(),
		TenantID:  uuid.New(),
		RealmID:   uuid.New(),
		Version:   TokenVersionMinimal,
	}

	data, err := json.Marshal(claims)
	require.NoError(t, err)

	var m map[string]interface{}
	require.NoError(t, json.Unmarshal(data, &m))

	// jwt.RegisteredClaims standard field names.
	assert.Contains(t, m, "iss", "Issuer must appear as 'iss'")
	assert.Contains(t, m, "sub", "Subject must appear as 'sub'")
	assert.Equal(t, "falcon-id", m["iss"])
	assert.Equal(t, subject, m["sub"])
}

// ==================== SpiceDBClaims embeds jwt.RegisteredClaims ====================

func TestSpiceDBClaims_EmbeddsRegisteredClaims(t *testing.T) {
	subject := uuid.New().String()

	claims := &SpiceDBClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:  "falcon-id",
			Subject: subject,
		},
		SessionID: uuid.New(),
		TenantID:  uuid.New(),
		RealmID:   uuid.New(),
		Version:   TokenVersionSpiceDB,
	}

	data, err := json.Marshal(claims)
	require.NoError(t, err)

	var m map[string]interface{}
	require.NoError(t, json.Unmarshal(data, &m))

	assert.Contains(t, m, "iss")
	assert.Contains(t, m, "sub")
	assert.Equal(t, "falcon-id", m["iss"])
	assert.Equal(t, subject, m["sub"])
}
