// SPDX-License-Identifier: AGPL-3.0-or-later

package models

import (
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ==================== MinimalClaims struct ====================

func TestMinimalClaims_StructFields(t *testing.T) {
	t.Run("should carry all claim fields correctly", func(t *testing.T) {
		sessionID := uuid.New()
		tenantID := uuid.New()
		realmID := uuid.New()
		subject := uuid.New().String()

		claims := MinimalClaims{
			RegisteredClaims: jwt.RegisteredClaims{
				Subject: subject,
				Issuer:  "falcon-id",
			},
			SessionID: sessionID,
			TenantID:  tenantID,
			RealmID:   realmID,
			Roles:     []string{"admin", "user"},
			Scope:     "tenant",
			Version:   TokenVersionMinimal,
		}

		assert.Equal(t, subject, claims.Subject)
		assert.Equal(t, "falcon-id", claims.Issuer)
		assert.Equal(t, sessionID, claims.SessionID)
		assert.Equal(t, tenantID, claims.TenantID)
		assert.Equal(t, realmID, claims.RealmID)
		assert.Equal(t, []string{"admin", "user"}, claims.Roles)
		assert.Equal(t, "tenant", claims.Scope)
		assert.Equal(t, TokenVersionMinimal, claims.Version)
	})

	t.Run("should embed jwt.RegisteredClaims correctly", func(_ *testing.T) {
		claims := MinimalClaims{}

		// Verify it embeds RegisteredClaims by accessing embedded fields
		var _ jwt.Claims = &claims
	})

	t.Run("should support platform scope", func(t *testing.T) {
		claims := MinimalClaims{
			Scope:   "platform",
			Version: TokenVersionMinimal,
		}

		assert.Equal(t, "platform", claims.Scope)
	})

	t.Run("should support tenant scope", func(t *testing.T) {
		claims := MinimalClaims{
			Scope:   "tenant",
			Version: TokenVersionMinimal,
		}

		assert.Equal(t, "tenant", claims.Scope)
	})

	t.Run("should allow empty Roles slice", func(t *testing.T) {
		claims := MinimalClaims{
			SessionID: uuid.New(),
			TenantID:  uuid.New(),
			RealmID:   uuid.New(),
			Roles:     []string{},
			Version:   TokenVersionMinimal,
		}

		assert.Empty(t, claims.Roles)
	})

	t.Run("should carry version field matching TokenVersionMinimal", func(t *testing.T) {
		claims := MinimalClaims{Version: TokenVersionMinimal}
		assert.Equal(t, 1, claims.Version)
	})
}

// ==================== SpiceDBClaims struct ====================

func TestSpiceDBClaims_StructFields(t *testing.T) {
	t.Run("should carry all claim fields correctly", func(t *testing.T) {
		sessionID := uuid.New()
		tenantID := uuid.New()
		realmID := uuid.New()
		subject := uuid.New().String()

		claims := SpiceDBClaims{
			RegisteredClaims: jwt.RegisteredClaims{
				Subject: subject,
				Issuer:  "falcon-id",
			},
			SessionID: sessionID,
			TenantID:  tenantID,
			RealmID:   realmID,
			Roles:     []string{"admin"},
			Version:   TokenVersionSpiceDB,
		}

		assert.Equal(t, subject, claims.Subject)
		assert.Equal(t, "falcon-id", claims.Issuer)
		assert.Equal(t, sessionID, claims.SessionID)
		assert.Equal(t, tenantID, claims.TenantID)
		assert.Equal(t, realmID, claims.RealmID)
		assert.Equal(t, []string{"admin"}, claims.Roles)
		assert.Equal(t, TokenVersionSpiceDB, claims.Version)
	})

	t.Run("should embed jwt.RegisteredClaims correctly", func(_ *testing.T) {
		claims := SpiceDBClaims{}
		// Verify it satisfies jwt.Claims interface
		var _ jwt.Claims = &claims
	})

	t.Run("should allow nil/empty Roles (omitempty)", func(t *testing.T) {
		claims := SpiceDBClaims{
			SessionID: uuid.New(),
			TenantID:  uuid.New(),
			RealmID:   uuid.New(),
			Version:   TokenVersionSpiceDB,
		}

		assert.Nil(t, claims.Roles)
	})

	t.Run("should carry version field matching TokenVersionSpiceDB", func(t *testing.T) {
		claims := SpiceDBClaims{Version: TokenVersionSpiceDB}
		assert.Equal(t, 2, claims.Version)
	})
}

// ==================== SessionData struct ====================

func TestSessionData_StructFields(t *testing.T) {
	t.Run("should carry all session data fields", func(t *testing.T) {
		userID := uuid.New()
		tenantID := uuid.New()
		realmID := uuid.New()
		impersonatorID := uuid.New()
		impersonationSessionID := uuid.New()
		now := int64(1700000000)

		session := SessionData{
			UserID:                 userID,
			TenantID:               tenantID,
			Username:               "alice",
			Email:                  "alice@example.com",
			Roles:                  []string{"admin", "user"},
			Permissions:            []string{"core:users:read", "core:users:write"},
			RealmID:                realmID,
			RealmSlug:              "main",
			RealmType:              "enterprise",
			RoleVersion:            42,
			DeviceInfo:             "MacBook Pro",
			IPAddress:              "192.168.1.100",
			CreatedAt:              now,
			ImpersonatorID:         &impersonatorID,
			ImpersonationSessionID: &impersonationSessionID,
		}

		assert.Equal(t, userID, session.UserID)
		assert.Equal(t, tenantID, session.TenantID)
		assert.Equal(t, "alice", session.Username)
		assert.Equal(t, "alice@example.com", session.Email)
		assert.Equal(t, []string{"admin", "user"}, session.Roles)
		assert.Equal(t, []string{"core:users:read", "core:users:write"}, session.Permissions)
		assert.Equal(t, realmID, session.RealmID)
		assert.Equal(t, "main", session.RealmSlug)
		assert.Equal(t, "enterprise", session.RealmType)
		assert.Equal(t, int64(42), session.RoleVersion)
		assert.Equal(t, "MacBook Pro", session.DeviceInfo)
		assert.Equal(t, "192.168.1.100", session.IPAddress)
		assert.Equal(t, now, session.CreatedAt)
		require.NotNil(t, session.ImpersonatorID)
		assert.Equal(t, impersonatorID, *session.ImpersonatorID)
		require.NotNil(t, session.ImpersonationSessionID)
		assert.Equal(t, impersonationSessionID, *session.ImpersonationSessionID)
	})

	t.Run("should allow nil impersonation fields for regular sessions", func(t *testing.T) {
		session := SessionData{
			UserID:   uuid.New(),
			TenantID: uuid.New(),
			Username: "bob",
			Email:    "bob@example.com",
		}

		assert.Nil(t, session.ImpersonatorID)
		assert.Nil(t, session.ImpersonationSessionID)
	})
}

// ==================== MinimalClaims vs SpiceDBClaims version distinction ====================

func TestClaims_VersionDistinction(t *testing.T) {
	t.Run("MinimalClaims and SpiceDBClaims use different version values", func(t *testing.T) {
		minimal := MinimalClaims{Version: TokenVersionMinimal}
		spicedb := SpiceDBClaims{Version: TokenVersionSpiceDB}

		assert.NotEqual(t, minimal.Version, spicedb.Version,
			"minimal (v1) and spicedb (v2) token versions must differ")
	})
}

// ==================== MinimalClaims role variations ====================

func TestMinimalClaims_RoleVariations(t *testing.T) {
	tests := []struct {
		name  string
		roles []string
	}{
		{
			name:  "single admin role",
			roles: []string{"admin"},
		},
		{
			name:  "multiple roles",
			roles: []string{"admin", "user", "manager"},
		},
		{
			name:  "platform admin role",
			roles: []string{"platform_admin"},
		},
		{
			name:  "empty roles",
			roles: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			claims := MinimalClaims{
				SessionID: uuid.New(),
				TenantID:  uuid.New(),
				RealmID:   uuid.New(),
				Roles:     tt.roles,
				Version:   TokenVersionMinimal,
			}

			assert.Equal(t, tt.roles, claims.Roles)
		})
	}
}

// ==================== SessionData permissions list ====================

func TestSessionData_Permissions(t *testing.T) {
	t.Run("should store full permissions list", func(t *testing.T) {
		permissions := []string{
			"core:users:read",
			"core:users:write",
			"core:users:delete",
			"billing:invoices:read",
			"crm:contacts:read",
		}

		session := SessionData{
			UserID:      uuid.New(),
			TenantID:    uuid.New(),
			Permissions: permissions,
		}

		assert.Equal(t, permissions, session.Permissions)
		assert.Len(t, session.Permissions, 5)
	})

	t.Run("should allow empty permissions list", func(t *testing.T) {
		session := SessionData{
			UserID:      uuid.New(),
			TenantID:    uuid.New(),
			Permissions: []string{},
		}

		assert.Empty(t, session.Permissions)
	})
}
