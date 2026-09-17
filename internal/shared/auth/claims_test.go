// SPDX-License-Identifier: AGPL-3.0-or-later

package auth

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ==================== Claims.IsImpersonated ====================

func TestClaims_IsImpersonated(t *testing.T) {
	tests := []struct {
		name     string
		claims   Claims
		expected bool
	}{
		{
			name: "should return true when ImpersonatorID is set",
			claims: Claims{
				ImpersonatorID: uuidPtr(uuid.New()),
			},
			expected: true,
		},
		{
			name:     "should return false when ImpersonatorID is nil",
			claims:   Claims{},
			expected: false,
		},
		{
			name: "should return true even when ImpersonationSessionID is also set",
			claims: Claims{
				ImpersonatorID:         uuidPtr(uuid.New()),
				ImpersonationSessionID: uuidPtr(uuid.New()),
			},
			expected: true,
		},
		{
			name: "should return false when only ImpersonationSessionID is set (no impersonator)",
			claims: Claims{
				ImpersonationSessionID: uuidPtr(uuid.New()),
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.claims.IsImpersonated())
		})
	}
}

// ==================== Claims.IsServiceAccount ====================

func TestClaims_IsServiceAccount(t *testing.T) {
	tests := []struct {
		name     string
		claims   Claims
		expected bool
	}{
		{
			name: "should return true when ServiceAccountID is set",
			claims: Claims{
				ServiceAccountID: uuidPtr(uuid.New()),
			},
			expected: true,
		},
		{
			name: "should return true when TokenType is service_account",
			claims: Claims{
				TokenType: "service_account",
			},
			expected: true,
		},
		{
			name: "should return true when both ServiceAccountID and TokenType are set",
			claims: Claims{
				ServiceAccountID: uuidPtr(uuid.New()),
				TokenType:        "service_account",
			},
			expected: true,
		},
		{
			name:     "should return false when neither ServiceAccountID nor TokenType is set",
			claims:   Claims{},
			expected: false,
		},
		{
			name: "should return false when TokenType is user",
			claims: Claims{
				TokenType: "user",
			},
			expected: false,
		},
		{
			name: "should return false when TokenType is empty string",
			claims: Claims{
				TokenType: "",
			},
			expected: false,
		},
		{
			name: "should return false when TokenType is an arbitrary non-service-account value",
			claims: Claims{
				TokenType: "client_credentials",
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.claims.IsServiceAccount())
		})
	}
}

// ==================== Claims.IsExpired ====================

func TestClaims_IsExpired(t *testing.T) {
	now := time.Now()

	tests := []struct {
		name     string
		claims   Claims
		expected bool
	}{
		{
			name: "should return true when ExpiresAt is in the past",
			claims: Claims{
				ExpiresAt: now.Add(-1 * time.Hour).Unix(),
			},
			expected: true,
		},
		{
			name: "should return true when ExpiresAt is one second in the past",
			claims: Claims{
				ExpiresAt: now.Add(-1 * time.Second).Unix(),
			},
			expected: true,
		},
		{
			name: "should return false when ExpiresAt is in the future",
			claims: Claims{
				ExpiresAt: now.Add(1 * time.Hour).Unix(),
			},
			expected: false,
		},
		{
			name: "should return false when ExpiresAt is far in the future",
			claims: Claims{
				ExpiresAt: now.Add(365 * 24 * time.Hour).Unix(),
			},
			expected: false,
		},
		{
			name: "should return false when ExpiresAt is zero (no expiry configured)",
			claims: Claims{
				ExpiresAt: 0,
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.claims.IsExpired())
		})
	}
}

// TestClaims_IsExpired_ZeroValue confirms that a zero-value Claims struct is
// not considered expired (ExpiresAt defaults to 0).
func TestClaims_IsExpired_ZeroValue(t *testing.T) {
	c := Claims{}
	assert.False(t, c.IsExpired(), "zero-value Claims must not be considered expired")
}

// TestClaims_IsExpired_Boundary verifies boundary conditions at the expiry edge.
func TestClaims_IsExpired_Boundary(t *testing.T) {
	t.Run("token expiring exactly one minute from now is not expired", func(t *testing.T) {
		c := Claims{
			ExpiresAt: time.Now().Add(1 * time.Minute).Unix(),
		}
		assert.False(t, c.IsExpired())
	})

	t.Run("token that expired one nanosecond ago (unix-second boundary) may or may not expire", func(t *testing.T) {
		// Unix() truncates to seconds, so expiring "one nanosecond ago" at the
		// sub-second level means the Unix timestamp is the current second or one
		// second in the past depending on when within the second this runs.
		// We deliberately use a full second in the past to ensure determinism.
		c := Claims{
			ExpiresAt: time.Now().Add(-1 * time.Second).Unix(),
		}
		assert.True(t, c.IsExpired())
	})
}

// ==================== Claims.IsNotYetValid ====================

func TestClaims_IsNotYetValid(t *testing.T) {
	now := time.Now()

	tests := []struct {
		name     string
		claims   Claims
		expected bool
	}{
		{
			name: "should return true when NotBefore is in the future",
			claims: Claims{
				NotBefore: now.Add(1 * time.Hour).Unix(),
			},
			expected: true,
		},
		{
			name: "should return true when NotBefore is one minute in the future",
			claims: Claims{
				NotBefore: now.Add(1 * time.Minute).Unix(),
			},
			expected: true,
		},
		{
			name: "should return false when NotBefore is in the past",
			claims: Claims{
				NotBefore: now.Add(-1 * time.Hour).Unix(),
			},
			expected: false,
		},
		{
			name: "should return false when NotBefore is one second in the past",
			claims: Claims{
				NotBefore: now.Add(-1 * time.Second).Unix(),
			},
			expected: false,
		},
		{
			name: "should return false when NotBefore is zero (no restriction)",
			claims: Claims{
				NotBefore: 0,
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.claims.IsNotYetValid())
		})
	}
}

// TestClaims_IsNotYetValid_ZeroValue confirms that a zero-value Claims struct
// does not report the token as not-yet-valid.
func TestClaims_IsNotYetValid_ZeroValue(t *testing.T) {
	c := Claims{}
	assert.False(t, c.IsNotYetValid(), "zero-value Claims must not be considered not-yet-valid")
}

// ==================== Claims mutual state combinations ====================

func TestClaims_StateCombinations(t *testing.T) {
	now := time.Now()

	t.Run("valid token — not expired, not future-dated, not impersonated, not service account", func(t *testing.T) {
		c := Claims{
			IssuedAt:  now.Add(-5 * time.Minute).Unix(),
			NotBefore: now.Add(-5 * time.Minute).Unix(),
			ExpiresAt: now.Add(55 * time.Minute).Unix(),
		}

		assert.False(t, c.IsExpired())
		assert.False(t, c.IsNotYetValid())
		assert.False(t, c.IsImpersonated())
		assert.False(t, c.IsServiceAccount())
	})

	t.Run("expired impersonated token", func(t *testing.T) {
		c := Claims{
			ExpiresAt:      now.Add(-10 * time.Minute).Unix(),
			ImpersonatorID: uuidPtr(uuid.New()),
		}

		assert.True(t, c.IsExpired())
		assert.True(t, c.IsImpersonated())
	})

	t.Run("not-yet-valid service account token", func(t *testing.T) {
		c := Claims{
			NotBefore: now.Add(30 * time.Minute).Unix(),
			ExpiresAt: now.Add(2 * time.Hour).Unix(),
			TokenType: "service_account",
		}

		assert.False(t, c.IsExpired())
		assert.True(t, c.IsNotYetValid())
		assert.True(t, c.IsServiceAccount())
	})
}

// ==================== NewCurrentUserFromClaims — field mapping ====================

func TestNewCurrentUserFromClaims_FieldMapping(t *testing.T) {
	t.Run("should map all standard JWT claims to CurrentUser correctly", func(t *testing.T) {
		tenantID := uuid.New()
		userID := uuid.New()
		sessionID := uuid.New()

		claims := &Claims{
			TenantID:    tenantID,
			UserID:      userID,
			Username:    "jane.doe",
			Email:       "jane.doe@example.com",
			Roles:       []string{"admin", "manager"},
			Permissions: []string{"core:users:read", "core:users:write"},
			SessionID:   sessionID,
		}

		user := NewCurrentUserFromClaims(claims)

		require.NotNil(t, user)
		assert.Equal(t, userID, user.ID)
		assert.Equal(t, tenantID, user.TenantID)
		assert.Equal(t, "jane.doe", user.Username)
		assert.Equal(t, "jane.doe@example.com", user.Email)
		assert.Equal(t, []string{"admin", "manager"}, user.Roles)
		assert.Equal(t, []string{"core:users:read", "core:users:write"}, user.Permissions)
		assert.Equal(t, sessionID, user.SessionID)
		assert.Equal(t, AuthMethodJWT, user.AuthMethod)
		assert.Nil(t, user.ServiceAccountID)
	})

	t.Run("should set AuthMethod to ServiceAccount when claims.IsServiceAccount() is true via ServiceAccountID", func(t *testing.T) {
		saID := uuid.New()
		claims := &Claims{
			TenantID:         uuid.New(),
			UserID:           uuid.New(),
			SessionID:        uuid.New(),
			ServiceAccountID: &saID,
		}

		user := NewCurrentUserFromClaims(claims)

		require.NotNil(t, user)
		assert.Equal(t, AuthMethodServiceAccount, user.AuthMethod)
		require.NotNil(t, user.ServiceAccountID)
		assert.Equal(t, saID, *user.ServiceAccountID)
	})

	t.Run("should set AuthMethod to ServiceAccount when TokenType is service_account", func(t *testing.T) {
		claims := &Claims{
			TenantID:  uuid.New(),
			UserID:    uuid.New(),
			SessionID: uuid.New(),
			TokenType: "service_account",
		}

		user := NewCurrentUserFromClaims(claims)

		require.NotNil(t, user)
		assert.Equal(t, AuthMethodServiceAccount, user.AuthMethod)
	})

	t.Run("should propagate nil ServiceAccountID when claims have no service account", func(t *testing.T) {
		claims := &Claims{
			TenantID:  uuid.New(),
			UserID:    uuid.New(),
			SessionID: uuid.New(),
			TokenType: "user",
		}

		user := NewCurrentUserFromClaims(claims)

		assert.Equal(t, AuthMethodJWT, user.AuthMethod)
		assert.Nil(t, user.ServiceAccountID)
	})

	t.Run("should map empty roles and permissions slices without nil panic", func(t *testing.T) {
		claims := &Claims{
			TenantID:    uuid.New(),
			UserID:      uuid.New(),
			SessionID:   uuid.New(),
			Roles:       []string{},
			Permissions: []string{},
		}

		user := NewCurrentUserFromClaims(claims)

		require.NotNil(t, user)
		assert.Empty(t, user.Roles)
		assert.Empty(t, user.Permissions)
	})

	t.Run("should map nil roles and permissions from claims without panic", func(t *testing.T) {
		claims := &Claims{
			TenantID:    uuid.New(),
			UserID:      uuid.New(),
			SessionID:   uuid.New(),
			Roles:       nil,
			Permissions: nil,
		}

		user := NewCurrentUserFromClaims(claims)

		require.NotNil(t, user)
		assert.Nil(t, user.Roles)
		assert.Nil(t, user.Permissions)
	})
}

// TestNewCurrentUserFromClaims_ServiceAccountPermissions verifies that a service
// account user built from claims correctly reports its permissions.
func TestNewCurrentUserFromClaims_ServiceAccountPermissions(t *testing.T) {
	saID := uuid.New()
	claims := &Claims{
		TenantID:         uuid.New(),
		UserID:           uuid.New(),
		SessionID:        uuid.New(),
		ServiceAccountID: &saID,
		TokenType:        "service_account",
		Permissions:      []string{"internal:*"},
		Scopes:           []string{"read", "write"},
	}

	user := NewCurrentUserFromClaims(claims)

	require.NotNil(t, user)
	assert.Equal(t, AuthMethodServiceAccount, user.AuthMethod)
	assert.True(t, user.IsServiceAccount())
	assert.True(t, user.HasPermission("internal:service:call"))
	assert.False(t, user.HasPermission("core:users:read"))
}

// ==================== CurrentUser.IsServiceAccount ====================

func TestCurrentUser_IsServiceAccount_Comprehensive(t *testing.T) {
	tests := []struct {
		name     string
		user     CurrentUser
		expected bool
	}{
		{
			name: "should return true when ServiceAccountID is set",
			user: CurrentUser{
				ServiceAccountID: uuidPtr(uuid.New()),
				AuthMethod:       AuthMethodJWT,
			},
			expected: true,
		},
		{
			name: "should return true when AuthMethod is AuthMethodServiceAccount",
			user: CurrentUser{
				AuthMethod: AuthMethodServiceAccount,
			},
			expected: true,
		},
		{
			name: "should return true when both are set",
			user: CurrentUser{
				ServiceAccountID: uuidPtr(uuid.New()),
				AuthMethod:       AuthMethodServiceAccount,
			},
			expected: true,
		},
		{
			name: "should return false for JWT user without service account ID",
			user: CurrentUser{
				AuthMethod: AuthMethodJWT,
			},
			expected: false,
		},
		{
			name: "should return false for API key user without service account ID",
			user: CurrentUser{
				AuthMethod: AuthMethodAPIKey,
			},
			expected: false,
		},
		{
			name:     "should return false for zero-value user",
			user:     CurrentUser{},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.user.IsServiceAccount())
		})
	}
}

// ==================== CurrentUser.IsAPIKeyAuth ====================

func TestCurrentUser_IsAPIKeyAuth_Comprehensive(t *testing.T) {
	tests := []struct {
		name     string
		user     CurrentUser
		expected bool
	}{
		{
			name: "should return true when AuthMethod is AuthMethodAPIKey",
			user: CurrentUser{
				AuthMethod: AuthMethodAPIKey,
			},
			expected: true,
		},
		{
			name: "should return false when AuthMethod is AuthMethodJWT",
			user: CurrentUser{
				AuthMethod: AuthMethodJWT,
			},
			expected: false,
		},
		{
			name: "should return false when AuthMethod is AuthMethodServiceAccount",
			user: CurrentUser{
				AuthMethod: AuthMethodServiceAccount,
			},
			expected: false,
		},
		{
			name:     "should return false for zero-value user",
			user:     CurrentUser{},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.user.IsAPIKeyAuth())
		})
	}
}

// ==================== AuthMethod constants ====================

func TestAuthMethodConstants(t *testing.T) {
	assert.Equal(t, AuthMethod("jwt"), AuthMethodJWT)
	assert.Equal(t, AuthMethod("api_key"), AuthMethodAPIKey)
	assert.Equal(t, AuthMethod("service_account"), AuthMethodServiceAccount)
}

// ==================== Helpers ====================

// uuidPtr returns a pointer to the given uuid.UUID value.
func uuidPtr(u uuid.UUID) *uuid.UUID {
	return &u
}
