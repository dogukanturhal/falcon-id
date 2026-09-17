// SPDX-License-Identifier: AGPL-3.0-or-later

package spicedb

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateTenantContext(t *testing.T) {
	client := &Client{}

	tenantA := uuid.New()
	tenantB := uuid.New()

	tests := []struct {
		name              string
		contextTenant     uuid.UUID
		requestedTenant   uuid.UUID
		isPlatformAdmin   bool
		expectError       bool
		expectedErrorType error
	}{
		{
			name:            "valid - same tenant",
			contextTenant:   tenantA,
			requestedTenant: tenantA,
			expectError:     false,
		},
		{
			name:              "invalid - different tenant",
			contextTenant:     tenantA,
			requestedTenant:   tenantB,
			expectError:       true,
			expectedErrorType: ErrTenantMismatch,
		},
		{
			name:            "valid - platform admin cross-tenant",
			contextTenant:   tenantA,
			requestedTenant: tenantB,
			isPlatformAdmin: true,
			expectError:     false,
		},
		{
			name:              "invalid - zero tenant ID",
			contextTenant:     tenantA,
			requestedTenant:   uuid.Nil,
			expectError:       true,
			expectedErrorType: ErrInvalidTenantID,
		},
		{
			name:              "invalid - missing context",
			contextTenant:     uuid.Nil,
			requestedTenant:   tenantA,
			expectError:       true,
			expectedErrorType: ErrTenantContextMissing,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()

			// Set context only if tenant is not nil
			if tt.contextTenant != uuid.Nil {
				ctx = SetAuthenticatedTenant(ctx, tt.contextTenant)
			}

			if tt.isPlatformAdmin {
				ctx = SetPlatformAdmin(ctx, true)
			}

			err := client.ValidateTenantContext(ctx, tt.requestedTenant)

			if tt.expectError {
				require.Error(t, err)
				if tt.expectedErrorType != nil {
					assert.ErrorIs(t, err, tt.expectedErrorType)
				}
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestValidateUserContext(t *testing.T) {
	client := &Client{}

	userA := uuid.New()
	userB := uuid.New()

	tests := []struct {
		name              string
		contextUser       uuid.UUID
		requestedUser     uuid.UUID
		allowCrossUser    bool
		isPlatformAdmin   bool
		expectError       bool
		expectedErrorType error
	}{
		{
			name:           "valid - same user",
			contextUser:    userA,
			requestedUser:  userA,
			allowCrossUser: false,
			expectError:    false,
		},
		{
			name:           "invalid - different user without cross-user permission",
			contextUser:    userA,
			requestedUser:  userB,
			allowCrossUser: false,
			expectError:    true,
		},
		{
			name:           "valid - different user with cross-user permission",
			contextUser:    userA,
			requestedUser:  userB,
			allowCrossUser: true,
			expectError:    false,
		},
		{
			name:            "valid - platform admin cross-user",
			contextUser:     userA,
			requestedUser:   userB,
			allowCrossUser:  false,
			isPlatformAdmin: true,
			expectError:     false,
		},
		{
			name:              "invalid - zero user ID",
			contextUser:       userA,
			requestedUser:     uuid.Nil,
			expectError:       true,
			expectedErrorType: ErrInvalidUserID,
		},
		{
			name:              "invalid - missing context",
			contextUser:       uuid.Nil,
			requestedUser:     userA,
			expectError:       true,
			expectedErrorType: ErrUserContextMissing,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()

			// Set context only if user is not nil
			if tt.contextUser != uuid.Nil {
				ctx = SetAuthenticatedUser(ctx, tt.contextUser)
			}

			if tt.isPlatformAdmin {
				ctx = SetPlatformAdmin(ctx, true)
			}

			err := client.ValidateUserContext(ctx, tt.requestedUser, tt.allowCrossUser)

			if tt.expectError {
				require.Error(t, err)
				if tt.expectedErrorType != nil {
					assert.ErrorIs(t, err, tt.expectedErrorType)
				}
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestContextSettersAndGetters(t *testing.T) {
	tenantID := uuid.New()
	userID := uuid.New()

	t.Run("SetAuthenticatedTenant and GetAuthenticatedTenant", func(t *testing.T) {
		ctx := context.Background()
		ctx = SetAuthenticatedTenant(ctx, tenantID)

		retrieved := GetAuthenticatedTenant(ctx)
		assert.Equal(t, tenantID, retrieved)
	})

	t.Run("SetAuthenticatedUser and GetAuthenticatedUser", func(t *testing.T) {
		ctx := context.Background()
		ctx = SetAuthenticatedUser(ctx, userID)

		retrieved := GetAuthenticatedUser(ctx)
		assert.Equal(t, userID, retrieved)
	})

	t.Run("SetPlatformAdmin and IsPlatformAdmin", func(t *testing.T) {
		ctx := context.Background()
		ctx = SetPlatformAdmin(ctx, true)

		isPlatformAdmin := IsPlatformAdmin(ctx)
		assert.True(t, isPlatformAdmin)
	})

	t.Run("GetAuthenticatedTenant with empty context", func(t *testing.T) {
		ctx := context.Background()
		retrieved := GetAuthenticatedTenant(ctx)
		assert.Equal(t, uuid.Nil, retrieved)
	})

	t.Run("GetAuthenticatedUser with empty context", func(t *testing.T) {
		ctx := context.Background()
		retrieved := GetAuthenticatedUser(ctx)
		assert.Equal(t, uuid.Nil, retrieved)
	})

	t.Run("IsPlatformAdmin with empty context", func(t *testing.T) {
		ctx := context.Background()
		isPlatformAdmin := IsPlatformAdmin(ctx)
		assert.False(t, isPlatformAdmin)
	})
}

func TestCrosstenantAttackPrevention(t *testing.T) {
	client := &Client{}

	// Simulate an attacker from tenant A trying to access tenant B
	attackerTenant := uuid.New()
	victimTenant := uuid.New()

	ctx := context.Background()
	ctx = SetAuthenticatedTenant(ctx, attackerTenant)
	ctx = SetPlatformAdmin(ctx, false)

	// Attempt to validate access to victim tenant
	err := client.ValidateTenantContext(ctx, victimTenant)

	require.Error(t, err)
	assert.ErrorIs(t, err, ErrTenantMismatch)
}

func TestPlatformAdminBypass(t *testing.T) {
	client := &Client{}

	platformTenant := uuid.New()
	customerTenant := uuid.New()

	ctx := context.Background()
	ctx = SetAuthenticatedTenant(ctx, platformTenant)
	ctx = SetPlatformAdmin(ctx, true)

	// Platform admin should be able to access any tenant
	err := client.ValidateTenantContext(ctx, customerTenant)
	require.NoError(t, err)
}

func TestZeroUUIDRejection(t *testing.T) {
	client := &Client{}

	validTenant := uuid.New()

	tests := []struct {
		name            string
		contextTenant   uuid.UUID
		requestedTenant uuid.UUID
		shouldFail      bool
	}{
		{
			name:            "reject zero requested tenant",
			contextTenant:   validTenant,
			requestedTenant: uuid.Nil,
			shouldFail:      true,
		},
		{
			name:            "reject zero context tenant",
			contextTenant:   uuid.Nil,
			requestedTenant: validTenant,
			shouldFail:      true,
		},
		{
			name:            "accept valid tenants",
			contextTenant:   validTenant,
			requestedTenant: validTenant,
			shouldFail:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()

			if tt.contextTenant != uuid.Nil {
				ctx = SetAuthenticatedTenant(ctx, tt.contextTenant)
			}

			err := client.ValidateTenantContext(ctx, tt.requestedTenant)

			if tt.shouldFail {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}
