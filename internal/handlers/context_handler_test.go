// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func TestAvailableContext(t *testing.T) {
	// Test AvailableContext struct initialization
	tenantID := uuid.New()
	realmID := uuid.New()

	ctx := AvailableContext{
		TenantID:   tenantID,
		TenantSlug: "test-tenant",
		TenantName: "Test Tenant",
		RealmID:    realmID,
		RealmSlug:  "test-realm",
		RealmName:  "Test Realm",
		RealmType:  "enterprise",
		Roles:      []string{"admin", "user"},
		IsCurrent:  true,
	}

	assert.Equal(t, tenantID, ctx.TenantID)
	assert.Equal(t, "test-tenant", ctx.TenantSlug)
	assert.Equal(t, "Test Tenant", ctx.TenantName)
	assert.Equal(t, realmID, ctx.RealmID)
	assert.Equal(t, "test-realm", ctx.RealmSlug)
	assert.Equal(t, "Test Realm", ctx.RealmName)
	assert.Equal(t, "enterprise", ctx.RealmType)
	assert.Equal(t, []string{"admin", "user"}, ctx.Roles)
	assert.True(t, ctx.IsCurrent)
}

func TestSwitchContextRequest(t *testing.T) {
	// Test SwitchContextRequest validation
	tenantID := uuid.New()
	realmID := uuid.New()

	req := SwitchContextRequest{
		TenantID: tenantID,
		RealmID:  realmID,
	}

	assert.Equal(t, tenantID, req.TenantID)
	assert.Equal(t, realmID, req.RealmID)
}

func TestUserContext(t *testing.T) {
	// Test UserContext struct
	tenantID := uuid.New()
	realmID := uuid.New()

	uc := UserContext{
		TenantID:   tenantID,
		TenantSlug: "acme",
		TenantName: "ACME Corp",
		RealmID:    realmID,
		RealmSlug:  "production",
		RealmName:  "Production Realm",
		RealmType:  "enterprise",
		Roles:      []string{"admin"},
	}

	assert.Equal(t, tenantID, uc.TenantID)
	assert.Equal(t, "acme", uc.TenantSlug)
	assert.Equal(t, "ACME Corp", uc.TenantName)
	assert.Equal(t, realmID, uc.RealmID)
	assert.Equal(t, "production", uc.RealmSlug)
	assert.Equal(t, "Production Realm", uc.RealmName)
	assert.Equal(t, "enterprise", uc.RealmType)
	assert.Len(t, uc.Roles, 1)
	assert.Contains(t, uc.Roles, "admin")
}

func TestSessionContextUpdate(t *testing.T) {
	// Test SessionContextUpdate struct
	tenantID := uuid.New()
	realmID := uuid.New()

	update := SessionContextUpdate{
		TenantID:    tenantID,
		RealmID:     realmID,
		Roles:       []string{"user", "manager"},
		Permissions: []string{"read:users", "write:users"},
	}

	assert.Equal(t, tenantID, update.TenantID)
	assert.Equal(t, realmID, update.RealmID)
	assert.Len(t, update.Roles, 2)
	assert.Contains(t, update.Roles, "user")
	assert.Contains(t, update.Roles, "manager")
	assert.Len(t, update.Permissions, 2)
	assert.Contains(t, update.Permissions, "read:users")
	assert.Contains(t, update.Permissions, "write:users")
}
