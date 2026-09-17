// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

// ---------------------------------------------------------------------------
// BootstrapTenant — nil client
// ---------------------------------------------------------------------------

func TestBootstrapTenant_NilClient_ReturnsError(t *testing.T) {
	svc := NewTenantBootstrapService(nil)

	result, err := svc.BootstrapTenant(context.Background(), uuid.New(), uuid.New())

	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "SpiceDB client not initialized")
}

// ---------------------------------------------------------------------------
// BootstrapUserMembership — nil client
// ---------------------------------------------------------------------------

func TestBootstrapUserMembership_NilClient_ReturnsError(t *testing.T) {
	svc := NewTenantBootstrapService(nil)

	token, err := svc.BootstrapUserMembership(context.Background(), uuid.New(), uuid.New(), false)

	assert.Error(t, err)
	assert.Equal(t, "", token)
	assert.Contains(t, err.Error(), "SpiceDB client not initialized")
}

func TestBootstrapUserMembership_NilClient_Admin_ReturnsError(t *testing.T) {
	svc := NewTenantBootstrapService(nil)

	token, err := svc.BootstrapUserMembership(context.Background(), uuid.New(), uuid.New(), true)

	assert.Error(t, err)
	assert.Equal(t, "", token)
}

// ---------------------------------------------------------------------------
// BootstrapRolePermissions — nil client
// ---------------------------------------------------------------------------

func TestBootstrapRolePermissions_NilClient_ReturnsError(t *testing.T) {
	svc := NewTenantBootstrapService(nil)

	result, err := svc.BootstrapRolePermissions(context.Background(), uuid.New(), uuid.New(), []string{"crm:contacts:read"})

	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "SpiceDB client not initialized")
}

// ---------------------------------------------------------------------------
// BootstrapUserRole — nil client
// ---------------------------------------------------------------------------

func TestBootstrapUserRole_NilClient_ReturnsError(t *testing.T) {
	svc := NewTenantBootstrapService(nil)

	token, err := svc.BootstrapUserRole(context.Background(), uuid.New(), uuid.New(), uuid.New())

	assert.Error(t, err)
	assert.Equal(t, "", token)
	assert.Contains(t, err.Error(), "SpiceDB client not initialized")
}

func TestSyncUserRoles_NilClient_ReturnsError(t *testing.T) {
	svc := NewTenantBootstrapService(nil)

	err := svc.SyncUserRoles(context.Background(), uuid.New(), uuid.New(), []uuid.UUID{uuid.New()})

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "SpiceDB client not initialized")
}

func TestSyncUserAccess_NilClient_ReturnsError(t *testing.T) {
	svc := NewTenantBootstrapService(nil)

	err := svc.SyncUserAccess(context.Background(), uuid.New(), uuid.New(), false, false, nil)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "SpiceDB client not initialized")
}

// ---------------------------------------------------------------------------
// BootstrapResult struct
// ---------------------------------------------------------------------------

func TestBootstrapResult_Fields(t *testing.T) {
	tenantID := uuid.New()
	result := &BootstrapResult{
		TenantID:             tenantID,
		RelationshipsWritten: 3,
		LastZedToken:         "zed-token-abc",
		Errors:               nil,
	}

	assert.Equal(t, tenantID, result.TenantID)
	assert.Equal(t, 3, result.RelationshipsWritten)
	assert.Equal(t, "zed-token-abc", result.LastZedToken)
	assert.Empty(t, result.Errors)
}
