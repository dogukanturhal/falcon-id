// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

// ---------------------------------------------------------------------------
// SyncUserRoleAssignment — returns (string, error)
// ---------------------------------------------------------------------------

func TestSyncUserRoleAssignment_NilClient_ReturnsError(t *testing.T) {
	svc := &SpiceDBSyncService{client: nil}

	token, err := svc.SyncUserRoleAssignment(context.Background(), uuid.New(), uuid.New(), uuid.New())

	assert.Error(t, err)
	assert.Equal(t, "", token)
	assert.Contains(t, err.Error(), "SpiceDB client not initialized")
}

// ---------------------------------------------------------------------------
// SyncUserRoleRemoval — returns (string, error)
// ---------------------------------------------------------------------------

func TestSyncUserRoleRemoval_NilClient_ReturnsError(t *testing.T) {
	svc := &SpiceDBSyncService{client: nil}

	token, err := svc.SyncUserRoleRemoval(context.Background(), uuid.New(), uuid.New(), uuid.New())

	assert.Error(t, err)
	assert.Equal(t, "", token)
	assert.Contains(t, err.Error(), "SpiceDB client not initialized")
}

// ---------------------------------------------------------------------------
// SyncUserTenantMembership — returns (string, error)
// ---------------------------------------------------------------------------

func TestSyncUserTenantMembership_NilClient_ReturnsError(t *testing.T) {
	svc := &SpiceDBSyncService{client: nil}

	token, err := svc.SyncUserTenantMembership(context.Background(), uuid.New(), uuid.New(), false)

	assert.Error(t, err)
	assert.Equal(t, "", token)
	assert.Contains(t, err.Error(), "SpiceDB client not initialized")
}

func TestSyncUserTenantMembership_NilClient_AdminRelation_ReturnsError(t *testing.T) {
	svc := &SpiceDBSyncService{client: nil}

	token, err := svc.SyncUserTenantMembership(context.Background(), uuid.New(), uuid.New(), true)

	assert.Error(t, err)
	assert.Equal(t, "", token)
	assert.Contains(t, err.Error(), "SpiceDB client not initialized")
}

// ---------------------------------------------------------------------------
// Metrics & Health
// ---------------------------------------------------------------------------

func TestSpiceDBSyncService_Metrics_DefaultValues(t *testing.T) {
	svc := &SpiceDBSyncService{
		writeQueue: make(chan *syncOperation, 100),
	}

	metrics := svc.Metrics()
	assert.Equal(t, int64(0), metrics.SyncCount)
	assert.Equal(t, int64(0), metrics.ErrorCount)
	assert.Equal(t, 0, metrics.QueueSize)
}

func TestSpiceDBSyncService_IsHealthy_InitiallyHealthy(t *testing.T) {
	svc := &SpiceDBSyncService{
		writeQueue: make(chan *syncOperation, 100),
	}

	assert.True(t, svc.IsHealthy())
}
