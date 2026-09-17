// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dogukanturhal/falcon-id/pkg/config"
)

// ---------------------------------------------------------------------------
// ReconcileStats — struct fields
// ---------------------------------------------------------------------------

func TestReconcileStats_DefaultValues(t *testing.T) {
	stats := ReconcileStats{}

	assert.Equal(t, 0, stats.TenantsProcessed)
	assert.Equal(t, 0, stats.UserTenantRepairs)
	assert.Equal(t, 0, stats.UserRoleRepairs)
	assert.Equal(t, 0, stats.RolePermissionRepairs)
	assert.Equal(t, 0, stats.Errors)
	assert.True(t, stats.StartedAt.IsZero())
	assert.True(t, stats.CompletedAt.IsZero())
}

// ---------------------------------------------------------------------------
// NewSpiceDBReconciler
// ---------------------------------------------------------------------------

func TestNewSpiceDBReconciler_NilDeps(t *testing.T) {
	cfg := &config.Config{}
	reconciler := NewSpiceDBReconciler(nil, nil, cfg)

	require.NotNil(t, reconciler)
	assert.NotNil(t, reconciler.stopChan)
}

// ---------------------------------------------------------------------------
// Stats — thread-safe access
// ---------------------------------------------------------------------------

func TestSpiceDBReconciler_Stats_ReturnsDefault(t *testing.T) {
	cfg := &config.Config{}
	reconciler := NewSpiceDBReconciler(nil, nil, cfg)

	stats := reconciler.Stats()
	assert.Equal(t, 0, stats.TenantsProcessed)
	assert.Equal(t, 0, stats.Errors)
}

func TestSpiceDBReconciler_Stats_ReturnsLastRun(t *testing.T) {
	cfg := &config.Config{}
	reconciler := NewSpiceDBReconciler(nil, nil, cfg)

	// Simulate a completed run
	now := time.Now()
	reconciler.mu.Lock()
	reconciler.lastRunStats = ReconcileStats{
		TenantsProcessed:      5,
		UserTenantRepairs:     3,
		UserRoleRepairs:       2,
		RolePermissionRepairs: 10,
		Errors:                1,
		StartedAt:             now.Add(-time.Minute),
		CompletedAt:           now,
	}
	reconciler.mu.Unlock()

	stats := reconciler.Stats()
	assert.Equal(t, 5, stats.TenantsProcessed)
	assert.Equal(t, 3, stats.UserTenantRepairs)
	assert.Equal(t, 2, stats.UserRoleRepairs)
	assert.Equal(t, 10, stats.RolePermissionRepairs)
	assert.Equal(t, 1, stats.Errors)
}

// ---------------------------------------------------------------------------
// StartScheduler — disabled by config
// ---------------------------------------------------------------------------

func TestSpiceDBReconciler_StartScheduler_Disabled(_ *testing.T) {
	cfg := &config.Config{SpiceDBReconcilerEnabled: false}
	reconciler := NewSpiceDBReconciler(nil, nil, cfg)

	// StartScheduler should be a no-op when disabled
	reconciler.StartScheduler(context.TODO())

	// StopScheduler should also be safe to call
	reconciler.StopScheduler()
}

// ---------------------------------------------------------------------------
// StopScheduler — safe to call multiple times
// ---------------------------------------------------------------------------

func TestSpiceDBReconciler_StopScheduler_MultipleCallsSafe(_ *testing.T) {
	cfg := &config.Config{SpiceDBReconcilerEnabled: false}
	reconciler := NewSpiceDBReconciler(nil, nil, cfg)

	// Multiple StopScheduler calls should not panic
	reconciler.StopScheduler()
	reconciler.StopScheduler()
	reconciler.StopScheduler()
}

func TestSpiceDBReconciler_StopScheduler_CancelsEnabledScheduler(t *testing.T) {
	cfg := &config.Config{SpiceDBReconcilerEnabled: true, SpiceDBReconcilerInterval: time.Hour}
	reconciler := NewSpiceDBReconciler(nil, nil, cfg)
	reconciler.StartScheduler(context.Background())

	stopped := make(chan struct{})
	go func() {
		reconciler.StopScheduler()
		close(stopped)
	}()

	select {
	case <-stopped:
	case <-time.After(time.Second):
		t.Fatal("enabled reconciler did not stop promptly")
	}
}

// ---------------------------------------------------------------------------
// Reconcile — nil DB returns error
// ---------------------------------------------------------------------------

func TestSpiceDBReconciler_Reconcile_NilDB_ReturnsError(t *testing.T) {
	cfg := &config.Config{}
	reconciler := NewSpiceDBReconciler(nil, nil, cfg)

	// Reconcile needs a DB pool to query tenants
	stats, err := reconciler.Reconcile(t.Context())

	assert.Error(t, err)
	assert.Nil(t, stats)
}

// ---------------------------------------------------------------------------
// parsePermissionName
// ---------------------------------------------------------------------------

func TestParsePermissionName_AccessGrantPattern(t *testing.T) {
	roleID := uuid.New()

	tests := []struct {
		name         string
		permName     string
		wantObjType  string
		wantObjID    string
		wantRelation string
	}{
		{
			name:         "colon format: crm:contacts:read",
			permName:     "crm:contacts:read",
			wantObjType:  "access_grant",
			wantObjID:    "crm__contacts__read",
			wantRelation: "granted_to_role",
		},
		{
			name:         "colon format: iam:users:manage",
			permName:     "iam:users:manage",
			wantObjType:  "access_grant",
			wantObjID:    "iam__users__manage",
			wantRelation: "granted_to_role",
		},
		{
			name:         "dot format: invoice.view (passthrough, no colons)",
			permName:     "invoice.view",
			wantObjType:  "access_grant",
			wantObjID:    "invoice.view",
			wantRelation: "granted_to_role",
		},
		{
			name:         "dot format: user.manage",
			permName:     "user.manage",
			wantObjType:  "access_grant",
			wantObjID:    "user.manage",
			wantRelation: "granted_to_role",
		},
		{
			name:         "no separator: billing",
			permName:     "billing",
			wantObjType:  "access_grant",
			wantObjID:    "billing",
			wantRelation: "granted_to_role",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			objType, objID, relation, err := parsePermissionName(tc.permName, roleID)

			require.NoError(t, err)
			assert.Equal(t, tc.wantObjType, objType)
			assert.Equal(t, tc.wantObjID, objID)
			assert.Equal(t, tc.wantRelation, relation)
		})
	}
}

func TestParsePermissionName_Empty_ReturnsError(t *testing.T) {
	roleID := uuid.New()

	_, _, _, err := parsePermissionName("", roleID)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "empty permission name")
}
