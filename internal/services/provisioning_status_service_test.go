// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

// ── Mock implementations ────────────────────────────────────────────────────

type mockProvisioningStatusInstanceRepo struct {
	instances []models.ProductInstance
}

func (m *mockProvisioningStatusInstanceRepo) ListByTenantAll(_ context.Context, tenantID uuid.UUID) ([]models.ProductInstance, error) {
	var result []models.ProductInstance
	for _, pi := range m.instances {
		if pi.TenantID == tenantID && pi.ProvisioningState != models.ProvisioningStateDeleted {
			result = append(result, pi)
		}
	}
	return result, nil
}

type mockProvisioningStatusDBRepo struct {
	databases map[uuid.UUID][]models.InstanceDatabase
}

func (m *mockProvisioningStatusDBRepo) ListByInstance(_ context.Context, instanceID uuid.UUID) ([]models.InstanceDatabase, error) {
	return m.databases[instanceID], nil
}

// ── Tests ───────────────────────────────────────────────────────────────────

func TestProvisioningStatusService_ActiveTenant(t *testing.T) {
	tenantID := uuid.New()
	instanceID := uuid.New()
	instanceRepo := &mockProvisioningStatusInstanceRepo{
		instances: []models.ProductInstance{
			{ID: instanceID, TenantID: tenantID, ProductID: uuid.New(), ProvisioningState: models.ProvisioningStateActive},
		},
	}
	dbRepo := &mockProvisioningStatusDBRepo{
		databases: map[uuid.UUID][]models.InstanceDatabase{
			instanceID: {
				{ID: uuid.New(), InstanceID: instanceID, Status: models.InstanceDBStatusActive},
				{ID: uuid.New(), InstanceID: instanceID, Status: models.InstanceDBStatusActive},
			},
		},
	}

	svc := NewProvisioningStatusService(instanceRepo, dbRepo)
	status, err := svc.GetStatus(context.Background(), tenantID)
	require.NoError(t, err)

	assert.Equal(t, tenantID, status.TenantID)
	assert.Equal(t, "active", status.State)
	assert.False(t, status.IsSuspended)
	assert.False(t, status.IsDeleting)
	// No database_progress for active state
	assert.Nil(t, status.DatabaseProgress)
}

func TestProvisioningStatusService_ProvisioningInProgress(t *testing.T) {
	tenantID := uuid.New()
	instanceID := uuid.New()
	instanceRepo := &mockProvisioningStatusInstanceRepo{
		instances: []models.ProductInstance{
			{ID: instanceID, TenantID: tenantID, ProductID: uuid.New(), ProvisioningState: models.ProvisioningStateCreating},
		},
	}
	dbRepo := &mockProvisioningStatusDBRepo{
		databases: map[uuid.UUID][]models.InstanceDatabase{
			instanceID: {
				{ID: uuid.New(), InstanceID: instanceID, DatabaseName: "hexxlock_crm", Status: models.InstanceDBStatusActive},
				{ID: uuid.New(), InstanceID: instanceID, DatabaseName: "hexxlock_hr", Status: models.InstanceDBStatusActive},
				{ID: uuid.New(), InstanceID: instanceID, DatabaseName: "hexxlock_finance", Status: models.InstanceDBStatusCreating},
				{ID: uuid.New(), InstanceID: instanceID, DatabaseName: "hexxlock_pm", Status: models.InstanceDBStatusPending},
			},
		},
	}

	svc := NewProvisioningStatusService(instanceRepo, dbRepo)
	status, err := svc.GetStatus(context.Background(), tenantID)
	require.NoError(t, err)

	assert.Equal(t, "provisioning", status.State)
	require.NotNil(t, status.DatabaseProgress)
	assert.Equal(t, 4, status.DatabaseProgress.Total)
	assert.Equal(t, 2, status.DatabaseProgress.Completed)
	assert.Equal(t, "hexxlock_finance", *status.DatabaseProgress.CurrentDatabase)
}

func TestProvisioningStatusService_MigratingState(t *testing.T) {
	tenantID := uuid.New()
	instanceID := uuid.New()
	instanceRepo := &mockProvisioningStatusInstanceRepo{
		instances: []models.ProductInstance{
			{ID: instanceID, TenantID: tenantID, ProductID: uuid.New(), ProvisioningState: models.ProvisioningStateMigrating},
		},
	}
	dbRepo := &mockProvisioningStatusDBRepo{
		databases: map[uuid.UUID][]models.InstanceDatabase{
			instanceID: {
				{ID: uuid.New(), InstanceID: instanceID, DatabaseName: "hexxlock_crm", Status: models.InstanceDBStatusActive},
				{ID: uuid.New(), InstanceID: instanceID, DatabaseName: "hexxlock_hr", Status: models.InstanceDBStatusMigrating},
			},
		},
	}

	svc := NewProvisioningStatusService(instanceRepo, dbRepo)
	status, err := svc.GetStatus(context.Background(), tenantID)
	require.NoError(t, err)

	assert.Equal(t, "migrating", status.State)
	require.NotNil(t, status.DatabaseProgress)
	assert.Equal(t, 2, status.DatabaseProgress.Total)
	assert.Equal(t, 1, status.DatabaseProgress.Completed)
	assert.Equal(t, "hexxlock_hr", *status.DatabaseProgress.CurrentDatabase)
}

func TestProvisioningStatusService_FailedState(t *testing.T) {
	tenantID := uuid.New()
	reason := "schema_conflict"
	instanceRepo := &mockProvisioningStatusInstanceRepo{
		instances: []models.ProductInstance{
			{ID: uuid.New(), TenantID: tenantID, ProductID: uuid.New(), ProvisioningState: models.ProvisioningStateFailed, FailureReason: &reason},
		},
	}
	dbRepo := &mockProvisioningStatusDBRepo{databases: map[uuid.UUID][]models.InstanceDatabase{}}

	svc := NewProvisioningStatusService(instanceRepo, dbRepo)
	status, err := svc.GetStatus(context.Background(), tenantID)
	require.NoError(t, err)

	assert.Equal(t, "failed", status.State)
	assert.Nil(t, status.DatabaseProgress)
}

func TestProvisioningStatusService_DeletingState(t *testing.T) {
	tenantID := uuid.New()
	instanceRepo := &mockProvisioningStatusInstanceRepo{
		instances: []models.ProductInstance{
			{ID: uuid.New(), TenantID: tenantID, ProductID: uuid.New(), ProvisioningState: models.ProvisioningStateDeleting},
		},
	}
	dbRepo := &mockProvisioningStatusDBRepo{databases: map[uuid.UUID][]models.InstanceDatabase{}}

	svc := NewProvisioningStatusService(instanceRepo, dbRepo)
	status, err := svc.GetStatus(context.Background(), tenantID)
	require.NoError(t, err)

	assert.Equal(t, "deleting", status.State)
	assert.True(t, status.IsDeleting)
}

func TestProvisioningStatusService_NoInstances(t *testing.T) {
	tenantID := uuid.New()
	instanceRepo := &mockProvisioningStatusInstanceRepo{instances: nil}
	dbRepo := &mockProvisioningStatusDBRepo{databases: map[uuid.UUID][]models.InstanceDatabase{}}

	svc := NewProvisioningStatusService(instanceRepo, dbRepo)
	status, err := svc.GetStatus(context.Background(), tenantID)
	require.NoError(t, err)

	assert.Equal(t, tenantID, status.TenantID)
	assert.Equal(t, "pending", status.State)
	assert.Nil(t, status.DatabaseProgress)
}

func TestProvisioningStatusService_NoDatabases_StillShowsProgress(t *testing.T) {
	tenantID := uuid.New()
	instanceID := uuid.New()
	instanceRepo := &mockProvisioningStatusInstanceRepo{
		instances: []models.ProductInstance{
			{ID: instanceID, TenantID: tenantID, ProductID: uuid.New(), ProvisioningState: models.ProvisioningStateCreating},
		},
	}
	// Instance is creating but no instance_databases created yet
	dbRepo := &mockProvisioningStatusDBRepo{databases: map[uuid.UUID][]models.InstanceDatabase{}}

	svc := NewProvisioningStatusService(instanceRepo, dbRepo)
	status, err := svc.GetStatus(context.Background(), tenantID)
	require.NoError(t, err)

	assert.Equal(t, "provisioning", status.State)
	// No database_progress when no DBs exist yet (still early in provisioning)
	assert.Nil(t, status.DatabaseProgress)
}

func TestProvisioningStatusService_MultipleInstances_PicksNonTerminal(t *testing.T) {
	tenantID := uuid.New()
	instanceID := uuid.New()
	instanceRepo := &mockProvisioningStatusInstanceRepo{
		instances: []models.ProductInstance{
			{ID: uuid.New(), TenantID: tenantID, ProductID: uuid.New(), ProvisioningState: models.ProvisioningStateActive},
			{ID: instanceID, TenantID: tenantID, ProductID: uuid.New(), ProvisioningState: models.ProvisioningStateCreating},
		},
	}
	dbRepo := &mockProvisioningStatusDBRepo{
		databases: map[uuid.UUID][]models.InstanceDatabase{
			instanceID: {
				{ID: uuid.New(), InstanceID: instanceID, DatabaseName: "hexxlock_crm", Status: models.InstanceDBStatusCreating},
			},
		},
	}

	svc := NewProvisioningStatusService(instanceRepo, dbRepo)
	status, err := svc.GetStatus(context.Background(), tenantID)
	require.NoError(t, err)

	// Should report provisioning because one instance is still in progress
	assert.Equal(t, "provisioning", status.State)
	require.NotNil(t, status.DatabaseProgress)
}
