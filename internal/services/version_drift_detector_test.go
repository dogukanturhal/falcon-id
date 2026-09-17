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

type mockDriftInstanceRepo struct {
	instances []models.ProductInstance
}

func (m *mockDriftInstanceRepo) ListActiveByProduct(_ context.Context, productID uuid.UUID) ([]models.ProductInstance, error) {
	var result []models.ProductInstance
	for _, pi := range m.instances {
		if pi.ProductID == productID && pi.ProvisioningState == models.ProvisioningStateActive {
			result = append(result, pi)
		}
	}
	return result, nil
}

func (m *mockDriftInstanceRepo) ListAllActive(_ context.Context) ([]models.ProductInstance, error) {
	var result []models.ProductInstance
	for _, pi := range m.instances {
		if pi.ProvisioningState == models.ProvisioningStateActive {
			result = append(result, pi)
		}
	}
	return result, nil
}

// ── Tests ───────────────────────────────────────────────────────────────────

func TestVersionDriftDetector_NoDrift(t *testing.T) {
	productID := uuid.New()
	repo := &mockDriftInstanceRepo{
		instances: []models.ProductInstance{
			{ID: uuid.New(), ProductID: productID, ProvisioningState: models.ProvisioningStateActive, LastMigrationVersion: 10},
			{ID: uuid.New(), ProductID: productID, ProvisioningState: models.ProvisioningStateActive, LastMigrationVersion: 10},
			{ID: uuid.New(), ProductID: productID, ProvisioningState: models.ProvisioningStateActive, LastMigrationVersion: 10},
		},
	}

	detector := NewVersionDriftDetector(repo)

	report, err := detector.DetectDrift(context.Background(), productID)
	require.NoError(t, err)
	assert.False(t, report.HasDrift)
	assert.Equal(t, 10, report.MaxVersion)
	assert.Equal(t, 10, report.MinVersion)
	assert.Empty(t, report.DriftedInstances)
}

func TestVersionDriftDetector_WithDrift(t *testing.T) {
	productID := uuid.New()
	driftedID := uuid.New()
	repo := &mockDriftInstanceRepo{
		instances: []models.ProductInstance{
			{ID: uuid.New(), ProductID: productID, ProvisioningState: models.ProvisioningStateActive, LastMigrationVersion: 10},
			{ID: uuid.New(), ProductID: productID, ProvisioningState: models.ProvisioningStateActive, LastMigrationVersion: 10},
			{ID: driftedID, ProductID: productID, ProvisioningState: models.ProvisioningStateActive, LastMigrationVersion: 8},
		},
	}

	detector := NewVersionDriftDetector(repo)

	report, err := detector.DetectDrift(context.Background(), productID)
	require.NoError(t, err)
	assert.True(t, report.HasDrift)
	assert.Equal(t, 10, report.MaxVersion)
	assert.Equal(t, 8, report.MinVersion)
	assert.Len(t, report.DriftedInstances, 1)
	assert.Equal(t, driftedID, report.DriftedInstances[0].InstanceID)
	assert.Equal(t, 8, report.DriftedInstances[0].CurrentVersion)
	assert.Equal(t, 10, report.DriftedInstances[0].ExpectedVersion)
}

func TestVersionDriftDetector_SingleInstance_NoDrift(t *testing.T) {
	productID := uuid.New()
	repo := &mockDriftInstanceRepo{
		instances: []models.ProductInstance{
			{ID: uuid.New(), ProductID: productID, ProvisioningState: models.ProvisioningStateActive, LastMigrationVersion: 5},
		},
	}

	detector := NewVersionDriftDetector(repo)

	report, err := detector.DetectDrift(context.Background(), productID)
	require.NoError(t, err)
	assert.False(t, report.HasDrift)
}

func TestVersionDriftDetector_NoInstances(t *testing.T) {
	repo := &mockDriftInstanceRepo{instances: nil}
	detector := NewVersionDriftDetector(repo)

	report, err := detector.DetectDrift(context.Background(), uuid.New())
	require.NoError(t, err)
	assert.False(t, report.HasDrift)
	assert.Equal(t, 0, report.TotalInstances)
}

func TestVersionDriftDetector_IgnoresNonActive(t *testing.T) {
	productID := uuid.New()
	repo := &mockDriftInstanceRepo{
		instances: []models.ProductInstance{
			{ID: uuid.New(), ProductID: productID, ProvisioningState: models.ProvisioningStateActive, LastMigrationVersion: 10},
			{ID: uuid.New(), ProductID: productID, ProvisioningState: models.ProvisioningStateFailed, LastMigrationVersion: 5},
			{ID: uuid.New(), ProductID: productID, ProvisioningState: models.ProvisioningStateMigrating, LastMigrationVersion: 7},
		},
	}

	detector := NewVersionDriftDetector(repo)

	report, err := detector.DetectDrift(context.Background(), productID)
	require.NoError(t, err)
	assert.False(t, report.HasDrift, "should only consider active instances")
	assert.Equal(t, 1, report.TotalInstances)
}

func TestVersionDriftDetector_DetectAllDrift(t *testing.T) {
	productA := uuid.New()
	productB := uuid.New()
	repo := &mockDriftInstanceRepo{
		instances: []models.ProductInstance{
			{ID: uuid.New(), ProductID: productA, ProvisioningState: models.ProvisioningStateActive, LastMigrationVersion: 10},
			{ID: uuid.New(), ProductID: productA, ProvisioningState: models.ProvisioningStateActive, LastMigrationVersion: 8},
			{ID: uuid.New(), ProductID: productB, ProvisioningState: models.ProvisioningStateActive, LastMigrationVersion: 5},
			{ID: uuid.New(), ProductID: productB, ProvisioningState: models.ProvisioningStateActive, LastMigrationVersion: 5},
		},
	}

	detector := NewVersionDriftDetector(repo)

	reports, err := detector.DetectAllDrift(context.Background())
	require.NoError(t, err)
	require.Len(t, reports, 2)

	// Find the one with drift.
	var drifted *DriftReport
	for i := range reports {
		if reports[i].HasDrift {
			drifted = &reports[i]
		}
	}
	require.NotNil(t, drifted, "should have one product with drift")
	assert.Equal(t, productA, drifted.ProductID)
}

func TestVersionDriftDetector_MultipleDriftedInstances(t *testing.T) {
	productID := uuid.New()
	repo := &mockDriftInstanceRepo{
		instances: []models.ProductInstance{
			{ID: uuid.New(), ProductID: productID, ProvisioningState: models.ProvisioningStateActive, LastMigrationVersion: 10},
			{ID: uuid.New(), ProductID: productID, ProvisioningState: models.ProvisioningStateActive, LastMigrationVersion: 8},
			{ID: uuid.New(), ProductID: productID, ProvisioningState: models.ProvisioningStateActive, LastMigrationVersion: 6},
		},
	}

	detector := NewVersionDriftDetector(repo)

	report, err := detector.DetectDrift(context.Background(), productID)
	require.NoError(t, err)
	assert.True(t, report.HasDrift)
	assert.Len(t, report.DriftedInstances, 2, "two instances are behind max version")
	assert.Equal(t, 10, report.MaxVersion)
	assert.Equal(t, 6, report.MinVersion)
}
