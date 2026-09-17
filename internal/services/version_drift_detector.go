// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"

	"github.com/google/uuid"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

// driftInstanceRepo abstracts the product instance queries needed for drift detection.
type driftInstanceRepo interface {
	ListActiveByProduct(ctx context.Context, productID uuid.UUID) ([]models.ProductInstance, error)
	ListAllActive(ctx context.Context) ([]models.ProductInstance, error)
}

// DriftedInstance describes a single instance that is behind the expected version.
type DriftedInstance struct {
	InstanceID      uuid.UUID `json:"instance_id"`
	CurrentVersion  int       `json:"current_version"`
	ExpectedVersion int       `json:"expected_version"`
}

// DriftReport summarises version drift for a single product.
type DriftReport struct {
	ProductID        uuid.UUID         `json:"product_id"`
	HasDrift         bool              `json:"has_drift"`
	MaxVersion       int               `json:"max_version"`
	MinVersion       int               `json:"min_version"`
	TotalInstances   int               `json:"total_instances"`
	DriftedInstances []DriftedInstance `json:"drifted_instances,omitempty"`
}

// VersionDriftDetector detects migration version drift across product instances.
type VersionDriftDetector struct {
	repo driftInstanceRepo
}

// NewVersionDriftDetector creates a new drift detector.
func NewVersionDriftDetector(repo driftInstanceRepo) *VersionDriftDetector {
	return &VersionDriftDetector{repo: repo}
}

// DetectDrift checks for version drift among active instances of a single product.
func (d *VersionDriftDetector) DetectDrift(ctx context.Context, productID uuid.UUID) (*DriftReport, error) {
	instances, err := d.repo.ListActiveByProduct(ctx, productID)
	if err != nil {
		return nil, err
	}

	report := buildDriftReport(productID, instances)
	return &report, nil
}

// DetectAllDrift checks for version drift across all products.
func (d *VersionDriftDetector) DetectAllDrift(ctx context.Context) ([]DriftReport, error) {
	all, err := d.repo.ListAllActive(ctx)
	if err != nil {
		return nil, err
	}

	// Group by product.
	grouped := make(map[uuid.UUID][]models.ProductInstance)
	for _, pi := range all {
		grouped[pi.ProductID] = append(grouped[pi.ProductID], pi)
	}

	reports := make([]DriftReport, 0, len(grouped))
	for productID, instances := range grouped {
		reports = append(reports, buildDriftReport(productID, instances))
	}
	return reports, nil
}

// buildDriftReport builds a drift report from a list of active instances for one product.
func buildDriftReport(productID uuid.UUID, instances []models.ProductInstance) DriftReport {
	report := DriftReport{
		ProductID:      productID,
		TotalInstances: len(instances),
	}

	if len(instances) == 0 {
		return report
	}

	// Find max and min versions.
	maxV := instances[0].LastMigrationVersion
	minV := instances[0].LastMigrationVersion
	for _, pi := range instances[1:] {
		if pi.LastMigrationVersion > maxV {
			maxV = pi.LastMigrationVersion
		}
		if pi.LastMigrationVersion < minV {
			minV = pi.LastMigrationVersion
		}
	}

	report.MaxVersion = maxV
	report.MinVersion = minV
	report.HasDrift = maxV != minV

	if report.HasDrift {
		for _, pi := range instances {
			if pi.LastMigrationVersion < maxV {
				report.DriftedInstances = append(report.DriftedInstances, DriftedInstance{
					InstanceID:      pi.ID,
					CurrentVersion:  pi.LastMigrationVersion,
					ExpectedVersion: maxV,
				})
			}
		}
	}

	return report
}
