// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"

	"github.com/google/uuid"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

// provisioningStatusInstanceRepo abstracts instance queries for the status service.
type provisioningStatusInstanceRepo interface {
	ListByTenantAll(ctx context.Context, tenantID uuid.UUID) ([]models.ProductInstance, error)
}

// provisioningStatusDBRepo abstracts instance database queries for the status service.
type provisioningStatusDBRepo interface {
	ListByInstance(ctx context.Context, instanceID uuid.UUID) ([]models.InstanceDatabase, error)
}

// DatabaseProgress tracks multi-DB provisioning progress.
type DatabaseProgress struct {
	Total           int     `json:"total"`
	Completed       int     `json:"completed"`
	CurrentDatabase *string `json:"current_database,omitempty"`
}

// TenantProvisioningStatus is the response returned to the unified dashboard.
type TenantProvisioningStatus struct {
	TenantID         uuid.UUID         `json:"tenant_id"`
	State            string            `json:"state"`
	IsSuspended      bool              `json:"is_suspended"`
	IsDeleting       bool              `json:"is_deleting"`
	ComplianceHolds  []interface{}     `json:"compliance_holds"`
	DatabaseProgress *DatabaseProgress `json:"database_progress,omitempty"`
}

// ProvisioningStatusService computes tenant provisioning status from product instances
// and their associated instance databases.
type ProvisioningStatusService struct {
	instanceRepo provisioningStatusInstanceRepo
	dbRepo       provisioningStatusDBRepo
}

// NewProvisioningStatusService creates a new provisioning status service.
func NewProvisioningStatusService(
	instanceRepo provisioningStatusInstanceRepo,
	dbRepo provisioningStatusDBRepo,
) *ProvisioningStatusService {
	return &ProvisioningStatusService{
		instanceRepo: instanceRepo,
		dbRepo:       dbRepo,
	}
}

// GetStatus returns the provisioning status for a tenant.
func (s *ProvisioningStatusService) GetStatus(ctx context.Context, tenantID uuid.UUID) (*TenantProvisioningStatus, error) {
	instances, err := s.instanceRepo.ListByTenantAll(ctx, tenantID)
	if err != nil {
		return nil, err
	}

	status := &TenantProvisioningStatus{
		TenantID:        tenantID,
		State:           "pending",
		ComplianceHolds: []interface{}{},
	}

	if len(instances) == 0 {
		return status, nil
	}

	// Find the most relevant instance: prefer non-terminal states over terminal ones.
	var primary *models.ProductInstance
	for i := range instances {
		pi := &instances[i]
		if !pi.ProvisioningState.IsTerminal() {
			primary = pi
			break
		}
		if primary == nil {
			primary = pi
		}
	}

	// Map provisioning state to frontend state.
	status.State = mapProvisioningState(primary.ProvisioningState)
	status.IsDeleting = primary.ProvisioningState == models.ProvisioningStateDeleting

	// Populate database progress for transitional states.
	if isTransitionalState(primary.ProvisioningState) {
		progress, err := s.computeDatabaseProgress(ctx, primary.ID)
		if err == nil && progress != nil {
			status.DatabaseProgress = progress
		}
	}

	return status, nil
}

// computeDatabaseProgress counts active vs total databases for an instance.
func (s *ProvisioningStatusService) computeDatabaseProgress(ctx context.Context, instanceID uuid.UUID) (*DatabaseProgress, error) {
	dbs, err := s.dbRepo.ListByInstance(ctx, instanceID)
	if err != nil {
		return nil, err
	}

	if len(dbs) == 0 {
		return nil, nil
	}

	progress := &DatabaseProgress{
		Total: len(dbs),
	}

	for _, db := range dbs {
		switch db.Status {
		case models.InstanceDBStatusActive:
			progress.Completed++
		case models.InstanceDBStatusCreating, models.InstanceDBStatusMigrating:
			if progress.CurrentDatabase == nil {
				name := db.DatabaseName
				progress.CurrentDatabase = &name
			}
		}
	}

	return progress, nil
}

// mapProvisioningState maps internal provisioning states to frontend-friendly states.
func mapProvisioningState(state models.ProvisioningState) string {
	switch state {
	case models.ProvisioningStateActive:
		return provisioningStateActive
	case models.ProvisioningStateFailed:
		return awxJobStatusFailed
	case models.ProvisioningStateDeleting:
		return "deleting"
	case models.ProvisioningStateDeleted:
		return "deleted"
	case models.ProvisioningStateMigrating:
		return "migrating"
	case models.ProvisioningStatePending:
		return "pending"
	default:
		// creating, seeding, configuring_auth, registering_service → "provisioning"
		return "provisioning"
	}
}

// isTransitionalState returns true for states where database_progress is relevant.
func isTransitionalState(state models.ProvisioningState) bool {
	switch state {
	case models.ProvisioningStateCreating,
		models.ProvisioningStateMigrating,
		models.ProvisioningStateSeeding,
		models.ProvisioningStateConfiguringAuth,
		models.ProvisioningStateRegisteringService:
		return true
	default:
		return false
	}
}
