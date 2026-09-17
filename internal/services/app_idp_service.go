// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"fmt"

	"github.com/google/uuid"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/internal/repositories"
)

// AppIdentityProviderService handles per-app IDP enablement business logic.
type AppIdentityProviderService struct {
	repo *repositories.AppIdentityProviderRepository
}

// NewAppIdentityProviderService creates a new AppIdentityProviderService.
func NewAppIdentityProviderService(repo *repositories.AppIdentityProviderRepository) *AppIdentityProviderService {
	return &AppIdentityProviderService{repo: repo}
}

// EnableIDPForApp is an exported identifier.
// EnableIDPForApp enables an IDP for an application.
func (s *AppIdentityProviderService) EnableIDPForApp(ctx context.Context, applicationID uuid.UUID, req *models.CreateAppIdentityProviderRequest) (*models.AppIdentityProvider, error) {
	isEnabled := true
	if req.IsEnabled != nil {
		isEnabled = *req.IsEnabled
	}

	record := &models.AppIdentityProvider{
		ApplicationID:      applicationID,
		IdentityProviderID: req.IdentityProviderID,
		IsEnabled:          isEnabled,
		Priority:           req.Priority,
	}

	if err := s.repo.Add(ctx, record); err != nil {
		return nil, fmt.Errorf("failed to enable IdP for app: %w", err)
	}

	return record, nil
}

// DisableIDPForApp is an exported identifier.
// DisableIDPForApp removes an IDP from an application.
func (s *AppIdentityProviderService) DisableIDPForApp(ctx context.Context, applicationID, identityProviderID uuid.UUID) error {
	return s.repo.Remove(ctx, applicationID, identityProviderID)
}

// ListEnabledIDPs is an exported identifier.
// ListEnabledIDPs returns all IDPs enabled for an application.
func (s *AppIdentityProviderService) ListEnabledIDPs(ctx context.Context, applicationID uuid.UUID) ([]models.AppIdentityProvider, error) {
	return s.repo.ListByApp(ctx, applicationID)
}

// IsIDPEnabledForApp is an exported identifier.
// IsIDPEnabledForApp checks if a specific IDP is enabled for a specific application.
func (s *AppIdentityProviderService) IsIDPEnabledForApp(ctx context.Context, applicationID, identityProviderID uuid.UUID) (bool, error) {
	return s.repo.IsEnabled(ctx, applicationID, identityProviderID)
}

// GetEnabledIDPIDs is an exported identifier.
// GetEnabledIDPIDs returns the set of enabled IDP IDs for an application.
func (s *AppIdentityProviderService) GetEnabledIDPIDs(ctx context.Context, applicationID uuid.UUID) ([]uuid.UUID, error) {
	return s.repo.GetEnabledIDPIDs(ctx, applicationID)
}
