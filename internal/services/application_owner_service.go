// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"fmt"

	"github.com/google/uuid"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

// appOwnerRepo is the repository interface consumed by ApplicationOwnerService.
type appOwnerRepo interface {
	Add(ctx context.Context, o *models.ApplicationOwner) error
	Remove(ctx context.Context, appID, ownerID uuid.UUID) error
	ListByApp(ctx context.Context, appID uuid.UUID) ([]models.ApplicationOwner, error)
	IsOwner(ctx context.Context, appID, userID uuid.UUID) (bool, error)
	CountByApp(ctx context.Context, appID uuid.UUID) (int, error)
}

// ApplicationOwnerService manages the multi-owner relationship for Application Objects.
// It enforces the invariant that every application must retain at least one owner.
type ApplicationOwnerService struct {
	repo appOwnerRepo
}

// NewApplicationOwnerService creates a new ApplicationOwnerService.
func NewApplicationOwnerService(repo appOwnerRepo) *ApplicationOwnerService {
	return &ApplicationOwnerService{repo: repo}
}

// AddOwner registers a new owner for an application. addedBy is the ID of the
// authenticated user performing the action and may be nil for system operations.
func (s *ApplicationOwnerService) AddOwner(ctx context.Context, appID uuid.UUID, req *models.AddOwnerRequest, addedBy *uuid.UUID) (*models.ApplicationOwner, error) {
	owner := &models.ApplicationOwner{
		ApplicationID: appID,
		OwnerID:       req.OwnerID,
		OwnerType:     req.OwnerType,
		Role:          req.Role,
		AddedBy:       addedBy,
	}

	if err := s.repo.Add(ctx, owner); err != nil {
		return nil, fmt.Errorf("ApplicationOwnerService.AddOwner: %w", err)
	}
	return owner, nil
}

// RemoveOwner removes an owner from an application. The operation is rejected
// when the target is the last remaining owner, preventing an application from
// becoming ownerless.
func (s *ApplicationOwnerService) RemoveOwner(ctx context.Context, appID, ownerID uuid.UUID) error {
	count, err := s.repo.CountByApp(ctx, appID)
	if err != nil {
		return fmt.Errorf("ApplicationOwnerService.RemoveOwner: %w", err)
	}
	if count <= 1 {
		return fmt.Errorf("ApplicationOwnerService.RemoveOwner: cannot remove the last owner of application %s", appID)
	}

	if err := s.repo.Remove(ctx, appID, ownerID); err != nil {
		return fmt.Errorf("ApplicationOwnerService.RemoveOwner: %w", err)
	}
	return nil
}

// ListOwners returns all owners of an application ordered by creation time.
func (s *ApplicationOwnerService) ListOwners(ctx context.Context, appID uuid.UUID) ([]models.ApplicationOwner, error) {
	owners, err := s.repo.ListByApp(ctx, appID)
	if err != nil {
		return nil, fmt.Errorf("ApplicationOwnerService.ListOwners: %w", err)
	}
	return owners, nil
}

// IsOwner reports whether userID is registered as an owner of appID.
func (s *ApplicationOwnerService) IsOwner(ctx context.Context, appID, userID uuid.UUID) (bool, error) {
	ok, err := s.repo.IsOwner(ctx, appID, userID)
	if err != nil {
		return false, fmt.Errorf("ApplicationOwnerService.IsOwner: %w", err)
	}
	return ok, nil
}
