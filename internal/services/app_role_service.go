// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

// ============================================================================
// Repository interfaces
// ============================================================================

// appRoleAssignmentRepo is the subset of ApplicationRoleAssignmentRepository used here.
type appRoleAssignmentRepo interface {
	Create(ctx context.Context, a *models.ApplicationRoleAssignment) error
	Delete(ctx context.Context, id uuid.UUID) error
	ListByApplication(ctx context.Context, appID uuid.UUID) ([]models.ApplicationRoleAssignment, error)
	ListByPrincipal(ctx context.Context, principalType string, principalID uuid.UUID) ([]models.ApplicationRoleAssignment, error)
	GetByID(ctx context.Context, id uuid.UUID) (*models.ApplicationRoleAssignment, error)
}

// appRoleAppRepo is the subset of ApplicationRepository needed to read app roles.
// GetAppRoles returns the raw JSONB bytes for an application's app_roles column.
type appRoleAppRepo interface {
	GetAppRoles(ctx context.Context, appID uuid.UUID) ([]byte, error)
}

// ============================================================================
// Service
// ============================================================================

// AppRoleService handles app role assignment business logic.
type AppRoleService struct {
	repo    appRoleAssignmentRepo
	appRepo appRoleAppRepo
}

// NewAppRoleService creates a new AppRoleService.
func NewAppRoleService(repo appRoleAssignmentRepo, appRepo appRoleAppRepo) *AppRoleService {
	return &AppRoleService{repo: repo, appRepo: appRepo}
}

// AssignRole grants an app role to a principal after validating that the role
// exists in the application's JSONB definition.
func (s *AppRoleService) AssignRole(
	ctx context.Context,
	appID uuid.UUID,
	req *models.AssignAppRoleRequest,
	assignedBy uuid.UUID,
) (*models.ApplicationRoleAssignment, error) {
	// Validate that the requested role exists in the application definition.
	if err := s.validateRoleExists(ctx, appID, req.AppRoleID); err != nil {
		return nil, err
	}

	a := &models.ApplicationRoleAssignment{
		ApplicationID: appID,
		AppRoleID:     req.AppRoleID,
		PrincipalType: req.PrincipalType,
		PrincipalID:   req.PrincipalID,
		AssignedBy:    assignedBy,
	}

	if err := s.repo.Create(ctx, a); err != nil {
		return nil, fmt.Errorf("AppRoleService.AssignRole: %w", err)
	}
	return a, nil
}

// UnassignRole removes an app role assignment by its ID.
func (s *AppRoleService) UnassignRole(ctx context.Context, assignmentID uuid.UUID) error {
	if err := s.repo.Delete(ctx, assignmentID); err != nil {
		return fmt.Errorf("AppRoleService.UnassignRole: %w", err)
	}
	return nil
}

// ListAssignments returns all role assignments for the given application.
func (s *AppRoleService) ListAssignments(ctx context.Context, appID uuid.UUID) ([]models.ApplicationRoleAssignment, error) {
	assignments, err := s.repo.ListByApplication(ctx, appID)
	if err != nil {
		return nil, fmt.Errorf("AppRoleService.ListAssignments: %w", err)
	}
	return assignments, nil
}

// ListByPrincipal returns all role assignments held by a given principal.
func (s *AppRoleService) ListByPrincipal(ctx context.Context, principalType string, principalID uuid.UUID) ([]models.ApplicationRoleAssignment, error) {
	assignments, err := s.repo.ListByPrincipal(ctx, principalType, principalID)
	if err != nil {
		return nil, fmt.Errorf("AppRoleService.ListByPrincipal: %w", err)
	}
	return assignments, nil
}

// ============================================================================
// Internal helpers
// ============================================================================

// validateRoleExists checks that appRoleID appears in the application's JSONB
// app_roles array and that the role is enabled.
func (s *AppRoleService) validateRoleExists(ctx context.Context, appID, appRoleID uuid.UUID) error {
	raw, err := s.appRepo.GetAppRoles(ctx, appID)
	if err != nil {
		return fmt.Errorf("AppRoleService.validateRoleExists: failed to fetch app roles: %w", err)
	}

	var roles []models.AppRole
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &roles); err != nil {
			return fmt.Errorf("AppRoleService.validateRoleExists: malformed app_roles JSONB: %w", err)
		}
	}

	roleIDStr := appRoleID.String()
	for _, r := range roles {
		if r.ID == roleIDStr {
			if !r.IsEnabled {
				return fmt.Errorf("AppRoleService.validateRoleExists: app role %s is disabled", appRoleID)
			}
			return nil
		}
	}

	return fmt.Errorf("AppRoleService.validateRoleExists: app role %s not found in application %s", appRoleID, appID)
}
