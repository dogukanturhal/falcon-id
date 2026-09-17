// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/internal/repositories"
	"github.com/dogukanturhal/falcon-id/pkg/logger"
)

// AppAccessService handles application-level access control:
// per-app role assignments, per-app auth policies, and audience-scoped tokens.
type AppAccessService struct {
	repo      *repositories.AppAccessRepository
	oauthRepo *repositories.OAuthClientRepository
}

// NewAppAccessService creates a new AppAccessService.
func NewAppAccessService(repo *repositories.AppAccessRepository, oauthRepo *repositories.OAuthClientRepository) *AppAccessService {
	return &AppAccessService{
		repo:      repo,
		oauthRepo: oauthRepo,
	}
}

// ValidateAppAccess resolves the OAuth client by client_id string, checks require_assignment,
// and returns the filtered (roles, permissions) for the user within this application.
func (s *AppAccessService) ValidateAppAccess(ctx context.Context, userID, _ uuid.UUID, clientID string, allRoleNames, allPermNames []string) (*models.OAuthClient, []string, []string, error) {
	// 1. Resolve OAuth client by client_id string
	client, err := s.oauthRepo.GetByClientID(ctx, clientID)
	if err != nil {
		logger.Error("GetByClientID failed", zap.String("client_id", clientID), zap.Error(err))
		return nil, nil, nil, fmt.Errorf("unknown application: %s", clientID)
	}

	if !client.IsActive {
		return nil, nil, nil, fmt.Errorf("application is disabled: %s", clientID)
	}

	// 2. Get app auth policy (may be nil if no policy exists)
	policy, err := s.repo.GetAuthPolicyByClientID(ctx, client.ID)
	if err != nil {
		logger.Error("Failed to get app auth policy", zap.Error(err), zap.String("client_id", clientID))
	}

	// 3. Get app role assignments for this user + client
	assignments, err := s.repo.GetRoleAssignmentsByUserAndClient(ctx, userID, client.ID)
	if err != nil {
		logger.Error("Failed to get app role assignments", zap.Error(err))
	}

	// 4. Check if assignment is required (from OAuth client or auth policy)
	requireAssignment := client.RequireAssignment
	if policy != nil && policy.RequireAssignment {
		requireAssignment = true
	}

	if requireAssignment && len(assignments) == 0 {
		logger.Warn("User has no app role assignments for required application",
			zap.String("user_id", userID.String()),
			zap.String("client_id", clientID),
		)
		return nil, nil, nil, fmt.Errorf("access denied: user is not assigned to application %s", client.Name)
	}

	// 5. Filter roles and permissions to only those assigned for this app
	var filteredRoleNames []string
	var filteredPermNames []string

	if len(assignments) > 0 {
		appRoleSet := make(map[string]bool, len(assignments))
		for _, a := range assignments {
			appRoleSet[a.RoleName] = true
		}

		for _, rn := range allRoleNames {
			if appRoleSet[rn] {
				filteredRoleNames = append(filteredRoleNames, rn)
			}
		}

		filteredPermNames = allPermNames
	} else {
		filteredRoleNames = allRoleNames
		filteredPermNames = allPermNames
	}

	logger.Info("App access validated",
		zap.String("user_id", userID.String()),
		zap.String("client_id", clientID),
		zap.String("app_name", client.Name),
		zap.Int("app_role_assignments", len(assignments)),
		zap.Int("filtered_roles", len(filteredRoleNames)),
		zap.Bool("require_assignment", requireAssignment),
	)

	return client, filteredRoleNames, filteredPermNames, nil
}

// ResolveClientID resolves a client_id string (e.g. "platform-admin") to the
// internal UUID by looking up the OAuth client. If the string is already a valid
// UUID it is returned directly.
func (s *AppAccessService) ResolveClientID(ctx context.Context, clientIDStr string) (uuid.UUID, error) {
	// Fast path: already a UUID
	if id, err := uuid.Parse(clientIDStr); err == nil {
		return id, nil
	}

	// Slow path: look up by string client_id
	client, err := s.oauthRepo.GetByClientID(ctx, clientIDStr)
	if err != nil {
		return uuid.Nil, fmt.Errorf("unknown application: %s", clientIDStr)
	}
	return client.ID, nil
}

// CheckAppAuthPolicy checks the app auth policy and returns whether MFA is required.
func (s *AppAccessService) CheckAppAuthPolicy(ctx context.Context, clientUUID uuid.UUID) (*models.AppAuthPolicy, error) {
	return s.repo.GetAuthPolicyByClientID(ctx, clientUUID)
}

// AssignRole creates a new app role assignment.
func (s *AppAccessService) AssignRole(ctx context.Context, clientID uuid.UUID, req *models.CreateAppRoleAssignmentRequest, assignedBy *uuid.UUID) error {
	assignment := &models.AppAccessRoleAssignment{
		TenantID:   req.TenantID,
		UserID:     req.UserID,
		ClientID:   clientID,
		RoleID:     req.RoleID,
		AssignedBy: assignedBy,
	}

	if err := s.repo.CreateRoleAssignment(ctx, assignment); err != nil {
		return fmt.Errorf("failed to assign role: %w", err)
	}

	logger.Info("App role assigned",
		zap.String("user_id", req.UserID.String()),
		zap.String("client_id", clientID.String()),
		zap.String("role_id", req.RoleID.String()),
	)

	return nil
}

// RevokeRole deletes an app role assignment.
func (s *AppAccessService) RevokeRole(ctx context.Context, assignmentID uuid.UUID) error {
	if err := s.repo.DeleteRoleAssignment(ctx, assignmentID); err != nil {
		return fmt.Errorf("failed to revoke role: %w", err)
	}
	return nil
}

// ListRoleAssignments returns paginated role assignments for an application.
func (s *AppAccessService) ListRoleAssignments(ctx context.Context, clientID uuid.UUID, page, pageSize int) ([]models.AppAccessRoleAssignment, int64, error) {
	return s.repo.ListRoleAssignmentsByClient(ctx, clientID, page, pageSize)
}

// ListUserAssignments returns paginated role assignments for a user across all applications.
func (s *AppAccessService) ListUserAssignments(ctx context.Context, userID uuid.UUID, page, pageSize int) ([]models.AppAccessRoleAssignment, int64, error) {
	return s.repo.ListRoleAssignmentsByUser(ctx, userID, page, pageSize)
}

// GetAuthPolicy returns the auth policy for an application.
func (s *AppAccessService) GetAuthPolicy(ctx context.Context, clientID uuid.UUID) (*models.AppAuthPolicy, error) {
	return s.repo.GetAuthPolicyByClientID(ctx, clientID)
}

// UpsertAuthPolicy creates or updates an app auth policy.
func (s *AppAccessService) UpsertAuthPolicy(ctx context.Context, clientID uuid.UUID, req *models.UpdateAppAuthPolicyRequest) error {
	err := s.repo.UpdateAuthPolicy(ctx, clientID, req)
	if err != nil {
		policy := &models.AppAuthPolicy{
			ClientID: clientID,
		}
		if req.RequireMFA != nil {
			policy.RequireMFA = *req.RequireMFA
		}
		if req.RequireAssignment != nil {
			policy.RequireAssignment = *req.RequireAssignment
		}
		policy.AllowedIPRanges = req.AllowedIPRanges
		policy.MaxSessionDurationSeconds = req.MaxSessionDurationSeconds

		client, clientErr := s.oauthRepo.GetByID(ctx, clientID)
		if clientErr != nil {
			return fmt.Errorf("failed to resolve client for policy: %w", clientErr)
		}
		policy.TenantID = client.TenantID

		if createErr := s.repo.CreateAuthPolicy(ctx, policy); createErr != nil {
			return fmt.Errorf("failed to create auth policy: %w", createErr)
		}
	}

	return nil
}
