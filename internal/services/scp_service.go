// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

// scpRepository defines the persistence operations required by SCPService.
// SCPRepository in the repositories package satisfies this interface.
type scpRepository interface {
	// Create persists a new service control policy.
	// The repository is responsible for populating ID, CreatedAt, and UpdatedAt.
	Create(ctx context.Context, scp *models.ServiceControlPolicy) error

	// GetByID returns the policy identified by id, or (nil, nil) when not found.
	GetByID(ctx context.Context, id uuid.UUID) (*models.ServiceControlPolicy, error)

	// List returns a paginated slice of policies and the total matching count.
	// scope may be "" to return all scopes, or one of "platform", "realm", "tenant".
	List(ctx context.Context, scope string, page, pageSize int) ([]*models.ServiceControlPolicy, int64, error)

	// Update applies a sparse patch to the identified policy.
	Update(ctx context.Context, id uuid.UUID, req *models.UpdateSCPRequest) (*models.ServiceControlPolicy, error)

	// Delete permanently removes the identified policy.
	Delete(ctx context.Context, id uuid.UUID) error

	// SetEnabled toggles the is_enabled flag on the identified policy.
	SetEnabled(ctx context.Context, id uuid.UUID, enabled bool) error

	// ListApplicable returns all enabled SCPs for the given tenant/realm scope chain,
	// ordered by priority DESC (highest priority evaluated first).
	ListApplicable(ctx context.Context, tenantID, realmID uuid.UUID) ([]*models.ServiceControlPolicy, error)
}

// SCPService manages service control policies and their evaluation.
type SCPService struct {
	repo   scpRepository
	logger *zap.Logger
}

// NewSCPService creates a new SCPService backed by the given repository.
func NewSCPService(repo scpRepository, log *zap.Logger) *SCPService {
	return &SCPService{
		repo:   repo,
		logger: log,
	}
}

// Create validates and persists a new service control policy.
// For non-platform scopes, a scope_id is required.
func (s *SCPService) Create(ctx context.Context, req *models.CreateSCPRequest) (*models.ServiceControlPolicy, error) {
	if req.Scope != models.SCPScopePlatform && req.ScopeID == nil {
		return nil, fmt.Errorf("scope_id is required for scope %s", req.Scope)
	}

	scp := &models.ServiceControlPolicy{
		Name:           req.Name,
		Description:    req.Description,
		Scope:          req.Scope,
		ScopeID:        req.ScopeID,
		PolicyDocument: req.PolicyDocument,
		Priority:       req.Priority,
		IsEnabled:      true,
	}

	if err := s.repo.Create(ctx, scp); err != nil {
		return nil, fmt.Errorf("SCPService.Create: %w", err)
	}

	s.logger.Info("service control policy created",
		zap.String("id", scp.ID.String()),
		zap.String("name", scp.Name),
		zap.String("scope", string(scp.Scope)),
	)

	return scp, nil
}

// GetByID retrieves a service control policy by its ID.
// Returns (nil, nil) when the policy does not exist.
func (s *SCPService) GetByID(ctx context.Context, id uuid.UUID) (*models.ServiceControlPolicy, error) {
	return s.repo.GetByID(ctx, id)
}

// List returns a paginated list of service control policies.
// scope may be "", "platform", "realm", or "tenant" to filter by scope.
func (s *SCPService) List(ctx context.Context, scope string, page, pageSize int) ([]*models.ServiceControlPolicy, int64, error) {
	if pageSize <= 0 {
		pageSize = 20
	}
	if page <= 0 {
		page = 1
	}

	policies, total, err := s.repo.List(ctx, scope, page, pageSize)
	if err != nil {
		return nil, 0, fmt.Errorf("SCPService.List: %w", err)
	}
	return policies, total, nil
}

// Update applies a partial update to an existing service control policy.
func (s *SCPService) Update(ctx context.Context, id uuid.UUID, req *models.UpdateSCPRequest) (*models.ServiceControlPolicy, error) {
	existing, err := s.repo.GetByID(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("SCPService.Update: fetch: %w", err)
	}
	if existing == nil {
		return nil, fmt.Errorf("SCPService.Update: SCP not found")
	}

	scp, err := s.repo.Update(ctx, id, req)
	if err != nil {
		return nil, fmt.Errorf("SCPService.Update: persist: %w", err)
	}

	return scp, nil
}

// Delete removes the service control policy identified by id.
func (s *SCPService) Delete(ctx context.Context, id uuid.UUID) error {
	existing, err := s.repo.GetByID(ctx, id)
	if err != nil {
		return fmt.Errorf("SCPService.Delete: fetch: %w", err)
	}
	if existing == nil {
		return fmt.Errorf("SCPService.Delete: SCP not found")
	}

	if err := s.repo.Delete(ctx, id); err != nil {
		return fmt.Errorf("SCPService.Delete: %w", err)
	}

	return nil
}

// Enable activates a service control policy.
func (s *SCPService) Enable(ctx context.Context, id uuid.UUID) error {
	existing, err := s.repo.GetByID(ctx, id)
	if err != nil {
		return fmt.Errorf("SCPService.Enable: fetch: %w", err)
	}
	if existing == nil {
		return fmt.Errorf("SCPService.Enable: SCP not found")
	}

	if err := s.repo.SetEnabled(ctx, id, true); err != nil {
		return fmt.Errorf("SCPService.Enable: persist: %w", err)
	}

	return nil
}

// Disable deactivates a service control policy without deleting it.
func (s *SCPService) Disable(ctx context.Context, id uuid.UUID) error {
	existing, err := s.repo.GetByID(ctx, id)
	if err != nil {
		return fmt.Errorf("SCPService.Disable: fetch: %w", err)
	}
	if existing == nil {
		return fmt.Errorf("SCPService.Disable: SCP not found")
	}

	if err := s.repo.SetEnabled(ctx, id, false); err != nil {
		return fmt.Errorf("SCPService.Disable: persist: %w", err)
	}

	return nil
}

// EvaluateSCPs evaluates all applicable SCPs for the given tenant, realm, action, and resource.
// Platform-scoped, realm-scoped, and tenant-scoped SCPs are loaded ordered by
// priority descending. The first explicit denial short-circuits evaluation.
//
// Evaluation order: action denied_actions -> resource denied_resources.
// Returns (denied, reason, nil) when a policy denies, (false, "", nil) when all permit.
func (s *SCPService) EvaluateSCPs(ctx context.Context, tenantID, realmID uuid.UUID, action, resource string) (bool, string, error) {
	scps, err := s.repo.ListApplicable(ctx, tenantID, realmID)
	if err != nil {
		return false, "", fmt.Errorf("SCPService.EvaluateSCPs: failed to get applicable SCPs: %w", err)
	}

	for _, scp := range scps {
		if !scp.IsEnabled {
			continue
		}

		// Check whether the action is explicitly denied.
		if scp.IsDenied(action) {
			reason := fmt.Sprintf("denied by SCP '%s' (scope: %s)", scp.Name, scp.Scope)
			s.logger.Warn("action denied by SCP",
				zap.String("scp_id", scp.ID.String()),
				zap.String("scp_name", scp.Name),
				zap.String("scope", string(scp.Scope)),
				zap.String("action", action),
				zap.String("tenant_id", tenantID.String()),
			)
			return true, reason, nil
		}

		// Check whether the resource is explicitly denied.
		for _, deniedResource := range scp.PolicyDocument.DeniedResources {
			if deniedResource == resource || deniedResource == "*" {
				reason := fmt.Sprintf("resource %q denied by SCP '%s' (scope: %s)", resource, scp.Name, scp.Scope)
				s.logger.Warn("resource denied by SCP",
					zap.String("scp_id", scp.ID.String()),
					zap.String("scp_name", scp.Name),
					zap.String("scope", string(scp.Scope)),
					zap.String("action", action),
					zap.String("resource", resource),
					zap.String("tenant_id", tenantID.String()),
				)
				return true, reason, nil
			}
		}
	}

	return false, "", nil
}
