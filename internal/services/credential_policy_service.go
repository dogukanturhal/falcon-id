// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

// credentialPolicyRepo defines the repository interface for the credential policy service.
type credentialPolicyRepo interface {
	GetByScope(ctx context.Context, scopeType models.CredentialPolicyScopeType, scopeID *uuid.UUID) (*models.CredentialPolicy, error)
	GetEffective(ctx context.Context, tenantID uuid.UUID) (*models.CredentialPolicy, error)
	Upsert(ctx context.Context, policy *models.CredentialPolicy) error
	Delete(ctx context.Context, id uuid.UUID) error
	List(ctx context.Context) ([]models.CredentialPolicy, error)
}

// CredentialPolicyService manages credential lifetime policies.
type CredentialPolicyService struct {
	repo credentialPolicyRepo
}

// NewCredentialPolicyService creates a new CredentialPolicyService.
func NewCredentialPolicyService(repo credentialPolicyRepo) *CredentialPolicyService {
	return &CredentialPolicyService{repo: repo}
}

// GetPlatformPolicy returns the platform-level credential policy.
func (s *CredentialPolicyService) GetPlatformPolicy(ctx context.Context) (*models.CredentialPolicy, error) {
	p, err := s.repo.GetByScope(ctx, models.CredentialPolicyScopePlatform, nil)
	if err != nil {
		return nil, fmt.Errorf("CredentialPolicyService.GetPlatformPolicy: %w", err)
	}
	return p, nil
}

// GetEffectivePolicy returns the most specific policy for a tenant.
func (s *CredentialPolicyService) GetEffectivePolicy(ctx context.Context, tenantID uuid.UUID) (*models.CredentialPolicy, error) {
	p, err := s.repo.GetEffective(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("CredentialPolicyService.GetEffectivePolicy: %w", err)
	}
	return p, nil
}

// UpsertPolicy creates or updates a credential policy.
func (s *CredentialPolicyService) UpsertPolicy(ctx context.Context, req *models.CreateCredentialPolicyRequest) (*models.CredentialPolicy, error) {
	policy := &models.CredentialPolicy{
		ScopeType:             req.ScopeType,
		ScopeID:               req.ScopeID,
		MaxSecretLifetimeDays: 365,
		MaxCertLifetimeDays:   730,
		RequireExpiry:         false,
	}

	if req.MaxSecretLifetimeDays != nil {
		policy.MaxSecretLifetimeDays = *req.MaxSecretLifetimeDays
	}
	if req.MaxCertLifetimeDays != nil {
		policy.MaxCertLifetimeDays = *req.MaxCertLifetimeDays
	}
	if req.RequireExpiry != nil {
		policy.RequireExpiry = *req.RequireExpiry
	}

	if err := s.repo.Upsert(ctx, policy); err != nil {
		return nil, fmt.Errorf("CredentialPolicyService.UpsertPolicy: %w", err)
	}
	return policy, nil
}

// DeletePolicy removes a credential policy.
func (s *CredentialPolicyService) DeletePolicy(ctx context.Context, id uuid.UUID) error {
	if err := s.repo.Delete(ctx, id); err != nil {
		return fmt.Errorf("CredentialPolicyService.DeletePolicy: %w", err)
	}
	return nil
}

// ListPolicies returns all credential policies.
func (s *CredentialPolicyService) ListPolicies(ctx context.Context) ([]models.CredentialPolicy, error) {
	policies, err := s.repo.List(ctx)
	if err != nil {
		return nil, fmt.Errorf("CredentialPolicyService.ListPolicies: %w", err)
	}
	return policies, nil
}

// ValidateCredentialExpiry checks whether a proposed credential expiry complies with the effective policy.
// Returns nil if valid, error describing the violation if not.
func (s *CredentialPolicyService) ValidateCredentialExpiry(ctx context.Context, tenantID uuid.UUID, credType models.SPCredentialType, expiresAt *time.Time) error {
	policy, err := s.repo.GetEffective(ctx, tenantID)
	if err != nil {
		// No policy found — allow anything
		return nil //nolint:nilerr // intentional: if no policy is found, allow anything
	}

	if policy.RequireExpiry && expiresAt == nil {
		return fmt.Errorf("credential policy requires an expiration date for %s credentials", credType)
	}

	if expiresAt == nil {
		return nil
	}

	daysUntilExpiry := int(time.Until(*expiresAt).Hours() / 24)

	switch credType {
	case models.SPCredentialTypeClientSecret:
		if daysUntilExpiry > policy.MaxSecretLifetimeDays {
			return fmt.Errorf("credential policy limits client_secret lifetime to %d days, requested %d days", policy.MaxSecretLifetimeDays, daysUntilExpiry)
		}
	case models.SPCredentialTypeRSAKey:
		if daysUntilExpiry > policy.MaxCertLifetimeDays {
			return fmt.Errorf("credential policy limits rsa_key lifetime to %d days, requested %d days", policy.MaxCertLifetimeDays, daysUntilExpiry)
		}
	}

	return nil
}
