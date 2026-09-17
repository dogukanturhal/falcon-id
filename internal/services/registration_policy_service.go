// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"fmt"
	"path"

	"github.com/google/uuid"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

// registrationPolicyRepo is the minimal repository interface consumed by
// RegistrationPolicyService, allowing the service to be tested with a mock.
type registrationPolicyRepo interface {
	Create(ctx context.Context, p *models.RegistrationPolicy) error
	GetByID(ctx context.Context, id uuid.UUID) (*models.RegistrationPolicy, error)
	GetDefault(ctx context.Context) (*models.RegistrationPolicy, error)
	Update(ctx context.Context, p *models.RegistrationPolicy) error
	Delete(ctx context.Context, id uuid.UUID) error
	List(ctx context.Context) ([]models.RegistrationPolicy, error)
	CountByTenantID(ctx context.Context, tenantID uuid.UUID) (int, error)
}

// RegistrationPolicyService manages the lifecycle of client registration policies
// and validates prospective app registrations against the effective policy.
type RegistrationPolicyService struct {
	repo registrationPolicyRepo
}

// NewRegistrationPolicyService creates a new RegistrationPolicyService.
func NewRegistrationPolicyService(repo registrationPolicyRepo) *RegistrationPolicyService {
	return &RegistrationPolicyService{repo: repo}
}

// defaultMaxAppsPerTenant is applied when the caller omits MaxAppsPerTenant.
const defaultMaxAppsPerTenant = 50

// defaultAllowedGrantTypes is applied when the caller omits AllowedGrantTypes.
var defaultAllowedGrantTypes = []string{"authorization_code", "client_credentials"}

// Create persists a new registration policy.
// When IsDefault is true any existing default policy is NOT automatically cleared —
// that enforcement lives at the database UNIQUE constraint level if desired, or
// callers can coordinate via List + Update.
func (s *RegistrationPolicyService) Create(
	ctx context.Context,
	req *models.CreateRegistrationPolicyRequest,
) (*models.RegistrationPolicy, error) {
	p := &models.RegistrationPolicy{
		Name:                    req.Name,
		Description:             req.Description,
		RequireApproval:         false,
		AllowedRedirectPatterns: req.AllowedRedirectPatterns,
		MaxAppsPerTenant:        defaultMaxAppsPerTenant,
		AllowedGrantTypes:       defaultAllowedGrantTypes,
		IsDefault:               false,
	}

	if req.RequireApproval != nil {
		p.RequireApproval = *req.RequireApproval
	}
	if req.MaxAppsPerTenant != nil {
		p.MaxAppsPerTenant = *req.MaxAppsPerTenant
	}
	if len(req.AllowedGrantTypes) > 0 {
		p.AllowedGrantTypes = req.AllowedGrantTypes
	}
	if req.IsDefault != nil {
		p.IsDefault = *req.IsDefault
	}
	if len(p.AllowedRedirectPatterns) == 0 {
		p.AllowedRedirectPatterns = []string{}
	}

	if err := s.repo.Create(ctx, p); err != nil {
		return nil, fmt.Errorf("RegistrationPolicyService.Create: %w", err)
	}
	return p, nil
}

// Get retrieves a registration policy by UUID.
func (s *RegistrationPolicyService) Get(
	ctx context.Context,
	id uuid.UUID,
) (*models.RegistrationPolicy, error) {
	p, err := s.repo.GetByID(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("RegistrationPolicyService.Get: %w", err)
	}
	return p, nil
}

// GetDefault retrieves the policy marked as the platform default.
func (s *RegistrationPolicyService) GetDefault(ctx context.Context) (*models.RegistrationPolicy, error) {
	p, err := s.repo.GetDefault(ctx)
	if err != nil {
		return nil, fmt.Errorf("RegistrationPolicyService.GetDefault: %w", err)
	}
	return p, nil
}

// Update applies the provided changes to an existing registration policy.
func (s *RegistrationPolicyService) Update(
	ctx context.Context,
	id uuid.UUID,
	req *models.UpdateRegistrationPolicyRequest,
) (*models.RegistrationPolicy, error) {
	p, err := s.repo.GetByID(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("RegistrationPolicyService.Update: registration policy not found: %w", err)
	}

	if req.Name != nil {
		p.Name = *req.Name
	}
	if req.Description != nil {
		p.Description = req.Description
	}
	if req.RequireApproval != nil {
		p.RequireApproval = *req.RequireApproval
	}
	if req.AllowedRedirectPatterns != nil {
		p.AllowedRedirectPatterns = req.AllowedRedirectPatterns
	}
	if req.MaxAppsPerTenant != nil {
		p.MaxAppsPerTenant = *req.MaxAppsPerTenant
	}
	if req.AllowedGrantTypes != nil {
		p.AllowedGrantTypes = req.AllowedGrantTypes
	}
	if req.IsDefault != nil {
		p.IsDefault = *req.IsDefault
	}

	if err := s.repo.Update(ctx, p); err != nil {
		return nil, fmt.Errorf("RegistrationPolicyService.Update: %w", err)
	}
	return p, nil
}

// Delete removes a registration policy. Deleting the default policy is not
// permitted; callers must first reassign the default to another policy.
func (s *RegistrationPolicyService) Delete(ctx context.Context, id uuid.UUID) error {
	p, err := s.repo.GetByID(ctx, id)
	if err != nil {
		return fmt.Errorf("RegistrationPolicyService.Delete: registration policy not found: %w", err)
	}

	if p.IsDefault {
		return fmt.Errorf("RegistrationPolicyService.Delete: cannot delete the default registration policy")
	}

	if err := s.repo.Delete(ctx, id); err != nil {
		return fmt.Errorf("RegistrationPolicyService.Delete: %w", err)
	}
	return nil
}

// List returns all registration policies.
func (s *RegistrationPolicyService) List(ctx context.Context) ([]models.RegistrationPolicy, error) {
	policies, err := s.repo.List(ctx)
	if err != nil {
		return nil, fmt.Errorf("RegistrationPolicyService.List: %w", err)
	}
	return policies, nil
}

// ValidateRegistration checks whether a prospective app registration request
// complies with the effective (default) registration policy.
// It validates:
//  1. Each redirect URI matches at least one of the allowed redirect patterns
//     (glob matching via path.Match from the standard library).
//  2. Every requested grant type appears in the policy's AllowedGrantTypes list.
//  3. The tenant has not yet reached MaxAppsPerTenant existing registrations.
//
// When no default policy is configured, validation passes unconditionally.
func (s *RegistrationPolicyService) ValidateRegistration(
	ctx context.Context,
	req *models.AppRegistrationValidationRequest,
) error {
	policy, err := s.repo.GetDefault(ctx)
	if err != nil {
		// No default policy — allow registration unconditionally.
		return nil //nolint:nilerr // intentional: if no default policy found, allow registration unconditionally
	}

	// 1. Redirect URI pattern check.
	for _, uri := range req.RedirectURIs {
		if !matchesAnyPattern(uri, policy.AllowedRedirectPatterns) {
			return fmt.Errorf(
				"RegistrationPolicyService.ValidateRegistration: redirect URI %q does not match any allowed pattern",
				uri,
			)
		}
	}

	// 2. Grant type check.
	allowedSet := make(map[string]struct{}, len(policy.AllowedGrantTypes))
	for _, gt := range policy.AllowedGrantTypes {
		allowedSet[gt] = struct{}{}
	}
	for _, gt := range req.GrantTypes {
		if _, ok := allowedSet[gt]; !ok {
			return fmt.Errorf(
				"RegistrationPolicyService.ValidateRegistration: grant type %q is not allowed by the registration policy",
				gt,
			)
		}
	}

	// 3. Per-tenant app count check.
	count, err := s.repo.CountByTenantID(ctx, req.TenantID)
	if err != nil {
		return fmt.Errorf("RegistrationPolicyService.ValidateRegistration: %w", err)
	}
	if count >= policy.MaxAppsPerTenant {
		return fmt.Errorf(
			"RegistrationPolicyService.ValidateRegistration: tenant has reached the maximum number of app registrations (%d)",
			policy.MaxAppsPerTenant,
		)
	}

	return nil
}

// matchesAnyPattern returns true when s matches at least one glob pattern using
// path.Match semantics. When patterns is empty, every URI is considered allowed
// (an empty allow-list means "unrestricted").
func matchesAnyPattern(s string, patterns []string) bool {
	if len(patterns) == 0 {
		return true
	}
	for _, pattern := range patterns {
		matched, err := path.Match(pattern, s)
		if err == nil && matched {
			return true
		}
	}
	return false
}
