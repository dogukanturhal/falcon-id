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

// idpOverrideRepoIface is the minimal persistence contract needed by
// IDPTenantOverrideService.  Using an interface keeps the service testable
// without a live database.
type idpOverrideRepoIface interface {
	Upsert(ctx context.Context, o *models.IDPTenantOverride) error
	GetByID(ctx context.Context, id uuid.UUID) (*models.IDPTenantOverride, error)
	GetByTenantAndProvider(ctx context.Context, tenantID, providerID uuid.UUID) (*models.IDPTenantOverride, error)
	List(ctx context.Context, tenantID uuid.UUID) ([]*models.IDPTenantOverride, error)
	Delete(ctx context.Context, id uuid.UUID) error
	GetOverrideMapByTenant(ctx context.Context, tenantID uuid.UUID) (map[uuid.UUID]*models.IDPTenantOverride, error)
}

// idpRepoIface is the minimal identity-provider persistence contract needed by
// IDPTenantOverrideService.
type idpRepoIface interface {
	GetByID(ctx context.Context, id uuid.UUID) (*models.IdentityProvider, error)
	List(ctx context.Context, tenantID uuid.UUID) ([]*models.IdentityProvider, error)
}

// Compile-time assertion: the concrete repositories satisfy the interfaces.
var (
	_ idpOverrideRepoIface = (*repositories.IDPTenantOverrideRepository)(nil)
	_ idpRepoIface         = (*repositories.IdentityProviderRepository)(nil)
)

// IDPTenantOverrideService is an exported identifier.
// IDPTenantOverrideService provides business logic for per-tenant IDP overrides.
type IDPTenantOverrideService struct {
	overrideRepo idpOverrideRepoIface
	idpRepo      idpRepoIface
}

// NewIDPTenantOverrideService is an exported identifier.
// NewIDPTenantOverrideService constructs a new IDPTenantOverrideService using the
// concrete repository types.
func NewIDPTenantOverrideService(
	overrideRepo *repositories.IDPTenantOverrideRepository,
	idpRepo *repositories.IdentityProviderRepository,
) *IDPTenantOverrideService {
	return &IDPTenantOverrideService{
		overrideRepo: overrideRepo,
		idpRepo:      idpRepo,
	}
}

// Upsert creates or updates a per-tenant override for the given provider.
// It validates that the provider exists before upserting.
func (s *IDPTenantOverrideService) Upsert(
	ctx context.Context,
	tenantID uuid.UUID,
	req *models.UpsertIDPTenantOverrideRequest,
) (*models.IDPTenantOverride, error) {
	provider, err := s.idpRepo.GetByID(ctx, req.ProviderID)
	if err != nil {
		return nil, fmt.Errorf("idp_tenant_override: fetch provider: %w", err)
	}
	if provider == nil {
		return nil, fmt.Errorf("idp_tenant_override: provider %s not found", req.ProviderID)
	}

	override := &models.IDPTenantOverride{
		TenantID:                tenantID,
		ProviderID:              req.ProviderID,
		IsEnabled:               req.IsEnabled,
		DisplayName:             req.DisplayName,
		Priority:                req.Priority,
		ConfigOverrides:         req.ConfigOverrides,
		AssignMembershipOnLogin: req.AssignMembershipOnLogin,
		IsSignupEnabled:         req.IsSignupEnabled,
		ShowAsButton:            req.ShowAsButton,
	}

	if err := s.overrideRepo.Upsert(ctx, override); err != nil {
		return nil, fmt.Errorf("idp_tenant_override: upsert: %w", err)
	}

	logger.Info("IdP tenant override upserted",
		zap.String("tenant_id", tenantID.String()),
		zap.String("provider_id", req.ProviderID.String()),
	)

	return override, nil
}

// GetOverride returns the override for a (tenant, provider) pair together with
// the provider itself.  Returns nil if the provider does not exist.
func (s *IDPTenantOverrideService) GetOverride(
	ctx context.Context,
	tenantID, providerID uuid.UUID,
) (*models.IDPWithOverride, error) {
	provider, err := s.idpRepo.GetByID(ctx, providerID)
	if err != nil {
		return nil, fmt.Errorf("idp_tenant_override: fetch provider: %w", err)
	}
	if provider == nil {
		return nil, nil
	}

	override, err := s.overrideRepo.GetByTenantAndProvider(ctx, tenantID, providerID)
	if err != nil {
		return nil, fmt.Errorf("idp_tenant_override: fetch override: %w", err)
	}

	return &models.IDPWithOverride{
		Provider: provider,
		Override: override,
	}, nil
}

// ListWithProviders returns all providers visible to the tenant, each paired
// with their override (if any).
func (s *IDPTenantOverrideService) ListWithProviders(
	ctx context.Context,
	tenantID uuid.UUID,
) ([]*models.IDPWithOverride, error) {
	providers, err := s.idpRepo.List(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("idp_tenant_override: list providers: %w", err)
	}

	overrideMap, err := s.overrideRepo.GetOverrideMapByTenant(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("idp_tenant_override: load override map: %w", err)
	}

	result := make([]*models.IDPWithOverride, 0, len(providers))
	for _, p := range providers {
		result = append(result, &models.IDPWithOverride{
			Provider: p,
			Override: overrideMap[p.ID],
		})
	}

	return result, nil
}

// GetEnabledLoginProvidersWithOverrides returns the list of providers that are
// enabled for the tenant.  When showButtonOnly is true, providers whose
// EffectiveShowAsButton() resolves to false are excluded.
func (s *IDPTenantOverrideService) GetEnabledLoginProvidersWithOverrides(
	ctx context.Context,
	tenantID uuid.UUID,
	showButtonOnly bool,
) ([]*models.IDPWithOverride, error) {
	all, err := s.ListWithProviders(ctx, tenantID)
	if err != nil {
		return nil, err
	}

	result := make([]*models.IDPWithOverride, 0, len(all))
	for _, combo := range all {
		if !combo.EffectiveIsEnabled() {
			continue
		}
		if showButtonOnly && !combo.EffectiveShowAsButton() {
			continue
		}
		result = append(result, combo)
	}

	return result, nil
}

// DeleteOverride removes a per-tenant override by its primary key.
// It verifies that the override belongs to the given tenant before deletion.
func (s *IDPTenantOverrideService) DeleteOverride(
	ctx context.Context,
	tenantID, overrideID uuid.UUID,
) error {
	existing, err := s.overrideRepo.GetByID(ctx, overrideID)
	if err != nil {
		return fmt.Errorf("idp_tenant_override: fetch for delete: %w", err)
	}
	if existing == nil {
		return fmt.Errorf("idp_tenant_override: override %s not found", overrideID)
	}
	if existing.TenantID != tenantID {
		return fmt.Errorf("idp_tenant_override: override %s does not belong to tenant", overrideID)
	}

	return s.overrideRepo.Delete(ctx, overrideID)
}
