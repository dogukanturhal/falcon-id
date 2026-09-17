// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"fmt"

	"github.com/google/uuid"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

// defaultPrimaryColor and defaultBackgroundColor define the platform defaults
// returned when a tenant has not yet configured custom branding.
const (
	defaultPrimaryColor    = "#2563eb"
	defaultBackgroundColor = "#ffffff"
)

// tenantBrandingRepo is the repository interface required by TenantBrandingService.
type tenantBrandingRepo interface {
	GetByTenantID(ctx context.Context, tenantID uuid.UUID) (*models.TenantBranding, error)
	Upsert(ctx context.Context, branding *models.TenantBranding) error
	Delete(ctx context.Context, tenantID uuid.UUID) error
}

// TenantBrandingService manages the visual branding configuration for tenants.
// It enforces a default palette when no custom branding is present and provides
// partial-update semantics so callers only need to supply changed fields.
type TenantBrandingService struct {
	repo tenantBrandingRepo
}

// NewTenantBrandingService constructs a TenantBrandingService with the supplied repo.
func NewTenantBrandingService(repo tenantBrandingRepo) *TenantBrandingService {
	return &TenantBrandingService{repo: repo}
}

// GetBranding returns the current branding for the tenant.
// When no custom branding is stored it returns a value object populated with
// platform defaults so callers always receive a usable response.
func (s *TenantBrandingService) GetBranding(ctx context.Context, tenantID uuid.UUID) (*models.TenantBranding, error) {
	branding, err := s.repo.GetByTenantID(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("get branding: %w", err)
	}

	if branding == nil {
		return &models.TenantBranding{
			TenantID:        tenantID,
			PrimaryColor:    defaultPrimaryColor,
			BackgroundColor: defaultBackgroundColor,
		}, nil
	}

	return branding, nil
}

// UpdateBranding creates or updates the branding configuration for a tenant.
// Only non-nil fields in the request are applied; existing values are preserved
// for fields omitted from the request.
func (s *TenantBrandingService) UpdateBranding(ctx context.Context, tenantID uuid.UUID, req *models.UpdateTenantBrandingRequest) (*models.TenantBranding, error) {
	// Retrieve the current record so we can do a partial merge.
	branding, err := s.repo.GetByTenantID(ctx, tenantID)
	if err != nil {
		// Non-fatal: treat a fetch error as "no existing record" and create fresh.
		branding = nil
	}

	if branding == nil {
		branding = &models.TenantBranding{
			ID:              uuid.New(),
			TenantID:        tenantID,
			PrimaryColor:    defaultPrimaryColor,
			BackgroundColor: defaultBackgroundColor,
		}
	}

	// Apply only the fields the caller explicitly provided.
	if req.LogoURL != nil {
		branding.LogoURL = req.LogoURL
	}
	if req.FaviconURL != nil {
		branding.FaviconURL = req.FaviconURL
	}
	if req.PrimaryColor != nil {
		branding.PrimaryColor = *req.PrimaryColor
	}
	if req.BackgroundColor != nil {
		branding.BackgroundColor = *req.BackgroundColor
	}
	if req.AccentColor != nil {
		branding.AccentColor = req.AccentColor
	}
	if req.CustomCSS != nil {
		branding.CustomCSS = req.CustomCSS
	}
	if req.LoginTitle != nil {
		branding.LoginTitle = req.LoginTitle
	}
	if req.LoginSubtitle != nil {
		branding.LoginSubtitle = req.LoginSubtitle
	}
	if req.LoginMessage != nil {
		branding.LoginMessage = req.LoginMessage
	}
	if req.SupportEmail != nil {
		branding.SupportEmail = req.SupportEmail
	}
	if req.SupportURL != nil {
		branding.SupportURL = req.SupportURL
	}
	if req.PrivacyPolicyURL != nil {
		branding.PrivacyPolicyURL = req.PrivacyPolicyURL
	}
	if req.TermsOfServiceURL != nil {
		branding.TermsOfServiceURL = req.TermsOfServiceURL
	}
	if req.HideHexxlockBranding != nil {
		branding.HideHexxlockBranding = *req.HideHexxlockBranding
	}

	if err := s.repo.Upsert(ctx, branding); err != nil {
		return nil, fmt.Errorf("update branding: %w", err)
	}

	return branding, nil
}

// DeleteBranding removes the stored branding for a tenant, reverting it to
// platform defaults on the next GetBranding call.
func (s *TenantBrandingService) DeleteBranding(ctx context.Context, tenantID uuid.UUID) error {
	if err := s.repo.Delete(ctx, tenantID); err != nil {
		return fmt.Errorf("delete branding: %w", err)
	}
	return nil
}
