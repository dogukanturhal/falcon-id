// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

// appConsentRepo defines the consent repository methods.
type appConsentRepo interface {
	Upsert(ctx context.Context, consent *models.AppConsent) error
	Revoke(ctx context.Context, id uuid.UUID) error
	RevokeByAppAndTenant(ctx context.Context, appID, tenantID uuid.UUID) error
	HasConsent(ctx context.Context, appID, tenantID uuid.UUID) (bool, error)
	ListByApp(ctx context.Context, appID uuid.UUID) ([]models.AppConsent, error)
	ListByTenant(ctx context.Context, tenantID uuid.UUID) ([]models.AppConsent, error)
}

// AppConsentService manages application consent lifecycle.
type AppConsentService struct {
	consentRepo appConsentRepo
}

// NewAppConsentService creates a new AppConsentService.
func NewAppConsentService(consentRepo appConsentRepo) *AppConsentService {
	return &AppConsentService{consentRepo: consentRepo}
}

// GrantAdminConsent grants admin-level consent for an app in a tenant (covers all users).
func (s *AppConsentService) GrantAdminConsent(ctx context.Context, appID, tenantID, consentedBy uuid.UUID, scopes []string) (*models.AppConsent, error) {
	if scopes == nil {
		scopes = []string{}
	}

	consent := &models.AppConsent{
		ID:            uuid.New(),
		ApplicationID: appID,
		TenantID:      tenantID,
		ConsentedBy:   consentedBy,
		ConsentType:   models.AppConsentTypeAdmin,
		Scopes:        scopes,
		Status:        models.AppConsentStatusGranted,
		GrantedAt:     time.Now(),
	}

	if err := s.consentRepo.Upsert(ctx, consent); err != nil {
		return nil, fmt.Errorf("AppConsentService.GrantAdminConsent: %w", err)
	}
	return consent, nil
}

// GrantUserConsent grants user-level consent for an app (individual scope).
func (s *AppConsentService) GrantUserConsent(ctx context.Context, appID, tenantID, consentedBy uuid.UUID, scopes []string) (*models.AppConsent, error) {
	if scopes == nil {
		scopes = []string{}
	}

	consent := &models.AppConsent{
		ID:            uuid.New(),
		ApplicationID: appID,
		TenantID:      tenantID,
		ConsentedBy:   consentedBy,
		ConsentType:   models.AppConsentTypeUser,
		Scopes:        scopes,
		Status:        models.AppConsentStatusGranted,
		GrantedAt:     time.Now(),
	}

	if err := s.consentRepo.Upsert(ctx, consent); err != nil {
		return nil, fmt.Errorf("AppConsentService.GrantUserConsent: %w", err)
	}
	return consent, nil
}

// RevokeConsent soft-revokes a specific consent record.
func (s *AppConsentService) RevokeConsent(ctx context.Context, id uuid.UUID) error {
	if err := s.consentRepo.Revoke(ctx, id); err != nil {
		return fmt.Errorf("AppConsentService.RevokeConsent: %w", err)
	}
	return nil
}

// RevokeAllForAppInTenant revokes all consents for an app in a tenant.
func (s *AppConsentService) RevokeAllForAppInTenant(ctx context.Context, appID, tenantID uuid.UUID) error {
	if err := s.consentRepo.RevokeByAppAndTenant(ctx, appID, tenantID); err != nil {
		return fmt.Errorf("AppConsentService.RevokeAllForAppInTenant: %w", err)
	}
	return nil
}

// HasConsent checks if an app has active admin consent in a tenant.
func (s *AppConsentService) HasConsent(ctx context.Context, appID, tenantID uuid.UUID) (bool, error) {
	has, err := s.consentRepo.HasConsent(ctx, appID, tenantID)
	if err != nil {
		return false, fmt.Errorf("AppConsentService.HasConsent: %w", err)
	}
	return has, nil
}

// ListByApp returns all consents for an application.
func (s *AppConsentService) ListByApp(ctx context.Context, appID uuid.UUID) ([]models.AppConsent, error) {
	consents, err := s.consentRepo.ListByApp(ctx, appID)
	if err != nil {
		return nil, fmt.Errorf("AppConsentService.ListByApp: %w", err)
	}
	return consents, nil
}

// ListByTenant returns all consents for a tenant.
func (s *AppConsentService) ListByTenant(ctx context.Context, tenantID uuid.UUID) ([]models.AppConsent, error) {
	consents, err := s.consentRepo.ListByTenant(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("AppConsentService.ListByTenant: %w", err)
	}
	return consents, nil
}
