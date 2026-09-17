// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

const (
	appAudienceSingleTenant = "single_tenant"
	appAudienceMultiTenant  = "multi_tenant"
)

// applicationServiceRepo defines the application repository methods needed by ApplicationService.
type applicationServiceRepo interface {
	Create(ctx context.Context, app *models.Application) error
	GetByID(ctx context.Context, id uuid.UUID) (*models.Application, error)
	GetByIDIncludeDeleted(ctx context.Context, id uuid.UUID) (*models.Application, error)
	GetBySlug(ctx context.Context, slug string) (*models.Application, error)
	List(ctx context.Context, page, pageSize int, status, publisherType string, isPlatformApp *bool) ([]models.Application, int64, error)
	Update(ctx context.Context, id uuid.UUID, req *models.UpdateApplicationRequest) (*models.Application, error)
	Delete(ctx context.Context, id uuid.UUID) error
	GetPreauthorized(ctx context.Context) ([]models.Application, error)
	CountServicePrincipals(ctx context.Context, appID uuid.UUID) (int64, error)
	UpdatePublisherVerification(ctx context.Context, id uuid.UUID, verified bool, domain *string) error
	SoftDelete(ctx context.Context, id uuid.UUID) error
	Restore(ctx context.Context, id uuid.UUID) error
	PurgeExpired(ctx context.Context) (int64, error)
	ListDeleted(ctx context.Context) ([]models.Application, error)
	SoftDeleteSP(ctx context.Context, spID uuid.UUID) error
	RestoreSP(ctx context.Context, spID uuid.UUID) error
}

// applicationServiceSPRepo defines the service principal repository methods needed for provisioning.
type applicationServiceSPRepo interface {
	Create(ctx context.Context, sp *models.ServicePrincipal) error
	GetByID(ctx context.Context, id uuid.UUID) (*models.ServicePrincipal, error)
	GetByApplicationAndTenant(ctx context.Context, appID, tenantID uuid.UUID) (*models.ServicePrincipal, error)
	ListByApplication(ctx context.Context, appID uuid.UUID) ([]models.ServicePrincipal, error)
	ListByTenant(ctx context.Context, tenantID uuid.UUID) ([]models.ServicePrincipal, error)
	Update(ctx context.Context, sp *models.ServicePrincipal) error
	Delete(ctx context.Context, id uuid.UUID) error
}

// applicationServiceAppRegCreator creates OAuth app registrations (client_id + secret).
type applicationServiceAppRegCreator interface {
	Create(ctx context.Context, req *models.CreateAppRegistrationRequest, tenantID, createdBy uuid.UUID) (*models.AppRegistration, string, error)
}

// applicationServiceWebhookTrigger fires webhook events.
type applicationServiceWebhookTrigger interface {
	TriggerEvent(ctx context.Context, event *models.WebhookEvent) error
}

// applicationServiceConsentChecker verifies that a tenant has granted admin
// consent for a given application before a service principal is provisioned.
type applicationServiceConsentChecker interface {
	HasConsent(ctx context.Context, appID, tenantID uuid.UUID) (bool, error)
}

// ApplicationService handles Application Object business logic.
type ApplicationService struct {
	appRepo        applicationServiceRepo
	spRepo         applicationServiceSPRepo
	appRegService  applicationServiceAppRegCreator
	webhookService applicationServiceWebhookTrigger
	consentService applicationServiceConsentChecker
}

// NewApplicationService creates a new application service.
func NewApplicationService(appRepo applicationServiceRepo, spRepo applicationServiceSPRepo) *ApplicationService {
	return &ApplicationService{
		appRepo: appRepo,
		spRepo:  spRepo,
	}
}

// SetAppRegService wires the app registration service for credential creation.
func (s *ApplicationService) SetAppRegService(svc applicationServiceAppRegCreator) {
	s.appRegService = svc
}

// SetWebhookService wires the webhook service for lifecycle events.
func (s *ApplicationService) SetWebhookService(svc applicationServiceWebhookTrigger) {
	s.webhookService = svc
}

// SetAppConsentService wires the consent checker used by ProvisionServicePrincipal
// to enforce admin-consent gating for multi-tenant third-party applications.
func (s *ApplicationService) SetAppConsentService(svc applicationServiceConsentChecker) {
	s.consentService = svc
}

// ============================================================================
// CRUD
// ============================================================================

// Create registers a new Application Object.
func (s *ApplicationService) Create(ctx context.Context, req *models.CreateApplicationRequest, createdBy *uuid.UUID) (*models.Application, error) {
	app := &models.Application{
		ID:                uuid.New(),
		DisplayName:       req.DisplayName,
		Slug:              req.Slug,
		Description:       req.Description,
		LogoURL:           req.LogoURL,
		HomepageURL:       req.HomepageURL,
		PrivacyPolicyURL:  req.PrivacyPolicyURL,
		TermsOfServiceURL: req.TermsOfServiceURL,
		AppType:           req.AppType,
		PublisherType:     req.PublisherType,
		SignInAudience:    req.SignInAudience,
		RedirectURIs:      req.RedirectURIs,
		PostLogoutURIs:    req.PostLogoutURIs,
		AllowedGrantTypes: req.AllowedGrantTypes,
		DefaultScopes:     req.DefaultScopes,
		IsPublic:          req.IsPublic,
		RequirePKCE:       req.RequirePKCE,
		Preauthorized:     req.Preauthorized,
		Status:            models.ApplicationStatusActive,
		Tags:              req.Tags,
		Metadata:          []byte("{}"),
		CreatedBy:         createdBy,
	}

	// Apply defaults
	if app.PublisherType == "" {
		app.PublisherType = models.ApplicationPublisherThirdParty
	}
	if app.SignInAudience == "" {
		app.SignInAudience = appAudienceSingleTenant
	}
	if app.AllowedGrantTypes == nil {
		app.AllowedGrantTypes = []string{"authorization_code", "refresh_token"}
	}
	if app.DefaultScopes == nil {
		app.DefaultScopes = []string{"openid", "profile", "email"}
	}
	if app.RedirectURIs == nil {
		app.RedirectURIs = []string{}
	}
	if app.PostLogoutURIs == nil {
		app.PostLogoutURIs = []string{}
	}
	if app.Tags == nil {
		app.Tags = []string{}
	}

	// Token lifetimes
	if req.AccessTokenLifetime != nil {
		app.AccessTokenLifetime = *req.AccessTokenLifetime
	} else {
		app.AccessTokenLifetime = 3600
	}
	if req.RefreshTokenLifetime != nil {
		app.RefreshTokenLifetime = *req.RefreshTokenLifetime
	} else {
		app.RefreshTokenLifetime = 86400
	}
	if req.IDTokenLifetime != nil {
		app.IDTokenLifetime = *req.IDTokenLifetime
	} else {
		app.IDTokenLifetime = 3600
	}

	if err := s.appRepo.Create(ctx, app); err != nil {
		return nil, fmt.Errorf("ApplicationService.Create: %w", err)
	}

	s.fireWebhook(ctx, "application.created", uuid.Nil, map[string]interface{}{
		"application_id": app.ID.String(),
		"display_name":   app.DisplayName,
	})

	return app, nil
}

// GetByID retrieves an application by UUID.
func (s *ApplicationService) GetByID(ctx context.Context, id uuid.UUID) (*models.Application, error) {
	app, err := s.appRepo.GetByID(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("ApplicationService.GetByID: %w", err)
	}
	return app, nil
}

// GetBySlug retrieves an application by slug.
func (s *ApplicationService) GetBySlug(ctx context.Context, slug string) (*models.Application, error) {
	app, err := s.appRepo.GetBySlug(ctx, slug)
	if err != nil {
		return nil, fmt.Errorf("ApplicationService.GetBySlug: %w", err)
	}
	return app, nil
}

// List returns a paginated list of applications with optional filters.
func (s *ApplicationService) List(ctx context.Context, page, pageSize int, status, publisherType string, isPlatformApp *bool) ([]models.Application, int64, error) {
	apps, total, err := s.appRepo.List(ctx, page, pageSize, status, publisherType, isPlatformApp)
	if err != nil {
		return nil, 0, fmt.Errorf("ApplicationService.List: %w", err)
	}
	return apps, total, nil
}

// Update applies partial updates to an application.
func (s *ApplicationService) Update(ctx context.Context, id uuid.UUID, req *models.UpdateApplicationRequest) (*models.Application, error) {
	if _, err := s.appRepo.GetByID(ctx, id); err != nil {
		return nil, fmt.Errorf("application not found: %w", err)
	}

	app, err := s.appRepo.Update(ctx, id, req)
	if err != nil {
		return nil, fmt.Errorf("ApplicationService.Update: %w", err)
	}

	s.fireWebhook(ctx, "application.updated", uuid.Nil, map[string]interface{}{
		"application_id": id.String(),
	})

	return app, nil
}

// Delete initiates a soft-delete for an application (sets deleted_at + purge_after).
// If the application is already soft-deleted (within its grace period), the
// second call hard-deletes it immediately — matching the "confirm deletion" UX
// used by services like GitHub repository deletion.
func (s *ApplicationService) Delete(ctx context.Context, id uuid.UUID) error {
	app, err := s.appRepo.GetByIDIncludeDeleted(ctx, id)
	if err != nil {
		return fmt.Errorf("application not found: %w", err)
	}

	// Already soft-deleted within grace period — hard-delete on second call.
	if app.DeletedAt != nil {
		if err := s.appRepo.Delete(ctx, id); err != nil {
			return fmt.Errorf("ApplicationService.Delete (hard): %w", err)
		}
		s.fireWebhook(ctx, "application.purged", uuid.Nil, map[string]interface{}{
			"application_id": id.String(),
		})
		return nil
	}

	// First call — soft-delete.
	return s.SoftDelete(ctx, id)
}

// SoftDelete marks an application as deleted with a 30-day grace period before
// permanent removal. The application is hidden from normal queries immediately.
func (s *ApplicationService) SoftDelete(ctx context.Context, id uuid.UUID) error {
	if _, err := s.appRepo.GetByID(ctx, id); err != nil {
		return fmt.Errorf("application not found: %w", err)
	}

	if err := s.appRepo.SoftDelete(ctx, id); err != nil {
		return fmt.Errorf("ApplicationService.SoftDelete: %w", err)
	}

	s.fireWebhook(ctx, "application.deleted", uuid.Nil, map[string]interface{}{
		"application_id": id.String(),
	})

	return nil
}

// Restore cancels a pending soft-delete, making the application active again.
// Returns an error if the 30-day purge window has already elapsed.
func (s *ApplicationService) Restore(ctx context.Context, id uuid.UUID) (*models.Application, error) {
	if err := s.appRepo.Restore(ctx, id); err != nil {
		if err.Error() == "ApplicationRepository.Restore: application not found, already restored, or purge window has elapsed" {
			return nil, fmt.Errorf("ApplicationService.Restore: application cannot be restored — not found or purge window has elapsed")
		}
		return nil, fmt.Errorf("ApplicationService.Restore: %w", err)
	}

	app, err := s.appRepo.GetByID(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("ApplicationService.Restore: failed to reload application: %w", err)
	}

	s.fireWebhook(ctx, "application.restored", uuid.Nil, map[string]interface{}{
		"application_id": id.String(),
	})

	return app, nil
}

// PurgeExpired hard-deletes all applications whose 30-day grace period has passed.
// Returns the number of records permanently removed. Intended to be called by
// the background purge task.
func (s *ApplicationService) PurgeExpired(ctx context.Context) (int64, error) {
	count, err := s.appRepo.PurgeExpired(ctx)
	if err != nil {
		return 0, fmt.Errorf("ApplicationService.PurgeExpired: %w", err)
	}
	return count, nil
}

// ListDeleted returns all soft-deleted applications still within their grace period.
func (s *ApplicationService) ListDeleted(ctx context.Context) ([]models.Application, error) {
	apps, err := s.appRepo.ListDeleted(ctx)
	if err != nil {
		return nil, fmt.Errorf("ApplicationService.ListDeleted: %w", err)
	}
	return apps, nil
}

// ============================================================================
// SP Provisioning & Lifecycle
// ============================================================================

// ProvisionServicePrincipal creates a service principal for an application in a given tenant.
// Idempotent: if the SP already exists for this (app, tenant) pair, returns it.
// Phase 2: generates OAuth credentials and RSA key on provisioning.
func (s *ApplicationService) ProvisionServicePrincipal(ctx context.Context, appID, tenantID uuid.UUID, scopeOverrides []string) (*models.ProvisionServicePrincipalResponse, error) {
	// Check if already provisioned
	existing, err := s.spRepo.GetByApplicationAndTenant(ctx, appID, tenantID)
	if err == nil && existing != nil {
		return &models.ProvisionServicePrincipalResponse{
			ServicePrincipal: existing.ToResponse(),
		}, nil
	}

	// Get the application object
	app, err := s.appRepo.GetByID(ctx, appID)
	if err != nil {
		return nil, fmt.Errorf("ApplicationService.ProvisionServicePrincipal: app not found: %w", err)
	}

	if app.Status != models.ApplicationStatusActive {
		return nil, fmt.Errorf("ApplicationService.ProvisionServicePrincipal: application is not active (status=%s)", app.Status)
	}

	// C5: Sign-in audience enforcement
	if err := s.enforceAudience(app, tenantID); err != nil {
		return nil, err
	}

	// Consent gate: multi-tenant third-party apps must have admin consent in the
	// target tenant before a service principal is provisioned.
	// First-party apps and preauthorized apps are exempt — they are controlled
	// directly by HexxLock and do not require explicit tenant admin consent.
	if s.consentService != nil && !app.IsFirstParty() && !app.Preauthorized {
		hasConsent, consentErr := s.consentService.HasConsent(ctx, app.ID, tenantID)
		if consentErr != nil {
			return nil, fmt.Errorf("ApplicationService.ProvisionServicePrincipal: consent check failed: %w", consentErr)
		}
		if !hasConsent {
			return nil, fmt.Errorf("ApplicationService.ProvisionServicePrincipal: tenant %s has not granted admin consent for application %s", tenantID, app.ID)
		}
	}

	now := time.Now()
	sp := &models.ServicePrincipal{
		ID:                 uuid.New(),
		Name:               app.DisplayName + " (provisioned)",
		Slug:               app.Slug + "-" + tenantID.String()[:8],
		Description:        fmt.Sprintf("Auto-provisioned SP for %s", app.DisplayName),
		PublicKeyPEM:       "",
		KeyID:              "",
		AllowedScopes:      app.DefaultScopes,
		IPAllowlist:        []string{},
		Status:             "active",
		CreatedAt:          now,
		UpdatedAt:          now,
		Type:               models.SPTypeApplication,
		ApplicationID:      &appID,
		TenantID:           &tenantID,
		InstallationStatus: models.SPInstallStatusEnabled,
		ScopeOverrides:     scopeOverrides,
	}

	// Generate RSA keypair for the SP
	pubPEM, keyID, err := generateRSAKeyPair()
	if err == nil {
		sp.PublicKeyPEM = pubPEM
		sp.KeyID = keyID
	}

	if err := s.spRepo.Create(ctx, sp); err != nil {
		return nil, fmt.Errorf("ApplicationService.ProvisionServicePrincipal: %w", err)
	}

	resp := &models.ProvisionServicePrincipalResponse{
		ServicePrincipal: sp.ToResponse(),
	}

	// Generate OAuth credentials via AppRegistrationService if wired
	if s.appRegService != nil && sp.TenantID != nil {
		desc := sp.Description
		appRegReq := &models.CreateAppRegistrationRequest{
			Name:         sp.Name,
			Description:  &desc,
			GrantTypes:   app.AllowedGrantTypes,
			Scopes:       app.DefaultScopes,
			RedirectURIs: app.RedirectURIs,
		}
		reg, plainSecret, regErr := s.appRegService.Create(ctx, appRegReq, *sp.TenantID, sp.ID)
		if regErr == nil && reg != nil {
			resp.ClientID = reg.ClientID
			resp.ClientSecret = plainSecret
			// Link the OAuth client to the SP
			sp.OAuthClientID = &reg.ID
			_ = s.spRepo.Update(ctx, sp)
		}
	}

	s.fireWebhook(ctx, "sp.provisioned", tenantID, map[string]interface{}{
		"application_id":       appID.String(),
		"service_principal_id": sp.ID.String(),
		"tenant_id":            tenantID.String(),
	})

	return resp, nil
}

// EnableSP enables a service principal (installed/disabled → enabled).
func (s *ApplicationService) EnableSP(ctx context.Context, appID, spID uuid.UUID) (*models.ServicePrincipal, error) {
	sp, err := s.getSPForApp(ctx, appID, spID)
	if err != nil {
		return nil, err
	}

	if err := ValidateStatusTransition(sp.InstallationStatus, models.SPInstallStatusEnabled); err != nil {
		return nil, fmt.Errorf("ApplicationService.EnableSP: %w", err)
	}

	sp.InstallationStatus = models.SPInstallStatusEnabled
	sp.UpdatedAt = time.Now()
	if err := s.spRepo.Update(ctx, sp); err != nil {
		return nil, fmt.Errorf("ApplicationService.EnableSP: %w", err)
	}

	tenantID := uuid.Nil
	if sp.TenantID != nil {
		tenantID = *sp.TenantID
	}
	s.fireWebhook(ctx, "sp.enabled", tenantID, map[string]interface{}{
		"service_principal_id": sp.ID.String(),
	})

	return sp, nil
}

// DisableSP disables a service principal (enabled → disabled).
func (s *ApplicationService) DisableSP(ctx context.Context, appID, spID uuid.UUID) (*models.ServicePrincipal, error) {
	sp, err := s.getSPForApp(ctx, appID, spID)
	if err != nil {
		return nil, err
	}

	if err := ValidateStatusTransition(sp.InstallationStatus, models.SPInstallStatusDisabled); err != nil {
		return nil, fmt.Errorf("ApplicationService.DisableSP: %w", err)
	}

	sp.InstallationStatus = models.SPInstallStatusDisabled
	sp.UpdatedAt = time.Now()
	if err := s.spRepo.Update(ctx, sp); err != nil {
		return nil, fmt.Errorf("ApplicationService.DisableSP: %w", err)
	}

	tenantID := uuid.Nil
	if sp.TenantID != nil {
		tenantID = *sp.TenantID
	}
	s.fireWebhook(ctx, "sp.disabled", tenantID, map[string]interface{}{
		"service_principal_id": sp.ID.String(),
	})

	return sp, nil
}

// GetSP retrieves a single SP belonging to an application.
func (s *ApplicationService) GetSP(ctx context.Context, appID, spID uuid.UUID) (*models.ServicePrincipal, error) {
	return s.getSPForApp(ctx, appID, spID)
}

// DeleteSP hard-deletes a service principal.
func (s *ApplicationService) DeleteSP(ctx context.Context, appID, spID uuid.UUID) error {
	sp, err := s.getSPForApp(ctx, appID, spID)
	if err != nil {
		return err
	}

	if err := s.spRepo.Delete(ctx, sp.ID); err != nil {
		return fmt.Errorf("ApplicationService.DeleteSP: %w", err)
	}
	return nil
}

// RotateSPCredentials generates new RSA keypair and OAuth secret for an SP.
func (s *ApplicationService) RotateSPCredentials(ctx context.Context, appID, spID uuid.UUID) (*models.ProvisionServicePrincipalResponse, error) {
	sp, err := s.getSPForApp(ctx, appID, spID)
	if err != nil {
		return nil, err
	}

	// Rotate RSA key
	pubPEM, keyID, err := generateRSAKeyPair()
	if err != nil {
		return nil, fmt.Errorf("ApplicationService.RotateSPCredentials: keygen failed: %w", err)
	}

	sp.PublicKeyPEM = pubPEM
	sp.KeyID = keyID
	sp.UpdatedAt = time.Now()

	if err := s.spRepo.Update(ctx, sp); err != nil {
		return nil, fmt.Errorf("ApplicationService.RotateSPCredentials: update failed: %w", err)
	}

	resp := &models.ProvisionServicePrincipalResponse{
		ServicePrincipal: sp.ToResponse(),
	}

	// Rotate OAuth secret via new AppRegistration
	if s.appRegService != nil && sp.TenantID != nil {
		rotatedDesc := sp.Description
		regReq := &models.CreateAppRegistrationRequest{
			Name:        sp.Name + " (rotated)",
			Description: &rotatedDesc,
		}
		reg, plainSecret, regErr := s.appRegService.Create(ctx, regReq, *sp.TenantID, sp.ID)
		if regErr == nil && reg != nil {
			resp.ClientID = reg.ClientID
			resp.ClientSecret = plainSecret
			sp.OAuthClientID = &reg.ID
			_ = s.spRepo.Update(ctx, sp)
		}
	}

	tenantID := uuid.Nil
	if sp.TenantID != nil {
		tenantID = *sp.TenantID
	}
	s.fireWebhook(ctx, "sp.credentials.rotated", tenantID, map[string]interface{}{
		"service_principal_id": sp.ID.String(),
	})

	return resp, nil
}

// ListServicePrincipals returns all SPs for an application across tenants.
func (s *ApplicationService) ListServicePrincipals(ctx context.Context, appID uuid.UUID) ([]models.ServicePrincipal, error) {
	sps, err := s.spRepo.ListByApplication(ctx, appID)
	if err != nil {
		return nil, fmt.Errorf("ApplicationService.ListServicePrincipals: %w", err)
	}
	return sps, nil
}

// ListSPsByTenant returns all SPs for a given tenant across applications.
func (s *ApplicationService) ListSPsByTenant(ctx context.Context, tenantID uuid.UUID) ([]models.ServicePrincipal, error) {
	sps, err := s.spRepo.ListByTenant(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("ApplicationService.ListSPsByTenant: %w", err)
	}
	return sps, nil
}

// GetServicePrincipalCount returns the count of SPs for an application.
func (s *ApplicationService) GetServicePrincipalCount(ctx context.Context, appID uuid.UUID) (int64, error) {
	return s.appRepo.CountServicePrincipals(ctx, appID)
}

// ============================================================================
// Publisher Verification (C1)
// ============================================================================

// VerifyPublisher marks an application as publisher-verified with a domain.
func (s *ApplicationService) VerifyPublisher(ctx context.Context, id uuid.UUID, domain string) (*models.Application, error) {
	if _, err := s.appRepo.GetByID(ctx, id); err != nil {
		return nil, fmt.Errorf("application not found: %w", err)
	}

	if err := s.appRepo.UpdatePublisherVerification(ctx, id, true, &domain); err != nil {
		return nil, fmt.Errorf("ApplicationService.VerifyPublisher: %w", err)
	}

	return s.appRepo.GetByID(ctx, id)
}

// RevokeVerification removes publisher verification from an application.
func (s *ApplicationService) RevokeVerification(ctx context.Context, id uuid.UUID) (*models.Application, error) {
	if _, err := s.appRepo.GetByID(ctx, id); err != nil {
		return nil, fmt.Errorf("application not found: %w", err)
	}

	if err := s.appRepo.UpdatePublisherVerification(ctx, id, false, nil); err != nil {
		return nil, fmt.Errorf("ApplicationService.RevokeVerification: %w", err)
	}

	return s.appRepo.GetByID(ctx, id)
}

// ============================================================================
// Bulk Provisioning (C2)
// ============================================================================

// BulkProvisionServicePrincipals provisions SPs across multiple tenants.
func (s *ApplicationService) BulkProvisionServicePrincipals(ctx context.Context, appID uuid.UUID, tenantIDs []uuid.UUID) []models.BulkProvisionResult {
	results := make([]models.BulkProvisionResult, 0, len(tenantIDs))

	for _, tenantID := range tenantIDs {
		resp, err := s.ProvisionServicePrincipal(ctx, appID, tenantID, nil)
		result := models.BulkProvisionResult{
			TenantID: tenantID,
		}
		if err != nil {
			result.Success = false
			result.Error = err.Error()
		} else {
			result.Success = true
			result.SP = resp
		}
		results = append(results, result)
	}

	return results
}

// ============================================================================
// State Machine (B1)
// ============================================================================

// ValidateStatusTransition validates the installation status transition.
// Valid transitions:
//
//	installed → enabled
//	enabled → disabled
//	disabled → enabled
//	disabled → uninstalled
func ValidateStatusTransition(from, to models.ServicePrincipalInstallStatus) error {
	validTransitions := map[models.ServicePrincipalInstallStatus][]models.ServicePrincipalInstallStatus{
		models.SPInstallStatusInstalled: {models.SPInstallStatusEnabled},
		models.SPInstallStatusEnabled:   {models.SPInstallStatusDisabled},
		models.SPInstallStatusDisabled:  {models.SPInstallStatusEnabled, models.SPInstallStatusUninstalled},
	}

	allowed, ok := validTransitions[from]
	if !ok {
		return fmt.Errorf("invalid transition: cannot transition from %q", from)
	}

	for _, a := range allowed {
		if a == to {
			return nil
		}
	}

	return fmt.Errorf("invalid transition: %q → %q is not allowed", from, to)
}

// ============================================================================
// Audience Enforcement (C5)
// ============================================================================

func (s *ApplicationService) enforceAudience(app *models.Application, tenantID uuid.UUID) error {
	switch app.SignInAudience {
	case appAudienceSingleTenant:
		// Only the app owner's tenant or first-party apps may provision
		if app.IsFirstParty() {
			return nil
		}
		if app.CreatedBy != nil && *app.CreatedBy == tenantID {
			return nil
		}
		return fmt.Errorf("ApplicationService.ProvisionServicePrincipal: single_tenant audience blocks cross-tenant provisioning for app %s", app.ID)
	case appAudienceMultiTenant:
		return nil
	case "personal_accounts":
		return fmt.Errorf("ApplicationService.ProvisionServicePrincipal: personal_accounts audience is not supported")
	default:
		return nil
	}
}

// ============================================================================
// Internal helpers
// ============================================================================

// getSPForApp retrieves an SP and validates it belongs to the given application.
func (s *ApplicationService) getSPForApp(ctx context.Context, appID, spID uuid.UUID) (*models.ServicePrincipal, error) {
	sp, err := s.spRepo.GetByID(ctx, spID)
	if err != nil {
		return nil, fmt.Errorf("service principal not found: %w", err)
	}

	if sp.ApplicationID == nil || *sp.ApplicationID != appID {
		return nil, fmt.Errorf("service principal %s does not belong to application %s", spID, appID)
	}

	return sp, nil
}

// fireWebhook fires a webhook event if the webhook service is wired.
func (s *ApplicationService) fireWebhook(ctx context.Context, eventType string, tenantID uuid.UUID, data map[string]interface{}) {
	if s.webhookService == nil {
		return
	}

	event := &models.WebhookEvent{
		ID:        uuid.New().String(),
		Type:      models.WebhookEventType(eventType),
		TenantID:  tenantID,
		Timestamp: time.Now(),
		Data:      data,
	}
	// Best-effort: don't fail the main operation on webhook errors
	_ = s.webhookService.TriggerEvent(ctx, event)
}

// generateRSAKeyPair generates a 2048-bit RSA keypair and returns the public PEM and key ID.
func generateRSAKeyPair() (pubPEM string, keyID string, err error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", "", fmt.Errorf("generateRSAKeyPair: %w", err)
	}

	pubDER, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return "", "", fmt.Errorf("generateRSAKeyPair marshal: %w", err)
	}

	pubPEM = string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}))
	hash := sha256.Sum256(pubDER)
	keyID = base64.RawURLEncoding.EncodeToString(hash[:12])
	return pubPEM, keyID, nil
}
