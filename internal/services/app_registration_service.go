// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"

	"github.com/google/uuid"
	"github.com/dogukanturhal/falcon-id/internal/models"
	"golang.org/x/crypto/bcrypt"
)

// appRegistrationServiceRepo defines the app registration repository methods needed by AppRegistrationService.
type appRegistrationServiceRepo interface {
	Create(ctx context.Context, reg *models.AppRegistration) error
	GetByID(ctx context.Context, id uuid.UUID) (*models.AppRegistration, error)
	GetByClientID(ctx context.Context, clientID string) (*models.AppRegistration, error)
	List(ctx context.Context, page, pageSize int, tenantID, productID *uuid.UUID, status string) ([]models.AppRegistration, int64, error)
	Update(ctx context.Context, id uuid.UUID, req *models.UpdateAppRegistrationRequest) (*models.AppRegistration, error)
	UpdateSecret(ctx context.Context, id uuid.UUID, secretHash string) error
	UpdateStatus(ctx context.Context, id uuid.UUID, status string) error
	Delete(ctx context.Context, id uuid.UUID) error
}

// AppRegistrationService handles app registration business logic.
type AppRegistrationService struct {
	appRegRepo   appRegistrationServiceRepo
	auditService *AuditService
}

// NewAppRegistrationService creates a new app registration service.
func NewAppRegistrationService(appRegRepo appRegistrationServiceRepo, auditService *AuditService) *AppRegistrationService {
	return &AppRegistrationService{
		appRegRepo:   appRegRepo,
		auditService: auditService,
	}
}

// Create registers a new application. It generates a client_id and client_secret,
// hashes the secret, and returns the registration along with the plain-text secret
// (the only time the secret is visible).
func (s *AppRegistrationService) Create(
	ctx context.Context,
	req *models.CreateAppRegistrationRequest,
	tenantID, createdBy uuid.UUID,
) (*models.AppRegistration, string, error) {
	clientID, err := s.generateClientID()
	if err != nil {
		return nil, "", fmt.Errorf("AppRegistrationService.Create generate client_id: %w", err)
	}

	plainSecret, secretHash, err := s.generateAndHashSecret()
	if err != nil {
		return nil, "", fmt.Errorf("AppRegistrationService.Create generate secret: %w", err)
	}

	reg := &models.AppRegistration{
		ProductID:        req.ProductID,
		TenantID:         tenantID,
		ClientID:         clientID,
		ClientSecretHash: secretHash,
		Name:             req.Name,
		Description:      req.Description,
		RedirectURIs:     req.RedirectURIs,
		AllowedOrigins:   req.AllowedOrigins,
		GrantTypes:       req.GrantTypes,
		Scopes:           req.Scopes,
		LogoURL:          req.LogoURL,
		Status:           models.AppRegistrationStatusActive,
		CreatedBy:        &createdBy,
	}

	if err := s.appRegRepo.Create(ctx, reg); err != nil {
		return nil, "", fmt.Errorf("AppRegistrationService.Create: %w", err)
	}

	return reg, plainSecret, nil
}

// GetByID retrieves an app registration by UUID.
func (s *AppRegistrationService) GetByID(ctx context.Context, id uuid.UUID) (*models.AppRegistration, error) {
	reg, err := s.appRegRepo.GetByID(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("AppRegistrationService.GetByID: %w", err)
	}
	return reg, nil
}

// GetByClientID retrieves an app registration by its OAuth client_id.
func (s *AppRegistrationService) GetByClientID(ctx context.Context, clientID string) (*models.AppRegistration, error) {
	reg, err := s.appRegRepo.GetByClientID(ctx, clientID)
	if err != nil {
		return nil, fmt.Errorf("AppRegistrationService.GetByClientID: %w", err)
	}
	return reg, nil
}

// List returns a paginated list of app registrations.
func (s *AppRegistrationService) List(
	ctx context.Context,
	page, pageSize int,
	tenantID, productID *uuid.UUID,
	status string,
) ([]models.AppRegistration, int64, error) {
	regs, total, err := s.appRegRepo.List(ctx, page, pageSize, tenantID, productID, status)
	if err != nil {
		return nil, 0, fmt.Errorf("AppRegistrationService.List: %w", err)
	}
	return regs, total, nil
}

// Update applies partial updates to an app registration.
func (s *AppRegistrationService) Update(ctx context.Context, id uuid.UUID, req *models.UpdateAppRegistrationRequest) (*models.AppRegistration, error) {
	if _, err := s.appRegRepo.GetByID(ctx, id); err != nil {
		return nil, fmt.Errorf("app registration not found: %w", err)
	}

	reg, err := s.appRegRepo.Update(ctx, id, req)
	if err != nil {
		return nil, fmt.Errorf("AppRegistrationService.Update: %w", err)
	}
	return reg, nil
}

// RotateSecret generates a new client secret, hashes it, persists the hash, and
// returns the app registration together with the new plain-text secret.
func (s *AppRegistrationService) RotateSecret(ctx context.Context, id uuid.UUID) (*models.AppRegistration, string, error) {
	if _, err := s.appRegRepo.GetByID(ctx, id); err != nil {
		return nil, "", fmt.Errorf("app registration not found: %w", err)
	}

	plainSecret, secretHash, err := s.generateAndHashSecret()
	if err != nil {
		return nil, "", fmt.Errorf("AppRegistrationService.RotateSecret generate: %w", err)
	}

	if err := s.appRegRepo.UpdateSecret(ctx, id, secretHash); err != nil {
		return nil, "", fmt.Errorf("AppRegistrationService.RotateSecret persist: %w", err)
	}

	// Re-fetch to get the updated updated_at timestamp.
	reg, err := s.appRegRepo.GetByID(ctx, id)
	if err != nil {
		return nil, "", fmt.Errorf("AppRegistrationService.RotateSecret re-fetch: %w", err)
	}

	return reg, plainSecret, nil
}

// Suspend temporarily disables an app registration.
func (s *AppRegistrationService) Suspend(ctx context.Context, id uuid.UUID) error {
	if _, err := s.appRegRepo.GetByID(ctx, id); err != nil {
		return fmt.Errorf("app registration not found: %w", err)
	}

	if err := s.appRegRepo.UpdateStatus(ctx, id, string(models.AppRegistrationStatusSuspended)); err != nil {
		return fmt.Errorf("AppRegistrationService.Suspend: %w", err)
	}
	return nil
}

// Revoke permanently cancels an app registration.
func (s *AppRegistrationService) Revoke(ctx context.Context, id uuid.UUID) error {
	if _, err := s.appRegRepo.GetByID(ctx, id); err != nil {
		return fmt.Errorf("app registration not found: %w", err)
	}

	if err := s.appRegRepo.UpdateStatus(ctx, id, string(models.AppRegistrationStatusRevoked)); err != nil {
		return fmt.Errorf("AppRegistrationService.Revoke: %w", err)
	}
	return nil
}

// Delete removes an app registration permanently.
func (s *AppRegistrationService) Delete(ctx context.Context, id uuid.UUID) error {
	if _, err := s.appRegRepo.GetByID(ctx, id); err != nil {
		return fmt.Errorf("app registration not found: %w", err)
	}

	if err := s.appRegRepo.Delete(ctx, id); err != nil {
		return fmt.Errorf("AppRegistrationService.Delete: %w", err)
	}
	return nil
}

// generateClientID creates a unique client ID with the "app_" prefix.
func (s *AppRegistrationService) generateClientID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "app_" + hex.EncodeToString(b), nil
}

// generateAndHashSecret creates a random plain-text secret and its bcrypt hash.
func (s *AppRegistrationService) generateAndHashSecret() (plain string, hash string, err error) {
	b := make([]byte, 32)
	if _, err = rand.Read(b); err != nil {
		return
	}
	plain = hex.EncodeToString(b)

	hashBytes, err := bcrypt.GenerateFromPassword([]byte(plain), bcrypt.DefaultCost)
	if err != nil {
		return
	}
	hash = string(hashBytes)
	return
}
