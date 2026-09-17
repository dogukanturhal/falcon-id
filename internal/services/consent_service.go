// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/pkg/logger"
	"go.uber.org/zap"
)

// consentServiceConsentRepo defines the consent repository methods needed by ConsentService.
type consentServiceConsentRepo interface {
	GetConsentTypes(ctx context.Context, tenantID uuid.UUID) ([]models.ConsentType, error)
	GetUserConsents(ctx context.Context, userID uuid.UUID, tenantID uuid.UUID) ([]models.UserConsentWithType, error)
	GetPendingRequiredConsents(ctx context.Context, userID, tenantID uuid.UUID) ([]models.ConsentType, error)
	GetConsentTypeByName(ctx context.Context, tenantID uuid.UUID, name string) (*models.ConsentType, error)
	GetUserConsent(ctx context.Context, userID, consentTypeID uuid.UUID) (*models.UserConsent, error)
	UpsertConsent(ctx context.Context, consent *models.UserConsent) error
	GetConsentTypeByID(ctx context.Context, id uuid.UUID) (*models.ConsentType, error)
	HasGrantedAllRequired(ctx context.Context, userID, tenantID uuid.UUID) (bool, error)
	DeleteUserConsents(ctx context.Context, userID uuid.UUID) error
	GetConsentHistory(ctx context.Context, userID uuid.UUID, since time.Time) ([]models.UserConsentWithType, error)
	GetConsentHistoryDetailed(ctx context.Context, userID uuid.UUID, tenantID uuid.UUID, limit int) ([]models.ConsentHistoryWithType, error)
}

// ConsentService is an exported type.
type ConsentService struct {
	consentRepo  consentServiceConsentRepo
	auditService *AuditService
}

// NewConsentService is an exported function.
func NewConsentService(
	consentRepo consentServiceConsentRepo,
	auditService *AuditService,
) *ConsentService {
	return &ConsentService{
		consentRepo:  consentRepo,
		auditService: auditService,
	}
}

// GetConsentTypes returns all active consent types for a tenant
func (s *ConsentService) GetConsentTypes(ctx context.Context, tenantID uuid.UUID) ([]models.ConsentType, error) {
	return s.consentRepo.GetConsentTypes(ctx, tenantID)
}

// GetUserConsents returns all consents for a user with pending required consents
func (s *ConsentService) GetUserConsents(ctx context.Context, userID, tenantID uuid.UUID) (*models.ConsentListResponse, error) {
	// Get user's existing consents
	consents, err := s.consentRepo.GetUserConsents(ctx, userID, tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user consents: %w", err)
	}

	// Get pending required consents
	pendingRequired, err := s.consentRepo.GetPendingRequiredConsents(ctx, userID, tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to get pending required consents: %w", err)
	}

	// Convert to response format
	consentResponses := make([]models.UserConsentResponse, len(consents))
	for i, c := range consents {
		consentResponses[i] = *c.ToResponse()
	}

	pendingResponses := make([]models.ConsentTypeResponse, len(pendingRequired))
	for i, p := range pendingRequired {
		pendingResponses[i] = *p.ToResponse()
	}

	return &models.ConsentListResponse{
		Consents:           consentResponses,
		PendingRequired:    pendingResponses,
		HasPendingRequired: len(pendingRequired) > 0,
	}, nil
}

// UpdateConsent grants or revokes a specific consent
func (s *ConsentService) UpdateConsent(
	ctx context.Context,
	userID, tenantID uuid.UUID,
	consentTypeName string,
	granted bool,
	ipAddress, userAgent string,
) error {
	// Get consent type by name
	consentType, err := s.consentRepo.GetConsentTypeByName(ctx, tenantID, consentTypeName)
	if err != nil {
		return fmt.Errorf("failed to get consent type: %w", err)
	}
	if consentType == nil {
		return fmt.Errorf("consent type not found: %s", consentTypeName)
	}

	// Check if trying to revoke required consent
	if consentType.IsRequired && !granted {
		return fmt.Errorf("cannot revoke required consent: %s", consentTypeName)
	}

	// Get existing consent if any
	existingConsent, err := s.consentRepo.GetUserConsent(ctx, userID, consentType.ID)
	if err != nil {
		return fmt.Errorf("failed to check existing consent: %w", err)
	}

	now := time.Now()
	consent := &models.UserConsent{
		UserID:         userID,
		ConsentTypeID:  consentType.ID,
		Granted:        granted,
		ConsentVersion: consentType.Version,
		IPAddress:      &ipAddress,
		UserAgent:      &userAgent,
	}

	if existingConsent != nil {
		consent.ID = existingConsent.ID
	}

	if granted {
		consent.GrantedAt = &now
	} else {
		consent.RevokedAt = &now
	}

	if err := s.consentRepo.UpsertConsent(ctx, consent); err != nil {
		return fmt.Errorf("failed to update consent: %w", err)
	}

	// Log audit event
	action := "consent_granted"
	if !granted {
		action = "consent_revoked"
	}
	s.auditService.LogUserAction(ctx, tenantID, &userID, &userID, action, true, map[string]interface{}{
		"consent_type": consentTypeName,
		"version":      consentType.Version,
	})

	logger.Info("Consent updated",
		zap.String("user_id", userID.String()),
		zap.String("consent_type", consentTypeName),
		zap.Bool("granted", granted),
	)

	return nil
}

// UpdateConsentByID grants or revokes a consent by consent type ID
func (s *ConsentService) UpdateConsentByID(
	ctx context.Context,
	userID uuid.UUID,
	tenantID uuid.UUID,
	consentTypeID uuid.UUID,
	granted bool,
	ipAddress, userAgent string,
) error {
	// Get consent type
	consentType, err := s.consentRepo.GetConsentTypeByID(ctx, consentTypeID)
	if err != nil {
		return fmt.Errorf("failed to get consent type: %w", err)
	}
	if consentType == nil {
		return fmt.Errorf("consent type not found")
	}

	// Verify the consent type belongs to the user's tenant
	if consentType.TenantID != tenantID {
		return fmt.Errorf("consent type not found")
	}

	// Check if trying to revoke required consent
	if consentType.IsRequired && !granted {
		return fmt.Errorf("cannot revoke required consent: %s", consentType.Name)
	}

	now := time.Now()
	consent := &models.UserConsent{
		UserID:         userID,
		ConsentTypeID:  consentTypeID,
		Granted:        granted,
		ConsentVersion: consentType.Version,
		IPAddress:      &ipAddress,
		UserAgent:      &userAgent,
	}

	if granted {
		consent.GrantedAt = &now
	} else {
		consent.RevokedAt = &now
	}

	if err := s.consentRepo.UpsertConsent(ctx, consent); err != nil {
		return fmt.Errorf("failed to update consent: %w", err)
	}

	// Log audit event
	action := "consent_granted"
	if !granted {
		action = "consent_revoked"
	}
	s.auditService.LogUserAction(ctx, consentType.TenantID, &userID, &userID, action, true, map[string]interface{}{
		"consent_type":    consentType.Name,
		"consent_type_id": consentTypeID.String(),
		"version":         consentType.Version,
	})

	logger.Info("Consent updated",
		zap.String("user_id", userID.String()),
		zap.String("consent_type_id", consentTypeID.String()),
		zap.Bool("granted", granted),
	)

	return nil
}

// BulkUpdateConsents updates multiple consents at once
func (s *ConsentService) BulkUpdateConsents(
	ctx context.Context,
	userID, tenantID uuid.UUID,
	consents []struct {
		ConsentTypeID string `json:"consent_type_id"`
		Granted       bool   `json:"granted"`
	},
	ipAddress, userAgent string,
) error {
	for _, c := range consents {
		consentTypeID, err := uuid.Parse(c.ConsentTypeID)
		if err != nil {
			return fmt.Errorf("invalid consent type ID: %s", c.ConsentTypeID)
		}

		if err := s.UpdateConsentByID(ctx, userID, tenantID, consentTypeID, c.Granted, ipAddress, userAgent); err != nil {
			return fmt.Errorf("failed to update consent %s: %w", c.ConsentTypeID, err)
		}
	}

	return nil
}

// HasGrantedAllRequired checks if a user has granted all required consents
func (s *ConsentService) HasGrantedAllRequired(ctx context.Context, userID, tenantID uuid.UUID) (bool, error) {
	return s.consentRepo.HasGrantedAllRequired(ctx, userID, tenantID)
}

// GetPendingRequiredConsents returns required consents that the user hasn't granted
func (s *ConsentService) GetPendingRequiredConsents(ctx context.Context, userID, tenantID uuid.UUID) ([]models.ConsentType, error) {
	return s.consentRepo.GetPendingRequiredConsents(ctx, userID, tenantID)
}

// DeleteUserConsents deletes all consents for a user (for GDPR data erasure)
func (s *ConsentService) DeleteUserConsents(ctx context.Context, userID uuid.UUID, tenantID uuid.UUID) error {
	if err := s.consentRepo.DeleteUserConsents(ctx, userID); err != nil {
		return fmt.Errorf("failed to delete user consents: %w", err)
	}

	s.auditService.LogUserAction(ctx, tenantID, &userID, &userID, "consents_deleted", true, map[string]interface{}{
		"reason": "gdpr_erasure",
	})

	logger.Info("User consents deleted",
		zap.String("user_id", userID.String()),
	)

	return nil
}

// GetConsentHistory returns consent history for a user (for audit)
func (s *ConsentService) GetConsentHistory(ctx context.Context, userID uuid.UUID, since time.Time) ([]models.UserConsentWithType, error) {
	return s.consentRepo.GetConsentHistory(ctx, userID, since)
}

// GetConsentHistoryDetailed returns detailed consent history from the history table
func (s *ConsentService) GetConsentHistoryDetailed(ctx context.Context, userID uuid.UUID, tenantID uuid.UUID, limit int) ([]models.ConsentHistoryWithType, error) {
	if limit <= 0 || limit > 100 {
		limit = 50
	}
	return s.consentRepo.GetConsentHistoryDetailed(ctx, userID, tenantID, limit)
}
