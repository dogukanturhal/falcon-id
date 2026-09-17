// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

// SSFRepository defines persistence operations for SSF streams.
// It is satisfied by repositories.SSFRepository.
type SSFRepository interface {
	CreateStream(ctx context.Context, stream *models.SSFStream) error
	ListStreams(ctx context.Context, tenantID uuid.UUID) ([]*models.SSFStream, error)
	GetStream(ctx context.Context, id uuid.UUID) (*models.SSFStream, error)
	UpdateStream(ctx context.Context, stream *models.SSFStream) error
	DeleteStream(ctx context.Context, id uuid.UUID) error
}

// SSFServiceConfig holds configuration for the SSF service.
type SSFServiceConfig struct {
	// Issuer is the URI included in SSF metadata as the event issuer.
	Issuer string
	// JWKSEndpoint is the public JWKS endpoint for verifying signed events.
	JWKSEndpoint string
	// SupportedEventTypes lists the CAE/RISC event types this issuer delivers.
	SupportedEventTypes []string
}

// DefaultSSFServiceConfig returns sensible defaults.
func DefaultSSFServiceConfig() SSFServiceConfig {
	return SSFServiceConfig{
		SupportedEventTypes: []string{
			"https://schemas.openid.net/secevent/caep/event-type/session-revoked",
			"https://schemas.openid.net/secevent/caep/event-type/credential-change",
			"https://schemas.openid.net/secevent/caep/event-type/assurance-level-change",
			"https://schemas.openid.net/secevent/risc/event-type/account-disabled",
			"https://schemas.openid.net/secevent/risc/event-type/account-enabled",
		},
	}
}

// SSFService manages Shared Signals Framework streams and metadata.
// It implements draft-ietf-sharedsignals-framework.
type SSFService struct {
	repo   SSFRepository
	cfg    SSFServiceConfig
	logger *zap.Logger
}

// NewSSFService constructs an SSFService.
func NewSSFService(repo SSFRepository, cfg SSFServiceConfig, logger *zap.Logger) *SSFService {
	return &SSFService{
		repo:   repo,
		cfg:    cfg,
		logger: logger,
	}
}

// GetConfiguration returns the SSF discovery metadata (RFC-style well-known document).
func (s *SSFService) GetConfiguration() map[string]interface{} {
	return map[string]interface{}{
		"issuer":                s.cfg.Issuer,
		"jwks_uri":              s.cfg.JWKSEndpoint,
		"supported_event_types": s.cfg.SupportedEventTypes,
		"delivery_methods_supported": []string{
			"https://schemas.openid.net/secevent/risc/delivery-method/push",
			"https://schemas.openid.net/secevent/risc/delivery-method/poll",
		},
	}
}

// CreateStream persists a new SSF stream for a tenant.
func (s *SSFService) CreateStream(ctx context.Context, stream *models.SSFStream) error {
	s.logger.Info("Creating SSF stream",
		zap.String("tenant_id", stream.TenantID.String()),
		zap.Stringp("endpoint", stream.PushEndpointURL),
	)
	return s.repo.CreateStream(ctx, stream)
}

// ListStreams returns all streams for a tenant.
func (s *SSFService) ListStreams(ctx context.Context, tenantID uuid.UUID) ([]*models.SSFStream, error) {
	return s.repo.ListStreams(ctx, tenantID)
}

// GetStream retrieves a single stream by ID.
func (s *SSFService) GetStream(ctx context.Context, id uuid.UUID) (*models.SSFStream, error) {
	return s.repo.GetStream(ctx, id)
}

// UpdateStream updates an existing SSF stream.
func (s *SSFService) UpdateStream(ctx context.Context, stream *models.SSFStream) error {
	return s.repo.UpdateStream(ctx, stream)
}

// DeleteStream removes an SSF stream.
func (s *SSFService) DeleteStream(ctx context.Context, id uuid.UUID) error {
	return s.repo.DeleteStream(ctx, id)
}
