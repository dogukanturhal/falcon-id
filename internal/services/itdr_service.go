// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

// ITDRRepository defines persistence operations for identity threat detection.
// It is satisfied by repositories.ITDRRepository.
type ITDRRepository interface {
	ListThreats(ctx context.Context, tenantID uuid.UUID, limit, offset int) ([]*models.ITDRThreat, int, error)
	GetThreat(ctx context.Context, id uuid.UUID) (*models.ITDRThreat, error)
	AcknowledgeThreat(ctx context.Context, id, ackedBy uuid.UUID) error
	ListDetectionRules(ctx context.Context, limit, offset int) ([]*models.ITDRDetectionRule, int, error)
	UpdateDetectionRule(ctx context.Context, rule *models.ITDRDetectionRule) error
}

// ITDRDetectionPipeline defines the interface for a real-time detection pipeline.
// Implementations may use Redis streams, Kafka, or in-process evaluation.
type ITDRDetectionPipeline interface {
	Run(ctx context.Context) error
	ProcessLoginEvent(ctx context.Context, event models.ITDRLoginEvent) (*models.ITDRDetectionResult, error)
	ProcessMFAEvent(ctx context.Context, event models.ITDRMFAEvent) (*models.ITDRDetectionResult, error)
	ProcessSessionEvent(ctx context.Context, event models.ITDRSessionEvent) (*models.ITDRDetectionResult, error)
}

// ITDRService coordinates identity threat detection and response.
// It uses a detection pipeline (e.g. Redis Streams) to receive raw events and
// persists correlated threats via the repository.
type ITDRService struct {
	repo     ITDRRepository
	pipeline ITDRDetectionPipeline
	logger   *zap.Logger
}

// NewITDRService constructs an ITDRService.
// pipeline may be nil; detection will be disabled but query endpoints still work.
func NewITDRService(repo ITDRRepository, pipeline ITDRDetectionPipeline, logger *zap.Logger) *ITDRService {
	return &ITDRService{
		repo:     repo,
		pipeline: pipeline,
		logger:   logger,
	}
}

// SetDetectionPipeline wires the real-time detection pipeline via setter injection,
// allowing it to be configured after construction (e.g. when Redis is optional).
func (s *ITDRService) SetDetectionPipeline(p ITDRDetectionPipeline) {
	s.pipeline = p
}

// ListThreats returns paginated threats for a given tenant.
func (s *ITDRService) ListThreats(ctx context.Context, tenantID uuid.UUID, limit, offset int) ([]*models.ITDRThreat, int, error) {
	return s.repo.ListThreats(ctx, tenantID, limit, offset)
}

// GetThreat retrieves a single threat by ID.
func (s *ITDRService) GetThreat(ctx context.Context, id uuid.UUID) (*models.ITDRThreat, error) {
	return s.repo.GetThreat(ctx, id)
}

// AcknowledgeThreat marks a threat as acknowledged by the given operator.
func (s *ITDRService) AcknowledgeThreat(ctx context.Context, id, ackedBy uuid.UUID) error {
	return s.repo.AcknowledgeThreat(ctx, id, ackedBy)
}

// ListDetectionRules returns all configured detection rules.
func (s *ITDRService) ListDetectionRules(ctx context.Context, limit, offset int) ([]*models.ITDRDetectionRule, int, error) {
	return s.repo.ListDetectionRules(ctx, limit, offset)
}

// UpdateDetectionRule persists changes to a detection rule.
func (s *ITDRService) UpdateDetectionRule(ctx context.Context, rule *models.ITDRDetectionRule) error {
	return s.repo.UpdateDetectionRule(ctx, rule)
}
