// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/internal/repositories"
	"github.com/dogukanturhal/falcon-id/pkg/logger"
	"github.com/dogukanturhal/falcon-id/pkg/spicedb"
)

// OutboxProcessorStats contains statistics about the outbox processor
type OutboxProcessorStats struct {
	PendingCount    int64                      `json:"pending_count"`
	ProcessingCount int64                      `json:"processing_count"`
	FailedCount     int64                      `json:"failed_count"`
	CompletedCount  int64                      `json:"completed_count"`
	OldestPending   *time.Time                 `json:"oldest_pending,omitempty"`
	LagSeconds      *int64                     `json:"lag_seconds,omitempty"`
	FailedEvents    []*models.PermissionOutbox `json:"failed_events,omitempty"`
	PollInterval    time.Duration              `json:"poll_interval"`
	BatchSize       int                        `json:"batch_size"`
}

// OutboxService handles transactional outbox operations for reliable SpiceDB synchronization
type OutboxService interface {
	// AddRelationshipEvent adds a relationship event to the outbox within a transaction
	AddRelationshipEvent(ctx context.Context, tx pgx.Tx, event models.RelationshipEvent) error

	// ProcessPendingEvents processes a batch of pending events
	ProcessPendingEvents(ctx context.Context, batchSize int) (int, error)

	// GetStats retrieves outbox statistics for monitoring
	GetStats(ctx context.Context) (*models.OutboxStats, error)

	// CleanupCompleted removes old completed events
	CleanupCompleted(ctx context.Context, retentionDays int) (int64, error)

	// GetFailedEvents retrieves permanently failed events
	GetFailedEvents(ctx context.Context, limit int) ([]*models.PermissionOutbox, error)

	// ResetStuckProcessing resets events stuck in processing state
	ResetStuckProcessing(ctx context.Context) (int64, error)
}

type outboxService struct {
	outboxRepo    *repositories.OutboxRepository
	spicedbClient *spicedb.Client
}

// NewOutboxService creates a new outbox service
func NewOutboxService(
	outboxRepo *repositories.OutboxRepository,
	spicedbClient *spicedb.Client,
) OutboxService {
	return &outboxService{
		outboxRepo:    outboxRepo,
		spicedbClient: spicedbClient,
	}
}

// AddRelationshipEvent adds a relationship event to the outbox within a transaction
// This method should be called within the same database transaction as the business logic
// to ensure atomicity between database changes and permission updates
func (s *outboxService) AddRelationshipEvent(ctx context.Context, tx pgx.Tx, event models.RelationshipEvent) error {
	// Convert event to outbox entry
	outboxEntry, err := event.ToOutboxEntry()
	if err != nil {
		return fmt.Errorf("failed to convert event to outbox entry: %w", err)
	}

	// Add to outbox within the transaction
	if err := s.outboxRepo.AddEvent(ctx, tx, outboxEntry); err != nil {
		return fmt.Errorf("failed to add event to outbox: %w", err)
	}

	logger.Debug("Added relationship event to outbox",
		zap.String("event_id", outboxEntry.ID.String()),
		zap.String("event_type", outboxEntry.EventType),
		zap.String("resource_type", outboxEntry.ResourceType),
		zap.String("resource_id", outboxEntry.ResourceID),
		zap.String("relation", outboxEntry.Relation),
		zap.String("subject_type", outboxEntry.SubjectType),
		zap.String("subject_id", outboxEntry.SubjectID),
		zap.String("operation", string(outboxEntry.Operation)),
	)

	return nil
}

// ProcessPendingEvents processes a batch of pending outbox events
// Returns the number of events successfully processed
func (s *outboxService) ProcessPendingEvents(ctx context.Context, batchSize int) (int, error) {
	// Retrieve pending events
	events, err := s.outboxRepo.GetPendingEvents(ctx, batchSize)
	if err != nil {
		return 0, fmt.Errorf("failed to retrieve pending events: %w", err)
	}

	if len(events) == 0 {
		return 0, nil
	}

	logger.Info("Processing outbox events",
		zap.Int("event_count", len(events)),
	)

	successCount := 0
	for _, event := range events {
		if err := s.processEvent(ctx, event); err != nil {
			logger.Error("Failed to process outbox event",
				zap.String("event_id", event.ID.String()),
				zap.String("event_type", event.EventType),
				zap.Error(err),
			)
			// Mark as failed with error message
			if markErr := s.outboxRepo.MarkFailed(ctx, event.ID, err.Error()); markErr != nil {
				logger.Error("Failed to mark event as failed",
					zap.String("event_id", event.ID.String()),
					zap.Error(markErr),
				)
			}
			continue
		}

		// Mark as completed
		if err := s.outboxRepo.MarkCompleted(ctx, event.ID); err != nil {
			logger.Error("Failed to mark event as completed",
				zap.String("event_id", event.ID.String()),
				zap.Error(err),
			)
			continue
		}

		successCount++
	}

	logger.Info("Finished processing outbox events",
		zap.Int("total", len(events)),
		zap.Int("success", successCount),
		zap.Int("failed", len(events)-successCount),
	)

	return successCount, nil
}

// processEvent processes a single outbox event by writing to SpiceDB
func (s *outboxService) processEvent(ctx context.Context, event *models.PermissionOutbox) error {
	// Mark as processing
	if err := s.outboxRepo.MarkProcessing(ctx, event.ID); err != nil {
		return fmt.Errorf("failed to mark event as processing: %w", err)
	}

	// Check if SpiceDB client is available
	if s.spicedbClient == nil {
		return fmt.Errorf("SpiceDB client not initialized")
	}

	// Parse payload if present
	var metadata map[string]string
	if len(event.Payload) > 0 {
		var payload map[string]interface{}
		if err := json.Unmarshal(event.Payload, &payload); err != nil {
			logger.Warn("Failed to parse event payload, continuing without metadata",
				zap.String("event_id", event.ID.String()),
				zap.Error(err),
			)
		} else {
			// Convert to string map for SpiceDB metadata
			metadata = make(map[string]string)
			for k, v := range payload {
				metadata[k] = fmt.Sprintf("%v", v)
			}
		}
	}

	// Execute operation based on type
	switch event.Operation {
	case models.OutboxOperationTouch:
		// Create or update relationship
		_, err := s.spicedbClient.WriteResourceRelationship(ctx,
			event.TenantID,
			event.ResourceType,
			event.ResourceID,
			event.Relation,
			event.SubjectType,
			event.SubjectID,
		)
		if err != nil {
			return fmt.Errorf("failed to write relationship to SpiceDB: %w", err)
		}

		logger.Debug("Created relationship in SpiceDB",
			zap.String("event_id", event.ID.String()),
			zap.String("resource", fmt.Sprintf("%s:%s", event.ResourceType, event.ResourceID)),
			zap.String("relation", event.Relation),
			zap.String("subject", fmt.Sprintf("%s:%s", event.SubjectType, event.SubjectID)),
		)

	case models.OutboxOperationDelete:
		// Delete relationship
		err := s.spicedbClient.DeleteResourceRelationship(ctx,
			event.TenantID,
			event.ResourceType,
			event.ResourceID,
			event.Relation,
			event.SubjectType,
			event.SubjectID,
		)
		if err != nil {
			return fmt.Errorf("failed to delete relationship from SpiceDB: %w", err)
		}

		logger.Debug("Deleted relationship from SpiceDB",
			zap.String("event_id", event.ID.String()),
			zap.String("resource", fmt.Sprintf("%s:%s", event.ResourceType, event.ResourceID)),
			zap.String("relation", event.Relation),
			zap.String("subject", fmt.Sprintf("%s:%s", event.SubjectType, event.SubjectID)),
		)

	default:
		return fmt.Errorf("unsupported operation: %s", event.Operation)
	}

	return nil
}

// GetStats retrieves outbox statistics for monitoring
func (s *outboxService) GetStats(ctx context.Context) (*models.OutboxStats, error) {
	return s.outboxRepo.GetStats(ctx)
}

// CleanupCompleted removes old completed events
func (s *outboxService) CleanupCompleted(ctx context.Context, retentionDays int) (int64, error) {
	return s.outboxRepo.CleanupCompleted(ctx, retentionDays)
}

// GetFailedEvents retrieves permanently failed events
func (s *outboxService) GetFailedEvents(ctx context.Context, limit int) ([]*models.PermissionOutbox, error) {
	return s.outboxRepo.GetFailedEvents(ctx, limit)
}

// ResetStuckProcessing resets events stuck in processing state
func (s *outboxService) ResetStuckProcessing(ctx context.Context) (int64, error) {
	// Reset events stuck for more than 5 minutes
	stuckThreshold := 5 * time.Minute
	return s.outboxRepo.ResetStuckProcessing(ctx, stuckThreshold)
}
