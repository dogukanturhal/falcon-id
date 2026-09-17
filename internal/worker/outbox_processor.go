// SPDX-License-Identifier: AGPL-3.0-or-later

// Package worker implements background worker processes.
package worker

import (
	"context"
	"fmt"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/services"
	"github.com/dogukanturhal/falcon-id/pkg/logger"
)

// OutboxProcessor is a background worker that processes pending outbox events
type OutboxProcessor struct {
	outboxService services.OutboxService
	pollInterval  time.Duration
	batchSize     int
	stopChan      chan struct{}
	stopOnce      sync.Once
}

// NewOutboxProcessor creates a new outbox processor worker
func NewOutboxProcessor(
	outboxService services.OutboxService,
	pollInterval time.Duration,
	batchSize int,
) *OutboxProcessor {
	return &OutboxProcessor{
		outboxService: outboxService,
		pollInterval:  pollInterval,
		batchSize:     batchSize,
		stopChan:      make(chan struct{}),
	}
}

// Start begins processing outbox events in the background
func (p *OutboxProcessor) Start(ctx context.Context) {
	logger.Info("Starting outbox processor worker",
		zap.Duration("poll_interval", p.pollInterval),
		zap.Int("batch_size", p.batchSize),
	)

	ticker := time.NewTicker(p.pollInterval)
	defer ticker.Stop()

	// Process immediately on startup
	p.processEvents(ctx)

	// Start cleanup ticker (runs every hour)
	cleanupTicker := time.NewTicker(1 * time.Hour)
	defer cleanupTicker.Stop()

	// Start stuck event recovery ticker (runs every 5 minutes)
	recoveryTicker := time.NewTicker(5 * time.Minute)
	defer recoveryTicker.Stop()

	for {
		select {
		case <-ticker.C:
			p.processEvents(ctx)

		case <-cleanupTicker.C:
			p.cleanupCompleted(ctx)

		case <-recoveryTicker.C:
			p.resetStuckEvents(ctx)

		case <-ctx.Done():
			logger.Info("Outbox processor stopped by context cancellation")
			return

		case <-p.stopChan:
			logger.Info("Outbox processor stopped")
			return
		}
	}
}

// Stop stops the outbox processor
func (p *OutboxProcessor) Stop() {
	p.stopOnce.Do(func() { close(p.stopChan) })
}

// processEvents processes a batch of pending outbox events
func (p *OutboxProcessor) processEvents(ctx context.Context) {
	startTime := time.Now()

	// Get outbox stats for monitoring
	stats, err := p.outboxService.GetStats(ctx)
	if err != nil {
		logger.Error("Failed to get outbox stats",
			zap.Error(err),
		)
	} else {
		logger.Debug("Outbox stats",
			zap.Int64("pending", stats.PendingCount),
			zap.Int64("processing", stats.ProcessingCount),
			zap.Int64("failed", stats.FailedCount),
			zap.Int64("completed", stats.CompletedCount),
		)

		// Log warning if lag is significant
		if stats.LagSeconds != nil && *stats.LagSeconds > 60 {
			logger.Warn("Outbox processing lag detected",
				zap.Int64("lag_seconds", *stats.LagSeconds),
				zap.Int64("pending_count", stats.PendingCount),
			)
		}
	}

	// Process pending events
	processedCount, err := p.outboxService.ProcessPendingEvents(ctx, p.batchSize)
	if err != nil {
		logger.Error("Failed to process outbox events",
			zap.Error(err),
		)
		return
	}

	if processedCount > 0 {
		duration := time.Since(startTime)
		logger.Info("Outbox batch processed",
			zap.Int("processed", processedCount),
			zap.Duration("duration", duration),
			zap.Float64("events_per_second", float64(processedCount)/duration.Seconds()),
		)
	}
}

// cleanupCompleted removes old completed events
func (p *OutboxProcessor) cleanupCompleted(ctx context.Context) {
	logger.Info("Starting outbox cleanup of completed events")

	// Keep completed events for 7 days
	retentionDays := 7
	deletedCount, err := p.outboxService.CleanupCompleted(ctx, retentionDays)
	if err != nil {
		logger.Error("Failed to cleanup completed outbox events",
			zap.Error(err),
		)
		return
	}

	if deletedCount > 0 {
		logger.Info("Outbox cleanup completed",
			zap.Int64("deleted_count", deletedCount),
			zap.Int("retention_days", retentionDays),
		)
	}
}

// resetStuckEvents resets events stuck in processing state
func (p *OutboxProcessor) resetStuckEvents(ctx context.Context) {
	resetCount, err := p.outboxService.ResetStuckProcessing(ctx)
	if err != nil {
		logger.Error("Failed to reset stuck outbox events",
			zap.Error(err),
		)
		return
	}

	if resetCount > 0 {
		logger.Warn("Reset stuck outbox events",
			zap.Int64("reset_count", resetCount),
		)
	}
}

// GetStats returns the current outbox statistics
func (p *OutboxProcessor) GetStats(ctx context.Context) (*services.OutboxProcessorStats, error) {
	outboxStats, err := p.outboxService.GetStats(ctx)
	if err != nil {
		return nil, fmt.Errorf("GetStats: %w", err)
	}

	// Get failed events
	failedEvents, err := p.outboxService.GetFailedEvents(ctx, 100)
	if err != nil {
		logger.Error("Failed to get failed events",
			zap.Error(err),
		)
		failedEvents = nil
	}

	return &services.OutboxProcessorStats{
		PendingCount:    outboxStats.PendingCount,
		ProcessingCount: outboxStats.ProcessingCount,
		FailedCount:     outboxStats.FailedCount,
		CompletedCount:  outboxStats.CompletedCount,
		OldestPending:   outboxStats.OldestPending,
		LagSeconds:      outboxStats.LagSeconds,
		FailedEvents:    failedEvents,
		PollInterval:    p.pollInterval,
		BatchSize:       p.batchSize,
	}, nil
}
