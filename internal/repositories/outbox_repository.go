// SPDX-License-Identifier: AGPL-3.0-or-later

package repositories

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

// OutboxRepository is an exported type.
type OutboxRepository struct {
	db *pgxpool.Pool
}

// NewOutboxRepository is an exported function.
func NewOutboxRepository(db *pgxpool.Pool) *OutboxRepository {
	return &OutboxRepository{db: db}
}

// AddEvent adds a new event to the outbox within a transaction
// This should be called within the same transaction as the business logic
func (r *OutboxRepository) AddEvent(ctx context.Context, tx pgx.Tx, event *models.PermissionOutbox) error {
	query := `
		INSERT INTO iam_permission_outbox (
			id, tenant_id, event_type, resource_type, resource_id,
			relation, subject_type, subject_id, operation, payload,
			status, retry_count, max_retries, created_at
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)`

	if event.ID == uuid.Nil {
		event.ID = uuid.New()
	}
	if event.CreatedAt.IsZero() {
		event.CreatedAt = time.Now()
	}
	if event.Status == "" {
		event.Status = models.OutboxStatusPending
	}
	if event.MaxRetries == 0 {
		event.MaxRetries = 5
	}

	_, err := tx.Exec(ctx, query,
		event.ID,
		event.TenantID,
		event.EventType,
		event.ResourceType,
		event.ResourceID,
		event.Relation,
		event.SubjectType,
		event.SubjectID,
		event.Operation,
		event.Payload,
		event.Status,
		event.RetryCount,
		event.MaxRetries,
		event.CreatedAt,
	)
	if err != nil {
		return fmt.Errorf("AddEvent: %w", err)
	}
	return nil
}

// GetPendingEvents retrieves pending and failed (ready for retry) events
func (r *OutboxRepository) GetPendingEvents(ctx context.Context, batchSize int) ([]*models.PermissionOutbox, error) {
	query := `
		SELECT id, tenant_id, event_type, resource_type, resource_id,
			   relation, subject_type, subject_id, operation, payload,
			   status, retry_count, max_retries, error_message,
			   created_at, processed_at, next_retry_at
		FROM iam_permission_outbox
		WHERE event_type <> 'role.revoked' AND ((status = $1)
		   OR (status = $2 AND next_retry_at IS NOT NULL AND next_retry_at <= NOW() AND retry_count < max_retries))
		ORDER BY created_at ASC
		LIMIT $3
		FOR UPDATE SKIP LOCKED`

	rows, err := r.db.Query(ctx, query,
		models.OutboxStatusPending,
		models.OutboxStatusFailed,
		batchSize,
	)
	if err != nil {
		return nil, fmt.Errorf("GetPendingEvents: %w", err)
	}
	defer rows.Close()

	var events []*models.PermissionOutbox
	for rows.Next() {
		event := &models.PermissionOutbox{}
		err := rows.Scan(
			&event.ID,
			&event.TenantID,
			&event.EventType,
			&event.ResourceType,
			&event.ResourceID,
			&event.Relation,
			&event.SubjectType,
			&event.SubjectID,
			&event.Operation,
			&event.Payload,
			&event.Status,
			&event.RetryCount,
			&event.MaxRetries,
			&event.ErrorMessage,
			&event.CreatedAt,
			&event.ProcessedAt,
			&event.NextRetryAt,
		)
		if err != nil {
			return nil, fmt.Errorf("GetPendingEvents: %w", err)
		}
		events = append(events, event)
	}

	return events, rows.Err()
}

// MarkProcessing marks an event as being processed
func (r *OutboxRepository) MarkProcessing(ctx context.Context, eventID uuid.UUID) error {
	query := `
		UPDATE iam_permission_outbox
		SET status = $1
		WHERE id = $2`

	_, err := r.db.Exec(ctx, query, models.OutboxStatusProcessing, eventID)
	if err != nil {
		return fmt.Errorf("MarkProcessing: %w", err)
	}
	return nil
}

// MarkCompleted marks an event as successfully completed
func (r *OutboxRepository) MarkCompleted(ctx context.Context, eventID uuid.UUID) error {
	now := time.Now()
	query := `
		UPDATE iam_permission_outbox
		SET status = $1, processed_at = $2, error_message = NULL
		WHERE id = $3`

	_, err := r.db.Exec(ctx, query, models.OutboxStatusCompleted, now, eventID)
	if err != nil {
		return fmt.Errorf("MarkCompleted: %w", err)
	}
	return nil
}

// MarkFailed marks an event as failed and schedules retry with exponential backoff
func (r *OutboxRepository) MarkFailed(ctx context.Context, eventID uuid.UUID, errorMsg string) error {
	// Get current retry count
	var retryCount int
	var maxRetries int
	err := r.db.QueryRow(ctx,
		`SELECT retry_count, max_retries FROM iam_permission_outbox WHERE id = $1`,
		eventID,
	).Scan(&retryCount, &maxRetries)
	if err != nil {
		return fmt.Errorf("MarkFailed: %w", err)
	}

	// Increment retry count
	retryCount++

	// Calculate next retry time with exponential backoff
	nextRetry := calculateNextRetry(retryCount)

	query := `
		UPDATE iam_permission_outbox
		SET status = $1, retry_count = $2, error_message = $3, next_retry_at = $4
		WHERE id = $5`

	_, err = r.db.Exec(ctx, query,
		models.OutboxStatusFailed,
		retryCount,
		errorMsg,
		nextRetry,
		eventID,
	)
	if err != nil {
		return fmt.Errorf("MarkFailed: %w", err)
	}
	return nil
}

// GetEventByID retrieves a single event by ID
func (r *OutboxRepository) GetEventByID(ctx context.Context, eventID uuid.UUID) (*models.PermissionOutbox, error) {
	query := `
		SELECT id, tenant_id, event_type, resource_type, resource_id,
			   relation, subject_type, subject_id, operation, payload,
			   status, retry_count, max_retries, error_message,
			   created_at, processed_at, next_retry_at
		FROM iam_permission_outbox
		WHERE id = $1`

	event := &models.PermissionOutbox{}
	err := r.db.QueryRow(ctx, query, eventID).Scan(
		&event.ID,
		&event.TenantID,
		&event.EventType,
		&event.ResourceType,
		&event.ResourceID,
		&event.Relation,
		&event.SubjectType,
		&event.SubjectID,
		&event.Operation,
		&event.Payload,
		&event.Status,
		&event.RetryCount,
		&event.MaxRetries,
		&event.ErrorMessage,
		&event.CreatedAt,
		&event.ProcessedAt,
		&event.NextRetryAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("GetEventByID: %w", err)
	}

	return event, nil
}

// GetStats retrieves statistics about the outbox for monitoring
func (r *OutboxRepository) GetStats(ctx context.Context) (*models.OutboxStats, error) {
	stats := &models.OutboxStats{}

	query := `
		SELECT
			COUNT(*) FILTER (WHERE status = 'pending') as pending_count,
			COUNT(*) FILTER (WHERE status = 'processing') as processing_count,
			COUNT(*) FILTER (WHERE status = 'failed') as failed_count,
			COUNT(*) FILTER (WHERE status = 'completed') as completed_count,
			MIN(created_at) FILTER (WHERE status = 'pending') as oldest_pending
		FROM iam_permission_outbox`

	var oldestPending *time.Time
	err := r.db.QueryRow(ctx, query).Scan(
		&stats.PendingCount,
		&stats.ProcessingCount,
		&stats.FailedCount,
		&stats.CompletedCount,
		&oldestPending,
	)
	if err != nil {
		return nil, fmt.Errorf("GetStats: %w", err)
	}

	stats.OldestPending = oldestPending

	// Calculate lag in seconds
	if oldestPending != nil {
		lag := int64(time.Since(*oldestPending).Seconds())
		stats.LagSeconds = &lag
	}

	return stats, nil
}

// CleanupCompleted removes completed events older than retention period
func (r *OutboxRepository) CleanupCompleted(ctx context.Context, retentionDays int) (int64, error) {
	query := `
		DELETE FROM iam_permission_outbox
		WHERE status = $1 AND processed_at < NOW() - INTERVAL '1 day' * $2`

	result, err := r.db.Exec(ctx, query, models.OutboxStatusCompleted, retentionDays)
	if err != nil {
		return 0, fmt.Errorf("CleanupCompleted: %w", err)
	}

	return result.RowsAffected(), nil
}

// GetFailedEvents retrieves permanently failed events (exceeded max retries)
func (r *OutboxRepository) GetFailedEvents(ctx context.Context, limit int) ([]*models.PermissionOutbox, error) {
	query := `
		SELECT id, tenant_id, event_type, resource_type, resource_id,
			   relation, subject_type, subject_id, operation, payload,
			   status, retry_count, max_retries, error_message,
			   created_at, processed_at, next_retry_at
		FROM iam_permission_outbox
		WHERE status = $1 AND retry_count >= max_retries
		ORDER BY created_at ASC
		LIMIT $2`

	rows, err := r.db.Query(ctx, query, models.OutboxStatusFailed, limit)
	if err != nil {
		return nil, fmt.Errorf("GetFailedEvents: %w", err)
	}
	defer rows.Close()

	var events []*models.PermissionOutbox
	for rows.Next() {
		event := &models.PermissionOutbox{}
		err := rows.Scan(
			&event.ID,
			&event.TenantID,
			&event.EventType,
			&event.ResourceType,
			&event.ResourceID,
			&event.Relation,
			&event.SubjectType,
			&event.SubjectID,
			&event.Operation,
			&event.Payload,
			&event.Status,
			&event.RetryCount,
			&event.MaxRetries,
			&event.ErrorMessage,
			&event.CreatedAt,
			&event.ProcessedAt,
			&event.NextRetryAt,
		)
		if err != nil {
			return nil, fmt.Errorf("GetFailedEvents: %w", err)
		}
		events = append(events, event)
	}

	return events, rows.Err()
}

// calculateNextRetry calculates the next retry time using exponential backoff
// Backoff pattern: 2^retryCount seconds, capped at 5 minutes
func calculateNextRetry(retryCount int) time.Time {
	// Base delay: 2 seconds
	baseDelay := 2 * time.Second

	// Exponential backoff: 2^retryCount * baseDelay
	delay := time.Duration(1<<uint(retryCount)) * baseDelay //nolint:gosec // value is bounded by page size config, safe conversion

	// Cap at 5 minutes
	maxDelay := 5 * time.Minute
	if delay > maxDelay {
		delay = maxDelay
	}

	return time.Now().Add(delay)
}

// ResetStuckProcessing resets events stuck in processing state (recovery mechanism)
func (r *OutboxRepository) ResetStuckProcessing(ctx context.Context, stuckThreshold time.Duration) (int64, error) {
	query := `
		UPDATE iam_permission_outbox
		SET status = $1
		WHERE status = $2 AND created_at < NOW() - $3::interval`

	result, err := r.db.Exec(ctx, query,
		models.OutboxStatusPending,
		models.OutboxStatusProcessing,
		fmt.Sprintf("%d seconds", int(stuckThreshold.Seconds())),
	)
	if err != nil {
		return 0, fmt.Errorf("ResetStuckProcessing: %w", err)
	}

	return result.RowsAffected(), nil
}
