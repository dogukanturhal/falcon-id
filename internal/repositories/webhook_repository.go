// SPDX-License-Identifier: AGPL-3.0-or-later

package repositories

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

const (
	msgWebhookNotFound = "webhook not found"
	msgWebhookList     = "List: %w"
	msgListDeliveries  = "ListDeliveries: %w"
)

// WebhookRepository handles webhook database operations
type WebhookRepository struct {
	pool    DBPool
	realmID *uuid.UUID
}

// WithRealmID returns a shallow clone of WebhookRepository scoped to the given realm.
func (r *WebhookRepository) WithRealmID(realmID uuid.UUID) *WebhookRepository {
	clone := *r
	clone.realmID = &realmID
	return &clone
}

// NewWebhookRepository creates a new WebhookRepository
func NewWebhookRepository(pool *pgxpool.Pool) *WebhookRepository {
	return &WebhookRepository{pool: pool}
}

// Create creates a new webhook
func (r *WebhookRepository) Create(ctx context.Context, webhook *models.Webhook) error {
	headersJSON, err := json.Marshal(webhook.Headers)
	if err != nil {
		return fmt.Errorf("failed to marshal headers: %w", err)
	}

	query := `
		INSERT INTO iam_webhooks (
			id, tenant_id, name, description, url, secret_hash, events, headers,
			is_active, retry_count, timeout_seconds, created_at, updated_at, created_by
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
	`

	_, err = r.pool.Exec(ctx, query,
		webhook.ID,
		webhook.TenantID,
		webhook.Name,
		webhook.Description,
		webhook.URL,
		webhook.SecretHash,
		webhook.Events,
		headersJSON,
		webhook.IsActive,
		webhook.RetryCount,
		webhook.TimeoutSeconds,
		webhook.CreatedAt,
		webhook.UpdatedAt,
		webhook.CreatedBy,
	)
	if err != nil {
		return fmt.Errorf("Create: %w", err)
	}
	return nil
}

// GetByID retrieves a webhook by ID
func (r *WebhookRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.Webhook, error) {
	query := `
		SELECT id, tenant_id, name, description, url, secret_hash, events, headers,
		       is_active, retry_count, timeout_seconds, created_at, updated_at, created_by
		FROM iam_webhooks
		WHERE id = $1
	`

	webhook := &models.Webhook{}
	var headersJSON []byte

	err := r.pool.QueryRow(ctx, query, id).Scan(
		&webhook.ID,
		&webhook.TenantID,
		&webhook.Name,
		&webhook.Description,
		&webhook.URL,
		&webhook.SecretHash,
		&webhook.Events,
		&headersJSON,
		&webhook.IsActive,
		&webhook.RetryCount,
		&webhook.TimeoutSeconds,
		&webhook.CreatedAt,
		&webhook.UpdatedAt,
		&webhook.CreatedBy,
	)

	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errors.New(msgWebhookNotFound)
	}
	if err != nil {
		return nil, fmt.Errorf("GetByID: %w", err)
	}

	if len(headersJSON) > 0 {
		_ = json.Unmarshal(headersJSON, &webhook.Headers)
	}

	return webhook, nil
}

// GetByIDAndTenant retrieves a webhook by ID and tenant
func (r *WebhookRepository) GetByIDAndTenant(ctx context.Context, id, tenantID uuid.UUID) (*models.Webhook, error) {
	query := `
		SELECT id, tenant_id, name, description, url, secret_hash, events, headers,
		       is_active, retry_count, timeout_seconds, created_at, updated_at, created_by
		FROM iam_webhooks
		WHERE id = $1 AND tenant_id = $2
	`

	webhook := &models.Webhook{}
	var headersJSON []byte

	err := r.pool.QueryRow(ctx, query, id, tenantID).Scan(
		&webhook.ID,
		&webhook.TenantID,
		&webhook.Name,
		&webhook.Description,
		&webhook.URL,
		&webhook.SecretHash,
		&headersJSON,
		&webhook.Events,
		&webhook.IsActive,
		&webhook.RetryCount,
		&webhook.TimeoutSeconds,
		&webhook.CreatedAt,
		&webhook.UpdatedAt,
		&webhook.CreatedBy,
	)

	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errors.New(msgWebhookNotFound)
	}
	if err != nil {
		return nil, fmt.Errorf("GetByIDAndTenant: %w", err)
	}

	if len(headersJSON) > 0 {
		_ = json.Unmarshal(headersJSON, &webhook.Headers)
	}

	return webhook, nil
}

// Update updates a webhook
func (r *WebhookRepository) Update(ctx context.Context, webhook *models.Webhook) error {
	headersJSON, err := json.Marshal(webhook.Headers)
	if err != nil {
		return fmt.Errorf("failed to marshal headers: %w", err)
	}

	query := `
		UPDATE iam_webhooks
		SET name = $1, description = $2, url = $3, secret_hash = $4, events = $5,
		    headers = $6, is_active = $7, retry_count = $8, timeout_seconds = $9
		WHERE id = $10 AND tenant_id = $11
	`

	result, err := r.pool.Exec(ctx, query,
		webhook.Name,
		webhook.Description,
		webhook.URL,
		webhook.SecretHash,
		webhook.Events,
		headersJSON,
		webhook.IsActive,
		webhook.RetryCount,
		webhook.TimeoutSeconds,
		webhook.ID,
		webhook.TenantID,
	)
	if err != nil {
		return fmt.Errorf("Update: %w", err)
	}

	if result.RowsAffected() == 0 {
		return errors.New(msgWebhookNotFound)
	}

	return nil
}

// Delete deletes a webhook
func (r *WebhookRepository) Delete(ctx context.Context, id, tenantID uuid.UUID) error {
	query := `DELETE FROM iam_webhooks WHERE id = $1 AND tenant_id = $2`
	result, err := r.pool.Exec(ctx, query, id, tenantID)
	if err != nil {
		return fmt.Errorf("Delete: %w", err)
	}
	if result.RowsAffected() == 0 {
		return errors.New(msgWebhookNotFound)
	}
	return nil
}

// List lists webhooks for a tenant with pagination
func (r *WebhookRepository) List(ctx context.Context, tenantID uuid.UUID, page, pageSize int, activeOnly bool) ([]*models.Webhook, int, error) {
	offset := (page - 1) * pageSize

	// Count query
	countQuery := `SELECT COUNT(*) FROM iam_webhooks WHERE tenant_id = $1`
	if activeOnly {
		countQuery += ` AND is_active = true`
	}

	var total int
	err := r.pool.QueryRow(ctx, countQuery, tenantID).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf(msgWebhookList, err)
	}

	// List query
	listQuery := `
		SELECT id, tenant_id, name, description, url, secret_hash, events, headers,
		       is_active, retry_count, timeout_seconds, created_at, updated_at, created_by
		FROM iam_webhooks
		WHERE tenant_id = $1
	`
	if activeOnly {
		listQuery += ` AND is_active = true`
	}
	listQuery += ` ORDER BY created_at DESC LIMIT $2 OFFSET $3`

	rows, err := r.pool.Query(ctx, listQuery, tenantID, pageSize, offset)
	if err != nil {
		return nil, 0, fmt.Errorf(msgWebhookList, err)
	}
	defer rows.Close()

	webhooks := make([]*models.Webhook, 0)
	for rows.Next() {
		webhook := &models.Webhook{}
		var headersJSON []byte

		err := rows.Scan(
			&webhook.ID,
			&webhook.TenantID,
			&webhook.Name,
			&webhook.Description,
			&webhook.URL,
			&webhook.SecretHash,
			&webhook.Events,
			&headersJSON,
			&webhook.IsActive,
			&webhook.RetryCount,
			&webhook.TimeoutSeconds,
			&webhook.CreatedAt,
			&webhook.UpdatedAt,
			&webhook.CreatedBy,
		)
		if err != nil {
			return nil, 0, fmt.Errorf(msgWebhookList, err)
		}

		if len(headersJSON) > 0 {
			_ = json.Unmarshal(headersJSON, &webhook.Headers)
		}

		webhooks = append(webhooks, webhook)
	}

	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("List: rows iteration: %w", err)
	}

	return webhooks, total, nil
}

// GetActiveByEvent gets all active webhooks for a tenant that subscribe to an event
func (r *WebhookRepository) GetActiveByEvent(ctx context.Context, tenantID uuid.UUID, eventType string) ([]*models.Webhook, error) {
	query := `
		SELECT id, tenant_id, name, description, url, secret_hash, events, headers,
		       is_active, retry_count, timeout_seconds, created_at, updated_at, created_by
		FROM iam_webhooks
		WHERE tenant_id = $1 AND is_active = true AND $2 = ANY(events)
	`

	rows, err := r.pool.Query(ctx, query, tenantID, eventType)
	if err != nil {
		return nil, fmt.Errorf("GetActiveByEvent: %w", err)
	}
	defer rows.Close()

	webhooks := make([]*models.Webhook, 0)
	for rows.Next() {
		webhook := &models.Webhook{}
		var headersJSON []byte

		err := rows.Scan(
			&webhook.ID,
			&webhook.TenantID,
			&webhook.Name,
			&webhook.Description,
			&webhook.URL,
			&webhook.SecretHash,
			&webhook.Events,
			&headersJSON,
			&webhook.IsActive,
			&webhook.RetryCount,
			&webhook.TimeoutSeconds,
			&webhook.CreatedAt,
			&webhook.UpdatedAt,
			&webhook.CreatedBy,
		)
		if err != nil {
			return nil, fmt.Errorf("GetActiveByEvent: %w", err)
		}

		if len(headersJSON) > 0 {
			_ = json.Unmarshal(headersJSON, &webhook.Headers)
		}

		webhooks = append(webhooks, webhook)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("GetActiveByEvent: rows iteration: %w", err)
	}

	return webhooks, nil
}

// CreateDelivery creates a new webhook delivery record
func (r *WebhookRepository) CreateDelivery(ctx context.Context, delivery *models.WebhookDelivery) error {
	payloadJSON, err := json.Marshal(delivery.Payload)
	if err != nil {
		return fmt.Errorf("failed to marshal payload: %w", err)
	}

	query := `
		INSERT INTO iam_webhook_deliveries (
			id, webhook_id, event_type, event_id, payload, status, attempts, max_attempts,
			next_retry_at, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
	`

	_, err = r.pool.Exec(ctx, query,
		delivery.ID,
		delivery.WebhookID,
		delivery.EventType,
		delivery.EventID,
		payloadJSON,
		delivery.Status,
		delivery.Attempts,
		delivery.MaxAttempts,
		delivery.NextRetryAt,
		delivery.CreatedAt,
	)
	if err != nil {
		return fmt.Errorf("CreateDelivery: %w", err)
	}
	return nil
}

// UpdateDelivery updates a webhook delivery record
func (r *WebhookRepository) UpdateDelivery(ctx context.Context, delivery *models.WebhookDelivery) error {
	var responseHeadersJSON []byte
	if delivery.ResponseHeaders != nil {
		var err error
		responseHeadersJSON, err = json.Marshal(delivery.ResponseHeaders)
		if err != nil {
			return fmt.Errorf("failed to marshal response headers: %w", err)
		}
	}

	query := `
		UPDATE iam_webhook_deliveries
		SET status = $1, attempts = $2, next_retry_at = $3, last_attempt_at = $4,
		    response_status = $5, response_body = $6, response_headers = $7,
		    duration_ms = $8, error_message = $9, completed_at = $10
		WHERE id = $11
	`

	_, err := r.pool.Exec(ctx, query,
		delivery.Status,
		delivery.Attempts,
		delivery.NextRetryAt,
		delivery.LastAttemptAt,
		delivery.ResponseStatus,
		delivery.ResponseBody,
		responseHeadersJSON,
		delivery.DurationMs,
		delivery.ErrorMessage,
		delivery.CompletedAt,
		delivery.ID,
	)
	if err != nil {
		return fmt.Errorf("UpdateDelivery: %w", err)
	}
	return nil
}

// GetDeliveryByID gets a delivery by ID
func (r *WebhookRepository) GetDeliveryByID(ctx context.Context, id uuid.UUID) (*models.WebhookDelivery, error) {
	query := `
		SELECT d.id, d.webhook_id, d.event_type, d.event_id, d.payload, d.status,
		       d.attempts, d.max_attempts, d.next_retry_at, d.last_attempt_at,
		       d.response_status, d.response_body, d.response_headers, d.duration_ms,
		       d.error_message, d.created_at, d.completed_at,
		       w.name as webhook_name
		FROM iam_webhook_deliveries d
		JOIN iam_webhooks w ON w.id = d.webhook_id
		WHERE d.id = $1
	`

	delivery := &models.WebhookDelivery{}
	var payloadJSON, responseHeadersJSON []byte
	var webhookName string

	err := r.pool.QueryRow(ctx, query, id).Scan(
		&delivery.ID,
		&delivery.WebhookID,
		&delivery.EventType,
		&delivery.EventID,
		&payloadJSON,
		&delivery.Status,
		&delivery.Attempts,
		&delivery.MaxAttempts,
		&delivery.NextRetryAt,
		&delivery.LastAttemptAt,
		&delivery.ResponseStatus,
		&delivery.ResponseBody,
		&responseHeadersJSON,
		&delivery.DurationMs,
		&delivery.ErrorMessage,
		&delivery.CreatedAt,
		&delivery.CompletedAt,
		&webhookName,
	)

	if errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("delivery not found")
	}
	if err != nil {
		return nil, fmt.Errorf("GetDeliveryByID: %w", err)
	}

	if len(payloadJSON) > 0 {
		_ = json.Unmarshal(payloadJSON, &delivery.Payload)
	}
	if len(responseHeadersJSON) > 0 {
		_ = json.Unmarshal(responseHeadersJSON, &delivery.ResponseHeaders)
	}

	delivery.Webhook = &models.Webhook{ID: delivery.WebhookID, Name: webhookName}

	return delivery, nil
}

// ListDeliveries lists deliveries for a webhook with pagination
func (r *WebhookRepository) ListDeliveries(ctx context.Context, webhookID uuid.UUID, page, pageSize int, status *string) ([]*models.WebhookDelivery, int, error) {
	offset := (page - 1) * pageSize

	// Count query
	countQuery := `SELECT COUNT(*) FROM iam_webhook_deliveries WHERE webhook_id = $1`
	args := []interface{}{webhookID}

	if status != nil {
		countQuery += ` AND status = $2`
		args = append(args, *status)
	}

	var total int
	err := r.pool.QueryRow(ctx, countQuery, args...).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf(msgListDeliveries, err)
	}

	// List query
	listQuery := `
		SELECT id, webhook_id, event_type, event_id, payload, status, attempts, max_attempts,
		       next_retry_at, last_attempt_at, response_status, response_body, response_headers,
		       duration_ms, error_message, created_at, completed_at
		FROM iam_webhook_deliveries
		WHERE webhook_id = $1
	`

	listArgs := []interface{}{webhookID}
	argNum := 2

	if status != nil {
		listQuery += fmt.Sprintf(` AND status = $%d`, argNum)
		listArgs = append(listArgs, *status)
		argNum++
	}

	listQuery += fmt.Sprintf(` ORDER BY created_at DESC LIMIT $%d OFFSET $%d`, argNum, argNum+1)
	listArgs = append(listArgs, pageSize, offset)

	rows, err := r.pool.Query(ctx, listQuery, listArgs...)
	if err != nil {
		return nil, 0, fmt.Errorf(msgListDeliveries, err)
	}
	defer rows.Close()

	deliveries := make([]*models.WebhookDelivery, 0)
	for rows.Next() {
		delivery := &models.WebhookDelivery{}
		var payloadJSON, responseHeadersJSON []byte

		err := rows.Scan(
			&delivery.ID,
			&delivery.WebhookID,
			&delivery.EventType,
			&delivery.EventID,
			&payloadJSON,
			&delivery.Status,
			&delivery.Attempts,
			&delivery.MaxAttempts,
			&delivery.NextRetryAt,
			&delivery.LastAttemptAt,
			&delivery.ResponseStatus,
			&delivery.ResponseBody,
			&responseHeadersJSON,
			&delivery.DurationMs,
			&delivery.ErrorMessage,
			&delivery.CreatedAt,
			&delivery.CompletedAt,
		)
		if err != nil {
			return nil, 0, fmt.Errorf(msgListDeliveries, err)
		}

		if len(payloadJSON) > 0 {
			_ = json.Unmarshal(payloadJSON, &delivery.Payload)
		}
		if len(responseHeadersJSON) > 0 {
			_ = json.Unmarshal(responseHeadersJSON, &delivery.ResponseHeaders)
		}

		deliveries = append(deliveries, delivery)
	}

	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("ListDeliveries: rows iteration: %w", err)
	}

	return deliveries, total, nil
}

// GetPendingDeliveries gets deliveries that are pending retry
func (r *WebhookRepository) GetPendingDeliveries(ctx context.Context, limit int) ([]*models.WebhookDelivery, error) {
	query := `
		SELECT d.id, d.webhook_id, d.event_type, d.event_id, d.payload, d.status,
		       d.attempts, d.max_attempts, d.next_retry_at, d.last_attempt_at,
		       d.response_status, d.response_body, d.response_headers, d.duration_ms,
		       d.error_message, d.created_at, d.completed_at,
		       w.url, w.secret_hash, w.headers, w.timeout_seconds
		FROM iam_webhook_deliveries d
		JOIN iam_webhooks w ON w.id = d.webhook_id
		WHERE d.status = 'pending'
		  AND (d.next_retry_at IS NULL OR d.next_retry_at <= NOW())
		  AND w.is_active = true
		ORDER BY d.created_at ASC
		LIMIT $1
	`

	rows, err := r.pool.Query(ctx, query, limit)
	if err != nil {
		return nil, fmt.Errorf("GetPendingDeliveries: %w", err)
	}
	defer rows.Close()

	deliveries := make([]*models.WebhookDelivery, 0)
	for rows.Next() {
		delivery := &models.WebhookDelivery{Webhook: &models.Webhook{}}
		var payloadJSON, responseHeadersJSON, webhookHeadersJSON []byte

		err := rows.Scan(
			&delivery.ID,
			&delivery.WebhookID,
			&delivery.EventType,
			&delivery.EventID,
			&payloadJSON,
			&delivery.Status,
			&delivery.Attempts,
			&delivery.MaxAttempts,
			&delivery.NextRetryAt,
			&delivery.LastAttemptAt,
			&delivery.ResponseStatus,
			&delivery.ResponseBody,
			&responseHeadersJSON,
			&delivery.DurationMs,
			&delivery.ErrorMessage,
			&delivery.CreatedAt,
			&delivery.CompletedAt,
			&delivery.Webhook.URL,
			&delivery.Webhook.SecretHash,
			&webhookHeadersJSON,
			&delivery.Webhook.TimeoutSeconds,
		)
		if err != nil {
			return nil, fmt.Errorf("GetPendingDeliveries: %w", err)
		}

		if len(payloadJSON) > 0 {
			_ = json.Unmarshal(payloadJSON, &delivery.Payload)
		}
		if len(responseHeadersJSON) > 0 {
			_ = json.Unmarshal(responseHeadersJSON, &delivery.ResponseHeaders)
		}
		if len(webhookHeadersJSON) > 0 {
			_ = json.Unmarshal(webhookHeadersJSON, &delivery.Webhook.Headers)
		}

		delivery.Webhook.ID = delivery.WebhookID
		deliveries = append(deliveries, delivery)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("GetPendingDeliveries: rows iteration: %w", err)
	}

	return deliveries, nil
}

// MarkDeliveryProcessing marks a delivery as processing
func (r *WebhookRepository) MarkDeliveryProcessing(ctx context.Context, id uuid.UUID) error {
	query := `
		UPDATE iam_webhook_deliveries
		SET status = 'processing', last_attempt_at = $1
		WHERE id = $2 AND status = 'pending'
	`
	result, err := r.pool.Exec(ctx, query, time.Now(), id)
	if err != nil {
		return fmt.Errorf("MarkDeliveryProcessing: %w", err)
	}
	if result.RowsAffected() == 0 {
		return fmt.Errorf("delivery not found or already processing")
	}
	return nil
}

// GetDeliveryStats gets delivery statistics for a webhook
func (r *WebhookRepository) GetDeliveryStats(ctx context.Context, webhookID uuid.UUID) (map[string]int, error) {
	query := `
		SELECT status, COUNT(*) as count
		FROM iam_webhook_deliveries
		WHERE webhook_id = $1
		GROUP BY status
	`

	rows, err := r.pool.Query(ctx, query, webhookID)
	if err != nil {
		return nil, fmt.Errorf("GetDeliveryStats: %w", err)
	}
	defer rows.Close()

	stats := make(map[string]int)
	for rows.Next() {
		var status string
		var count int
		if err := rows.Scan(&status, &count); err != nil {
			return nil, fmt.Errorf("GetDeliveryStats: %w", err)
		}
		stats[status] = count
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("GetDeliveryStats: rows iteration: %w", err)
	}

	return stats, nil
}
