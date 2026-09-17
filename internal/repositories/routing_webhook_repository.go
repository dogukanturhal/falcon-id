// SPDX-License-Identifier: AGPL-3.0-or-later

package repositories

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

const msgRoutingWebhookNotFound = "routing webhook not found"

// RoutingWebhookRepository handles routing webhook database operations
type RoutingWebhookRepository struct {
	pool *pgxpool.Pool
}

// NewRoutingWebhookRepository creates a new RoutingWebhookRepository
func NewRoutingWebhookRepository(pool *pgxpool.Pool) *RoutingWebhookRepository {
	return &RoutingWebhookRepository{pool: pool}
}

// Create creates a new routing webhook
func (r *RoutingWebhookRepository) Create(ctx context.Context, webhook *models.RoutingWebhook) error {
	query := `
		INSERT INTO iam_routing_webhooks (
			id, tenant_id, name, description, url, method,
			auth_type, auth_secret, auth_username,
			timeout_ms, retry_count,
			cb_enabled, cb_threshold, cb_timeout_sec,
			fallback_action, fallback_provider_id,
			is_enabled, priority,
			created_at, updated_at, created_by
		) VALUES (
			$1, $2, $3, $4, $5, $6,
			$7, $8, $9,
			$10, $11,
			$12, $13, $14,
			$15, $16,
			$17, $18,
			$19, $20, $21
		)
	`

	_, err := r.pool.Exec(ctx, query,
		webhook.ID,
		webhook.TenantID,
		webhook.Name,
		webhook.Description,
		webhook.URL,
		webhook.Method,
		webhook.AuthType,
		webhook.AuthSecret,
		webhook.AuthUsername,
		webhook.TimeoutMs,
		webhook.RetryCount,
		webhook.CBEnabled,
		webhook.CBThreshold,
		webhook.CBTimeoutSec,
		webhook.FallbackAction,
		webhook.FallbackProviderID,
		webhook.IsEnabled,
		webhook.Priority,
		webhook.CreatedAt,
		webhook.UpdatedAt,
		webhook.CreatedBy,
	)
	if err != nil {
		return fmt.Errorf("Create: %w", err)
	}
	return nil
}

// GetByID retrieves a routing webhook by ID
func (r *RoutingWebhookRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.RoutingWebhook, error) {
	query := `
		SELECT id, tenant_id, name, description, url, method,
		       auth_type, auth_secret, auth_username,
		       timeout_ms, retry_count,
		       cb_enabled, cb_threshold, cb_timeout_sec,
		       fallback_action, fallback_provider_id,
		       is_enabled, priority,
		       created_at, updated_at, created_by
		FROM iam_routing_webhooks
		WHERE id = $1
	`

	webhook := &models.RoutingWebhook{}
	err := r.pool.QueryRow(ctx, query, id).Scan(
		&webhook.ID,
		&webhook.TenantID,
		&webhook.Name,
		&webhook.Description,
		&webhook.URL,
		&webhook.Method,
		&webhook.AuthType,
		&webhook.AuthSecret,
		&webhook.AuthUsername,
		&webhook.TimeoutMs,
		&webhook.RetryCount,
		&webhook.CBEnabled,
		&webhook.CBThreshold,
		&webhook.CBTimeoutSec,
		&webhook.FallbackAction,
		&webhook.FallbackProviderID,
		&webhook.IsEnabled,
		&webhook.Priority,
		&webhook.CreatedAt,
		&webhook.UpdatedAt,
		&webhook.CreatedBy,
	)

	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errors.New(msgRoutingWebhookNotFound)
	}
	if err != nil {
		return nil, fmt.Errorf("GetByID: %w", err)
	}
	return webhook, nil
}

// GetByIDAndTenant retrieves a routing webhook by ID and tenant
func (r *RoutingWebhookRepository) GetByIDAndTenant(ctx context.Context, id, tenantID uuid.UUID) (*models.RoutingWebhook, error) {
	query := `
		SELECT id, tenant_id, name, description, url, method,
		       auth_type, auth_secret, auth_username,
		       timeout_ms, retry_count,
		       cb_enabled, cb_threshold, cb_timeout_sec,
		       fallback_action, fallback_provider_id,
		       is_enabled, priority,
		       created_at, updated_at, created_by
		FROM iam_routing_webhooks
		WHERE id = $1 AND tenant_id = $2
	`

	webhook := &models.RoutingWebhook{}
	err := r.pool.QueryRow(ctx, query, id, tenantID).Scan(
		&webhook.ID,
		&webhook.TenantID,
		&webhook.Name,
		&webhook.Description,
		&webhook.URL,
		&webhook.Method,
		&webhook.AuthType,
		&webhook.AuthSecret,
		&webhook.AuthUsername,
		&webhook.TimeoutMs,
		&webhook.RetryCount,
		&webhook.CBEnabled,
		&webhook.CBThreshold,
		&webhook.CBTimeoutSec,
		&webhook.FallbackAction,
		&webhook.FallbackProviderID,
		&webhook.IsEnabled,
		&webhook.Priority,
		&webhook.CreatedAt,
		&webhook.UpdatedAt,
		&webhook.CreatedBy,
	)

	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errors.New(msgRoutingWebhookNotFound)
	}
	if err != nil {
		return nil, fmt.Errorf("GetByIDAndTenant: %w", err)
	}
	return webhook, nil
}

// Update updates a routing webhook
func (r *RoutingWebhookRepository) Update(ctx context.Context, webhook *models.RoutingWebhook) error {
	query := `
		UPDATE iam_routing_webhooks
		SET name = $1, description = $2, url = $3, method = $4,
		    auth_type = $5, auth_secret = $6, auth_username = $7,
		    timeout_ms = $8, retry_count = $9,
		    cb_enabled = $10, cb_threshold = $11, cb_timeout_sec = $12,
		    fallback_action = $13, fallback_provider_id = $14,
		    is_enabled = $15, priority = $16,
		    updated_at = now()
		WHERE id = $17 AND tenant_id = $18
	`

	result, err := r.pool.Exec(ctx, query,
		webhook.Name,
		webhook.Description,
		webhook.URL,
		webhook.Method,
		webhook.AuthType,
		webhook.AuthSecret,
		webhook.AuthUsername,
		webhook.TimeoutMs,
		webhook.RetryCount,
		webhook.CBEnabled,
		webhook.CBThreshold,
		webhook.CBTimeoutSec,
		webhook.FallbackAction,
		webhook.FallbackProviderID,
		webhook.IsEnabled,
		webhook.Priority,
		webhook.ID,
		webhook.TenantID,
	)
	if err != nil {
		return fmt.Errorf("Update: %w", err)
	}
	if result.RowsAffected() == 0 {
		return errors.New(msgRoutingWebhookNotFound)
	}
	return nil
}

// Delete deletes a routing webhook
func (r *RoutingWebhookRepository) Delete(ctx context.Context, id, tenantID uuid.UUID) error {
	query := `DELETE FROM iam_routing_webhooks WHERE id = $1 AND tenant_id = $2`
	result, err := r.pool.Exec(ctx, query, id, tenantID)
	if err != nil {
		return fmt.Errorf("Delete: %w", err)
	}
	if result.RowsAffected() == 0 {
		return errors.New(msgRoutingWebhookNotFound)
	}
	return nil
}

// List lists routing webhooks for a tenant with pagination
func (r *RoutingWebhookRepository) List(ctx context.Context, tenantID uuid.UUID, page, pageSize int) ([]*models.RoutingWebhook, int, error) {
	offset := (page - 1) * pageSize

	// Count query
	countQuery := `SELECT COUNT(*) FROM iam_routing_webhooks WHERE tenant_id = $1`
	var total int
	err := r.pool.QueryRow(ctx, countQuery, tenantID).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("List count: %w", err)
	}

	// List query
	listQuery := `
		SELECT id, tenant_id, name, description, url, method,
		       auth_type, auth_secret, auth_username,
		       timeout_ms, retry_count,
		       cb_enabled, cb_threshold, cb_timeout_sec,
		       fallback_action, fallback_provider_id,
		       is_enabled, priority,
		       created_at, updated_at, created_by
		FROM iam_routing_webhooks
		WHERE tenant_id = $1
		ORDER BY priority ASC, created_at DESC
		LIMIT $2 OFFSET $3
	`

	rows, err := r.pool.Query(ctx, listQuery, tenantID, pageSize, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("List: %w", err)
	}
	defer rows.Close()

	webhooks := make([]*models.RoutingWebhook, 0)
	for rows.Next() {
		webhook := &models.RoutingWebhook{}
		err := rows.Scan(
			&webhook.ID,
			&webhook.TenantID,
			&webhook.Name,
			&webhook.Description,
			&webhook.URL,
			&webhook.Method,
			&webhook.AuthType,
			&webhook.AuthSecret,
			&webhook.AuthUsername,
			&webhook.TimeoutMs,
			&webhook.RetryCount,
			&webhook.CBEnabled,
			&webhook.CBThreshold,
			&webhook.CBTimeoutSec,
			&webhook.FallbackAction,
			&webhook.FallbackProviderID,
			&webhook.IsEnabled,
			&webhook.Priority,
			&webhook.CreatedAt,
			&webhook.UpdatedAt,
			&webhook.CreatedBy,
		)
		if err != nil {
			return nil, 0, fmt.Errorf("List scan: %w", err)
		}
		webhooks = append(webhooks, webhook)
	}

	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("List: rows iteration: %w", err)
	}

	return webhooks, total, nil
}

// GetEnabled retrieves enabled routing webhooks for a tenant, ordered by priority
func (r *RoutingWebhookRepository) GetEnabled(ctx context.Context, tenantID uuid.UUID) ([]*models.RoutingWebhook, error) {
	query := `
		SELECT id, tenant_id, name, description, url, method,
		       auth_type, auth_secret, auth_username,
		       timeout_ms, retry_count,
		       cb_enabled, cb_threshold, cb_timeout_sec,
		       fallback_action, fallback_provider_id,
		       is_enabled, priority,
		       created_at, updated_at, created_by
		FROM iam_routing_webhooks
		WHERE tenant_id = $1 AND is_enabled = true
		ORDER BY priority ASC
	`

	rows, err := r.pool.Query(ctx, query, tenantID)
	if err != nil {
		return nil, fmt.Errorf("GetEnabled: %w", err)
	}
	defer rows.Close()

	webhooks := make([]*models.RoutingWebhook, 0)
	for rows.Next() {
		webhook := &models.RoutingWebhook{}
		err := rows.Scan(
			&webhook.ID,
			&webhook.TenantID,
			&webhook.Name,
			&webhook.Description,
			&webhook.URL,
			&webhook.Method,
			&webhook.AuthType,
			&webhook.AuthSecret,
			&webhook.AuthUsername,
			&webhook.TimeoutMs,
			&webhook.RetryCount,
			&webhook.CBEnabled,
			&webhook.CBThreshold,
			&webhook.CBTimeoutSec,
			&webhook.FallbackAction,
			&webhook.FallbackProviderID,
			&webhook.IsEnabled,
			&webhook.Priority,
			&webhook.CreatedAt,
			&webhook.UpdatedAt,
			&webhook.CreatedBy,
		)
		if err != nil {
			return nil, fmt.Errorf("GetEnabled scan: %w", err)
		}
		webhooks = append(webhooks, webhook)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("GetEnabled: rows iteration: %w", err)
	}

	return webhooks, nil
}

// CreateLog creates a webhook execution log entry
func (r *RoutingWebhookRepository) CreateLog(ctx context.Context, log *models.RoutingWebhookLog) error {
	query := `
		INSERT INTO iam_routing_webhook_logs (
			id, tenant_id, webhook_id,
			request_url, request_body,
			response_status, response_body, response_ms,
			action_taken, provider_id, error_message, used_fallback,
			created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
	`

	_, err := r.pool.Exec(ctx, query,
		log.ID,
		log.TenantID,
		log.WebhookID,
		log.RequestURL,
		log.RequestBody,
		log.ResponseStatus,
		log.ResponseBody,
		log.ResponseMs,
		log.ActionTaken,
		log.ProviderID,
		log.ErrorMessage,
		log.UsedFallback,
		log.CreatedAt,
	)
	if err != nil {
		return fmt.Errorf("CreateLog: %w", err)
	}
	return nil
}

// ListLogs lists webhook execution logs for a specific webhook
func (r *RoutingWebhookRepository) ListLogs(ctx context.Context, webhookID uuid.UUID, page, pageSize int) ([]*models.RoutingWebhookLog, int, error) {
	offset := (page - 1) * pageSize

	// Count
	countQuery := `SELECT COUNT(*) FROM iam_routing_webhook_logs WHERE webhook_id = $1`
	var total int
	err := r.pool.QueryRow(ctx, countQuery, webhookID).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("ListLogs count: %w", err)
	}

	// List
	listQuery := `
		SELECT id, tenant_id, webhook_id,
		       request_url, request_body,
		       response_status, response_body, response_ms,
		       action_taken, provider_id, error_message, used_fallback,
		       created_at
		FROM iam_routing_webhook_logs
		WHERE webhook_id = $1
		ORDER BY created_at DESC
		LIMIT $2 OFFSET $3
	`

	rows, err := r.pool.Query(ctx, listQuery, webhookID, pageSize, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("ListLogs: %w", err)
	}
	defer rows.Close()

	logs := make([]*models.RoutingWebhookLog, 0)
	for rows.Next() {
		logEntry := &models.RoutingWebhookLog{}
		var reqBody, respBody []byte
		err := rows.Scan(
			&logEntry.ID,
			&logEntry.TenantID,
			&logEntry.WebhookID,
			&logEntry.RequestURL,
			&reqBody,
			&logEntry.ResponseStatus,
			&respBody,
			&logEntry.ResponseMs,
			&logEntry.ActionTaken,
			&logEntry.ProviderID,
			&logEntry.ErrorMessage,
			&logEntry.UsedFallback,
			&logEntry.CreatedAt,
		)
		if err != nil {
			return nil, 0, fmt.Errorf("ListLogs scan: %w", err)
		}
		if len(reqBody) > 0 {
			logEntry.RequestBody = json.RawMessage(reqBody)
		}
		if len(respBody) > 0 {
			logEntry.ResponseBody = json.RawMessage(respBody)
		}
		logs = append(logs, logEntry)
	}

	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("ListLogs: rows iteration: %w", err)
	}

	return logs, total, nil
}
