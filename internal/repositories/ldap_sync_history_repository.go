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

// LDAPSyncHistoryRepository is an exported type.
type LDAPSyncHistoryRepository struct {
	db *pgxpool.Pool
}

// NewLDAPSyncHistoryRepository is an exported function.
func NewLDAPSyncHistoryRepository(db *pgxpool.Pool) *LDAPSyncHistoryRepository {
	return &LDAPSyncHistoryRepository{db: db}
}

// Create creates a new LDAP sync history record
func (r *LDAPSyncHistoryRepository) Create(ctx context.Context, history *models.LDAPSyncHistory) error {
	if history.ID == uuid.Nil {
		history.ID = uuid.New()
	}

	errorsJSON, err := json.Marshal(history.Errors)
	if err != nil {
		errorsJSON = []byte("[]")
	}

	query := `
		INSERT INTO ldap_sync_history (
			id, tenant_id, provider_id, provider_name, sync_type, status,
			started_at, completed_at, duration_ms, users_found, users_created,
			users_updated, users_disabled, groups_found, errors, message, triggered_by
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17
		) RETURNING created_at`

	return r.db.QueryRow(ctx, query,
		history.ID, history.TenantID, history.ProviderID, history.ProviderName, history.SyncType,
		history.Status, history.StartedAt, history.CompletedAt, history.DurationMs,
		history.UsersFound, history.UsersCreated, history.UsersUpdated, history.UsersDisabled,
		history.GroupsFound, errorsJSON, history.Message, history.TriggeredBy,
	).Scan(&history.CreatedAt)
}

// Update updates an existing LDAP sync history record
func (r *LDAPSyncHistoryRepository) Update(ctx context.Context, history *models.LDAPSyncHistory) error {
	errorsJSON, err := json.Marshal(history.Errors)
	if err != nil {
		errorsJSON = []byte("[]")
	}

	query := `
		UPDATE ldap_sync_history SET
			status = $2, completed_at = $3, duration_ms = $4, users_found = $5,
			users_created = $6, users_updated = $7, users_disabled = $8,
			groups_found = $9, errors = $10, message = $11
		WHERE id = $1`

	_, err = r.db.Exec(ctx, query,
		history.ID, history.Status, history.CompletedAt, history.DurationMs,
		history.UsersFound, history.UsersCreated, history.UsersUpdated,
		history.UsersDisabled, history.GroupsFound, errorsJSON, history.Message,
	)
	if err != nil {
		return fmt.Errorf("Update: %w", err)
	}
	return nil
}

// GetByProviderID retrieves sync history for a specific provider
func (r *LDAPSyncHistoryRepository) GetByProviderID(ctx context.Context, providerID uuid.UUID, limit, offset int) ([]*models.LDAPSyncHistory, int, error) {
	// Get total count
	var total int
	countQuery := `SELECT COUNT(*) FROM ldap_sync_history WHERE provider_id = $1`
	if err := r.db.QueryRow(ctx, countQuery, providerID).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("failed to count sync history: %w", err)
	}

	// Get records
	query := `
		SELECT id, tenant_id, provider_id, provider_name, sync_type, status,
			   started_at, completed_at, duration_ms, users_found, users_created,
			   users_updated, users_disabled, groups_found, errors, message, triggered_by, created_at
		FROM ldap_sync_history
		WHERE provider_id = $1
		ORDER BY started_at DESC
		LIMIT $2 OFFSET $3`

	rows, err := r.db.Query(ctx, query, providerID, limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to query sync history: %w", err)
	}
	defer rows.Close()

	var history []*models.LDAPSyncHistory
	for rows.Next() {
		h := &models.LDAPSyncHistory{}
		var errorsJSON []byte
		err := rows.Scan(
			&h.ID, &h.TenantID, &h.ProviderID, &h.ProviderName, &h.SyncType, &h.Status,
			&h.StartedAt, &h.CompletedAt, &h.DurationMs, &h.UsersFound, &h.UsersCreated,
			&h.UsersUpdated, &h.UsersDisabled, &h.GroupsFound, &errorsJSON, &h.Message,
			&h.TriggeredBy, &h.CreatedAt,
		)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to scan sync history: %w", err)
		}

		if len(errorsJSON) > 0 {
			_ = json.Unmarshal(errorsJSON, &h.Errors)
		}

		history = append(history, h)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("GetByProviderID: rows iteration: %w", err)
	}

	return history, total, nil
}

// GetByID retrieves a specific sync history record
func (r *LDAPSyncHistoryRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.LDAPSyncHistory, error) {
	h := &models.LDAPSyncHistory{}
	var errorsJSON []byte

	query := `
		SELECT id, tenant_id, provider_id, provider_name, sync_type, status,
			   started_at, completed_at, duration_ms, users_found, users_created,
			   users_updated, users_disabled, groups_found, errors, message, triggered_by, created_at
		FROM ldap_sync_history
		WHERE id = $1`

	err := r.db.QueryRow(ctx, query, id).Scan(
		&h.ID, &h.TenantID, &h.ProviderID, &h.ProviderName, &h.SyncType, &h.Status,
		&h.StartedAt, &h.CompletedAt, &h.DurationMs, &h.UsersFound, &h.UsersCreated,
		&h.UsersUpdated, &h.UsersDisabled, &h.GroupsFound, &errorsJSON, &h.Message,
		&h.TriggeredBy, &h.CreatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get sync history: %w", err)
	}

	if len(errorsJSON) > 0 {
		_ = json.Unmarshal(errorsJSON, &h.Errors)
	}

	return h, nil
}

// GetLatestByProviderID retrieves the latest sync for a provider
func (r *LDAPSyncHistoryRepository) GetLatestByProviderID(ctx context.Context, providerID uuid.UUID) (*models.LDAPSyncHistory, error) {
	h := &models.LDAPSyncHistory{}
	var errorsJSON []byte

	query := `
		SELECT id, tenant_id, provider_id, provider_name, sync_type, status,
			   started_at, completed_at, duration_ms, users_found, users_created,
			   users_updated, users_disabled, groups_found, errors, message, triggered_by, created_at
		FROM ldap_sync_history
		WHERE provider_id = $1
		ORDER BY started_at DESC
		LIMIT 1`

	err := r.db.QueryRow(ctx, query, providerID).Scan(
		&h.ID, &h.TenantID, &h.ProviderID, &h.ProviderName, &h.SyncType, &h.Status,
		&h.StartedAt, &h.CompletedAt, &h.DurationMs, &h.UsersFound, &h.UsersCreated,
		&h.UsersUpdated, &h.UsersDisabled, &h.GroupsFound, &errorsJSON, &h.Message,
		&h.TriggeredBy, &h.CreatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get latest sync history: %w", err)
	}

	if len(errorsJSON) > 0 {
		_ = json.Unmarshal(errorsJSON, &h.Errors)
	}

	return h, nil
}

// DeleteOlderThan deletes sync history older than the specified duration
func (r *LDAPSyncHistoryRepository) DeleteOlderThan(ctx context.Context, olderThan time.Duration) (int64, error) {
	cutoff := time.Now().Add(-olderThan)
	query := `DELETE FROM ldap_sync_history WHERE created_at < $1`
	result, err := r.db.Exec(ctx, query, cutoff)
	if err != nil {
		return 0, fmt.Errorf("failed to delete old sync history: %w", err)
	}
	return result.RowsAffected(), nil
}
