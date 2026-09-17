// SPDX-License-Identifier: AGPL-3.0-or-later

package repositories

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

// IDPScopeAuditRepository is an exported identifier.
// IDPScopeAuditRepository handles the iam_idp_scope_audit_log table.
type IDPScopeAuditRepository struct {
	pool *pgxpool.Pool
}

// NewIDPScopeAuditRepository is an exported identifier.
// NewIDPScopeAuditRepository creates a new IDPScopeAuditRepository.
func NewIDPScopeAuditRepository(pool *pgxpool.Pool) *IDPScopeAuditRepository {
	return &IDPScopeAuditRepository{pool: pool}
}

// Record inserts a new scope audit entry.
func (r *IDPScopeAuditRepository) Record(ctx context.Context, entry *models.IDPScopeAuditEntry) error {
	var metadataJSON []byte
	var err error
	if entry.Metadata != nil {
		metadataJSON, err = json.Marshal(entry.Metadata)
		if err != nil {
			return fmt.Errorf("failed to marshal metadata: %w", err)
		}
	}

	query := `
		INSERT INTO iam_idp_scope_audit_log
			(provider_id, provider_name, action, scope, realm_id, tenant_id, performed_by, reason, metadata)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		RETURNING id, created_at
	`

	return r.pool.QueryRow(ctx, query,
		entry.ProviderID,
		entry.ProviderName,
		entry.Action,
		entry.Scope,
		entry.RealmID,
		entry.TenantID,
		entry.PerformedBy,
		entry.Reason,
		metadataJSON,
	).Scan(&entry.ID, &entry.CreatedAt)
}

// ListByProvider returns all audit entries for a specific provider ID.
func (r *IDPScopeAuditRepository) ListByProvider(ctx context.Context, providerID uuid.UUID) ([]models.IDPScopeAuditEntry, error) {
	query := `
		SELECT id, provider_id, provider_name, action, scope, realm_id, tenant_id,
		       performed_by, reason, metadata, created_at
		FROM iam_idp_scope_audit_log
		WHERE provider_id = $1
		ORDER BY created_at DESC
	`

	rows, err := r.pool.Query(ctx, query, providerID)
	if err != nil {
		return nil, fmt.Errorf("failed to list scope audit entries: %w", err)
	}
	defer rows.Close()

	var entries []models.IDPScopeAuditEntry
	for rows.Next() {
		var entry models.IDPScopeAuditEntry
		var metadataJSON []byte
		if err := rows.Scan(
			&entry.ID, &entry.ProviderID, &entry.ProviderName, &entry.Action,
			&entry.Scope, &entry.RealmID, &entry.TenantID, &entry.PerformedBy,
			&entry.Reason, &metadataJSON, &entry.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf("failed to scan scope audit entry: %w", err)
		}
		if metadataJSON != nil {
			entry.Metadata = make(map[string]any)
			_ = json.Unmarshal(metadataJSON, &entry.Metadata)
		}
		entries = append(entries, entry)
	}

	return entries, rows.Err()
}

// ListByTenant returns recent audit entries for a tenant.
func (r *IDPScopeAuditRepository) ListByTenant(ctx context.Context, tenantID uuid.UUID, limit int) ([]models.IDPScopeAuditEntry, error) {
	if limit <= 0 || limit > 100 {
		limit = 50
	}

	query := `
		SELECT id, provider_id, provider_name, action, scope, realm_id, tenant_id,
		       performed_by, reason, metadata, created_at
		FROM iam_idp_scope_audit_log
		WHERE tenant_id = $1
		ORDER BY created_at DESC
		LIMIT $2
	`

	rows, err := r.pool.Query(ctx, query, tenantID, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to list tenant scope audit entries: %w", err)
	}
	defer rows.Close()

	var entries []models.IDPScopeAuditEntry
	for rows.Next() {
		var entry models.IDPScopeAuditEntry
		var metadataJSON []byte
		if err := rows.Scan(
			&entry.ID, &entry.ProviderID, &entry.ProviderName, &entry.Action,
			&entry.Scope, &entry.RealmID, &entry.TenantID, &entry.PerformedBy,
			&entry.Reason, &metadataJSON, &entry.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf("failed to scan scope audit entry: %w", err)
		}
		if metadataJSON != nil {
			entry.Metadata = make(map[string]any)
			_ = json.Unmarshal(metadataJSON, &entry.Metadata)
		}
		entries = append(entries, entry)
	}

	return entries, rows.Err()
}
