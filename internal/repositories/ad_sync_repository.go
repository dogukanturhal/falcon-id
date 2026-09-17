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

// ADSyncRepository handles AD sync data access
type ADSyncRepository struct {
	db *pgxpool.Pool
}

// NewADSyncRepository creates a new AD sync repository
func NewADSyncRepository(db *pgxpool.Pool) *ADSyncRepository {
	return &ADSyncRepository{db: db}
}

// GetSyncState retrieves the sync state for a provider and domain controller
func (r *ADSyncRepository) GetSyncState(ctx context.Context, tenantID, providerID uuid.UUID, dc string) (*models.ADSyncState, error) {
	query := `
		SELECT id, tenant_id, provider_id, domain_controller, highest_usn, invocation_id,
		       last_sync_at, last_full_sync_at, sync_status, error_message, created_at, updated_at
		FROM iam_ad_sync_state
		WHERE tenant_id = $1 AND provider_id = $2 AND domain_controller = $3`

	state := &models.ADSyncState{}
	err := r.db.QueryRow(ctx, query, tenantID, providerID, dc).Scan(
		&state.ID, &state.TenantID, &state.ProviderID, &state.DomainController,
		&state.HighestUSN, &state.InvocationID, &state.LastSyncAt, &state.LastFullSyncAt,
		&state.SyncStatus, &state.ErrorMessage, &state.CreatedAt, &state.UpdatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("GetSyncState: %w", err)
	}
	return state, nil
}

// UpsertSyncState creates or updates the sync state
func (r *ADSyncRepository) UpsertSyncState(ctx context.Context, state *models.ADSyncState) error {
	query := `
		INSERT INTO iam_ad_sync_state (
			id, tenant_id, provider_id, domain_controller, highest_usn, invocation_id,
			last_sync_at, last_full_sync_at, sync_status, error_message
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		ON CONFLICT (tenant_id, provider_id, domain_controller) DO UPDATE SET
			highest_usn = EXCLUDED.highest_usn,
			invocation_id = EXCLUDED.invocation_id,
			last_sync_at = EXCLUDED.last_sync_at,
			last_full_sync_at = EXCLUDED.last_full_sync_at,
			sync_status = EXCLUDED.sync_status,
			error_message = EXCLUDED.error_message,
			updated_at = NOW()
		RETURNING id, created_at, updated_at`

	if state.ID == uuid.Nil {
		state.ID = uuid.New()
	}

	return r.db.QueryRow(ctx, query,
		state.ID, state.TenantID, state.ProviderID, state.DomainController,
		state.HighestUSN, state.InvocationID, state.LastSyncAt, state.LastFullSyncAt,
		state.SyncStatus, state.ErrorMessage,
	).Scan(&state.ID, &state.CreatedAt, &state.UpdatedAt)
}

// GetObjectMapping retrieves an object mapping by AD GUID
func (r *ADSyncRepository) GetObjectMapping(ctx context.Context, tenantID, providerID uuid.UUID, adGUID string) (*models.ADObjectMapping, error) {
	query := `
		SELECT id, tenant_id, provider_id, ad_object_guid, ad_object_dn, ad_object_type,
		       iam_object_id, iam_object_type, usn_changed, when_changed, sync_status,
		       conflict_data, last_synced_at, created_at, updated_at
		FROM iam_ad_object_mapping
		WHERE tenant_id = $1 AND provider_id = $2 AND ad_object_guid = $3`

	mapping := &models.ADObjectMapping{}
	var conflictDataBytes []byte

	err := r.db.QueryRow(ctx, query, tenantID, providerID, adGUID).Scan(
		&mapping.ID, &mapping.TenantID, &mapping.ProviderID, &mapping.ADObjectGUID,
		&mapping.ADObjectDN, &mapping.ADObjectType, &mapping.IAMObjectID, &mapping.IAMObjectType,
		&mapping.USNChanged, &mapping.WhenChanged, &mapping.SyncStatus,
		&conflictDataBytes, &mapping.LastSyncedAt, &mapping.CreatedAt, &mapping.UpdatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("GetObjectMapping: %w", err)
	}

	if conflictDataBytes != nil {
		_ = json.Unmarshal(conflictDataBytes, &mapping.ConflictData)
	}

	return mapping, nil
}

// UpsertObjectMapping creates or updates an object mapping
func (r *ADSyncRepository) UpsertObjectMapping(ctx context.Context, mapping *models.ADObjectMapping) error {
	conflictDataBytes, _ := json.Marshal(mapping.ConflictData)

	query := `
		INSERT INTO iam_ad_object_mapping (
			id, tenant_id, provider_id, ad_object_guid, ad_object_dn, ad_object_type,
			iam_object_id, iam_object_type, usn_changed, when_changed, sync_status, conflict_data
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
		ON CONFLICT (tenant_id, provider_id, ad_object_guid) DO UPDATE SET
			ad_object_dn = EXCLUDED.ad_object_dn,
			iam_object_id = EXCLUDED.iam_object_id,
			usn_changed = EXCLUDED.usn_changed,
			when_changed = EXCLUDED.when_changed,
			sync_status = EXCLUDED.sync_status,
			conflict_data = EXCLUDED.conflict_data,
			last_synced_at = NOW(),
			updated_at = NOW()
		RETURNING id, created_at, updated_at, last_synced_at`

	if mapping.ID == uuid.Nil {
		mapping.ID = uuid.New()
	}

	return r.db.QueryRow(ctx, query,
		mapping.ID, mapping.TenantID, mapping.ProviderID, mapping.ADObjectGUID,
		mapping.ADObjectDN, mapping.ADObjectType, mapping.IAMObjectID, mapping.IAMObjectType,
		mapping.USNChanged, mapping.WhenChanged, mapping.SyncStatus, conflictDataBytes,
	).Scan(&mapping.ID, &mapping.CreatedAt, &mapping.UpdatedAt, &mapping.LastSyncedAt)
}

// GetGroupRoleMappings retrieves active group-to-role mappings for a provider
func (r *ADSyncRepository) GetGroupRoleMappings(ctx context.Context, tenantID, providerID uuid.UUID) ([]models.ADGroupRoleMapping, error) {
	query := `
		SELECT id, tenant_id, provider_id, ad_group_guid, ad_group_dn, ad_group_name,
		       iam_role_id, mapping_type, priority, is_active, created_at, updated_at, created_by
		FROM iam_ad_group_role_mapping
		WHERE tenant_id = $1 AND provider_id = $2 AND is_active = true
		ORDER BY priority DESC, ad_group_name`

	rows, err := r.db.Query(ctx, query, tenantID, providerID)
	if err != nil {
		return nil, fmt.Errorf("GetGroupRoleMappings: %w", err)
	}
	defer rows.Close()

	var mappings []models.ADGroupRoleMapping
	for rows.Next() {
		var m models.ADGroupRoleMapping
		if err := rows.Scan(
			&m.ID, &m.TenantID, &m.ProviderID, &m.ADGroupGUID, &m.ADGroupDN, &m.ADGroupName,
			&m.IAMRoleID, &m.MappingType, &m.Priority, &m.IsActive,
			&m.CreatedAt, &m.UpdatedAt, &m.CreatedBy,
		); err != nil {
			return nil, fmt.Errorf("GetGroupRoleMappings: %w", err)
		}
		mappings = append(mappings, m)
	}

	return mappings, rows.Err()
}

// CreateGroupRoleMapping creates a new group-to-role mapping
func (r *ADSyncRepository) CreateGroupRoleMapping(ctx context.Context, mapping *models.ADGroupRoleMapping) error {
	query := `
		INSERT INTO iam_ad_group_role_mapping (
			id, tenant_id, provider_id, ad_group_guid, ad_group_dn, ad_group_name,
			iam_role_id, mapping_type, priority, is_active, created_by
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
		RETURNING created_at, updated_at`

	if mapping.ID == uuid.Nil {
		mapping.ID = uuid.New()
	}
	if mapping.MappingType == "" {
		mapping.MappingType = models.MappingTypeManual
	}

	return r.db.QueryRow(ctx, query,
		mapping.ID, mapping.TenantID, mapping.ProviderID, mapping.ADGroupGUID,
		mapping.ADGroupDN, mapping.ADGroupName, mapping.IAMRoleID, mapping.MappingType,
		mapping.Priority, mapping.IsActive, mapping.CreatedBy,
	).Scan(&mapping.CreatedAt, &mapping.UpdatedAt)
}

// UpdateGroupRoleMapping updates a group-to-role mapping
func (r *ADSyncRepository) UpdateGroupRoleMapping(ctx context.Context, id uuid.UUID, isActive *bool, priority *int) error {
	query := `
		UPDATE iam_ad_group_role_mapping
		SET is_active = COALESCE($2, is_active),
		    priority = COALESCE($3, priority),
		    updated_at = NOW()
		WHERE id = $1`

	_, err := r.db.Exec(ctx, query, id, isActive, priority)
	if err != nil {
		return fmt.Errorf("UpdateGroupRoleMapping: %w", err)
	}
	return nil
}

// DeleteGroupRoleMapping deletes a group-to-role mapping
func (r *ADSyncRepository) DeleteGroupRoleMapping(ctx context.Context, id uuid.UUID) error {
	_, err := r.db.Exec(ctx, "DELETE FROM iam_ad_group_role_mapping WHERE id = $1", id)
	if err != nil {
		return fmt.Errorf("DeleteGroupRoleMapping: %w", err)
	}
	return nil
}

// CreateConflict creates a new sync conflict record
func (r *ADSyncRepository) CreateConflict(ctx context.Context, conflict *models.ADSyncConflict) error {
	adDataBytes, _ := json.Marshal(conflict.ADData)
	iamDataBytes, _ := json.Marshal(conflict.IAMData)

	query := `
		INSERT INTO iam_ad_sync_conflicts (
			id, tenant_id, provider_id, object_mapping_id, ad_object_guid, ad_object_dn,
			conflict_type, ad_data, iam_data, resolution
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		RETURNING created_at`

	if conflict.ID == uuid.Nil {
		conflict.ID = uuid.New()
	}

	return r.db.QueryRow(ctx, query,
		conflict.ID, conflict.TenantID, conflict.ProviderID, conflict.ObjectMappingID,
		conflict.ADObjectGUID, conflict.ADObjectDN, conflict.ConflictType,
		adDataBytes, iamDataBytes, conflict.Resolution,
	).Scan(&conflict.CreatedAt)
}

// GetPendingConflicts retrieves unresolved conflicts
func (r *ADSyncRepository) GetPendingConflicts(ctx context.Context, tenantID, providerID uuid.UUID) ([]models.ADSyncConflict, error) {
	query := `
		SELECT id, tenant_id, provider_id, object_mapping_id, ad_object_guid, ad_object_dn,
		       conflict_type, ad_data, iam_data, resolution, resolution_details,
		       resolved_at, resolved_by, created_at
		FROM iam_ad_sync_conflicts
		WHERE tenant_id = $1 AND provider_id = $2 AND (resolution IS NULL OR resolution = 'pending')
		ORDER BY created_at DESC`

	rows, err := r.db.Query(ctx, query, tenantID, providerID)
	if err != nil {
		return nil, fmt.Errorf("GetPendingConflicts: %w", err)
	}
	defer rows.Close()

	var conflicts []models.ADSyncConflict
	for rows.Next() {
		var c models.ADSyncConflict
		var adDataBytes, iamDataBytes, resDetailsBytes []byte

		if err := rows.Scan(
			&c.ID, &c.TenantID, &c.ProviderID, &c.ObjectMappingID, &c.ADObjectGUID, &c.ADObjectDN,
			&c.ConflictType, &adDataBytes, &iamDataBytes, &c.Resolution, &resDetailsBytes,
			&c.ResolvedAt, &c.ResolvedBy, &c.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf("GetPendingConflicts: %w", err)
		}

		_ = json.Unmarshal(adDataBytes, &c.ADData)
		_ = json.Unmarshal(iamDataBytes, &c.IAMData)
		if resDetailsBytes != nil {
			_ = json.Unmarshal(resDetailsBytes, &c.ResolutionDetails)
		}

		conflicts = append(conflicts, c)
	}

	return conflicts, rows.Err()
}

// GetConflictTenantID retrieves the tenant_id for a specific sync conflict.
func (r *ADSyncRepository) GetConflictTenantID(ctx context.Context, conflictID uuid.UUID) (uuid.UUID, error) {
	var tenantID uuid.UUID
	query := `SELECT tenant_id FROM iam_ad_sync_conflicts WHERE id = $1`
	err := r.db.QueryRow(ctx, query, conflictID).Scan(&tenantID)
	if err != nil {
		return uuid.Nil, fmt.Errorf("GetConflictTenantID: %w", err)
	}
	return tenantID, nil
}

// ResolveConflict resolves a sync conflict
func (r *ADSyncRepository) ResolveConflict(ctx context.Context, conflictID uuid.UUID, resolution string, details map[string]interface{}, resolvedBy uuid.UUID) error {
	detailsBytes, _ := json.Marshal(details)

	query := `
		UPDATE iam_ad_sync_conflicts
		SET resolution = $2,
		    resolution_details = $3,
		    resolved_at = NOW(),
		    resolved_by = $4
		WHERE id = $1`

	_, err := r.db.Exec(ctx, query, conflictID, resolution, detailsBytes, resolvedBy)
	if err != nil {
		return fmt.Errorf("ResolveConflict: %w", err)
	}
	return nil
}

// GetPendingChanges retrieves pending changes for bidirectional sync
func (r *ADSyncRepository) GetPendingChanges(ctx context.Context, tenantID, providerID uuid.UUID, limit int) ([]models.ADPendingChange, error) {
	query := `
		SELECT id, tenant_id, provider_id, object_mapping_id, change_type, change_direction,
		       object_type, object_id, ad_object_dn, change_data, status, attempts,
		       last_error, priority, scheduled_at, processed_at, created_at, created_by
		FROM iam_ad_pending_changes
		WHERE tenant_id = $1 AND provider_id = $2 AND status = 'pending'
		  AND scheduled_at <= NOW()
		ORDER BY priority DESC, created_at
		LIMIT $3`

	rows, err := r.db.Query(ctx, query, tenantID, providerID, limit)
	if err != nil {
		return nil, fmt.Errorf("GetPendingChanges: %w", err)
	}
	defer rows.Close()

	var changes []models.ADPendingChange
	for rows.Next() {
		var c models.ADPendingChange
		var changeDataBytes []byte

		if err := rows.Scan(
			&c.ID, &c.TenantID, &c.ProviderID, &c.ObjectMappingID, &c.ChangeType, &c.ChangeDirection,
			&c.ObjectType, &c.ObjectID, &c.ADObjectDN, &changeDataBytes, &c.Status, &c.Attempts,
			&c.LastError, &c.Priority, &c.ScheduledAt, &c.ProcessedAt, &c.CreatedAt, &c.CreatedBy,
		); err != nil {
			return nil, fmt.Errorf("GetPendingChanges: %w", err)
		}

		_ = json.Unmarshal(changeDataBytes, &c.ChangeData)
		changes = append(changes, c)
	}

	return changes, rows.Err()
}

// CreatePendingChange creates a pending change for bidirectional sync
func (r *ADSyncRepository) CreatePendingChange(ctx context.Context, change *models.ADPendingChange) error {
	changeDataBytes, _ := json.Marshal(change.ChangeData)

	query := `
		INSERT INTO iam_ad_pending_changes (
			id, tenant_id, provider_id, object_mapping_id, change_type, change_direction,
			object_type, object_id, ad_object_dn, change_data, status, priority, created_by
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
		RETURNING created_at, scheduled_at`

	if change.ID == uuid.Nil {
		change.ID = uuid.New()
	}
	if change.Status == "" {
		change.Status = models.PendingChangeStatusPending
	}

	return r.db.QueryRow(ctx, query,
		change.ID, change.TenantID, change.ProviderID, change.ObjectMappingID,
		change.ChangeType, change.ChangeDirection, change.ObjectType, change.ObjectID,
		change.ADObjectDN, changeDataBytes, change.Status, change.Priority, change.CreatedBy,
	).Scan(&change.CreatedAt, &change.ScheduledAt)
}

// UpdatePendingChangeStatus updates the status of a pending change
func (r *ADSyncRepository) UpdatePendingChangeStatus(ctx context.Context, id uuid.UUID, status string, lastError *string) error {
	query := `
		UPDATE iam_ad_pending_changes
		SET status = $2,
		    last_error = $3,
		    attempts = attempts + 1,
		    processed_at = CASE WHEN $2 IN ('completed', 'failed', 'cancelled') THEN NOW() ELSE processed_at END
		WHERE id = $1`

	_, err := r.db.Exec(ctx, query, id, status, lastError)
	if err != nil {
		return fmt.Errorf("UpdatePendingChangeStatus: %w", err)
	}
	return nil
}

// SyncUserRolesFromADGroups syncs user roles based on AD group membership
func (r *ADSyncRepository) SyncUserRolesFromADGroups(ctx context.Context, tenantID, providerID, userID uuid.UUID, adGroupGUIDs []string) error {
	query := `SELECT sync_ad_group_roles($1, $2, $3, $4)`
	_, err := r.db.Exec(ctx, query, tenantID, providerID, userID, adGroupGUIDs)
	if err != nil {
		return fmt.Errorf("SyncUserRolesFromADGroups: %w", err)
	}
	return nil
}

// GetMappingsByIAMObject retrieves all mappings for an IAM object
func (r *ADSyncRepository) GetMappingsByIAMObject(ctx context.Context, objectType string, objectID uuid.UUID) ([]models.ADObjectMapping, error) {
	query := `
		SELECT id, tenant_id, provider_id, ad_object_guid, ad_object_dn, ad_object_type,
		       iam_object_id, iam_object_type, usn_changed, when_changed, sync_status,
		       conflict_data, last_synced_at, created_at, updated_at
		FROM iam_ad_object_mapping
		WHERE iam_object_type = $1 AND iam_object_id = $2`

	rows, err := r.db.Query(ctx, query, objectType, objectID)
	if err != nil {
		return nil, fmt.Errorf("GetMappingsByIAMObject: %w", err)
	}
	defer rows.Close()

	var mappings []models.ADObjectMapping
	for rows.Next() {
		var m models.ADObjectMapping
		var conflictDataBytes []byte

		if err := rows.Scan(
			&m.ID, &m.TenantID, &m.ProviderID, &m.ADObjectGUID, &m.ADObjectDN, &m.ADObjectType,
			&m.IAMObjectID, &m.IAMObjectType, &m.USNChanged, &m.WhenChanged, &m.SyncStatus,
			&conflictDataBytes, &m.LastSyncedAt, &m.CreatedAt, &m.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("GetMappingsByIAMObject: %w", err)
		}

		if conflictDataBytes != nil {
			_ = json.Unmarshal(conflictDataBytes, &m.ConflictData)
		}

		mappings = append(mappings, m)
	}

	return mappings, rows.Err()
}

// DeleteObjectMapping marks an object mapping as deleted
func (r *ADSyncRepository) DeleteObjectMapping(ctx context.Context, id uuid.UUID) error {
	query := `UPDATE iam_ad_object_mapping SET sync_status = 'deleted', updated_at = NOW() WHERE id = $1`
	_, err := r.db.Exec(ctx, query, id)
	if err != nil {
		return fmt.Errorf("DeleteObjectMapping: %w", err)
	}
	return nil
}

// GetSyncStatsByTenant returns sync statistics for a tenant
func (r *ADSyncRepository) GetSyncStatsByTenant(ctx context.Context, tenantID uuid.UUID) (map[string]interface{}, error) {
	query := `
		SELECT
			COUNT(*) FILTER (WHERE sync_status = 'synced') AS synced_count,
			COUNT(*) FILTER (WHERE sync_status = 'pending') AS pending_count,
			COUNT(*) FILTER (WHERE sync_status = 'conflict') AS conflict_count,
			COUNT(*) FILTER (WHERE sync_status = 'deleted') AS deleted_count,
			COUNT(*) FILTER (WHERE ad_object_type = 'user') AS user_mappings,
			COUNT(*) FILTER (WHERE ad_object_type = 'group') AS group_mappings,
			MAX(last_synced_at) AS last_sync
		FROM iam_ad_object_mapping
		WHERE tenant_id = $1`

	var stats struct {
		SyncedCount   int64
		PendingCount  int64
		ConflictCount int64
		DeletedCount  int64
		UserMappings  int64
		GroupMappings int64
		LastSync      *string
	}

	err := r.db.QueryRow(ctx, query, tenantID).Scan(
		&stats.SyncedCount, &stats.PendingCount, &stats.ConflictCount, &stats.DeletedCount,
		&stats.UserMappings, &stats.GroupMappings, &stats.LastSync,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to get sync stats: %w", err)
	}

	return map[string]interface{}{
		"synced_count":   stats.SyncedCount,
		"pending_count":  stats.PendingCount,
		"conflict_count": stats.ConflictCount,
		"deleted_count":  stats.DeletedCount,
		"user_mappings":  stats.UserMappings,
		"group_mappings": stats.GroupMappings,
		"last_sync":      stats.LastSync,
	}, nil
}
