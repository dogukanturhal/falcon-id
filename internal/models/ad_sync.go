// SPDX-License-Identifier: AGPL-3.0-or-later

package models

import (
	"time"

	"github.com/google/uuid"
)

// ADSyncState represents the synchronization state for an AD provider
type ADSyncState struct {
	ID               uuid.UUID  `json:"id" db:"id"`
	TenantID         uuid.UUID  `json:"tenant_id" db:"tenant_id"`
	ProviderID       uuid.UUID  `json:"provider_id" db:"provider_id"`
	DomainController string     `json:"domain_controller" db:"domain_controller"`
	HighestUSN       int64      `json:"highest_usn" db:"highest_usn"`
	InvocationID     *string    `json:"invocation_id,omitempty" db:"invocation_id"`
	LastSyncAt       *time.Time `json:"last_sync_at,omitempty" db:"last_sync_at"`
	LastFullSyncAt   *time.Time `json:"last_full_sync_at,omitempty" db:"last_full_sync_at"`
	SyncStatus       string     `json:"sync_status" db:"sync_status"`
	ErrorMessage     *string    `json:"error_message,omitempty" db:"error_message"`
	CreatedAt        time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt        time.Time  `json:"updated_at" db:"updated_at"`
}

// SyncStatus constants
const (
	SyncStatusIdle     = "idle"
	SyncStatusSyncing  = "syncing"
	SyncStatusComplete = "complete"
	SyncStatusError    = "error"
)

// ADObjectMapping represents a mapping between an AD object and an IAM object
type ADObjectMapping struct {
	ID            uuid.UUID              `json:"id" db:"id"`
	TenantID      uuid.UUID              `json:"tenant_id" db:"tenant_id"`
	ProviderID    uuid.UUID              `json:"provider_id" db:"provider_id"`
	ADObjectGUID  string                 `json:"ad_object_guid" db:"ad_object_guid"`
	ADObjectDN    string                 `json:"ad_object_dn" db:"ad_object_dn"`
	ADObjectType  string                 `json:"ad_object_type" db:"ad_object_type"`
	IAMObjectID   uuid.UUID              `json:"iam_object_id" db:"iam_object_id"`
	IAMObjectType string                 `json:"iam_object_type" db:"iam_object_type"`
	USNChanged    *int64                 `json:"usn_changed,omitempty" db:"usn_changed"`
	WhenChanged   *time.Time             `json:"when_changed,omitempty" db:"when_changed"`
	SyncStatus    string                 `json:"sync_status" db:"sync_status"`
	ConflictData  map[string]interface{} `json:"conflict_data,omitempty" db:"conflict_data"`
	LastSyncedAt  time.Time              `json:"last_synced_at" db:"last_synced_at"`
	CreatedAt     time.Time              `json:"created_at" db:"created_at"`
	UpdatedAt     time.Time              `json:"updated_at" db:"updated_at"`
}

// ObjectMappingStatus constants
const (
	ObjectMappingSynced   = "synced"
	ObjectMappingPending  = "pending"
	ObjectMappingConflict = "conflict"
	ObjectMappingDeleted  = "deleted"
)

// ADObjectType constants
const (
	ADObjectTypeUser  = "user"
	ADObjectTypeGroup = "group"
)

// ADGroupRoleMapping represents a mapping between an AD group and an IAM role
type ADGroupRoleMapping struct {
	ID          uuid.UUID  `json:"id" db:"id"`
	TenantID    uuid.UUID  `json:"tenant_id" db:"tenant_id"`
	ProviderID  uuid.UUID  `json:"provider_id" db:"provider_id"`
	ADGroupGUID string     `json:"ad_group_guid" db:"ad_group_guid"`
	ADGroupDN   string     `json:"ad_group_dn" db:"ad_group_dn"`
	ADGroupName string     `json:"ad_group_name" db:"ad_group_name"`
	IAMRoleID   uuid.UUID  `json:"iam_role_id" db:"iam_role_id"`
	MappingType string     `json:"mapping_type" db:"mapping_type"`
	Priority    int        `json:"priority" db:"priority"`
	IsActive    bool       `json:"is_active" db:"is_active"`
	CreatedAt   time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at" db:"updated_at"`
	CreatedBy   *uuid.UUID `json:"created_by,omitempty" db:"created_by"`
}

// MappingType constants
const (
	MappingTypeAutomatic = "automatic"
	MappingTypeManual    = "manual"
)

// ADSyncConflict represents a synchronization conflict
type ADSyncConflict struct {
	ID                uuid.UUID              `json:"id" db:"id"`
	TenantID          uuid.UUID              `json:"tenant_id" db:"tenant_id"`
	ProviderID        uuid.UUID              `json:"provider_id" db:"provider_id"`
	ObjectMappingID   *uuid.UUID             `json:"object_mapping_id,omitempty" db:"object_mapping_id"`
	ADObjectGUID      string                 `json:"ad_object_guid" db:"ad_object_guid"`
	ADObjectDN        *string                `json:"ad_object_dn,omitempty" db:"ad_object_dn"`
	ConflictType      string                 `json:"conflict_type" db:"conflict_type"`
	ADData            map[string]interface{} `json:"ad_data" db:"ad_data"`
	IAMData           map[string]interface{} `json:"iam_data" db:"iam_data"`
	Resolution        *string                `json:"resolution,omitempty" db:"resolution"`
	ResolutionDetails map[string]interface{} `json:"resolution_details,omitempty" db:"resolution_details"`
	ResolvedAt        *time.Time             `json:"resolved_at,omitempty" db:"resolved_at"`
	ResolvedBy        *uuid.UUID             `json:"resolved_by,omitempty" db:"resolved_by"`
	CreatedAt         time.Time              `json:"created_at" db:"created_at"`
}

// ConflictType constants
const (
	ConflictTypeAttributeMismatch = "attribute_mismatch"
	ConflictTypeDeletedInAD       = "deleted_in_ad"
	ConflictTypeDeletedInIAM      = "deleted_in_iam"
	ConflictTypeDuplicate         = "duplicate"
)

// ConflictResolution constants
const (
	ResolutionADWins  = "ad_wins"
	ResolutionIAMWins = "iam_wins"
	ResolutionMerged  = "merged"
	ResolutionIgnored = "ignored"
	ResolutionPending = "pending"
)

// ADPendingChange represents a pending change for bidirectional sync
type ADPendingChange struct {
	ID              uuid.UUID              `json:"id" db:"id"`
	TenantID        uuid.UUID              `json:"tenant_id" db:"tenant_id"`
	ProviderID      uuid.UUID              `json:"provider_id" db:"provider_id"`
	ObjectMappingID *uuid.UUID             `json:"object_mapping_id,omitempty" db:"object_mapping_id"`
	ChangeType      string                 `json:"change_type" db:"change_type"`
	ChangeDirection string                 `json:"change_direction" db:"change_direction"`
	ObjectType      string                 `json:"object_type" db:"object_type"`
	ObjectID        *uuid.UUID             `json:"object_id,omitempty" db:"object_id"`
	ADObjectDN      *string                `json:"ad_object_dn,omitempty" db:"ad_object_dn"`
	ChangeData      map[string]interface{} `json:"change_data" db:"change_data"`
	Status          string                 `json:"status" db:"status"`
	Attempts        int                    `json:"attempts" db:"attempts"`
	LastError       *string                `json:"last_error,omitempty" db:"last_error"`
	Priority        int                    `json:"priority" db:"priority"`
	ScheduledAt     time.Time              `json:"scheduled_at" db:"scheduled_at"`
	ProcessedAt     *time.Time             `json:"processed_at,omitempty" db:"processed_at"`
	CreatedAt       time.Time              `json:"created_at" db:"created_at"`
	CreatedBy       *uuid.UUID             `json:"created_by,omitempty" db:"created_by"`
}

// ChangeType constants
const (
	ChangeTypeCreate          = "create"
	ChangeTypeUpdate          = "update"
	ChangeTypeDelete          = "delete"
	ChangeTypeAddToGroup      = "add_to_group"
	ChangeTypeRemoveFromGroup = "remove_from_group"
)

// ChangeDirection constants
const (
	ChangeDirectionToAD  = "to_ad"
	ChangeDirectionToIAM = "to_iam"
)

// PendingChangeStatus constants
const (
	PendingChangeStatusPending    = "pending"
	PendingChangeStatusProcessing = "processing"
	PendingChangeStatusCompleted  = "completed"
	PendingChangeStatusFailed     = "failed"
	PendingChangeStatusCancelled  = "cancelled"
)

// CreateADGroupRoleMappingRequest represents a request to create an AD group to role mapping
type CreateADGroupRoleMappingRequest struct {
	ProviderID  uuid.UUID `json:"provider_id" binding:"required"`
	ADGroupGUID string    `json:"ad_group_guid" binding:"required"`
	ADGroupDN   string    `json:"ad_group_dn" binding:"required"`
	ADGroupName string    `json:"ad_group_name" binding:"required"`
	IAMRoleID   uuid.UUID `json:"iam_role_id" binding:"required"`
	MappingType string    `json:"mapping_type"`
	Priority    int       `json:"priority"`
}

// UpdateADGroupRoleMappingRequest represents a request to update an AD group to role mapping
type UpdateADGroupRoleMappingRequest struct {
	IsActive *bool `json:"is_active,omitempty"`
	Priority *int  `json:"priority,omitempty"`
}

// ADSyncResult represents the result of an AD sync operation
type ADSyncResult struct {
	Status           string    `json:"status"`
	UsersCreated     int       `json:"users_created"`
	UsersUpdated     int       `json:"users_updated"`
	UsersDisabled    int       `json:"users_disabled"`
	GroupsCreated    int       `json:"groups_created"`
	GroupsUpdated    int       `json:"groups_updated"`
	RolesAssigned    int       `json:"roles_assigned"`
	RolesRevoked     int       `json:"roles_revoked"`
	ConflictsFound   int       `json:"conflicts_found"`
	ErrorCount       int       `json:"error_count"`
	StartedAt        time.Time `json:"started_at"`
	CompletedAt      time.Time `json:"completed_at"`
	HighestUSNBefore int64     `json:"highest_usn_before"`
	HighestUSNAfter  int64     `json:"highest_usn_after"`
}

// IncrementalSyncRequest represents a request for incremental AD sync
type IncrementalSyncRequest struct {
	ProviderID       uuid.UUID `json:"provider_id" binding:"required"`
	DomainController string    `json:"domain_controller"`
	ForceFullSync    bool      `json:"force_full_sync"`
}

// ResolveConflictRequest represents a request to resolve an AD sync conflict
type ResolveConflictRequest struct {
	Resolution        string                 `json:"resolution" binding:"required"`
	ResolutionDetails map[string]interface{} `json:"resolution_details,omitempty"`
}
