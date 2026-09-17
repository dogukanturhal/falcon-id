// SPDX-License-Identifier: AGPL-3.0-or-later

package models

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ==================== SyncStatus constants ====================

func TestSyncStatusConstants(t *testing.T) {
	tests := []struct {
		name     string
		constant string
		expected string
	}{
		{name: "idle status should match expected value", constant: SyncStatusIdle, expected: "idle"},
		{name: "syncing status should match expected value", constant: SyncStatusSyncing, expected: "syncing"},
		{name: "complete status should match expected value", constant: SyncStatusComplete, expected: "complete"},
		{name: "error status should match expected value", constant: SyncStatusError, expected: "error"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.constant)
		})
	}
}

func TestSyncStatusConstants_Distinct(t *testing.T) {
	statuses := []string{SyncStatusIdle, SyncStatusSyncing, SyncStatusComplete, SyncStatusError}
	seen := make(map[string]struct{}, len(statuses))
	for _, s := range statuses {
		_, dup := seen[s]
		assert.False(t, dup, "duplicate SyncStatus constant: %s", s)
		seen[s] = struct{}{}
	}
}

// ==================== ObjectMapping constants ====================

func TestObjectMappingStatusConstants(t *testing.T) {
	tests := []struct {
		name     string
		constant string
		expected string
	}{
		{name: "synced status", constant: ObjectMappingSynced, expected: "synced"},
		{name: "pending status", constant: ObjectMappingPending, expected: "pending"},
		{name: "conflict status", constant: ObjectMappingConflict, expected: "conflict"},
		{name: "deleted status", constant: ObjectMappingDeleted, expected: "deleted"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.constant)
		})
	}
}

// ==================== ADObjectType constants ====================

func TestADObjectTypeConstants(t *testing.T) {
	assert.Equal(t, "user", ADObjectTypeUser)
	assert.Equal(t, "group", ADObjectTypeGroup)
	assert.NotEqual(t, ADObjectTypeUser, ADObjectTypeGroup)
}

// ==================== MappingType constants ====================

func TestMappingTypeConstants(t *testing.T) {
	assert.Equal(t, "automatic", MappingTypeAutomatic)
	assert.Equal(t, "manual", MappingTypeManual)
	assert.NotEqual(t, MappingTypeAutomatic, MappingTypeManual)
}

// ==================== ChangeType constants ====================

func TestChangeTypeConstants(t *testing.T) {
	tests := []struct {
		name     string
		constant string
		expected string
	}{
		{name: "create change type", constant: ChangeTypeCreate, expected: "create"},
		{name: "update change type", constant: ChangeTypeUpdate, expected: "update"},
		{name: "delete change type", constant: ChangeTypeDelete, expected: "delete"},
		{name: "add to group change type", constant: ChangeTypeAddToGroup, expected: "add_to_group"},
		{name: "remove from group change type", constant: ChangeTypeRemoveFromGroup, expected: "remove_from_group"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.constant)
		})
	}
}

func TestChangeTypeConstants_Distinct(t *testing.T) {
	changeTypes := []string{
		ChangeTypeCreate,
		ChangeTypeUpdate,
		ChangeTypeDelete,
		ChangeTypeAddToGroup,
		ChangeTypeRemoveFromGroup,
	}
	seen := make(map[string]struct{}, len(changeTypes))
	for _, ct := range changeTypes {
		_, dup := seen[ct]
		assert.False(t, dup, "duplicate ChangeType constant: %s", ct)
		seen[ct] = struct{}{}
	}
}

// ==================== ChangeDirection constants ====================

func TestChangeDirectionConstants(t *testing.T) {
	assert.Equal(t, "to_ad", ChangeDirectionToAD)
	assert.Equal(t, "to_iam", ChangeDirectionToIAM)
	assert.NotEqual(t, ChangeDirectionToAD, ChangeDirectionToIAM)
}

// ==================== PendingChangeStatus constants ====================

func TestPendingChangeStatusConstants(t *testing.T) {
	tests := []struct {
		name     string
		constant string
		expected string
	}{
		{name: "pending status", constant: PendingChangeStatusPending, expected: "pending"},
		{name: "processing status", constant: PendingChangeStatusProcessing, expected: "processing"},
		{name: "completed status", constant: PendingChangeStatusCompleted, expected: "completed"},
		{name: "failed status", constant: PendingChangeStatusFailed, expected: "failed"},
		{name: "cancelled status", constant: PendingChangeStatusCancelled, expected: "cancelled"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.constant)
		})
	}
}

func TestPendingChangeStatusConstants_Distinct(t *testing.T) {
	statuses := []string{
		PendingChangeStatusPending,
		PendingChangeStatusProcessing,
		PendingChangeStatusCompleted,
		PendingChangeStatusFailed,
		PendingChangeStatusCancelled,
	}
	seen := make(map[string]struct{}, len(statuses))
	for _, s := range statuses {
		_, dup := seen[s]
		assert.False(t, dup, "duplicate PendingChangeStatus constant: %s", s)
		seen[s] = struct{}{}
	}
}

// ==================== ConflictType constants ====================

func TestConflictTypeConstants(t *testing.T) {
	tests := []struct {
		name     string
		constant string
		expected string
	}{
		{name: "attribute mismatch conflict", constant: ConflictTypeAttributeMismatch, expected: "attribute_mismatch"},
		{name: "deleted in AD conflict", constant: ConflictTypeDeletedInAD, expected: "deleted_in_ad"},
		{name: "deleted in IAM conflict", constant: ConflictTypeDeletedInIAM, expected: "deleted_in_iam"},
		{name: "duplicate conflict", constant: ConflictTypeDuplicate, expected: "duplicate"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.constant)
		})
	}
}

// ==================== ConflictResolution constants ====================

func TestConflictResolutionConstants(t *testing.T) {
	tests := []struct {
		name     string
		constant string
		expected string
	}{
		{name: "AD wins resolution", constant: ResolutionADWins, expected: "ad_wins"},
		{name: "IAM wins resolution", constant: ResolutionIAMWins, expected: "iam_wins"},
		{name: "merged resolution", constant: ResolutionMerged, expected: "merged"},
		{name: "ignored resolution", constant: ResolutionIgnored, expected: "ignored"},
		{name: "pending resolution", constant: ResolutionPending, expected: "pending"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.constant)
		})
	}
}

// ==================== ADSyncState struct ====================

func TestADSyncState_Instantiation(t *testing.T) {
	t.Run("should create a fully populated ADSyncState", func(t *testing.T) {
		id := uuid.New()
		tenantID := uuid.New()
		providerID := uuid.New()
		now := time.Now().Truncate(time.Second)
		lastSync := now.Add(-1 * time.Hour)
		lastFullSync := now.Add(-24 * time.Hour)
		invocationID := "abc123def456"
		errMsg := ""

		state := &ADSyncState{
			ID:               id,
			TenantID:         tenantID,
			ProviderID:       providerID,
			DomainController: "dc01.corp.com",
			HighestUSN:       987654,
			InvocationID:     &invocationID,
			LastSyncAt:       &lastSync,
			LastFullSyncAt:   &lastFullSync,
			SyncStatus:       SyncStatusIdle,
			ErrorMessage:     &errMsg,
			CreatedAt:        now,
			UpdatedAt:        now,
		}

		assert.Equal(t, id, state.ID)
		assert.Equal(t, tenantID, state.TenantID)
		assert.Equal(t, providerID, state.ProviderID)
		assert.Equal(t, "dc01.corp.com", state.DomainController)
		assert.Equal(t, int64(987654), state.HighestUSN)
		require.NotNil(t, state.InvocationID)
		assert.Equal(t, "abc123def456", *state.InvocationID)
		require.NotNil(t, state.LastSyncAt)
		assert.Equal(t, lastSync, *state.LastSyncAt)
		require.NotNil(t, state.LastFullSyncAt)
		assert.Equal(t, lastFullSync, *state.LastFullSyncAt)
		assert.Equal(t, SyncStatusIdle, state.SyncStatus)
		assert.Equal(t, now, state.CreatedAt)
		assert.Equal(t, now, state.UpdatedAt)
	})

	t.Run("should create a new ADSyncState without last sync times", func(t *testing.T) {
		state := &ADSyncState{
			ID:               uuid.New(),
			TenantID:         uuid.New(),
			ProviderID:       uuid.New(),
			DomainController: "dc01.corp.com",
			HighestUSN:       0,
			SyncStatus:       SyncStatusIdle,
		}

		assert.Nil(t, state.LastSyncAt)
		assert.Nil(t, state.LastFullSyncAt)
		assert.Nil(t, state.InvocationID)
		assert.Nil(t, state.ErrorMessage)
		assert.Equal(t, int64(0), state.HighestUSN)
	})

	t.Run("should represent all valid sync status values", func(t *testing.T) {
		statuses := []string{SyncStatusIdle, SyncStatusSyncing, SyncStatusComplete, SyncStatusError}
		for _, status := range statuses {
			state := &ADSyncState{SyncStatus: status}
			assert.Equal(t, status, state.SyncStatus)
		}
	})

	t.Run("should store an error message when sync fails", func(t *testing.T) {
		errMsg := "LDAP connection refused: dial tcp dc01.corp.com:636: connect: connection refused"
		state := &ADSyncState{
			SyncStatus:   SyncStatusError,
			ErrorMessage: &errMsg,
		}

		assert.Equal(t, SyncStatusError, state.SyncStatus)
		require.NotNil(t, state.ErrorMessage)
		assert.Contains(t, *state.ErrorMessage, "connection refused")
	})
}

// ==================== ADObjectMapping struct ====================

func TestADObjectMapping_Instantiation(t *testing.T) {
	t.Run("should create a fully populated ADObjectMapping for a user", func(t *testing.T) {
		id := uuid.New()
		tenantID := uuid.New()
		providerID := uuid.New()
		iamObjectID := uuid.New()
		now := time.Now().Truncate(time.Second)
		whenChanged := now.Add(-30 * time.Minute)
		usnChanged := int64(500100)

		mapping := &ADObjectMapping{
			ID:            id,
			TenantID:      tenantID,
			ProviderID:    providerID,
			ADObjectGUID:  "guid-user-001",
			ADObjectDN:    "CN=Alice,OU=Users,DC=corp,DC=com",
			ADObjectType:  ADObjectTypeUser,
			IAMObjectID:   iamObjectID,
			IAMObjectType: "user",
			USNChanged:    &usnChanged,
			WhenChanged:   &whenChanged,
			SyncStatus:    ObjectMappingSynced,
			ConflictData:  nil,
			LastSyncedAt:  now,
			CreatedAt:     now,
			UpdatedAt:     now,
		}

		assert.Equal(t, id, mapping.ID)
		assert.Equal(t, tenantID, mapping.TenantID)
		assert.Equal(t, providerID, mapping.ProviderID)
		assert.Equal(t, "guid-user-001", mapping.ADObjectGUID)
		assert.Equal(t, "CN=Alice,OU=Users,DC=corp,DC=com", mapping.ADObjectDN)
		assert.Equal(t, ADObjectTypeUser, mapping.ADObjectType)
		assert.Equal(t, iamObjectID, mapping.IAMObjectID)
		assert.Equal(t, "user", mapping.IAMObjectType)
		require.NotNil(t, mapping.USNChanged)
		assert.Equal(t, int64(500100), *mapping.USNChanged)
		require.NotNil(t, mapping.WhenChanged)
		assert.Equal(t, whenChanged, *mapping.WhenChanged)
		assert.Equal(t, ObjectMappingSynced, mapping.SyncStatus)
		assert.Nil(t, mapping.ConflictData)
		assert.Equal(t, now, mapping.LastSyncedAt)
	})

	t.Run("should create a pending ADObjectMapping for a group", func(t *testing.T) {
		mapping := &ADObjectMapping{
			ID:            uuid.New(),
			TenantID:      uuid.New(),
			ProviderID:    uuid.New(),
			ADObjectGUID:  "guid-group-001",
			ADObjectDN:    "CN=Devs,OU=Groups,DC=corp,DC=com",
			ADObjectType:  ADObjectTypeGroup,
			IAMObjectID:   uuid.New(),
			IAMObjectType: "group",
			SyncStatus:    ObjectMappingPending,
		}

		assert.Equal(t, ADObjectTypeGroup, mapping.ADObjectType)
		assert.Equal(t, ObjectMappingPending, mapping.SyncStatus)
		assert.Nil(t, mapping.USNChanged)
		assert.Nil(t, mapping.WhenChanged)
	})

	t.Run("should store conflict data for a conflicting mapping", func(t *testing.T) {
		conflictData := map[string]interface{}{
			"field":     "email",
			"ad_value":  "alice@corp.com",
			"iam_value": "alice@other.com",
		}

		mapping := &ADObjectMapping{
			ID:           uuid.New(),
			SyncStatus:   ObjectMappingConflict,
			ConflictData: conflictData,
		}

		assert.Equal(t, ObjectMappingConflict, mapping.SyncStatus)
		require.NotNil(t, mapping.ConflictData)
		assert.Equal(t, "email", mapping.ConflictData["field"])
		assert.Equal(t, "alice@corp.com", mapping.ConflictData["ad_value"])
	})
}

// ==================== ADGroupRoleMapping struct ====================

func TestADGroupRoleMapping_Instantiation(t *testing.T) {
	t.Run("should create a fully populated ADGroupRoleMapping", func(t *testing.T) {
		id := uuid.New()
		tenantID := uuid.New()
		providerID := uuid.New()
		iamRoleID := uuid.New()
		createdBy := uuid.New()
		now := time.Now().Truncate(time.Second)

		mapping := &ADGroupRoleMapping{
			ID:          id,
			TenantID:    tenantID,
			ProviderID:  providerID,
			ADGroupGUID: "group-guid-001",
			ADGroupDN:   "CN=Admins,OU=Groups,DC=corp,DC=com",
			ADGroupName: "Domain Admins",
			IAMRoleID:   iamRoleID,
			MappingType: MappingTypeAutomatic,
			Priority:    10,
			IsActive:    true,
			CreatedAt:   now,
			UpdatedAt:   now,
			CreatedBy:   &createdBy,
		}

		assert.Equal(t, id, mapping.ID)
		assert.Equal(t, tenantID, mapping.TenantID)
		assert.Equal(t, providerID, mapping.ProviderID)
		assert.Equal(t, "group-guid-001", mapping.ADGroupGUID)
		assert.Equal(t, "CN=Admins,OU=Groups,DC=corp,DC=com", mapping.ADGroupDN)
		assert.Equal(t, "Domain Admins", mapping.ADGroupName)
		assert.Equal(t, iamRoleID, mapping.IAMRoleID)
		assert.Equal(t, MappingTypeAutomatic, mapping.MappingType)
		assert.Equal(t, 10, mapping.Priority)
		assert.True(t, mapping.IsActive)
		assert.Equal(t, now, mapping.CreatedAt)
		require.NotNil(t, mapping.CreatedBy)
		assert.Equal(t, createdBy, *mapping.CreatedBy)
	})

	t.Run("should create a manual inactive mapping with lowest priority", func(t *testing.T) {
		mapping := &ADGroupRoleMapping{
			ID:          uuid.New(),
			ADGroupName: "Archived Group",
			MappingType: MappingTypeManual,
			Priority:    0,
			IsActive:    false,
		}

		assert.Equal(t, MappingTypeManual, mapping.MappingType)
		assert.Equal(t, 0, mapping.Priority)
		assert.False(t, mapping.IsActive)
		assert.Nil(t, mapping.CreatedBy)
	})
}

// ==================== ADSyncConflict struct ====================

func TestADSyncConflict_Instantiation(t *testing.T) {
	t.Run("should create a fully populated unresolved ADSyncConflict", func(t *testing.T) {
		id := uuid.New()
		tenantID := uuid.New()
		providerID := uuid.New()
		objectMappingID := uuid.New()
		adObjectDN := "CN=User,OU=Users,DC=corp,DC=com"
		now := time.Now().Truncate(time.Second)

		conflict := &ADSyncConflict{
			ID:              id,
			TenantID:        tenantID,
			ProviderID:      providerID,
			ObjectMappingID: &objectMappingID,
			ADObjectGUID:    "guid-user-001",
			ADObjectDN:      &adObjectDN,
			ConflictType:    ConflictTypeAttributeMismatch,
			ADData: map[string]interface{}{
				"email": "user@ad.corp.com",
			},
			IAMData: map[string]interface{}{
				"email": "user@iam.corp.com",
			},
			Resolution:        nil,
			ResolutionDetails: nil,
			ResolvedAt:        nil,
			ResolvedBy:        nil,
			CreatedAt:         now,
		}

		assert.Equal(t, id, conflict.ID)
		assert.Equal(t, tenantID, conflict.TenantID)
		assert.Equal(t, ConflictTypeAttributeMismatch, conflict.ConflictType)
		require.NotNil(t, conflict.ObjectMappingID)
		assert.Equal(t, objectMappingID, *conflict.ObjectMappingID)
		require.NotNil(t, conflict.ADObjectDN)
		assert.Equal(t, adObjectDN, *conflict.ADObjectDN)
		assert.Equal(t, "user@ad.corp.com", conflict.ADData["email"])
		assert.Equal(t, "user@iam.corp.com", conflict.IAMData["email"])
		assert.Nil(t, conflict.Resolution)
		assert.Nil(t, conflict.ResolvedAt)
		assert.Nil(t, conflict.ResolvedBy)
	})

	t.Run("should create a resolved ADSyncConflict with AD winning", func(t *testing.T) {
		resolution := ResolutionADWins
		now := time.Now().Truncate(time.Second)
		resolvedBy := uuid.New()
		resolvedAt := now

		conflict := &ADSyncConflict{
			ID:           uuid.New(),
			ConflictType: ConflictTypeAttributeMismatch,
			ADData:       map[string]interface{}{"email": "new@ad.com"},
			IAMData:      map[string]interface{}{"email": "old@iam.com"},
			Resolution:   &resolution,
			ResolutionDetails: map[string]interface{}{
				"resolved_field": "email",
			},
			ResolvedAt: &resolvedAt,
			ResolvedBy: &resolvedBy,
		}

		require.NotNil(t, conflict.Resolution)
		assert.Equal(t, ResolutionADWins, *conflict.Resolution)
		require.NotNil(t, conflict.ResolvedAt)
		assert.Equal(t, resolvedAt, *conflict.ResolvedAt)
		require.NotNil(t, conflict.ResolvedBy)
		assert.Equal(t, resolvedBy, *conflict.ResolvedBy)
		require.NotNil(t, conflict.ResolutionDetails)
		assert.Equal(t, "email", conflict.ResolutionDetails["resolved_field"])
	})

	t.Run("should handle all conflict type values", func(t *testing.T) {
		conflictTypes := []string{
			ConflictTypeAttributeMismatch,
			ConflictTypeDeletedInAD,
			ConflictTypeDeletedInIAM,
			ConflictTypeDuplicate,
		}

		for _, ct := range conflictTypes {
			conflict := &ADSyncConflict{
				ID:           uuid.New(),
				ConflictType: ct,
				ADData:       map[string]interface{}{},
				IAMData:      map[string]interface{}{},
			}
			assert.Equal(t, ct, conflict.ConflictType)
		}
	})
}

// ==================== ADPendingChange struct ====================

func TestADPendingChange_Instantiation(t *testing.T) {
	t.Run("should create a fully populated ADPendingChange", func(t *testing.T) {
		id := uuid.New()
		tenantID := uuid.New()
		providerID := uuid.New()
		objectMappingID := uuid.New()
		objectID := uuid.New()
		adObjectDN := "CN=User,OU=Users,DC=corp,DC=com"
		createdBy := uuid.New()
		now := time.Now().Truncate(time.Second)
		processed := now.Add(5 * time.Second)
		lastErr := "temporary connection error"

		change := &ADPendingChange{
			ID:              id,
			TenantID:        tenantID,
			ProviderID:      providerID,
			ObjectMappingID: &objectMappingID,
			ChangeType:      ChangeTypeUpdate,
			ChangeDirection: ChangeDirectionToAD,
			ObjectType:      ADObjectTypeUser,
			ObjectID:        &objectID,
			ADObjectDN:      &adObjectDN,
			ChangeData: map[string]interface{}{
				"email": "newemail@corp.com",
			},
			Status:      PendingChangeStatusCompleted,
			Attempts:    2,
			LastError:   &lastErr,
			Priority:    5,
			ScheduledAt: now,
			ProcessedAt: &processed,
			CreatedAt:   now,
			CreatedBy:   &createdBy,
		}

		assert.Equal(t, id, change.ID)
		assert.Equal(t, tenantID, change.TenantID)
		assert.Equal(t, providerID, change.ProviderID)
		require.NotNil(t, change.ObjectMappingID)
		assert.Equal(t, objectMappingID, *change.ObjectMappingID)
		assert.Equal(t, ChangeTypeUpdate, change.ChangeType)
		assert.Equal(t, ChangeDirectionToAD, change.ChangeDirection)
		assert.Equal(t, ADObjectTypeUser, change.ObjectType)
		require.NotNil(t, change.ObjectID)
		assert.Equal(t, objectID, *change.ObjectID)
		require.NotNil(t, change.ADObjectDN)
		assert.Equal(t, adObjectDN, *change.ADObjectDN)
		assert.Equal(t, "newemail@corp.com", change.ChangeData["email"])
		assert.Equal(t, PendingChangeStatusCompleted, change.Status)
		assert.Equal(t, 2, change.Attempts)
		require.NotNil(t, change.LastError)
		assert.Equal(t, "temporary connection error", *change.LastError)
		assert.Equal(t, 5, change.Priority)
		assert.Equal(t, now, change.ScheduledAt)
		require.NotNil(t, change.ProcessedAt)
		assert.Equal(t, processed, *change.ProcessedAt)
	})

	t.Run("should create a new pending change with zero attempts", func(t *testing.T) {
		now := time.Now()
		change := &ADPendingChange{
			ID:              uuid.New(),
			TenantID:        uuid.New(),
			ProviderID:      uuid.New(),
			ChangeType:      ChangeTypeCreate,
			ChangeDirection: ChangeDirectionToIAM,
			ObjectType:      ADObjectTypeUser,
			ChangeData:      map[string]interface{}{"dn": "CN=New,DC=corp,DC=com"},
			Status:          PendingChangeStatusPending,
			Attempts:        0,
			ScheduledAt:     now,
			CreatedAt:       now,
		}

		assert.Equal(t, 0, change.Attempts)
		assert.Equal(t, PendingChangeStatusPending, change.Status)
		assert.Nil(t, change.LastError)
		assert.Nil(t, change.ProcessedAt)
		assert.Nil(t, change.ObjectMappingID)
		assert.Nil(t, change.ObjectID)
		assert.Nil(t, change.ADObjectDN)
		assert.Nil(t, change.CreatedBy)
	})

	t.Run("should represent add-to-group direction to IAM", func(t *testing.T) {
		change := &ADPendingChange{
			ChangeType:      ChangeTypeAddToGroup,
			ChangeDirection: ChangeDirectionToIAM,
			ObjectType:      ADObjectTypeUser,
			Status:          PendingChangeStatusPending,
			ChangeData: map[string]interface{}{
				"user_dn":  "CN=Alice,DC=corp,DC=com",
				"group_dn": "CN=Admins,DC=corp,DC=com",
			},
		}

		assert.Equal(t, ChangeTypeAddToGroup, change.ChangeType)
		assert.Equal(t, ChangeDirectionToIAM, change.ChangeDirection)
	})

	t.Run("should represent remove-from-group direction to AD", func(t *testing.T) {
		change := &ADPendingChange{
			ChangeType:      ChangeTypeRemoveFromGroup,
			ChangeDirection: ChangeDirectionToAD,
			Status:          PendingChangeStatusFailed,
			Attempts:        3,
		}

		assert.Equal(t, ChangeTypeRemoveFromGroup, change.ChangeType)
		assert.Equal(t, ChangeDirectionToAD, change.ChangeDirection)
		assert.Equal(t, 3, change.Attempts)
	})
}

// ==================== CreateADGroupRoleMappingRequest ====================

func TestCreateADGroupRoleMappingRequest_Fields(t *testing.T) {
	t.Run("should set all required fields and optional fields", func(t *testing.T) {
		providerID := uuid.New()
		iamRoleID := uuid.New()

		req := &CreateADGroupRoleMappingRequest{
			ProviderID:  providerID,
			ADGroupGUID: "group-guid-001",
			ADGroupDN:   "CN=Admins,OU=Groups,DC=corp,DC=com",
			ADGroupName: "Domain Admins",
			IAMRoleID:   iamRoleID,
			MappingType: MappingTypeAutomatic,
			Priority:    5,
		}

		assert.Equal(t, providerID, req.ProviderID)
		assert.Equal(t, "group-guid-001", req.ADGroupGUID)
		assert.Equal(t, "CN=Admins,OU=Groups,DC=corp,DC=com", req.ADGroupDN)
		assert.Equal(t, "Domain Admins", req.ADGroupName)
		assert.Equal(t, iamRoleID, req.IAMRoleID)
		assert.Equal(t, MappingTypeAutomatic, req.MappingType)
		assert.Equal(t, 5, req.Priority)
	})

	t.Run("should default MappingType and Priority to zero values", func(t *testing.T) {
		req := &CreateADGroupRoleMappingRequest{
			ProviderID:  uuid.New(),
			ADGroupGUID: "guid",
			ADGroupDN:   "CN=Group,DC=corp,DC=com",
			ADGroupName: "Group",
			IAMRoleID:   uuid.New(),
		}

		assert.Empty(t, req.MappingType)
		assert.Equal(t, 0, req.Priority)
	})
}

// ==================== UpdateADGroupRoleMappingRequest ====================

func TestUpdateADGroupRoleMappingRequest_Fields(t *testing.T) {
	t.Run("should deactivate a mapping", func(t *testing.T) {
		isActive := false
		req := &UpdateADGroupRoleMappingRequest{
			IsActive: &isActive,
		}

		require.NotNil(t, req.IsActive)
		assert.False(t, *req.IsActive)
		assert.Nil(t, req.Priority)
	})

	t.Run("should change priority", func(t *testing.T) {
		priority := 20
		req := &UpdateADGroupRoleMappingRequest{
			Priority: &priority,
		}

		require.NotNil(t, req.Priority)
		assert.Equal(t, 20, *req.Priority)
		assert.Nil(t, req.IsActive)
	})

	t.Run("should allow noop update with all nil fields", func(t *testing.T) {
		req := &UpdateADGroupRoleMappingRequest{}

		assert.Nil(t, req.IsActive)
		assert.Nil(t, req.Priority)
	})
}

// ==================== ADSyncResult struct ====================

func TestADSyncResult_Instantiation(t *testing.T) {
	t.Run("should create a successful ADSyncResult", func(t *testing.T) {
		now := time.Now().Truncate(time.Second)
		completed := now.Add(2 * time.Minute)

		result := &ADSyncResult{
			Status:           "completed",
			UsersCreated:     10,
			UsersUpdated:     25,
			UsersDisabled:    3,
			GroupsCreated:    2,
			GroupsUpdated:    5,
			RolesAssigned:    15,
			RolesRevoked:     4,
			ConflictsFound:   1,
			ErrorCount:       0,
			StartedAt:        now,
			CompletedAt:      completed,
			HighestUSNBefore: 500000,
			HighestUSNAfter:  500100,
		}

		assert.Equal(t, "completed", result.Status)
		assert.Equal(t, 10, result.UsersCreated)
		assert.Equal(t, 25, result.UsersUpdated)
		assert.Equal(t, 3, result.UsersDisabled)
		assert.Equal(t, 2, result.GroupsCreated)
		assert.Equal(t, 5, result.GroupsUpdated)
		assert.Equal(t, 15, result.RolesAssigned)
		assert.Equal(t, 4, result.RolesRevoked)
		assert.Equal(t, 1, result.ConflictsFound)
		assert.Equal(t, 0, result.ErrorCount)
		assert.Equal(t, now, result.StartedAt)
		assert.Equal(t, completed, result.CompletedAt)
		assert.Equal(t, int64(500000), result.HighestUSNBefore)
		assert.Equal(t, int64(500100), result.HighestUSNAfter)
	})

	t.Run("should create a failed ADSyncResult with error count", func(t *testing.T) {
		now := time.Now()
		result := &ADSyncResult{
			Status:     "failed",
			ErrorCount: 5,
			StartedAt:  now,
		}

		assert.Equal(t, "failed", result.Status)
		assert.Equal(t, 5, result.ErrorCount)
		assert.Zero(t, result.UsersCreated)
	})

	t.Run("should confirm USN advances after a successful sync", func(t *testing.T) {
		result := &ADSyncResult{
			HighestUSNBefore: 100000,
			HighestUSNAfter:  100050,
		}

		assert.Greater(t, result.HighestUSNAfter, result.HighestUSNBefore,
			"HighestUSNAfter should be greater than HighestUSNBefore after a productive sync")
	})
}

// ==================== IncrementalSyncRequest ====================

func TestIncrementalSyncRequest_Fields(t *testing.T) {
	t.Run("should set all fields including force full sync", func(t *testing.T) {
		providerID := uuid.New()

		req := &IncrementalSyncRequest{
			ProviderID:       providerID,
			DomainController: "dc01.corp.com",
			ForceFullSync:    true,
		}

		assert.Equal(t, providerID, req.ProviderID)
		assert.Equal(t, "dc01.corp.com", req.DomainController)
		assert.True(t, req.ForceFullSync)
	})

	t.Run("should default ForceFullSync to false", func(t *testing.T) {
		req := &IncrementalSyncRequest{
			ProviderID: uuid.New(),
		}

		assert.False(t, req.ForceFullSync)
		assert.Empty(t, req.DomainController)
	})
}

// ==================== ResolveConflictRequest ====================

func TestResolveConflictRequest_Fields(t *testing.T) {
	t.Run("should resolve with AD wins and no details", func(t *testing.T) {
		req := &ResolveConflictRequest{
			Resolution: ResolutionADWins,
		}

		assert.Equal(t, ResolutionADWins, req.Resolution)
		assert.Nil(t, req.ResolutionDetails)
	})

	t.Run("should resolve with merge and provide resolution details", func(t *testing.T) {
		req := &ResolveConflictRequest{
			Resolution: ResolutionMerged,
			ResolutionDetails: map[string]interface{}{
				"email_source":        "ad",
				"display_name_source": "iam",
			},
		}

		assert.Equal(t, ResolutionMerged, req.Resolution)
		require.NotNil(t, req.ResolutionDetails)
		assert.Equal(t, "ad", req.ResolutionDetails["email_source"])
		assert.Equal(t, "iam", req.ResolutionDetails["display_name_source"])
	})

	t.Run("should resolve with ignore resolution", func(t *testing.T) {
		req := &ResolveConflictRequest{
			Resolution: ResolutionIgnored,
		}
		assert.Equal(t, ResolutionIgnored, req.Resolution)
	})

	t.Run("should support all resolution values", func(t *testing.T) {
		resolutions := []string{
			ResolutionADWins,
			ResolutionIAMWins,
			ResolutionMerged,
			ResolutionIgnored,
			ResolutionPending,
		}

		for _, r := range resolutions {
			req := &ResolveConflictRequest{Resolution: r}
			assert.Equal(t, r, req.Resolution)
		}
	})
}
