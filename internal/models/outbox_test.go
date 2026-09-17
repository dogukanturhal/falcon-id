// SPDX-License-Identifier: AGPL-3.0-or-later

package models

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ==================== OutboxStatus constants ====================

func TestOutboxStatusConstants(t *testing.T) {
	assert.Equal(t, OutboxStatus("pending"), OutboxStatusPending)
	assert.Equal(t, OutboxStatus("processing"), OutboxStatusProcessing)
	assert.Equal(t, OutboxStatus("completed"), OutboxStatusCompleted)
	assert.Equal(t, OutboxStatus("failed"), OutboxStatusFailed)
}

// ==================== OutboxOperation constants ====================

func TestOutboxOperationConstants(t *testing.T) {
	assert.Equal(t, OutboxOperation("touch"), OutboxOperationTouch)
	assert.Equal(t, OutboxOperation("delete"), OutboxOperationDelete)
}

// ==================== PermissionOutbox struct ====================

func TestPermissionOutbox_StructFields(t *testing.T) {
	t.Run("should carry all fields correctly", func(t *testing.T) {
		id := uuid.New()
		tenantID := uuid.New()
		now := time.Now().Truncate(time.Second)
		processedAt := now.Add(1 * time.Second)
		nextRetry := now.Add(30 * time.Second)
		errMsg := "connection refused"
		payload := json.RawMessage(`{"key":"value"}`)

		event := &PermissionOutbox{
			ID:           id,
			TenantID:     tenantID,
			EventType:    "relationship.created",
			ResourceType: "crm_contact",
			ResourceID:   "resource-123",
			Relation:     "owner",
			SubjectType:  "user",
			SubjectID:    "user-456",
			Operation:    OutboxOperationTouch,
			Payload:      payload,
			Status:       OutboxStatusPending,
			RetryCount:   0,
			MaxRetries:   5,
			ErrorMessage: &errMsg,
			CreatedAt:    now,
			ProcessedAt:  &processedAt,
			NextRetryAt:  &nextRetry,
		}

		require.NotNil(t, event)
		assert.Equal(t, id, event.ID)
		assert.Equal(t, tenantID, event.TenantID)
		assert.Equal(t, "relationship.created", event.EventType)
		assert.Equal(t, "crm_contact", event.ResourceType)
		assert.Equal(t, "resource-123", event.ResourceID)
		assert.Equal(t, "owner", event.Relation)
		assert.Equal(t, "user", event.SubjectType)
		assert.Equal(t, "user-456", event.SubjectID)
		assert.Equal(t, OutboxOperationTouch, event.Operation)
		assert.Equal(t, payload, event.Payload)
		assert.Equal(t, OutboxStatusPending, event.Status)
		assert.Equal(t, 0, event.RetryCount)
		assert.Equal(t, 5, event.MaxRetries)
		assert.Equal(t, &errMsg, event.ErrorMessage)
		assert.Equal(t, now, event.CreatedAt)
		assert.Equal(t, &processedAt, event.ProcessedAt)
		assert.Equal(t, &nextRetry, event.NextRetryAt)
	})

	t.Run("should allow nil optional fields", func(t *testing.T) {
		event := &PermissionOutbox{
			ID:           uuid.New(),
			TenantID:     uuid.New(),
			EventType:    "relationship.deleted",
			ResourceType: "invoice",
			ResourceID:   "inv-001",
			Relation:     "viewer",
			SubjectType:  "group",
			SubjectID:    "grp-001",
			Operation:    OutboxOperationDelete,
			Status:       OutboxStatusCompleted,
			MaxRetries:   3,
		}

		assert.Nil(t, event.Payload)
		assert.Nil(t, event.ErrorMessage)
		assert.Nil(t, event.ProcessedAt)
		assert.Nil(t, event.NextRetryAt)
	})
}

// ==================== RelationshipEvent.ToOutboxEntry ====================

func TestRelationshipEvent_ToOutboxEntry(t *testing.T) {
	t.Run("should create a pending outbox entry with correct fields", func(t *testing.T) {
		tenantID := uuid.New()
		before := time.Now()

		event := &RelationshipEvent{
			TenantID:     tenantID,
			EventType:    "relationship.created",
			ResourceType: "crm_contact",
			ResourceID:   "contact-123",
			Relation:     "owner",
			SubjectType:  "user",
			SubjectID:    "user-456",
			Operation:    OutboxOperationTouch,
		}

		entry, err := event.ToOutboxEntry()

		require.NoError(t, err)
		require.NotNil(t, entry)
		assert.Equal(t, tenantID, entry.TenantID)
		assert.Equal(t, "relationship.created", entry.EventType)
		assert.Equal(t, "crm_contact", entry.ResourceType)
		assert.Equal(t, "contact-123", entry.ResourceID)
		assert.Equal(t, "owner", entry.Relation)
		assert.Equal(t, "user", entry.SubjectType)
		assert.Equal(t, "user-456", entry.SubjectID)
		assert.Equal(t, OutboxOperationTouch, entry.Operation)
		assert.Equal(t, OutboxStatusPending, entry.Status, "new entries must start as pending")
		assert.Equal(t, 0, entry.RetryCount, "new entries must have zero retries")
		assert.Equal(t, 5, entry.MaxRetries, "default max retries must be 5")
		assert.True(t, entry.CreatedAt.After(before) || entry.CreatedAt.Equal(before),
			"CreatedAt should be set to current time")
		assert.Nil(t, entry.ProcessedAt)
		assert.Nil(t, entry.NextRetryAt)
		assert.Nil(t, entry.ErrorMessage)
	})

	t.Run("should generate a unique UUID for each entry", func(t *testing.T) {
		event := &RelationshipEvent{
			TenantID:     uuid.New(),
			EventType:    "relationship.created",
			ResourceType: "doc",
			ResourceID:   "d1",
			Operation:    OutboxOperationTouch,
		}

		entry1, err1 := event.ToOutboxEntry()
		entry2, err2 := event.ToOutboxEntry()

		require.NoError(t, err1)
		require.NoError(t, err2)
		assert.NotEqual(t, entry1.ID, entry2.ID, "each call must produce a unique ID")
	})

	t.Run("should marshal payload when provided", func(t *testing.T) {
		event := &RelationshipEvent{
			TenantID:     uuid.New(),
			EventType:    "relationship.created",
			ResourceType: "resource",
			ResourceID:   "r1",
			Operation:    OutboxOperationTouch,
			Payload: map[string]interface{}{
				"key":   "value",
				"count": float64(42),
			},
		}

		entry, err := event.ToOutboxEntry()

		require.NoError(t, err)
		require.NotNil(t, entry.Payload)

		var decoded map[string]interface{}
		require.NoError(t, json.Unmarshal(entry.Payload, &decoded))
		assert.Equal(t, "value", decoded["key"])
		assert.Equal(t, float64(42), decoded["count"])
	})

	t.Run("should set nil payload when event payload is nil", func(t *testing.T) {
		event := &RelationshipEvent{
			TenantID:     uuid.New(),
			EventType:    "relationship.deleted",
			ResourceType: "resource",
			ResourceID:   "r2",
			Operation:    OutboxOperationDelete,
			Payload:      nil,
		}

		entry, err := event.ToOutboxEntry()

		require.NoError(t, err)
		assert.Nil(t, entry.Payload)
	})

	t.Run("should set nil payload when event payload is empty map", func(t *testing.T) {
		event := &RelationshipEvent{
			TenantID:     uuid.New(),
			EventType:    "relationship.deleted",
			ResourceType: "resource",
			ResourceID:   "r3",
			Operation:    OutboxOperationDelete,
			Payload:      map[string]interface{}{},
		}

		entry, err := event.ToOutboxEntry()

		require.NoError(t, err)
		// Empty map has no length, so payload should be nil
		assert.Nil(t, entry.Payload)
	})

	t.Run("should use delete operation correctly", func(t *testing.T) {
		event := &RelationshipEvent{
			TenantID:     uuid.New(),
			EventType:    "relationship.deleted",
			ResourceType: "invoice",
			ResourceID:   "inv-999",
			Relation:     "editor",
			SubjectType:  "group",
			SubjectID:    "grp-finance",
			Operation:    OutboxOperationDelete,
		}

		entry, err := event.ToOutboxEntry()

		require.NoError(t, err)
		assert.Equal(t, OutboxOperationDelete, entry.Operation)
		assert.Equal(t, "relationship.deleted", entry.EventType)
	})
}

// ==================== OutboxStats struct ====================

func TestOutboxStats_StructFields(t *testing.T) {
	t.Run("should carry all count fields correctly", func(t *testing.T) {
		now := time.Now()
		lag := int64(300)

		stats := &OutboxStats{
			PendingCount:    10,
			ProcessingCount: 2,
			FailedCount:     5,
			CompletedCount:  1000,
			OldestPending:   &now,
			LagSeconds:      &lag,
		}

		assert.Equal(t, int64(10), stats.PendingCount)
		assert.Equal(t, int64(2), stats.ProcessingCount)
		assert.Equal(t, int64(5), stats.FailedCount)
		assert.Equal(t, int64(1000), stats.CompletedCount)
		assert.Equal(t, &now, stats.OldestPending)
		assert.Equal(t, &lag, stats.LagSeconds)
	})

	t.Run("should allow nil optional fields", func(t *testing.T) {
		stats := &OutboxStats{
			PendingCount:    0,
			ProcessingCount: 0,
			FailedCount:     0,
			CompletedCount:  0,
		}

		assert.Nil(t, stats.OldestPending)
		assert.Nil(t, stats.LagSeconds)
	})

	t.Run("should support zero values", func(t *testing.T) {
		stats := &OutboxStats{}

		assert.Equal(t, int64(0), stats.PendingCount)
		assert.Equal(t, int64(0), stats.ProcessingCount)
		assert.Equal(t, int64(0), stats.FailedCount)
		assert.Equal(t, int64(0), stats.CompletedCount)
	})
}

// ==================== RelationshipEvent struct ====================

func TestRelationshipEvent_StructFields(t *testing.T) {
	t.Run("should carry all fields correctly", func(t *testing.T) {
		tenantID := uuid.New()

		event := RelationshipEvent{
			TenantID:     tenantID,
			EventType:    "relationship.created",
			ResourceType: "project",
			ResourceID:   "proj-abc",
			Relation:     "member",
			SubjectType:  "user",
			SubjectID:    "user-789",
			Operation:    OutboxOperationTouch,
			Payload: map[string]interface{}{
				"source": "api",
			},
		}

		assert.Equal(t, tenantID, event.TenantID)
		assert.Equal(t, "relationship.created", event.EventType)
		assert.Equal(t, "project", event.ResourceType)
		assert.Equal(t, "proj-abc", event.ResourceID)
		assert.Equal(t, "member", event.Relation)
		assert.Equal(t, "user", event.SubjectType)
		assert.Equal(t, "user-789", event.SubjectID)
		assert.Equal(t, OutboxOperationTouch, event.Operation)
		assert.Equal(t, "api", event.Payload["source"])
	})
}

// ==================== Status lifecycle coverage ====================

func TestOutboxStatus_AllValues(t *testing.T) {
	statuses := []OutboxStatus{
		OutboxStatusPending,
		OutboxStatusProcessing,
		OutboxStatusCompleted,
		OutboxStatusFailed,
	}

	for _, s := range statuses {
		s := s
		t.Run(string(s), func(t *testing.T) {
			event := &PermissionOutbox{
				ID:     uuid.New(),
				Status: s,
			}
			assert.Equal(t, s, event.Status)
		})
	}
}
