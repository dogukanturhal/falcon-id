// SPDX-License-Identifier: AGPL-3.0-or-later

package models

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// OutboxStatus represents the processing status of an outbox event
type OutboxStatus string

const (
	// OutboxStatusPending is an exported identifier.
	OutboxStatusPending OutboxStatus = "pending"
	// OutboxStatusProcessing is an exported identifier.
	OutboxStatusProcessing OutboxStatus = "processing"
	// OutboxStatusCompleted is an exported identifier.
	OutboxStatusCompleted OutboxStatus = "completed"
	// OutboxStatusFailed is an exported identifier.
	OutboxStatusFailed OutboxStatus = "failed"
)

// OutboxOperation represents the SpiceDB operation to perform
type OutboxOperation string

const (
	// OutboxOperationTouch is an exported identifier.
	OutboxOperationTouch OutboxOperation = "touch" // Create/update relationship
	// OutboxOperationDelete is an exported identifier.
	OutboxOperationDelete OutboxOperation = "delete" // Delete relationship
)

// PermissionOutbox represents an event in the outbox for SpiceDB synchronization
type PermissionOutbox struct {
	ID           uuid.UUID       `json:"id" db:"id"`
	TenantID     uuid.UUID       `json:"tenant_id" db:"tenant_id"`
	EventType    string          `json:"event_type" db:"event_type"`       // "relationship.created", "relationship.deleted"
	ResourceType string          `json:"resource_type" db:"resource_type"` // "crm_contact", "invoice", etc.
	ResourceID   string          `json:"resource_id" db:"resource_id"`
	Relation     string          `json:"relation" db:"relation"` // "owner", "viewer", "editor"
	SubjectType  string          `json:"subject_type" db:"subject_type"`
	SubjectID    string          `json:"subject_id" db:"subject_id"`
	Operation    OutboxOperation `json:"operation" db:"operation"`
	Payload      json.RawMessage `json:"payload,omitempty" db:"payload"` // Optional metadata
	Status       OutboxStatus    `json:"status" db:"status"`
	RetryCount   int             `json:"retry_count" db:"retry_count"`
	MaxRetries   int             `json:"max_retries" db:"max_retries"`
	ErrorMessage *string         `json:"error_message,omitempty" db:"error_message"`
	CreatedAt    time.Time       `json:"created_at" db:"created_at"`
	ProcessedAt  *time.Time      `json:"processed_at,omitempty" db:"processed_at"`
	NextRetryAt  *time.Time      `json:"next_retry_at,omitempty" db:"next_retry_at"`
}

// RelationshipEvent is the input data for creating an outbox event
type RelationshipEvent struct {
	TenantID     uuid.UUID
	EventType    string // "relationship.created", "relationship.deleted"
	ResourceType string
	ResourceID   string
	Relation     string
	SubjectType  string
	SubjectID    string
	Operation    OutboxOperation
	Payload      map[string]interface{} // Optional metadata
}

// ToOutboxEntry converts RelationshipEvent to PermissionOutbox
func (e *RelationshipEvent) ToOutboxEntry() (*PermissionOutbox, error) {
	var payload json.RawMessage
	var err error

	if len(e.Payload) > 0 {
		payload, err = json.Marshal(e.Payload)
		if err != nil {
			return nil, fmt.Errorf("ToOutboxEntry: Marshal failed: %w", err)
		}
	}

	return &PermissionOutbox{
		ID:           uuid.New(),
		TenantID:     e.TenantID,
		EventType:    e.EventType,
		ResourceType: e.ResourceType,
		ResourceID:   e.ResourceID,
		Relation:     e.Relation,
		SubjectType:  e.SubjectType,
		SubjectID:    e.SubjectID,
		Operation:    e.Operation,
		Payload:      payload,
		Status:       OutboxStatusPending,
		RetryCount:   0,
		MaxRetries:   5,
		CreatedAt:    time.Now(),
	}, nil
}

// OutboxStats represents statistics about the outbox
type OutboxStats struct {
	PendingCount    int64      `json:"pending_count"`
	ProcessingCount int64      `json:"processing_count"`
	FailedCount     int64      `json:"failed_count"`
	CompletedCount  int64      `json:"completed_count"`
	OldestPending   *time.Time `json:"oldest_pending,omitempty"`
	LagSeconds      *int64     `json:"lag_seconds,omitempty"`
}
