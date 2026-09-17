// SPDX-License-Identifier: AGPL-3.0-or-later

package audit

import (
	"time"

	"github.com/google/uuid"
)

// ActorType represents the type of actor performing an action
type ActorType string

const (
	// ActorTypeUser is an exported identifier.
	ActorTypeUser ActorType = "user"
	// ActorTypeService is an exported identifier.
	ActorTypeService ActorType = "service"
	// ActorTypeSystem is an exported identifier.
	ActorTypeSystem ActorType = "system"
)

// Result represents the outcome of an audit event
type Result string

const (
	// ResultSuccess is an exported identifier.
	ResultSuccess Result = "success"
	// ResultDenied is an exported identifier.
	ResultDenied Result = "denied"
	// ResultError is an exported identifier.
	ResultError Result = "error"
)

// Action represents audit actions
type Action string

const (
	// ActionRelationshipCreated is an exported identifier.
	ActionRelationshipCreated Action = "relationship.created"
	// ActionRelationshipDeleted is an exported identifier.
	ActionRelationshipDeleted Action = "relationship.deleted"
	// ActionPermissionChecked is an exported identifier.
	ActionPermissionChecked Action = "permission.checked"
	// ActionPermissionDenied is an exported identifier.
	ActionPermissionDenied Action = "permission.denied"
	// ActionPermissionError is an exported identifier.
	ActionPermissionError Action = "permission.error"
)

// Log represents a single audit log entry
type Log struct {
	ID           uuid.UUID              `db:"id" json:"id"`
	TenantID     uuid.UUID              `db:"tenant_id" json:"tenant_id"`
	ActorID      uuid.UUID              `db:"actor_id" json:"actor_id"`
	ActorType    ActorType              `db:"actor_type" json:"actor_type"`
	Action       Action                 `db:"action" json:"action"`
	ResourceType string                 `db:"resource_type" json:"resource_type"`
	ResourceID   string                 `db:"resource_id" json:"resource_id"`
	Relation     *string                `db:"relation" json:"relation,omitempty"`
	SubjectType  *string                `db:"subject_type" json:"subject_type,omitempty"`
	SubjectID    *string                `db:"subject_id" json:"subject_id,omitempty"`
	Result       Result                 `db:"result" json:"result"`
	Metadata     map[string]interface{} `db:"metadata" json:"metadata,omitempty"`
	IPAddress    *string                `db:"ip_address" json:"ip_address,omitempty"`
	UserAgent    *string                `db:"user_agent" json:"user_agent,omitempty"`
	RequestID    *string                `db:"request_id" json:"request_id,omitempty"`
	ErrorMessage *string                `db:"error_message" json:"error_message,omitempty"`
	LatencyMs    *int64                 `db:"latency_ms" json:"latency_ms,omitempty"`
	CreatedAt    time.Time              `db:"created_at" json:"created_at"`
}

// RelationshipAuditEntry represents data for logging relationship changes
type RelationshipAuditEntry struct {
	TenantID     uuid.UUID
	ActorID      uuid.UUID
	ActorType    ActorType
	Action       Action // ActionRelationshipCreated or ActionRelationshipDeleted
	ResourceType string
	ResourceID   string
	Relation     string
	SubjectType  string
	SubjectID    string
	Metadata     map[string]interface{}
	IPAddress    string
	UserAgent    string
	RequestID    string
}

// PermissionCheckAuditEntry represents data for logging permission checks
type PermissionCheckAuditEntry struct {
	TenantID     uuid.UUID
	ActorID      uuid.UUID
	ResourceType string
	ResourceID   string
	Permission   string
	Result       bool
	Latency      time.Duration
	IPAddress    string
	UserAgent    string
	RequestID    string
	ErrorMessage string
}

// SecurityAuditEntry represents security-related events
type SecurityAuditEntry struct {
	TenantID     uuid.UUID
	ActorID      uuid.UUID
	EventType    string // "cross_tenant_attempt", "permission_denied", "rate_limited"
	Details      string
	IPAddress    string
	UserAgent    string
	RequestID    string
	Severity     string // "critical", "high", "medium", "low"
	ResourceType string
	ResourceID   string
}

// Filter represents filters for querying audit logs
type Filter struct {
	TenantID     *uuid.UUID
	ActorID      *uuid.UUID
	Action       *Action
	ResourceType *string
	ResourceID   *string
	Result       *Result
	StartDate    *time.Time
	EndDate      *time.Time
	Limit        int
	Offset       int
}

// Stats represents audit statistics
type Stats struct {
	TotalEvents         int64   `json:"total_events"`
	RelationshipCreates int64   `json:"relationship_creates"`
	RelationshipDeletes int64   `json:"relationship_deletes"`
	PermissionChecks    int64   `json:"permission_checks"`
	PermissionDenials   int64   `json:"permission_denials"`
	Errors              int64   `json:"errors"`
	UniqueActors        int64   `json:"unique_actors"`
	UniqueResources     int64   `json:"unique_resources"`
	AvgLatencyMs        float64 `json:"avg_latency_ms"`
}

// SuspiciousActivity represents detected suspicious activity
type SuspiciousActivity struct {
	ActorID         uuid.UUID                `json:"actor_id"`
	DenialCount     int64                    `json:"denial_count"`
	UniqueResources int64                    `json:"unique_resources"`
	FirstDenial     time.Time                `json:"first_denial"`
	LastDenial      time.Time                `json:"last_denial"`
	SampleActions   []map[string]interface{} `json:"sample_actions"`
}
