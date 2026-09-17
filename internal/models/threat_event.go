// SPDX-License-Identifier: AGPL-3.0-or-later

package models

import (
	"encoding/json"
	"net"
	"time"

	"github.com/google/uuid"
)

// ThreatSeverity represents the severity level of a detected threat event.
type ThreatSeverity string

const (
	// ThreatSeverityLow indicates informational or low-risk detections.
	ThreatSeverityLow ThreatSeverity = "low"
	// ThreatSeverityMedium indicates suspicious activity that warrants review.
	ThreatSeverityMedium ThreatSeverity = "medium"
	// ThreatSeverityHigh indicates a confirmed or high-confidence threat requiring prompt action.
	ThreatSeverityHigh ThreatSeverity = "high"
	// ThreatSeverityCritical indicates a critical security incident requiring immediate response.
	ThreatSeverityCritical ThreatSeverity = "critical"
)

// ThreatEventStatus represents the investigation lifecycle of a threat event.
type ThreatEventStatus string

const (
	// ThreatEventStatusOpen indicates the event has been detected but not yet reviewed.
	ThreatEventStatusOpen ThreatEventStatus = "open"
	// ThreatEventStatusInvestigating indicates an analyst is actively reviewing the event.
	ThreatEventStatusInvestigating ThreatEventStatus = "investigating"
	// ThreatEventStatusResolved indicates the threat has been contained and closed.
	ThreatEventStatusResolved ThreatEventStatus = "resolved"
	// ThreatEventStatusFalsePositive indicates the event was determined to be benign.
	ThreatEventStatusFalsePositive ThreatEventStatus = "false_positive"
)

// ThreatEvent is a structured security incident detected by Falcon-ID.
// Examples include brute-force login attempts, impossible-travel logins,
// credential-stuffing bursts, and privilege-escalation attempts.
//
// correlated_events holds the IDs of other ThreatEvents that belong to the
// same attack chain, enabling multi-step threat reconstruction.
type ThreatEvent struct {
	ID               uuid.UUID         `json:"id" db:"id"`
	TenantID         *uuid.UUID        `json:"tenant_id,omitempty" db:"tenant_id"`
	EventType        string            `json:"event_type" db:"event_type"`
	Severity         ThreatSeverity    `json:"severity" db:"severity"`
	SourceIP         *net.IP           `json:"source_ip,omitempty" db:"source_ip"`
	UserID           *uuid.UUID        `json:"user_id,omitempty" db:"user_id"`
	Details          json.RawMessage   `json:"details" db:"details"`
	CorrelatedEvents []uuid.UUID       `json:"correlated_events" db:"correlated_events"`
	Status           ThreatEventStatus `json:"status" db:"status"`
	CreatedAt        time.Time         `json:"created_at" db:"created_at"`
	ResolvedAt       *time.Time        `json:"resolved_at,omitempty" db:"resolved_at"`
	ResolvedBy       *uuid.UUID        `json:"resolved_by,omitempty" db:"resolved_by"`
}

// IsOpen returns true when the threat event has not yet been reviewed.
func (t *ThreatEvent) IsOpen() bool {
	return t.Status == ThreatEventStatusOpen
}

// IsCritical returns true when the threat has critical severity.
func (t *ThreatEvent) IsCritical() bool {
	return t.Severity == ThreatSeverityCritical
}

// IsResolved returns true when the event has been closed as either resolved or
// a false positive.
func (t *ThreatEvent) IsResolved() bool {
	return t.Status == ThreatEventStatusResolved || t.Status == ThreatEventStatusFalsePositive
}

// SIEMWebhook is a registered external SIEM endpoint that Falcon-ID pushes
// threat events to.  auth_header_enc stores the Authorization header value
// encrypted with the platform key so credentials are never held in plaintext.
type SIEMWebhook struct {
	ID              uuid.UUID `json:"id" db:"id"`
	Name            string    `json:"name" db:"name"`
	EndpointURL     string    `json:"endpoint_url" db:"endpoint_url"`
	AuthHeaderEnc   []byte    `json:"-" db:"auth_header_enc"` // never expose encrypted bytes
	SeverityFilter  []string  `json:"severity_filter" db:"severity_filter"`
	EventTypeFilter []string  `json:"event_type_filter" db:"event_type_filter"`
	IsActive        bool      `json:"is_active" db:"is_active"`
	CreatedAt       time.Time `json:"created_at" db:"created_at"`
	UpdatedAt       time.Time `json:"updated_at" db:"updated_at"`
}

// ==================== Query Params ====================

// ThreatEventListParams holds query parameters for listing threat events.
type ThreatEventListParams struct {
	Page     int        `json:"page"`
	PageSize int        `json:"page_size"`
	Severity string     `json:"severity"`
	Status   string     `json:"status"`
	Type     string     `json:"type"`
	TenantID *uuid.UUID `json:"tenant_id"`
	UserID   *uuid.UUID `json:"user_id"`
	From     *time.Time `json:"from"`
	To       *time.Time `json:"to"`
}

// ==================== Request DTOs ====================

// CreateThreatEventRequest is the payload for recording a new threat detection.
type CreateThreatEventRequest struct {
	TenantID         *uuid.UUID      `json:"tenant_id"`
	EventType        string          `json:"event_type" binding:"required,min=1,max=255"`
	Severity         ThreatSeverity  `json:"severity" binding:"required,oneof=low medium high critical"`
	SourceIP         *string         `json:"source_ip" binding:"omitempty,ip"`
	UserID           *uuid.UUID      `json:"user_id"`
	Details          json.RawMessage `json:"details"`
	CorrelatedEvents []uuid.UUID     `json:"correlated_events"`
}

// UpdateThreatEventRequest is the payload for updating the status of a threat event.
type UpdateThreatEventRequest struct {
	Status ThreatEventStatus `json:"status" binding:"required,oneof=open investigating resolved false_positive"`
}

// CreateSIEMWebhookRequest is the payload for registering a new SIEM endpoint.
type CreateSIEMWebhookRequest struct {
	Name            string   `json:"name" binding:"required,min=1,max=255"`
	EndpointURL     string   `json:"endpoint_url" binding:"required,url"`
	AuthHeader      *string  `json:"auth_header"` // plaintext; encrypted server-side
	SeverityFilter  []string `json:"severity_filter" binding:"omitempty,dive,oneof=low medium high critical"`
	EventTypeFilter []string `json:"event_type_filter"`
	IsActive        *bool    `json:"is_active"`
}

// UpdateSIEMWebhookRequest is the payload for modifying an existing SIEM endpoint.
// All fields are optional to allow partial updates.
type UpdateSIEMWebhookRequest struct {
	Name            *string  `json:"name" binding:"omitempty,min=1,max=255"`
	EndpointURL     *string  `json:"endpoint_url" binding:"omitempty,url"`
	AuthHeader      *string  `json:"auth_header"`
	SeverityFilter  []string `json:"severity_filter" binding:"omitempty,dive,oneof=low medium high critical"`
	EventTypeFilter []string `json:"event_type_filter"`
	IsActive        *bool    `json:"is_active"`
}

// ==================== Response DTOs ====================

// ThreatEventResponse is the API representation of a threat event.
type ThreatEventResponse struct {
	ID               uuid.UUID         `json:"id"`
	TenantID         *uuid.UUID        `json:"tenant_id,omitempty"`
	EventType        string            `json:"event_type"`
	Severity         ThreatSeverity    `json:"severity"`
	SourceIP         *string           `json:"source_ip,omitempty"`
	UserID           *uuid.UUID        `json:"user_id,omitempty"`
	Details          json.RawMessage   `json:"details"`
	CorrelatedEvents []uuid.UUID       `json:"correlated_events"`
	Status           ThreatEventStatus `json:"status"`
	CreatedAt        time.Time         `json:"created_at"`
	ResolvedAt       *time.Time        `json:"resolved_at,omitempty"`
	ResolvedBy       *uuid.UUID        `json:"resolved_by,omitempty"`
}

// ThreatEventListResponse is the paginated list of threat events.
type ThreatEventListResponse struct {
	Events     []ThreatEventResponse `json:"events"`
	Total      int64                 `json:"total"`
	Page       int                   `json:"page"`
	PageSize   int                   `json:"page_size"`
	TotalPages int                   `json:"total_pages"`
}

// SIEMWebhookResponse is the API representation of a SIEM webhook registration.
// auth_header_enc is never included in responses.
type SIEMWebhookResponse struct {
	ID              uuid.UUID `json:"id"`
	Name            string    `json:"name"`
	EndpointURL     string    `json:"endpoint_url"`
	SeverityFilter  []string  `json:"severity_filter"`
	EventTypeFilter []string  `json:"event_type_filter"`
	IsActive        bool      `json:"is_active"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
}

// SIEMWebhookListResponse is the paginated list of SIEM webhook registrations.
type SIEMWebhookListResponse struct {
	Webhooks   []SIEMWebhookResponse `json:"webhooks"`
	Total      int64                 `json:"total"`
	Page       int                   `json:"page"`
	PageSize   int                   `json:"page_size"`
	TotalPages int                   `json:"total_pages"`
}

// ==================== Conversion methods ====================

// ToResponse converts a ThreatEvent to its API response representation.
// net.IP is serialised as a dotted-decimal string for JSON readability.
func (t *ThreatEvent) ToResponse() *ThreatEventResponse {
	resp := &ThreatEventResponse{
		ID:               t.ID,
		TenantID:         t.TenantID,
		EventType:        t.EventType,
		Severity:         t.Severity,
		UserID:           t.UserID,
		Details:          t.Details,
		CorrelatedEvents: t.CorrelatedEvents,
		Status:           t.Status,
		CreatedAt:        t.CreatedAt,
		ResolvedAt:       t.ResolvedAt,
		ResolvedBy:       t.ResolvedBy,
	}
	if t.SourceIP != nil {
		s := t.SourceIP.String()
		resp.SourceIP = &s
	}
	return resp
}

// ToResponse converts a SIEMWebhook to its API response representation.
// The encrypted auth header is never included.
func (s *SIEMWebhook) ToResponse() *SIEMWebhookResponse {
	return &SIEMWebhookResponse{
		ID:              s.ID,
		Name:            s.Name,
		EndpointURL:     s.EndpointURL,
		SeverityFilter:  s.SeverityFilter,
		EventTypeFilter: s.EventTypeFilter,
		IsActive:        s.IsActive,
		CreatedAt:       s.CreatedAt,
		UpdatedAt:       s.UpdatedAt,
	}
}
