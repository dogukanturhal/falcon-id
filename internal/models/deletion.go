// SPDX-License-Identifier: AGPL-3.0-or-later

package models

import (
	"time"

	"github.com/google/uuid"
)

// Deletion request status constants
const (
	DeletionRequestStatusPending    = "pending"
	DeletionRequestStatusScheduled  = "scheduled"
	DeletionRequestStatusProcessing = "processing"
	DeletionRequestStatusCompleted  = "completed"
	DeletionRequestStatusFailed     = "failed"
	DeletionRequestStatusCancelled  = "cancelled"
)

// DeletionRequest represents a GDPR data deletion request
type DeletionRequest struct {
	ID                uuid.UUID  `json:"id" db:"id"`
	TenantID          uuid.UUID  `json:"tenant_id" db:"tenant_id"`
	UserID            uuid.UUID  `json:"user_id" db:"user_id"`
	Status            string     `json:"status" db:"status"`
	RequestedAt       time.Time  `json:"requested_at" db:"requested_at"`
	ScheduledDeleteAt *time.Time `json:"scheduled_delete_at,omitempty" db:"scheduled_delete_at"`
	ProcessedAt       *time.Time `json:"processed_at,omitempty" db:"processed_at"`
	CompletedAt       *time.Time `json:"completed_at,omitempty" db:"completed_at"`
	LegalHold         bool       `json:"legal_hold" db:"legal_hold"`
	LegalHoldReason   *string    `json:"legal_hold_reason,omitempty" db:"legal_hold_reason"`
	LegalHoldSetAt    *time.Time `json:"legal_hold_set_at,omitempty" db:"legal_hold_set_at"`
	LegalHoldSetBy    *uuid.UUID `json:"legal_hold_set_by,omitempty" db:"legal_hold_set_by"`
	RequestedBy       *uuid.UUID `json:"requested_by,omitempty" db:"requested_by"`
	Notes             *string    `json:"notes,omitempty" db:"notes"`
	ErrorMessage      *string    `json:"error_message,omitempty" db:"error_message"`
	CreatedAt         time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt         time.Time  `json:"updated_at" db:"updated_at"`
}

// IsActive returns true if the deletion request is pending or scheduled
func (d *DeletionRequest) IsActive() bool {
	return d.Status == DeletionRequestStatusPending || d.Status == DeletionRequestStatusScheduled
}

// IsCancellable returns true if the deletion request can be cancelled
func (d *DeletionRequest) IsCancellable() bool {
	return d.Status == DeletionRequestStatusPending || d.Status == DeletionRequestStatusScheduled
}

// ToResponse converts a DeletionRequest to a DeletionRequestResponse
func (d *DeletionRequest) ToResponse() *DeletionRequestResponse {
	resp := &DeletionRequestResponse{
		ID:                d.ID.String(),
		TenantID:          d.TenantID.String(),
		UserID:            d.UserID.String(),
		Status:            d.Status,
		RequestedAt:       d.RequestedAt,
		ScheduledDeleteAt: d.ScheduledDeleteAt,
		ProcessedAt:       d.ProcessedAt,
		CompletedAt:       d.CompletedAt,
		LegalHold:         d.LegalHold,
		LegalHoldReason:   d.LegalHoldReason,
		LegalHoldSetAt:    d.LegalHoldSetAt,
		Notes:             d.Notes,
		ErrorMessage:      d.ErrorMessage,
		CreatedAt:         d.CreatedAt,
		UpdatedAt:         d.UpdatedAt,
	}

	if d.LegalHoldSetBy != nil {
		s := d.LegalHoldSetBy.String()
		resp.LegalHoldSetBy = &s
	}

	if d.RequestedBy != nil {
		s := d.RequestedBy.String()
		resp.RequestedBy = &s
	}

	// Calculate days remaining until deletion
	if d.ScheduledDeleteAt != nil && d.Status == DeletionRequestStatusScheduled {
		daysRemaining := int(time.Until(*d.ScheduledDeleteAt).Hours() / 24)
		if daysRemaining < 0 {
			daysRemaining = 0
		}
		resp.DaysRemaining = &daysRemaining
	}

	return resp
}

// CreateDeletionRequestRequest represents a request to create a deletion request
type CreateDeletionRequestRequest struct {
	UserID uuid.UUID `json:"user_id"` // Usually derived from URL param, but can be in body for admin
	Notes  *string   `json:"notes,omitempty"`
}

// DeletionRequestResponse is the API response for a deletion request
type DeletionRequestResponse struct {
	ID                string     `json:"id"`
	TenantID          string     `json:"tenant_id"`
	UserID            string     `json:"user_id"`
	Status            string     `json:"status"`
	RequestedAt       time.Time  `json:"requested_at"`
	ScheduledDeleteAt *time.Time `json:"scheduled_delete_at,omitempty"`
	ProcessedAt       *time.Time `json:"processed_at,omitempty"`
	CompletedAt       *time.Time `json:"completed_at,omitempty"`
	LegalHold         bool       `json:"legal_hold"`
	LegalHoldReason   *string    `json:"legal_hold_reason,omitempty"`
	LegalHoldSetAt    *time.Time `json:"legal_hold_set_at,omitempty"`
	LegalHoldSetBy    *string    `json:"legal_hold_set_by,omitempty"`
	RequestedBy       *string    `json:"requested_by,omitempty"`
	Notes             *string    `json:"notes,omitempty"`
	ErrorMessage      *string    `json:"error_message,omitempty"`
	DaysRemaining     *int       `json:"days_remaining,omitempty"` // Days until scheduled deletion
	CreatedAt         time.Time  `json:"created_at"`
	UpdatedAt         time.Time  `json:"updated_at"`
}

// DeletionRequestListResponse is the paginated response for listing deletion requests
type DeletionRequestListResponse struct {
	Requests   []DeletionRequestResponse `json:"requests"`
	Total      int                       `json:"total"`
	Page       int                       `json:"page"`
	PageSize   int                       `json:"page_size"`
	TotalPages int                       `json:"total_pages"`
}

// SetLegalHoldRequest represents a request to set a legal hold on a deletion request
type SetLegalHoldRequest struct {
	Reason string `json:"reason" binding:"required,min=10,max=1000"`
}

// CancelDeletionRequest represents a request to cancel a deletion request
type CancelDeletionRequest struct {
	Reason *string `json:"reason,omitempty"`
}
