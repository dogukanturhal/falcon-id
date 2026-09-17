// SPDX-License-Identifier: AGPL-3.0-or-later

package models

import (
	"time"

	"github.com/google/uuid"
)

// AdminConsentRequestStatus represents the lifecycle state of an admin consent request.
type AdminConsentRequestStatus string

const (
	// AdminConsentRequestStatusPending is an exported identifier.
	AdminConsentRequestStatusPending AdminConsentRequestStatus = "pending"
	// AdminConsentRequestStatusApproved is an exported identifier.
	AdminConsentRequestStatusApproved AdminConsentRequestStatus = "approved"
	// AdminConsentRequestStatusDenied is an exported identifier.
	AdminConsentRequestStatusDenied AdminConsentRequestStatus = "denied"
)

// AdminConsentRequest is the database model for an admin consent workflow request.
type AdminConsentRequest struct {
	ID              uuid.UUID                 `json:"id"`
	ApplicationID   uuid.UUID                 `json:"application_id"`
	TenantID        uuid.UUID                 `json:"tenant_id"`
	RequesterID     uuid.UUID                 `json:"requester_id"`
	ApproverID      *uuid.UUID                `json:"approver_id,omitempty"`
	RequestedScopes []string                  `json:"requested_scopes"`
	Justification   *string                   `json:"justification,omitempty"`
	Status          AdminConsentRequestStatus `json:"status"`
	DecidedAt       *time.Time                `json:"decided_at,omitempty"`
	CreatedAt       time.Time                 `json:"created_at"`
}

// CreateAdminConsentRequestInput is the request body for submitting a new admin consent request.
type CreateAdminConsentRequestInput struct {
	ApplicationID   uuid.UUID `json:"application_id" binding:"required"`
	RequestedScopes []string  `json:"requested_scopes" binding:"required"`
	Justification   *string   `json:"justification"`
}

// DecideAdminConsentRequestInput is the request body for approving or denying a consent request.
type DecideAdminConsentRequestInput struct {
	Decision AdminConsentRequestStatus `json:"decision" binding:"required,oneof=approved denied"`
}
