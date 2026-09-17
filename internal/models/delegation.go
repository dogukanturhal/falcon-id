// SPDX-License-Identifier: AGPL-3.0-or-later

package models

import (
	"time"

	"github.com/google/uuid"
)

// Delegation represents a temporary delegation of permissions from one user to another
type Delegation struct {
	ID           uuid.UUID  `json:"id" db:"id"`
	TenantID     uuid.UUID  `json:"tenant_id" db:"tenant_id"`
	DelegatorID  uuid.UUID  `json:"delegator_id" db:"delegator_id"`
	DelegateeID  uuid.UUID  `json:"delegatee_id" db:"delegatee_id"`
	Permissions  []string   `json:"permissions" db:"permissions"`
	ResourceType *string    `json:"resource_type,omitempty" db:"resource_type"`
	ResourceID   *string    `json:"resource_id,omitempty" db:"resource_id"`
	ExpiresAt    time.Time  `json:"expires_at" db:"expires_at"`
	Reason       *string    `json:"reason,omitempty" db:"reason"`
	RevokedAt    *time.Time `json:"revoked_at,omitempty" db:"revoked_at"`
	RevokedBy    *uuid.UUID `json:"revoked_by,omitempty" db:"revoked_by"`
	CreatedAt    time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt    time.Time  `json:"updated_at" db:"updated_at"`
}

// IsActive returns true if the delegation is currently active
func (d *Delegation) IsActive() bool {
	return d.RevokedAt == nil && time.Now().Before(d.ExpiresAt)
}

// IsExpired returns true if the delegation has expired
func (d *Delegation) IsExpired() bool {
	return time.Now().After(d.ExpiresAt)
}

// IsRevoked returns true if the delegation has been revoked
func (d *Delegation) IsRevoked() bool {
	return d.RevokedAt != nil
}

// ToResponse converts a Delegation to a DelegationResponse
func (d *Delegation) ToResponse(delegatorName, delegateeName string) *DelegationResponse {
	status := "active"
	if d.IsRevoked() {
		status = "revoked"
	} else if d.IsExpired() {
		status = "expired"
	}

	return &DelegationResponse{
		ID:            d.ID.String(),
		TenantID:      d.TenantID.String(),
		DelegatorID:   d.DelegatorID.String(),
		DelegatorName: delegatorName,
		DelegateeID:   d.DelegateeID.String(),
		DelegateeName: delegateeName,
		Permissions:   d.Permissions,
		ResourceType:  d.ResourceType,
		ResourceID:    d.ResourceID,
		ExpiresAt:     d.ExpiresAt,
		Reason:        d.Reason,
		RevokedAt:     d.RevokedAt,
		RevokedBy:     uuidPtrToStringPtr(d.RevokedBy),
		Status:        status,
		CreatedAt:     d.CreatedAt,
		UpdatedAt:     d.UpdatedAt,
	}
}

// CreateDelegationRequest represents a request to create a new delegation
type CreateDelegationRequest struct {
	DelegateeID  uuid.UUID `json:"delegatee_id" binding:"required"`
	Permissions  []string  `json:"permissions" binding:"required,min=1"`
	ResourceType *string   `json:"resource_type,omitempty"`
	ResourceID   *string   `json:"resource_id,omitempty"`
	Duration     int       `json:"duration" binding:"required,min=60,max=604800"` // 1 minute to 7 days in seconds
	Reason       *string   `json:"reason,omitempty"`
}

// DelegationResponse is the API response for a delegation
type DelegationResponse struct {
	ID            string     `json:"id"`
	TenantID      string     `json:"tenant_id"`
	DelegatorID   string     `json:"delegator_id"`
	DelegatorName string     `json:"delegator_name"`
	DelegateeID   string     `json:"delegatee_id"`
	DelegateeName string     `json:"delegatee_name"`
	Permissions   []string   `json:"permissions"`
	ResourceType  *string    `json:"resource_type,omitempty"`
	ResourceID    *string    `json:"resource_id,omitempty"`
	ExpiresAt     time.Time  `json:"expires_at"`
	Reason        *string    `json:"reason,omitempty"`
	RevokedAt     *time.Time `json:"revoked_at,omitempty"`
	RevokedBy     *string    `json:"revoked_by,omitempty"`
	Status        string     `json:"status"` // active, expired, revoked
	CreatedAt     time.Time  `json:"created_at"`
	UpdatedAt     time.Time  `json:"updated_at"`
}

// DelegationListResponse is the paginated response for listing delegations
type DelegationListResponse struct {
	Delegations []DelegationResponse `json:"delegations"`
	Total       int                  `json:"total"`
	Page        int                  `json:"page"`
	PageSize    int                  `json:"page_size"`
	TotalPages  int                  `json:"total_pages"`
}

// uuidPtrToStringPtr converts a *uuid.UUID to a *string
func uuidPtrToStringPtr(u *uuid.UUID) *string {
	if u == nil {
		return nil
	}
	s := u.String()
	return &s
}
