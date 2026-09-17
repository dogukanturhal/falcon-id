// SPDX-License-Identifier: AGPL-3.0-or-later

package models

import (
	"time"

	"github.com/google/uuid"
)

// JITAccessStatus represents the lifecycle state of a just-in-time access grant.
type JITAccessStatus string

const (
	// JITAccessStatusPending is an exported identifier.
	JITAccessStatusPending JITAccessStatus = "pending"
	// JITAccessStatusApproved is an exported identifier.
	JITAccessStatusApproved JITAccessStatus = "approved"
	// JITAccessStatusActive is an exported identifier.
	JITAccessStatusActive JITAccessStatus = "active"
	// JITAccessStatusExpired is an exported identifier.
	JITAccessStatusExpired JITAccessStatus = "expired"
	// JITAccessStatusRevoked is an exported identifier.
	JITAccessStatusRevoked JITAccessStatus = "revoked"
)

// JITAccessGrant represents a temporary, time-boxed role grant that requires
// explicit approval before it becomes active. The grant is automatically
// cleaned up once it expires or is revoked.
type JITAccessGrant struct {
	ID            uuid.UUID       `json:"id" db:"id"`
	UserID        uuid.UUID       `json:"user_id" db:"user_id"`
	RoleID        uuid.UUID       `json:"role_id" db:"role_id"`
	TenantID      uuid.UUID       `json:"tenant_id" db:"tenant_id"`
	Justification string          `json:"justification" db:"justification"`
	RequestedAt   time.Time       `json:"requested_at" db:"requested_at"`
	ApprovedBy    *uuid.UUID      `json:"approved_by,omitempty" db:"approved_by"`
	ApprovedAt    *time.Time      `json:"approved_at,omitempty" db:"approved_at"`
	StartsAt      time.Time       `json:"starts_at" db:"starts_at"`
	ExpiresAt     time.Time       `json:"expires_at" db:"expires_at"`
	Status        JITAccessStatus `json:"status" db:"status"`
	CreatedAt     time.Time       `json:"created_at" db:"created_at"`
}

// IsActive reports whether the grant is currently in the active state and
// the current time falls within its validity window.
func (g *JITAccessGrant) IsActive() bool {
	now := time.Now()
	return g.Status == JITAccessStatusActive &&
		now.After(g.StartsAt) &&
		now.Before(g.ExpiresAt)
}

// IsExpired reports whether the grant has passed its expiry time.
func (g *JITAccessGrant) IsExpired() bool {
	return time.Now().After(g.ExpiresAt)
}

// ToResponse converts the grant to its API response form.
func (g *JITAccessGrant) ToResponse() *JITAccessGrantResponse {
	return &JITAccessGrantResponse{
		ID:            g.ID,
		UserID:        g.UserID,
		RoleID:        g.RoleID,
		TenantID:      g.TenantID,
		Justification: g.Justification,
		RequestedAt:   g.RequestedAt,
		ApprovedBy:    g.ApprovedBy,
		ApprovedAt:    g.ApprovedAt,
		StartsAt:      g.StartsAt,
		ExpiresAt:     g.ExpiresAt,
		Status:        g.Status,
		CreatedAt:     g.CreatedAt,
	}
}

// CreateJITAccessRequest is the request body for creating a just-in-time access grant.
// Duration is expressed in seconds and controls how long the grant is valid once
// it becomes active; the minimum is 60 s (1 minute) and the maximum is 86400 s
// (24 hours).
type CreateJITAccessRequest struct {
	UserID        uuid.UUID `json:"user_id" binding:"required"`
	RoleID        uuid.UUID `json:"role_id" binding:"required"`
	Justification string    `json:"justification" binding:"required,min=10,max=2048"`
	Duration      int       `json:"duration" binding:"required,min=60,max=86400"` // seconds
}

// ApproveJITAccessRequest is the request body for approving a pending grant.
// An optional StartsAt time allows the approver to schedule future activation;
// if omitted, the grant becomes active immediately on approval.
type ApproveJITAccessRequest struct {
	StartsAt *time.Time `json:"starts_at,omitempty"`
}

// JITAccessGrantResponse is the API representation of a just-in-time access grant.
type JITAccessGrantResponse struct {
	ID            uuid.UUID       `json:"id"`
	UserID        uuid.UUID       `json:"user_id"`
	RoleID        uuid.UUID       `json:"role_id"`
	TenantID      uuid.UUID       `json:"tenant_id"`
	Justification string          `json:"justification"`
	RequestedAt   time.Time       `json:"requested_at"`
	ApprovedBy    *uuid.UUID      `json:"approved_by,omitempty"`
	ApprovedAt    *time.Time      `json:"approved_at,omitempty"`
	StartsAt      time.Time       `json:"starts_at"`
	ExpiresAt     time.Time       `json:"expires_at"`
	Status        JITAccessStatus `json:"status"`
	CreatedAt     time.Time       `json:"created_at"`
}

// JITAccessGrantListResponse is the paginated API response for listing grants.
type JITAccessGrantListResponse struct {
	Grants     []JITAccessGrantResponse `json:"grants"`
	Total      int64                    `json:"total"`
	Page       int                      `json:"page"`
	PageSize   int                      `json:"page_size"`
	TotalPages int                      `json:"total_pages"`
}
