// SPDX-License-Identifier: AGPL-3.0-or-later

package models

import (
	"time"

	"github.com/google/uuid"
)

// PermissionBoundary represents the maximum set of permissions that may be
// granted to a user, role, or service principal within a tenant. The effective
// permissions are the intersection of the granted set and the boundary's
// MaxPermissions.
type PermissionBoundary struct {
	ID             uuid.UUID `json:"id" db:"id"`
	TargetType     string    `json:"target_type" db:"target_type"` // "user", "role", "service_principal"
	TargetID       uuid.UUID `json:"target_id" db:"target_id"`
	TenantID       uuid.UUID `json:"tenant_id" db:"tenant_id"`
	MaxPermissions []string  `json:"max_permissions" db:"max_permissions"`
	CreatedAt      time.Time `json:"created_at" db:"created_at"`
	UpdatedAt      time.Time `json:"updated_at" db:"updated_at"`
}

// CreatePermissionBoundaryRequest is the API request body for setting a boundary.
type CreatePermissionBoundaryRequest struct {
	TargetType     string   `json:"target_type" binding:"required,oneof=user role service_principal"`
	TargetID       string   `json:"target_id" binding:"required,uuid"`
	MaxPermissions []string `json:"max_permissions" binding:"required"`
}

// PermissionBoundaryResponse is the API representation of a permission boundary.
type PermissionBoundaryResponse struct {
	ID             uuid.UUID `json:"id"`
	TargetType     string    `json:"target_type"`
	TargetID       uuid.UUID `json:"target_id"`
	TenantID       uuid.UUID `json:"tenant_id"`
	MaxPermissions []string  `json:"max_permissions"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}
