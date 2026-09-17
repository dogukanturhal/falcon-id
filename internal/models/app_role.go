// SPDX-License-Identifier: AGPL-3.0-or-later

package models

import (
	"time"

	"github.com/google/uuid"
)

// AppRole defines a role that an application exposes to its principals.
// Roles are stored as a JSONB array in the iam_applications.app_roles column.
// The ID is a UUID stored as a plain string so it can survive JSON round-trips
// without any pgx-specific type scanning.
type AppRole struct {
	ID          string `json:"id"`
	DisplayName string `json:"display_name"`
	Description string `json:"description,omitempty"`
	Value       string `json:"value"` // e.g. "admin", "reader", "writer"
	IsEnabled   bool   `json:"is_enabled"`
}

// ApplicationRoleAssignment records that a principal has been granted an AppRole
// for a specific application. Maps directly to iam_app_role_assignments.
type ApplicationRoleAssignment struct {
	ID            uuid.UUID `json:"id" db:"id"`
	ApplicationID uuid.UUID `json:"application_id" db:"application_id"`
	AppRoleID     uuid.UUID `json:"app_role_id" db:"app_role_id"`
	PrincipalType string    `json:"principal_type" db:"principal_type"` // "user", "group", "service_principal"
	PrincipalID   uuid.UUID `json:"principal_id" db:"principal_id"`
	TenantID      uuid.UUID `json:"tenant_id" db:"tenant_id"`
	AssignedBy    uuid.UUID `json:"assigned_by" db:"assigned_by"`
	CreatedAt     time.Time `json:"created_at" db:"created_at"`
}

// AssignAppRoleRequest is the payload for POST /:id/roles/assignments.
type AssignAppRoleRequest struct {
	AppRoleID     uuid.UUID `json:"app_role_id" binding:"required"`
	PrincipalType string    `json:"principal_type" binding:"required,oneof=user group service_principal"`
	PrincipalID   uuid.UUID `json:"principal_id" binding:"required"`
}
