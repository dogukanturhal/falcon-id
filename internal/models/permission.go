// SPDX-License-Identifier: AGPL-3.0-or-later

package models

import (
	"time"

	"github.com/google/uuid"
)

// Permission is an exported type.
type Permission struct {
	ID          uuid.UUID `json:"id" db:"id"`
	Module      string    `json:"module" db:"module"`
	Resource    string    `json:"resource" db:"resource"`
	Action      string    `json:"action" db:"action"`
	Name        string    `json:"name" db:"name"`
	DisplayName string    `json:"display_name" db:"display_name"`
	Description *string   `json:"description,omitempty" db:"description"`
	IsSystem    bool      `json:"is_system" db:"is_system"`
	Source      string    `json:"source" db:"source"`

	// Versioning and deprecation fields — added by migration 090.
	// Version is a monotonically increasing counter bumped on each structural change.
	Version int `json:"version" db:"version"`
	// DeprecatedAt is set when the permission enters the deprecated state.
	// A nil value means the permission is still active.
	DeprecatedAt *time.Time `json:"deprecated_at,omitempty" db:"deprecated_at"`
	// ReplacementPermission is the name (module:resource:action) of the
	// successor permission, if one exists.
	ReplacementPermission *string `json:"replacement_permission,omitempty" db:"replacement_permission"`
	// SunsetAt is the timestamp after which the authorization engine stops
	// honouring this permission.  Nil means no forced sunset.
	SunsetAt *time.Time `json:"sunset_at,omitempty" db:"sunset_at"`

	CreatedAt time.Time `json:"created_at" db:"created_at"`
}

// PermissionResponse is an exported type.
type PermissionResponse struct {
	ID                    uuid.UUID  `json:"id"`
	Module                string     `json:"module"`
	Resource              string     `json:"resource"`
	Action                string     `json:"action"`
	Name                  string     `json:"name"`
	DisplayName           string     `json:"display_name"`
	Description           *string    `json:"description,omitempty"`
	IsSystem              bool       `json:"is_system"`
	Source                string     `json:"source"`
	Version               int        `json:"version"`
	DeprecatedAt          *time.Time `json:"deprecated_at,omitempty"`
	ReplacementPermission *string    `json:"replacement_permission,omitempty"`
	SunsetAt              *time.Time `json:"sunset_at,omitempty"`
}

// PermissionListResponse is an exported type.
type PermissionListResponse struct {
	Permissions []PermissionResponse `json:"permissions"`
	Total       int64                `json:"total"`
}

// PermissionsByModule is an exported type.
type PermissionsByModule struct {
	Module      string               `json:"module"`
	Permissions []PermissionResponse `json:"permissions"`
}

// ToResponse is an exported function.
func (p *Permission) ToResponse() *PermissionResponse {
	return &PermissionResponse{
		ID:                    p.ID,
		Module:                p.Module,
		Resource:              p.Resource,
		Action:                p.Action,
		Name:                  p.Name,
		DisplayName:           p.DisplayName,
		Description:           p.Description,
		IsSystem:              p.IsSystem,
		Source:                p.Source,
		Version:               p.Version,
		DeprecatedAt:          p.DeprecatedAt,
		ReplacementPermission: p.ReplacementPermission,
		SunsetAt:              p.SunsetAt,
	}
}

// IsDeprecated returns true when the permission has been deprecated.
func (p *Permission) IsDeprecated() bool {
	return p.DeprecatedAt != nil
}

// IsSunset returns true when the permission has passed its sunset date and
// should no longer be honoured by the authorization engine.
func (p *Permission) IsSunset() bool {
	if p.SunsetAt == nil {
		return false
	}
	return time.Now().After(*p.SunsetAt)
}

// RolePermission represents the many-to-many relationship
type RolePermission struct {
	ID           uuid.UUID  `json:"id" db:"id"`
	RoleID       uuid.UUID  `json:"role_id" db:"role_id"`
	PermissionID uuid.UUID  `json:"permission_id" db:"permission_id"`
	CreatedAt    time.Time  `json:"created_at" db:"created_at"`
	CreatedBy    *uuid.UUID `json:"created_by,omitempty" db:"created_by"`
}

// UserRole represents the many-to-many relationship
type UserRole struct {
	ID         uuid.UUID  `json:"id" db:"id"`
	UserID     uuid.UUID  `json:"user_id" db:"user_id"`
	RoleID     uuid.UUID  `json:"role_id" db:"role_id"`
	AssignedAt time.Time  `json:"assigned_at" db:"assigned_at"`
	AssignedBy *uuid.UUID `json:"assigned_by,omitempty" db:"assigned_by"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty" db:"expires_at"`
}

// PermissionDefinition defines a single permission within a resource
type PermissionDefinition struct {
	Resource    string   `json:"resource" binding:"required"`
	Actions     []string `json:"actions" binding:"required,min=1"`
	DisplayName string   `json:"displayName"`
	Description string   `json:"description"`
}

// RegisterModuleRequest is the request body for registering module permissions.
//
// Default behaviour is purely ADDITIVE: catalog rows for permissions absent
// from the payload are left untouched. This keeps existing single-service
// startup register calls safe — a misconfigured pod shipping an empty manifest
// can never blow away another pod's permissions.
//
// When `Prune` is true, any permission row that currently exists in the
// catalog for this `Module` AND does NOT appear in the payload is transitioned
// to the deprecation lifecycle: `deprecated_at = now()`, `sunset_at = now() +
// 30 days`. Already-deprecated rows are left alone (idempotent). Hard delete
// is a separate sweep that fires after `sunset_at` passes and validates that
// no `iam_role_permissions` row references the permission. The caller must
// hold the same `service:register` scope as for the additive path.
type RegisterModuleRequest struct {
	Module      string                 `json:"module" binding:"required"`
	Permissions []PermissionDefinition `json:"permissions" binding:"required,min=1"`
	// Prune toggles sync semantics. When true, permissions in the catalog
	// for this Module but absent from Permissions are soft-deprecated.
	// Defaults to false (additive, backward-compat).
	Prune bool `json:"prune,omitempty"`
}

// RegisterModuleResponse is the response for permission registration
type RegisterModuleResponse struct {
	Module      string               `json:"module"`
	Registered  int                  `json:"registered"`
	Updated     int                  `json:"updated"`
	// Deprecated is the count of catalog rows transitioned to the
	// deprecated state during this call. Always 0 when Prune=false.
	Deprecated  int                  `json:"deprecated"`
	Permissions []PermissionResponse `json:"permissions"`
}

// CreatePermissionRequest is the request body for creating a single permission
type CreatePermissionRequest struct {
	Module      string  `json:"module" binding:"required"`
	Resource    string  `json:"resource" binding:"required"`
	Action      string  `json:"action" binding:"required"`
	DisplayName string  `json:"display_name" binding:"required"`
	Description *string `json:"description"`
}

// UpdatePermissionRequest is the request body for updating a permission
type UpdatePermissionRequest struct {
	DisplayName *string `json:"display_name"`
	Description *string `json:"description"`
}

// AuthorizeRequest is the request body for authorization check
type AuthorizeRequest struct {
	UserID     uuid.UUID `json:"userId" binding:"required"`
	Permission string    `json:"permission" binding:"required"`
	TenantID   uuid.UUID `json:"tenantId"`

	// Resource context for ABAC evaluation
	ResourceType string                 `json:"resourceType,omitempty"` // e.g., "invoice", "document"
	ResourceID   string                 `json:"resourceId,omitempty"`   // e.g., "123"
	OwnerID      *uuid.UUID             `json:"ownerId,omitempty"`      // Resource owner for ownership checks
	Attributes   map[string]interface{} `json:"attributes,omitempty"`   // e.g., {"amount": 5000}

	// Request context for ABAC evaluation
	IPAddress   string `json:"ipAddress,omitempty"`
	UserAgent   string `json:"userAgent,omitempty"`
	RequestPath string `json:"requestPath,omitempty"`
}

// AuthorizeResponse is the response for authorization check
type AuthorizeResponse struct {
	Allowed bool   `json:"allowed"`
	Reason  string `json:"reason,omitempty"`
}

// BatchAuthorizeRequest is the request body for batch authorization check
type BatchAuthorizeRequest struct {
	UserID      uuid.UUID `json:"userId" binding:"required"`
	Permissions []string  `json:"permissions" binding:"required,min=1"`
	TenantID    uuid.UUID `json:"tenantId"`
}

// BatchAuthorizeResponse is the response for batch authorization check
type BatchAuthorizeResponse struct {
	Results map[string]bool `json:"results"`
}

// EffectivePermissionsResponse is the response for getting user's effective permissions
type EffectivePermissionsResponse struct {
	UserID      uuid.UUID            `json:"userId"`
	Permissions []PermissionResponse `json:"permissions"`
	Roles       []string             `json:"roles"`
}
