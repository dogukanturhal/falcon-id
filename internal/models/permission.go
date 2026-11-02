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

	// Dependencies declares other module names this module's role templates
	// are allowed to reference permissions from, in addition to Module
	// itself and the permissions already present in this same Permissions
	// payload. Optional and additive — omitting it (the pre-existing
	// behaviour for every caller that doesn't use RoleTemplates) means role
	// templates may only reference permissions belonging to Module or to
	// this same request's Permissions.
	Dependencies []string `json:"dependencies,omitempty"`

	// RoleTemplates publishes this module's versioned starter-role catalog
	// (the product roadmap §4.1 "Role templates"). Optional and additive: a
	// caller that omits it (every existing RegisterModule caller today)
	// behaves exactly as before. See RoleTemplateDefinition for the
	// per-template validation rules (key ownership, permission scope,
	// monotonic version).
	RoleTemplates []RoleTemplateDefinition `json:"role_templates,omitempty"`
}

// RegisterModuleResponse is the response for permission registration
type RegisterModuleResponse struct {
	Module     string `json:"module"`
	Registered int    `json:"registered"`
	Updated    int    `json:"updated"`
	// Deprecated is the count of catalog rows transitioned to the
	// deprecated state during this call. Always 0 when Prune=false.
	Deprecated  int                  `json:"deprecated"`
	Permissions []PermissionResponse `json:"permissions"`

	// RoleTemplates lists the templates that were registered (newly
	// inserted or matched an existing identical version) during this call.
	// Empty when the request omitted RoleTemplates.
	RoleTemplates []RoleTemplateResponse `json:"role_templates,omitempty"`
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

// DecisionReason is the machine-readable reason a permission was not granted
// (23-authorization-rbac-abac-rebac.md §5.6/§7.2). It shares one vocabulary
// with the audit reason_code and the frontend's disabled-with-reason / 403
// copy. Every value other than "" is a deny; anything the service cannot
// classify is DecisionReasonUnknown (fail closed).
type DecisionReason string

const (
	// DecisionReasonEntitlementMissing: the tenant's plan does not include the
	// permission's module (module_not_entitled).
	DecisionReasonEntitlementMissing DecisionReason = "entitlement_missing_for_module"
	// DecisionReasonPermissionDenied: the user holds no role granting it.
	DecisionReasonPermissionDenied DecisionReason = "permission_denied"
	// DecisionReasonCaveatFailed: a role/relation grants it but a caveat
	// (approval limit, time window, elevation...) did not pass or could not be
	// decided. PermissionDecision.Caveat / MissingContext say which.
	DecisionReasonCaveatFailed DecisionReason = "caveat_failed"
	// DecisionReasonSoDConflict: a block-mode separation-of-duties rule
	// forbids this permission for the user.
	DecisionReasonSoDConflict DecisionReason = "sod_conflict"
	// DecisionReasonTenantSuspended: the tenant is suspended.
	DecisionReasonTenantSuspended DecisionReason = "tenant_suspended"
	// DecisionReasonPermissionSunset: the permission was retired.
	DecisionReasonPermissionSunset DecisionReason = "permission_sunset"
	// DecisionReasonUnavailable: a dependency needed to decide (SpiceDB,
	// entitlement lookup) failed; the decision fails closed.
	DecisionReasonUnavailable DecisionReason = "authz_unavailable"
	// DecisionReasonUnknown: denied for a reason the service cannot classify.
	DecisionReasonUnknown DecisionReason = "unknown"
)

// PermissionDecision is the per-key answer of authorize/batch.
type PermissionDecision struct {
	Allowed bool           `json:"allowed"`
	Reason  DecisionReason `json:"reason,omitempty"`
	// Caveat names the failed caveat when Reason is caveat_failed and it is
	// known; MissingContext lists caveat parameters that were not supplied.
	Caveat         string   `json:"caveat,omitempty"`
	MissingContext []string `json:"missingContext,omitempty"`
	// Module is the module the denial concerns (entitlement_missing_for_module).
	Module string `json:"module,omitempty"`
}

// BatchAuthorizeResponse is the response for batch authorization check.
// Results is the legacy key->bool map (kept so existing callers keep working);
// Decisions carries the same verdict per key plus the reason for a denial.
type BatchAuthorizeResponse struct {
	Results   map[string]bool               `json:"results"`
	Decisions map[string]PermissionDecision `json:"decisions"`
}

// SimulateRequest is the body of POST /api/v1/authorize/simulate: "can user X
// do Y, and why". The user must belong to the caller's own tenant.
type SimulateRequest struct {
	UserID     uuid.UUID `json:"userId" binding:"required"`
	Permission string    `json:"permission" binding:"required"`
}

// SimulateResponse is the policy-simulator answer: the same decision
// authorize/batch would give, plus the SpiceDB resolution trace and any open
// SoD warnings that touch the permission.
type SimulateResponse struct {
	UserID      uuid.UUID          `json:"userId"`
	Permission  string             `json:"permission"`
	Decision    PermissionDecision `json:"decision"`
	Trace       interface{}        `json:"trace,omitempty"`
	Caveats     interface{}        `json:"caveats,omitempty"`
	SoDWarnings []SoDViolation     `json:"sodWarnings,omitempty"`
}

// EffectivePermissionsResponse is the response for getting user's effective permissions
type EffectivePermissionsResponse struct {
	UserID      uuid.UUID            `json:"userId"`
	Permissions []PermissionResponse `json:"permissions"`
	Roles       []string             `json:"roles"`
}
