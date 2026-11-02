// SPDX-License-Identifier: AGPL-3.0-or-later

package models

import (
	"time"

	"github.com/google/uuid"
)

// PlatformRoleKey enumerates the Hexxlock platform-plane role keys.
// Mirrors iam_platform_roles.role_key / iam_jit_elevations.role_key's
// CHECK constraint, and 1:1 the hxl_platform SpiceDB relation names via
// spicedb.PlatformRoleKeyToRelation.
type PlatformRoleKey string

const (
	// PlatformRoleAdmin is an exported identifier.
	PlatformRoleAdmin PlatformRoleKey = "platform_admin"
	// PlatformRoleSupport is an exported identifier.
	PlatformRoleSupport PlatformRoleKey = "platform_support"
	// PlatformRoleBilling is an exported identifier.
	PlatformRoleBilling PlatformRoleKey = "platform_billing"
	// PlatformRoleSecurity is an exported identifier.
	PlatformRoleSecurity PlatformRoleKey = "platform_security"
	// PlatformRoleViewer is the only standing (non-JIT) platform role.
	PlatformRoleViewer PlatformRoleKey = "platform_viewer"
	// PlatformRoleCompliance is a JIT-only role (migration 0035).
	PlatformRoleCompliance PlatformRoleKey = "platform_compliance"
	// PlatformRoleSRE is a JIT-only role (migration 0035).
	PlatformRoleSRE PlatformRoleKey = "platform_sre"
)

// IsValidPlatformRoleKey reports whether key is one of the allowed
// role_key values.
func IsValidPlatformRoleKey(key string) bool {
	switch PlatformRoleKey(key) {
	case PlatformRoleAdmin, PlatformRoleSupport, PlatformRoleBilling, PlatformRoleSecurity, PlatformRoleViewer,
		PlatformRoleCompliance, PlatformRoleSRE:
		return true
	default:
		return false
	}
}

// PlatformElevationStatus enumerates iam_jit_elevations.status values.
type PlatformElevationStatus string

const (
	// PlatformElevationPending is an exported identifier.
	PlatformElevationPending PlatformElevationStatus = "pending"
	// PlatformElevationApproved is an exported identifier.
	PlatformElevationApproved PlatformElevationStatus = "approved"
	// PlatformElevationActive is an exported identifier.
	PlatformElevationActive PlatformElevationStatus = "active"
	// PlatformElevationExpired is an exported identifier.
	PlatformElevationExpired PlatformElevationStatus = "expired"
	// PlatformElevationRevoked is an exported identifier.
	PlatformElevationRevoked PlatformElevationStatus = "revoked"
	// PlatformElevationDenied is an exported identifier.
	PlatformElevationDenied PlatformElevationStatus = "denied"
)

// PlatformElevationMaxDuration is the 8h JIT elevation duration cap
// (mockups account-admin/30-platform-jit-elevation.html), mirrored by
// migration 0016's CHECK constraint.
const PlatformElevationMaxDuration = 8 * time.Hour

// BreakGlassMaxDuration is the 1h break-glass self-grant window cap,
// mirrored by migration 0016's CHECK constraint.
const BreakGlassMaxDuration = 1 * time.Hour

// BreakGlassRetroactiveApprovalSLA is the 24h window a break-glass grant
// has to receive retroactive approval before the SLA sweep flags
// break_glass_violation=true and auto-revokes it.
const BreakGlassRetroactiveApprovalSLA = 24 * time.Hour

// PlatformRole is a standing iam_platform_roles row.
type PlatformRole struct {
	UserID    uuid.UUID       `json:"user_id" db:"user_id"`
	RoleKey   PlatformRoleKey `json:"role_key" db:"role_key"`
	GrantedAt time.Time       `json:"granted_at" db:"granted_at"`
	GrantedBy *uuid.UUID      `json:"granted_by,omitempty" db:"granted_by"`
}

// PlatformElevation is an iam_jit_elevations row.
type PlatformElevation struct {
	ID                       uuid.UUID               `json:"id" db:"id"`
	RequesterID              uuid.UUID               `json:"requester_id" db:"requester_id"`
	RoleKey                  PlatformRoleKey         `json:"role_key" db:"role_key"`
	TenantScope              *uuid.UUID              `json:"tenant_scope,omitempty" db:"tenant_scope"`
	Reason                   string                  `json:"reason" db:"reason"`
	Status                   PlatformElevationStatus `json:"status" db:"status"`
	ApproverID               *uuid.UUID              `json:"approver_id,omitempty" db:"approver_id"`
	ApprovedAt               *time.Time              `json:"approved_at,omitempty" db:"approved_at"`
	RequestedDurationSeconds int                     `json:"requested_duration_seconds" db:"requested_duration_seconds"`
	ExpiresAt                *time.Time              `json:"expires_at,omitempty" db:"expires_at"`
	IsBreakGlass             bool                    `json:"is_break_glass" db:"is_break_glass"`
	RetroactiveApproverID    *uuid.UUID              `json:"retroactive_approver_id,omitempty" db:"retroactive_approver_id"`
	RetroactiveApprovedAt    *time.Time              `json:"retroactive_approved_at,omitempty" db:"retroactive_approved_at"`
	BreakGlassViolation      bool                    `json:"break_glass_violation" db:"break_glass_violation"`
	SpiceDBActivateZedToken  *string                 `json:"-" db:"spicedb_activate_zed_token"`
	SpiceDBRevokeZedToken    *string                 `json:"-" db:"spicedb_revoke_zed_token"`
	CreatedAt                time.Time               `json:"created_at" db:"created_at"`
	UpdatedAt                time.Time               `json:"updated_at" db:"updated_at"`
}

// RequestPlatformElevationRequest is the POST /internal/v1/jit-elevations body.
type RequestPlatformElevationRequest struct {
	RoleKey         string     `json:"role_key" binding:"required"`
	TenantScope     *uuid.UUID `json:"tenant_scope,omitempty"`
	Reason          string     `json:"reason" binding:"required,min=1"`
	DurationSeconds int        `json:"duration_seconds" binding:"required,min=1,max=28800"`
}

// ApprovePlatformElevationRequest is the POST
// /internal/v1/jit-elevations/{id}/approve body.
type ApprovePlatformElevationRequest struct {
	Note string `json:"note,omitempty"`
}

// RequestBreakGlassRequest is the POST /internal/v1/break-glass body.
type RequestBreakGlassRequest struct {
	RoleKey         string     `json:"role_key" binding:"required"`
	TenantScope     *uuid.UUID `json:"tenant_scope,omitempty"`
	Reason          string     `json:"reason" binding:"required,min=1"`
	DurationSeconds int        `json:"duration_seconds" binding:"required,min=1,max=3600"`
}

// RetroactiveApprovalRequest is the POST
// /internal/v1/break-glass/{id}/retroactive-approve body.
type RetroactiveApprovalRequest struct {
	Note string `json:"note,omitempty"`
}

// ElevationListFilter narrows a GET /internal/v1/jit-elevations or
// GET /internal/v1/break-glass listing. All fields are optional
// (nil/empty = no filter on that column). BreakGlassOnly is set by the
// break-glass handler, never bound from a query param, so a caller of
// /jit-elevations cannot smuggle break-glass rows into that listing (and
// vice versa) — the two GET routes are otherwise identical plumbing over
// the same iam_jit_elevations table, distinguished only by this flag.
type ElevationListFilter struct {
	Status         *PlatformElevationStatus
	RequesterID    *uuid.UUID
	BreakGlassOnly *bool
}

// ElevationListPage is the paginated result of a filtered elevation
// listing. Total is the filter-matched row count (not the page size),
// so callers can compute total pages / "has more" without a second
// round trip.
type ElevationListPage struct {
	Items []*PlatformElevation
	Total int
}

// PlatformElevationTransition is one append-only, hash-chained row from
// iam_jit_elevation_transitions (migration 0016). Read-only from the API's
// perspective — the only writer is
// PlatformElevationRepository.AppendTransition via
// PlatformJITService.appendTransition.
type PlatformElevationTransition struct {
	ID          uuid.UUID  `json:"id" db:"id"`
	ElevationID uuid.UUID  `json:"elevation_id" db:"elevation_id"`
	FromStatus  *string    `json:"from_status,omitempty" db:"from_status"`
	ToStatus    string     `json:"to_status" db:"to_status"`
	ActorID     *uuid.UUID `json:"actor_id,omitempty" db:"actor_id"`
	OccurredAt  time.Time  `json:"occurred_at" db:"occurred_at"`
	PrevHash    string     `json:"prev_hash" db:"prev_hash"`
	EntryHash   string     `json:"entry_hash" db:"entry_hash"`
	Details     []byte     `json:"details,omitempty" db:"details"`
}

// TransitionListPage is the paginated result of a transitions/audit
// listing (see PlatformElevationRepository.ListTransitions).
type TransitionListPage struct {
	Items []*PlatformElevationTransition
	Total int
}

// ElevationListResponse is the JSON envelope for
// GET /internal/v1/jit-elevations and GET /internal/v1/break-glass,
// following this codebase's page/page_size/total/total_pages
// convention (see e.g. ThreatSignalListResponse in internal/models/itdr.go).
type ElevationListResponse struct {
	Elevations []*PlatformElevation `json:"elevations"`
	Total      int                  `json:"total"`
	Page       int                  `json:"page"`
	PageSize   int                  `json:"page_size"`
	TotalPages int                  `json:"total_pages"`
}

// TransitionListResponse is the JSON envelope for
// GET /internal/v1/jit-elevations/:id/transitions (the read-only audit
// endpoint over the append-only hash-chain log).
type TransitionListResponse struct {
	Transitions []*PlatformElevationTransition `json:"transitions"`
	Total       int                            `json:"total"`
	Page        int                            `json:"page"`
	PageSize    int                            `json:"page_size"`
	TotalPages  int                            `json:"total_pages"`
}
