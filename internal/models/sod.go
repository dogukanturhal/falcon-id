// SPDX-License-Identifier: AGPL-3.0-or-later

package models

import (
	"time"

	"github.com/google/uuid"
)

// SoDMode is the enforcement mode of a SoD rule.
type SoDMode string

const (
	// SoDModeWarn allows the write that creates the conflict but records
	// an iam_sod_violations row. The only mode any seeded rule uses in R1
	// (the product roadmap: "SoD rules (warn in R1; block for PreAcc in R2
	// and Accounting in R3)").
	SoDModeWarn SoDMode = "warn"
	// SoDModeBlock rejects the write with 409 sod_conflict. Not exercised
	// by any seeded rule yet — reserved for the per-module R2/R3 flip.
	SoDModeBlock SoDMode = "block"
)

// SoDRule is a single conflicting-permission-pair rule
// (23-authorization-rbac-abac-rebac.md §5.2/§2.7).
type SoDRule struct {
	ID          uuid.UUID  `json:"id" db:"id"`
	TenantID    *uuid.UUID `json:"tenant_id,omitempty" db:"tenant_id"`
	Module      string     `json:"module" db:"module"`
	PermissionA string     `json:"permission_a" db:"permission_a"`
	PermissionB string     `json:"permission_b" db:"permission_b"`
	Mode        SoDMode    `json:"mode" db:"mode"`
	Description *string    `json:"description,omitempty" db:"description"`
	IsDefault   bool       `json:"is_default" db:"is_default"`
	CreatedBy   *uuid.UUID `json:"created_by,omitempty" db:"created_by"`
	DisabledAt  *time.Time `json:"disabled_at,omitempty" db:"disabled_at"`
	CreatedAt   time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at" db:"updated_at"`
}

// IsActive reports whether the rule is currently in effect.
func (r *SoDRule) IsActive() bool {
	return r.DisabledAt == nil
}

// CreateSoDRuleRequest is the body for
// POST /api/v1/account/sod-rules.
type CreateSoDRuleRequest struct {
	Module      string  `json:"module" binding:"required"`
	PermissionA string  `json:"permission_a" binding:"required"`
	PermissionB string  `json:"permission_b" binding:"required"`
	Mode        SoDMode `json:"mode" binding:"omitempty,oneof=warn block"`
	Description *string `json:"description,omitempty"`
}

// UpdateSoDRuleRequest is the body for
// PATCH /api/v1/account/sod-rules/{id}. All fields optional; nil means
// "leave unchanged". Disabled is a pointer so `false` (re-enable) is
// distinguishable from "not supplied".
type UpdateSoDRuleRequest struct {
	Mode        *SoDMode `json:"mode,omitempty" binding:"omitempty,oneof=warn block"`
	Description *string  `json:"description,omitempty"`
	Disabled    *bool    `json:"disabled,omitempty"`
}

// SoDViolation is a detected conflict: a user holding both permissions of
// an active SoDRule pair.
type SoDViolation struct {
	ID          uuid.UUID   `json:"id" db:"id"`
	TenantID    uuid.UUID   `json:"tenant_id" db:"tenant_id"`
	UserID      uuid.UUID   `json:"user_id" db:"user_id"`
	RuleID      uuid.UUID   `json:"rule_id" db:"rule_id"`
	PermissionA string      `json:"permission_a" db:"permission_a"`
	PermissionB string      `json:"permission_b" db:"permission_b"`
	Mode        SoDMode     `json:"mode" db:"mode"`
	RoleIDs     []uuid.UUID `json:"role_ids" db:"role_ids"`
	DetectedAt  time.Time   `json:"detected_at" db:"detected_at"`
	ResolvedAt  *time.Time  `json:"resolved_at,omitempty" db:"resolved_at"`
	ResolvedBy  *uuid.UUID  `json:"resolved_by,omitempty" db:"resolved_by"`
}

// IsOpen reports whether the violation is still unresolved.
func (v *SoDViolation) IsOpen() bool {
	return v.ResolvedAt == nil
}

// EvaluateSoDRequest is the body for POST /internal/v1/sod/evaluate.
type EvaluateSoDRequest struct {
	TenantID uuid.UUID `json:"tenant_id" binding:"required"`
	UserID   uuid.UUID `json:"user_id" binding:"required"`
	// RoleIDs, when supplied, is recorded on any violation detected by
	// this evaluation (best-effort provenance — "which roles put this
	// user in conflict"). Optional: a continuous/scheduled re-evaluation
	// call may not have this context handy.
	RoleIDs []uuid.UUID `json:"role_ids,omitempty"`
}

// EvaluateSoDResponse is the response for POST /internal/v1/sod/evaluate.
type EvaluateSoDResponse struct {
	TenantID   uuid.UUID      `json:"tenant_id"`
	UserID     uuid.UUID      `json:"user_id"`
	Violations []SoDViolation `json:"violations"`
}
