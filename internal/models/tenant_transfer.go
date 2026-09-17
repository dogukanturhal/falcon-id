// SPDX-License-Identifier: AGPL-3.0-or-later

package models

import (
	"time"

	"github.com/google/uuid"
)

// TenantTransferStatus enumerates the lifecycle states of a
// consumer→business tenant-transfer request. Microsoft's MSA-to-Entra
// migration uses an analogous "pending / approved / executed /
// rejected / expired" state machine; HexxLock follows the same pattern.
type TenantTransferStatus string

const (
	// TenantTransferStatusPending — request created, not yet acted on.
	TenantTransferStatusPending TenantTransferStatus = "pending"
	// TenantTransferStatusApproved — business-tenant admin accepted
	// the user as a member; the actual data-move is still queued.
	TenantTransferStatusApproved TenantTransferStatus = "approved"
	// TenantTransferStatusExecuted — user + their owned data (sessions,
	// devices, OAuth tokens, app-role assignments) now live in the
	// destination tenant. Source tenant membership revoked.
	TenantTransferStatusExecuted TenantTransferStatus = "executed"
	// TenantTransferStatusRejected — business-tenant admin declined.
	TenantTransferStatusRejected TenantTransferStatus = "rejected"
	// TenantTransferStatusExpired — request not acted on within the
	// configured TTL (default 7 days).
	TenantTransferStatusExpired TenantTransferStatus = "expired"
)

// TenantTransferRequest models a consumer-to-business tenant transfer.
//
// Use case: user signs up with personal@example.com landing in the
// shared consumer tenant. Later, example.com gets claimed by an
// Acme Corp business tenant. The user (or Acme admin) initiates a
// transfer to move the user + their data from consumer → Acme tenant.
//
// Currently STUB ONLY — the handler at /api/v1/admin/tenant-transfers
// returns 501 Not Implemented. This model + the skeleton handler
// land first so that:
//
//   1. The API shape is stable enough that frontend can mock against
//      it for UX iteration.
//   2. Subsequent MRs that implement actual migration semantics don't
//      need to also bikeshed the request shape.
//   3. The Keystone schema gets the iam_tenant_transfers table on the
//      next regen, ready for the real implementation to write rows.
//
// Real implementation surface (ENT-6 Phase 2):
//
//   - DataDeletionService-style cascade across iam_sessions /
//     iam_oauth_tokens / iam_app_role_assignments / iam_user_devices /
//     iam_user_consents → re-attribute to new tenant.
//   - Audit trail of every row touched.
//   - Idempotent retry: a transfer that fails mid-cascade can resume
//     from the last successfully-moved row class.
//   - Email notifications to both source-tenant admin (consumer = no
//     admin, so the platform takes that role) and destination admin.
//
// See docs/operator-runbooks/ent6-tenant-transfer-procedure.md
// (TODO) for the full design.
type TenantTransferRequest struct {
	ID uuid.UUID `json:"id" db:"id"`
	// UserID — the user being transferred.
	UserID uuid.UUID `json:"user_id" db:"user_id"`
	// FromTenantID — the source tenant (currently the consumer
	// tenant in most cases). The user is a MEMBER of this tenant
	// at request creation time.
	FromTenantID uuid.UUID `json:"from_tenant_id" db:"from_tenant_id"`
	// ToTenantID — the destination tenant (the business tenant
	// that has claimed the user's email domain).
	ToTenantID uuid.UUID `json:"to_tenant_id" db:"to_tenant_id"`
	// Status — current lifecycle state.
	Status TenantTransferStatus `json:"status" db:"status"`
	// InitiatedBy — the user or admin who created the request.
	// For self-initiated (user wants to move TO a business tenant),
	// this equals UserID. For admin-initiated (Acme admin wants to
	// pull a consumer-tenant user into their tenant), this is the
	// admin's UUID.
	InitiatedBy uuid.UUID `json:"initiated_by" db:"initiated_by"`
	// ApprovedBy — the destination-tenant admin who approved.
	// NULL until status transitions to approved.
	ApprovedBy *uuid.UUID `json:"approved_by,omitempty" db:"approved_by"`
	// ExecutedAt — when the actual data-move completed.
	ExecutedAt *time.Time `json:"executed_at,omitempty" db:"executed_at"`
	// ExpiresAt — request expires after this. Default 7d post-create.
	ExpiresAt time.Time `json:"expires_at" db:"expires_at"`
	// Reason — free-text rationale, surfaced in the audit trail.
	Reason *string `json:"reason,omitempty" db:"reason"`

	CreatedAt time.Time `json:"created_at" db:"created_at"`
	UpdatedAt time.Time `json:"updated_at" db:"updated_at"`
}

// CreateTenantTransferRequest is the API input for POST /api/v1/admin/
// tenant-transfers. Validated by the handler.
type CreateTenantTransferRequest struct {
	UserID     uuid.UUID `json:"user_id" binding:"required"`
	ToTenantID uuid.UUID `json:"to_tenant_id" binding:"required"`
	Reason     *string   `json:"reason"`
}
