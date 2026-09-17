// SPDX-License-Identifier: AGPL-3.0-or-later

package models

import (
	"time"

	"github.com/google/uuid"
)

// IDPScopeAuditAction is an exported identifier.
// IDPScopeAuditAction defines the actions recorded in the scope audit log.
type IDPScopeAuditAction string

const (
	// IDPScopeAuditCreated is an exported identifier.
	IDPScopeAuditCreated IDPScopeAuditAction = "created"
	// IDPScopeAuditDeleted is an exported identifier.
	IDPScopeAuditDeleted IDPScopeAuditAction = "deleted"
	// IDPScopeAuditScopeChangeBlocked is an exported identifier.
	IDPScopeAuditScopeChangeBlocked IDPScopeAuditAction = "scope_change_blocked"
)

// IDPScopeAuditEntry is an exported identifier.
// IDPScopeAuditEntry represents a row in iam_idp_scope_audit_log.
// It records all scope-sensitive lifecycle events for identity providers
// so that administrators have a clear audit trail when following the
// "delete + recreate" workflow to change an IDP's scope.
type IDPScopeAuditEntry struct {
	ID           uuid.UUID           `json:"id" db:"id"`
	ProviderID   uuid.UUID           `json:"provider_id" db:"provider_id"`
	ProviderName string              `json:"provider_name" db:"provider_name"`
	Action       IDPScopeAuditAction `json:"action" db:"action"`
	Scope        string              `json:"scope" db:"scope"`
	RealmID      *uuid.UUID          `json:"realm_id,omitempty" db:"realm_id"`
	TenantID     *uuid.UUID          `json:"tenant_id,omitempty" db:"tenant_id"`
	PerformedBy  *uuid.UUID          `json:"performed_by,omitempty" db:"performed_by"`
	Reason       *string             `json:"reason,omitempty" db:"reason"`
	Metadata     map[string]any      `json:"metadata,omitempty" db:"metadata"`
	CreatedAt    time.Time           `json:"created_at" db:"created_at"`
}
