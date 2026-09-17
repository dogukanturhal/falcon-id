// SPDX-License-Identifier: AGPL-3.0-or-later

package models

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"time"

	"github.com/google/uuid"
)

// CanonicalInvitationEmail is the invitation identity representation used for
// validation, persistence, and all downstream delivery metadata. Deliberately
// do not add Unicode normalization or IDNA conversion: the existing Falcon
// email policy only trims surrounding whitespace and lowercases.
func CanonicalInvitationEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

// TeamInvitationTokenDigest keeps newly-issued bearer tokens out of the
// invitation row. The prefix distinguishes digests from legacy plaintext rows
// during the bounded compatibility window for already-issued invitations.
func TeamInvitationTokenDigest(token string) string {
	digest := sha256.Sum256([]byte(token))
	return "sha256:" + hex.EncodeToString(digest[:])
}

// TeamInvitationStatus enumerates the states of an iam_team_invitations row.
type TeamInvitationStatus string

const (
	// TeamInvitationStatusPending is the initial state after creation.
	TeamInvitationStatusPending TeamInvitationStatus = "pending"
	// TeamInvitationStatusAccepted is set when the invitee accepts.
	TeamInvitationStatusAccepted TeamInvitationStatus = "accepted"
	// TeamInvitationStatusExpired is set by a background sweep or on
	// token validation when expires_at is in the past.
	TeamInvitationStatusExpired TeamInvitationStatus = "expired"
	// TeamInvitationStatusRevoked is set when an admin cancels the invite.
	TeamInvitationStatusRevoked TeamInvitationStatus = "revoked"
)

// TeamInvitation represents a row in iam_team_invitations.
// The token column stores a SHA-256 digest for new invitations. Legacy
// plaintext tokens remain readable only until their seven-day expiry.
// When accepted, role_ids are applied to the invitee via iam_user_roles.
type TeamInvitation struct {
	ID         uuid.UUID            `json:"id"`
	TenantID   uuid.UUID            `json:"tenantId"`
	Email      string               `json:"email"`
	RoleIDs    []uuid.UUID          `json:"roleIds"`
	InvitedBy  uuid.UUID            `json:"invitedBy"`
	Token      string               `json:"-"` // never serialised to the client
	Status     TeamInvitationStatus `json:"status"`
	ExpiresAt  time.Time            `json:"expiresAt"`
	CreatedAt  time.Time            `json:"createdAt"`
	AcceptedAt *time.Time           `json:"acceptedAt,omitempty"`
}

// IsValid returns true when the invitation is pending and not yet expired.
func (i *TeamInvitation) IsValid() bool {
	return i.Status == TeamInvitationStatusPending && time.Now().Before(i.ExpiresAt)
}

// CreateTeamInvitationRequest is the body accepted by POST /api/v1/invitations.
type CreateTeamInvitationRequest struct {
	Email   string      `json:"email"   binding:"required,email"`
	RoleIDs []uuid.UUID `json:"roleIds" binding:"required,min=1"`
}

// AcceptTeamInvitationRequest is the body accepted by POST /api/v1/invitations/accept.
type AcceptTeamInvitationRequest struct {
	Token string `json:"token" binding:"required"`
}

// TeamInvitationResponse is the wire shape returned by the list / create endpoints.
type TeamInvitationResponse struct {
	ID        uuid.UUID            `json:"id"`
	Email     string               `json:"email"`
	RoleIDs   []uuid.UUID          `json:"roleIds"`
	Status    TeamInvitationStatus `json:"status"`
	ExpiresAt time.Time            `json:"expiresAt"`
	CreatedAt time.Time            `json:"createdAt"`
}

// TenantUserWithRoles is the wire shape for GET /api/v1/tenants/me/users.
type TenantUserWithRoles struct {
	ID          uuid.UUID `json:"id"`
	Email       string    `json:"email"`
	DisplayName string    `json:"displayName"`
	IsActive    bool      `json:"isActive"`
	Roles       []RoleRef `json:"roles"`
	CreatedAt   time.Time `json:"createdAt"`
	// This response is sourced only from iam_users, so it always represents a
	// human principal. Native machine principals have a separate endpoint.
	PrincipalType   string `json:"principalType"`
	PrincipalSource string `json:"principalSource"`
}

// RoleRef is a lightweight role reference embedded in TenantUserWithRoles.
//
// Editable reports whether the self-service role picker (GET /api/v1/roles,
// RoleService.ListSelfService) for the CALLER's current tenant could have
// offered this exact role, i.e. whether POST /api/v1/team/users/:id/roles
// is allowed to change it. A role is non-editable for either of two
// reasons, both surfaced via Reason:
//   - it belongs to a different tenant than the caller's (tenant_id
//     mismatch — defence in depth; not known to occur in practice today);
//   - it belongs to the caller's own tenant but that tenant isn't entitled
//     to the role's product module, so ListSelfService's module filter
//     excludes it from the picker even though the grant exists.
//
// Reason is populated only when Editable is false. See
// TeamInvitationHandler.ListTenantUsers for the exact strings, and
// UserRepository.AssignRolesInTenant for how this same set bounds what a
// save is allowed to delete.
type RoleRef struct {
	ID       uuid.UUID  `json:"id"`
	Name     string     `json:"name"`
	Editable bool       `json:"editable"`
	Reason   string     `json:"reason,omitempty"`
	Source   RoleSource `json:"source"`
}

// TeamSetUserRolesRequest is the body accepted by the team management
// POST /api/v1/users/:id/roles endpoint. Replaces the user's role
// assignments, but ONLY within the set the self-service role picker could
// have offered (this tenant's entitled-module roles) — any grant outside
// that set (another tenant's role, or this tenant's role for an
// unentitled module) is left untouched. See
// UserRepository.AssignRolesInTenant.
type TeamSetUserRolesRequest struct {
	RoleIDs []uuid.UUID `json:"roleIds" binding:"required"`
}

// TenantMachinePrincipal is a credential-free inventory item. It deliberately
// has no client ID, secret, public key, key ID, scope, or allow-list fields.
type TenantMachinePrincipal struct {
	ID        uuid.UUID `json:"id"`
	Name      string    `json:"name"`
	Kind      string    `json:"kind"`
	Source    string    `json:"source"`
	Status    string    `json:"status"`
	CreatedAt time.Time `json:"createdAt"`
}
