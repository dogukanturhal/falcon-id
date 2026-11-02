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
	// TeamInvitationStatusDeclined is set when the INVITEE declines the
	// invitation via POST /api/v1/invitations/decline. Deliberately a
	// distinct value from "revoked" (an admin action against the invite)
	// even though both are terminal, non-accepted states — audit trails
	// and the pending-invitations UI need to tell "the admin withdrew this"
	// apart from "the invitee said no". Requires the matching
	// iam_team_invitations_status_check CHECK constraint in
	// the GitOps repository to list 'declined'; see that migration for the
	// schema half of this change.
	TeamInvitationStatusDeclined TeamInvitationStatus = "declined"
)

// SeatClass mirrors the product roadmap §2.1/§3.2's locked seat_class rule:
// "member" consumes a tenant seat; "external" (accountant/guest) and
// "service" (service/API account) never do. Shared between
// iam_team_invitations and iam_user_memberships so an accepted invitation's
// seat_class carries over to its membership row unchanged.
type SeatClass string

const (
	// SeatClassMember consumes a seat and is counted by tenant_seat_counters.
	SeatClassMember SeatClass = "member"
	// SeatClassExternal (accountant/guest) never consumes a seat.
	SeatClassExternal SeatClass = "external"
	// SeatClassService (service/API account) never consumes a seat.
	SeatClassService SeatClass = "service"
	// SeatClassEmployee (R-HR WP-21): an HR employee's own self-service login. Lives in the
	// employer tenant, never consumes a seat, created only by the S2S employee-accounts
	// endpoint (never by a team invitation) and ends at iam_user_memberships.access_expires_at.
	SeatClassEmployee SeatClass = "employee"
	// SeatClassKiosk (R6 WP-23): a shop-floor Production Operatör login. Lives in the employer tenant, never
	// consumes a paid seat, is counted against the quota-service kiosk_users quota, and is created only by
	// POST /api/v1/tenants/me/kiosk-users (never by team invitation).
	SeatClassKiosk SeatClass = "kiosk"
)

// IsValidSeatClass reports whether s is one of the four seat classes.
// Empty string is invalid; callers default to SeatClassMember explicitly
// rather than relying on the zero value.
func IsValidSeatClass(s SeatClass) bool {
	switch s {
	case SeatClassMember, SeatClassExternal, SeatClassService, SeatClassEmployee, SeatClassKiosk:
		return true
	default:
		return false
	}
}

// TeamInvitation represents a row in iam_team_invitations.
// The token column stores a SHA-256 digest for new invitations. Legacy
// plaintext tokens remain readable only until their seven-day expiry.
// When accepted, role_ids are applied to the invitee via iam_user_roles.
type TeamInvitation struct {
	ID           uuid.UUID            `json:"id"`
	TenantID     uuid.UUID            `json:"tenantId"`
	Email        string               `json:"email"`
	RoleIDs      []uuid.UUID          `json:"roleIds"`
	InvitedBy    uuid.UUID            `json:"invitedBy"`
	Token        string               `json:"-"` // never serialised to the client
	Status       TeamInvitationStatus `json:"status"`
	SeatClass    SeatClass            `json:"seatClass"`
	ExpiresAt    time.Time            `json:"expiresAt"`
	CreatedAt    time.Time            `json:"createdAt"`
	AcceptedAt   *time.Time           `json:"acceptedAt,omitempty"`
	LastResentAt *time.Time           `json:"lastResentAt,omitempty"`
}

// IsValid returns true when the invitation is pending and not yet expired.
func (i *TeamInvitation) IsValid() bool {
	return i.Status == TeamInvitationStatusPending && time.Now().Before(i.ExpiresAt)
}

// ConsumesSeat reports whether this invitation's seat_class counts against
// tenant_seat_counters (member only — see SeatClass doc comment).
func (i *TeamInvitation) ConsumesSeat() bool {
	return i.SeatClass == SeatClassMember
}

// CreateTeamInvitationRequest is the body accepted by POST /api/v1/invitations.
// SeatClass is optional and defaults to "member" (existing pre-seat-class
// callers keep working unchanged).
type CreateTeamInvitationRequest struct {
	Email     string      `json:"email"   binding:"required,email"`
	RoleIDs   []uuid.UUID `json:"roleIds" binding:"required,min=1"`
	SeatClass SeatClass   `json:"seatClass" binding:"omitempty,oneof=member external service"`
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
	SeatClass SeatClass            `json:"seatClass"`
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

// ExternalMember is the wire shape for GET /api/v1/tenants/me/external-members:
// an active seat_class=external membership (accountant from a partner
// tenant). Roles lists only grants in the caller's tenant.
type ExternalMember struct {
	ID          uuid.UUID `json:"id"`
	Email       string    `json:"email"`
	DisplayName string    `json:"displayName"`
	SeatClass   SeatClass `json:"seatClass"`
	Roles       []RoleRef `json:"roles"`
	JoinedAt    time.Time `json:"joinedAt"`
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
