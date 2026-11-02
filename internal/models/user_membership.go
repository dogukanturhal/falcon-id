// SPDX-License-Identifier: AGPL-3.0-or-later

package models

import (
	"time"

	"github.com/google/uuid"
)

// UserMembershipStatus is the lifecycle state of an iam_user_memberships row.
type UserMembershipStatus string

const (
	// UserMembershipStatusActive is a live, seat-counting (if member-class) membership.
	UserMembershipStatusActive UserMembershipStatus = "active"
	// UserMembershipStatusDeactivated frees the seat but retains the row/history.
	UserMembershipStatusDeactivated UserMembershipStatus = "deactivated"
)

// UserMembership represents a row in iam_user_memberships: the tenant<->user
// membership + seat_class ledger (the product roadmap §4.1 "Invitations and
// memberships"; the product specification §13.7). This is the
// seat-counting source of truth for tenant_seat_counters.seats_used — never
// a live COUNT(*) over iam_users.
type UserMembership struct {
	ID            uuid.UUID            `json:"id"`
	TenantID      uuid.UUID            `json:"tenantId"`
	UserID        uuid.UUID            `json:"userId"`
	SeatClass     SeatClass            `json:"seatClass"`
	Status        UserMembershipStatus `json:"status"`
	InvitationID  *uuid.UUID           `json:"invitationId,omitempty"`
	CreatedAt     time.Time            `json:"createdAt"`
	DeactivatedAt *time.Time           `json:"deactivatedAt,omitempty"`
	// AccessExpiresAt (employee seat class only): access ends at this instant; nil = no expiry set.
	AccessExpiresAt *time.Time `json:"accessExpiresAt,omitempty"`
}

// IsActiveMember reports whether this membership currently consumes a seat.
func (m *UserMembership) IsActiveMember() bool {
	return m != nil && m.Status == UserMembershipStatusActive && m.SeatClass == SeatClassMember
}

// TenantExchangeMembership is what the RFC 8693 tenant token exchange needs
// to decide whether a user may get a token for a tenant: the user's
// membership row there, the tenant's lifecycle status, and the user's role
// names scoped to that tenant only.
type TenantExchangeMembership struct {
	TenantID     uuid.UUID
	TenantSlug   string
	TenantStatus string
	SeatClass    SeatClass
	Status       UserMembershipStatus
	RoleNames    []string
}
