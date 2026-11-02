// SPDX-License-Identifier: AGPL-3.0-or-later

package models

import (
	"encoding/json"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func TestTenantUserWithRoles_UnknownPrincipalDoesNotImplyServiceAccount(t *testing.T) {
	grantID := uuid.New()
	user := TenantUserWithRoles{
		Email:           "automation@example.test",
		PrincipalType:   "unknown",
		PrincipalSource: "unknown",
		Roles: []RoleRef{{
			ID:       grantID,
			Name:     "legacy-grant",
			Editable: false,
			Reason:   "grant source is not managed by this tenant",
			Source:   RoleSourceUnknown,
		}},
	}

	body, err := json.Marshal(user)
	assert.NoError(t, err)
	assert.Contains(t, string(body), `"principalType":"unknown"`)
	assert.Contains(t, string(body), `"principalSource":"unknown"`)
	assert.Contains(t, string(body), `"source":"unknown"`)
}

func TestCanonicalInvitationEmail(t *testing.T) {
	assert.Equal(t, "member@example.test", CanonicalInvitationEmail("  Member@Example.Test  "))
	assert.Empty(t, CanonicalInvitationEmail(" \t\n "))
}

func TestTeamInvitationTokenDigest(t *testing.T) {
	digest := TeamInvitationTokenDigest("secret")
	assert.Equal(t, "sha256:2bb80d537b1da3e38bd30361aa855686bde0eacd7162fef6a25fe97bf527a25b", digest)
	assert.NotContains(t, digest, "secret")
}

// TestConsumesSeat pins the product roadmap §2.1/§3.2's locked seat_class
// rule: only "member" consumes a tenant seat. "external" (accountant/guest
// -- mali müşavir seats are free) and "service" never do. Every seat-limit
// call site in team_invitation_handler.go gates ReserveSeat/ConfirmSeat/
// ReleaseReservation on this method, so a regression here would silently
// start charging (or stop charging) the wrong seat class against
// seat_limit.
func TestConsumesSeat(t *testing.T) {
	tests := []struct {
		name      string
		seatClass SeatClass
		want      bool
	}{
		{"member consumes a seat", SeatClassMember, true},
		{"external (accountant/guest) never consumes a seat", SeatClassExternal, false},
		{"service never consumes a seat", SeatClassService, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			inv := &TeamInvitation{SeatClass: tt.seatClass}
			assert.Equal(t, tt.want, inv.ConsumesSeat())
		})
	}
}

// TestSeatClassEmployee_NeverConsumesSeat: the employee class (R-HR WP-21) is valid but never billable.
func TestSeatClassEmployee_NeverConsumesSeat(t *testing.T) {
	assert.True(t, IsValidSeatClass(SeatClassEmployee))
	assert.True(t, IsValidSeatClass(SeatClassKiosk))
	inv := &TeamInvitation{SeatClass: SeatClassEmployee}
	assert.False(t, inv.ConsumesSeat())
}
