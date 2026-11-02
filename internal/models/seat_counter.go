// SPDX-License-Identifier: AGPL-3.0-or-later

package models

import (
	"time"

	"github.com/google/uuid"
)

// SeatCounters is the wire/read shape of a tenant_seat_counters row
// (the product roadmap §2.1/§4.9 "Seat model live"; acmeapp-plan/specs/
// 17-module-account.md §13.2/§13.7). SeatLimit is nil while the tenant's
// seat limit has never been configured (enforcement OFF — see the 0013
// migration header for why).
type SeatCounters struct {
	TenantID     uuid.UUID `json:"tenantId"`
	SeatsUsed    int       `json:"seatsUsed"`
	SeatsPending int       `json:"seatsPending"`
	SeatLimit    *int      `json:"seatLimit,omitempty"`
	// SeatLimitVersion/SeatLimitComputedAt (0014_tenant_seat_limit_version.sql,
	// R1 "trial-aware seat caps", spec 25 §4.5): the monotonic ordering key
	// and diagnostic timestamp behind the last SeatLimit write that was
	// actually applied. Nil when seat_limit has never been set via a
	// versioned (subscription-management) PUT.
	SeatLimitVersion    *int64     `json:"seatLimitVersion,omitempty"`
	SeatLimitComputedAt *time.Time `json:"seatLimitComputedAt,omitempty"`
	UpdatedAt           time.Time  `json:"updatedAt"`
}

// SeatLimitReached reports whether a reservation attempt would need to be
// (or was) rejected: seatLimit is configured and used+pending has reached it.
// Exposed for callers that want to render the same shortfall math the 409
// response body uses.
func (c *SeatCounters) SeatLimitReached() bool {
	if c == nil || c.SeatLimit == nil {
		return false
	}
	return c.SeatsUsed+c.SeatsPending >= *c.SeatLimit
}

// SeatLimitReachedError is the 409 problem+json body for
// code: seat_limit_reached (see task spec: "409 seat_limit_reached with a
// clear error code").
type SeatLimitReachedError struct {
	Code      string `json:"code"`
	SeatLimit int    `json:"seatLimit"`
	SeatsUsed int    `json:"seatsUsed"`
	Requested int    `json:"requested"`
	Shortfall int    `json:"shortfall"`
}

// SetSeatLimitRequest is the body accepted by
// PUT /internal/v1/tenants/{id}/seat-limit.
//
// Deliberately no `binding:"required"` on SeatLimit: 0 is a legitimate,
// non-zero-value-looking business value here (block all new member invites
// for a tenant), and go-playground/validator's "required" tag rejects a
// literal 0 for a plain int since it's indistinguishable from "field
// omitted". min=0 alone still rejects negative limits.
//
// Version/ComputedAt (R1 "trial-aware seat caps", spec 25 §4.5): both
// optional, both nil for a legacy/manual operator PUT (always applied,
// same as before this change). subscription-management always sets both
// -- Version is its computed_at as Unix nanoseconds, a monotonically
// increasing per-tenant ordering key used to reject a stale, redelivered
// outbox retry that lands after a newer PUT already applied. ComputedAt
// is carried through to seat_limit_computed_at for diagnostics only; the
// stale-write compare uses Version, not this field.
type SetSeatLimitRequest struct {
	SeatLimit  int        `json:"seatLimit" binding:"min=0"`
	Version    *int64     `json:"version,omitempty"`
	ComputedAt *time.Time `json:"computedAt,omitempty"`
}
