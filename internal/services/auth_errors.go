// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"fmt"
	"time"
)

// AccountLockedError is returned by login-path pre-auth checks when
// the user account is in the locked state. It carries the unlock
// timestamp + reason so the auth handler can render a discriminated
// HTTP response with a countdown to unlock — rather than the generic
// "invalid credentials" message that pre-fix masked the actual cause
// and led to users hammering the form (which extended the lockout).
//
// Wire shape consumed by the handler at internal/handlers/auth_handler.go:
//
//	{
//	  "error": "account_locked",
//	  "error_description": "...",
//	  "locked_until": "2026-05-25T15:23:00Z",
//	  "lock_reason": "too many failed login attempts",
//	  "retry_after_seconds": 1234
//	}
//
// Status code: 423 Locked (RFC 4918 §11.3) — semantically precise vs
// the generic 401 the credentials path otherwise returns. Some
// upstream tooling rejects 423 from non-WebDAV resources; in that
// case the handler may translate to 401 + the same body and clients
// dispatch on `body.error == "account_locked"`.
type AccountLockedError struct {
	LockedUntil *time.Time
	LockReason  *string
}

// Error implements the error interface. Format matches RFC 6749
// `error="account_locked"` so callers grepping log lines see the
// same identifier they'd see on the wire.
func (e *AccountLockedError) Error() string {
	if e.LockedUntil != nil {
		return fmt.Sprintf("account_locked (until %s)", e.LockedUntil.Format(time.RFC3339))
	}
	return "account_locked"
}

// RetryAfterSeconds returns the number of seconds until the lock
// expires automatically, or 0 if no LockedUntil is set (e.g.
// administratively-locked account requires admin intervention).
// Used by the handler to populate the `Retry-After` HTTP header per
// RFC 7231 §7.1.3 and the matching body field.
func (e *AccountLockedError) RetryAfterSeconds() int {
	if e.LockedUntil == nil {
		return 0
	}
	d := time.Until(*e.LockedUntil)
	if d <= 0 {
		return 0
	}
	return int(d.Seconds())
}
