// SPDX-License-Identifier: AGPL-3.0-or-later

package models

import (
	"time"

	"github.com/google/uuid"
)

// RecoveryMethodType enumerates the kinds of account-recovery method a user can
// register. Only "email" is wired today; "phone" is reserved (the schema + API
// accept it, but verification requires SMS delivery that isn't yet available).
type RecoveryMethodType string

const (
	RecoveryMethodEmail RecoveryMethodType = "email"
	RecoveryMethodPhone RecoveryMethodType = "phone"
)

// RecoveryMethod is a verified alternate way for a user to regain account
// access — a recovery email today, recovery phone later. Persisted in
// iam_user_recovery_methods (migration 0005). Only verified methods are stored;
// pending (unverified) values live transiently in Redis as OTP challenges.
type RecoveryMethod struct {
	ID         uuid.UUID          `json:"id" db:"id"`
	UserID     uuid.UUID          `json:"user_id" db:"user_id"`
	TenantID   uuid.UUID          `json:"tenant_id" db:"tenant_id"`
	MethodType RecoveryMethodType `json:"method_type" db:"method_type"`
	Value      string             `json:"value" db:"value"`
	Verified   bool               `json:"verified" db:"verified"`
	CreatedAt  time.Time          `json:"created_at" db:"created_at"`
	VerifiedAt *time.Time         `json:"verified_at,omitempty" db:"verified_at"`
}

// RecoveryEmailStatus is the user-facing view of their recovery email — masked
// value, verified state, and whether a verification is currently in flight.
type RecoveryEmailStatus struct {
	// Configured is true when a verified recovery email exists.
	Configured bool `json:"configured"`
	// MaskedEmail is the verified recovery email with the local part partly
	// obscured (e.g. "j•••n@example.com"). Empty when not configured.
	MaskedEmail string `json:"masked_email,omitempty"`
	// PendingEmail is the masked address awaiting verification, if any.
	PendingEmail string `json:"pending_email,omitempty"`
	// PendingExpiresAt is when the in-flight verification code expires.
	PendingExpiresAt *time.Time `json:"pending_expires_at,omitempty"`
}

// RecoveryStatus is the aggregate recovery view returned by GET
// /users/me/recovery. Phone is reported as unsupported until SMS lands.
type RecoveryStatus struct {
	Email RecoveryEmailStatus `json:"email"`
}
