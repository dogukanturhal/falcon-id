// SPDX-License-Identifier: AGPL-3.0-or-later

package models

import (
	"time"

	"github.com/google/uuid"
)

// SPSignInActivity records a service principal authentication event.
type SPSignInActivity struct {
	ID             uuid.UUID  `json:"id" db:"id"`
	SPID           uuid.UUID  `json:"sp_id" db:"sp_id"`
	ApplicationID  *uuid.UUID `json:"application_id,omitempty" db:"application_id"`
	TenantID       *uuid.UUID `json:"tenant_id,omitempty" db:"tenant_id"`
	IPAddress      *string    `json:"ip_address,omitempty" db:"ip_address"`
	UserAgent      *string    `json:"user_agent,omitempty" db:"user_agent"`
	CredentialID   *uuid.UUID `json:"credential_id,omitempty" db:"credential_id"`
	CredentialType *string    `json:"credential_type,omitempty" db:"credential_type"`
	Success        bool       `json:"success" db:"success"`
	ErrorCode      *string    `json:"error_code,omitempty" db:"error_code"`
	SignedInAt     time.Time  `json:"signed_in_at" db:"signed_in_at"`
}

// SPSignInActivityListResponse is the paginated list response for sign-in activity.
type SPSignInActivityListResponse struct {
	Activities []SPSignInActivity `json:"activities"`
	Total      int                `json:"total"`
}
