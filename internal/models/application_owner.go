// SPDX-License-Identifier: AGPL-3.0-or-later

package models

import (
	"time"

	"github.com/google/uuid"
)

// ApplicationOwner represents an owner or contributor of an Application Object.
// Multiple owners allow shared management of a single application registration,
// matching the GitHub/Entra ID pattern of organization-owned repositories.
type ApplicationOwner struct {
	ID            uuid.UUID  `json:"id" db:"id"`
	ApplicationID uuid.UUID  `json:"application_id" db:"application_id"`
	OwnerID       uuid.UUID  `json:"owner_id" db:"owner_id"`
	OwnerType     string     `json:"owner_type" db:"owner_type"`
	Role          string     `json:"role" db:"role"`
	AddedBy       *uuid.UUID `json:"added_by,omitempty" db:"added_by"`
	CreatedAt     time.Time  `json:"created_at" db:"created_at"`
}

// AddOwnerRequest is the request payload to add an owner to an application.
type AddOwnerRequest struct {
	OwnerID   uuid.UUID `json:"owner_id" binding:"required"`
	OwnerType string    `json:"owner_type" binding:"required,oneof=user group service_principal"`
	Role      string    `json:"role" binding:"required,oneof=owner contributor"`
}

// ApplicationOwnerListResponse is the response envelope for listing application owners.
type ApplicationOwnerListResponse struct {
	Owners []ApplicationOwner `json:"owners"`
	Total  int                `json:"total"`
}
