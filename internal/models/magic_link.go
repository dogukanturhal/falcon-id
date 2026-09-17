// SPDX-License-Identifier: AGPL-3.0-or-later

package models

import (
	"time"

	"github.com/google/uuid"
)

// MagicLink represents a magic link token for passwordless authentication
type MagicLink struct {
	ID        uuid.UUID  `json:"id" db:"id"`
	UserID    *uuid.UUID `json:"user_id,omitempty" db:"user_id"`
	Email     string     `json:"email" db:"email"`
	TokenHash string     `json:"-" db:"token_hash"`
	IPAddress *string    `json:"ip_address,omitempty" db:"ip_address"`
	UserAgent *string    `json:"user_agent,omitempty" db:"user_agent"`
	UsedAt    *time.Time `json:"used_at,omitempty" db:"used_at"`
	ExpiresAt time.Time  `json:"expires_at" db:"expires_at"`
	CreatedAt time.Time  `json:"created_at" db:"created_at"`
}

// MagicLinkRequest is the request to send a magic link
type MagicLinkRequest struct {
	Email string `json:"email" binding:"required,email"`
}

// MagicLinkVerifyRequest is the request to verify a magic link
type MagicLinkVerifyRequest struct {
	Token string `json:"token" binding:"required"`
}

// IsExpired checks if the magic link has expired
func (m *MagicLink) IsExpired() bool {
	return time.Now().After(m.ExpiresAt)
}

// IsUsed checks if the magic link has been used
func (m *MagicLink) IsUsed() bool {
	return m.UsedAt != nil
}

// IsValid checks if the magic link is valid (not expired and not used)
func (m *MagicLink) IsValid() bool {
	return !m.IsExpired() && !m.IsUsed()
}
