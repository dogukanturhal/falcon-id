// SPDX-License-Identifier: AGPL-3.0-or-later

package models

import (
	"time"

	"github.com/google/uuid"
)

// ImpersonationSession represents an admin impersonating another user
type ImpersonationSession struct {
	ID                     uuid.UUID  `json:"id"`
	TenantID               uuid.UUID  `json:"tenant_id"`
	AdminUserID            uuid.UUID  `json:"admin_user_id"`
	TargetUserID           uuid.UUID  `json:"target_user_id"`
	Reason                 string     `json:"reason"`
	IPAddress              *string    `json:"ip_address,omitempty"`
	UserAgent              *string    `json:"user_agent,omitempty"`
	StartedAt              time.Time  `json:"started_at"`
	EndedAt                *time.Time `json:"ended_at,omitempty"`
	OriginalSessionID      *uuid.UUID `json:"original_session_id,omitempty"`
	ImpersonationSessionID *uuid.UUID `json:"impersonation_session_id,omitempty"`
	CreatedAt              time.Time  `json:"created_at"`

	// Populated fields
	AdminUser  *User `json:"admin_user,omitempty"`
	TargetUser *User `json:"target_user,omitempty"`
}

// IsActive returns true if the impersonation session is still active
func (s *ImpersonationSession) IsActive() bool {
	return s.EndedAt == nil
}

// StartImpersonationRequest represents a request to start impersonation
type StartImpersonationRequest struct {
	Reason string `json:"reason" binding:"required,min=10"`
}

// ImpersonationResponse is returned when starting impersonation
// ImpersonationResponse deliberately has NO refresh token: an impersonation
// credential is a single non-refreshable access token (<= 15 min, act claim);
// to continue, the operator ends the session and starts a new one.
type ImpersonationResponse struct {
	ImpersonationSessionID string `json:"impersonation_session_id"`
	AccessToken            string `json:"access_token"`
	ExpiresIn              int    `json:"expires_in"`
	TokenType              string `json:"token_type"`
	TargetUser             *User  `json:"target_user"`
	Message                string `json:"message"`
}

// ImpersonationSessionListResponse for listing impersonation sessions
type ImpersonationSessionListResponse struct {
	Sessions   []*ImpersonationSession `json:"sessions"`
	Total      int                     `json:"total"`
	Page       int                     `json:"page"`
	PageSize   int                     `json:"page_size"`
	TotalPages int                     `json:"total_pages"`
}

// ImpersonationStatus indicates if the current session is impersonated
type ImpersonationStatus struct {
	IsImpersonating        bool       `json:"is_impersonating"`
	ImpersonationSessionID *string    `json:"impersonation_session_id,omitempty"`
	AdminUserID            *string    `json:"admin_user_id,omitempty"`
	AdminUsername          *string    `json:"admin_username,omitempty"`
	AdminEmail             *string    `json:"admin_email,omitempty"`
	TargetUserID           *string    `json:"target_user_id,omitempty"`
	TargetUsername         *string    `json:"target_username,omitempty"`
	StartedAt              *time.Time `json:"started_at,omitempty"`
	Reason                 *string    `json:"reason,omitempty"`
}
