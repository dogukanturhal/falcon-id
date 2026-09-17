// SPDX-License-Identifier: AGPL-3.0-or-later

package models

import (
	"time"

	"github.com/google/uuid"
)

// InvitationType represents the type of invitation
type InvitationType string

const (
	// InvitationTypeTenantAdmin is an exported identifier.
	InvitationTypeTenantAdmin InvitationType = "tenant_admin"
	// InvitationTypeUserInvite is an exported identifier.
	InvitationTypeUserInvite InvitationType = "user_invite"
	// InvitationTypePasswordSetup is an exported identifier.
	InvitationTypePasswordSetup InvitationType = "password_setup"
)

// InvitationStatus represents the status of an invitation
type InvitationStatus string

const (
	// InvitationStatusPending is an exported identifier.
	InvitationStatusPending InvitationStatus = "pending"
	// InvitationStatusAccepted is an exported identifier.
	InvitationStatusAccepted InvitationStatus = "accepted"
	// InvitationStatusExpired is an exported identifier.
	InvitationStatusExpired InvitationStatus = "expired"
	// InvitationStatusRevoked is an exported identifier.
	InvitationStatusRevoked InvitationStatus = "revoked"
)

// UserActivationStatus represents the activation status of a user
type UserActivationStatus string

const (
	// UserActivationPendingInvitation is an exported identifier.
	UserActivationPendingInvitation UserActivationStatus = "pending_invitation"
	// UserActivationPendingActivation is an exported identifier.
	UserActivationPendingActivation UserActivationStatus = "pending_activation"
	// UserActivationActive is an exported identifier.
	UserActivationActive UserActivationStatus = "active"
	// UserActivationSuspended is an exported identifier.
	UserActivationSuspended UserActivationStatus = "suspended"
	// UserActivationDeactivated is an exported identifier.
	UserActivationDeactivated UserActivationStatus = "deactivated"
)

// UserInvitation represents an invitation for user account setup
type UserInvitation struct {
	ID               uuid.UUID        `json:"id" db:"id"`
	UserID           uuid.UUID        `json:"user_id" db:"user_id"`
	TenantID         uuid.UUID        `json:"tenant_id" db:"tenant_id"`
	RealmID          *uuid.UUID       `json:"realm_id,omitempty" db:"realm_id"`
	TokenHash        string           `json:"-" db:"token_hash"`
	InvitationType   InvitationType   `json:"invitation_type" db:"invitation_type"`
	InvitedByAdminID *uuid.UUID       `json:"invited_by_admin_id,omitempty" db:"invited_by_admin_id"`
	InvitedByUserID  *uuid.UUID       `json:"invited_by_user_id,omitempty" db:"invited_by_user_id"`
	Email            string           `json:"email" db:"email"`
	EmailSentAt      *time.Time       `json:"email_sent_at,omitempty" db:"email_sent_at"`
	EmailSendCount   int              `json:"email_send_count" db:"email_send_count"`
	LastEmailSentAt  *time.Time       `json:"last_email_sent_at,omitempty" db:"last_email_sent_at"`
	Status           InvitationStatus `json:"status" db:"status"`
	AcceptedAt       *time.Time       `json:"accepted_at,omitempty" db:"accepted_at"`
	AcceptedIP       *string          `json:"accepted_ip,omitempty" db:"accepted_ip"`
	ExpiresAt        time.Time        `json:"expires_at" db:"expires_at"`
	CustomMessage    *string          `json:"custom_message,omitempty" db:"custom_message"`
	CreatedAt        time.Time        `json:"created_at" db:"created_at"`
	UpdatedAt        time.Time        `json:"updated_at" db:"updated_at"`
}

// CreateInvitationRequest is the request to create an invitation
type CreateInvitationRequest struct {
	UserID           uuid.UUID      `json:"user_id" binding:"required"`
	TenantID         uuid.UUID      `json:"tenant_id" binding:"required"`
	RealmID          *uuid.UUID     `json:"realm_id,omitempty"`
	InvitationType   InvitationType `json:"invitation_type" binding:"required"`
	InvitedByAdminID *uuid.UUID     `json:"invited_by_admin_id,omitempty"`
	InvitedByUserID  *uuid.UUID     `json:"invited_by_user_id,omitempty"`
	Email            string         `json:"email" binding:"required,email"`
	ExpiryHours      int            `json:"expiry_hours,omitempty"` // Default: 72
	CustomMessage    string         `json:"custom_message,omitempty"`
	SendEmail        bool           `json:"send_email"` // Default: true
}

// SetupAccountRequest is the request to complete account setup via invitation
type SetupAccountRequest struct {
	Token           string `json:"token" binding:"required"`
	Password        string `json:"password" binding:"required,min=8"`
	ConfirmPassword string `json:"confirm_password" binding:"required,eqfield=Password"`
}

// ValidateInvitationRequest is the request to validate an invitation token
type ValidateInvitationRequest struct {
	Token string `json:"token" binding:"required"`
}

// ValidateInvitationResponse is the response for invitation validation
type ValidateInvitationResponse struct {
	Valid          bool           `json:"valid"`
	Email          string         `json:"email,omitempty"`
	TenantName     string         `json:"tenant_name,omitempty"`
	InvitationType InvitationType `json:"invitation_type,omitempty"`
	ExpiresAt      *time.Time     `json:"expires_at,omitempty"`
	Error          string         `json:"error,omitempty"`
}

// ResendInvitationRequest is the request to resend an invitation
type ResendInvitationRequest struct {
	UserID        uuid.UUID `json:"user_id" binding:"required"`
	Force         bool      `json:"force,omitempty"`          // Create new token even if old one hasn't expired
	CustomMessage string    `json:"custom_message,omitempty"` // Optional new message
}

// InvitationResponse is the response containing invitation details
type InvitationResponse struct {
	ID             uuid.UUID        `json:"id"`
	UserID         uuid.UUID        `json:"user_id"`
	Email          string           `json:"email"`
	InvitationType InvitationType   `json:"invitation_type"`
	Status         InvitationStatus `json:"status"`
	EmailSent      bool             `json:"email_sent"`
	EmailSendCount int              `json:"email_send_count"`
	ExpiresAt      time.Time        `json:"expires_at"`
	CreatedAt      time.Time        `json:"created_at"`
}

// IsExpired checks if the invitation has expired
func (i *UserInvitation) IsExpired() bool {
	return time.Now().After(i.ExpiresAt)
}

// IsAccepted checks if the invitation has been accepted
func (i *UserInvitation) IsAccepted() bool {
	return i.Status == InvitationStatusAccepted
}

// IsRevoked checks if the invitation has been revoked
func (i *UserInvitation) IsRevoked() bool {
	return i.Status == InvitationStatusRevoked
}

// IsPending checks if the invitation is still pending
func (i *UserInvitation) IsPending() bool {
	return i.Status == InvitationStatusPending
}

// IsValid checks if the invitation is valid (pending and not expired)
func (i *UserInvitation) IsValid() bool {
	return i.IsPending() && !i.IsExpired()
}

// CanResendEmail checks if invitation email can be resent
// Limited to 3 emails per day
func (i *UserInvitation) CanResendEmail() bool {
	if i.EmailSendCount >= 5 {
		return false
	}
	if i.LastEmailSentAt != nil {
		// Allow resend after 5 minutes
		return time.Since(*i.LastEmailSentAt) > 5*time.Minute
	}
	return true
}

// ToResponse converts UserInvitation to InvitationResponse
func (i *UserInvitation) ToResponse() *InvitationResponse {
	return &InvitationResponse{
		ID:             i.ID,
		UserID:         i.UserID,
		Email:          i.Email,
		InvitationType: i.InvitationType,
		Status:         i.Status,
		EmailSent:      i.EmailSentAt != nil,
		EmailSendCount: i.EmailSendCount,
		ExpiresAt:      i.ExpiresAt,
		CreatedAt:      i.CreatedAt,
	}
}
