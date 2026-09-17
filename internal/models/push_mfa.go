// SPDX-License-Identifier: AGPL-3.0-or-later

package models

import (
	"time"

	"github.com/google/uuid"
)

// PushMFAChallengeStatus represents the lifecycle state of a push challenge.
type PushMFAChallengeStatus string

const (
	// PushChallengeStatusPending is an exported identifier.
	PushChallengeStatusPending PushMFAChallengeStatus = "pending"
	// PushChallengeStatusApproved is an exported identifier.
	PushChallengeStatusApproved PushMFAChallengeStatus = "approved"
	// PushChallengeStatusDenied is an exported identifier.
	PushChallengeStatusDenied PushMFAChallengeStatus = "denied"
	// PushChallengeStatusExpired is an exported identifier.
	PushChallengeStatusExpired PushMFAChallengeStatus = "expired"
)

// PushMFADevice represents a registered authenticator device capable of
// receiving push MFA challenges.
type PushMFADevice struct {
	ID                 uuid.UUID  `json:"id" db:"id"`
	UserID             uuid.UUID  `json:"user_id" db:"user_id"`
	DeviceName         string     `json:"device_name" db:"device_name"`
	Platform           string     `json:"platform" db:"platform"` // "ios" or "android"
	PushTokenEncrypted string     `json:"-" db:"push_token_encrypted"`
	PublicKey          string     `json:"public_key,omitempty" db:"public_key"`
	RegisteredAt       time.Time  `json:"registered_at" db:"registered_at"`
	LastUsedAt         *time.Time `json:"last_used_at,omitempty" db:"last_used_at"`
}

// PushMFAChallenge represents a pending (or resolved) push notification
// challenge issued during an authentication attempt.
type PushMFAChallenge struct {
	ID          uuid.UUID              `json:"id" db:"id"`
	UserID      uuid.UUID              `json:"user_id" db:"user_id"`
	TenantID    uuid.UUID              `json:"tenant_id" db:"tenant_id"`
	DeviceID    *uuid.UUID             `json:"device_id,omitempty" db:"device_id"`
	Status      PushMFAChallengeStatus `json:"status" db:"status"`
	IPAddress   string                 `json:"ip_address,omitempty" db:"ip_address"`
	UserAgent   string                 `json:"user_agent,omitempty" db:"user_agent"`
	GeoLocation string                 `json:"geo_location,omitempty" db:"geo_location"`
	ExpiresAt   time.Time              `json:"expires_at" db:"expires_at"`
	CreatedAt   time.Time              `json:"created_at" db:"created_at"`
	RespondedAt *time.Time             `json:"responded_at,omitempty" db:"responded_at"`
}

// RegisterDeviceRequest is the API request body for device registration.
type RegisterDeviceRequest struct {
	DeviceName string `json:"device_name" binding:"required,min=1,max=100"`
	Platform   string `json:"platform" binding:"required,oneof=ios android"`
	PushToken  string `json:"push_token" binding:"required,min=1,max=4096"`
	PublicKey  string `json:"public_key" binding:"omitempty,max=8192"`
}

// RegisterDeviceResponse is the API response returned after device registration.
type RegisterDeviceResponse struct {
	DeviceID     uuid.UUID `json:"device_id"`
	DeviceName   string    `json:"device_name"`
	Platform     string    `json:"platform"`
	RegisteredAt time.Time `json:"registered_at"`
}

// PushDeviceListResponse is the API response for listing registered push-MFA devices.
type PushDeviceListResponse struct {
	Devices []PushDeviceResponse `json:"devices"`
	Total   int                  `json:"total"`
}

// PushDeviceResponse is a single push-MFA device entry in a list response.
type PushDeviceResponse struct {
	ID           uuid.UUID  `json:"id"`
	DeviceName   string     `json:"device_name"`
	Platform     string     `json:"platform"`
	RegisteredAt time.Time  `json:"registered_at"`
	LastUsedAt   *time.Time `json:"last_used_at,omitempty"`
}

// InitiatePushChallengeRequest is the API request body for starting a push
// challenge from the login flow.
type InitiatePushChallengeRequest struct {
	UserID    string `json:"user_id" binding:"required,min=1,max=36"`
	TenantID  string `json:"tenant_id" binding:"required,min=1,max=36"`
	SessionID string `json:"session_id" binding:"omitempty,max=255"`
}

// PushChallengeResponse is returned when a push challenge has been created.
type PushChallengeResponse struct {
	ChallengeID uuid.UUID `json:"challenge_id"`
	ExpiresAt   time.Time `json:"expires_at"`
	Message     string    `json:"message"`
}

// RespondToChallengeRequest is the request body sent by the mobile app to
// approve or deny a push challenge.
type RespondToChallengeRequest struct {
	ChallengeID string `json:"challenge_id" binding:"required,min=1,max=36"`
	Approved    bool   `json:"approved"`
	Signature   string `json:"signature" binding:"omitempty,max=4096"` // optional end-to-end proof
}

// ChallengeStatusResponse is returned when polling the challenge status.
type ChallengeStatusResponse struct {
	ChallengeID uuid.UUID              `json:"challenge_id"`
	Status      PushMFAChallengeStatus `json:"status"`
	ExpiresAt   time.Time              `json:"expires_at"`
	RespondedAt *time.Time             `json:"responded_at,omitempty"`
}
