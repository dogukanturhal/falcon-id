// SPDX-License-Identifier: AGPL-3.0-or-later

package models

import (
	"time"

	"github.com/google/uuid"
)

// DeviceCodeStatus tracks the authorization state of a device code pair.
type DeviceCodeStatus string

const (
	// DeviceCodeStatusPending is an exported identifier.
	DeviceCodeStatusPending DeviceCodeStatus = "pending"
	// DeviceCodeStatusAuthorized is an exported identifier.
	DeviceCodeStatusAuthorized DeviceCodeStatus = "authorized"
	// DeviceCodeStatusDenied is an exported identifier.
	DeviceCodeStatusDenied DeviceCodeStatus = "denied"
	// DeviceCodeStatusExpired is an exported identifier.
	DeviceCodeStatusExpired DeviceCodeStatus = "expired"
	// DeviceCodeStatusConsumed is an exported identifier.
	DeviceCodeStatusConsumed DeviceCodeStatus = "consumed"
)

// OAuthDeviceCode represents an RFC 8628 device authorization record.
// The device_code column stores the SHA-256 hash of the raw device code so that
// the raw value never persists in the database.
type OAuthDeviceCode struct {
	ID       uuid.UUID `json:"id" db:"id"`
	TenantID uuid.UUID `json:"tenant_id" db:"tenant_id"`
	ClientID uuid.UUID `json:"client_id" db:"client_id"`

	// Codes (device_code is hashed; user_code is plain-text XXXX-XXXX)
	DeviceCode string `json:"-" db:"device_code"`
	UserCode   string `json:"user_code" db:"user_code"`

	// Verification URIs presented to the end-user
	VerificationURI         string  `json:"verification_uri" db:"verification_uri"`
	VerificationURIComplete *string `json:"verification_uri_complete,omitempty" db:"verification_uri_complete"`

	// Requested scopes
	Scopes []string `json:"scopes" db:"scopes"`

	// Status
	Status DeviceCodeStatus `json:"status" db:"status"`

	// Set after user authorizes
	UserID       *uuid.UUID `json:"user_id,omitempty" db:"user_id"`
	AuthorizedAt *time.Time `json:"authorized_at,omitempty" db:"authorized_at"`

	// Polling (RFC 8628 §3.5)
	IntervalSeconds int        `json:"interval" db:"interval_seconds"`
	LastPolledAt    *time.Time `json:"last_polled_at,omitempty" db:"last_polled_at"`
	PollCount       int        `json:"poll_count" db:"poll_count"`

	ExpiresAt time.Time `json:"expires_at" db:"expires_at"`
	CreatedAt time.Time `json:"created_at" db:"created_at"`
}

// ==================== RFC 8628 Request / Response DTOs ====================

// DeviceAuthorizationRequest is the body sent to /oauth/device/authorize.
// Per RFC 8628 §3.1 the client sends its client_id and optionally a scope.
type DeviceAuthorizationRequest struct {
	ClientID string `form:"client_id" binding:"required"`
	Scope    string `form:"scope"`
}

// DeviceAuthorizationResponse is the JSON body returned per RFC 8628 §3.2.
type DeviceAuthorizationResponse struct {
	// DeviceCode is sent to the device for polling; never shown to the user.
	DeviceCode string `json:"device_code"`

	// UserCode is displayed to the user for manual entry at the verification URI.
	UserCode string `json:"user_code"`

	// VerificationURI is where the user should authenticate.
	VerificationURI string `json:"verification_uri"`

	// VerificationURIComplete pre-fills the user code in the URI (optional).
	VerificationURIComplete string `json:"verification_uri_complete,omitempty"`

	// ExpiresIn is the lifetime of the device_code in seconds.
	ExpiresIn int64 `json:"expires_in"`

	// Interval is the minimum polling interval in seconds.
	Interval int `json:"interval"`
}

// DeviceTokenPollRequest is the body the device sends to /oauth/token while polling.
// GrantType must be "urn:ietf:params:oauth:grant-type:device_code".
type DeviceTokenPollRequest struct {
	GrantType  string `form:"grant_type" binding:"required"`
	DeviceCode string `form:"device_code" binding:"required"`
	ClientID   string `form:"client_id" binding:"required"`
}

// IsExpired reports whether the device code window has closed.
func (d *OAuthDeviceCode) IsExpired() bool {
	return time.Now().After(d.ExpiresAt)
}

// IsPending reports whether the device code is awaiting user authorization.
func (d *OAuthDeviceCode) IsPending() bool {
	return d.Status == DeviceCodeStatusPending
}

// IsAuthorized reports whether the user has approved the device.
func (d *OAuthDeviceCode) IsAuthorized() bool {
	return d.Status == DeviceCodeStatusAuthorized
}
