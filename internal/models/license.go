// SPDX-License-Identifier: AGPL-3.0-or-later

package models

import (
	"strings"
	"time"

	"github.com/google/uuid"
)

// LicenseType represents the commercial tier of a license.
type LicenseType string

const (
	// LicenseTypeTrial is a time-limited evaluation license.
	LicenseTypeTrial LicenseType = "trial"
	// LicenseTypeStandard is a base commercial license.
	LicenseTypeStandard LicenseType = "standard"
	// LicenseTypeProfessional is a mid-tier commercial license with additional features.
	LicenseTypeProfessional LicenseType = "professional"
	// LicenseTypeEnterprise is a full-featured commercial license for large organisations.
	LicenseTypeEnterprise LicenseType = "enterprise"
)

// LicenseStatus represents the operational state of a license.
type LicenseStatus string

const (
	// LicenseStatusActive indicates the license is valid and usable.
	LicenseStatusActive LicenseStatus = "active"
	// LicenseStatusSuspended indicates the license has been temporarily disabled.
	LicenseStatusSuspended LicenseStatus = "suspended"
	// LicenseStatusExpired indicates the license has passed its expiry date.
	LicenseStatusExpired LicenseStatus = "expired"
	// LicenseStatusRevoked indicates the license has been permanently cancelled.
	LicenseStatusRevoked LicenseStatus = "revoked"
)

// LicenseActivationStatus represents the state of an individual machine activation.
type LicenseActivationStatus string

const (
	// LicenseActivationStatusActive indicates the activation is current and valid.
	LicenseActivationStatusActive LicenseActivationStatus = "active"
	// LicenseActivationStatusDeactivated indicates the activation has been released.
	LicenseActivationStatusDeactivated LicenseActivationStatus = "deactivated"
)

// License represents a license grant issued to a tenant for a specific product.
type License struct {
	ID          uuid.UUID              `json:"id" db:"id"`
	ProductID   uuid.UUID              `json:"product_id" db:"product_id"`
	TenantID    uuid.UUID              `json:"tenant_id" db:"tenant_id"`
	LicenseKey  string                 `json:"license_key" db:"license_key"`
	Type        LicenseType            `json:"type" db:"type"`
	Status      LicenseStatus          `json:"status" db:"status"`
	MaxSeats    int                    `json:"max_seats" db:"max_seats"`
	UsedSeats   int                    `json:"used_seats" db:"used_seats"`
	Features    map[string]interface{} `json:"features,omitempty" db:"features"`
	Metadata    map[string]interface{} `json:"metadata,omitempty" db:"metadata"`
	IssuedAt    time.Time              `json:"issued_at" db:"issued_at"`
	ExpiresAt   *time.Time             `json:"expires_at,omitempty" db:"expires_at"`
	SuspendedAt *time.Time             `json:"suspended_at,omitempty" db:"suspended_at"`
	RevokedAt   *time.Time             `json:"revoked_at,omitempty" db:"revoked_at"`
	RevokedBy   *uuid.UUID             `json:"revoked_by,omitempty" db:"revoked_by"`
	CreatedBy   *uuid.UUID             `json:"created_by,omitempty" db:"created_by"`
	CreatedAt   time.Time              `json:"created_at" db:"created_at"`
	UpdatedAt   time.Time              `json:"updated_at" db:"updated_at"`
}

// LicenseActivation represents a per-machine activation of a licensed product.
// Licensed products phone home to validate activations against this record.
type LicenseActivation struct {
	ID              uuid.UUID               `json:"id" db:"id"`
	LicenseID       uuid.UUID               `json:"license_id" db:"license_id"`
	MachineID       string                  `json:"machine_id" db:"machine_id"`
	DeviceName      *string                 `json:"device_name,omitempty" db:"device_name"`
	IPAddress       *string                 `json:"ip_address,omitempty" db:"ip_address"`
	UserAgent       *string                 `json:"user_agent,omitempty" db:"user_agent"`
	ActivatedAt     time.Time               `json:"activated_at" db:"activated_at"`
	LastValidatedAt time.Time               `json:"last_validated_at" db:"last_validated_at"`
	DeactivatedAt   *time.Time              `json:"deactivated_at,omitempty" db:"deactivated_at"`
	Status          LicenseActivationStatus `json:"status" db:"status"`
}

// ==================== Status helper methods ====================

// IsActive returns true when the license is in the active state.
func (l *License) IsActive() bool {
	return l.Status == LicenseStatusActive
}

// IsSuspended returns true when the license has been temporarily suspended.
func (l *License) IsSuspended() bool {
	return l.Status == LicenseStatusSuspended
}

// IsExpired returns true when the license has passed its expiry date or is
// explicitly marked as expired.
func (l *License) IsExpired() bool {
	if l.Status == LicenseStatusExpired {
		return true
	}
	if l.ExpiresAt != nil && time.Now().After(*l.ExpiresAt) {
		return true
	}
	return false
}

// IsRevoked returns true when the license has been permanently cancelled.
func (l *License) IsRevoked() bool {
	return l.Status == LicenseStatusRevoked
}

// HasAvailableSeats returns true when there is at least one seat that can still
// be activated.
func (l *License) HasAvailableSeats() bool {
	return l.UsedSeats < l.MaxSeats
}

// ==================== Request DTOs ====================

// CreateLicenseRequest is the payload for issuing a new license to a tenant.
// The license key is generated server-side and should not be supplied by the client.
type CreateLicenseRequest struct {
	ProductID uuid.UUID              `json:"product_id" binding:"required"`
	TenantID  uuid.UUID              `json:"tenant_id" binding:"required"`
	Type      LicenseType            `json:"type" binding:"required,oneof=trial standard professional enterprise"`
	MaxSeats  int                    `json:"max_seats" binding:"required,min=1"`
	Features  map[string]interface{} `json:"features"`
	Metadata  map[string]interface{} `json:"metadata"`
	IssuedAt  *time.Time             `json:"issued_at"`
	ExpiresAt *time.Time             `json:"expires_at"`
}

// UpdateLicenseRequest is the payload for modifying an existing license.
// All fields are optional to allow partial updates.
type UpdateLicenseRequest struct {
	Type      *LicenseType           `json:"type" binding:"omitempty,oneof=trial standard professional enterprise"`
	Status    *LicenseStatus         `json:"status" binding:"omitempty,oneof=active suspended expired revoked"`
	MaxSeats  *int                   `json:"max_seats" binding:"omitempty,min=1"`
	Features  map[string]interface{} `json:"features"`
	Metadata  map[string]interface{} `json:"metadata"`
	ExpiresAt *time.Time             `json:"expires_at"`
}

// ActivateLicenseRequest is the payload sent by a licensed product when
// registering a new machine activation (phone-home).
type ActivateLicenseRequest struct {
	LicenseKey string  `json:"license_key" binding:"required"`
	MachineID  string  `json:"machine_id" binding:"required,min=1,max=255"`
	DeviceName *string `json:"device_name" binding:"omitempty,max=255"`
}

// LicenseValidationRequest is the payload sent by a licensed product to verify
// that an existing activation is still valid.
type LicenseValidationRequest struct {
	LicenseKey  string `json:"license_key" binding:"required"`
	MachineID   string `json:"machine_id" binding:"required"`
	ProductSlug string `json:"product_slug" binding:"required"`
}

// ==================== Response DTOs ====================

// LicenseResponse is the API representation of a license (safe for external use).
type LicenseResponse struct {
	ID          uuid.UUID              `json:"id"`
	ProductID   uuid.UUID              `json:"product_id"`
	TenantID    uuid.UUID              `json:"tenant_id"`
	LicenseKey  string                 `json:"license_key"`
	Type        LicenseType            `json:"type"`
	Status      LicenseStatus          `json:"status"`
	MaxSeats    int                    `json:"max_seats"`
	UsedSeats   int                    `json:"used_seats"`
	Features    map[string]interface{} `json:"features,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
	IssuedAt    time.Time              `json:"issued_at"`
	ExpiresAt   *time.Time             `json:"expires_at,omitempty"`
	SuspendedAt *time.Time             `json:"suspended_at,omitempty"`
	RevokedAt   *time.Time             `json:"revoked_at,omitempty"`
	RevokedBy   *uuid.UUID             `json:"revoked_by,omitempty"`
	CreatedBy   *uuid.UUID             `json:"created_by,omitempty"`
	CreatedAt   time.Time              `json:"created_at"`
	UpdatedAt   time.Time              `json:"updated_at"`
}

// LicenseListResponse is the paginated list of licenses.
type LicenseListResponse struct {
	Licenses   []LicenseResponse `json:"licenses"`
	Total      int64             `json:"total"`
	Page       int               `json:"page"`
	PageSize   int               `json:"page_size"`
	TotalPages int               `json:"total_pages"`
}

// LicenseActivationResponse is the API representation of a machine activation.
type LicenseActivationResponse struct {
	ID              uuid.UUID               `json:"id"`
	LicenseID       uuid.UUID               `json:"license_id"`
	MachineID       string                  `json:"machine_id"`
	DeviceName      *string                 `json:"device_name,omitempty"`
	IPAddress       *string                 `json:"ip_address,omitempty"`
	ActivatedAt     time.Time               `json:"activated_at"`
	LastValidatedAt time.Time               `json:"last_validated_at"`
	DeactivatedAt   *time.Time              `json:"deactivated_at,omitempty"`
	Status          LicenseActivationStatus `json:"status"`
}

// LicenseValidationResponse is the reply sent to a licensed product after a
// phone-home validation check.
type LicenseValidationResponse struct {
	// Valid indicates whether the license + machine combination is currently authorised.
	Valid bool `json:"valid"`
	// Tier is the license type (trial, standard, professional, enterprise).
	Tier LicenseType `json:"tier"`
	// Features is the feature-flag map encoded in the license.
	Features map[string]interface{} `json:"features,omitempty"`
	// ExpiresAt is the license expiry time, nil for perpetual licenses.
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	// OfflineGracePeriodSeconds is the number of seconds the product may operate
	// without a successful validation before locking out the user.
	OfflineGracePeriodSeconds int `json:"offline_grace_period_seconds"`
}

// ==================== Conversion methods ====================

// MaskLicenseKey returns a masked version of the license key, showing only
// the prefix and last 4 characters. e.g. "HEXX-****-****-****-1A2B"
func MaskLicenseKey(key string) string {
	parts := strings.Split(key, "-")
	if len(parts) < 2 {
		return "****"
	}
	// Keep the first part (HEXX) and last part, mask the rest.
	masked := make([]string, len(parts))
	masked[0] = parts[0]
	for i := 1; i < len(parts)-1; i++ {
		masked[i] = "****"
	}
	masked[len(parts)-1] = parts[len(parts)-1]
	return strings.Join(masked, "-")
}

// ToResponse converts a License to its API response representation.
// License keys are masked to prevent credential exposure in list/get responses.
func (l *License) ToResponse() *LicenseResponse {
	return &LicenseResponse{
		ID:          l.ID,
		ProductID:   l.ProductID,
		TenantID:    l.TenantID,
		LicenseKey:  MaskLicenseKey(l.LicenseKey),
		Type:        l.Type,
		Status:      l.Status,
		MaxSeats:    l.MaxSeats,
		UsedSeats:   l.UsedSeats,
		Features:    l.Features,
		Metadata:    l.Metadata,
		IssuedAt:    l.IssuedAt,
		ExpiresAt:   l.ExpiresAt,
		SuspendedAt: l.SuspendedAt,
		RevokedAt:   l.RevokedAt,
		RevokedBy:   l.RevokedBy,
		CreatedBy:   l.CreatedBy,
		CreatedAt:   l.CreatedAt,
		UpdatedAt:   l.UpdatedAt,
	}
}

// ToResponseWithKey converts a License to its API response with the full unmasked key.
// Only use this at creation time when the key needs to be shown to the admin.
func (l *License) ToResponseWithKey() *LicenseResponse {
	resp := l.ToResponse()
	resp.LicenseKey = l.LicenseKey
	return resp
}

// ToResponse converts a LicenseActivation to its API response representation.
func (a *LicenseActivation) ToResponse() *LicenseActivationResponse {
	return &LicenseActivationResponse{
		ID:              a.ID,
		LicenseID:       a.LicenseID,
		MachineID:       a.MachineID,
		DeviceName:      a.DeviceName,
		IPAddress:       a.IPAddress,
		ActivatedAt:     a.ActivatedAt,
		LastValidatedAt: a.LastValidatedAt,
		DeactivatedAt:   a.DeactivatedAt,
		Status:          a.Status,
	}
}
