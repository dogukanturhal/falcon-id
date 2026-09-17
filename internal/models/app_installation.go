// SPDX-License-Identifier: AGPL-3.0-or-later

package models

import (
	"time"

	"github.com/google/uuid"
)

// AppInstallationStatus represents the lifecycle state of an app installation.
type AppInstallationStatus string

const (
	// AppInstallationStatusActive indicates the product is installed and usable by the tenant.
	AppInstallationStatusActive AppInstallationStatus = "active"
	// AppInstallationStatusSuspended indicates the installation has been temporarily disabled.
	AppInstallationStatusSuspended AppInstallationStatus = "suspended"
	// AppInstallationStatusUninstalled indicates the tenant has removed the product.
	AppInstallationStatusUninstalled AppInstallationStatus = "uninstalled"
)

// AppInstallation records a tenant's marketplace installation of a product.
// Each (tenant_id, product_id) pair is unique — a tenant can only install a
// given product once.  The status field tracks the full lifecycle from active
// through suspended to uninstalled.
type AppInstallation struct {
	ID            uuid.UUID             `json:"id" db:"id"`
	TenantID      uuid.UUID             `json:"tenant_id" db:"tenant_id"`
	ProductID     uuid.UUID             `json:"product_id" db:"product_id"`
	InstalledBy   uuid.UUID             `json:"installed_by" db:"installed_by"`
	ConsentScopes []string              `json:"consent_scopes" db:"consent_scopes"`
	Status        AppInstallationStatus `json:"status" db:"status"`
	InstalledAt   time.Time             `json:"installed_at" db:"installed_at"`
	UninstalledAt *time.Time            `json:"uninstalled_at,omitempty" db:"uninstalled_at"`
	CreatedAt     time.Time             `json:"created_at" db:"created_at"`
	UpdatedAt     time.Time             `json:"updated_at" db:"updated_at"`
}

// ==================== Status helpers ====================

// IsActive returns true when the installation is in the active state.
func (a *AppInstallation) IsActive() bool {
	return a.Status == AppInstallationStatusActive
}

// IsSuspended returns true when the installation has been suspended.
func (a *AppInstallation) IsSuspended() bool {
	return a.Status == AppInstallationStatusSuspended
}

// IsUninstalled returns true when the tenant has uninstalled the product.
func (a *AppInstallation) IsUninstalled() bool {
	return a.Status == AppInstallationStatusUninstalled
}

// ==================== Request DTOs ====================

// InstallAppRequest is the payload for installing a marketplace product into a tenant.
type InstallAppRequest struct {
	ProductID     uuid.UUID `json:"product_id" binding:"required"`
	ConsentScopes []string  `json:"consent_scopes"`
}

// UpdateAppInstallationRequest is the payload for modifying an existing installation.
// Only the status and consent scopes may be changed after installation.
type UpdateAppInstallationRequest struct {
	Status        *AppInstallationStatus `json:"status" binding:"omitempty,oneof=active suspended uninstalled"`
	ConsentScopes []string               `json:"consent_scopes"`
}

// ==================== Response DTOs ====================

// AppInstallationResponse is the API representation of an app installation.
type AppInstallationResponse struct {
	ID            uuid.UUID             `json:"id"`
	TenantID      uuid.UUID             `json:"tenant_id"`
	ProductID     uuid.UUID             `json:"product_id"`
	InstalledBy   uuid.UUID             `json:"installed_by"`
	ConsentScopes []string              `json:"consent_scopes"`
	Status        AppInstallationStatus `json:"status"`
	InstalledAt   time.Time             `json:"installed_at"`
	UninstalledAt *time.Time            `json:"uninstalled_at,omitempty"`
	CreatedAt     time.Time             `json:"created_at"`
	UpdatedAt     time.Time             `json:"updated_at"`
}

// AppInstallationListResponse is the paginated list of app installations.
type AppInstallationListResponse struct {
	Installations []AppInstallationResponse `json:"installations"`
	Total         int64                     `json:"total"`
	Page          int                       `json:"page"`
	PageSize      int                       `json:"page_size"`
	TotalPages    int                       `json:"total_pages"`
}

// ==================== Conversion methods ====================

// ToResponse converts an AppInstallation to its API response representation.
func (a *AppInstallation) ToResponse() *AppInstallationResponse {
	return &AppInstallationResponse{
		ID:            a.ID,
		TenantID:      a.TenantID,
		ProductID:     a.ProductID,
		InstalledBy:   a.InstalledBy,
		ConsentScopes: a.ConsentScopes,
		Status:        a.Status,
		InstalledAt:   a.InstalledAt,
		UninstalledAt: a.UninstalledAt,
		CreatedAt:     a.CreatedAt,
		UpdatedAt:     a.UpdatedAt,
	}
}
