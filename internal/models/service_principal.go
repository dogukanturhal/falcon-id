// SPDX-License-Identifier: AGPL-3.0-or-later

package models

import (
	"time"

	"github.com/google/uuid"
)

// ServicePrincipalType represents the type of a service principal.
type ServicePrincipalType string

const (
	// SPTypeApplication is an exported identifier.
	SPTypeApplication ServicePrincipalType = "application"
	// SPTypeManagedIdentity is an exported identifier.
	SPTypeManagedIdentity ServicePrincipalType = "managed_identity"
	// SPTypeLegacy is an exported identifier.
	SPTypeLegacy ServicePrincipalType = "legacy"
)

// ServicePrincipalInstallStatus represents the Atlassian-inspired installation lifecycle.
type ServicePrincipalInstallStatus string

const (
	// SPInstallStatusInstalled is an exported identifier.
	SPInstallStatusInstalled ServicePrincipalInstallStatus = "installed"
	// SPInstallStatusEnabled is an exported identifier.
	SPInstallStatusEnabled ServicePrincipalInstallStatus = "enabled"
	// SPInstallStatusDisabled is an exported identifier.
	SPInstallStatusDisabled ServicePrincipalInstallStatus = "disabled"
	// SPInstallStatusUninstalled is an exported identifier.
	SPInstallStatusUninstalled ServicePrincipalInstallStatus = "uninstalled"
)

// ServicePrincipal represents a service identity for microservice-to-microservice authentication.
// Evolved with Entra ID Application Object / Service Principal pattern.
type ServicePrincipal struct {
	ID                  uuid.UUID  `json:"id" db:"id"`
	ProductID           *uuid.UUID `json:"product_id,omitempty" db:"product_id"`
	Name                string     `json:"name" db:"name"`
	Slug                string     `json:"slug" db:"slug"`
	Description         string     `json:"description" db:"description"`
	PublicKeyPEM        string     `json:"-" db:"public_key_pem"`
	KeyID               string     `json:"key_id" db:"key_id"`
	AllowedScopes       []string   `json:"allowed_scopes" db:"allowed_scopes"`
	IPAllowlist         []string   `json:"ip_allowlist" db:"ip_allowlist"`
	Status              string     `json:"status" db:"status"`
	LastAuthenticatedAt *time.Time `json:"last_authenticated_at,omitempty" db:"last_authenticated_at"`
	CreatedAt           time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt           time.Time  `json:"updated_at" db:"updated_at"`

	// Application Object fields (Phase 1)
	Type                ServicePrincipalType          `json:"type" db:"type"`
	ApplicationID       *uuid.UUID                    `json:"application_id,omitempty" db:"application_id"`
	TenantID            *uuid.UUID                    `json:"tenant_id,omitempty" db:"tenant_id"`
	DisplayNameOverride *string                       `json:"display_name_override,omitempty" db:"display_name_override"`
	OAuthClientID       *uuid.UUID                    `json:"oauth_client_id,omitempty" db:"oauth_client_id"`
	InstallationStatus  ServicePrincipalInstallStatus `json:"installation_status" db:"installation_status"`

	// Phase 2: Per-SP scope & token overrides
	ScopeOverrides        []string `json:"scope_overrides,omitempty" db:"scope_overrides"`
	TokenLifetimeOverride []byte   `json:"token_lifetime_override,omitempty" db:"token_lifetime_override"`

	// Soft-delete grace period (Migration 114)
	DeletedAt  *time.Time `json:"deleted_at,omitempty" db:"deleted_at"`
	PurgeAfter *time.Time `json:"purge_after,omitempty" db:"purge_after"`
}

// ServicePrincipalResponse is the API response for a service principal.
type ServicePrincipalResponse struct {
	ID                  uuid.UUID                     `json:"id"`
	ProductID           *uuid.UUID                    `json:"product_id,omitempty"`
	Name                string                        `json:"name"`
	Slug                string                        `json:"slug"`
	Description         string                        `json:"description"`
	KeyID               string                        `json:"key_id"`
	AllowedScopes       []string                      `json:"allowed_scopes"`
	IPAllowlist         []string                      `json:"ip_allowlist"`
	Status              string                        `json:"status"`
	LastAuthenticatedAt *time.Time                    `json:"last_authenticated_at,omitempty"`
	CreatedAt           time.Time                     `json:"created_at"`
	UpdatedAt           time.Time                     `json:"updated_at"`
	Type                ServicePrincipalType          `json:"type"`
	ApplicationID       *uuid.UUID                    `json:"application_id,omitempty"`
	TenantID            *uuid.UUID                    `json:"tenant_id,omitempty"`
	DisplayNameOverride *string                       `json:"display_name_override,omitempty"`
	OAuthClientID       *uuid.UUID                    `json:"oauth_client_id,omitempty"`
	InstallationStatus  ServicePrincipalInstallStatus `json:"installation_status"`
	ScopeOverrides      []string                      `json:"scope_overrides,omitempty"`
}

// ToResponse converts a ServicePrincipal to its API response form.
func (sp *ServicePrincipal) ToResponse() ServicePrincipalResponse {
	return ServicePrincipalResponse{
		ID:                  sp.ID,
		ProductID:           sp.ProductID,
		Name:                sp.Name,
		Slug:                sp.Slug,
		Description:         sp.Description,
		KeyID:               sp.KeyID,
		AllowedScopes:       sp.AllowedScopes,
		IPAllowlist:         sp.IPAllowlist,
		Status:              sp.Status,
		LastAuthenticatedAt: sp.LastAuthenticatedAt,
		CreatedAt:           sp.CreatedAt,
		UpdatedAt:           sp.UpdatedAt,
		Type:                sp.Type,
		ApplicationID:       sp.ApplicationID,
		TenantID:            sp.TenantID,
		DisplayNameOverride: sp.DisplayNameOverride,
		OAuthClientID:       sp.OAuthClientID,
		InstallationStatus:  sp.InstallationStatus,
		ScopeOverrides:      sp.ScopeOverrides,
	}
}

// CreateServicePrincipalRequest is the request body for creating a service principal.
type CreateServicePrincipalRequest struct {
	Name                string               `json:"name" binding:"required"`
	Slug                string               `json:"slug" binding:"required"`
	Description         string               `json:"description"`
	ProductID           *uuid.UUID           `json:"product_id"`
	AllowedScopes       []string             `json:"allowed_scopes"`
	IPAllowlist         []string             `json:"ip_allowlist"`
	Type                ServicePrincipalType `json:"type"`
	ApplicationID       *uuid.UUID           `json:"application_id"`
	TenantID            *uuid.UUID           `json:"tenant_id"`
	DisplayNameOverride *string              `json:"display_name_override"`
}

// UpdateServicePrincipalRequest is the request body for updating a service principal.
type UpdateServicePrincipalRequest struct {
	Name          *string  `json:"name"`
	Description   *string  `json:"description"`
	AllowedScopes []string `json:"allowed_scopes"`
	IPAllowlist   []string `json:"ip_allowlist"`
	Status        *string  `json:"status"`
}

// ServiceEndpoint represents an API endpoint registered by a service.
type ServiceEndpoint struct {
	ID                  uuid.UUID `json:"id" db:"id"`
	ServicePrincipalID  uuid.UUID `json:"service_principal_id" db:"service_principal_id"`
	Path                string    `json:"path" db:"path"`
	Method              string    `json:"method" db:"method"`
	RequiredPermissions []string  `json:"required_permissions" db:"required_permissions"`
	Description         string    `json:"description" db:"description"`
	IsInternal          bool      `json:"is_internal" db:"is_internal"`
	RateLimitRPS        *int      `json:"rate_limit_rps,omitempty" db:"rate_limit_rps"`
	CreatedAt           time.Time `json:"created_at" db:"created_at"`
}

// ServiceEvent represents an event published by a service.
type ServiceEvent struct {
	ID                 uuid.UUID `json:"id" db:"id"`
	ServicePrincipalID uuid.UUID `json:"service_principal_id" db:"service_principal_id"`
	EventType          string    `json:"event_type" db:"event_type"`
	SchemaVersion      string    `json:"schema_version" db:"schema_version"`
	PayloadSchema      []byte    `json:"payload_schema,omitempty" db:"payload_schema"`
	Description        string    `json:"description" db:"description"`
	CreatedAt          time.Time `json:"created_at" db:"created_at"`
}

// RegisterServiceManifest is the request body for registering a service's endpoints and events.
type RegisterServiceManifest struct {
	Endpoints []ServiceEndpoint `json:"endpoints"`
	Events    []ServiceEvent    `json:"events"`
}
