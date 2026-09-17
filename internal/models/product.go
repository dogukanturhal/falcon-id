// SPDX-License-Identifier: AGPL-3.0-or-later

package models

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// ProductType represents the delivery model for a product.
type ProductType string

const (
	// ProductTypeSaaS is a cloud-hosted product accessed via browser or API.
	ProductTypeSaaS ProductType = "saas"
	// ProductTypeLicensed is an on-premises product that phones home for verification.
	ProductTypeLicensed ProductType = "licensed"
	// ProductTypeHybrid is a product that supports both SaaS and on-premises deployment.
	ProductTypeHybrid ProductType = "hybrid"
)

// ProductStatus represents the lifecycle state of a product.
type ProductStatus string

const (
	// ProductStatusActive indicates the product is generally available.
	ProductStatusActive ProductStatus = "active"
	// ProductStatusDeprecated indicates the product is still usable but no longer recommended.
	ProductStatusDeprecated ProductStatus = "deprecated"
	// ProductStatusArchived indicates the product has been retired.
	ProductStatusArchived ProductStatus = "archived"
)

// ProductVersionStatus represents the lifecycle state of a specific product version.
type ProductVersionStatus string

const (
	// ProductVersionStatusActive indicates the version is current and supported.
	ProductVersionStatusActive ProductVersionStatus = "active"
	// ProductVersionStatusDeprecated indicates the version is still usable but superseded.
	ProductVersionStatusDeprecated ProductVersionStatus = "deprecated"
	// ProductVersionStatusEndOfLife indicates the version is no longer supported.
	ProductVersionStatusEndOfLife ProductVersionStatus = "end_of_life"
)

// Product represents a product in the HexxLock product registry.
type Product struct {
	ID               uuid.UUID              `json:"id" db:"id"`
	Name             string                 `json:"name" db:"name"`
	Slug             string                 `json:"slug" db:"slug"`
	Description      *string                `json:"description,omitempty" db:"description"`
	Type             ProductType            `json:"type" db:"type"`
	Status           ProductStatus          `json:"status" db:"status"`
	IconURL          *string                `json:"icon_url,omitempty" db:"icon_url"`
	HomepageURL      *string                `json:"homepage_url,omitempty" db:"homepage_url"`
	DocumentationURL *string                `json:"documentation_url,omitempty" db:"documentation_url"`
	Metadata         map[string]interface{} `json:"metadata,omitempty" db:"metadata"`
	// CapabilityManifest is a structured JSONB manifest describing the product's
	// API endpoints, resource types, event catalog, quota definitions, and
	// inter-product dependencies.  Added by migration 086.
	CapabilityManifest json.RawMessage `json:"capability_manifest,omitempty" db:"capability_manifest"`
	CreatedBy          *uuid.UUID      `json:"created_by,omitempty" db:"created_by"`
	CreatedAt          time.Time       `json:"created_at" db:"created_at"`
	UpdatedAt          time.Time       `json:"updated_at" db:"updated_at"`
}

// ProductVersion represents a specific version of a product.
type ProductVersion struct {
	ID            uuid.UUID            `json:"id" db:"id"`
	ProductID     uuid.UUID            `json:"product_id" db:"product_id"`
	Version       string               `json:"version" db:"version"`
	ReleaseNotes  *string              `json:"release_notes,omitempty" db:"release_notes"`
	MinAPIVersion *string              `json:"min_api_version,omitempty" db:"min_api_version"`
	Status        ProductVersionStatus `json:"status" db:"status"`
	ReleasedAt    *time.Time           `json:"released_at,omitempty" db:"released_at"`
	CreatedAt     time.Time            `json:"created_at" db:"created_at"`
}

// IsActive returns true when the product is in active status.
func (p *Product) IsActive() bool {
	return p.Status == ProductStatusActive
}

// IsDeprecated returns true when the product is deprecated.
func (p *Product) IsDeprecated() bool {
	return p.Status == ProductStatusDeprecated
}

// IsArchived returns true when the product has been archived.
func (p *Product) IsArchived() bool {
	return p.Status == ProductStatusArchived
}

// ==================== Request DTOs ====================

// CreateProductRequest is the payload for registering a new product.
type CreateProductRequest struct {
	Name             string                 `json:"name" binding:"required,min=2,max=255"`
	Slug             string                 `json:"slug" binding:"required,min=2,max=100"`
	Description      *string                `json:"description"`
	Type             ProductType            `json:"type" binding:"required,oneof=saas licensed hybrid"`
	IconURL          *string                `json:"icon_url" binding:"omitempty,url"`
	HomepageURL      *string                `json:"homepage_url" binding:"omitempty,url"`
	DocumentationURL *string                `json:"documentation_url" binding:"omitempty,url"`
	Metadata         map[string]interface{} `json:"metadata"`
}

// UpdateProductRequest is the payload for updating an existing product.
// All fields are optional to allow partial updates.
type UpdateProductRequest struct {
	Name               *string                `json:"name" binding:"omitempty,min=2,max=255"`
	Description        *string                `json:"description"`
	Status             *ProductStatus         `json:"status" binding:"omitempty,oneof=active deprecated archived"`
	IconURL            *string                `json:"icon_url" binding:"omitempty,url"`
	HomepageURL        *string                `json:"homepage_url" binding:"omitempty,url"`
	DocumentationURL   *string                `json:"documentation_url" binding:"omitempty,url"`
	Metadata           map[string]interface{} `json:"metadata"`
	CapabilityManifest json.RawMessage        `json:"capability_manifest"`
}

// CreateProductVersionRequest is the payload for adding a new version to a product.
type CreateProductVersionRequest struct {
	Version       string     `json:"version" binding:"required,min=1,max=50"`
	ReleaseNotes  *string    `json:"release_notes"`
	MinAPIVersion *string    `json:"min_api_version" binding:"omitempty,max=50"`
	ReleasedAt    *time.Time `json:"released_at"`
}

// ==================== Response DTOs ====================

// ProductResponse is the API representation of a product.
type ProductResponse struct {
	ID                 uuid.UUID              `json:"id"`
	Name               string                 `json:"name"`
	Slug               string                 `json:"slug"`
	Description        *string                `json:"description,omitempty"`
	Type               ProductType            `json:"type"`
	Status             ProductStatus          `json:"status"`
	IconURL            *string                `json:"icon_url,omitempty"`
	HomepageURL        *string                `json:"homepage_url,omitempty"`
	DocumentationURL   *string                `json:"documentation_url,omitempty"`
	Metadata           map[string]interface{} `json:"metadata,omitempty"`
	CapabilityManifest json.RawMessage        `json:"capability_manifest,omitempty"`
	CreatedBy          *uuid.UUID             `json:"created_by,omitempty"`
	CreatedAt          time.Time              `json:"created_at"`
	UpdatedAt          time.Time              `json:"updated_at"`
}

// ProductListResponse is the paginated list of products.
type ProductListResponse struct {
	Products   []ProductResponse `json:"products"`
	Total      int64             `json:"total"`
	Page       int               `json:"page"`
	PageSize   int               `json:"page_size"`
	TotalPages int               `json:"total_pages"`
}

// ProductVersionResponse is the API representation of a product version.
type ProductVersionResponse struct {
	ID            uuid.UUID            `json:"id"`
	ProductID     uuid.UUID            `json:"product_id"`
	Version       string               `json:"version"`
	ReleaseNotes  *string              `json:"release_notes,omitempty"`
	MinAPIVersion *string              `json:"min_api_version,omitempty"`
	Status        ProductVersionStatus `json:"status"`
	ReleasedAt    *time.Time           `json:"released_at,omitempty"`
	CreatedAt     time.Time            `json:"created_at"`
}

// ProductVersionListResponse is the paginated list of product versions.
type ProductVersionListResponse struct {
	Versions   []ProductVersionResponse `json:"versions"`
	Total      int64                    `json:"total"`
	Page       int                      `json:"page"`
	PageSize   int                      `json:"page_size"`
	TotalPages int                      `json:"total_pages"`
}

// ==================== Conversion methods ====================

// ToResponse converts a Product to its API response representation.
func (p *Product) ToResponse() *ProductResponse {
	return &ProductResponse{
		ID:                 p.ID,
		Name:               p.Name,
		Slug:               p.Slug,
		Description:        p.Description,
		Type:               p.Type,
		Status:             p.Status,
		IconURL:            p.IconURL,
		HomepageURL:        p.HomepageURL,
		DocumentationURL:   p.DocumentationURL,
		Metadata:           p.Metadata,
		CapabilityManifest: p.CapabilityManifest,
		CreatedBy:          p.CreatedBy,
		CreatedAt:          p.CreatedAt,
		UpdatedAt:          p.UpdatedAt,
	}
}

// ToResponse converts a ProductVersion to its API response representation.
func (v *ProductVersion) ToResponse() *ProductVersionResponse {
	return &ProductVersionResponse{
		ID:            v.ID,
		ProductID:     v.ProductID,
		Version:       v.Version,
		ReleaseNotes:  v.ReleaseNotes,
		MinAPIVersion: v.MinAPIVersion,
		Status:        v.Status,
		ReleasedAt:    v.ReleasedAt,
		CreatedAt:     v.CreatedAt,
	}
}
