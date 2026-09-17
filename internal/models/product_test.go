// SPDX-License-Identifier: AGPL-3.0-or-later

package models

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ==================== Product status helpers ====================

func TestProduct_IsActive(t *testing.T) {
	tests := []struct {
		name     string
		product  Product
		expected bool
	}{
		{
			name:     "should return true when status is active",
			product:  Product{Status: ProductStatusActive},
			expected: true,
		},
		{
			name:     "should return false when status is deprecated",
			product:  Product{Status: ProductStatusDeprecated},
			expected: false,
		},
		{
			name:     "should return false when status is archived",
			product:  Product{Status: ProductStatusArchived},
			expected: false,
		},
		{
			name:     "should return false when status is empty",
			product:  Product{Status: ""},
			expected: false,
		},
		{
			name:     "should return false for unknown status",
			product:  Product{Status: "unknown"},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.product.IsActive())
		})
	}
}

func TestProduct_IsDeprecated(t *testing.T) {
	tests := []struct {
		name     string
		product  Product
		expected bool
	}{
		{
			name:     "should return true when status is deprecated",
			product:  Product{Status: ProductStatusDeprecated},
			expected: true,
		},
		{
			name:     "should return false when status is active",
			product:  Product{Status: ProductStatusActive},
			expected: false,
		},
		{
			name:     "should return false when status is archived",
			product:  Product{Status: ProductStatusArchived},
			expected: false,
		},
		{
			name:     "should return false when status is empty",
			product:  Product{Status: ""},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.product.IsDeprecated())
		})
	}
}

func TestProduct_IsArchived(t *testing.T) {
	tests := []struct {
		name     string
		product  Product
		expected bool
	}{
		{
			name:     "should return true when status is archived",
			product:  Product{Status: ProductStatusArchived},
			expected: true,
		},
		{
			name:     "should return false when status is active",
			product:  Product{Status: ProductStatusActive},
			expected: false,
		},
		{
			name:     "should return false when status is deprecated",
			product:  Product{Status: ProductStatusDeprecated},
			expected: false,
		},
		{
			name:     "should return false when status is empty",
			product:  Product{Status: ""},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.product.IsArchived())
		})
	}
}

// TestProduct_StatusMutualExclusivity verifies that exactly one status flag is
// set at any given time for each known status value.
func TestProduct_StatusMutualExclusivity(t *testing.T) {
	tests := []struct {
		status         ProductStatus
		wantActive     bool
		wantDeprecated bool
		wantArchived   bool
	}{
		{
			status:         ProductStatusActive,
			wantActive:     true,
			wantDeprecated: false,
			wantArchived:   false,
		},
		{
			status:         ProductStatusDeprecated,
			wantActive:     false,
			wantDeprecated: true,
			wantArchived:   false,
		},
		{
			status:         ProductStatusArchived,
			wantActive:     false,
			wantDeprecated: false,
			wantArchived:   true,
		},
	}

	for _, tt := range tests {
		t.Run(string(tt.status), func(t *testing.T) {
			p := &Product{Status: tt.status}
			assert.Equal(t, tt.wantActive, p.IsActive(), "IsActive mismatch")
			assert.Equal(t, tt.wantDeprecated, p.IsDeprecated(), "IsDeprecated mismatch")
			assert.Equal(t, tt.wantArchived, p.IsArchived(), "IsArchived mismatch")
		})
	}
}

// ==================== Product.ToResponse ====================

func TestProduct_ToResponse(t *testing.T) {
	t.Run("should map all scalar fields correctly", func(t *testing.T) {
		id := uuid.New()
		createdBy := uuid.New()
		now := time.Now().Truncate(time.Second)
		desc := "A great product"
		icon := "https://example.com/icon.png"
		homepage := "https://example.com"
		docs := "https://docs.example.com"

		p := &Product{
			ID:               id,
			Name:             "My Product",
			Slug:             "my-product",
			Description:      &desc,
			Type:             ProductTypeSaaS,
			Status:           ProductStatusActive,
			IconURL:          &icon,
			HomepageURL:      &homepage,
			DocumentationURL: &docs,
			Metadata:         map[string]interface{}{"key": "value"},
			CreatedBy:        &createdBy,
			CreatedAt:        now,
			UpdatedAt:        now,
		}

		resp := p.ToResponse()

		require.NotNil(t, resp)
		assert.Equal(t, id, resp.ID)
		assert.Equal(t, "My Product", resp.Name)
		assert.Equal(t, "my-product", resp.Slug)
		assert.Equal(t, &desc, resp.Description)
		assert.Equal(t, ProductTypeSaaS, resp.Type)
		assert.Equal(t, ProductStatusActive, resp.Status)
		assert.Equal(t, &icon, resp.IconURL)
		assert.Equal(t, &homepage, resp.HomepageURL)
		assert.Equal(t, &docs, resp.DocumentationURL)
		assert.Equal(t, map[string]interface{}{"key": "value"}, resp.Metadata)
		assert.Equal(t, &createdBy, resp.CreatedBy)
		assert.Equal(t, now, resp.CreatedAt)
		assert.Equal(t, now, resp.UpdatedAt)
	})

	t.Run("should handle nil optional fields", func(t *testing.T) {
		p := &Product{
			ID:     uuid.New(),
			Name:   "Minimal Product",
			Slug:   "minimal-product",
			Type:   ProductTypeLicensed,
			Status: ProductStatusDeprecated,
		}

		resp := p.ToResponse()

		require.NotNil(t, resp)
		assert.Nil(t, resp.Description)
		assert.Nil(t, resp.IconURL)
		assert.Nil(t, resp.HomepageURL)
		assert.Nil(t, resp.DocumentationURL)
		assert.Nil(t, resp.Metadata)
		assert.Nil(t, resp.CreatedBy)
	})

	t.Run("should produce a distinct response instance each call", func(t *testing.T) {
		p := &Product{
			ID:     uuid.New(),
			Name:   "Product",
			Status: ProductStatusActive,
		}

		resp1 := p.ToResponse()
		resp2 := p.ToResponse()

		// Must be different pointers but equal in value.
		assert.NotSame(t, resp1, resp2)
		assert.Equal(t, resp1, resp2)
	})
}

// ==================== ProductVersion.ToResponse ====================

func TestProductVersion_ToResponse(t *testing.T) {
	t.Run("should map all fields correctly", func(t *testing.T) {
		id := uuid.New()
		productID := uuid.New()
		now := time.Now().Truncate(time.Second)
		notes := "Initial release"
		minAPI := "v1.0"
		released := time.Now().Add(-48 * time.Hour)

		v := &ProductVersion{
			ID:            id,
			ProductID:     productID,
			Version:       "1.0.0",
			ReleaseNotes:  &notes,
			MinAPIVersion: &minAPI,
			Status:        ProductVersionStatusActive,
			ReleasedAt:    &released,
			CreatedAt:     now,
		}

		resp := v.ToResponse()

		require.NotNil(t, resp)
		assert.Equal(t, id, resp.ID)
		assert.Equal(t, productID, resp.ProductID)
		assert.Equal(t, "1.0.0", resp.Version)
		assert.Equal(t, &notes, resp.ReleaseNotes)
		assert.Equal(t, &minAPI, resp.MinAPIVersion)
		assert.Equal(t, ProductVersionStatusActive, resp.Status)
		assert.Equal(t, &released, resp.ReleasedAt)
		assert.Equal(t, now, resp.CreatedAt)
	})

	t.Run("should handle nil optional fields", func(t *testing.T) {
		v := &ProductVersion{
			ID:        uuid.New(),
			ProductID: uuid.New(),
			Version:   "2.0.0",
			Status:    ProductVersionStatusDeprecated,
		}

		resp := v.ToResponse()

		require.NotNil(t, resp)
		assert.Nil(t, resp.ReleaseNotes)
		assert.Nil(t, resp.MinAPIVersion)
		assert.Nil(t, resp.ReleasedAt)
	})

	t.Run("should carry end_of_life status through", func(t *testing.T) {
		v := &ProductVersion{
			ID:        uuid.New(),
			ProductID: uuid.New(),
			Version:   "0.1.0-legacy",
			Status:    ProductVersionStatusEndOfLife,
		}

		resp := v.ToResponse()
		assert.Equal(t, ProductVersionStatusEndOfLife, resp.Status)
	})
}

// ==================== Product type constants ====================

func TestProductTypeConstants(t *testing.T) {
	assert.Equal(t, ProductType("saas"), ProductTypeSaaS)
	assert.Equal(t, ProductType("licensed"), ProductTypeLicensed)
	assert.Equal(t, ProductType("hybrid"), ProductTypeHybrid)
}

func TestProductStatusConstants(t *testing.T) {
	assert.Equal(t, ProductStatus("active"), ProductStatusActive)
	assert.Equal(t, ProductStatus("deprecated"), ProductStatusDeprecated)
	assert.Equal(t, ProductStatus("archived"), ProductStatusArchived)
}

func TestProductVersionStatusConstants(t *testing.T) {
	assert.Equal(t, ProductVersionStatus("active"), ProductVersionStatusActive)
	assert.Equal(t, ProductVersionStatus("deprecated"), ProductVersionStatusDeprecated)
	assert.Equal(t, ProductVersionStatus("end_of_life"), ProductVersionStatusEndOfLife)
}
