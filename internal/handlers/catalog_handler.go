// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"context"
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/dogukanturhal/falcon-id/internal/models"
	"go.uber.org/zap"
)

// catalogProductRepo is the minimal repository interface required by
// CatalogHandler.  It deliberately contains only the two read operations
// needed by the public catalog endpoints so that callers can provide a
// focused test double without implementing the full product repository.
type catalogProductRepo interface {
	// ListActive returns the page of active products together with the total
	// count of active products across all pages.
	ListActive(ctx context.Context, page, pageSize int) ([]models.Product, int64, error)

	// GetBySlug returns the active product identified by slug.
	// Implementations should return an error containing "not found" (or
	// sql.ErrNoRows) when no matching product exists.
	GetBySlug(ctx context.Context, slug string) (*models.Product, error)
}

// CatalogProductResponse is the public-safe representation of a product
// returned by the catalog endpoints.  Internal fields (CreatedBy, sensitive
// Metadata keys) are intentionally excluded.
type CatalogProductResponse struct {
	ID               uuid.UUID            `json:"id"`
	Name             string               `json:"name"`
	Slug             string               `json:"slug"`
	Description      *string              `json:"description,omitempty"`
	Type             models.ProductType   `json:"type"`
	Status           models.ProductStatus `json:"status"`
	IconURL          *string              `json:"icon_url,omitempty"`
	HomepageURL      *string              `json:"homepage_url,omitempty"`
	DocumentationURL *string              `json:"documentation_url,omitempty"`
}

// CatalogListResponse is the paginated response returned by ListProducts.
type CatalogListResponse struct {
	Products   []CatalogProductResponse `json:"products"`
	Total      int64                    `json:"total"`
	Page       int                      `json:"page"`
	PageSize   int                      `json:"page_size"`
	TotalPages int                      `json:"total_pages"`
}

// CatalogHandler handles public, unauthenticated product catalog endpoints.
// The handler deliberately omits all authentication middleware so that
// prospective customers can browse the product catalog without logging in.
type CatalogHandler struct {
	productRepo catalogProductRepo
	logger      *zap.Logger
}

// NewCatalogHandler creates a new CatalogHandler backed by repo.
func NewCatalogHandler(repo catalogProductRepo, logger *zap.Logger) *CatalogHandler {
	return &CatalogHandler{
		productRepo: repo,
		logger:      logger,
	}
}

// ListProducts handles GET /api/v1/catalog/products
//
// Returns a paginated list of active products with public-safe fields only.
// Supports the following query parameters:
//
//	page      – 1-based page number (default: 1)
//	page_size – items per page, capped at 100 (default: 20)
func (h *CatalogHandler) ListProducts(c *gin.Context) {
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "20"))

	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 100 {
		pageSize = 20
	}

	products, total, err := h.productRepo.ListActive(c.Request.Context(), page, pageSize)
	if err != nil {
		h.logger.Error("catalog: failed to list active products",
			zap.Error(err),
			zap.Int("page", page),
			zap.Int("page_size", pageSize),
		)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list products"})
		return
	}

	responses := make([]CatalogProductResponse, 0, len(products))
	for i := range products {
		responses = append(responses, toPublicResponse(&products[i]))
	}

	totalPages := int(total) / pageSize
	if int(total)%pageSize > 0 {
		totalPages++
	}

	c.JSON(http.StatusOK, CatalogListResponse{
		Products:   responses,
		Total:      total,
		Page:       page,
		PageSize:   pageSize,
		TotalPages: totalPages,
	})
}

// GetProduct handles GET /api/v1/catalog/products/:slug
//
// Returns a single active product by its URL slug.
// Responds with 404 when no active product matches the slug.
func (h *CatalogHandler) GetProduct(c *gin.Context) {
	slug := c.Param("slug")
	if slug == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Product slug is required"})
		return
	}

	product, err := h.productRepo.GetBySlug(c.Request.Context(), slug)
	if err != nil {
		if isNotFound(err) {
			c.JSON(http.StatusNotFound, gin.H{"error": "Product not found"})
			return
		}
		h.logger.Error("catalog: failed to fetch product by slug",
			zap.Error(err),
			zap.String("slug", slug),
		)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve product"})
		return
	}

	c.JSON(http.StatusOK, toPublicResponse(product))
}

// toPublicResponse converts an internal Product model into a
// CatalogProductResponse that is safe to serve without authentication.
// It deliberately omits CreatedBy and strips sensitive metadata keys.
func toPublicResponse(p *models.Product) CatalogProductResponse {
	return CatalogProductResponse{
		ID:               p.ID,
		Name:             p.Name,
		Slug:             p.Slug,
		Description:      p.Description,
		Type:             p.Type,
		Status:           p.Status,
		IconURL:          p.IconURL,
		HomepageURL:      p.HomepageURL,
		DocumentationURL: p.DocumentationURL,
	}
}

// isNotFound returns true when the error represents a "not found" condition.
// It recognises the sql.ErrNoRows message and common ORM / repository
// conventions used throughout the falcon-id codebase.
func isNotFound(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "not found") ||
		strings.Contains(msg, "no rows") ||
		strings.Contains(msg, "no_rows")
}
