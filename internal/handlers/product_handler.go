// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/dogukanturhal/falcon-id/internal/middleware"
	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/internal/services"
)

const (
	msgProductInvalidID     = "Invalid product ID"
	msgProductNotFound      = "Product not found"
	msgProductNotFoundLower = "not found"
)

// ProductHandler handles product registry HTTP endpoints.
type ProductHandler struct {
	productService *services.ProductService
}

// NewProductHandler creates a new product handler.
func NewProductHandler(productService *services.ProductService) *ProductHandler {
	return &ProductHandler{productService: productService}
}

// Create registers a new product.
//
// @Summary Create product
// @Description Registers a new product in the platform product registry
// @Tags Products
// @Accept json
// @Produce json
// @Param request body models.CreateProductRequest true "Product details"
// @Success 201 {object} models.ProductResponse "Created product"
// @Failure 400 {object} map[string]string "Validation error"
// @Failure 401 {object} map[string]string "Not authenticated"
// @Failure 409 {object} map[string]string "Product already exists"
// @Failure 500 {object} map[string]string "Internal server error"
// @Router /api/v1/platform/products [post]
func (h *ProductHandler) Create(c *gin.Context) {
	currentUser := middleware.GetCurrentUser(c)
	if currentUser == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Not authenticated"})
		return
	}

	var req models.CreateProductRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	product, err := h.productService.Create(c.Request.Context(), &req, currentUser.ID)
	if err != nil {
		if strings.Contains(err.Error(), "already exists") {
			c.JSON(http.StatusConflict, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create product"})
		return
	}

	c.JSON(http.StatusCreated, product.ToResponse())
}

// Get retrieves a product by ID.
//
// @Summary Get product
// @Description Retrieves a product by its UUID
// @Tags Products
// @Produce json
// @Param id path string true "Product UUID"
// @Success 200 {object} models.ProductResponse "Product details"
// @Failure 400 {object} map[string]string msgProductInvalidID
// @Failure 404 {object} map[string]string msgProductNotFound
// @Failure 500 {object} map[string]string "Internal server error"
// @Router /api/v1/platform/products/{id} [get]
func (h *ProductHandler) Get(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgProductInvalidID})
		return
	}

	product, err := h.productService.GetByID(c.Request.Context(), id)
	if err != nil {
		if strings.Contains(err.Error(), "no rows") {
			c.JSON(http.StatusNotFound, gin.H{"error": msgProductNotFound})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve product"})
		return
	}

	c.JSON(http.StatusOK, product.ToResponse())
}

// List returns a paginated list of products.
//
// @Summary List products
// @Description Returns a paginated list of products with optional filters
// @Tags Products
// @Produce json
// @Param page query int false "Page number" default(1)
// @Param page_size query int false "Results per page" default(20)
// @Param search query string false "Search by name or slug"
// @Param type query string false "Filter by product type"
// @Param status query string false "Filter by status"
// @Success 200 {object} models.ProductListResponse "Paginated list of products"
// @Failure 500 {object} map[string]string "Internal server error"
// @Router /api/v1/platform/products [get]
func (h *ProductHandler) List(c *gin.Context) {
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "20"))
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 100 {
		pageSize = 20
	}

	search := c.Query("search")
	productType := c.Query("type")
	status := c.Query("status")

	products, total, err := h.productService.List(c.Request.Context(), page, pageSize, search, productType, status)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list products"})
		return
	}

	responses := make([]*models.ProductResponse, 0, len(products))
	for i := range products {
		responses = append(responses, products[i].ToResponse())
	}

	totalPages := int(total) / pageSize
	if int(total)%pageSize > 0 {
		totalPages++
	}

	c.JSON(http.StatusOK, models.ProductListResponse{
		Products:   flattenProductResponses(responses),
		Total:      total,
		Page:       page,
		PageSize:   pageSize,
		TotalPages: totalPages,
	})
}

// Update applies partial updates to a product.
//
// @Summary Update product
// @Description Applies partial updates to an existing product
// @Tags Products
// @Accept json
// @Produce json
// @Param id path string true "Product UUID"
// @Param request body models.UpdateProductRequest true "Fields to update"
// @Success 200 {object} models.ProductResponse "Updated product"
// @Failure 400 {object} map[string]string "Invalid product ID or validation error"
// @Failure 404 {object} map[string]string msgProductNotFound
// @Failure 500 {object} map[string]string "Internal server error"
// @Router /api/v1/platform/products/{id} [put]
func (h *ProductHandler) Update(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgProductInvalidID})
		return
	}

	var req models.UpdateProductRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	product, err := h.productService.Update(c.Request.Context(), id, &req)
	if err != nil {
		if strings.Contains(err.Error(), msgProductNotFoundLower) {
			c.JSON(http.StatusNotFound, gin.H{"error": msgProductNotFound})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update product"})
		return
	}

	c.JSON(http.StatusOK, product.ToResponse())
}

// Delete removes a product.
//
// @Summary Delete product
// @Description Permanently removes a product from the registry
// @Tags Products
// @Produce json
// @Param id path string true "Product UUID"
// @Success 204 "Product deleted"
// @Failure 400 {object} map[string]string msgProductInvalidID
// @Failure 404 {object} map[string]string msgProductNotFound
// @Failure 500 {object} map[string]string "Internal server error"
// @Router /api/v1/platform/products/{id} [delete]
func (h *ProductHandler) Delete(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgProductInvalidID})
		return
	}

	if err := h.productService.Delete(c.Request.Context(), id); err != nil {
		if strings.Contains(err.Error(), msgProductNotFoundLower) {
			c.JSON(http.StatusNotFound, gin.H{"error": msgProductNotFound})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete product"})
		return
	}

	c.Status(http.StatusNoContent)
}

// CreateVersion adds a new version to a product.
//
// @Summary Create product version
// @Description Adds a new version entry to a product
// @Tags Products
// @Accept json
// @Produce json
// @Param id path string true "Product UUID"
// @Param request body models.CreateProductVersionRequest true "Version details"
// @Success 201 {object} models.ProductVersionResponse "Created version"
// @Failure 400 {object} map[string]string "Invalid product ID or validation error"
// @Failure 404 {object} map[string]string msgProductNotFound
// @Failure 500 {object} map[string]string "Internal server error"
// @Router /api/v1/platform/products/{id}/versions [post]
func (h *ProductHandler) CreateVersion(c *gin.Context) {
	productID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgProductInvalidID})
		return
	}

	var req models.CreateProductVersionRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	version, err := h.productService.CreateVersion(c.Request.Context(), productID, &req)
	if err != nil {
		if strings.Contains(err.Error(), msgProductNotFoundLower) {
			c.JSON(http.StatusNotFound, gin.H{"error": msgProductNotFound})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create product version"})
		return
	}

	c.JSON(http.StatusCreated, version.ToResponse())
}

// ListVersions returns all versions for a product.
//
// @Summary List product versions
// @Description Returns all version entries for the specified product
// @Tags Products
// @Produce json
// @Param id path string true "Product UUID"
// @Success 200 {object} map[string]interface{} "List of product versions"
// @Failure 400 {object} map[string]string msgProductInvalidID
// @Failure 500 {object} map[string]string "Internal server error"
// @Router /api/v1/platform/products/{id}/versions [get]
func (h *ProductHandler) ListVersions(c *gin.Context) {
	productID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgProductInvalidID})
		return
	}

	versions, err := h.productService.ListVersions(c.Request.Context(), productID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list product versions"})
		return
	}

	responses := make([]*models.ProductVersionResponse, 0, len(versions))
	for i := range versions {
		responses = append(responses, versions[i].ToResponse())
	}

	c.JSON(http.StatusOK, gin.H{"versions": responses})
}

// flattenProductResponses converts a slice of pointers to a slice of values.
func flattenProductResponses(in []*models.ProductResponse) []models.ProductResponse {
	out := make([]models.ProductResponse, 0, len(in))
	for _, r := range in {
		if r != nil {
			out = append(out, *r)
		}
	}
	return out
}
