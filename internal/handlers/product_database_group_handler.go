// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/internal/repositories"
)

// ProductDatabaseGroupHandler handles database group API endpoints.
type ProductDatabaseGroupHandler struct {
	repo *repositories.ProductDatabaseGroupRepository
}

// NewProductDatabaseGroupHandler creates a new handler.
func NewProductDatabaseGroupHandler(repo *repositories.ProductDatabaseGroupRepository) *ProductDatabaseGroupHandler {
	return &ProductDatabaseGroupHandler{repo: repo}
}

// ListByProduct returns all database groups for a product.
// GET /api/v1/platform/products/:product_id/database-groups
func (h *ProductDatabaseGroupHandler) ListByProduct(c *gin.Context) {
	productID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid product ID"})
		return
	}

	groups, err := h.repo.ListByProduct(c.Request.Context(), productID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list database groups"})
		return
	}

	if groups == nil {
		groups = []models.ProductDatabaseGroup{}
	}

	c.JSON(http.StatusOK, gin.H{"database_groups": groups, "total": len(groups)})
}

// Create adds a new database group for a product.
// POST /api/v1/platform/products/:product_id/database-groups
func (h *ProductDatabaseGroupHandler) Create(c *gin.Context) {
	productID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid product ID"})
		return
	}

	var req models.CreateProductDatabaseGroupRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	group := &models.ProductDatabaseGroup{
		ProductID:          productID,
		DatabaseName:       req.DatabaseName,
		DisplayName:        req.DisplayName,
		MigrationDir:       req.MigrationDir,
		Priority:           req.Priority,
		IsControlPlane:     req.IsControlPlane,
		RequiredExtensions: req.RequiredExtensions,
	}
	if group.Priority == 0 {
		group.Priority = 10
	}

	if err := h.repo.Create(c.Request.Context(), group); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create database group"})
		return
	}

	c.JSON(http.StatusCreated, group)
}

// Delete removes a database group.
// DELETE /api/v1/platform/products/:product_id/database-groups/:group_id
func (h *ProductDatabaseGroupHandler) Delete(c *gin.Context) {
	groupID, err := uuid.Parse(c.Param("group_id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid group ID"})
		return
	}

	if err := h.repo.Delete(c.Request.Context(), groupID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete database group"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Database group deleted"})
}
