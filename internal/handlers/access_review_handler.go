// SPDX-License-Identifier: AGPL-3.0-or-later

// Package handlers implements HTTP request handlers.
package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/middleware"
	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/internal/services"
)

const (
	msgInvalidCampaignID = "invalid campaign id"
)

// AccessReviewHandler exposes HTTP endpoints for managing access review campaigns.
type AccessReviewHandler struct {
	service *services.AccessReviewService
	logger  *zap.Logger
}

// NewAccessReviewHandler creates a new AccessReviewHandler.
func NewAccessReviewHandler(service *services.AccessReviewService, logger *zap.Logger) *AccessReviewHandler {
	return &AccessReviewHandler{
		service: service,
		logger:  logger,
	}
}

// CreateCampaign handles POST /access-reviews
// Creates a new access review campaign and seeds review items.
func (h *AccessReviewHandler) CreateCampaign(c *gin.Context) {
	currentUser := middleware.GetCurrentUser(c)
	if currentUser == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	var req models.CreateAccessReviewRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	campaign, err := h.service.CreateCampaign(c.Request.Context(), currentUser.TenantID, currentUser.ID, &req)
	if err != nil {
		h.logger.Error("Failed to create access review campaign",
			zap.Error(err),
			zap.String("tenant_id", currentUser.TenantID.String()),
		)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create campaign"})
		return
	}

	c.JSON(http.StatusCreated, campaign)
}

// ListCampaigns handles GET /access-reviews
// Returns a paginated list of campaigns, optionally filtered by status.
func (h *AccessReviewHandler) ListCampaigns(c *gin.Context) {
	currentUser := middleware.GetCurrentUser(c)
	if currentUser == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	status := c.Query("status")
	page := queryInt(c, "page", 1)
	pageSize := queryInt(c, "page_size", 20)

	campaigns, total, err := h.service.ListCampaigns(c.Request.Context(), currentUser.TenantID, status, page, pageSize)
	if err != nil {
		h.logger.Error("Failed to list access review campaigns", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list campaigns"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"campaigns": campaigns,
		"total":     total,
		"page":      page,
		"page_size": pageSize,
	})
}

// GetCampaign handles GET /access-reviews/:id
// Returns campaign details together with aggregate stats.
func (h *AccessReviewHandler) GetCampaign(c *gin.Context) {
	currentUser := middleware.GetCurrentUser(c)
	if currentUser == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	campaignID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgInvalidCampaignID})
		return
	}

	resp, err := h.service.GetCampaignDetails(c.Request.Context(), campaignID, currentUser.TenantID)
	if err != nil {
		h.logger.Error("Failed to get access review campaign", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get campaign"})
		return
	}
	if resp == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "campaign not found"})
		return
	}

	c.JSON(http.StatusOK, resp)
}

// ListPendingItems handles GET /access-reviews/pending
// Returns pending review items assigned to the authenticated user.
func (h *AccessReviewHandler) ListPendingItems(c *gin.Context) {
	currentUser := middleware.GetCurrentUser(c)
	if currentUser == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	items, err := h.service.ListPendingItems(c.Request.Context(), currentUser.ID, currentUser.TenantID)
	if err != nil {
		h.logger.Error("Failed to list pending review items", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list pending items"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"items": items, "total": len(items)})
}

// SubmitDecision handles POST /access-reviews/:id/items/:itemId/decide
// Records an approve or deny decision by the authenticated reviewer.
func (h *AccessReviewHandler) SubmitDecision(c *gin.Context) {
	currentUser := middleware.GetCurrentUser(c)
	if currentUser == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	campaignID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgInvalidCampaignID})
		return
	}
	_ = campaignID // used for URL structure; item lookup is by itemID + tenantID

	itemID, err := uuid.Parse(c.Param("itemId"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid item id"})
		return
	}

	var req models.SubmitDecisionRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := h.service.SubmitDecision(c.Request.Context(), currentUser.TenantID, currentUser.ID, itemID, &req); err != nil {
		h.logger.Error("Failed to submit access review decision",
			zap.Error(err),
			zap.String("item_id", itemID.String()),
		)
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "decision recorded"})
}

// FinalizeCampaign handles POST /access-reviews/:id/finalize
// Closes the campaign and optionally auto-expires pending items.
func (h *AccessReviewHandler) FinalizeCampaign(c *gin.Context) {
	currentUser := middleware.GetCurrentUser(c)
	if currentUser == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	campaignID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgInvalidCampaignID})
		return
	}

	if err := h.service.FinalizeCampaign(c.Request.Context(), campaignID, currentUser.TenantID); err != nil {
		h.logger.Error("Failed to finalize access review campaign",
			zap.Error(err),
			zap.String("campaign_id", campaignID.String()),
		)
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "campaign finalized"})
}
