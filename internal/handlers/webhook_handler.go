// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/internal/services"
)

const (
	msgWebhookTenantIDNotFound = "Tenant ID not found in context"
	msgWebhookInvalidID        = "Invalid webhook ID"
)

// WebhookHandler handles webhook-related HTTP requests
type WebhookHandler struct {
	webhookService *services.WebhookService
}

// NewWebhookHandler creates a new WebhookHandler
func NewWebhookHandler(webhookService *services.WebhookService) *WebhookHandler {
	return &WebhookHandler{
		webhookService: webhookService,
	}
}

// CreateWebhook handles POST /api/admin/webhooks
func (h *WebhookHandler) CreateWebhook(c *gin.Context) {
	tenantID, exists := c.Get("tenant_id")
	if !exists {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgWebhookTenantIDNotFound})
		return
	}

	var req models.CreateWebhookRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Validate secret length
	if len(req.Secret) < 16 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Secret must be at least 16 characters"})
		return
	}

	// Get creator user ID
	var createdBy *uuid.UUID
	if userID, exists := c.Get("user_id"); exists {
		uid := userID.(uuid.UUID)
		createdBy = &uid
	}

	response, err := h.webhookService.CreateWebhook(
		c.Request.Context(),
		tenantID.(uuid.UUID),
		&req,
		createdBy,
	)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, response)
}

// GetWebhook handles GET /api/admin/webhooks/:id
func (h *WebhookHandler) GetWebhook(c *gin.Context) {
	tenantID, exists := c.Get("tenant_id")
	if !exists {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgWebhookTenantIDNotFound})
		return
	}

	webhookID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgWebhookInvalidID})
		return
	}

	response, err := h.webhookService.GetWebhook(c.Request.Context(), webhookID, tenantID.(uuid.UUID))
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Webhook not found"})
		return
	}

	c.JSON(http.StatusOK, response)
}

// UpdateWebhook handles PUT /api/admin/webhooks/:id
func (h *WebhookHandler) UpdateWebhook(c *gin.Context) {
	tenantID, exists := c.Get("tenant_id")
	if !exists {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgWebhookTenantIDNotFound})
		return
	}

	webhookID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgWebhookInvalidID})
		return
	}

	var req models.UpdateWebhookRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Validate secret length if provided
	if req.Secret != nil && len(*req.Secret) < 16 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Secret must be at least 16 characters"})
		return
	}

	response, err := h.webhookService.UpdateWebhook(
		c.Request.Context(),
		webhookID,
		tenantID.(uuid.UUID),
		&req,
	)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, response)
}

// DeleteWebhook handles DELETE /api/admin/webhooks/:id
func (h *WebhookHandler) DeleteWebhook(c *gin.Context) {
	tenantID, exists := c.Get("tenant_id")
	if !exists {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgWebhookTenantIDNotFound})
		return
	}

	webhookID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgWebhookInvalidID})
		return
	}

	if err := h.webhookService.DeleteWebhook(c.Request.Context(), webhookID, tenantID.(uuid.UUID)); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Webhook deleted successfully"})
}

// ListWebhooks handles GET /api/admin/webhooks
func (h *WebhookHandler) ListWebhooks(c *gin.Context) {
	tenantID, exists := c.Get("tenant_id")
	if !exists {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgWebhookTenantIDNotFound})
		return
	}

	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "20"))
	activeOnly := c.Query("active_only") == queryBoolTrue

	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 100 {
		pageSize = 20
	}

	response, err := h.webhookService.ListWebhooks(
		c.Request.Context(),
		tenantID.(uuid.UUID),
		page,
		pageSize,
		activeOnly,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "An internal error occurred"})
		return
	}

	c.JSON(http.StatusOK, response)
}

// TestWebhook handles POST /api/admin/webhooks/:id/test
func (h *WebhookHandler) TestWebhook(c *gin.Context) {
	tenantID, exists := c.Get("tenant_id")
	if !exists {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgWebhookTenantIDNotFound})
		return
	}

	webhookID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgWebhookInvalidID})
		return
	}

	var req models.WebhookTestRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	response, err := h.webhookService.TestWebhook(
		c.Request.Context(),
		webhookID,
		tenantID.(uuid.UUID),
		req.EventType,
	)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, response)
}

// ListDeliveries handles GET /api/admin/webhooks/:id/deliveries
func (h *WebhookHandler) ListDeliveries(c *gin.Context) {
	tenantID, exists := c.Get("tenant_id")
	if !exists {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgWebhookTenantIDNotFound})
		return
	}

	webhookID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgWebhookInvalidID})
		return
	}

	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "20"))

	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 100 {
		pageSize = 20
	}

	var status *string
	if s := c.Query("status"); s != "" {
		status = &s
	}

	response, err := h.webhookService.ListDeliveries(
		c.Request.Context(),
		webhookID,
		tenantID.(uuid.UUID),
		page,
		pageSize,
		status,
	)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, response)
}

// GetDelivery handles GET /api/admin/webhooks/deliveries/:deliveryId
func (h *WebhookHandler) GetDelivery(c *gin.Context) {
	tenantID, exists := c.Get("tenant_id")
	if !exists {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgWebhookTenantIDNotFound})
		return
	}

	deliveryID, err := uuid.Parse(c.Param("deliveryId"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid delivery ID"})
		return
	}

	delivery, err := h.webhookService.GetDelivery(c.Request.Context(), deliveryID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Delivery not found"})
		return
	}

	// Verify the delivery's webhook belongs to the current tenant
	webhook, err := h.webhookService.GetWebhook(c.Request.Context(), delivery.WebhookID, tenantID.(uuid.UUID))
	if err != nil || webhook == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Delivery not found"})
		return
	}

	c.JSON(http.StatusOK, delivery)
}

// RetryDelivery handles POST /api/admin/webhooks/deliveries/:deliveryId/retry
func (h *WebhookHandler) RetryDelivery(c *gin.Context) {
	tenantID, exists := c.Get("tenant_id")
	if !exists {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgWebhookTenantIDNotFound})
		return
	}

	deliveryID, err := uuid.Parse(c.Param("deliveryId"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid delivery ID"})
		return
	}

	if err := h.webhookService.RetryDelivery(c.Request.Context(), deliveryID, tenantID.(uuid.UUID)); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Delivery queued for retry"})
}

// GetEventTypes handles GET /api/admin/webhooks/event-types
func (h *WebhookHandler) GetEventTypes(c *gin.Context) {
	eventTypes := h.webhookService.GetEventTypes()

	// Group by category
	grouped := make(map[string][]string)
	for _, et := range eventTypes {
		parts := splitEventType(string(et))
		if len(parts) == 2 {
			grouped[parts[0]] = append(grouped[parts[0]], string(et))
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"event_types": eventTypes,
		"grouped":     grouped,
	})
}

// GetDeliveryStats handles GET /api/admin/webhooks/:id/stats
func (h *WebhookHandler) GetDeliveryStats(c *gin.Context) {
	tenantID, exists := c.Get("tenant_id")
	if !exists {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgWebhookTenantIDNotFound})
		return
	}

	webhookID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgWebhookInvalidID})
		return
	}

	stats, err := h.webhookService.GetDeliveryStats(c.Request.Context(), webhookID, tenantID.(uuid.UUID))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"stats": stats})
}

func splitEventType(eventType string) []string {
	for i := len(eventType) - 1; i >= 0; i-- {
		if eventType[i] == '.' {
			return []string{eventType[:i], eventType[i+1:]}
		}
	}
	return []string{eventType}
}
