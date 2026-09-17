// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"context"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

// subscriptionEventBridge is the narrow interface for triggering provisioning.
type subscriptionEventBridge interface {
	TriggerProvisioning(ctx context.Context, tenantID, productID uuid.UUID, isolationTier string) (*models.ProductInstance, error)
}

// SubscriptionEventHandler handles inbound subscription lifecycle events
// from the subscription-management service.
type SubscriptionEventHandler struct {
	bridge subscriptionEventBridge
}

// NewSubscriptionEventHandler creates a new handler.
func NewSubscriptionEventHandler(bridge subscriptionEventBridge) *SubscriptionEventHandler {
	return &SubscriptionEventHandler{bridge: bridge}
}

// subscriptionActivatedRequest is the payload from subscription-management
// when a tenant subscribes to a product.
type subscriptionActivatedRequest struct {
	TenantID      uuid.UUID `json:"tenant_id" binding:"required"`
	ProductID     uuid.UUID `json:"product_id" binding:"required"`
	IsolationTier string    `json:"isolation_tier"`
}

// HandleActivated handles POST /api/v1/internal/subscription-events/activated
// This is called by subscription-management when invoice.paid confirms a subscription.
func (h *SubscriptionEventHandler) HandleActivated(c *gin.Context) {
	var req subscriptionActivatedRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	instance, err := h.bridge.TriggerProvisioning(c.Request.Context(), req.TenantID, req.ProductID, req.IsolationTier)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to trigger provisioning"})
		return
	}

	c.JSON(http.StatusAccepted, gin.H{
		"message":  "provisioning triggered",
		"instance": instance,
	})
}
