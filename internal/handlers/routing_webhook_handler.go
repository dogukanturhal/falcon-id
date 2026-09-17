// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/dogukanturhal/falcon-id/internal/middleware"
	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/internal/services"
	"github.com/dogukanturhal/falcon-id/pkg/apierrors"
)

// RoutingWebhookHandler handles routing webhook HTTP requests
type RoutingWebhookHandler struct {
	svc *services.RoutingWebhookService
}

// NewRoutingWebhookHandler creates a new RoutingWebhookHandler
func NewRoutingWebhookHandler(svc *services.RoutingWebhookService) *RoutingWebhookHandler {
	return &RoutingWebhookHandler{svc: svc}
}

// ListWebhooks handles GET /api/v1/admin/routing-webhooks
func (h *RoutingWebhookHandler) ListWebhooks(c *gin.Context) {
	tenantID, ok := RequireTenantID(c)
	if !ok {
		return
	}

	page, pageSize, _ := GetPagination(c)

	resp, err := h.svc.ListWebhooks(c.Request.Context(), tenantID, page, pageSize)
	if err != nil {
		HandleError(c, err)
		return
	}

	SuccessWithMeta(c, resp.Webhooks, &Meta{
		Page:       resp.Page,
		PageSize:   resp.PageSize,
		TotalItems: int64(resp.Total),
		TotalPages: resp.TotalPages,
	})
}

// CreateWebhook handles POST /api/v1/admin/routing-webhooks
func (h *RoutingWebhookHandler) CreateWebhook(c *gin.Context) {
	tenantID, ok := RequireTenantID(c)
	if !ok {
		return
	}

	var req models.CreateRoutingWebhookRequest
	if !BindJSON(c, &req) {
		return
	}

	var createdBy *uuid.UUID
	if user := middleware.GetCurrentUser(c); user != nil {
		createdBy = &user.ID
	}

	webhook, err := h.svc.CreateWebhook(c.Request.Context(), tenantID, &req, createdBy)
	if err != nil {
		HandleError(c, err)
		return
	}

	Created(c, webhook)
}

// GetWebhook handles GET /api/v1/admin/routing-webhooks/:id
func (h *RoutingWebhookHandler) GetWebhook(c *gin.Context) {
	tenantID, ok := RequireTenantID(c)
	if !ok {
		return
	}

	webhookID, ok := ParseUUIDParam(c, "id")
	if !ok {
		return
	}

	webhook, err := h.svc.GetWebhook(c.Request.Context(), webhookID, tenantID)
	if err != nil {
		HandleError(c, err)
		return
	}

	Success(c, webhook)
}

// UpdateWebhook handles PUT /api/v1/admin/routing-webhooks/:id
func (h *RoutingWebhookHandler) UpdateWebhook(c *gin.Context) {
	tenantID, ok := RequireTenantID(c)
	if !ok {
		return
	}

	webhookID, ok := ParseUUIDParam(c, "id")
	if !ok {
		return
	}

	var req models.UpdateRoutingWebhookRequest
	if !BindJSON(c, &req) {
		return
	}

	webhook, err := h.svc.UpdateWebhook(c.Request.Context(), webhookID, tenantID, &req)
	if err != nil {
		HandleError(c, err)
		return
	}

	Success(c, webhook)
}

// DeleteWebhook handles DELETE /api/v1/admin/routing-webhooks/:id
func (h *RoutingWebhookHandler) DeleteWebhook(c *gin.Context) {
	tenantID, ok := RequireTenantID(c)
	if !ok {
		return
	}

	webhookID, ok := ParseUUIDParam(c, "id")
	if !ok {
		return
	}

	if err := h.svc.DeleteWebhook(c.Request.Context(), webhookID, tenantID); err != nil {
		HandleError(c, err)
		return
	}

	NoContent(c)
}

// TestWebhook handles POST /api/v1/admin/routing-webhooks/:id/test
func (h *RoutingWebhookHandler) TestWebhook(c *gin.Context) {
	tenantID, ok := RequireTenantID(c)
	if !ok {
		return
	}

	webhookID, ok := ParseUUIDParam(c, "id")
	if !ok {
		return
	}

	var req models.RoutingWebhookTestRequest
	if !BindJSON(c, &req) {
		return
	}

	// Fill in defaults from request context if not provided
	if req.ClientIP == "" {
		req.ClientIP = GetClientIP(c)
	}
	if req.UserAgent == "" {
		req.UserAgent = c.GetHeader("User-Agent")
	}

	resp, err := h.svc.TestWebhook(c.Request.Context(), webhookID, tenantID, &req)
	if err != nil {
		HandleError(c, err)
		return
	}

	if !resp.Success {
		Error(c, apierrors.New("WEBHOOK_TEST_FAILED", 422, "Webhook test failed").
			WithDetail("duration_ms", resp.DurationMs).
			WithDetail("error", resp.ErrorMessage))
		return
	}

	Success(c, resp)
}

// ListLogs handles GET /api/v1/admin/routing-webhooks/:id/logs
func (h *RoutingWebhookHandler) ListLogs(c *gin.Context) {
	tenantID, ok := RequireTenantID(c)
	if !ok {
		return
	}

	webhookID, ok := ParseUUIDParam(c, "id")
	if !ok {
		return
	}

	page, pageSize, _ := GetPagination(c)

	resp, err := h.svc.ListLogs(c.Request.Context(), webhookID, tenantID, page, pageSize)
	if err != nil {
		HandleError(c, err)
		return
	}

	SuccessWithMeta(c, resp.Logs, &Meta{
		Page:       resp.Page,
		PageSize:   resp.PageSize,
		TotalItems: int64(resp.Total),
		TotalPages: resp.TotalPages,
	})
}
