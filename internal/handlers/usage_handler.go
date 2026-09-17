// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"context"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

// usageMeteringService defines the service interface used by UsageHandler.
type usageMeteringService interface {
	RecordUsage(ctx context.Context, record *models.UsageRecord) error
	GetUsageSummary(ctx context.Context, tenantID uuid.UUID, from, to time.Time) ([]models.UsageRecord, error)
	GetProductUsage(ctx context.Context, tenantID, productID uuid.UUID, metric string, from, to time.Time) (int64, error)
}

// UsageHandler handles usage metering HTTP endpoints.
type UsageHandler struct {
	svc usageMeteringService
}

// NewUsageHandler creates a new UsageHandler.
func NewUsageHandler(svc usageMeteringService) *UsageHandler {
	return &UsageHandler{svc: svc}
}

// recordUsageRequest is the payload for POST /api/v1/internal/usage.
type recordUsageRequest struct {
	TenantID    uuid.UUID  `json:"tenant_id" binding:"required"`
	ProductID   uuid.UUID  `json:"product_id" binding:"required"`
	MetricName  string     `json:"metric_name" binding:"required,min=1,max=100"`
	Value       int64      `json:"value"`
	PeriodStart *time.Time `json:"period_start"`
	PeriodEnd   *time.Time `json:"period_end"`
}

// usageSummaryQuery is the query parameters for GET /api/v1/admin/usage.
type usageSummaryQuery struct {
	From string `form:"from"`
	To   string `form:"to"`
}

// productUsageQuery is the query parameters for GET /api/v1/admin/usage/:product_id.
type productUsageQuery struct {
	Metric string `form:"metric" binding:"required"`
	From   string `form:"from"`
	To     string `form:"to"`
}

// RecordUsage handles POST /api/v1/internal/usage.
// This is an internal endpoint — callers must be authenticated via internal API key.
func (h *UsageHandler) RecordUsage(c *gin.Context) {
	var req recordUsageRequest
	if !BindJSON(c, &req) {
		return
	}

	record := &models.UsageRecord{
		TenantID:   req.TenantID,
		ProductID:  req.ProductID,
		MetricName: req.MetricName,
		Value:      req.Value,
	}
	if req.PeriodStart != nil {
		record.PeriodStart = *req.PeriodStart
	}
	if req.PeriodEnd != nil {
		record.PeriodEnd = *req.PeriodEnd
	}

	if err := h.svc.RecordUsage(c.Request.Context(), record); err != nil {
		HandleError(c, err)
		return
	}

	c.JSON(http.StatusCreated, gin.H{"message": "usage recorded"})
}

// GetUsageSummary handles GET /api/v1/admin/usage.
// Returns all usage records for the requesting tenant within the given time range.
func (h *UsageHandler) GetUsageSummary(c *gin.Context) {
	tenantID, ok := RequireTenantID(c)
	if !ok {
		return
	}

	var query usageSummaryQuery
	_ = c.ShouldBindQuery(&query)

	from, to := parseTimeRange(query.From, query.To)

	records, err := h.svc.GetUsageSummary(c.Request.Context(), tenantID, from, to)
	if err != nil {
		HandleError(c, err)
		return
	}

	responses := make([]*models.UsageRecordResponse, 0, len(records))
	for i := range records {
		responses = append(responses, records[i].ToResponse())
	}

	c.JSON(http.StatusOK, gin.H{
		"records": responses,
		"total":   len(records),
		"from":    from,
		"to":      to,
	})
}

// GetProductUsage handles GET /api/v1/admin/usage/:product_id.
// Returns aggregated usage for a specific product and metric.
func (h *UsageHandler) GetProductUsage(c *gin.Context) {
	tenantID, ok := RequireTenantID(c)
	if !ok {
		return
	}

	productID, ok := ParseUUIDParam(c, "product_id")
	if !ok {
		return
	}

	var query productUsageQuery
	if err := c.ShouldBindQuery(&query); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "metric query parameter is required"})
		return
	}

	from, to := parseTimeRange(query.From, query.To)

	total, err := h.svc.GetProductUsage(c.Request.Context(), tenantID, productID, query.Metric, from, to)
	if err != nil {
		HandleError(c, err)
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"tenant_id":  tenantID,
		"product_id": productID,
		"metric":     query.Metric,
		"total":      total,
		"from":       from,
		"to":         to,
	})
}

// parseTimeRange parses optional from/to RFC3339 strings into time.Time values.
// Zero time is returned for invalid or empty inputs.
func parseTimeRange(fromStr, toStr string) (from, to time.Time) {
	if fromStr != "" {
		if t, err := time.Parse(time.RFC3339, fromStr); err == nil {
			from = t
		}
	}
	if toStr != "" {
		if t, err := time.Parse(time.RFC3339, toStr); err == nil {
			to = t
		}
	}
	return from, to
}
