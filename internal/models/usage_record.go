// SPDX-License-Identifier: AGPL-3.0-or-later

package models

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// UsageRecord stores aggregated usage data for a tenant's product during a
// specific billing period.  It is the source-of-truth for the subscription
// billing pipeline and quota enforcement logic.
//
// The (tenant_id, product_id, metric_name, period_start) composite unique key
// enables idempotent upserts from the billing aggregator using
// INSERT ... ON CONFLICT DO UPDATE.
type UsageRecord struct {
	ID          uuid.UUID       `json:"id" db:"id"`
	TenantID    uuid.UUID       `json:"tenant_id" db:"tenant_id"`
	ProductID   uuid.UUID       `json:"product_id" db:"product_id"`
	MetricName  string          `json:"metric_name" db:"metric_name"`
	Value       int64           `json:"value" db:"value"`
	PeriodStart time.Time       `json:"period_start" db:"period_start"`
	PeriodEnd   time.Time       `json:"period_end" db:"period_end"`
	RecordedAt  time.Time       `json:"recorded_at" db:"recorded_at"`
	Metadata    json.RawMessage `json:"metadata,omitempty" db:"metadata"`
}

// ==================== Request DTOs ====================

// RecordUsageRequest is the payload for inserting or upserting a usage record.
// The billing aggregator submits this after computing the aggregated metric value
// for the period.
type RecordUsageRequest struct {
	TenantID    uuid.UUID       `json:"tenant_id" binding:"required"`
	ProductID   uuid.UUID       `json:"product_id" binding:"required"`
	MetricName  string          `json:"metric_name" binding:"required,min=1,max=255"`
	Value       int64           `json:"value" binding:"min=0"`
	PeriodStart time.Time       `json:"period_start" binding:"required"`
	PeriodEnd   time.Time       `json:"period_end" binding:"required"`
	Metadata    json.RawMessage `json:"metadata"`
}

// UsageQueryRequest is the payload for querying usage records within a date range.
type UsageQueryRequest struct {
	TenantID    *uuid.UUID `json:"tenant_id" form:"tenant_id"`
	ProductID   *uuid.UUID `json:"product_id" form:"product_id"`
	MetricName  string     `json:"metric_name" form:"metric_name"`
	PeriodStart *time.Time `json:"period_start" form:"period_start"`
	PeriodEnd   *time.Time `json:"period_end" form:"period_end"`
	Page        int        `json:"page" form:"page"`
	PageSize    int        `json:"page_size" form:"page_size"`
}

// ==================== Response DTOs ====================

// UsageRecordResponse is the API representation of a usage record.
type UsageRecordResponse struct {
	ID          uuid.UUID       `json:"id"`
	TenantID    uuid.UUID       `json:"tenant_id"`
	ProductID   uuid.UUID       `json:"product_id"`
	MetricName  string          `json:"metric_name"`
	Value       int64           `json:"value"`
	PeriodStart time.Time       `json:"period_start"`
	PeriodEnd   time.Time       `json:"period_end"`
	RecordedAt  time.Time       `json:"recorded_at"`
	Metadata    json.RawMessage `json:"metadata,omitempty"`
}

// UsageRecordListResponse is the paginated list of usage records.
type UsageRecordListResponse struct {
	Records    []UsageRecordResponse `json:"records"`
	Total      int64                 `json:"total"`
	Page       int                   `json:"page"`
	PageSize   int                   `json:"page_size"`
	TotalPages int                   `json:"total_pages"`
}

// UsageSummaryResponse aggregates usage across multiple records for dashboard display.
type UsageSummaryResponse struct {
	TenantID    uuid.UUID            `json:"tenant_id"`
	ProductID   uuid.UUID            `json:"product_id"`
	Metrics     []UsageMetricSummary `json:"metrics"`
	PeriodStart time.Time            `json:"period_start"`
	PeriodEnd   time.Time            `json:"period_end"`
}

// UsageMetricSummary is a single metric's aggregated value within a summary.
type UsageMetricSummary struct {
	MetricName string `json:"metric_name"`
	Total      int64  `json:"total"`
	Peak       int64  `json:"peak"`
}

// ==================== Conversion methods ====================

// ToResponse converts a UsageRecord to its API response representation.
func (u *UsageRecord) ToResponse() *UsageRecordResponse {
	return &UsageRecordResponse{
		ID:          u.ID,
		TenantID:    u.TenantID,
		ProductID:   u.ProductID,
		MetricName:  u.MetricName,
		Value:       u.Value,
		PeriodStart: u.PeriodStart,
		PeriodEnd:   u.PeriodEnd,
		RecordedAt:  u.RecordedAt,
		Metadata:    u.Metadata,
	}
}
