// SPDX-License-Identifier: AGPL-3.0-or-later

package models

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// ComplianceReportType enumerates supported report standards.
type ComplianceReportType string

const (
	// ReportTypeSOC2Type2 is an exported identifier.
	ReportTypeSOC2Type2 ComplianceReportType = "soc2_type2"
	// ReportTypeGDPRArticle30 is an exported identifier.
	ReportTypeGDPRArticle30 ComplianceReportType = "gdpr_article30"
	// ReportTypeISO27001A9 is an exported identifier.
	ReportTypeISO27001A9 ComplianceReportType = "iso27001_a9"
	// ReportTypeAccessReview is an exported identifier.
	ReportTypeAccessReview ComplianceReportType = "access_review"
	// ReportTypeMFAEnrollment is an exported identifier.
	ReportTypeMFAEnrollment ComplianceReportType = "mfa_enrollment"
	// ReportTypePermissionChanges is an exported identifier.
	ReportTypePermissionChanges ComplianceReportType = "permission_changes"
)

// ComplianceReportStatus is the lifecycle state of a report generation job.
type ComplianceReportStatus string

const (
	// ReportStatusPending is an exported identifier.
	ReportStatusPending ComplianceReportStatus = "pending"
	// ReportStatusGenerating is an exported identifier.
	ReportStatusGenerating ComplianceReportStatus = "generating"
	// ReportStatusCompleted is an exported identifier.
	ReportStatusCompleted ComplianceReportStatus = "completed"
	// ReportStatusFailed is an exported identifier.
	ReportStatusFailed ComplianceReportStatus = "failed"
)

// ComplianceReportOutputFormat is the delivery format for a completed report.
type ComplianceReportOutputFormat string

const (
	// ReportOutputJSON is an exported identifier.
	ReportOutputJSON ComplianceReportOutputFormat = "json"
	// ReportOutputCSV is an exported identifier.
	ReportOutputCSV ComplianceReportOutputFormat = "csv"
	// ReportOutputPDF is an exported identifier.
	ReportOutputPDF ComplianceReportOutputFormat = "pdf"
)

// ComplianceReportTemplate is a reusable, named report configuration.
type ComplianceReportTemplate struct {
	ID            uuid.UUID                    `json:"id"             db:"id"`
	ReportType    ComplianceReportType         `json:"report_type"    db:"report_type"`
	Name          string                       `json:"name"           db:"name"`
	Description   string                       `json:"description"    db:"description"`
	DefaultParams json.RawMessage              `json:"default_params" db:"default_params"`
	OutputFormat  ComplianceReportOutputFormat `json:"output_format" db:"output_format"`
	IsSystem      bool                         `json:"is_system"      db:"is_system"`
	CreatedBy     *uuid.UUID                   `json:"created_by"     db:"created_by"`
	CreatedAt     time.Time                    `json:"created_at"     db:"created_at"`
	UpdatedAt     time.Time                    `json:"updated_at"     db:"updated_at"`
}

// ComplianceReport is a generated report instance.
type ComplianceReport struct {
	ID            uuid.UUID                    `json:"id"              db:"id"`
	TenantID      *uuid.UUID                   `json:"tenant_id"       db:"tenant_id"`
	ReportType    ComplianceReportType         `json:"report_type"     db:"report_type"`
	Name          string                       `json:"name"            db:"name"`
	Description   string                       `json:"description"     db:"description"`
	Status        ComplianceReportStatus       `json:"status"          db:"status"`
	PeriodStart   time.Time                    `json:"period_start"    db:"period_start"`
	PeriodEnd     time.Time                    `json:"period_end"      db:"period_end"`
	Parameters    json.RawMessage              `json:"parameters"      db:"parameters"`
	OutputFormat  ComplianceReportOutputFormat `json:"output_format"   db:"output_format"`
	FileSizeBytes *int64                       `json:"file_size_bytes" db:"file_size_bytes"`
	RecordCount   *int                         `json:"record_count"    db:"record_count"`
	OutputData    json.RawMessage              `json:"output_data,omitempty" db:"output_data"`
	GeneratedBy   uuid.UUID                    `json:"generated_by"    db:"generated_by"`
	StartedAt     *time.Time                   `json:"started_at"      db:"started_at"`
	CompletedAt   *time.Time                   `json:"completed_at"    db:"completed_at"`
	ErrorMessage  *string                      `json:"error_message"   db:"error_message"`
	CreatedAt     time.Time                    `json:"created_at"      db:"created_at"`
	UpdatedAt     time.Time                    `json:"updated_at"      db:"updated_at"`
}

// IsComplete returns true when the report has finished generating.
func (r *ComplianceReport) IsComplete() bool {
	return r.Status == ReportStatusCompleted
}

// IsFailed returns true when generation has failed.
func (r *ComplianceReport) IsFailed() bool {
	return r.Status == ReportStatusFailed
}

// ==================== CRUD DTOs ====================

// CreateComplianceReportRequest is the payload for requesting a new report.
type CreateComplianceReportRequest struct {
	TenantID     *uuid.UUID                   `json:"tenant_id"`
	ReportType   ComplianceReportType         `json:"report_type"   binding:"required,oneof=soc2_type2 gdpr_article30 iso27001_a9 access_review mfa_enrollment permission_changes"`
	Name         string                       `json:"name"          binding:"required,min=1,max=255"`
	Description  string                       `json:"description"`
	PeriodStart  time.Time                    `json:"period_start"  binding:"required"`
	PeriodEnd    time.Time                    `json:"period_end"    binding:"required"`
	Parameters   map[string]interface{}       `json:"parameters"`
	OutputFormat ComplianceReportOutputFormat `json:"output_format" binding:"omitempty,oneof=json csv pdf"`
}

// ComplianceReportListParams holds query parameters for listing reports.
type ComplianceReportListParams struct {
	TenantID   *uuid.UUID
	ReportType string
	Status     string
	Page       int
	PageSize   int
}
