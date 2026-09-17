// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"context"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

const (
	msgInvalidReportID = "invalid report ID"
)

// complianceReportService is the service interface used by ComplianceReportHandler.
type complianceReportService interface {
	ListTemplates(ctx context.Context) ([]models.ComplianceReportTemplate, error)
	Create(ctx context.Context, req *models.CreateComplianceReportRequest, generatedBy uuid.UUID) (*models.ComplianceReport, error)
	GetByID(ctx context.Context, id uuid.UUID) (*models.ComplianceReport, error)
	List(ctx context.Context, params models.ComplianceReportListParams) ([]models.ComplianceReport, int64, error)
	Delete(ctx context.Context, id uuid.UUID) error
	Download(ctx context.Context, id uuid.UUID) ([]byte, models.ComplianceReportOutputFormat, error)
}

// ComplianceReportHandler handles compliance report HTTP endpoints.
type ComplianceReportHandler struct {
	svc    complianceReportService
	logger *zap.Logger
}

// NewComplianceReportHandler creates a new ComplianceReportHandler.
func NewComplianceReportHandler(svc complianceReportService, log *zap.Logger) *ComplianceReportHandler {
	if log == nil {
		log = zap.NewNop()
	}
	return &ComplianceReportHandler{svc: svc, logger: log}
}

// ListTemplates handles GET /api/v1/platform/compliance/templates.
//
// @Summary List compliance report templates
// @Description Returns all available compliance report templates
// @Tags Compliance
// @Produce json
// @Success 200 {object} map[string]interface{} "List of report templates"
// @Failure 500 {object} map[string]string "Internal server error"
// @Router /api/v1/platform/compliance/templates [get]
func (h *ComplianceReportHandler) ListTemplates(c *gin.Context) {
	templates, err := h.svc.ListTemplates(c.Request.Context())
	if err != nil {
		h.logger.Error("ComplianceReportHandler.ListTemplates failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list templates"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"templates": templates, "total": len(templates)})
}

// List handles GET /api/v1/platform/compliance/reports.
//
// @Summary List compliance reports
// @Description Returns a paginated list of compliance reports with optional filters
// @Tags Compliance
// @Produce json
// @Param page query int false "Page number" default(1)
// @Param page_size query int false "Results per page" default(20)
// @Param report_type query string false "Filter by report type"
// @Param status query string false "Filter by status"
// @Param tenant_id query string false "Filter by tenant UUID"
// @Success 200 {object} map[string]interface{} "Paginated list of compliance reports"
// @Failure 500 {object} map[string]string "Internal server error"
// @Router /api/v1/platform/compliance/reports [get]
func (h *ComplianceReportHandler) List(c *gin.Context) {
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "20"))

	params := models.ComplianceReportListParams{
		ReportType: c.Query("report_type"),
		Status:     c.Query("status"),
		Page:       page,
		PageSize:   pageSize,
	}
	if tid := c.Query("tenant_id"); tid != "" {
		if id, err := uuid.Parse(tid); err == nil {
			params.TenantID = &id
		}
	}

	reports, total, err := h.svc.List(c.Request.Context(), params)
	if err != nil {
		h.logger.Error("ComplianceReportHandler.List failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list reports"})
		return
	}

	totalPages := int(total) / pageSize
	if int(total)%pageSize > 0 {
		totalPages++
	}

	c.JSON(http.StatusOK, gin.H{
		"reports":     reports,
		"total":       total,
		"page":        page,
		"page_size":   pageSize,
		"total_pages": totalPages,
	})
}

// Create handles POST /api/v1/platform/compliance/reports.
//
// @Summary Create compliance report
// @Description Queues a new compliance report for generation
// @Tags Compliance
// @Accept json
// @Produce json
// @Param request body models.CreateComplianceReportRequest true "Report configuration"
// @Success 202 {object} models.ComplianceReport "Report queued for generation"
// @Failure 400 {object} map[string]string "Validation error"
// @Failure 401 {object} map[string]string "Not authenticated"
// @Failure 500 {object} map[string]string "Internal server error"
// @Router /api/v1/platform/compliance/reports [post]
func (h *ComplianceReportHandler) Create(c *gin.Context) {
	var req models.CreateComplianceReportRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	currentUser, ok := RequireCurrentUser(c)
	if !ok || currentUser == nil {
		return
	}

	report, err := h.svc.Create(c.Request.Context(), &req, currentUser.ID)
	if err != nil {
		h.logger.Error("ComplianceReportHandler.Create failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create report"})
		return
	}

	c.JSON(http.StatusAccepted, report)
}

// GetByID handles GET /api/v1/platform/compliance/reports/:id.
//
// @Summary Get compliance report
// @Description Retrieves a compliance report by its UUID
// @Tags Compliance
// @Produce json
// @Param id path string true "Report UUID"
// @Success 200 {object} models.ComplianceReport "Compliance report"
// @Failure 400 {object} map[string]string "Invalid report ID"
// @Failure 404 {object} map[string]string "Report not found"
// @Router /api/v1/platform/compliance/reports/{id} [get]
func (h *ComplianceReportHandler) GetByID(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgInvalidReportID})
		return
	}

	report, err := h.svc.GetByID(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "report not found"})
		return
	}

	c.JSON(http.StatusOK, report)
}

// Download handles GET /api/v1/platform/compliance/reports/:id/download.
//
// @Summary Download compliance report
// @Description Downloads the generated compliance report as a file (JSON, CSV, or PDF)
// @Tags Compliance
// @Produce application/json,text/csv,application/pdf
// @Param id path string true "Report UUID"
// @Success 200 {file} binary "Report file"
// @Failure 400 {object} map[string]string "Invalid report ID or report not ready"
// @Failure 500 {object} map[string]string "Internal server error"
// @Router /api/v1/platform/compliance/reports/{id}/download [get]
func (h *ComplianceReportHandler) Download(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgInvalidReportID})
		return
	}

	data, format, err := h.svc.Download(c.Request.Context(), id)
	if err != nil {
		h.logger.Error("ComplianceReportHandler.Download failed", zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	contentType := "application/json"
	ext := ".json"
	switch format {
	case models.ReportOutputCSV:
		contentType = "text/csv"
		ext = ".csv"
	case models.ReportOutputPDF:
		contentType = "application/pdf"
		ext = ".pdf"
	}

	filename := "compliance-report-" + id.String() + ext
	c.Header("Content-Disposition", "attachment; filename="+filename)
	c.Data(http.StatusOK, contentType, data)
}

// Delete handles DELETE /api/v1/platform/compliance/reports/:id.
//
// @Summary Delete compliance report
// @Description Permanently removes a compliance report
// @Tags Compliance
// @Produce json
// @Param id path string true "Report UUID"
// @Success 200 {object} map[string]string "Report deleted"
// @Failure 400 {object} map[string]string "Invalid report ID"
// @Failure 500 {object} map[string]string "Internal server error"
// @Router /api/v1/platform/compliance/reports/{id} [delete]
func (h *ComplianceReportHandler) Delete(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgInvalidReportID})
		return
	}

	if err := h.svc.Delete(c.Request.Context(), id); err != nil {
		h.logger.Error("ComplianceReportHandler.Delete failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to delete report"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "report deleted"})
}
