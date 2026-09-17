// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"context"
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/dogukanturhal/falcon-id/internal/middleware"
	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/internal/services"
	"github.com/dogukanturhal/falcon-id/pkg/logger"
	"go.uber.org/zap"
)

// AuditHandler is an exported type.
type AuditHandler struct {
	auditService    *services.AuditService
	archiverService *services.AuditArchiverService
}

// NewAuditHandler is an exported function.
func NewAuditHandler(
	auditService *services.AuditService,
	archiverService *services.AuditArchiverService,
) *AuditHandler {
	return &AuditHandler{
		auditService:    auditService,
		archiverService: archiverService,
	}
}

// GetAuditLogs retrieves audit logs for the current tenant
// @Summary Get audit logs
// @Description Returns audit logs for the authenticated user's tenant
// @Tags Audit
// @Security BearerAuth
// @Produce json
// @Param page query int false "Page number" default(1)
// @Param page_size query int false "Page size" default(20) maximum(100)
// @Param action query string false "Filter by action"
// @Param user_id query string false "Filter by user ID"
// @Param from query string false "Filter from date (RFC3339)"
// @Param to query string false "Filter to date (RFC3339)"
// @Success 200 {object} models.AuditLogListResponse
// @Failure 401 {object} models.ErrorResponse
// @Failure 500 {object} models.ErrorResponse
// @Router /api/v1/auth/audit/logs [get]
func (h *AuditHandler) GetAuditLogs(c *gin.Context) {
	user := middleware.GetCurrentUser(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	// SECURITY: Use GetPagination to enforce max page size of 100
	page, pageSize, _ := GetPagination(c)

	filters := make(map[string]interface{})
	if action := c.Query("action"); action != "" {
		filters["action"] = action
	}
	if userIDStr := c.Query("user_id"); userIDStr != "" {
		if userID, err := uuid.Parse(userIDStr); err == nil {
			filters["user_id"] = userID
		}
	}
	if from := c.Query("from"); from != "" {
		filters["from"] = from
	}
	if to := c.Query("to"); to != "" {
		filters["to"] = to
	}

	response, err := h.auditService.GetAuditLogs(c.Request.Context(), user.TenantID, page, pageSize, filters)
	if err != nil {
		logger.Error("Failed to get audit logs", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get audit logs"})
		return
	}

	c.JSON(http.StatusOK, response)
}

// ArchiveTenantLogs triggers archival of old audit logs for the current tenant
// @Summary Archive audit logs
// @Description Archives audit logs older than retention period to S3
// @Tags Audit
// @Security BearerAuth
// @Produce json
// @Success 200 {object} models.MessageResponse
// @Failure 401 {object} models.ErrorResponse
// @Failure 403 {object} models.ErrorResponse
// @Failure 500 {object} models.ErrorResponse
// @Router /api/v1/auth/audit/archive [post]
func (h *AuditHandler) ArchiveTenantLogs(c *gin.Context) {
	user := middleware.GetCurrentUser(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	// Check if archiver service is configured
	if h.archiverService == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "audit archiving not configured"})
		return
	}

	// Capture values before responding — Gin cancels request context after handler returns
	tenantID := user.TenantID
	userID := user.ID

	c.JSON(http.StatusOK, gin.H{
		"message": "Audit log archival started. This process may take a few minutes.",
	})

	// Archive logs asynchronously with a detached context
	go func() {
		ctx := context.WithoutCancel(c.Request.Context())
		if err := h.archiverService.ArchiveTenantLogs(ctx, tenantID, &userID); err != nil {
			logger.Error("Failed to archive audit logs",
				zap.Error(err),
				zap.String("tenant_id", tenantID.String()),
			)
		}
	}()
}

// GetArchiveMetadata retrieves archive metadata for the current tenant
// @Summary Get archive metadata
// @Description Returns metadata for archived audit log batches
// @Tags Audit
// @Security BearerAuth
// @Produce json
// @Param page query int false "Page number" default(1)
// @Param page_size query int false "Page size" default(20) maximum(100)
// @Success 200 {object} map[string]interface{}
// @Failure 401 {object} models.ErrorResponse
// @Failure 500 {object} models.ErrorResponse
// @Router /api/v1/auth/audit/archives [get]
func (h *AuditHandler) GetArchiveMetadata(c *gin.Context) {
	user := middleware.GetCurrentUser(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	// SECURITY: Use GetPagination to enforce max page size of 100
	page, pageSize, _ := GetPagination(c)

	metadata, total, err := h.auditService.GetArchiveMetadata(c.Request.Context(), user.TenantID, page, pageSize)
	if err != nil {
		logger.Error("Failed to get archive metadata", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get archive metadata"})
		return
	}

	// Convert to response format
	responses := make([]models.AuditArchiveMetadataResponse, len(metadata))
	for i, m := range metadata {
		fileSizeMB := 0.0
		if m.FileSizeBytes != nil {
			fileSizeMB = float64(*m.FileSizeBytes) / (1024.0 * 1024.0)
		}

		responses[i] = models.AuditArchiveMetadataResponse{
			ID:                m.ID,
			TenantID:          m.TenantID,
			ArchiveBatchID:    m.ArchiveBatchID,
			StartDate:         m.StartDate,
			EndDate:           m.EndDate,
			RecordCount:       m.RecordCount,
			S3Bucket:          m.S3Bucket,
			S3Key:             m.S3Key,
			FileSizeMB:        fileSizeMB,
			CompressionType:   m.CompressionType,
			Encrypted:         m.Encrypted,
			ObjectLockEnabled: m.ObjectLockEnabled,
			CreatedAt:         m.CreatedAt,
		}
	}

	totalPages := int(total) / pageSize
	if int(total)%pageSize > 0 {
		totalPages++
	}

	c.JSON(http.StatusOK, gin.H{
		"archives":    responses,
		"total":       total,
		"page":        page,
		"page_size":   pageSize,
		"total_pages": totalPages,
	})
}

// VerifyArchiveIntegrity verifies the integrity of an archived batch
// @Summary Verify archive integrity
// @Description Verifies the integrity of an archived audit log batch using SHA-256 checksum
// @Tags Audit
// @Security BearerAuth
// @Produce json
// @Param batch_id path string true "Archive batch ID"
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} models.ErrorResponse
// @Failure 401 {object} models.ErrorResponse
// @Failure 404 {object} models.ErrorResponse
// @Failure 500 {object} models.ErrorResponse
// @Failure 503 {object} models.ErrorResponse
// @Router /api/v1/auth/audit/archives/{batch_id}/verify [post]
func (h *AuditHandler) VerifyArchiveIntegrity(c *gin.Context) {
	user := middleware.GetCurrentUser(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	if h.archiverService == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "audit archiving not configured"})
		return
	}

	batchIDStr := c.Param("batch_id")
	batchID, err := uuid.Parse(batchIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid batch ID"})
		return
	}

	// Get archive metadata
	metadata, total, err := h.auditService.GetArchiveMetadata(c.Request.Context(), user.TenantID, 1, 1000)
	if err != nil {
		logger.Error("Failed to get archive metadata", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get archive metadata"})
		return
	}

	if total == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "archive batch not found"})
		return
	}

	// Find the specific batch
	var targetMetadata *models.AuditArchiveMetadata
	for _, m := range metadata {
		if m.ArchiveBatchID == batchID {
			targetMetadata = &m
			break
		}
	}

	if targetMetadata == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "archive batch not found"})
		return
	}

	// Verify integrity
	valid, err := h.archiverService.VerifyArchiveIntegrity(c.Request.Context(), targetMetadata)
	if err != nil {
		logger.Error("Failed to verify archive integrity",
			zap.Error(err),
			zap.String("batch_id", batchID.String()),
		)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to verify archive integrity"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"batch_id":         batchID.String(),
		"integrity_valid":  valid,
		"verified_at":      "now",
		"checksum_type":    "SHA-256",
		"object_locked":    targetMetadata.ObjectLockEnabled,
		"archive_location": fmt.Sprintf("s3://%s/%s", targetMetadata.S3Bucket, targetMetadata.S3Key),
	})
}

// ExportAuditReport exports audit logs for compliance reporting
// @Summary Export audit report
// @Description Exports audit logs as JSON for compliance reporting
// @Tags Audit
// @Security BearerAuth
// @Produce json
// @Param from query string true "Start date (RFC3339)"
// @Param to query string true "End date (RFC3339)"
// @Param action query string false "Filter by action"
// @Success 200 {array} models.AuditLogResponse
// @Failure 400 {object} models.ErrorResponse
// @Failure 401 {object} models.ErrorResponse
// @Failure 500 {object} models.ErrorResponse
// @Router /api/v1/auth/audit/export [get]
func (h *AuditHandler) ExportAuditReport(c *gin.Context) {
	user := middleware.GetCurrentUser(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	from := c.Query("from")
	to := c.Query("to")
	if from == "" || to == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "from and to parameters are required"})
		return
	}

	filters := map[string]interface{}{
		"from": from,
		"to":   to,
	}

	if action := c.Query("action"); action != "" {
		filters["action"] = action
	}

	// SECURITY: Limit export to max 1000 records to prevent memory exhaustion
	response, err := h.auditService.GetAuditLogs(c.Request.Context(), user.TenantID, 1, 1000, filters)
	if err != nil {
		logger.Error("Failed to export audit logs", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to export audit logs"})
		return
	}

	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=audit-logs-%s-to-%s.json", from, to))
	c.JSON(http.StatusOK, response.Logs)
}
