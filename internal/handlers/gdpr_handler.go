// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/middleware"
	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/internal/services"
	"github.com/dogukanturhal/falcon-id/pkg/logger"
	"github.com/dogukanturhal/falcon-id/pkg/redis"
)

const (
	msgNotAuthenticatedGDPR     = "Not authenticated"
	msgInvalidUserIDGDPR        = "Invalid user ID"
	msgUserNotFoundGDPR         = "User not found"
	msgInvalidDeletionRequestID = "Invalid deletion request ID"
	msgDeletionRequestNotFound  = "Deletion request not found"
	roleAdmin                   = "admin"
)

// GDPRHandler handles GDPR compliance endpoints
type GDPRHandler struct {
	dataExportService   *services.DataExportService
	dataDeletionService *services.DataDeletionService
	userService         *services.UserService
	rateLimiter         *redis.RateLimiter
}

// NewGDPRHandler creates a new GDPR handler
func NewGDPRHandler(
	dataExportService *services.DataExportService,
	dataDeletionService *services.DataDeletionService,
	userService *services.UserService,
	rateLimiter *redis.RateLimiter,
) *GDPRHandler {
	return &GDPRHandler{
		dataExportService:   dataExportService,
		dataDeletionService: dataDeletionService,
		userService:         userService,
		rateLimiter:         rateLimiter,
	}
}

// ExportUserData exports all user data in JSON or CSV format
// @Summary Export User Data
// @Description Export all user data for GDPR compliance (JSON or CSV format)
// @Tags GDPR
// @Produce json,text/csv
// @Security BearerAuth
// @Param id path string true "User ID"
// @Success 200 {object} services.UserExportData
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Failure 403 {object} map[string]string
// @Failure 429 {object} map[string]string
// @Router /api/v1/users/{id}/export [get]
func (h *GDPRHandler) ExportUserData(c *gin.Context) {
	currentUser := middleware.GetCurrentUser(c)
	if currentUser == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": msgNotAuthenticatedGDPR})
		return
	}

	userIDStr := c.Param("id")
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgInvalidUserIDGDPR})
		return
	}

	isAdmin := currentUserIsAdmin(currentUser)
	if !isAdmin && currentUser.ID != userID {
		c.JSON(http.StatusForbidden, gin.H{"error": "You can only export your own data"})
		return
	}

	if isAdmin && currentUser.ID != userID {
		if ok := h.verifyUserSameTenant(c, userID, currentUser.TenantID); !ok {
			return
		}
	}

	if !h.checkExportRateLimit(c, userID) {
		return
	}

	exportData, err := h.dataExportService.CollectUserData(c.Request.Context(), userID)
	if err != nil {
		logger.Error("Failed to collect user data for export",
			zap.String("user_id", userID.String()),
			zap.Error(err),
		)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to collect user data"})
		return
	}

	format := resolveExportFormat(c.GetHeader("Accept"))
	h.serveExportData(c, userID, format, exportData)

	logger.Info("User data exported successfully",
		zap.String("user_id", userID.String()),
		zap.String("format", format),
		zap.String("requested_by", currentUser.ID.String()),
	)
}

// ExportMyData lets the authenticated user export their OWN data (GDPR Art. 15
// right of access) WITHOUT the admin `core:users:read` permission that gates
// the /users/:id/export route. The subject is taken from the session, never
// the path, so it is owner-scoped by construction. Same 1-per-24h rate limit
// as the admin path (the limiter is keyed on the user id).
func (h *GDPRHandler) ExportMyData(c *gin.Context) {
	currentUser := middleware.GetCurrentUser(c)
	if currentUser == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": msgNotAuthenticatedGDPR})
		return
	}
	userID := currentUser.ID

	if !h.checkExportRateLimit(c, userID) {
		return
	}

	exportData, err := h.dataExportService.CollectUserData(c.Request.Context(), userID)
	if err != nil {
		logger.Error("Failed to collect user data for self-service export",
			zap.String("user_id", userID.String()),
			zap.Error(err),
		)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to collect user data"})
		return
	}

	format := resolveExportFormat(c.GetHeader("Accept"))
	h.serveExportData(c, userID, format, exportData)

	logger.Info("User self-service data export",
		zap.String("user_id", userID.String()),
		zap.String("format", format),
	)
}

// currentUserIsAdmin returns true when the current user holds an admin or platform_admin role.
func currentUserIsAdmin(u *models.CurrentUser) bool {
	for _, role := range u.Roles {
		if role == roleAdmin || role == "platform_admin" {
			return true
		}
	}
	return false
}

// verifyUserSameTenant checks that the target user exists and belongs to the same tenant.
// It writes the appropriate error response and returns false on failure.
func (h *GDPRHandler) verifyUserSameTenant(c *gin.Context, userID uuid.UUID, tenantID uuid.UUID) bool {
	if h.userService == nil {
		return true
	}
	targetUser, err := h.userService.GetByID(c.Request.Context(), userID)
	if err != nil || targetUser == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": msgUserNotFoundGDPR})
		return false
	}
	if targetUser.TenantID != tenantID {
		c.JSON(http.StatusNotFound, gin.H{"error": msgUserNotFoundGDPR})
		return false
	}
	return true
}

// checkExportRateLimit enforces the 1-per-24h rate limit for data exports.
// Returns false and writes the 429 response when the limit is exceeded.
func (h *GDPRHandler) checkExportRateLimit(c *gin.Context, userID uuid.UUID) bool {
	if h.rateLimiter == nil {
		return true
	}
	rateLimitKey := fmt.Sprintf("gdpr:export:%s", userID.String())
	result, err := h.rateLimiter.Check(c.Request.Context(), rateLimitKey, 1, 24*time.Hour, 24*time.Hour)
	if err != nil {
		logger.Warn("Rate limiter error", zap.Error(err))
		return true
	}
	if !result.Allowed {
		c.JSON(http.StatusTooManyRequests, gin.H{"error": "Rate limit exceeded. You can request data export once per 24 hours."})
		return false
	}
	return true
}

// resolveExportFormat returns "csv" when the Accept header requests CSV, otherwise "json".
func resolveExportFormat(acceptHeader string) string {
	if strings.Contains(acceptHeader, "text/csv") || strings.Contains(acceptHeader, "application/csv") {
		return "csv"
	}
	return "json"
}

// serveExportData writes the export file to the response in the requested format.
func (h *GDPRHandler) serveExportData(c *gin.Context, userID uuid.UUID, format string, exportData *services.UserExportData) {
	dateFmt := time.Now().Format("20060102")
	switch format {
	case "csv":
		csvData, err := h.dataExportService.ExportToCSV(exportData)
		if err != nil {
			logger.Error("Failed to export data to CSV", zap.Error(err))
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to export data"})
			return
		}
		filename := fmt.Sprintf("user_data_%s_%s.csv", userID.String(), dateFmt)
		c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=%s", filename))
		c.Data(http.StatusOK, "text/csv", csvData)
	default:
		jsonData, err := h.dataExportService.ExportToJSON(exportData)
		if err != nil {
			logger.Error("Failed to export data to JSON", zap.Error(err))
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to export data"})
			return
		}
		filename := fmt.Sprintf("user_data_%s_%s.json", userID.String(), dateFmt)
		c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=%s", filename))
		c.Data(http.StatusOK, "application/json", jsonData)
	}
}

// RequestDeletion creates a user data deletion request
// @Summary Request User Data Deletion
// @Description Request deletion of user data with 30-day grace period (GDPR right to be forgotten)
// @Tags GDPR
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param id path string true "User ID"
// @Param body body models.CreateDeletionRequestRequest false "Deletion request details"
// @Success 200 {object} models.DeletionRequestResponse
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Failure 403 {object} map[string]string
// @Router /api/v1/users/{id}/delete [delete]
func (h *GDPRHandler) RequestDeletion(c *gin.Context) {
	currentUser := middleware.GetCurrentUser(c)
	if currentUser == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": msgNotAuthenticatedGDPR})
		return
	}

	userIDStr := c.Param("id")
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgInvalidUserIDGDPR})
		return
	}

	isAdmin := currentUserIsAdmin(currentUser)
	if !isAdmin && currentUser.ID != userID {
		c.JSON(http.StatusForbidden, gin.H{"error": "You can only request deletion of your own data"})
		return
	}
	if isAdmin && currentUser.ID != userID {
		if ok := h.verifyUserSameTenant(c, userID, currentUser.TenantID); !ok {
			return
		}
	}

	// Parse request body (optional)
	var req models.CreateDeletionRequestRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		// Body is optional
		req.UserID = userID
	}

	tenantID := middleware.GetTenantID(c)
	requestedBy := &currentUser.ID

	// Create deletion request
	deletionRequest, err := h.dataDeletionService.RequestDeletion(
		c.Request.Context(),
		userID,
		tenantID,
		requestedBy,
		req.Notes,
	)
	if err != nil {
		logger.Error("Failed to create deletion request",
			zap.String("user_id", userID.String()),
			zap.Error(err),
		)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create deletion request"})
		return
	}

	logger.Info("Deletion request created",
		zap.String("request_id", deletionRequest.ID.String()),
		zap.String("user_id", userID.String()),
		zap.String("requested_by", currentUser.ID.String()),
	)

	c.JSON(http.StatusOK, deletionRequest.ToResponse())
}

// GetDeletionRequest retrieves the status of a deletion request
// @Summary Get Deletion Request Status
// @Description Get the status of a user data deletion request
// @Tags GDPR
// @Produce json
// @Security BearerAuth
// @Param id path string true "User ID"
// @Success 200 {object} models.DeletionRequestResponse
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Failure 404 {object} map[string]string
// @Router /api/v1/users/{id}/deletion-status [get]
func (h *GDPRHandler) GetDeletionRequest(c *gin.Context) {
	currentUser := middleware.GetCurrentUser(c)
	if currentUser == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": msgNotAuthenticatedGDPR})
		return
	}

	userIDStr := c.Param("id")
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgInvalidUserIDGDPR})
		return
	}

	isAdmin := currentUserIsAdmin(currentUser)
	if !isAdmin && currentUser.ID != userID {
		c.JSON(http.StatusForbidden, gin.H{"error": "You can only view your own deletion status"})
		return
	}
	if isAdmin && currentUser.ID != userID {
		if ok := h.verifyUserSameTenant(c, userID, currentUser.TenantID); !ok {
			return
		}
	}

	// Get deletion request (latest one for the user)
	ctx := c.Request.Context()
	deletionRepo := services.NewDeletionRepository(h.dataDeletionService.GetDB())
	deletionRequest, err := deletionRepo.GetByUserID(ctx, userID)
	if err != nil {
		logger.Error("Failed to get deletion request",
			zap.String("user_id", userID.String()),
			zap.Error(err),
		)
		c.JSON(http.StatusNotFound, gin.H{"error": "No deletion request found"})
		return
	}

	c.JSON(http.StatusOK, deletionRequest.ToResponse())
}

// CancelDeletion cancels a pending deletion request
// @Summary Cancel Deletion Request
// @Description Cancel a pending user data deletion request (within grace period)
// @Tags GDPR
// @Produce json
// @Security BearerAuth
// @Param id path string true "Deletion Request ID"
// @Success 200 {object} map[string]string
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Failure 403 {object} map[string]string
// @Router /api/v1/deletion-requests/{id}/cancel [post]
func (h *GDPRHandler) CancelDeletion(c *gin.Context) {
	currentUser := middleware.GetCurrentUser(c)
	if currentUser == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": msgNotAuthenticatedGDPR})
		return
	}

	// Parse deletion request ID from path
	requestIDStr := c.Param("id")
	requestID, err := uuid.Parse(requestIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgInvalidDeletionRequestID})
		return
	}

	// Get the deletion request to check ownership
	deletionRequest, err := h.dataDeletionService.GetDeletionRequest(c.Request.Context(), requestID)
	if err != nil || deletionRequest == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": msgDeletionRequestNotFound})
		return
	}

	// Verify the deletion request belongs to the current tenant
	if deletionRequest.TenantID != currentUser.TenantID {
		c.JSON(http.StatusNotFound, gin.H{"error": msgDeletionRequestNotFound})
		return
	}

	isAdmin := currentUserIsAdmin(currentUser)
	if !isAdmin && currentUser.ID != deletionRequest.UserID {
		c.JSON(http.StatusForbidden, gin.H{"error": "You can only cancel your own deletion requests"})
		return
	}

	// Cancel the deletion request
	if err := h.dataDeletionService.CancelDeletion(c.Request.Context(), requestID, currentUser.ID); err != nil {
		logger.Error("Failed to cancel deletion request",
			zap.String("request_id", requestID.String()),
			zap.Error(err),
		)
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	logger.Info("Deletion request cancelled",
		zap.String("request_id", requestID.String()),
		zap.String("cancelled_by", currentUser.ID.String()),
	)

	c.JSON(http.StatusOK, gin.H{"message": "Deletion request cancelled successfully"})
}

// SetLegalHold sets a legal hold on a deletion request (admin only)
// @Summary Set Legal Hold
// @Description Set a legal hold on a deletion request to prevent deletion
// @Tags GDPR
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param id path string true "Deletion Request ID"
// @Param body body object{reason=string} true "Legal hold reason"
// @Success 200 {object} map[string]string
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Failure 403 {object} map[string]string
// @Router /api/v1/deletion-requests/{id}/legal-hold [post]
func (h *GDPRHandler) SetLegalHold(c *gin.Context) {
	currentUser := middleware.GetCurrentUser(c)
	if currentUser == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": msgNotAuthenticatedGDPR})
		return
	}

	if !currentUserIsAdmin(currentUser) {
		c.JSON(http.StatusForbidden, gin.H{"error": "Only administrators can set legal holds"})
		return
	}

	// Parse deletion request ID
	requestIDStr := c.Param("id")
	requestID, err := uuid.Parse(requestIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgInvalidDeletionRequestID})
		return
	}

	// Parse request body
	var req struct {
		Reason string `json:"reason" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Reason is required"})
		return
	}

	// Verify the deletion request belongs to the current tenant
	deletionRequest, err := h.dataDeletionService.GetDeletionRequest(c.Request.Context(), requestID)
	if err != nil || deletionRequest == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": msgDeletionRequestNotFound})
		return
	}
	if deletionRequest.TenantID != currentUser.TenantID {
		c.JSON(http.StatusNotFound, gin.H{"error": msgDeletionRequestNotFound})
		return
	}

	// Set legal hold
	if err := h.dataDeletionService.SetLegalHold(c.Request.Context(), requestID, req.Reason, currentUser.ID); err != nil {
		logger.Error("Failed to set legal hold",
			zap.String("request_id", requestID.String()),
			zap.Error(err),
		)
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	logger.Info("Legal hold set",
		zap.String("request_id", requestID.String()),
		zap.String("set_by", currentUser.ID.String()),
		zap.String("reason", req.Reason),
	)

	c.JSON(http.StatusOK, gin.H{"message": "Legal hold set successfully"})
}

// RemoveLegalHold removes a legal hold from a deletion request (admin only)
// @Summary Remove Legal Hold
// @Description Remove a legal hold from a deletion request
// @Tags GDPR
// @Produce json
// @Security BearerAuth
// @Param id path string true "Deletion Request ID"
// @Success 200 {object} map[string]string
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Failure 403 {object} map[string]string
// @Router /api/v1/deletion-requests/{id}/legal-hold [delete]
func (h *GDPRHandler) RemoveLegalHold(c *gin.Context) {
	currentUser := middleware.GetCurrentUser(c)
	if currentUser == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": msgNotAuthenticatedGDPR})
		return
	}

	if !currentUserIsAdmin(currentUser) {
		c.JSON(http.StatusForbidden, gin.H{"error": "Only administrators can remove legal holds"})
		return
	}

	// Parse deletion request ID
	requestIDStr := c.Param("id")
	requestID, err := uuid.Parse(requestIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgInvalidDeletionRequestID})
		return
	}

	// Verify the deletion request belongs to the current tenant
	deletionRequest, err := h.dataDeletionService.GetDeletionRequest(c.Request.Context(), requestID)
	if err != nil || deletionRequest == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": msgDeletionRequestNotFound})
		return
	}
	if deletionRequest.TenantID != currentUser.TenantID {
		c.JSON(http.StatusNotFound, gin.H{"error": msgDeletionRequestNotFound})
		return
	}

	// Remove legal hold
	if err := h.dataDeletionService.RemoveLegalHold(c.Request.Context(), requestID, currentUser.ID); err != nil {
		logger.Error("Failed to remove legal hold",
			zap.String("request_id", requestID.String()),
			zap.Error(err),
		)
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	logger.Info("Legal hold removed",
		zap.String("request_id", requestID.String()),
		zap.String("removed_by", currentUser.ID.String()),
	)

	c.JSON(http.StatusOK, gin.H{"message": "Legal hold removed successfully"})
}
