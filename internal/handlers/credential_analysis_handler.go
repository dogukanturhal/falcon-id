// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"

	"github.com/dogukanturhal/falcon-id/internal/services"
)

// CredentialAnalysisHandler provides endpoints for unused/stale credential analysis.
type CredentialAnalysisHandler struct {
	svc *services.SPCredentialService
}

// NewCredentialAnalysisHandler creates a new CredentialAnalysisHandler.
func NewCredentialAnalysisHandler(svc *services.SPCredentialService) *CredentialAnalysisHandler {
	return &CredentialAnalysisHandler{svc: svc}
}

// AnalyzeUsage returns a platform-wide usage summary for active credentials.
// GET /api/v1/platform/credential-analysis/usage
func (h *CredentialAnalysisHandler) AnalyzeUsage(c *gin.Context) {
	summary, err := h.svc.AnalyzeCredentialUsage(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to analyze credential usage"})
		return
	}
	c.JSON(http.StatusOK, summary)
}

// ListUnused returns all active credentials that have not been used within the
// requested number of days. Defaults to 90 days when the ?days query param is absent.
// GET /api/v1/platform/credential-analysis/unused?days=90
func (h *CredentialAnalysisHandler) ListUnused(c *gin.Context) {
	days := 90
	if daysStr := c.Query("days"); daysStr != "" {
		parsed, err := strconv.Atoi(daysStr)
		if err != nil || parsed < 1 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "days must be a positive integer"})
			return
		}
		days = parsed
	}

	creds, err := h.svc.ListUnusedCredentials(c.Request.Context(), days)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list unused credentials"})
		return
	}

	responses := make([]interface{}, 0, len(creds))
	for i := range creds {
		responses = append(responses, creds[i].ToResponse())
	}

	c.JSON(http.StatusOK, gin.H{
		"credentials": responses,
		"total":       len(creds),
		"unused_days": days,
	})
}
