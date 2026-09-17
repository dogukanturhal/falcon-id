// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"context"
	"net/http"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/services"
)

// complianceLiveEvidenceService is the interface used by ComplianceEvidenceHandler.
// It is satisfied by *services.ComplianceLiveEvidenceService and enables
// straightforward test substitution.
type complianceLiveEvidenceService interface {
	GenerateSOC2Report(ctx context.Context) (*services.ComplianceReport, error)
	GenerateGDPRReport(ctx context.Context) (*services.ComplianceReport, error)
	GenerateKVKKReport(ctx context.Context) (*services.ComplianceReport, error)
}

// ComplianceEvidenceHandler handles live compliance evidence HTTP endpoints.
type ComplianceEvidenceHandler struct {
	svc    complianceLiveEvidenceService
	logger *zap.Logger
}

// NewComplianceEvidenceHandler creates a ComplianceEvidenceHandler.
func NewComplianceEvidenceHandler(svc complianceLiveEvidenceService, log *zap.Logger) *ComplianceEvidenceHandler {
	if log == nil {
		log = zap.NewNop()
	}
	return &ComplianceEvidenceHandler{svc: svc, logger: log}
}

// SOC2Report handles GET /api/v1/platform/compliance/soc2.
//
// @Summary Generate SOC2 Type II evidence report
// @Description Generates a live SOC2 evidence report by querying system state
// @Tags Compliance
// @Produce json
// @Success 200 {object} services.ComplianceReport "SOC2 compliance report"
// @Failure 500 {object} map[string]string "Internal server error"
// @Router /api/v1/platform/compliance/soc2 [get]
func (h *ComplianceEvidenceHandler) SOC2Report(c *gin.Context) {
	report, err := h.svc.GenerateSOC2Report(c.Request.Context())
	if err != nil {
		h.logger.Error("ComplianceEvidenceHandler.SOC2Report failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate SOC2 report"})
		return
	}
	c.JSON(http.StatusOK, report)
}

// GDPRReport handles GET /api/v1/platform/compliance/gdpr.
//
// @Summary Generate GDPR Article 30 compliance report
// @Description Generates a live GDPR evidence report by querying system state
// @Tags Compliance
// @Produce json
// @Success 200 {object} services.ComplianceReport "GDPR compliance report"
// @Failure 500 {object} map[string]string "Internal server error"
// @Router /api/v1/platform/compliance/gdpr [get]
func (h *ComplianceEvidenceHandler) GDPRReport(c *gin.Context) {
	report, err := h.svc.GenerateGDPRReport(c.Request.Context())
	if err != nil {
		h.logger.Error("ComplianceEvidenceHandler.GDPRReport failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate GDPR report"})
		return
	}
	c.JSON(http.StatusOK, report)
}

// KVKKReport handles GET /api/v1/platform/compliance/kvkk.
//
// @Summary Generate KVKK compliance report
// @Description Generates a live KVKK (Turkish data protection) evidence report
// @Tags Compliance
// @Produce json
// @Success 200 {object} services.ComplianceReport "KVKK compliance report"
// @Failure 500 {object} map[string]string "Internal server error"
// @Router /api/v1/platform/compliance/kvkk [get]
func (h *ComplianceEvidenceHandler) KVKKReport(c *gin.Context) {
	report, err := h.svc.GenerateKVKKReport(c.Request.Context())
	if err != nil {
		h.logger.Error("ComplianceEvidenceHandler.KVKKReport failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate KVKK report"})
		return
	}
	c.JSON(http.StatusOK, report)
}
