// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/pkg/logger"
)

const (
	complianceStatusPass    = "pass"
	complianceStatusFail    = "fail"
	complianceStatusWarning = "warning"
)

// ---------------------------------------------------------------------------
// Evidence output types
// ---------------------------------------------------------------------------

// EvidencePackage is the top-level structure exported by ExportEvidencePackage.
// It is serialised to JSON and can be attached to audit reports or forwarded
// to a compliance management system.
type EvidencePackage struct {
	TenantID    uuid.UUID         `json:"tenant_id"`
	Framework   string            `json:"framework"`
	GeneratedAt time.Time         `json:"generated_at"`
	Period      EvidencePeriod    `json:"period"`
	Controls    []ControlEvidence `json:"controls"`
	Summary     EvidenceSummary   `json:"summary"`
}

// EvidencePeriod captures the date range over which evidence was collected.
type EvidencePeriod struct {
	From time.Time `json:"from"`
	To   time.Time `json:"to"`
}

// ControlEvidence holds the evaluation result and raw evidence for a single
// control within an EvidencePackage.
type ControlEvidence struct {
	ControlID      string         `json:"control_id"`
	Name           string         `json:"name"`
	Status         string         `json:"status"` // "pass", "fail", "warning", "not_evaluated"
	LastEvaluated  time.Time      `json:"last_evaluated"`
	Evidence       EvidenceDetail `json:"evidence"`
	Recommendation string         `json:"recommendation,omitempty"`
}

// EvidenceDetail captures the raw query result and metadata for a single
// control evaluation, providing auditors with the full evidence chain.
type EvidenceDetail struct {
	QueryExecuted string      `json:"query_executed,omitempty"`
	ResultValue   string      `json:"result_value"`
	ExpectedValue string      `json:"expected_value"`
	Timestamp     time.Time   `json:"timestamp"`
	RawResults    interface{} `json:"raw_results,omitempty"`
}

// EvidenceSummary aggregates pass/fail counts for the evidence package.
type EvidenceSummary struct {
	TotalControls int     `json:"total_controls"`
	PassCount     int     `json:"pass_count"`
	FailCount     int     `json:"fail_count"`
	ErrorCount    int     `json:"error_count"`
	Score         float64 `json:"score"` // pass / total * 100
}

// ComplianceReportOutput is the structured output of GenerateComplianceReport.
type ComplianceReportOutput struct {
	TenantID    uuid.UUID         `json:"tenant_id"`
	Framework   string            `json:"framework"`
	GeneratedAt time.Time         `json:"generated_at"`
	Controls    []ControlEvidence `json:"controls"`
	Summary     EvidenceSummary   `json:"summary"`
}

// ---------------------------------------------------------------------------
// Repository interface
// ---------------------------------------------------------------------------

// complianceEvidenceRepository abstracts the database queries needed by
// ComplianceEvidenceService, enabling straightforward unit testing with mocks.
type complianceEvidenceRepository interface {
	// ListLatestEvaluationsByFramework returns the most recent evaluation for
	// each control that belongs to the specified framework, filtered by the
	// tenant and evaluated within [from, to].
	ListLatestEvaluationsByFramework(
		ctx context.Context,
		tenantID uuid.UUID,
		framework string,
		from, to time.Time,
	) ([]ComplianceEvaluation, error)

	// GetControlByRef returns a control definition by (framework, control_ref).
	// Used to hydrate control names for evidence packaging.
	GetControlByRef(ctx context.Context, framework, controlRef string) (*ComplianceControl, error)
}

// ---------------------------------------------------------------------------
// Service
// ---------------------------------------------------------------------------

// ComplianceEvidenceService generates structured evidence packages and
// compliance reports suitable for auditor review or automated compliance
// management system ingestion.
type ComplianceEvidenceService struct {
	repo complianceEvidenceRepository
}

// NewComplianceEvidenceService creates a ComplianceEvidenceService backed by
// the provided repository implementation.
func NewComplianceEvidenceService(repo complianceEvidenceRepository) *ComplianceEvidenceService {
	return &ComplianceEvidenceService{repo: repo}
}

// ---------------------------------------------------------------------------
// ExportEvidencePackage
// ---------------------------------------------------------------------------

// ExportEvidencePackage generates a JSON-serialised EvidencePackage for the
// given tenant and compliance framework covering the specified time range.
//
// The returned byte slice is valid JSON suitable for file storage, API
// response bodies, or direct upload to a compliance management system.
func (s *ComplianceEvidenceService) ExportEvidencePackage(
	ctx context.Context,
	tenantID uuid.UUID,
	framework string,
	from, to time.Time,
) ([]byte, error) {
	evals, err := s.repo.ListLatestEvaluationsByFramework(ctx, tenantID, framework, from, to)
	if err != nil {
		return nil, fmt.Errorf("ExportEvidencePackage: list evaluations: %w", err)
	}

	pkg := EvidencePackage{
		TenantID:    tenantID,
		Framework:   framework,
		GeneratedAt: time.Now().UTC(),
		Period: EvidencePeriod{
			From: from,
			To:   to,
		},
		Controls: make([]ControlEvidence, 0, len(evals)),
	}

	for i := range evals {
		ce := buildControlEvidence(&evals[i])
		pkg.Controls = append(pkg.Controls, ce)
	}

	pkg.Summary = computeSummary(pkg.Controls)

	data, err := json.Marshal(pkg)
	if err != nil {
		return nil, fmt.Errorf("ExportEvidencePackage: marshal: %w", err)
	}

	logger.Log.Info("ComplianceEvidenceService.ExportEvidencePackage: generated",
		zap.String("tenant_id", tenantID.String()),
		zap.String("framework", framework),
		zap.Int("controls", len(pkg.Controls)),
		zap.Float64("score", pkg.Summary.Score),
	)

	return data, nil
}

// ---------------------------------------------------------------------------
// GenerateComplianceReport
// ---------------------------------------------------------------------------

// GenerateComplianceReport produces a ComplianceReportOutput for the given
// tenant and framework covering the past 90 days. The report includes per-control
// evidence, recommendations for failing controls, and an overall summary.
func (s *ComplianceEvidenceService) GenerateComplianceReport(
	ctx context.Context,
	tenantID uuid.UUID,
	framework string,
) (*ComplianceReportOutput, error) {
	to := time.Now().UTC()
	from := to.Add(-90 * 24 * time.Hour)

	evals, err := s.repo.ListLatestEvaluationsByFramework(ctx, tenantID, framework, from, to)
	if err != nil {
		return nil, fmt.Errorf("GenerateComplianceReport: list evaluations: %w", err)
	}

	report := &ComplianceReportOutput{
		TenantID:    tenantID,
		Framework:   framework,
		GeneratedAt: time.Now().UTC(),
		Controls:    make([]ControlEvidence, 0, len(evals)),
	}

	for i := range evals {
		ce := buildControlEvidence(&evals[i])
		if ce.Status == complianceStatusFail && ce.Recommendation == "" {
			ce.Recommendation = defaultRecommendation(evals[i].ControlRef, string(evals[i].Framework))
		}
		report.Controls = append(report.Controls, ce)
	}

	report.Summary = computeSummary(report.Controls)

	logger.Log.Info("ComplianceEvidenceService.GenerateComplianceReport: generated",
		zap.String("tenant_id", tenantID.String()),
		zap.String("framework", framework),
		zap.Float64("score", report.Summary.Score),
	)

	return report, nil
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

// buildControlEvidence converts a ComplianceEvaluation into a ControlEvidence
// record suitable for inclusion in an evidence package or compliance report.
func buildControlEvidence(ev *ComplianceEvaluation) ControlEvidence {
	status := evidenceStatus(ev.Status)

	// Extract query metadata from the Details JSON blob when present.
	queryExecuted := ""
	var rawResults interface{}
	if len(ev.Details) > 0 {
		var details map[string]interface{}
		if err := json.Unmarshal(ev.Details, &details); err == nil {
			if q, ok := details["query"].(string); ok {
				queryExecuted = q
			}
			rawResults = details
		}
	}

	recommendation := ""
	if status == complianceStatusFail {
		recommendation = defaultRecommendation(ev.ControlRef, string(ev.Framework))
	}

	return ControlEvidence{
		ControlID:     ev.ControlRef,
		Name:          ev.ControlRef, // hydrated from catalogue when available
		Status:        status,
		LastEvaluated: ev.EvaluatedAt,
		Evidence: EvidenceDetail{
			QueryExecuted: queryExecuted,
			ResultValue:   strconv.FormatFloat(ev.ActualValue, 'f', 4, 64),
			ExpectedValue: strconv.FormatFloat(ev.ExpectedValue, 'f', 4, 64),
			Timestamp:     ev.EvaluatedAt,
			RawResults:    rawResults,
		},
		Recommendation: recommendation,
	}
}

// evidenceStatus converts the internal evaluation status ("pass", "fail",
// "error", "skip") to the schema's external evidence status.
func evidenceStatus(internalStatus string) string {
	switch internalStatus {
	case complianceStatusPass:
		return complianceStatusPass
	case complianceStatusFail:
		return complianceStatusFail
	case complianceStatusWarning:
		return complianceStatusWarning
	default:
		// "error", "skip", "pending", or anything unexpected maps to not_evaluated.
		return "not_evaluated"
	}
}

// computeSummary tallies pass/fail/error counts and derives the compliance score.
func computeSummary(controls []ControlEvidence) EvidenceSummary {
	s := EvidenceSummary{
		TotalControls: len(controls),
	}
	for i := range controls {
		switch controls[i].Status {
		case complianceStatusPass:
			s.PassCount++
		case complianceStatusFail:
			s.FailCount++
		default:
			s.ErrorCount++
		}
	}
	if s.TotalControls > 0 {
		s.Score = float64(s.PassCount) / float64(s.TotalControls) * 100
	} else {
		s.Score = 100 // no controls = fully compliant by convention
	}
	return s
}

// defaultRecommendation returns a human-readable remediation hint for a
// control identified by its ref and framework. This is a best-effort lookup
// against the in-memory seed catalogue; it falls back to a generic message.
func defaultRecommendation(controlRef string, framework string) string {
	fw := ComplianceFramework(framework)
	for _, sc := range defaultSeedControls() {
		if sc.Framework == fw && sc.ControlID == controlRef {
			if sc.RemediationHint != "" {
				return sc.RemediationHint
			}
		}
	}
	return fmt.Sprintf("Review and remediate control %s to achieve compliance with %s.", controlRef, framework)
}
