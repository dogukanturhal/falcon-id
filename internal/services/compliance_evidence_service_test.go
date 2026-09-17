// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Mock: ComplianceEvidenceRepository
// ---------------------------------------------------------------------------

// mockEvidenceRepo implements complianceEvidenceRepository for testing.
type mockEvidenceRepo struct {
	mock.Mock
}

func (m *mockEvidenceRepo) ListLatestEvaluationsByFramework(
	ctx context.Context,
	tenantID uuid.UUID,
	framework string,
	from, to time.Time,
) ([]ComplianceEvaluation, error) {
	args := m.Called(ctx, tenantID, framework, from, to)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]ComplianceEvaluation), args.Error(1)
}

func (m *mockEvidenceRepo) GetControlByRef(
	ctx context.Context,
	framework, controlRef string,
) (*ComplianceControl, error) {
	args := m.Called(ctx, framework, controlRef)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*ComplianceControl), args.Error(1)
}

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

func evaluationFixture(controlRef, status string, actual, expected float64) ComplianceEvaluation {
	details, _ := json.Marshal(map[string]interface{}{
		"check_type":   "percentage_check",
		"operator":     ">=",
		"threshold":    expected,
		"actual_value": actual,
		"query":        "SELECT 95",
	})
	return ComplianceEvaluation{
		ID:             uuid.New(),
		PolicyID:       uuid.New(),
		TenantID:       uuid.New(),
		ControlID:      uuid.New(),
		Framework:      FrameworkSOC2,
		ControlRef:     controlRef,
		Status:         status,
		ActualValue:    actual,
		ExpectedValue:  expected,
		DriftDetected:  false,
		Details:        details,
		RemediationRun: false,
		EvaluatedAt:    time.Now(),
	}
}

// ---------------------------------------------------------------------------
// TestExportEvidencePackage_ValidJSON
// ---------------------------------------------------------------------------

// TestExportEvidencePackage_ValidJSON verifies that ExportEvidencePackage
// returns well-formed JSON containing the expected top-level keys.
func TestExportEvidencePackage_ValidJSON(t *testing.T) {
	repo := new(mockEvidenceRepo)
	svc := NewComplianceEvidenceService(repo)

	tenantID := uuid.New()
	from := time.Now().Add(-30 * 24 * time.Hour)
	to := time.Now()

	evals := []ComplianceEvaluation{
		evaluationFixture("CC6.1-MFA", "pass", 95, 90),
		evaluationFixture("CC6.2-PASSWD", "fail", 0, 1),
	}

	repo.On("ListLatestEvaluationsByFramework",
		mock.Anything, tenantID, "SOC2", from, to).
		Return(evals, nil)

	data, err := svc.ExportEvidencePackage(context.Background(), tenantID, "SOC2", from, to)
	require.NoError(t, err)
	require.NotEmpty(t, data)

	var pkg EvidencePackage
	require.NoError(t, json.Unmarshal(data, &pkg), "output must be valid JSON")

	assert.Equal(t, tenantID, pkg.TenantID)
	assert.Equal(t, "SOC2", pkg.Framework)
	assert.NotZero(t, pkg.GeneratedAt)
	// JSON round-trip strips the monotonic clock reading; compare wall-clock only.
	assert.True(t, pkg.Period.From.Equal(from), "period.from mismatch")
	assert.True(t, pkg.Period.To.Equal(to), "period.to mismatch")
	assert.Len(t, pkg.Controls, 2)
	assert.NotNil(t, pkg.Summary)
}

// ---------------------------------------------------------------------------
// TestExportEvidencePackage_IncludesAllControls
// ---------------------------------------------------------------------------

// TestExportEvidencePackage_IncludesAllControls verifies that every evaluation
// returned by the repository appears in the exported package.
func TestExportEvidencePackage_IncludesAllControls(t *testing.T) {
	repo := new(mockEvidenceRepo)
	svc := NewComplianceEvidenceService(repo)

	tenantID := uuid.New()
	from := time.Now().Add(-7 * 24 * time.Hour)
	to := time.Now()

	evals := []ComplianceEvaluation{
		evaluationFixture("CC6.1-MFA", "pass", 95, 90),
		evaluationFixture("CC6.2-PASSWD", "pass", 1, 1),
		evaluationFixture("CC6.3-SESSION", "fail", 0, 1),
		evaluationFixture("CC6.7-RETENTION", "pass", 5, 1),
	}

	repo.On("ListLatestEvaluationsByFramework",
		mock.Anything, tenantID, "SOC2", from, to).
		Return(evals, nil)

	data, err := svc.ExportEvidencePackage(context.Background(), tenantID, "SOC2", from, to)
	require.NoError(t, err)

	var pkg EvidencePackage
	require.NoError(t, json.Unmarshal(data, &pkg))
	assert.Len(t, pkg.Controls, len(evals),
		"every evaluation must appear in the exported controls")

	// Verify control refs are present.
	refs := map[string]bool{}
	for _, ce := range pkg.Controls {
		refs[ce.ControlID] = true
	}
	for _, ev := range evals {
		assert.True(t, refs[ev.ControlRef],
			"control %s must appear in evidence package", ev.ControlRef)
	}
}

// ---------------------------------------------------------------------------
// TestExportEvidencePackage_DateRangeFiltering
// ---------------------------------------------------------------------------

// TestExportEvidencePackage_DateRangeFiltering verifies that the from/to range
// is forwarded correctly to the repository and that empty results yield an
// empty controls slice (not an error).
func TestExportEvidencePackage_DateRangeFiltering(t *testing.T) {
	repo := new(mockEvidenceRepo)
	svc := NewComplianceEvidenceService(repo)

	tenantID := uuid.New()
	from := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	to := time.Date(2025, 3, 31, 23, 59, 59, 0, time.UTC)

	repo.On("ListLatestEvaluationsByFramework",
		mock.Anything, tenantID, "GDPR", from, to).
		Return([]ComplianceEvaluation{}, nil)

	data, err := svc.ExportEvidencePackage(context.Background(), tenantID, "GDPR", from, to)
	require.NoError(t, err)

	var pkg EvidencePackage
	require.NoError(t, json.Unmarshal(data, &pkg))
	// JSON round-trip strips the monotonic clock; compare wall-clock only.
	assert.True(t, pkg.Period.From.Equal(from), "period.from mismatch")
	assert.True(t, pkg.Period.To.Equal(to), "period.to mismatch")
	assert.Empty(t, pkg.Controls)

	repo.AssertCalled(t, "ListLatestEvaluationsByFramework",
		mock.Anything, tenantID, "GDPR", from, to)
}

// TestExportEvidencePackage_RepoError surfaces repository errors.
func TestExportEvidencePackage_RepoError(t *testing.T) {
	repo := new(mockEvidenceRepo)
	svc := NewComplianceEvidenceService(repo)

	tenantID := uuid.New()
	from := time.Now().Add(-24 * time.Hour)
	to := time.Now()

	repo.On("ListLatestEvaluationsByFramework",
		mock.Anything, tenantID, "SOC2", from, to).
		Return(nil, errors.New("database connection refused"))

	data, err := svc.ExportEvidencePackage(context.Background(), tenantID, "SOC2", from, to)
	require.Error(t, err)
	assert.Nil(t, data)
	assert.Contains(t, err.Error(), "ExportEvidencePackage")
}

// ---------------------------------------------------------------------------
// TestGenerateComplianceReport_FrameworkSpecific
// ---------------------------------------------------------------------------

// TestGenerateComplianceReport_FrameworkSpecific verifies that the report is
// scoped to the requested framework and that pass/fail counts are accurate.
func TestGenerateComplianceReport_FrameworkSpecific(t *testing.T) {
	repo := new(mockEvidenceRepo)
	svc := NewComplianceEvidenceService(repo)

	tenantID := uuid.New()

	evals := []ComplianceEvaluation{
		evaluationFixture("CC6.1-MFA", "pass", 95, 90),
		evaluationFixture("CC6.2-PASSWD", "pass", 1, 1),
		evaluationFixture("CC6.3-SESSION", "fail", 0, 1),
	}

	// GenerateComplianceReport uses a 90-day window by default.
	repo.On("ListLatestEvaluationsByFramework",
		mock.Anything, tenantID, "SOC2",
		mock.AnythingOfType("time.Time"),
		mock.AnythingOfType("time.Time")).
		Return(evals, nil)

	report, err := svc.GenerateComplianceReport(context.Background(), tenantID, "SOC2")
	require.NoError(t, err)
	require.NotNil(t, report)

	assert.Equal(t, "SOC2", report.Framework)
	assert.Equal(t, tenantID, report.TenantID)
	assert.Equal(t, 3, report.Summary.TotalControls)
	assert.Equal(t, 2, report.Summary.PassCount)
	assert.Equal(t, 1, report.Summary.FailCount)
	assert.InDelta(t, 66.67, report.Summary.Score, 0.5)
}

// ---------------------------------------------------------------------------
// TestGenerateComplianceReport_RecommendationsGenerated
// ---------------------------------------------------------------------------

// TestGenerateComplianceReport_RecommendationsGenerated verifies that every
// failing control in the report has a non-empty recommendation.
func TestGenerateComplianceReport_RecommendationsGenerated(t *testing.T) {
	repo := new(mockEvidenceRepo)
	svc := NewComplianceEvidenceService(repo)

	tenantID := uuid.New()

	evals := []ComplianceEvaluation{
		evaluationFixture("CC6.1-MFA", "fail", 70, 90),
		evaluationFixture("CC6.3-SESSION", "fail", 0, 1),
	}

	repo.On("ListLatestEvaluationsByFramework",
		mock.Anything, tenantID, "SOC2",
		mock.AnythingOfType("time.Time"),
		mock.AnythingOfType("time.Time")).
		Return(evals, nil)

	report, err := svc.GenerateComplianceReport(context.Background(), tenantID, "SOC2")
	require.NoError(t, err)

	for _, ce := range report.Controls {
		if ce.Status == "fail" {
			assert.NotEmpty(t, ce.Recommendation,
				"failing control %s must have a recommendation", ce.ControlID)
		}
	}
}

// ---------------------------------------------------------------------------
// TestGenerateComplianceReport_EvidenceStructure
// ---------------------------------------------------------------------------

// TestGenerateComplianceReport_EvidenceStructure verifies that each control
// in the report has properly populated Evidence fields.
func TestGenerateComplianceReport_EvidenceStructure(t *testing.T) {
	repo := new(mockEvidenceRepo)
	svc := NewComplianceEvidenceService(repo)

	tenantID := uuid.New()
	eval := evaluationFixture("CC6.1-MFA", "pass", 95, 90)

	repo.On("ListLatestEvaluationsByFramework",
		mock.Anything, tenantID, "SOC2",
		mock.AnythingOfType("time.Time"),
		mock.AnythingOfType("time.Time")).
		Return([]ComplianceEvaluation{eval}, nil)

	report, err := svc.GenerateComplianceReport(context.Background(), tenantID, "SOC2")
	require.NoError(t, err)
	require.Len(t, report.Controls, 1)

	ce := report.Controls[0]
	assert.Equal(t, eval.ControlRef, ce.ControlID)
	assert.Equal(t, "pass", ce.Status)
	assert.NotZero(t, ce.LastEvaluated)
	assert.NotEmpty(t, ce.Evidence.ResultValue)
	assert.NotEmpty(t, ce.Evidence.ExpectedValue)
	assert.NotZero(t, ce.Evidence.Timestamp)
}

// ---------------------------------------------------------------------------
// TestGenerateComplianceReport_AllStatuses
// ---------------------------------------------------------------------------

// TestGenerateComplianceReport_AllStatuses verifies pass, fail, and error
// statuses are all counted correctly in the summary.
func TestGenerateComplianceReport_AllStatuses(t *testing.T) {
	repo := new(mockEvidenceRepo)
	svc := NewComplianceEvidenceService(repo)

	tenantID := uuid.New()

	evals := []ComplianceEvaluation{
		evaluationFixture("CC6.1-MFA", "pass", 95, 90),
		evaluationFixture("CC6.2-PASSWD", "fail", 0, 1),
		evaluationFixture("CC7.1-AUDIT", "error", 0, 1),
	}

	repo.On("ListLatestEvaluationsByFramework",
		mock.Anything, tenantID, "SOC2",
		mock.AnythingOfType("time.Time"),
		mock.AnythingOfType("time.Time")).
		Return(evals, nil)

	report, err := svc.GenerateComplianceReport(context.Background(), tenantID, "SOC2")
	require.NoError(t, err)
	assert.Equal(t, 3, report.Summary.TotalControls)
	assert.Equal(t, 1, report.Summary.PassCount)
	assert.Equal(t, 1, report.Summary.FailCount)
	assert.Equal(t, 1, report.Summary.ErrorCount)
}

// ---------------------------------------------------------------------------
// TestEvidencePackage_SummaryAccuracy
// ---------------------------------------------------------------------------

// TestEvidencePackage_SummaryAccuracy verifies that the summary score in an
// exported package is the ratio of pass / total.
func TestEvidencePackage_SummaryAccuracy(t *testing.T) {
	repo := new(mockEvidenceRepo)
	svc := NewComplianceEvidenceService(repo)

	tenantID := uuid.New()
	from := time.Now().Add(-24 * time.Hour)
	to := time.Now()

	evals := []ComplianceEvaluation{
		evaluationFixture("CC6.1-MFA", "pass", 95, 90),
		evaluationFixture("CC6.2-PASSWD", "pass", 1, 1),
		evaluationFixture("CC6.3-SESSION", "fail", 0, 1),
		evaluationFixture("CC6.4-LOCKOUT", "fail", 0, 1),
	}

	repo.On("ListLatestEvaluationsByFramework",
		mock.Anything, tenantID, "SOC2", from, to).
		Return(evals, nil)

	data, err := svc.ExportEvidencePackage(context.Background(), tenantID, "SOC2", from, to)
	require.NoError(t, err)

	var pkg EvidencePackage
	require.NoError(t, json.Unmarshal(data, &pkg))
	assert.Equal(t, 4, pkg.Summary.TotalControls)
	assert.Equal(t, 2, pkg.Summary.PassCount)
	assert.Equal(t, 2, pkg.Summary.FailCount)
	assert.InDelta(t, 50.0, pkg.Summary.Score, 0.1)
}

// ---------------------------------------------------------------------------
// TestEvidenceControlStatus_NotEvaluated
// ---------------------------------------------------------------------------

// TestEvidenceControlStatus_NotEvaluated verifies that controls with an
// "error" DB status surface as "not_evaluated" in the evidence package
// to match the evidence output schema.
func TestEvidenceControlStatus_NotEvaluated(t *testing.T) {
	repo := new(mockEvidenceRepo)
	svc := NewComplianceEvidenceService(repo)

	tenantID := uuid.New()
	from := time.Now().Add(-24 * time.Hour)
	to := time.Now()

	evals := []ComplianceEvaluation{
		evaluationFixture("CC6.1-MFA", "error", 0, 90),
	}

	repo.On("ListLatestEvaluationsByFramework",
		mock.Anything, tenantID, "SOC2", from, to).
		Return(evals, nil)

	data, err := svc.ExportEvidencePackage(context.Background(), tenantID, "SOC2", from, to)
	require.NoError(t, err)

	var pkg EvidencePackage
	require.NoError(t, json.Unmarshal(data, &pkg))
	require.Len(t, pkg.Controls, 1)
	assert.Equal(t, "not_evaluated", pkg.Controls[0].Status)
}
