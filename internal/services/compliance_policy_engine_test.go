// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/pashagolub/pgxmock/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// newEngineWithMock creates a CompliancePolicyEngine backed by pgxmock so that
// all SQL is intercepted without touching a real database.
// pgxmock.PgxPoolIface satisfies the complianceDB interface.
func newEngineWithMock(t *testing.T) (*CompliancePolicyEngine, pgxmock.PgxPoolIface) {
	t.Helper()
	mockDB, err := pgxmock.NewPool()
	require.NoError(t, err)
	engine := &CompliancePolicyEngine{db: mockDB}
	return engine, mockDB
}

// controlFixture returns a minimal ComplianceControl suitable for test use.
// The CheckQuery returns a hard-coded scalar — pgxmock matches by regex against
// the query string.
func controlFixture(checkType ComplianceCheckType, threshold float64, operator string) *ComplianceControl {
	return &ComplianceControl{
		ID:              uuid.New(),
		Framework:       FrameworkSOC2,
		ControlID:       "CC6.1-MFA",
		Name:            "MFA Enrollment Rate",
		Description:     "MFA check",
		CheckType:       checkType,
		CheckQuery:      "SELECT 95.0 AS metric",
		Threshold:       threshold,
		Operator:        operator,
		Severity:        SeverityHigh,
		RemediationType: "notification",
		Enabled:         true,
		CreatedAt:       time.Now(),
		UpdatedAt:       time.Now(),
	}
}

// anyArgs returns n AnyArg matchers — used when we don't want to pin the
// exact values passed to an Exec or Query expectation.
func anyArgs(n int) []interface{} {
	args := make([]interface{}, n)
	for i := range args {
		args[i] = pgxmock.AnyArg()
	}
	return args
}

// setupEvaluateExpectations registers the pgxmock expectations for a full
// EvaluateControl call in the correct execution order:
//  1. CheckQuery  (QueryRow) — the compliance check
//  2. Baseline lookup (QueryRow) — drift detection (no prior baseline)
//  3. INSERT evaluation record (Exec, 13 args)
//
// When wantQueryErr is true the check query returns an error and only the
// INSERT for the error evaluation is expected (drift detection is skipped).
func setupEvaluateExpectations(
	m pgxmock.PgxPoolIface,
	ctrl *ComplianceControl,
	tenantID uuid.UUID,
	returnValue float64,
	wantQueryErr bool,
) {
	if wantQueryErr {
		m.ExpectQuery(ctrl.CheckQuery).
			WithArgs(tenantID).
			WillReturnError(errors.New("relation does not exist"))
		// EvaluateControl stores the error evaluation before returning.
		m.ExpectExec(`INSERT INTO iam_compliance_evaluations`).
			WithArgs(anyArgs(13)...).
			WillReturnResult(pgxmock.NewResult("INSERT", 1))
		return
	}

	// 1. Check query — returns the scalar compliance value.
	m.ExpectQuery(ctrl.CheckQuery).
		WithArgs(tenantID).
		WillReturnRows(pgxmock.NewRows([]string{"metric"}).AddRow(returnValue))

	// 2. Baseline lookup — no prior baseline exists for this control.
	m.ExpectQuery(`SELECT baseline_value FROM iam_compliance_baselines`).
		WithArgs(tenantID, ctrl.ID).
		WillReturnError(errors.New("no rows"))

	// 3. Persist evaluation record (13 columns).
	m.ExpectExec(`INSERT INTO iam_compliance_evaluations`).
		WithArgs(anyArgs(13)...).
		WillReturnResult(pgxmock.NewResult("INSERT", 1))
}

// ctx is a test helper that returns a background context.
func ctx() context.Context {
	return context.Background()
}

// ---------------------------------------------------------------------------
// TestSeedControls_AllFrameworksCovered
// ---------------------------------------------------------------------------

// TestSeedControls_AllFrameworksCovered verifies that the in-code seed control
// catalogue covers all four required compliance frameworks and contains at
// least 30 controls in total.
func TestSeedControls_AllFrameworksCovered(t *testing.T) {
	catalogue := defaultSeedControls()

	frameworks := map[ComplianceFramework]int{}
	for i := range catalogue {
		frameworks[catalogue[i].Framework]++
	}

	assert.GreaterOrEqual(t, len(catalogue), 30,
		"seed catalogue must have at least 30 controls, got %d", len(catalogue))

	for _, fw := range []ComplianceFramework{FrameworkSOC2, FrameworkGDPR, FrameworkISO27001, FrameworkHIPAA} {
		count := frameworks[fw]
		assert.GreaterOrEqual(t, count, 6,
			"framework %s must have at least 6 controls, got %d", fw, count)
	}
}

// TestSeedControls_NoDuplicateControlIDs ensures that each (framework, control_id)
// pair is unique within the catalogue.
func TestSeedControls_NoDuplicateControlIDs(t *testing.T) {
	catalogue := defaultSeedControls()
	seen := map[string]struct{}{}
	for i := range catalogue {
		key := fmt.Sprintf("%s::%s", catalogue[i].Framework, catalogue[i].ControlID)
		_, exists := seen[key]
		assert.False(t, exists, "duplicate control key found: %s", key)
		seen[key] = struct{}{}
	}
}

// TestSeedControls_AllFieldsPopulated verifies that every seed control has
// the required non-empty fields.
func TestSeedControls_AllFieldsPopulated(t *testing.T) {
	catalogue := defaultSeedControls()
	for i, sc := range catalogue {
		t.Run(fmt.Sprintf("%s/%s", sc.Framework, sc.ControlID), func(t *testing.T) {
			assert.NotEmpty(t, sc.Framework, "control[%d] Framework empty", i)
			assert.NotEmpty(t, sc.ControlID, "control[%d] ControlID empty", i)
			assert.NotEmpty(t, sc.Name, "control[%d] Name empty", i)
			assert.NotEmpty(t, sc.Description, "control[%d] Description empty", i)
			assert.NotEmpty(t, sc.CheckType, "control[%d] CheckType empty", i)
			assert.NotEmpty(t, sc.CheckQuery, "control[%d] CheckQuery empty", i)
			assert.NotEmpty(t, sc.Operator, "control[%d] Operator empty", i)
			assert.NotEmpty(t, sc.Severity, "control[%d] Severity empty", i)
			assert.NotEmpty(t, sc.RemediationType, "control[%d] RemediationType empty", i)
		})
	}
}

// TestSeedControls_ValidCheckTypes ensures every seed control uses a recognised
// check type constant.
func TestSeedControls_ValidCheckTypes(t *testing.T) {
	validTypes := map[ComplianceCheckType]struct{}{
		CheckTypeThreshold:  {},
		CheckTypeExistence:  {},
		CheckTypeTimeWindow: {},
		CheckTypePercentage: {},
		CheckTypeCount:      {},
	}

	catalogue := defaultSeedControls()
	for _, sc := range catalogue {
		t.Run(fmt.Sprintf("%s/%s", sc.Framework, sc.ControlID), func(t *testing.T) {
			_, ok := validTypes[sc.CheckType]
			assert.True(t, ok, "unknown check type %q", sc.CheckType)
		})
	}
}

// ---------------------------------------------------------------------------
// TestEvaluateControl — per check-type scenarios
//
// IMPORTANT: EvaluateControl executes SQL in this order:
//  1. control.CheckQuery (QueryRow)
//  2. DetectDrift → SELECT baseline_value ... (QueryRow)
//  3. storeEvaluation → INSERT ... (Exec)
// ---------------------------------------------------------------------------

// TestEvaluateControl_ThresholdCheck_Pass verifies that when the DB returns a
// value meeting the threshold the evaluation status is "pass".
func TestEvaluateControl_ThresholdCheck_Pass(t *testing.T) {
	engine, mock := newEngineWithMock(t)
	tenantID := uuid.New()
	policyID := uuid.New()
	ctrl := controlFixture(CheckTypeThreshold, 90, ">=")

	setupEvaluateExpectations(mock, ctrl, tenantID, 95.0, false)

	eval, err := engine.EvaluateControl(ctx(), policyID, tenantID, ctrl)
	require.NoError(t, err)
	assert.Equal(t, "pass", eval.Status)
	assert.Equal(t, 95.0, eval.ActualValue)
	assert.False(t, eval.DriftDetected)
}

// TestEvaluateControl_ThresholdCheck_Fail verifies that when the DB returns a
// value below the threshold the evaluation status is "fail".
func TestEvaluateControl_ThresholdCheck_Fail(t *testing.T) {
	engine, mock := newEngineWithMock(t)
	tenantID := uuid.New()
	policyID := uuid.New()
	ctrl := controlFixture(CheckTypeThreshold, 90, ">=")

	setupEvaluateExpectations(mock, ctrl, tenantID, 70.0, false)

	eval, err := engine.EvaluateControl(ctx(), policyID, tenantID, ctrl)
	require.NoError(t, err)
	assert.Equal(t, "fail", eval.Status)
	assert.Equal(t, 70.0, eval.ActualValue)
}

// TestEvaluateControl_ExistenceCheck_Pass verifies that an existence check with
// count >= 1 passes.
func TestEvaluateControl_ExistenceCheck_Pass(t *testing.T) {
	engine, mock := newEngineWithMock(t)
	tenantID := uuid.New()
	policyID := uuid.New()
	ctrl := controlFixture(CheckTypeExistence, 1, ">=")

	setupEvaluateExpectations(mock, ctrl, tenantID, 3.0, false)

	eval, err := engine.EvaluateControl(ctx(), policyID, tenantID, ctrl)
	require.NoError(t, err)
	assert.Equal(t, "pass", eval.Status)
}

// TestEvaluateControl_ExistenceCheck_Fail verifies that an existence check
// returning 0 fails.
func TestEvaluateControl_ExistenceCheck_Fail(t *testing.T) {
	engine, mock := newEngineWithMock(t)
	tenantID := uuid.New()
	policyID := uuid.New()
	ctrl := controlFixture(CheckTypeExistence, 1, ">=")

	setupEvaluateExpectations(mock, ctrl, tenantID, 0.0, false)

	eval, err := engine.EvaluateControl(ctx(), policyID, tenantID, ctrl)
	require.NoError(t, err)
	assert.Equal(t, "fail", eval.Status)
}

// TestEvaluateControl_TimeWindowCheck_Pass verifies that a time-window check
// with count > 0 passes (meaning events exist within the window).
func TestEvaluateControl_TimeWindowCheck_Pass(t *testing.T) {
	engine, mock := newEngineWithMock(t)
	tenantID := uuid.New()
	policyID := uuid.New()
	ctrl := controlFixture(CheckTypeTimeWindow, 1, ">=")

	setupEvaluateExpectations(mock, ctrl, tenantID, 42.0, false)

	eval, err := engine.EvaluateControl(ctx(), policyID, tenantID, ctrl)
	require.NoError(t, err)
	assert.Equal(t, "pass", eval.Status)
}

// TestEvaluateControl_TimeWindowCheck_Fail verifies that 0 events within the
// time window causes a failure.
func TestEvaluateControl_TimeWindowCheck_Fail(t *testing.T) {
	engine, mock := newEngineWithMock(t)
	tenantID := uuid.New()
	policyID := uuid.New()
	ctrl := controlFixture(CheckTypeTimeWindow, 1, ">=")

	setupEvaluateExpectations(mock, ctrl, tenantID, 0.0, false)

	eval, err := engine.EvaluateControl(ctx(), policyID, tenantID, ctrl)
	require.NoError(t, err)
	assert.Equal(t, "fail", eval.Status)
}

// TestEvaluateControl_CountCheck_Pass verifies a count-based control where
// 0 violations is the expected value (≤ 0 passes).
func TestEvaluateControl_CountCheck_Pass(t *testing.T) {
	engine, mock := newEngineWithMock(t)
	tenantID := uuid.New()
	policyID := uuid.New()
	ctrl := controlFixture(CheckTypeCount, 0, "<=")

	setupEvaluateExpectations(mock, ctrl, tenantID, 0.0, false)

	eval, err := engine.EvaluateControl(ctx(), policyID, tenantID, ctrl)
	require.NoError(t, err)
	assert.Equal(t, "pass", eval.Status)
}

// TestEvaluateControl_CountCheck_Fail verifies that non-zero violations in a
// count-based control produce a fail status.
func TestEvaluateControl_CountCheck_Fail(t *testing.T) {
	engine, mock := newEngineWithMock(t)
	tenantID := uuid.New()
	policyID := uuid.New()
	ctrl := controlFixture(CheckTypeCount, 0, "<=")

	setupEvaluateExpectations(mock, ctrl, tenantID, 5.0, false)

	eval, err := engine.EvaluateControl(ctx(), policyID, tenantID, ctrl)
	require.NoError(t, err)
	assert.Equal(t, "fail", eval.Status)
	assert.Equal(t, 5.0, eval.ActualValue)
}

// TestEvaluateControl_PercentageCheck_Pass verifies that a percentage of 95 ≥ 90
// passes.
func TestEvaluateControl_PercentageCheck_Pass(t *testing.T) {
	engine, mock := newEngineWithMock(t)
	tenantID := uuid.New()
	policyID := uuid.New()
	ctrl := controlFixture(CheckTypePercentage, 90, ">=")

	setupEvaluateExpectations(mock, ctrl, tenantID, 95.5, false)

	eval, err := engine.EvaluateControl(ctx(), policyID, tenantID, ctrl)
	require.NoError(t, err)
	assert.Equal(t, "pass", eval.Status)
	assert.Equal(t, 95.5, eval.ActualValue)
}

// TestEvaluateControl_PercentageCheck_Fail verifies that 85 < 90 fails.
func TestEvaluateControl_PercentageCheck_Fail(t *testing.T) {
	engine, mock := newEngineWithMock(t)
	tenantID := uuid.New()
	policyID := uuid.New()
	ctrl := controlFixture(CheckTypePercentage, 90, ">=")

	setupEvaluateExpectations(mock, ctrl, tenantID, 85.0, false)

	eval, err := engine.EvaluateControl(ctx(), policyID, tenantID, ctrl)
	require.NoError(t, err)
	assert.Equal(t, "fail", eval.Status)
}

// TestEvaluateControl_QueryError verifies that a database error on the check
// query is captured as status "error" in the stored evaluation.
func TestEvaluateControl_QueryError(t *testing.T) {
	engine, mock := newEngineWithMock(t)
	tenantID := uuid.New()
	policyID := uuid.New()
	ctrl := controlFixture(CheckTypeThreshold, 90, ">=")

	setupEvaluateExpectations(mock, ctrl, tenantID, 0, true)

	eval, err := engine.EvaluateControl(ctx(), policyID, tenantID, ctrl)
	require.Error(t, err)
	require.NotNil(t, eval)
	assert.Equal(t, "error", eval.Status)
}

// ---------------------------------------------------------------------------
// TestDriftDetection_BaselineComparison
// ---------------------------------------------------------------------------

// TestDriftDetection_BaselineComparison_NoDriftWhenNoBaseline verifies that
// when no baseline exists drift is reported as false (no reference point).
func TestDriftDetection_BaselineComparison_NoDriftWhenNoBaseline(t *testing.T) {
	engine, mock := newEngineWithMock(t)
	tenantID := uuid.New()
	controlID := uuid.New()

	mock.ExpectQuery(`SELECT baseline_value FROM iam_compliance_baselines`).
		WithArgs(tenantID, controlID).
		WillReturnError(errors.New("no rows"))

	drift, err := engine.DetectDrift(ctx(), tenantID, controlID, 85.0)
	require.NoError(t, err)
	assert.False(t, drift)
}

// TestDriftDetection_BaselineComparison_DriftDetectedOnSignificantChange
// verifies that a >5% deviation from the baseline triggers drift.
func TestDriftDetection_BaselineComparison_DriftDetectedOnSignificantChange(t *testing.T) {
	engine, mock := newEngineWithMock(t)
	tenantID := uuid.New()
	controlID := uuid.New()

	// Baseline is 95; current value is 80 — a 15.8% drop.
	mock.ExpectQuery(`SELECT baseline_value FROM iam_compliance_baselines`).
		WithArgs(tenantID, controlID).
		WillReturnRows(pgxmock.NewRows([]string{"baseline_value"}).AddRow(95.0))

	drift, err := engine.DetectDrift(ctx(), tenantID, controlID, 80.0)
	require.NoError(t, err)
	assert.True(t, drift, "expected drift to be detected for 15%% change from baseline")
}

// TestDriftDetection_BaselineComparison_NoDriftWithinTolerance verifies that
// a tiny variation (≤ 5%) does not trigger drift.
func TestDriftDetection_BaselineComparison_NoDriftWithinTolerance(t *testing.T) {
	engine, mock := newEngineWithMock(t)
	tenantID := uuid.New()
	controlID := uuid.New()

	// Baseline 95; current 96 — 1% change, well within 5% tolerance.
	mock.ExpectQuery(`SELECT baseline_value FROM iam_compliance_baselines`).
		WithArgs(tenantID, controlID).
		WillReturnRows(pgxmock.NewRows([]string{"baseline_value"}).AddRow(95.0))

	drift, err := engine.DetectDrift(ctx(), tenantID, controlID, 96.0)
	require.NoError(t, err)
	assert.False(t, drift)
}

// TestDriftDetection_BaselineComparison_ZeroBaselineAnyChange verifies that
// any change from a zero baseline triggers drift.
func TestDriftDetection_BaselineComparison_ZeroBaselineAnyChange(t *testing.T) {
	engine, mock := newEngineWithMock(t)
	tenantID := uuid.New()
	controlID := uuid.New()

	mock.ExpectQuery(`SELECT baseline_value FROM iam_compliance_baselines`).
		WithArgs(tenantID, controlID).
		WillReturnRows(pgxmock.NewRows([]string{"baseline_value"}).AddRow(0.0))

	drift, err := engine.DetectDrift(ctx(), tenantID, controlID, 1.0)
	require.NoError(t, err)
	assert.True(t, drift)
}

// TestDriftDetection_BaselineComparison_NoChangeNoBaseline verifies that zero
// value with zero baseline means no drift.
func TestDriftDetection_BaselineComparison_NoChangeNoBaseline(t *testing.T) {
	engine, mock := newEngineWithMock(t)
	tenantID := uuid.New()
	controlID := uuid.New()

	mock.ExpectQuery(`SELECT baseline_value FROM iam_compliance_baselines`).
		WithArgs(tenantID, controlID).
		WillReturnRows(pgxmock.NewRows([]string{"baseline_value"}).AddRow(0.0))

	drift, err := engine.DetectDrift(ctx(), tenantID, controlID, 0.0)
	require.NoError(t, err)
	assert.False(t, drift)
}

// ---------------------------------------------------------------------------
// TestAutoRemediation_PolicyCreation
// ---------------------------------------------------------------------------

// TestAutoRemediation_PolicyCreation_RemediationRun verifies that when a
// control fails and RemediationType == "auto" the remediation SQL is executed
// and RemediationRun is set to true on the evaluation record.
func TestAutoRemediation_PolicyCreation_RemediationRun(t *testing.T) {
	engine, mock := newEngineWithMock(t)
	tenantID := uuid.New()
	policyID := uuid.New()

	ctrl := controlFixture(CheckTypeCount, 0, "<=")
	ctrl.RemediationType = complianceRemediationTypeAuto
	ctrl.RemediationSQL = "UPDATE iam_sessions SET revoked = true WHERE tenant_id = $1"

	// 1. Check query returns 3 violations — control fails.
	mock.ExpectQuery(ctrl.CheckQuery).
		WithArgs(tenantID).
		WillReturnRows(pgxmock.NewRows([]string{"metric"}).AddRow(3.0))

	// 2. Baseline lookup — no prior baseline.
	mock.ExpectQuery(`SELECT baseline_value FROM iam_compliance_baselines`).
		WithArgs(tenantID, ctrl.ID).
		WillReturnError(errors.New("no rows"))

	// 3. Auto-remediation SQL executed ($1 = tenantID, matched with AnyArg).
	mock.ExpectExec(`UPDATE iam_sessions`).
		WithArgs(anyArgs(1)...).
		WillReturnResult(pgxmock.NewResult("UPDATE", 3))

	// 4. Evaluation stored (13 columns).
	mock.ExpectExec(`INSERT INTO iam_compliance_evaluations`).
		WithArgs(anyArgs(13)...).
		WillReturnResult(pgxmock.NewResult("INSERT", 1))

	eval, err := engine.EvaluateControl(ctx(), policyID, tenantID, ctrl)
	require.NoError(t, err)
	assert.Equal(t, "fail", eval.Status)
	assert.True(t, eval.RemediationRun, "expected remediation to have been run")
}

// TestAutoRemediation_PolicyCreation_NoRemediationOnPass verifies that
// remediation is NOT executed when the control passes.
func TestAutoRemediation_PolicyCreation_NoRemediationOnPass(t *testing.T) {
	engine, mock := newEngineWithMock(t)
	tenantID := uuid.New()
	policyID := uuid.New()

	ctrl := controlFixture(CheckTypeCount, 0, "<=")
	ctrl.RemediationType = complianceRemediationTypeAuto
	ctrl.RemediationSQL = "UPDATE iam_sessions SET revoked = true WHERE tenant_id = $1"

	// 0 violations — passes.
	mock.ExpectQuery(ctrl.CheckQuery).
		WithArgs(tenantID).
		WillReturnRows(pgxmock.NewRows([]string{"metric"}).AddRow(0.0))

	// Baseline lookup — no prior baseline.
	mock.ExpectQuery(`SELECT baseline_value FROM iam_compliance_baselines`).
		WithArgs(tenantID, ctrl.ID).
		WillReturnError(errors.New("no rows"))

	// No remediation exec — control passed.
	// Evaluation stored (13 columns).
	mock.ExpectExec(`INSERT INTO iam_compliance_evaluations`).
		WithArgs(anyArgs(13)...).
		WillReturnResult(pgxmock.NewResult("INSERT", 1))

	eval, err := engine.EvaluateControl(ctx(), policyID, tenantID, ctrl)
	require.NoError(t, err)
	assert.Equal(t, "pass", eval.Status)
	assert.False(t, eval.RemediationRun)
}

// ---------------------------------------------------------------------------
// TestControlSeeding_Idempotent
// ---------------------------------------------------------------------------

// TestControlSeeding_Idempotent verifies that the SeedControls method issues
// an INSERT ... ON CONFLICT DO NOTHING for each control (idempotent).
// SeedControls passes 11 arguments per INSERT ($1..$11).
func TestControlSeeding_Idempotent(t *testing.T) {
	engine, mock := newEngineWithMock(t)
	catalogue := defaultSeedControls()

	// Expect one exec per control (ON CONFLICT DO NOTHING), each with 11 args.
	for range catalogue {
		mock.ExpectExec(`INSERT INTO iam_compliance_controls`).
			WithArgs(anyArgs(11)...).
			WillReturnResult(pgxmock.NewResult("INSERT", 1))
	}

	err := engine.SeedControls(ctx())
	require.NoError(t, err, "SeedControls must be idempotent — no error on repeat calls")

	require.NoError(t, mock.ExpectationsWereMet())
}

// TestControlSeeding_DBError propagates a database error from SeedControls.
func TestControlSeeding_DBError(t *testing.T) {
	engine, mock := newEngineWithMock(t)

	mock.ExpectExec(`INSERT INTO iam_compliance_controls`).
		WithArgs(anyArgs(11)...).
		WillReturnError(errors.New("db connection lost"))

	err := engine.SeedControls(ctx())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "SeedControls")
}

// ---------------------------------------------------------------------------
// compareValues helper tests
// ---------------------------------------------------------------------------

func TestCompareValues_AllOperators(t *testing.T) {
	tests := []struct {
		name      string
		actual    float64
		operator  string
		threshold float64
		want      bool
	}{
		{"gte pass", 95, ">=", 90, true},
		{"gte fail", 85, ">=", 90, false},
		{"lte pass", 5, "<=", 10, true},
		{"lte fail", 15, "<=", 10, false},
		{"eq pass", 10, "==", 10, true},
		{"eq fail", 9, "==", 10, false},
		{"neq pass", 9, "!=", 10, true},
		{"neq fail", 10, "!=", 10, false},
		{"gt pass", 11, ">", 10, true},
		{"gt fail", 10, ">", 10, false},
		{"lt pass", 9, "<", 10, true},
		{"lt fail", 10, "<", 10, false},
		{"unknown defaults to >=", 95, "unknown", 90, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := compareValues(tt.actual, tt.operator, tt.threshold)
			assert.Equal(t, tt.want, got)
		})
	}
}

// ---------------------------------------------------------------------------
// nextRunTime helper tests
// ---------------------------------------------------------------------------

func TestNextRunTime_Schedules(t *testing.T) {
	now := time.Now()

	hourly := nextRunTime("hourly")
	assert.WithinDuration(t, now.Add(time.Hour), hourly, 5*time.Second)

	daily := nextRunTime("daily")
	assert.WithinDuration(t, now.Add(24*time.Hour), daily, 5*time.Second)

	weekly := nextRunTime("weekly")
	assert.WithinDuration(t, now.Add(7*24*time.Hour), weekly, 5*time.Second)

	defaultSchedule := nextRunTime("unknown")
	assert.WithinDuration(t, now.Add(24*time.Hour), defaultSchedule, 5*time.Second)
}

// ---------------------------------------------------------------------------
// EvaluateControl_Details verifies that evaluation details JSON is populated
// ---------------------------------------------------------------------------

func TestEvaluateControl_DetailsJSON(t *testing.T) {
	engine, mock := newEngineWithMock(t)
	tenantID := uuid.New()
	policyID := uuid.New()
	ctrl := controlFixture(CheckTypePercentage, 90, ">=")

	setupEvaluateExpectations(mock, ctrl, tenantID, 92.0, false)

	eval, err := engine.EvaluateControl(ctx(), policyID, tenantID, ctrl)
	require.NoError(t, err)

	var details map[string]interface{}
	require.NoError(t, json.Unmarshal(eval.Details, &details))
	assert.Equal(t, string(ctrl.CheckType), details["check_type"])
	assert.Equal(t, ctrl.Operator, details["operator"])
	assert.Equal(t, ctrl.Threshold, details["threshold"])
	assert.Equal(t, 92.0, details["actual_value"])
	assert.Equal(t, true, details["passed"])
}
