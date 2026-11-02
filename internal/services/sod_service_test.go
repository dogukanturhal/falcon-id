// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

// ---------------------------------------------------------------------------
// Mocks
// ---------------------------------------------------------------------------

type mockSoDRuleRepo struct{ mock.Mock }

func (m *mockSoDRuleRepo) ListActiveRulesForTenant(ctx context.Context, tenantID uuid.UUID) ([]models.SoDRule, error) {
	args := m.Called(ctx, tenantID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]models.SoDRule), args.Error(1)
}

func (m *mockSoDRuleRepo) ListRulesForTenant(ctx context.Context, tenantID uuid.UUID) ([]models.SoDRule, error) {
	args := m.Called(ctx, tenantID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]models.SoDRule), args.Error(1)
}

func (m *mockSoDRuleRepo) GetRuleByIDAndTenant(ctx context.Context, id, tenantID uuid.UUID) (*models.SoDRule, error) {
	args := m.Called(ctx, id, tenantID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.SoDRule), args.Error(1)
}

func (m *mockSoDRuleRepo) CreateRule(ctx context.Context, rule *models.SoDRule) error {
	args := m.Called(ctx, rule)
	return args.Error(0)
}

func (m *mockSoDRuleRepo) UpdateRule(ctx context.Context, id, tenantID uuid.UUID, req *models.UpdateSoDRuleRequest) (*models.SoDRule, error) {
	args := m.Called(ctx, id, tenantID, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.SoDRule), args.Error(1)
}

type mockSoDViolationRepo struct{ mock.Mock }

func (m *mockSoDViolationRepo) UpsertViolation(ctx context.Context, v *models.SoDViolation) error {
	args := m.Called(ctx, v)
	return args.Error(0)
}

func (m *mockSoDViolationRepo) ListViolationsForTenant(ctx context.Context, tenantID uuid.UUID, openOnly bool) ([]models.SoDViolation, error) {
	args := m.Called(ctx, tenantID, openOnly)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]models.SoDViolation), args.Error(1)
}

type mockSoDPermissionRepo struct{ mock.Mock }

func (m *mockSoDPermissionRepo) GetUserPermissionNames(ctx context.Context, userID, tenantID uuid.UUID) ([]string, error) {
	args := m.Called(ctx, userID, tenantID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]string), args.Error(1)
}

// ---------------------------------------------------------------------------
// EvaluateUser
// ---------------------------------------------------------------------------

func TestSoDService_EvaluateUser_NoConflict_NoViolationRecorded(t *testing.T) {
	ctx := context.Background()
	tenantID := uuid.New()
	userID := uuid.New()
	ruleID := uuid.New()

	rules := new(mockSoDRuleRepo)
	violations := new(mockSoDViolationRepo)
	perms := new(mockSoDPermissionRepo)
	svc := NewSoDService(rules, violations, perms)

	rules.On("ListActiveRulesForTenant", ctx, tenantID).Return([]models.SoDRule{
		{ID: ruleID, PermissionA: "accounting:journal_entries:create", PermissionB: "accounting:journal_entries:approve", Mode: models.SoDModeWarn},
	}, nil)
	// User holds only one side of the pair.
	perms.On("GetUserPermissionNames", ctx, userID, tenantID).Return([]string{"accounting:journal_entries:create"}, nil)

	got, err := svc.EvaluateUser(ctx, tenantID, userID, nil)

	require.NoError(t, err)
	assert.Empty(t, got)
	violations.AssertNotCalled(t, "UpsertViolation")
}

// TestSoDService_EvaluateUser_Conflict_RecordsWarnViolation_NeverBlocks is
// the "SoD warn mode logs + records a violation, never blocks" acceptance
// check: EvaluateUser returns no error and a violation even though the
// user holds both conflicting permissions — there is no block-mode path.
func TestSoDService_EvaluateUser_Conflict_RecordsWarnViolation_NeverBlocks(t *testing.T) {
	ctx := context.Background()
	tenantID := uuid.New()
	userID := uuid.New()
	ruleID := uuid.New()
	roleIDs := []uuid.UUID{uuid.New()}

	rules := new(mockSoDRuleRepo)
	violations := new(mockSoDViolationRepo)
	perms := new(mockSoDPermissionRepo)
	svc := NewSoDService(rules, violations, perms)

	rules.On("ListActiveRulesForTenant", ctx, tenantID).Return([]models.SoDRule{
		{ID: ruleID, PermissionA: "accounting:journal_entries:create", PermissionB: "accounting:journal_entries:approve", Mode: models.SoDModeWarn},
	}, nil)
	perms.On("GetUserPermissionNames", ctx, userID, tenantID).Return(
		[]string{"accounting:journal_entries:create", "accounting:journal_entries:approve"}, nil)
	violations.On("UpsertViolation", ctx, mock.MatchedBy(func(v *models.SoDViolation) bool {
		return v.TenantID == tenantID && v.UserID == userID && v.RuleID == ruleID && v.Mode == models.SoDModeWarn
	})).Return(nil)

	got, err := svc.EvaluateUser(ctx, tenantID, userID, roleIDs)

	require.NoError(t, err)
	require.Len(t, got, 1)
	assert.Equal(t, ruleID, got[0].RuleID)
	assert.Equal(t, models.SoDModeWarn, got[0].Mode)
	violations.AssertExpectations(t)
}

// TestSoDService_EvaluateUser_BlockModeRule_StillNeverBlocks asserts the
// R1 scope decision documented on SoDService: even a rule whose own `mode`
// column is 'block' is only ever logged + recorded by this service —
// EvaluateUser has no code path that returns a blocking error for any
// rule mode. Block enforcement is deferred to the R2/R3 per-module flip.
func TestSoDService_EvaluateUser_BlockModeRule_StillNeverBlocks(t *testing.T) {
	ctx := context.Background()
	tenantID := uuid.New()
	userID := uuid.New()
	ruleID := uuid.New()

	rules := new(mockSoDRuleRepo)
	violations := new(mockSoDViolationRepo)
	perms := new(mockSoDPermissionRepo)
	svc := NewSoDService(rules, violations, perms)

	rules.On("ListActiveRulesForTenant", ctx, tenantID).Return([]models.SoDRule{
		{ID: ruleID, PermissionA: "mm:requisition:create", PermissionB: "mm:requisition:approve", Mode: models.SoDModeBlock},
	}, nil)
	perms.On("GetUserPermissionNames", ctx, userID, tenantID).Return(
		[]string{"mm:requisition:create", "mm:requisition:approve"}, nil)
	violations.On("UpsertViolation", ctx, mock.Anything).Return(nil)

	got, err := svc.EvaluateUser(ctx, tenantID, userID, nil)

	require.NoError(t, err, "a block-mode rule must never surface as an error from EvaluateUser in R1")
	require.Len(t, got, 1)
}

func TestSoDService_EvaluateUser_NoActiveRules_ShortCircuitsWithoutPermissionLookup(t *testing.T) {
	ctx := context.Background()
	tenantID := uuid.New()
	userID := uuid.New()

	rules := new(mockSoDRuleRepo)
	violations := new(mockSoDViolationRepo)
	perms := new(mockSoDPermissionRepo)
	svc := NewSoDService(rules, violations, perms)

	rules.On("ListActiveRulesForTenant", ctx, tenantID).Return([]models.SoDRule{}, nil)

	got, err := svc.EvaluateUser(ctx, tenantID, userID, nil)

	require.NoError(t, err)
	assert.Nil(t, got)
	perms.AssertNotCalled(t, "GetUserPermissionNames")
}

func TestSoDService_EvaluateUser_UpsertFailure_LoggedNotReturned(t *testing.T) {
	ctx := context.Background()
	tenantID := uuid.New()
	userID := uuid.New()
	ruleID := uuid.New()

	rules := new(mockSoDRuleRepo)
	violations := new(mockSoDViolationRepo)
	perms := new(mockSoDPermissionRepo)
	svc := NewSoDService(rules, violations, perms)

	rules.On("ListActiveRulesForTenant", ctx, tenantID).Return([]models.SoDRule{
		{ID: ruleID, PermissionA: "qms:calibration:record_result", PermissionB: "cmms:calibration:update", Mode: models.SoDModeWarn},
	}, nil)
	perms.On("GetUserPermissionNames", ctx, userID, tenantID).Return(
		[]string{"qms:calibration:record_result", "cmms:calibration:update"}, nil)
	violations.On("UpsertViolation", ctx, mock.Anything).Return(errors.New("db unavailable"))

	got, err := svc.EvaluateUser(ctx, tenantID, userID, nil)

	require.NoError(t, err, "a DB failure recording the violation must not fail the evaluation call, let alone the triggering role-assignment write")
	assert.Empty(t, got)
}

func TestSoDService_EvaluateUserAsync_NilService_NoPanic(t *testing.T) {
	var svc *SoDService
	assert.NotPanics(t, func() {
		svc.EvaluateUserAsync(context.Background(), uuid.New(), uuid.New(), nil)
	})
}

// ---------------------------------------------------------------------------
// Rule CRUD passthroughs
// ---------------------------------------------------------------------------

func TestSoDService_CreateRule_SamePermissionBothSides_Rejected(t *testing.T) {
	rules := new(mockSoDRuleRepo)
	violations := new(mockSoDViolationRepo)
	perms := new(mockSoDPermissionRepo)
	svc := NewSoDService(rules, violations, perms)

	req := &models.CreateSoDRuleRequest{
		Module:      "crm",
		PermissionA: "crm:contacts:read",
		PermissionB: "crm:contacts:read",
	}

	_, err := svc.CreateRule(context.Background(), uuid.New(), req, nil)

	require.Error(t, err)
	rules.AssertNotCalled(t, "CreateRule")
}

func TestSoDService_CreateRule_DefaultsToWarnMode(t *testing.T) {
	ctx := context.Background()
	tenantID := uuid.New()
	rules := new(mockSoDRuleRepo)
	violations := new(mockSoDViolationRepo)
	perms := new(mockSoDPermissionRepo)
	svc := NewSoDService(rules, violations, perms)

	req := &models.CreateSoDRuleRequest{
		Module:      "crm",
		PermissionA: "crm:contacts:read",
		PermissionB: "crm:contacts:delete",
	}

	rules.On("CreateRule", ctx, mock.MatchedBy(func(r *models.SoDRule) bool {
		return r.Mode == models.SoDModeWarn && r.TenantID != nil && *r.TenantID == tenantID && !r.IsDefault
	})).Return(nil)

	rule, err := svc.CreateRule(ctx, tenantID, req, nil)

	require.NoError(t, err)
	assert.Equal(t, models.SoDModeWarn, rule.Mode)
}

func TestSoDService_ListRulesForTenant_DedupesOwnRulesFromDefaults(t *testing.T) {
	ctx := context.Background()
	tenantID := uuid.New()
	sharedID := uuid.New()
	tenantOnlyID := uuid.New()

	rules := new(mockSoDRuleRepo)
	violations := new(mockSoDViolationRepo)
	perms := new(mockSoDPermissionRepo)
	svc := NewSoDService(rules, violations, perms)

	rules.On("ListRulesForTenant", ctx, tenantID).Return([]models.SoDRule{
		{ID: sharedID}, {ID: tenantOnlyID},
	}, nil)
	rules.On("ListActiveRulesForTenant", ctx, tenantID).Return([]models.SoDRule{
		{ID: sharedID}, // platform default also returned by the "active" listing
	}, nil)

	got, err := svc.ListRulesForTenant(ctx, tenantID)

	require.NoError(t, err)
	assert.Len(t, got, 2, "the shared rule ID must not be duplicated")
}
