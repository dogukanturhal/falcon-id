// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

// --- Mocks ---

type mockDynamicGroupRuleRepo struct {
	rules []models.DynamicGroupRule
}

func (m *mockDynamicGroupRuleRepo) ListActiveByTenant(_ context.Context, tenantID uuid.UUID) ([]models.DynamicGroupRule, error) {
	var result []models.DynamicGroupRule
	for _, r := range m.rules {
		if r.TenantID == tenantID && r.IsActive {
			result = append(result, r)
		}
	}
	return result, nil
}

type mockDynGroupMemberAdder struct {
	calls []dynGroupAddCall
}

type dynGroupAddCall struct {
	GroupID uuid.UUID
	UserID  uuid.UUID
}

func (m *mockDynGroupMemberAdder) AddMember(_ context.Context, groupID, userID uuid.UUID) error {
	m.calls = append(m.calls, dynGroupAddCall{GroupID: groupID, UserID: userID})
	return nil
}

// helper to serialize conditions
func mustMarshalConditions(conditions []models.RuleCondition) []byte {
	b, _ := json.Marshal(conditions)
	return b
}

// --- Tests ---

func TestDynamicGroupEvaluator_NoRules(t *testing.T) {
	ruleRepo := &mockDynamicGroupRuleRepo{rules: nil}
	groupAdder := &mockDynGroupMemberAdder{}

	evaluator := NewDynamicGroupEvaluator(ruleRepo, groupAdder)

	user := &models.User{
		ID:       uuid.New(),
		TenantID: uuid.New(),
	}

	err := evaluator.EvaluateUser(context.Background(), user)

	assert.NoError(t, err)
	assert.Empty(t, groupAdder.calls)
}

func TestDynamicGroupEvaluator_MatchesDepartment(t *testing.T) {
	tenantID := uuid.New()
	groupID := uuid.New()
	userID := uuid.New()

	ruleRepo := &mockDynamicGroupRuleRepo{
		rules: []models.DynamicGroupRule{
			{
				ID:       uuid.New(),
				TenantID: tenantID,
				GroupID:  groupID,
				IsActive: true,
				Conditions: mustMarshalConditions([]models.RuleCondition{
					{Attribute: "department", Operator: models.OperatorEquals, Value: "Engineering"},
				}),
			},
		},
	}
	groupAdder := &mockDynGroupMemberAdder{}

	evaluator := NewDynamicGroupEvaluator(ruleRepo, groupAdder)

	user := &models.User{
		ID:         userID,
		TenantID:   tenantID,
		Department: dynStrPtr("Engineering"),
	}

	err := evaluator.EvaluateUser(context.Background(), user)

	assert.NoError(t, err)
	assert.Len(t, groupAdder.calls, 1)
	assert.Equal(t, groupID, groupAdder.calls[0].GroupID)
	assert.Equal(t, userID, groupAdder.calls[0].UserID)
}

func TestDynamicGroupEvaluator_NoMatch(t *testing.T) {
	tenantID := uuid.New()
	groupID := uuid.New()

	ruleRepo := &mockDynamicGroupRuleRepo{
		rules: []models.DynamicGroupRule{
			{
				ID:       uuid.New(),
				TenantID: tenantID,
				GroupID:  groupID,
				IsActive: true,
				Conditions: mustMarshalConditions([]models.RuleCondition{
					{Attribute: "department", Operator: models.OperatorEquals, Value: "Engineering"},
				}),
			},
		},
	}
	groupAdder := &mockDynGroupMemberAdder{}

	evaluator := NewDynamicGroupEvaluator(ruleRepo, groupAdder)

	user := &models.User{
		ID:         uuid.New(),
		TenantID:   tenantID,
		Department: dynStrPtr("Sales"),
	}

	err := evaluator.EvaluateUser(context.Background(), user)

	assert.NoError(t, err)
	assert.Empty(t, groupAdder.calls, "should not add user when department doesn't match")
}

func TestDynamicGroupEvaluator_MultipleRulesMultipleGroups(t *testing.T) {
	tenantID := uuid.New()
	groupA := uuid.New()
	groupB := uuid.New()
	userID := uuid.New()

	ruleRepo := &mockDynamicGroupRuleRepo{
		rules: []models.DynamicGroupRule{
			{
				ID:       uuid.New(),
				TenantID: tenantID,
				GroupID:  groupA,
				IsActive: true,
				Conditions: mustMarshalConditions([]models.RuleCondition{
					{Attribute: "department", Operator: models.OperatorEquals, Value: "Engineering"},
				}),
			},
			{
				ID:       uuid.New(),
				TenantID: tenantID,
				GroupID:  groupB,
				IsActive: true,
				Conditions: mustMarshalConditions([]models.RuleCondition{
					{Attribute: "title", Operator: models.OperatorContains, Value: "Engineer"},
				}),
			},
		},
	}
	groupAdder := &mockDynGroupMemberAdder{}

	evaluator := NewDynamicGroupEvaluator(ruleRepo, groupAdder)

	user := &models.User{
		ID:         userID,
		TenantID:   tenantID,
		Department: dynStrPtr("Engineering"),
		Title:      dynStrPtr("Senior Software Engineer"),
	}

	err := evaluator.EvaluateUser(context.Background(), user)

	assert.NoError(t, err)
	assert.Len(t, groupAdder.calls, 2, "should match both rules and add to both groups")
}

func TestDynamicGroupEvaluator_InactiveRuleSkipped(t *testing.T) {
	tenantID := uuid.New()

	ruleRepo := &mockDynamicGroupRuleRepo{
		rules: []models.DynamicGroupRule{
			{
				ID:       uuid.New(),
				TenantID: tenantID,
				GroupID:  uuid.New(),
				IsActive: false, // inactive
				Conditions: mustMarshalConditions([]models.RuleCondition{
					{Attribute: "department", Operator: models.OperatorEquals, Value: "Engineering"},
				}),
			},
		},
	}
	groupAdder := &mockDynGroupMemberAdder{}

	evaluator := NewDynamicGroupEvaluator(ruleRepo, groupAdder)

	user := &models.User{
		ID:         uuid.New(),
		TenantID:   tenantID,
		Department: dynStrPtr("Engineering"),
	}

	err := evaluator.EvaluateUser(context.Background(), user)

	assert.NoError(t, err)
	assert.Empty(t, groupAdder.calls, "inactive rules should be skipped")
}

func TestDynamicGroupEvaluator_ContainsOperator(t *testing.T) {
	tenantID := uuid.New()
	groupID := uuid.New()

	ruleRepo := &mockDynamicGroupRuleRepo{
		rules: []models.DynamicGroupRule{
			{
				ID:       uuid.New(),
				TenantID: tenantID,
				GroupID:  groupID,
				IsActive: true,
				Conditions: mustMarshalConditions([]models.RuleCondition{
					{Attribute: "email", Operator: models.OperatorContains, Value: "@example.com"},
				}),
			},
		},
	}
	groupAdder := &mockDynGroupMemberAdder{}

	evaluator := NewDynamicGroupEvaluator(ruleRepo, groupAdder)

	user := &models.User{
		ID:       uuid.New(),
		TenantID: tenantID,
		Email:    "john@example.com",
	}

	err := evaluator.EvaluateUser(context.Background(), user)

	assert.NoError(t, err)
	assert.Len(t, groupAdder.calls, 1)
}

func TestDynamicGroupEvaluator_StartsWithOperator(t *testing.T) {
	tenantID := uuid.New()
	groupID := uuid.New()

	ruleRepo := &mockDynamicGroupRuleRepo{
		rules: []models.DynamicGroupRule{
			{
				ID:       uuid.New(),
				TenantID: tenantID,
				GroupID:  groupID,
				IsActive: true,
				Conditions: mustMarshalConditions([]models.RuleCondition{
					{Attribute: "title", Operator: models.OperatorStartsWith, Value: "VP"},
				}),
			},
		},
	}
	groupAdder := &mockDynGroupMemberAdder{}

	evaluator := NewDynamicGroupEvaluator(ruleRepo, groupAdder)

	user := &models.User{
		ID:       uuid.New(),
		TenantID: tenantID,
		Title:    dynStrPtr("VP of Engineering"),
	}

	err := evaluator.EvaluateUser(context.Background(), user)

	assert.NoError(t, err)
	assert.Len(t, groupAdder.calls, 1)
}

func TestDynamicGroupEvaluator_AllConditionsMustMatch(t *testing.T) {
	tenantID := uuid.New()
	groupID := uuid.New()

	ruleRepo := &mockDynamicGroupRuleRepo{
		rules: []models.DynamicGroupRule{
			{
				ID:       uuid.New(),
				TenantID: tenantID,
				GroupID:  groupID,
				IsActive: true,
				Conditions: mustMarshalConditions([]models.RuleCondition{
					{Attribute: "department", Operator: models.OperatorEquals, Value: "Engineering"},
					{Attribute: "title", Operator: models.OperatorContains, Value: "Senior"},
				}),
			},
		},
	}
	groupAdder := &mockDynGroupMemberAdder{}

	evaluator := NewDynamicGroupEvaluator(ruleRepo, groupAdder)

	// Only matches department but not title
	user := &models.User{
		ID:         uuid.New(),
		TenantID:   tenantID,
		Department: dynStrPtr("Engineering"),
		Title:      dynStrPtr("Junior Developer"),
	}

	err := evaluator.EvaluateUser(context.Background(), user)

	assert.NoError(t, err)
	assert.Empty(t, groupAdder.calls, "ALL conditions must match for AND logic")
}

func dynStrPtr(s string) *string {
	return &s
}
