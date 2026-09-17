// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/pkg/logger"
)

// dynamicGroupRuleRepo provides access to dynamic group rules.
type dynamicGroupRuleRepo interface {
	ListActiveByTenant(ctx context.Context, tenantID uuid.UUID) ([]models.DynamicGroupRule, error)
}

// dynamicGroupMemberAdder adds a user to a group.
type dynamicGroupMemberAdder interface {
	AddMember(ctx context.Context, groupID, userID uuid.UUID) error
}

// DynamicGroupEvaluator evaluates dynamic group rules against a user's
// attributes and auto-assigns matching groups.
//
// Rule evaluation is AND-based: all conditions in a rule must match
// for the user to be added to the group.
type DynamicGroupEvaluator struct {
	ruleRepo   dynamicGroupRuleRepo
	groupAdder dynamicGroupMemberAdder
}

// NewDynamicGroupEvaluator creates a new evaluator.
func NewDynamicGroupEvaluator(
	ruleRepo dynamicGroupRuleRepo,
	groupAdder dynamicGroupMemberAdder,
) *DynamicGroupEvaluator {
	return &DynamicGroupEvaluator{
		ruleRepo:   ruleRepo,
		groupAdder: groupAdder,
	}
}

// EvaluateUser evaluates all active dynamic group rules for the user's tenant
// and adds the user to matching groups. Individual failures are non-fatal.
func (e *DynamicGroupEvaluator) EvaluateUser(ctx context.Context, user *models.User) error {
	rules, err := e.ruleRepo.ListActiveByTenant(ctx, user.TenantID)
	if err != nil {
		return fmt.Errorf("dynamic group evaluator: list rules: %w", err)
	}

	if len(rules) == 0 {
		return nil
	}

	attrs := extractUserAttributes(user)
	matchCount := 0

	for _, rule := range rules {
		var conditions []models.RuleCondition
		if err := json.Unmarshal(rule.Conditions, &conditions); err != nil {
			logger.Warn("Dynamic group evaluator: invalid rule conditions, skipping",
				zap.String("rule_id", rule.ID.String()),
				zap.Error(err),
			)
			continue
		}

		if matchesAllConditions(attrs, conditions) {
			if err := e.groupAdder.AddMember(ctx, rule.GroupID, user.ID); err != nil {
				logger.Warn("Dynamic group evaluator: add member failed (non-fatal)",
					zap.String("rule_id", rule.ID.String()),
					zap.String("group_id", rule.GroupID.String()),
					zap.String("user_id", user.ID.String()),
					zap.Error(err),
				)
				continue
			}
			matchCount++
		}
	}

	if matchCount > 0 {
		logger.Info("Dynamic group evaluation completed",
			zap.String("user_id", user.ID.String()),
			zap.String("tenant_id", user.TenantID.String()),
			zap.Int("rules_evaluated", len(rules)),
			zap.Int("groups_assigned", matchCount),
		)
	}

	return nil
}

// extractUserAttributes builds a flat string map of user attributes for rule evaluation.
func extractUserAttributes(user *models.User) map[string]string {
	attrs := map[string]string{
		"email":    user.Email,
		"username": user.Username,
	}
	if user.Department != nil {
		attrs["department"] = *user.Department
	}
	if user.Title != nil {
		attrs["title"] = *user.Title
	}
	if user.FirstName != nil {
		attrs["first_name"] = *user.FirstName
	}
	if user.LastName != nil {
		attrs["last_name"] = *user.LastName
	}
	if user.DisplayName != nil {
		attrs["display_name"] = *user.DisplayName
	}
	if user.FederationType != nil {
		attrs["federation_type"] = *user.FederationType
	}
	if user.FederationSource != nil {
		attrs["federation_source"] = *user.FederationSource
	}
	return attrs
}

// matchesAllConditions returns true if all conditions match (AND logic).
func matchesAllConditions(attrs map[string]string, conditions []models.RuleCondition) bool {
	for _, cond := range conditions {
		attrValue, exists := attrs[cond.Attribute]
		if !matchCondition(attrValue, exists, cond) {
			return false
		}
	}
	return true
}

// matchCondition evaluates a single condition against an attribute value.
func matchCondition(attrValue string, exists bool, cond models.RuleCondition) bool {
	condValue := fmt.Sprintf("%v", cond.Value)

	switch cond.Operator {
	case models.OperatorEquals:
		return exists && attrValue == condValue
	case models.OperatorNotEquals:
		return !exists || attrValue != condValue
	case models.OperatorContains:
		return exists && strings.Contains(attrValue, condValue)
	case models.OperatorStartsWith:
		return exists && strings.HasPrefix(attrValue, condValue)
	case models.OperatorExists:
		return exists && attrValue != ""
	case models.OperatorIn:
		// Value should be a slice; try to parse
		if !exists {
			return false
		}
		switch v := cond.Value.(type) {
		case []interface{}:
			for _, item := range v {
				if fmt.Sprintf("%v", item) == attrValue {
					return true
				}
			}
		case []string:
			for _, item := range v {
				if item == attrValue {
					return true
				}
			}
		}
		return false
	default:
		return false
	}
}
