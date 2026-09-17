// SPDX-License-Identifier: AGPL-3.0-or-later

package models

import (
	"time"

	"github.com/google/uuid"
)

// DynamicGroupRuleOperator defines the comparison operators for rule conditions.
type DynamicGroupRuleOperator string

const (
	// OperatorEquals is an exported identifier.
	OperatorEquals DynamicGroupRuleOperator = "eq"
	// OperatorNotEquals is an exported identifier.
	OperatorNotEquals DynamicGroupRuleOperator = "neq"
	// OperatorContains is an exported identifier.
	OperatorContains DynamicGroupRuleOperator = "contains"
	// OperatorIn is an exported identifier.
	OperatorIn DynamicGroupRuleOperator = "in"
	// OperatorStartsWith is an exported identifier.
	OperatorStartsWith DynamicGroupRuleOperator = "starts_with"
	// OperatorExists is an exported identifier.
	OperatorExists DynamicGroupRuleOperator = "exists"
)

// ValidOperators is the set of accepted condition operators.
var ValidOperators = map[DynamicGroupRuleOperator]bool{
	OperatorEquals:     true,
	OperatorNotEquals:  true,
	OperatorContains:   true,
	OperatorIn:         true,
	OperatorStartsWith: true,
	OperatorExists:     true,
}

// RuleCondition represents a single attribute-based condition.
type RuleCondition struct {
	Attribute string                   `json:"attribute"`
	Operator  DynamicGroupRuleOperator `json:"operator"`
	Value     interface{}              `json:"value"`
}

// DynamicGroupRule represents a rule that auto-assigns users to a group
// based on user attribute conditions.
type DynamicGroupRule struct {
	ID          uuid.UUID  `json:"id" db:"id"`
	TenantID    uuid.UUID  `json:"tenant_id" db:"tenant_id"`
	GroupID     uuid.UUID  `json:"group_id" db:"group_id"`
	Name        string     `json:"name" db:"name"`
	Description string     `json:"description,omitempty" db:"description"`
	Conditions  []byte     `json:"conditions" db:"conditions"`
	IsActive    bool       `json:"is_active" db:"is_active"`
	Priority    int        `json:"priority" db:"priority"`
	CreatedBy   *uuid.UUID `json:"created_by,omitempty" db:"created_by"`
	CreatedAt   time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at" db:"updated_at"`
}

// MaxDynamicGroupRulesPerTenant is the maximum number of dynamic group rules per tenant.
const MaxDynamicGroupRulesPerTenant = 100

// CreateDynamicGroupRuleRequest is the request body for creating a rule.
type CreateDynamicGroupRuleRequest struct {
	GroupID     uuid.UUID       `json:"group_id" binding:"required"`
	Name        string          `json:"name" binding:"required"`
	Description string          `json:"description"`
	Conditions  []RuleCondition `json:"conditions" binding:"required"`
	IsActive    *bool           `json:"is_active"`
	Priority    *int            `json:"priority"`
}

// UpdateDynamicGroupRuleRequest is the request body for updating a rule.
type UpdateDynamicGroupRuleRequest struct {
	IsActive *bool `json:"is_active"`
	Priority *int  `json:"priority"`
}

// DynamicGroupRuleResponse is the API response for a rule.
type DynamicGroupRuleResponse struct {
	ID          uuid.UUID       `json:"id"`
	TenantID    uuid.UUID       `json:"tenant_id"`
	GroupID     uuid.UUID       `json:"group_id"`
	Name        string          `json:"name"`
	Description string          `json:"description,omitempty"`
	Conditions  []RuleCondition `json:"conditions"`
	IsActive    bool            `json:"is_active"`
	Priority    int             `json:"priority"`
	CreatedBy   *uuid.UUID      `json:"created_by,omitempty"`
	CreatedAt   time.Time       `json:"created_at"`
	UpdatedAt   time.Time       `json:"updated_at"`
}
