// SPDX-License-Identifier: AGPL-3.0-or-later

package models

import (
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
)

// RoutingRuleAction defines the action to take when a routing rule matches.
type RoutingRuleAction string

const (
	// RoutingActionRedirect redirects the user to the matched IDP for authentication.
	RoutingActionRedirect RoutingRuleAction = "redirect"
	// RoutingActionAllow permits local (password) authentication.
	RoutingActionAllow RoutingRuleAction = "allow"
	// RoutingActionDeny blocks the authentication attempt entirely.
	RoutingActionDeny RoutingRuleAction = "deny"
	// RoutingActionStepUpMFA requires the user to complete MFA before proceeding.
	RoutingActionStepUpMFA RoutingRuleAction = "step_up_mfa"
)

// EnhancedIDPRoutingRule is an exported identifier.
// EnhancedIDPRoutingRule extends the base IDPRoutingRule with multi-criteria
// conditions for Okta-style routing policy evaluation.
type EnhancedIDPRoutingRule struct {
	IDPRoutingRule

	// Multi-criteria conditions (NULL = wildcard / match any)
	DeviceType    *string    `json:"device_type,omitempty" db:"device_type"`       // mobile, desktop, tablet, unknown
	NetworkZone   *string    `json:"network_zone,omitempty" db:"network_zone"`     // corporate, external, vpn, trusted, untrusted
	ApplicationID *uuid.UUID `json:"application_id,omitempty" db:"application_id"` // Specific application context

	// Risk-based routing signals (NULL = wildcard / match any risk level)
	// A rule with sign_in_risk_level = 'medium' matches when the current sign-in risk
	// is medium or higher. Risk hierarchy: low < medium < high < critical.
	SignInRiskLevel *string `json:"sign_in_risk_level,omitempty" db:"sign_in_risk_level"` // low, medium, high, critical
	UserRiskLevel   *string `json:"user_risk_level,omitempty" db:"user_risk_level"`       // low, medium, high, critical

	// Time-based routing conditions (NULL = wildcard / match any time)
	TimeStart  *string       `json:"time_start,omitempty" db:"time_start"`     // HH:MM:SS format, e.g. "09:00:00"
	TimeEnd    *string       `json:"time_end,omitempty" db:"time_end"`         // HH:MM:SS format, e.g. "17:00:00"
	DaysOfWeek pq.Int64Array `json:"days_of_week,omitempty" db:"days_of_week"` // 0=Sunday..6=Saturday (Go time.Weekday)
	Timezone   *string       `json:"timezone,omitempty" db:"timezone"`         // IANA timezone, defaults to UTC

	// Action to take when this rule matches
	Action RoutingRuleAction `json:"action" db:"action"`

	// Administrative fields
	Description *string        `json:"description,omitempty" db:"description"`
	Metadata    map[string]any `json:"metadata,omitempty" db:"metadata"`
}

// RoutingEvaluationContext contains all the signals available for rule evaluation.
// The HRD engine populates this from the request and passes it to the evaluation engine.
type RoutingEvaluationContext struct {
	TenantID      uuid.UUID  `json:"tenant_id"`
	EmailDomain   string     `json:"email_domain"`
	DeviceType    string     `json:"device_type"`    // mobile, desktop, tablet, unknown
	NetworkZone   string     `json:"network_zone"`   // Resolved from IP against network zones
	ClientIP      string     `json:"client_ip"`      // Raw IP for logging
	ApplicationID *uuid.UUID `json:"application_id"` // Which app is requesting auth
	UserAgent     string     `json:"user_agent"`     // Raw User-Agent for device classification

	// Risk-based signals populated from the risk assessment engine
	SignInRiskLevel string `json:"sign_in_risk_level,omitempty"` // Current sign-in risk level
	UserRiskLevel   string `json:"user_risk_level,omitempty"`    // User's overall risk level

	// Time context for time-based rule evaluation
	// If zero, the engine uses time.Now() at evaluation time
	EvaluationTime time.Time `json:"evaluation_time,omitempty"`
}

// RoutingEvaluationResult is the output of the routing rule evaluation engine.
type RoutingEvaluationResult struct {
	Matched      bool                    `json:"matched"`
	Rule         *EnhancedIDPRoutingRule `json:"rule,omitempty"`
	Action       RoutingRuleAction       `json:"action"`
	ProviderID   *uuid.UUID              `json:"provider_id,omitempty"`
	ProviderType *string                 `json:"provider_type,omitempty"`
	ProviderName *string                 `json:"provider_name,omitempty"`

	// Evaluation metadata
	RulesEvaluated int `json:"rules_evaluated"`
	EvaluationMs   int `json:"evaluation_ms"`
}

// RoutingEvaluation represents an audit log entry for a routing evaluation.
type RoutingEvaluation struct {
	ID             uuid.UUID  `json:"id" db:"id"`
	TenantID       uuid.UUID  `json:"tenant_id" db:"tenant_id"`
	RuleID         *uuid.UUID `json:"rule_id,omitempty" db:"rule_id"`
	EmailDomain    *string    `json:"email_domain,omitempty" db:"email_domain"`
	DeviceType     *string    `json:"device_type,omitempty" db:"device_type"`
	NetworkZone    *string    `json:"network_zone,omitempty" db:"network_zone"`
	ClientIP       *string    `json:"client_ip,omitempty" db:"client_ip"`
	ApplicationID  *uuid.UUID `json:"application_id,omitempty" db:"application_id"`
	Matched        bool       `json:"matched" db:"matched"`
	ActionTaken    *string    `json:"action_taken,omitempty" db:"action_taken"`
	ProviderID     *uuid.UUID `json:"provider_id,omitempty" db:"provider_id"`
	RulesEvaluated int        `json:"rules_evaluated" db:"rules_evaluated"`
	EvaluationMs   *int       `json:"evaluation_ms,omitempty" db:"evaluation_ms"`
	CreatedAt      time.Time  `json:"created_at" db:"created_at"`
}

// CreateEnhancedRoutingRuleRequest is the DTO for creating an enhanced routing rule.
type CreateEnhancedRoutingRuleRequest struct {
	IdentityProviderID uuid.UUID  `json:"identity_provider_id" binding:"required"`
	RuleType           string     `json:"rule_type" binding:"required,oneof=email_domain ip_range user_attribute"`
	RuleValue          string     `json:"rule_value" binding:"required,min=1,max=512"`
	Priority           int        `json:"priority"`
	IsEnabled          *bool      `json:"is_enabled"`
	DeviceType         *string    `json:"device_type" binding:"omitempty,oneof=mobile desktop tablet unknown"`
	NetworkZone        *string    `json:"network_zone" binding:"omitempty,oneof=corporate external vpn trusted untrusted"`
	ApplicationID      *uuid.UUID `json:"application_id"`
	SignInRiskLevel    *string    `json:"sign_in_risk_level" binding:"omitempty,oneof=low medium high critical"`
	UserRiskLevel      *string    `json:"user_risk_level" binding:"omitempty,oneof=low medium high critical"`
	TimeStart          *string    `json:"time_start" binding:"omitempty"`
	TimeEnd            *string    `json:"time_end" binding:"omitempty"`
	DaysOfWeek         []int      `json:"days_of_week" binding:"omitempty"`
	Timezone           *string    `json:"timezone" binding:"omitempty"`
	Action             string     `json:"action" binding:"omitempty,oneof=redirect allow deny step_up_mfa"`
	Description        *string    `json:"description" binding:"omitempty,max=500"`
}

// DiscoverRequestEnhanced extends DiscoverRequest with multi-criteria signals.
type DiscoverRequestEnhanced struct {
	Email         string     `json:"email" binding:"required,email"`
	ClientID      string     `json:"client_id,omitempty"`
	ApplicationID *uuid.UUID `json:"application_id,omitempty"`
	DeviceType    string     `json:"device_type,omitempty"`
	UserAgent     string     `json:"user_agent,omitempty"` // For server-side device classification
}
