// SPDX-License-Identifier: AGPL-3.0-or-later

package models

import (
	"time"

	"github.com/google/uuid"
)

// CAPAction represents the outcome of a matching conditional access policy.
type CAPAction string

const (
	// CAPActionAllow permits the authentication to proceed without additional steps.
	CAPActionAllow CAPAction = "allow"
	// CAPActionDeny blocks the authentication attempt unconditionally.
	CAPActionDeny CAPAction = "deny"
	// CAPActionRequireMFA requires the user to complete an MFA challenge.
	CAPActionRequireMFA CAPAction = "require_mfa"
	// CAPActionRequireReauth requires the user to fully reauthenticate.
	CAPActionRequireReauth CAPAction = "require_reauthentication"
	// CAPActionRestrictSession applies session-level restrictions (e.g. read-only).
	CAPActionRestrictSession CAPAction = "restrict_session"
)

// CAPTimeRange represents a window of time during which a condition applies.
type CAPTimeRange struct {
	Start string `json:"start"` // HH:MM in 24-hour format
	End   string `json:"end"`   // HH:MM in 24-hour format
	Days  []int  `json:"days"`  // 0=Sunday … 6=Saturday; nil = every day
}

// CAPConditions holds the structured condition block of a conditional access policy.
// Each field is optional; an empty struct matches all login contexts.
type CAPConditions struct {
	// IPRanges is a list of CIDR blocks that the source IP must be within.
	IPRanges []string `json:"ip_ranges,omitempty"`

	// Locations is a list of ISO 3166-1 alpha-2 country codes.
	Locations []string `json:"locations,omitempty"`

	// DeviceTrust specifies the required device trust level (any/trusted/compliant).
	DeviceTrust string `json:"device_trust,omitempty"`

	// RiskLevelMin is the minimum risk score (0-100) that triggers this policy.
	RiskLevelMin *int `json:"risk_level_min,omitempty"`

	// MFAStatus constrains matching to users who have (or have not) enrolled MFA.
	// Accepted values: "enrolled" | "not_enrolled" | "" (any)
	MFAStatus string `json:"mfa_status,omitempty"`

	// TimeRanges restricts the policy to specific time windows.
	TimeRanges []CAPTimeRange `json:"time_ranges,omitempty"`

	// ClientApps is a list of application client IDs the condition applies to.
	ClientApps []string `json:"client_apps,omitempty"`

	// SignInFrequencyHours forces reauthentication after this many hours.
	SignInFrequencyHours *int `json:"sign_in_frequency_hours,omitempty"`
}

// ConditionalAccessPolicy is the database representation of a CAP rule.
type ConditionalAccessPolicy struct {
	ID             uuid.UUID   `json:"id"               db:"id"`
	TenantID       *uuid.UUID  `json:"tenant_id"        db:"tenant_id"`
	Name           string      `json:"name"             db:"name"`
	Description    string      `json:"description"      db:"description"`
	Priority       int         `json:"priority"         db:"priority"`
	IsEnabled      bool        `json:"is_enabled"       db:"is_enabled"`
	TargetUsers    []uuid.UUID `json:"target_users"    db:"target_users"`
	TargetGroups   []uuid.UUID `json:"target_groups"   db:"target_groups"`
	TargetRoles    []string    `json:"target_roles"     db:"target_roles"`
	TargetAllUsers bool        `json:"target_all_users" db:"target_all_users"`
	ExcludeUsers   []uuid.UUID `json:"exclude_users"   db:"exclude_users"`
	ExcludeGroups  []uuid.UUID `json:"exclude_groups"  db:"exclude_groups"`
	Conditions     []byte      `json:"conditions"       db:"conditions"` // JSONB
	Action         CAPAction   `json:"action"           db:"action"`
	ActionParams   []byte      `json:"action_params"    db:"action_params"` // JSONB
	CreatedBy      uuid.UUID   `json:"created_by"       db:"created_by"`
	CreatedAt      time.Time   `json:"created_at"       db:"created_at"`
	UpdatedAt      time.Time   `json:"updated_at"       db:"updated_at"`
}

// CAPEvaluationContext holds all login-time signals needed for policy evaluation.
type CAPEvaluationContext struct {
	UserID     uuid.UUID   `json:"user_id"`
	TenantID   *uuid.UUID  `json:"tenant_id"`
	IPAddress  string      `json:"ip_address"`
	UserAgent  string      `json:"user_agent"`
	RiskScore  int         `json:"risk_score"`
	MFAEnabled bool        `json:"mfa_enabled"`
	DeviceID   *uuid.UUID  `json:"device_id"`
	IsTrusted  bool        `json:"is_trusted"`
	ClientApp  string      `json:"client_app"`
	UserRoles  []string    `json:"user_roles"`
	UserGroups []uuid.UUID `json:"user_groups"`
}

// CAPEvaluationResult summarises the outcome of evaluating all matching policies.
type CAPEvaluationResult struct {
	Action          CAPAction                 `json:"action"`
	DenyMessage     string                    `json:"deny_message,omitempty"`
	MatchedPolicies []ConditionalAccessPolicy `json:"matched_policies,omitempty"`
}

// IsDenied returns true when the evaluation result blocks the login.
func (r *CAPEvaluationResult) IsDenied() bool {
	return r.Action == CAPActionDeny
}

// RequiresMFA returns true when the result demands an MFA challenge.
func (r *CAPEvaluationResult) RequiresMFA() bool {
	return r.Action == CAPActionRequireMFA
}

// ==================== CRUD DTOs ====================

// CreateCAPRequest is the payload for creating a new conditional access policy.
type CreateCAPRequest struct {
	TenantID       *uuid.UUID             `json:"tenant_id"`
	Name           string                 `json:"name"            binding:"required,min=1,max=255"`
	Description    string                 `json:"description"`
	Priority       int                    `json:"priority"        binding:"omitempty,min=1,max=9999"`
	IsEnabled      *bool                  `json:"is_enabled"`
	TargetUsers    []uuid.UUID            `json:"target_users"`
	TargetGroups   []uuid.UUID            `json:"target_groups"`
	TargetRoles    []string               `json:"target_roles"`
	TargetAllUsers bool                   `json:"target_all_users"`
	ExcludeUsers   []uuid.UUID            `json:"exclude_users"`
	ExcludeGroups  []uuid.UUID            `json:"exclude_groups"`
	Conditions     CAPConditions          `json:"conditions"`
	Action         CAPAction              `json:"action" binding:"required,oneof=allow deny require_mfa require_reauthentication restrict_session"`
	ActionParams   map[string]interface{} `json:"action_params"`
}

// UpdateCAPRequest is the payload for updating an existing conditional access policy.
type UpdateCAPRequest struct {
	Name           *string                `json:"name"            binding:"omitempty,min=1,max=255"`
	Description    *string                `json:"description"`
	Priority       *int                   `json:"priority"        binding:"omitempty,min=1,max=9999"`
	IsEnabled      *bool                  `json:"is_enabled"`
	TargetUsers    []uuid.UUID            `json:"target_users"`
	TargetGroups   []uuid.UUID            `json:"target_groups"`
	TargetRoles    []string               `json:"target_roles"`
	TargetAllUsers *bool                  `json:"target_all_users"`
	ExcludeUsers   []uuid.UUID            `json:"exclude_users"`
	ExcludeGroups  []uuid.UUID            `json:"exclude_groups"`
	Conditions     *CAPConditions         `json:"conditions"`
	Action         *CAPAction             `json:"action"          binding:"omitempty,oneof=allow deny require_mfa require_reauthentication restrict_session"`
	ActionParams   map[string]interface{} `json:"action_params"`
}

// SimulateCAPRequest is the payload for a dry-run policy evaluation.
type SimulateCAPRequest struct {
	Context CAPEvaluationContext `json:"context" binding:"required"`
}

// ---------------------------------------------------------------------------
// Adaptive MFA policy types
// ---------------------------------------------------------------------------

// AdaptiveMFAPolicy is a risk-based policy that maps risk signals to MFA decisions.
// Policies are evaluated in priority order (lower number = higher priority).
type AdaptiveMFAPolicy struct {
	ID         uuid.UUID        `json:"id"`
	TenantID   uuid.UUID        `json:"tenant_id"`
	Name       string           `json:"name"`
	Priority   int              `json:"priority"`
	Conditions PolicyConditions `json:"conditions"`
	Actions    PolicyActions    `json:"actions"`
	Enabled    bool             `json:"enabled"`
}

// PolicyConditions defines the matching criteria for an AdaptiveMFAPolicy.
// All non-nil/non-empty fields must match for the policy to trigger.
type PolicyConditions struct {
	// MinRiskScore is the inclusive lower bound of the risk score window (0-100).
	// Nil means no lower bound.
	MinRiskScore *int `json:"min_risk_score,omitempty"`

	// MaxRiskScore is the inclusive upper bound of the risk score window (0-100).
	// Nil means no upper bound.
	MaxRiskScore *int `json:"max_risk_score,omitempty"`

	// Networks restricts matching to specific network categories.
	// Recognised values: "corporate", "external", "tor", "vpn".
	// Empty slice matches all networks.
	Networks []string `json:"networks,omitempty"`

	// DeviceStates restricts matching to specific device trust states.
	// Recognised values: "managed", "unmanaged", "new".
	// Empty slice matches all device states.
	DeviceStates []string `json:"device_states,omitempty"`

	// UserGroups restricts matching to users who are members of at least one
	// of the listed group IDs. Empty slice matches all users.
	UserGroups []uuid.UUID `json:"user_groups,omitempty"`

	// Applications restricts matching to specific application client IDs.
	// Empty slice matches all applications.
	Applications []string `json:"applications,omitempty"`
}

// PolicyActions specifies what happens when an AdaptiveMFAPolicy matches.
type PolicyActions struct {
	// Action is the enforcement outcome.
	// Valid values: "allow", "mfa", "step_up", "block".
	Action string `json:"action"`

	// MFAMethods is the ordered list of acceptable MFA methods when Action is
	// "mfa" or "step_up".
	// Recognised values: "totp", "fido2", "sms", "email".
	MFAMethods []string `json:"mfa_methods,omitempty"`

	// SessionDuration overrides the default session lifetime for the resulting
	// session when the policy allows access. Nil uses the tenant default.
	SessionDuration *time.Duration `json:"session_duration,omitempty"`
}
