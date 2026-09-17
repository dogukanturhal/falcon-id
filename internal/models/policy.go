// SPDX-License-Identifier: AGPL-3.0-or-later

package models

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// PolicyEffect represents the effect of a policy (allow or deny)
type PolicyEffect string

const (
	// PolicyEffectAllow is an exported identifier.
	PolicyEffectAllow PolicyEffect = "allow"
	// PolicyEffectDeny is an exported identifier.
	PolicyEffectDeny PolicyEffect = "deny"
)

// Policy represents an ABAC policy stored in the database
type Policy struct {
	ID          uuid.UUID       `json:"id" db:"id"`
	TenantID    *uuid.UUID      `json:"tenant_id,omitempty" db:"tenant_id"` // NULL for global policies
	Name        string          `json:"name" db:"name"`
	Description string          `json:"description,omitempty" db:"description"`
	Effect      PolicyEffect    `json:"effect" db:"effect"`                   // "allow" or "deny"
	Priority    int             `json:"priority" db:"priority"`               // Higher = evaluated first
	Conditions  json.RawMessage `json:"conditions,omitempty" db:"conditions"` // JSON conditions for UI-based policies
	RegoCode    string          `json:"rego_code,omitempty" db:"rego_code"`   // Custom Rego for advanced users
	IsGlobal    bool            `json:"is_global" db:"is_global"`             // Applies to all tenants
	IsActive    bool            `json:"is_active" db:"is_active"`
	IsSystem    bool            `json:"is_system" db:"is_system"` // Cannot be modified by tenants
	CreatedAt   time.Time       `json:"created_at" db:"created_at"`
	UpdatedAt   time.Time       `json:"updated_at" db:"updated_at"`
	CreatedBy   *uuid.UUID      `json:"created_by,omitempty" db:"created_by"`
	UpdatedBy   *uuid.UUID      `json:"updated_by,omitempty" db:"updated_by"`
}

// PolicyCondition represents structured conditions for UI-based policy creation
type PolicyCondition struct {
	Subject  map[string]interface{} `json:"subject,omitempty"`  // User attribute conditions
	Resource map[string]interface{} `json:"resource,omitempty"` // Resource attribute conditions
	Action   []string               `json:"action,omitempty"`   // Allowed actions
	Context  map[string]interface{} `json:"context,omitempty"`  // Environment conditions
}

// PolicyAudit represents an audit log entry for policy changes
type PolicyAudit struct {
	ID          uuid.UUID       `json:"id" db:"id"`
	PolicyID    uuid.UUID       `json:"policy_id" db:"policy_id"`
	Action      string          `json:"action" db:"action"` // 'create', 'update', 'delete', 'activate', 'deactivate'
	OldValue    json.RawMessage `json:"old_value,omitempty" db:"old_value"`
	NewValue    json.RawMessage `json:"new_value,omitempty" db:"new_value"`
	PerformedBy *uuid.UUID      `json:"performed_by,omitempty" db:"performed_by"`
	PerformedAt time.Time       `json:"performed_at" db:"performed_at"`
}

// CreatePolicyRequest represents the request to create a new policy
type CreatePolicyRequest struct {
	Name        string          `json:"name" binding:"required,min=1,max=100"`
	Description string          `json:"description,omitempty"`
	Effect      PolicyEffect    `json:"effect" binding:"required,oneof=allow deny"`
	Priority    int             `json:"priority"`
	Conditions  json.RawMessage `json:"conditions,omitempty"`
	RegoCode    string          `json:"rego_code,omitempty"`
	IsGlobal    bool            `json:"is_global"`
	IsActive    bool            `json:"is_active"`
}

// UpdatePolicyRequest represents the request to update an existing policy
type UpdatePolicyRequest struct {
	Name        *string          `json:"name,omitempty"`
	Description *string          `json:"description,omitempty"`
	Effect      *PolicyEffect    `json:"effect,omitempty"`
	Priority    *int             `json:"priority,omitempty"`
	Conditions  *json.RawMessage `json:"conditions,omitempty"`
	RegoCode    *string          `json:"rego_code,omitempty"`
	IsActive    *bool            `json:"is_active,omitempty"`
}

// PolicyListResponse represents the paginated list of policies
type PolicyListResponse struct {
	Policies   []Policy `json:"policies"`
	Total      int64    `json:"total"`
	Page       int      `json:"page"`
	PageSize   int      `json:"page_size"`
	TotalPages int      `json:"total_pages"`
}

// PolicyTestRequest represents a request to test a policy
type PolicyTestRequest struct {
	User     map[string]interface{} `json:"user" binding:"required"`
	Resource map[string]interface{} `json:"resource" binding:"required"`
	Action   string                 `json:"action" binding:"required"`
	Context  map[string]interface{} `json:"context,omitempty"`
}

// PolicyTestResponse represents the result of a policy test
type PolicyTestResponse struct {
	Allowed      bool     `json:"allowed"`
	MatchedRules []string `json:"matched_rules,omitempty"`
	Reasons      []string `json:"reasons,omitempty"`
}

// ToResponse converts Policy to a response-safe version
func (p *Policy) ToResponse() *Policy {
	return p
}
