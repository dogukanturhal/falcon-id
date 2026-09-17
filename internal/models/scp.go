// SPDX-License-Identifier: AGPL-3.0-or-later

package models

import (
	"time"

	"github.com/google/uuid"
)

// SCPScope represents the scope at which a service control policy applies.
type SCPScope string

const (
	// SCPScopePlatform is an exported identifier.
	SCPScopePlatform SCPScope = "platform"
	// SCPScopeRealm is an exported identifier.
	SCPScopeRealm SCPScope = "realm"
	// SCPScopeTenant is an exported identifier.
	SCPScopeTenant SCPScope = "tenant"
)

// SCPPolicyDocument is the structured body of a service control policy.
// DeniedActions lists action strings that are unconditionally denied (e.g. "iam:DeleteUser").
// DeniedResources lists resource patterns that cannot be acted upon (e.g. "iam:users:*").
// Conditions holds optional key/value pairs that further constrain evaluation.
type SCPPolicyDocument struct {
	DeniedActions   []string               `json:"denied_actions"`
	DeniedResources []string               `json:"denied_resources"`
	Conditions      map[string]interface{} `json:"conditions,omitempty"`
}

// ServiceControlPolicy represents a platform-level guardrail that overrides
// tenant or realm permissions. A single SCP can apply at the platform,
// realm, or tenant scope. Higher-priority values are evaluated first.
type ServiceControlPolicy struct {
	ID             uuid.UUID         `json:"id" db:"id"`
	Name           string            `json:"name" db:"name"`
	Description    string            `json:"description" db:"description"`
	Scope          SCPScope          `json:"scope" db:"scope"`
	ScopeID        *uuid.UUID        `json:"scope_id,omitempty" db:"scope_id"`
	PolicyDocument SCPPolicyDocument `json:"policy_document" db:"policy_document"`
	Priority       int               `json:"priority" db:"priority"`
	IsEnabled      bool              `json:"is_enabled" db:"is_enabled"`
	CreatedAt      time.Time         `json:"created_at" db:"created_at"`
	UpdatedAt      time.Time         `json:"updated_at" db:"updated_at"`
}

// IsDenied reports whether the given action is explicitly denied by this policy.
func (s *ServiceControlPolicy) IsDenied(action string) bool {
	for _, denied := range s.PolicyDocument.DeniedActions {
		if denied == action || denied == "*" {
			return true
		}
	}
	return false
}

// CreateSCPRequest is the request body for creating a new service control policy.
type CreateSCPRequest struct {
	Name           string            `json:"name" binding:"required,min=1,max=255"`
	Description    string            `json:"description" binding:"omitempty,max=1024"`
	Scope          SCPScope          `json:"scope" binding:"required,oneof=platform realm tenant"`
	ScopeID        *uuid.UUID        `json:"scope_id,omitempty"`
	PolicyDocument SCPPolicyDocument `json:"policy_document" binding:"required"`
	Priority       int               `json:"priority" binding:"min=0"`
}

// UpdateSCPRequest is the request body for updating an existing service control policy.
// All fields are optional; only non-nil fields are applied.
type UpdateSCPRequest struct {
	Name           *string            `json:"name,omitempty" binding:"omitempty,min=1,max=255"`
	Description    *string            `json:"description,omitempty" binding:"omitempty,max=1024"`
	PolicyDocument *SCPPolicyDocument `json:"policy_document,omitempty"`
	Priority       *int               `json:"priority,omitempty" binding:"omitempty,min=0"`
}

// SCPResponse is the API representation of a service control policy.
type SCPResponse struct {
	ID             uuid.UUID         `json:"id"`
	Name           string            `json:"name"`
	Description    string            `json:"description"`
	Scope          SCPScope          `json:"scope"`
	ScopeID        *uuid.UUID        `json:"scope_id,omitempty"`
	PolicyDocument SCPPolicyDocument `json:"policy_document"`
	Priority       int               `json:"priority"`
	IsEnabled      bool              `json:"is_enabled"`
	CreatedAt      time.Time         `json:"created_at"`
	UpdatedAt      time.Time         `json:"updated_at"`
}

// ToResponse converts a ServiceControlPolicy to its API response form.
func (s *ServiceControlPolicy) ToResponse() *SCPResponse {
	return &SCPResponse{
		ID:             s.ID,
		Name:           s.Name,
		Description:    s.Description,
		Scope:          s.Scope,
		ScopeID:        s.ScopeID,
		PolicyDocument: s.PolicyDocument,
		Priority:       s.Priority,
		IsEnabled:      s.IsEnabled,
		CreatedAt:      s.CreatedAt,
		UpdatedAt:      s.UpdatedAt,
	}
}

// SCPListResponse is the paginated API response for listing service control policies.
type SCPListResponse struct {
	Policies   []SCPResponse `json:"policies"`
	Total      int64         `json:"total"`
	Page       int           `json:"page"`
	PageSize   int           `json:"page_size"`
	TotalPages int           `json:"total_pages"`
}

// SCPEvaluationResult holds the outcome of evaluating all applicable SCPs.
type SCPEvaluationResult struct {
	Denied bool   `json:"denied"`
	Reason string `json:"reason,omitempty"`
}
