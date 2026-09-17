// SPDX-License-Identifier: AGPL-3.0-or-later

package models

import (
	"time"

	"github.com/google/uuid"
)

// DefaultAccessPolicyType defines whether the policy grants a role or group membership.
type DefaultAccessPolicyType string

const (
	// DefaultAccessPolicyTypeRole is an exported identifier.
	DefaultAccessPolicyTypeRole DefaultAccessPolicyType = "role"
	// DefaultAccessPolicyTypeGroup is an exported identifier.
	DefaultAccessPolicyTypeGroup DefaultAccessPolicyType = "group"
)

// DefaultAccessPolicyScope defines which users the policy applies to.
type DefaultAccessPolicyScope string

const (
	// DefaultAccessPolicyScopeAllUsers is an exported identifier.
	DefaultAccessPolicyScopeAllUsers DefaultAccessPolicyScope = "all_users"
	// DefaultAccessPolicyScopeNewUsersOnly is an exported identifier.
	DefaultAccessPolicyScopeNewUsersOnly DefaultAccessPolicyScope = "new_users_only"
)

// BlockedDefaultRoles are roles that MUST NOT be assigned via default access policies.
// This is a security requirement (SR-DAP-01) to prevent privilege escalation.
var BlockedDefaultRoles = map[string]bool{
	"admin":          true,
	"org_admin":      true,
	"owner":          true,
	"platform_admin": true,
	"super_admin":    true,
	"iam_admin":      true,
}

// MaxDefaultAccessRulesPerTenant is the hard limit on rules per tenant (SR-DAP-05).
const MaxDefaultAccessRulesPerTenant = 50

// MaxDefaultAccessAssignmentsPerUser is the hard limit on assignments per user (SR-DAP-05).
const MaxDefaultAccessAssignmentsPerUser = 20

// DefaultAccessPolicy represents a tenant-level policy that auto-grants roles or
// group memberships to new users.
type DefaultAccessPolicy struct {
	ID         uuid.UUID                `json:"id" db:"id"`
	TenantID   uuid.UUID                `json:"tenant_id" db:"tenant_id"`
	ProductID  *uuid.UUID               `json:"product_id,omitempty" db:"product_id"`
	PolicyType DefaultAccessPolicyType  `json:"policy_type" db:"policy_type"`
	TargetID   uuid.UUID                `json:"target_id" db:"target_id"`
	Scope      DefaultAccessPolicyScope `json:"scope" db:"scope"`
	IsActive   bool                     `json:"is_active" db:"is_active"`
	Priority   int                      `json:"priority" db:"priority"`
	CreatedBy  *uuid.UUID               `json:"created_by,omitempty" db:"created_by"`
	CreatedAt  time.Time                `json:"created_at" db:"created_at"`
	UpdatedAt  time.Time                `json:"updated_at" db:"updated_at"`

	// Joined fields (populated by queries, not stored)
	TargetName  string `json:"target_name,omitempty" db:"target_name"`
	ProductName string `json:"product_name,omitempty" db:"product_name"`
}

// CreateDefaultAccessPolicyRequest is the API request for creating a policy.
type CreateDefaultAccessPolicyRequest struct {
	ProductID  *uuid.UUID               `json:"product_id,omitempty"`
	PolicyType DefaultAccessPolicyType  `json:"policy_type" binding:"required,oneof=role group"`
	TargetID   uuid.UUID                `json:"target_id" binding:"required"`
	Scope      DefaultAccessPolicyScope `json:"scope" binding:"omitempty,oneof=all_users new_users_only"`
	IsActive   *bool                    `json:"is_active,omitempty"`
	Priority   *int                     `json:"priority,omitempty"`
}

// UpdateDefaultAccessPolicyRequest is the API request for updating a policy.
type UpdateDefaultAccessPolicyRequest struct {
	IsActive *bool `json:"is_active,omitempty"`
	Priority *int  `json:"priority,omitempty"`
}

// DefaultAccessPolicyResponse is the API response.
type DefaultAccessPolicyResponse struct {
	ID          uuid.UUID                `json:"id"`
	TenantID    uuid.UUID                `json:"tenant_id"`
	ProductID   *uuid.UUID               `json:"product_id,omitempty"`
	PolicyType  DefaultAccessPolicyType  `json:"policy_type"`
	TargetID    uuid.UUID                `json:"target_id"`
	TargetName  string                   `json:"target_name,omitempty"`
	ProductName string                   `json:"product_name,omitempty"`
	Scope       DefaultAccessPolicyScope `json:"scope"`
	IsActive    bool                     `json:"is_active"`
	Priority    int                      `json:"priority"`
	CreatedBy   *uuid.UUID               `json:"created_by,omitempty"`
	CreatedAt   time.Time                `json:"created_at"`
	UpdatedAt   time.Time                `json:"updated_at"`
}

// ToResponse converts the model to an API response.
func (p *DefaultAccessPolicy) ToResponse() *DefaultAccessPolicyResponse {
	return &DefaultAccessPolicyResponse{
		ID:          p.ID,
		TenantID:    p.TenantID,
		ProductID:   p.ProductID,
		PolicyType:  p.PolicyType,
		TargetID:    p.TargetID,
		TargetName:  p.TargetName,
		ProductName: p.ProductName,
		Scope:       p.Scope,
		IsActive:    p.IsActive,
		Priority:    p.Priority,
		CreatedBy:   p.CreatedBy,
		CreatedAt:   p.CreatedAt,
		UpdatedAt:   p.UpdatedAt,
	}
}
