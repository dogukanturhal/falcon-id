// SPDX-License-Identifier: AGPL-3.0-or-later

package models

import (
	"time"

	"github.com/google/uuid"
)

// IPRuleType defines whether the rule allows or denies traffic
type IPRuleType string

const (
	// IPRuleTypeAllow is an exported identifier.
	IPRuleTypeAllow IPRuleType = "allow"
	// IPRuleTypeDeny is an exported identifier.
	IPRuleTypeDeny IPRuleType = "deny"
)

// IPRuleAppliesTo defines what the rule applies to
type IPRuleAppliesTo string

const (
	// IPRuleAppliesToAll is an exported identifier.
	IPRuleAppliesToAll IPRuleAppliesTo = "all"
	// IPRuleAppliesToAdmin is an exported identifier.
	IPRuleAppliesToAdmin IPRuleAppliesTo = "admin"
	// IPRuleAppliesToAPI is an exported identifier.
	IPRuleAppliesToAPI IPRuleAppliesTo = "api"
	// IPRuleAppliesToUser is an exported identifier.
	IPRuleAppliesToUser IPRuleAppliesTo = "user"
)

// IPRule represents an IP whitelist/blacklist rule
type IPRule struct {
	ID          uuid.UUID       `json:"id" db:"id"`
	TenantID    uuid.UUID       `json:"tenant_id" db:"tenant_id"`
	Name        string          `json:"name" db:"name"`
	Description *string         `json:"description,omitempty" db:"description"`
	IPPattern   string          `json:"ip_pattern" db:"ip_pattern"` // IP or CIDR notation
	RuleType    IPRuleType      `json:"rule_type" db:"rule_type"`   // 'allow' or 'deny'
	Priority    int             `json:"priority" db:"priority"`
	IsActive    bool            `json:"is_active" db:"is_active"`
	AppliesTo   IPRuleAppliesTo `json:"applies_to" db:"applies_to"`
	ExpiresAt   *time.Time      `json:"expires_at,omitempty" db:"expires_at"`
	HitCount    int64           `json:"hit_count" db:"hit_count"`
	LastHitAt   *time.Time      `json:"last_hit_at,omitempty" db:"last_hit_at"`
	CreatedAt   time.Time       `json:"created_at" db:"created_at"`
	UpdatedAt   time.Time       `json:"updated_at" db:"updated_at"`
	CreatedBy   *uuid.UUID      `json:"created_by,omitempty" db:"created_by"`
	UpdatedBy   *uuid.UUID      `json:"updated_by,omitempty" db:"updated_by"`
}

// IPRuleLog represents a log entry for IP rule matches
type IPRuleLog struct {
	ID        uuid.UUID  `json:"id" db:"id"`
	RuleID    *uuid.UUID `json:"rule_id,omitempty" db:"rule_id"`
	TenantID  *uuid.UUID `json:"tenant_id,omitempty" db:"tenant_id"`
	IPAddress string     `json:"ip_address" db:"ip_address"`
	Action    string     `json:"action" db:"action"` // 'allowed' or 'denied'
	Endpoint  string     `json:"endpoint" db:"endpoint"`
	UserAgent string     `json:"user_agent,omitempty" db:"user_agent"`
	CreatedAt time.Time  `json:"created_at" db:"created_at"`
}

// CreateIPRuleRequest is the request to create an IP rule
type CreateIPRuleRequest struct {
	Name        string  `json:"name" validate:"required,min=1,max=100"`
	Description *string `json:"description,omitempty"`
	IPPattern   string  `json:"ip_pattern" validate:"required,min=1,max=50"`
	RuleType    string  `json:"rule_type" validate:"required,oneof=allow deny"`
	Priority    *int    `json:"priority,omitempty" validate:"omitempty,min=0,max=1000"`
	AppliesTo   *string `json:"applies_to,omitempty" validate:"omitempty,oneof=all admin api user"`
	ExpiresAt   *string `json:"expires_at,omitempty"` // ISO 8601 datetime string
	IsActive    *bool   `json:"is_active,omitempty"`
}

// UpdateIPRuleRequest is the request to update an IP rule
type UpdateIPRuleRequest struct {
	Name        *string `json:"name,omitempty" validate:"omitempty,min=1,max=100"`
	Description *string `json:"description,omitempty"`
	IPPattern   *string `json:"ip_pattern,omitempty" validate:"omitempty,min=1,max=50"`
	RuleType    *string `json:"rule_type,omitempty" validate:"omitempty,oneof=allow deny"`
	Priority    *int    `json:"priority,omitempty" validate:"omitempty,min=0,max=1000"`
	AppliesTo   *string `json:"applies_to,omitempty" validate:"omitempty,oneof=all admin api user"`
	ExpiresAt   *string `json:"expires_at,omitempty"` // ISO 8601 datetime string, empty string to clear
	IsActive    *bool   `json:"is_active,omitempty"`
}

// IPRuleResponse is the response for an IP rule
type IPRuleResponse struct {
	ID          uuid.UUID  `json:"id"`
	TenantID    uuid.UUID  `json:"tenant_id"`
	Name        string     `json:"name"`
	Description *string    `json:"description,omitempty"`
	IPPattern   string     `json:"ip_pattern"`
	RuleType    string     `json:"rule_type"`
	Priority    int        `json:"priority"`
	IsActive    bool       `json:"is_active"`
	AppliesTo   string     `json:"applies_to"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
	HitCount    int64      `json:"hit_count"`
	LastHitAt   *time.Time `json:"last_hit_at,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
}

// ToResponse converts an IPRule to IPRuleResponse
func (r *IPRule) ToResponse() *IPRuleResponse {
	return &IPRuleResponse{
		ID:          r.ID,
		TenantID:    r.TenantID,
		Name:        r.Name,
		Description: r.Description,
		IPPattern:   r.IPPattern,
		RuleType:    string(r.RuleType),
		Priority:    r.Priority,
		IsActive:    r.IsActive,
		AppliesTo:   string(r.AppliesTo),
		ExpiresAt:   r.ExpiresAt,
		HitCount:    r.HitCount,
		LastHitAt:   r.LastHitAt,
		CreatedAt:   r.CreatedAt,
		UpdatedAt:   r.UpdatedAt,
	}
}

// IPRuleLogResponse is the response for an IP rule log
type IPRuleLogResponse struct {
	ID        uuid.UUID  `json:"id"`
	RuleID    *uuid.UUID `json:"rule_id,omitempty"`
	TenantID  *uuid.UUID `json:"tenant_id,omitempty"`
	IPAddress string     `json:"ip_address"`
	Action    string     `json:"action"`
	Endpoint  string     `json:"endpoint"`
	UserAgent string     `json:"user_agent,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
}

// IPCheckResult represents the result of checking an IP against rules
type IPCheckResult struct {
	Allowed   bool      `json:"allowed"`
	RuleID    uuid.UUID `json:"rule_id,omitempty"`
	RuleName  string    `json:"rule_name,omitempty"`
	RuleType  string    `json:"rule_type,omitempty"`
	MatchedIP string    `json:"matched_ip,omitempty"`
}
