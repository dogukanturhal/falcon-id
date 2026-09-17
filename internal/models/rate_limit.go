// SPDX-License-Identifier: AGPL-3.0-or-later

package models

import (
	"time"

	"github.com/google/uuid"
)

// RateLimitScope defines the scope of rate limiting
type RateLimitScope string

const (
	// RateLimitScopeIP is an exported identifier.
	RateLimitScopeIP RateLimitScope = "ip"
	// RateLimitScopeUser is an exported identifier.
	RateLimitScopeUser RateLimitScope = "user"
	// RateLimitScopeTenant is an exported identifier.
	RateLimitScopeTenant RateLimitScope = "tenant"
	// RateLimitScopeGlobal is an exported identifier.
	RateLimitScopeGlobal RateLimitScope = "global"
)

// RateLimitRule defines a rate limiting rule
type RateLimitRule struct {
	ID                   uuid.UUID      `json:"id" db:"id"`
	TenantID             *uuid.UUID     `json:"tenant_id,omitempty" db:"tenant_id"`
	Name                 string         `json:"name" db:"name"`
	Description          *string        `json:"description,omitempty" db:"description"`
	EndpointPattern      string         `json:"endpoint_pattern" db:"endpoint_pattern"`
	Method               *string        `json:"method,omitempty" db:"method"`
	MaxRequests          int            `json:"max_requests" db:"max_requests"`
	WindowSeconds        int            `json:"window_seconds" db:"window_seconds"`
	BlockDurationSeconds int            `json:"block_duration_seconds" db:"block_duration_seconds"`
	Scope                RateLimitScope `json:"scope" db:"scope"`
	IsActive             bool           `json:"is_active" db:"is_active"`
	Priority             int            `json:"priority" db:"priority"`
	CreatedAt            time.Time      `json:"created_at" db:"created_at"`
	UpdatedAt            time.Time      `json:"updated_at" db:"updated_at"`
	CreatedBy            *uuid.UUID     `json:"created_by,omitempty" db:"created_by"`
	UpdatedBy            *uuid.UUID     `json:"updated_by,omitempty" db:"updated_by"`
}

// RateLimitEvent tracks rate limit hits
type RateLimitEvent struct {
	ID           uuid.UUID  `json:"id" db:"id"`
	RuleID       *uuid.UUID `json:"rule_id,omitempty" db:"rule_id"`
	TenantID     *uuid.UUID `json:"tenant_id,omitempty" db:"tenant_id"`
	Identifier   string     `json:"identifier" db:"identifier"`
	Endpoint     string     `json:"endpoint" db:"endpoint"`
	RequestCount int        `json:"request_count" db:"request_count"`
	Blocked      bool       `json:"blocked" db:"blocked"`
	BlockedUntil *time.Time `json:"blocked_until,omitempty" db:"blocked_until"`
	CreatedAt    time.Time  `json:"created_at" db:"created_at"`
}

// RateLimitState represents the current state of rate limiting for a key
type RateLimitState struct {
	Key          string    `json:"key"`
	Requests     int       `json:"requests"`
	WindowStart  time.Time `json:"window_start"`
	WindowEnd    time.Time `json:"window_end"`
	Blocked      bool      `json:"blocked"`
	BlockedUntil time.Time `json:"blocked_until,omitempty"`
	Remaining    int       `json:"remaining"`
	ResetAt      time.Time `json:"reset_at"`
}

// CreateRateLimitRuleRequest is the request to create a rate limit rule
type CreateRateLimitRuleRequest struct {
	Name                 string  `json:"name" binding:"required,min=1,max=100"`
	Description          *string `json:"description,omitempty" binding:"omitempty,max=500"`
	EndpointPattern      string  `json:"endpoint_pattern" binding:"required,min=1,max=255"`
	Method               *string `json:"method,omitempty" binding:"omitempty,oneof=GET POST PUT PATCH DELETE"`
	MaxRequests          int     `json:"max_requests" binding:"required,min=1,max=100000"`
	WindowSeconds        int     `json:"window_seconds" binding:"required,min=1,max=86400"`
	BlockDurationSeconds *int    `json:"block_duration_seconds,omitempty" binding:"omitempty,min=0,max=86400"`
	Scope                string  `json:"scope" binding:"required,oneof=ip user tenant global"`
	Priority             *int    `json:"priority,omitempty" binding:"omitempty,min=0,max=1000"`
	IsActive             *bool   `json:"is_active,omitempty"`
}

// UpdateRateLimitRuleRequest is the request to update a rate limit rule
type UpdateRateLimitRuleRequest struct {
	Name                 *string `json:"name,omitempty" binding:"omitempty,min=1,max=100"`
	Description          *string `json:"description,omitempty" binding:"omitempty,max=500"`
	EndpointPattern      *string `json:"endpoint_pattern,omitempty" binding:"omitempty,min=1,max=255"`
	Method               *string `json:"method,omitempty" binding:"omitempty,oneof=GET POST PUT PATCH DELETE"`
	MaxRequests          *int    `json:"max_requests,omitempty" binding:"omitempty,min=1,max=100000"`
	WindowSeconds        *int    `json:"window_seconds,omitempty" binding:"omitempty,min=1,max=86400"`
	BlockDurationSeconds *int    `json:"block_duration_seconds,omitempty" binding:"omitempty,min=0,max=86400"`
	Scope                *string `json:"scope,omitempty" binding:"omitempty,oneof=ip user tenant global"`
	Priority             *int    `json:"priority,omitempty" binding:"omitempty,min=0,max=1000"`
	IsActive             *bool   `json:"is_active,omitempty"`
}

// RateLimitRuleResponse is the response for a rate limit rule
type RateLimitRuleResponse struct {
	ID                   uuid.UUID  `json:"id"`
	TenantID             *uuid.UUID `json:"tenant_id,omitempty"`
	Name                 string     `json:"name"`
	Description          *string    `json:"description,omitempty"`
	EndpointPattern      string     `json:"endpoint_pattern"`
	Method               *string    `json:"method,omitempty"`
	MaxRequests          int        `json:"max_requests"`
	WindowSeconds        int        `json:"window_seconds"`
	BlockDurationSeconds int        `json:"block_duration_seconds"`
	Scope                string     `json:"scope"`
	IsActive             bool       `json:"is_active"`
	Priority             int        `json:"priority"`
	CreatedAt            time.Time  `json:"created_at"`
	UpdatedAt            time.Time  `json:"updated_at"`
}

// ToResponse converts a RateLimitRule to RateLimitRuleResponse
func (r *RateLimitRule) ToResponse() *RateLimitRuleResponse {
	return &RateLimitRuleResponse{
		ID:                   r.ID,
		TenantID:             r.TenantID,
		Name:                 r.Name,
		Description:          r.Description,
		EndpointPattern:      r.EndpointPattern,
		Method:               r.Method,
		MaxRequests:          r.MaxRequests,
		WindowSeconds:        r.WindowSeconds,
		BlockDurationSeconds: r.BlockDurationSeconds,
		Scope:                string(r.Scope),
		IsActive:             r.IsActive,
		Priority:             r.Priority,
		CreatedAt:            r.CreatedAt,
		UpdatedAt:            r.UpdatedAt,
	}
}

// RateLimitEventResponse is the response for rate limit events
type RateLimitEventResponse struct {
	ID           uuid.UUID  `json:"id"`
	RuleID       *uuid.UUID `json:"rule_id,omitempty"`
	TenantID     *uuid.UUID `json:"tenant_id,omitempty"`
	Identifier   string     `json:"identifier"`
	Endpoint     string     `json:"endpoint"`
	RequestCount int        `json:"request_count"`
	Blocked      bool       `json:"blocked"`
	BlockedUntil *time.Time `json:"blocked_until,omitempty"`
	CreatedAt    time.Time  `json:"created_at"`
}
