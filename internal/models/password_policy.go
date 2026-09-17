// SPDX-License-Identifier: AGPL-3.0-or-later

package models

import (
	"time"

	"github.com/google/uuid"
)

// PasswordPolicy represents tenant-specific password rules
type PasswordPolicy struct {
	ID       uuid.UUID `json:"id" db:"id"`
	TenantID uuid.UUID `json:"tenant_id" db:"tenant_id"`

	// Complexity requirements
	MinLength               int  `json:"min_length" db:"min_length"`
	MaxLength               *int `json:"max_length,omitempty" db:"max_length"`
	RequireUppercase        bool `json:"require_uppercase" db:"require_uppercase"`
	RequireLowercase        bool `json:"require_lowercase" db:"require_lowercase"`
	RequireNumbers          bool `json:"require_numbers" db:"require_numbers"`
	RequireSpecial          bool `json:"require_special" db:"require_special"`
	DisallowUsername        bool `json:"disallow_username" db:"disallow_username"`
	DisallowCommonPasswords bool `json:"disallow_common_passwords" db:"disallow_common_passwords"`

	// Password expiration
	MaxAgeDays              int `json:"max_age_days" db:"max_age_days"`
	WarningDaysBeforeExpiry int `json:"warning_days_before_expiry" db:"warning_days_before_expiry"`

	// Password history
	HistoryCount int `json:"history_count" db:"history_count"`

	// Lockout settings
	LockoutThreshold       int     `json:"lockout_threshold" db:"lockout_threshold"`
	LockoutDurationMinutes int     `json:"lockout_duration_minutes" db:"lockout_duration_minutes"`
	LockoutIncrementFactor float64 `json:"lockout_increment_factor" db:"lockout_increment_factor"`

	// Session settings
	RequirePasswordChangeOnFirstLogin bool `json:"require_password_change_on_first_login" db:"require_password_change_on_first_login"`

	// Metadata
	CreatedAt time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt time.Time  `json:"updated_at" db:"updated_at"`
	CreatedBy *uuid.UUID `json:"created_by,omitempty" db:"created_by"`
	UpdatedBy *uuid.UUID `json:"updated_by,omitempty" db:"updated_by"`
}

// PasswordHistory tracks previous passwords for a user
type PasswordHistory struct {
	ID           uuid.UUID `json:"id" db:"id"`
	UserID       uuid.UUID `json:"user_id" db:"user_id"`
	PasswordHash string    `json:"-" db:"password_hash"`
	CreatedAt    time.Time `json:"created_at" db:"created_at"`
}

// PasswordPolicyRequest for creating/updating password policy
type PasswordPolicyRequest struct {
	MinLength                         *int     `json:"min_length,omitempty" binding:"omitempty,min=1,max=128"`
	MaxLength                         *int     `json:"max_length,omitempty" binding:"omitempty,min=8,max=1024"`
	RequireUppercase                  *bool    `json:"require_uppercase,omitempty"`
	RequireLowercase                  *bool    `json:"require_lowercase,omitempty"`
	RequireNumbers                    *bool    `json:"require_numbers,omitempty"`
	RequireSpecial                    *bool    `json:"require_special,omitempty"`
	DisallowUsername                  *bool    `json:"disallow_username,omitempty"`
	DisallowCommonPasswords           *bool    `json:"disallow_common_passwords,omitempty"`
	MaxAgeDays                        *int     `json:"max_age_days,omitempty" binding:"omitempty,min=0,max=365"`
	WarningDaysBeforeExpiry           *int     `json:"warning_days_before_expiry,omitempty" binding:"omitempty,min=0,max=90"`
	HistoryCount                      *int     `json:"history_count,omitempty" binding:"omitempty,min=0,max=24"`
	LockoutThreshold                  *int     `json:"lockout_threshold,omitempty" binding:"omitempty,min=0,max=100"`
	LockoutDurationMinutes            *int     `json:"lockout_duration_minutes,omitempty" binding:"omitempty,min=0,max=1440"`
	LockoutIncrementFactor            *float64 `json:"lockout_increment_factor,omitempty"`
	RequirePasswordChangeOnFirstLogin *bool    `json:"require_password_change_on_first_login,omitempty"`
}

// PasswordPolicyResponse for API responses
type PasswordPolicyResponse struct {
	ID       uuid.UUID `json:"id"`
	TenantID uuid.UUID `json:"tenant_id"`

	// Complexity requirements
	MinLength               int  `json:"min_length"`
	MaxLength               *int `json:"max_length,omitempty"`
	RequireUppercase        bool `json:"require_uppercase"`
	RequireLowercase        bool `json:"require_lowercase"`
	RequireNumbers          bool `json:"require_numbers"`
	RequireSpecial          bool `json:"require_special"`
	DisallowUsername        bool `json:"disallow_username"`
	DisallowCommonPasswords bool `json:"disallow_common_passwords"`

	// Password expiration
	MaxAgeDays              int `json:"max_age_days"`
	WarningDaysBeforeExpiry int `json:"warning_days_before_expiry"`

	// Password history
	HistoryCount int `json:"history_count"`

	// Lockout settings
	LockoutThreshold       int     `json:"lockout_threshold"`
	LockoutDurationMinutes int     `json:"lockout_duration_minutes"`
	LockoutIncrementFactor float64 `json:"lockout_increment_factor"`

	// Session settings
	RequirePasswordChangeOnFirstLogin bool `json:"require_password_change_on_first_login"`

	// Metadata
	UpdatedAt time.Time `json:"updated_at"`
}

// ToResponse converts PasswordPolicy to PasswordPolicyResponse
func (p *PasswordPolicy) ToResponse() *PasswordPolicyResponse {
	return &PasswordPolicyResponse{
		ID:                                p.ID,
		TenantID:                          p.TenantID,
		MinLength:                         p.MinLength,
		MaxLength:                         p.MaxLength,
		RequireUppercase:                  p.RequireUppercase,
		RequireLowercase:                  p.RequireLowercase,
		RequireNumbers:                    p.RequireNumbers,
		RequireSpecial:                    p.RequireSpecial,
		DisallowUsername:                  p.DisallowUsername,
		DisallowCommonPasswords:           p.DisallowCommonPasswords,
		MaxAgeDays:                        p.MaxAgeDays,
		WarningDaysBeforeExpiry:           p.WarningDaysBeforeExpiry,
		HistoryCount:                      p.HistoryCount,
		LockoutThreshold:                  p.LockoutThreshold,
		LockoutDurationMinutes:            p.LockoutDurationMinutes,
		LockoutIncrementFactor:            p.LockoutIncrementFactor,
		RequirePasswordChangeOnFirstLogin: p.RequirePasswordChangeOnFirstLogin,
		UpdatedAt:                         p.UpdatedAt,
	}
}

// DefaultPasswordPolicy returns a default policy
func DefaultPasswordPolicy(tenantID uuid.UUID) *PasswordPolicy {
	return &PasswordPolicy{
		ID:                                uuid.New(),
		TenantID:                          tenantID,
		MinLength:                         8,
		MaxLength:                         nil,
		RequireUppercase:                  true,
		RequireLowercase:                  true,
		RequireNumbers:                    true,
		RequireSpecial:                    false,
		DisallowUsername:                  true,
		DisallowCommonPasswords:           true,
		MaxAgeDays:                        0,
		WarningDaysBeforeExpiry:           14,
		HistoryCount:                      5,
		LockoutThreshold:                  5,
		LockoutDurationMinutes:            30,
		LockoutIncrementFactor:            1.0,
		RequirePasswordChangeOnFirstLogin: true,
	}
}
