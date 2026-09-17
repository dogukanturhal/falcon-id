// SPDX-License-Identifier: AGPL-3.0-or-later

package models

import (
	"time"

	"github.com/google/uuid"
)

// ============================================================
// TENANT MANAGEMENT MODELS
// ============================================================

// TenantFilters represents filters for listing tenants
type TenantFilters struct {
	Status string `json:"status,omitempty"`
	Type   string `json:"type,omitempty"`
	Search string `json:"search,omitempty"`
	Plan   string `json:"plan,omitempty"`
}

// SuspendTenantRequest represents a request to suspend a tenant
type SuspendTenantRequest struct {
	Reason string `json:"reason" binding:"required"`
}

// UpdateTenantRequest represents a request to update tenant details
type UpdateTenantRequest struct {
	Name   *string `json:"name,omitempty"`
	Domain *string `json:"domain,omitempty"`
	Tier   *string `json:"tier,omitempty"`   // maps to plan column
	Status *string `json:"status,omitempty"` // active, trial, suspended
}

// TenantListResponse represents the response for listing tenants
type TenantListResponse struct {
	Tenants    []TenantResponse `json:"tenants"`
	Pagination PaginationInfo   `json:"pagination"`
}

// TenantResponse represents tenant data for API responses
type TenantResponse struct {
	ID            uuid.UUID  `json:"id"`
	Name          string     `json:"name"`
	Slug          string     `json:"slug"`
	DisplayName   string     `json:"display_name"`
	Domain        *string    `json:"domain,omitempty"`
	Status        string     `json:"status"`
	Type          string     `json:"type,omitempty"`
	Plan          string     `json:"plan"`
	BillingEmail  *string    `json:"billing_email,omitempty"`
	BillingExempt bool       `json:"billing_exempt"`
	MaxUsers      int        `json:"max_users"`
	MaxStorage    int64      `json:"max_storage"`
	TrialEndsAt   *time.Time `json:"trial_ends_at,omitempty"`
	SuspendedAt   *time.Time `json:"suspended_at,omitempty"`
	CancelledAt   *time.Time `json:"cancelled_at,omitempty"`
	CreatedAt     time.Time  `json:"created_at"`
	UpdatedAt     time.Time  `json:"updated_at"`

	// Owner info (populated in ListAll via JOIN)
	OwnerEmail *string `json:"owner_email,omitempty"`
	OwnerName  *string `json:"owner_name,omitempty"`

	// Statistics
	UserCount       *int64 `json:"user_count,omitempty"`
	ActiveUserCount *int64 `json:"active_user_count,omitempty"`
}

// PaginationInfo represents pagination metadata
type PaginationInfo struct {
	Page       int   `json:"page"`
	PageSize   int   `json:"page_size"`
	Total      int64 `json:"total"`
	TotalPages int64 `json:"total_pages"`
}

// ============================================================
// USER MANAGEMENT MODELS
// ============================================================

// PlatformResetPasswordRequest represents a request to reset a user's password (platform admin)
type PlatformResetPasswordRequest struct {
	Password           string `json:"password" binding:"required,min=8"`
	MustChangePassword *bool  `json:"must_change_password,omitempty"`
}

// BulkUserOperation represents a bulk operation on users
type BulkUserOperation struct {
	ID                uuid.UUID  `json:"id" db:"id"`
	TenantID          uuid.UUID  `json:"tenant_id" db:"tenant_id"`
	OperationType     string     `json:"operation_type" db:"operation_type"`
	InitiatedBy       uuid.UUID  `json:"initiated_by" db:"initiated_by"`
	InitiatedByName   string     `json:"initiated_by_name,omitempty" db:"initiated_by_username"`
	TotalRecords      int        `json:"total_records" db:"total_records"`
	ProcessedRecords  int        `json:"processed_records" db:"processed_records"`
	SuccessfulRecords int        `json:"successful_records" db:"successful_records"`
	FailedRecords     int        `json:"failed_records" db:"failed_records"`
	Status            string     `json:"status" db:"status"`
	InputFileURL      *string    `json:"input_file_url,omitempty" db:"input_file_url"`
	OutputFileURL     *string    `json:"output_file_url,omitempty" db:"output_file_url"`
	ErrorFileURL      *string    `json:"error_file_url,omitempty" db:"error_file_url"`
	StartedAt         *time.Time `json:"started_at,omitempty" db:"started_at"`
	CompletedAt       *time.Time `json:"completed_at,omitempty" db:"completed_at"`
	CreatedAt         time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt         time.Time  `json:"updated_at" db:"updated_at"`
}

// BulkRoleAssignmentRequest represents a request to assign roles to multiple users
type BulkRoleAssignmentRequest struct {
	UserIDs []uuid.UUID `json:"user_ids" binding:"required,min=1"`
	RoleIDs []uuid.UUID `json:"role_ids" binding:"required,min=1"`
}

// BulkUserActionRequest represents a request for bulk user actions
type BulkUserActionRequest struct {
	UserIDs []uuid.UUID `json:"user_ids" binding:"required,min=1"`
	Action  string      `json:"action" binding:"required"` // "activate", "deactivate", "delete"
}

// ============================================================
// PLATFORM AUDIT LOG MODELS
// ============================================================

// PlatformAuditLog represents an audit entry for platform admin actions
type PlatformAuditLog struct {
	ID                 uuid.UUID              `json:"id" db:"id"`
	AdminUserID        uuid.UUID              `json:"admin_user_id" db:"admin_user_id"`
	AdminUsername      string                 `json:"admin_username,omitempty" db:"admin_username"`
	TargetTenantID     *uuid.UUID             `json:"target_tenant_id,omitempty" db:"target_tenant_id"`
	TargetTenantName   *string                `json:"target_tenant_name,omitempty" db:"target_tenant_name"`
	TargetUserID       *uuid.UUID             `json:"target_user_id,omitempty" db:"target_user_id"`
	TargetResourceType string                 `json:"target_resource_type,omitempty" db:"target_resource_type"`
	TargetResourceID   *uuid.UUID             `json:"target_resource_id,omitempty" db:"target_resource_id"`
	Action             string                 `json:"action" db:"action"`
	ActionCategory     string                 `json:"action_category,omitempty" db:"action_category"`
	Details            map[string]interface{} `json:"details,omitempty" db:"details"`
	IPAddress          string                 `json:"ip_address,omitempty" db:"ip_address"`
	UserAgent          string                 `json:"user_agent,omitempty" db:"user_agent"`
	RequestID          string                 `json:"request_id,omitempty" db:"request_id"`
	Success            bool                   `json:"success" db:"success"`
	ErrorMessage       *string                `json:"error_message,omitempty" db:"error_message"`
	CreatedAt          time.Time              `json:"created_at" db:"created_at"`
}

// PlatformAuditFilters represents filters for platform audit logs
type PlatformAuditFilters struct {
	Action         string     `json:"action,omitempty"`
	TargetTenantID *uuid.UUID `json:"target_tenant_id,omitempty"`
	AdminUserID    *uuid.UUID `json:"admin_user_id,omitempty"`
	ActionCategory string     `json:"action_category,omitempty"`
	From           *time.Time `json:"from,omitempty"`
	To             *time.Time `json:"to,omitempty"`
}

// ============================================================
// PLATFORM STATISTICS MODELS
// ============================================================

// PlatformStatistics represents platform-wide statistics
type PlatformStatistics struct {
	TenantStats   TenantStatistics `json:"tenant_stats"`
	UserStats     UserStatistics   `json:"user_stats"`
	ActivityStats ActivityStats    `json:"activity_stats"`
	ResourceStats ResourceStats    `json:"resource_stats"`
	CalculatedAt  time.Time        `json:"calculated_at"`
}

// TenantStatistics represents tenant-related statistics
type TenantStatistics struct {
	TotalTenants     int64            `json:"total_tenants"`
	ActiveTenants    int64            `json:"active_tenants"`
	TrialTenants     int64            `json:"trial_tenants"`
	SuspendedTenants int64            `json:"suspended_tenants"`
	ByPlan           map[string]int64 `json:"by_plan"`
	ByType           map[string]int64 `json:"by_type"`
	NewThisMonth     int64            `json:"new_this_month"`
	ChurnedThisMonth int64            `json:"churned_this_month"`
}

// UserStatistics represents user-related statistics
type UserStatistics struct {
	TotalUsers      int64 `json:"total_users"`
	ActiveUsers     int64 `json:"active_users"`
	LockedUsers     int64 `json:"locked_users"`
	VerifiedUsers   int64 `json:"verified_users"`
	MFAEnabledUsers int64 `json:"mfa_enabled_users"`
	NewThisMonth    int64 `json:"new_this_month"`
	LoginsThisMonth int64 `json:"logins_this_month"`
}

// ActivityStats represents recent activity statistics
type ActivityStats struct {
	LoginAttemptsToday    int64 `json:"login_attempts_today"`
	SuccessfulLoginsToday int64 `json:"successful_logins_today"`
	FailedLoginsToday     int64 `json:"failed_logins_today"`
	PasswordResetsToday   int64 `json:"password_resets_today"`
	AccountLocksToday     int64 `json:"account_locks_today"`
	ImpersonationsToday   int64 `json:"impersonations_today"`
}

// ResourceStats represents resource usage statistics
type ResourceStats struct {
	TotalStorageUsedBytes  int64   `json:"total_storage_used_bytes"`
	TotalAPICallsThisMonth int64   `json:"total_api_calls_this_month"`
	AverageUsersPerTenant  float64 `json:"average_users_per_tenant"`
}

// ============================================================
// EMAIL QUOTA MODELS (for cross-service use)
// ============================================================

// EmailQuota represents email quota for a tenant
type EmailQuota struct {
	ID                uuid.UUID  `json:"id" db:"id"`
	TenantID          uuid.UUID  `json:"tenant_id" db:"tenant_id"`
	HourlyLimit       int        `json:"hourly_limit" db:"hourly_limit"`
	DailyLimit        int        `json:"daily_limit" db:"daily_limit"`
	MonthlyLimit      int        `json:"monthly_limit" db:"monthly_limit"`
	CurrentHourCount  int        `json:"current_hour_count" db:"current_hour_count"`
	CurrentDayCount   int        `json:"current_day_count" db:"current_day_count"`
	CurrentMonthCount int        `json:"current_month_count" db:"current_month_count"`
	HourResetAt       time.Time  `json:"hour_reset_at" db:"hour_reset_at"`
	DayResetAt        time.Time  `json:"day_reset_at" db:"day_reset_at"`
	MonthResetAt      time.Time  `json:"month_reset_at" db:"month_reset_at"`
	IsEnforced        bool       `json:"is_enforced" db:"is_enforced"`
	AllowBurst        bool       `json:"allow_burst" db:"allow_burst"`
	BurstMultiplier   float64    `json:"burst_multiplier" db:"burst_multiplier"`
	NotifyAtPercent   int        `json:"notify_at_percent" db:"notify_at_percent"`
	LastWarningSentAt *time.Time `json:"last_warning_sent_at,omitempty" db:"last_warning_sent_at"`
	CreatedAt         time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt         time.Time  `json:"updated_at" db:"updated_at"`
}

// UpdateEmailQuotaRequest represents a request to update email quota
type UpdateEmailQuotaRequest struct {
	HourlyLimit     *int     `json:"hourly_limit,omitempty"`
	DailyLimit      *int     `json:"daily_limit,omitempty"`
	MonthlyLimit    *int     `json:"monthly_limit,omitempty"`
	IsEnforced      *bool    `json:"is_enforced,omitempty"`
	AllowBurst      *bool    `json:"allow_burst,omitempty"`
	BurstMultiplier *float64 `json:"burst_multiplier,omitempty"`
	NotifyAtPercent *int     `json:"notify_at_percent,omitempty"`
}
