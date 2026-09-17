// SPDX-License-Identifier: AGPL-3.0-or-later

package models

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// SubscriptionTier enumerates the recognised tier labels.
type SubscriptionTier string

const (
	// TierFree is an exported identifier.
	TierFree SubscriptionTier = "free"
	// TierStarter is an exported identifier.
	TierStarter SubscriptionTier = "starter"
	// TierProfessional is an exported identifier.
	TierProfessional SubscriptionTier = "professional"
	// TierEnterprise is an exported identifier.
	TierEnterprise SubscriptionTier = "enterprise"
)

// TenantQuota holds the per-tenant rate-limit and quota configuration that is
// stored in the tenant_quotas table.  A missing row means the tenant has not
// had its quota explicitly configured; callers should fall back to the defaults
// for the tenant's subscription tier via DefaultQuotas.
type TenantQuota struct {
	TenantID              uuid.UUID        `json:"tenant_id"                 db:"tenant_id"`
	SubscriptionTier      SubscriptionTier `json:"subscription_tier"         db:"subscription_tier"`
	APIRequestsPerMinute  int              `json:"api_requests_per_minute"   db:"api_requests_per_minute"`
	APIRequestsPerHour    int              `json:"api_requests_per_hour"     db:"api_requests_per_hour"`
	APIRequestsPerDay     int              `json:"api_requests_per_day"      db:"api_requests_per_day"`
	AuthAttemptsPerMinute int              `json:"auth_attempts_per_minute"  db:"auth_attempts_per_minute"`
	TokenRefreshPerMinute int              `json:"token_refresh_per_minute"  db:"token_refresh_per_minute"`
	BurstMultiplier       float64          `json:"burst_multiplier"          db:"burst_multiplier"`
	CustomLimits          json.RawMessage  `json:"custom_limits,omitempty"   db:"custom_limits"`
	UpdatedAt             time.Time        `json:"updated_at"                db:"updated_at"`
	UpdatedBy             *uuid.UUID       `json:"updated_by,omitempty"      db:"updated_by"`
}

// QuotaDefaults holds the default quota values for a subscription tier.  It
// mirrors TenantQuota but without database-specific fields.
type QuotaDefaults struct {
	SubscriptionTier      SubscriptionTier `json:"subscription_tier"`
	APIRequestsPerMinute  int              `json:"api_requests_per_minute"`
	APIRequestsPerHour    int              `json:"api_requests_per_hour"`
	APIRequestsPerDay     int              `json:"api_requests_per_day"`
	AuthAttemptsPerMinute int              `json:"auth_attempts_per_minute"`
	TokenRefreshPerMinute int              `json:"token_refresh_per_minute"`
	BurstMultiplier       float64          `json:"burst_multiplier"`
}

// DefaultQuotas maps each subscription tier to its quota defaults.  These are
// the values used when a tenant has no explicit row in tenant_quotas.
var DefaultQuotas = map[SubscriptionTier]QuotaDefaults{
	TierFree: {
		SubscriptionTier:      TierFree,
		APIRequestsPerMinute:  60,
		APIRequestsPerHour:    1_000,
		APIRequestsPerDay:     10_000,
		AuthAttemptsPerMinute: 5,
		TokenRefreshPerMinute: 10,
		BurstMultiplier:       1.0,
	},
	TierStarter: {
		SubscriptionTier:      TierStarter,
		APIRequestsPerMinute:  300,
		APIRequestsPerHour:    10_000,
		APIRequestsPerDay:     100_000,
		AuthAttemptsPerMinute: 10,
		TokenRefreshPerMinute: 30,
		BurstMultiplier:       1.5,
	},
	TierProfessional: {
		SubscriptionTier:      TierProfessional,
		APIRequestsPerMinute:  1_000,
		APIRequestsPerHour:    50_000,
		APIRequestsPerDay:     500_000,
		AuthAttemptsPerMinute: 20,
		TokenRefreshPerMinute: 60,
		BurstMultiplier:       2.0,
	},
	TierEnterprise: {
		SubscriptionTier:      TierEnterprise,
		APIRequestsPerMinute:  10_000,
		APIRequestsPerHour:    500_000,
		APIRequestsPerDay:     10_000_000,
		AuthAttemptsPerMinute: 100,
		TokenRefreshPerMinute: 300,
		BurstMultiplier:       3.0,
	},
}

// FromDefaults builds a TenantQuota for the given tenant from the tier defaults.
// It does NOT set UpdatedAt or UpdatedBy; those are set during persistence.
func FromDefaults(tenantID uuid.UUID, tier SubscriptionTier) TenantQuota {
	d, ok := DefaultQuotas[tier]
	if !ok {
		d = DefaultQuotas[TierFree]
	}
	return TenantQuota{
		TenantID:              tenantID,
		SubscriptionTier:      d.SubscriptionTier,
		APIRequestsPerMinute:  d.APIRequestsPerMinute,
		APIRequestsPerHour:    d.APIRequestsPerHour,
		APIRequestsPerDay:     d.APIRequestsPerDay,
		AuthAttemptsPerMinute: d.AuthAttemptsPerMinute,
		TokenRefreshPerMinute: d.TokenRefreshPerMinute,
		BurstMultiplier:       d.BurstMultiplier,
	}
}

// ============================================================
// Request / Response DTOs
// ============================================================

// CreateQuotaRequest is the payload for creating a tenant quota record.
type CreateQuotaRequest struct {
	SubscriptionTier      SubscriptionTier `json:"subscription_tier"          binding:"required"`
	APIRequestsPerMinute  *int             `json:"api_requests_per_minute"`
	APIRequestsPerHour    *int             `json:"api_requests_per_hour"`
	APIRequestsPerDay     *int             `json:"api_requests_per_day"`
	AuthAttemptsPerMinute *int             `json:"auth_attempts_per_minute"`
	TokenRefreshPerMinute *int             `json:"token_refresh_per_minute"`
	BurstMultiplier       *float64         `json:"burst_multiplier"`
	CustomLimits          json.RawMessage  `json:"custom_limits,omitempty"`
}

// UpdateQuotaRequest is the payload for updating an existing tenant quota.  All
// fields are optional; only non-nil values overwrite the existing record.
type UpdateQuotaRequest struct {
	SubscriptionTier      *SubscriptionTier `json:"subscription_tier"`
	APIRequestsPerMinute  *int              `json:"api_requests_per_minute"`
	APIRequestsPerHour    *int              `json:"api_requests_per_hour"`
	APIRequestsPerDay     *int              `json:"api_requests_per_day"`
	AuthAttemptsPerMinute *int              `json:"auth_attempts_per_minute"`
	TokenRefreshPerMinute *int              `json:"token_refresh_per_minute"`
	BurstMultiplier       *float64          `json:"burst_multiplier"`
	CustomLimits          json.RawMessage   `json:"custom_limits,omitempty"`
}

// TenantQuotaResponse is the JSON representation returned to callers.
type TenantQuotaResponse struct {
	TenantID              uuid.UUID        `json:"tenant_id"`
	SubscriptionTier      SubscriptionTier `json:"subscription_tier"`
	APIRequestsPerMinute  int              `json:"api_requests_per_minute"`
	APIRequestsPerHour    int              `json:"api_requests_per_hour"`
	APIRequestsPerDay     int              `json:"api_requests_per_day"`
	AuthAttemptsPerMinute int              `json:"auth_attempts_per_minute"`
	TokenRefreshPerMinute int              `json:"token_refresh_per_minute"`
	BurstMultiplier       float64          `json:"burst_multiplier"`
	CustomLimits          json.RawMessage  `json:"custom_limits,omitempty"`
	UpdatedAt             time.Time        `json:"updated_at"`
	UpdatedBy             *uuid.UUID       `json:"updated_by,omitempty"`
	IsDefault             bool             `json:"is_default"` // true when synthesised from tier defaults
}

// ToResponse converts a TenantQuota to its HTTP response form.
func (q *TenantQuota) ToResponse() *TenantQuotaResponse {
	return &TenantQuotaResponse{
		TenantID:              q.TenantID,
		SubscriptionTier:      q.SubscriptionTier,
		APIRequestsPerMinute:  q.APIRequestsPerMinute,
		APIRequestsPerHour:    q.APIRequestsPerHour,
		APIRequestsPerDay:     q.APIRequestsPerDay,
		AuthAttemptsPerMinute: q.AuthAttemptsPerMinute,
		TokenRefreshPerMinute: q.TokenRefreshPerMinute,
		BurstMultiplier:       q.BurstMultiplier,
		CustomLimits:          q.CustomLimits,
		UpdatedAt:             q.UpdatedAt,
		UpdatedBy:             q.UpdatedBy,
		IsDefault:             false,
	}
}

// TierDefaultsResponse is the response for GET /quota/tiers.
type TierDefaultsResponse struct {
	Tiers map[SubscriptionTier]QuotaDefaults `json:"tiers"`
}

// UpdateTierDefaultRequest is the payload for PUT /quota/tiers/:tier.
// This updates the in-memory defaults; it does NOT persist to the database.
type UpdateTierDefaultRequest struct {
	APIRequestsPerMinute  *int     `json:"api_requests_per_minute"`
	APIRequestsPerHour    *int     `json:"api_requests_per_hour"`
	APIRequestsPerDay     *int     `json:"api_requests_per_day"`
	AuthAttemptsPerMinute *int     `json:"auth_attempts_per_minute"`
	TokenRefreshPerMinute *int     `json:"token_refresh_per_minute"`
	BurstMultiplier       *float64 `json:"burst_multiplier"`
}
