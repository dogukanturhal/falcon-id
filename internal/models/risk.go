// SPDX-License-Identifier: AGPL-3.0-or-later

package models

import (
	"time"

	"github.com/google/uuid"
)

// RiskSignalType represents types of risk signals
type RiskSignalType string

const (
	// RiskSignalImpossibleTravel is an exported identifier.
	RiskSignalImpossibleTravel RiskSignalType = "impossible_travel"
	// RiskSignalNewDevice is an exported identifier.
	RiskSignalNewDevice RiskSignalType = "new_device"
	// RiskSignalUnusualTime is an exported identifier.
	RiskSignalUnusualTime RiskSignalType = "unusual_time"
	// RiskSignalMultipleFailedAttempts is an exported identifier.
	RiskSignalMultipleFailedAttempts RiskSignalType = "multiple_failed_attempts"
	// RiskSignalNewLocation is an exported identifier.
	RiskSignalNewLocation RiskSignalType = "new_location"
	// RiskSignalSuspiciousUserAgent is an exported identifier.
	RiskSignalSuspiciousUserAgent RiskSignalType = "suspicious_user_agent"
	// RiskSignalFirstFederation is an exported identifier.
	RiskSignalFirstFederation RiskSignalType = "first_federation"
	// RiskSignalSSOAttributeMismatch is an exported identifier.
	RiskSignalSSOAttributeMismatch RiskSignalType = "sso_attribute_mismatch"
)

// RiskLevel represents risk levels
type RiskLevel string

const (
	// RiskLevelLow is an exported identifier.
	RiskLevelLow RiskLevel = "low"
	// RiskLevelMedium is an exported identifier.
	RiskLevelMedium RiskLevel = "medium"
	// RiskLevelHigh is an exported identifier.
	RiskLevelHigh RiskLevel = "high"
	// RiskLevelCritical is an exported identifier.
	RiskLevelCritical RiskLevel = "critical"
)

// RiskSignal represents a detected risk signal
type RiskSignal struct {
	ID             uuid.UUID              `json:"id" db:"id"`
	UserID         uuid.UUID              `json:"user_id" db:"user_id"`
	SessionID      *uuid.UUID             `json:"session_id,omitempty" db:"session_id"`
	SignalType     RiskSignalType         `json:"signal_type" db:"signal_type"`
	RiskScore      int                    `json:"risk_score" db:"risk_score"`
	IPAddress      *string                `json:"ip_address,omitempty" db:"ip_address"`
	UserAgent      *string                `json:"user_agent,omitempty" db:"user_agent"`
	AuthMethod     string                 `json:"auth_method,omitempty" db:"auth_method"`   // password, sso, saml
	SSOProvider    string                 `json:"sso_provider,omitempty" db:"sso_provider"` // google, microsoft, apple, etc.
	Details        map[string]interface{} `json:"details,omitempty" db:"details"`
	ResolvedAt     *time.Time             `json:"resolved_at,omitempty" db:"resolved_at"`
	ResolvedBy     *uuid.UUID             `json:"resolved_by,omitempty" db:"resolved_by"`
	ResolutionNote *string                `json:"resolution_note,omitempty" db:"resolution_note"`
	CreatedAt      time.Time              `json:"created_at" db:"created_at"`
}

// RiskPolicy represents a risk policy
type RiskPolicy struct {
	ID          uuid.UUID              `json:"id" db:"id"`
	TenantID    uuid.UUID              `json:"tenant_id" db:"tenant_id"`
	Name        string                 `json:"name" db:"name"`
	Description *string                `json:"description,omitempty" db:"description"`
	Conditions  map[string]interface{} `json:"conditions" db:"conditions"`
	Actions     map[string]interface{} `json:"actions" db:"actions"`
	Priority    int                    `json:"priority" db:"priority"`
	IsActive    bool                   `json:"is_active" db:"is_active"`
	CreatedAt   time.Time              `json:"created_at" db:"created_at"`
	UpdatedAt   time.Time              `json:"updated_at" db:"updated_at"`
}

// RiskThreshold represents tenant risk thresholds
type RiskThreshold struct {
	ID                    uuid.UUID `json:"id" db:"id"`
	TenantID              uuid.UUID `json:"tenant_id" db:"tenant_id"`
	LowThreshold          int       `json:"low_threshold" db:"low_threshold"`
	MediumThreshold       int       `json:"medium_threshold" db:"medium_threshold"`
	HighThreshold         int       `json:"high_threshold" db:"high_threshold"`
	CriticalThreshold     int       `json:"critical_threshold" db:"critical_threshold"`
	AutoBlockOnCritical   bool      `json:"auto_block_on_critical" db:"auto_block_on_critical"`
	BlockDurationMinutes  int       `json:"block_duration_minutes" db:"block_duration_minutes"`
	NotifyUserOnHighRisk  bool      `json:"notify_user_on_high_risk" db:"notify_user_on_high_risk"`
	NotifyAdminOnCritical bool      `json:"notify_admin_on_critical" db:"notify_admin_on_critical"`
	// DefaultMFAAtMedium forces MFA challenge when computed risk level >= medium,
	// even without a matching iam_risk_policies row. Tier-1 baseline; default true.
	DefaultMFAAtMedium bool `json:"default_mfa_at_medium" db:"default_mfa_at_medium"`
	// DefaultMFAAtHigh forces MFA challenge when computed risk level >= high,
	// even without a matching iam_risk_policies row. Tier-1 baseline; default true.
	DefaultMFAAtHigh bool      `json:"default_mfa_at_high" db:"default_mfa_at_high"`
	CreatedAt        time.Time `json:"created_at" db:"created_at"`
	UpdatedAt        time.Time `json:"updated_at" db:"updated_at"`
}

// LoginRiskEvent is a per-login rollup of the risk engine output.
// Companion to RiskSignal (per-signal granularity).
type LoginRiskEvent struct {
	ID          uuid.UUID `json:"id" db:"id"`
	UserID      uuid.UUID `json:"user_id" db:"user_id"`
	TenantID    uuid.UUID `json:"tenant_id" db:"tenant_id"`
	IPAddress   *string   `json:"ip_address,omitempty" db:"ip_address"`
	UserAgent   *string   `json:"user_agent,omitempty" db:"user_agent"`
	// Location: 2-letter country code from CF-IPCountry. Added in
	// migration v0.232.241 — nullable, nil for events captured before
	// the column existed or when the peer wasn't a trusted proxy.
	Location    *string   `json:"location,omitempty" db:"location"`
	TotalScore  int       `json:"total_score" db:"total_score"`
	Level       RiskLevel `json:"level" db:"level"`
	SignalCount int       `json:"signal_count" db:"signal_count"`
	// Outcome: 'allowed' | 'mfa_challenged' | 'blocked'.
	Outcome string `json:"outcome" db:"outcome"`
	// MFATrigger: 'user_enrolled' | 'risk_default_medium' | 'risk_default_high' |
	// 'risk_policy'. NULL when outcome != 'mfa_challenged'.
	MFATrigger  *string   `json:"mfa_trigger,omitempty" db:"mfa_trigger"`
	BlockReason *string   `json:"block_reason,omitempty" db:"block_reason"`
	CreatedAt   time.Time `json:"created_at" db:"created_at"`

	// Edge-stamped geo enrichment added in platform migration v0.232.247.
	// Same source + shape as iam_sessions geo columns (v0.232.246) —
	// X-Geo-* request headers from the geo-stamp Cloudflare
	// Worker, read by middleware.ClientGeo, propagated via clientctx.
	// All nullable: pre-migration rows + non-Cloudflare paths stay NULL.
	ASN       *string `json:"asn,omitempty" db:"asn"`
	ASNOrg    *string `json:"asn_org,omitempty" db:"asn_org"`
	City      *string `json:"city,omitempty" db:"city"`
	Region    *string `json:"region,omitempty" db:"region"`
	IsVPNHint *bool   `json:"is_vpn_hint,omitempty" db:"is_vpn_hint"`
}

// LoginRiskOutcome enumerates the values stored in iam_login_risk_events.outcome.
const (
	LoginRiskOutcomeAllowed       = "allowed"
	LoginRiskOutcomeMFAChallenged = "mfa_challenged"
	LoginRiskOutcomeBlocked       = "blocked"
)

// ToLoginHistoryEntry projects a risk event onto the user-facing login
// history shape served by /api/v1/auth/login-history. DeviceInfo is left
// nil — the consumer (frontend login-history-section) parses the
// user_agent string into a friendly "Chrome on Linux"-style label, and
// risk events only carry the raw UA. If we ever derive a server-side
// parsed label, it'll land here.
func (e *LoginRiskEvent) ToLoginHistoryEntry() *LoginHistoryEntry {
	return &LoginHistoryEntry{
		ID:          e.ID,
		UserAgent:   e.UserAgent,
		IPAddress:   e.IPAddress,
		Location:    e.Location,
		Outcome:     e.Outcome,
		MFATrigger:  e.MFATrigger,
		BlockReason: e.BlockReason,
		RiskLevel:   string(e.Level),
		LoginAt:     e.CreatedAt,
		// Geo enrichment passthrough (v0.232.247). When the risk event
		// row predates the migration or the Worker wasn't in path, these
		// stay nil — the UI handles each field as optional.
		ASN:       e.ASN,
		ASNOrg:    e.ASNOrg,
		City:      e.City,
		Region:    e.Region,
		IsVPNHint: e.IsVPNHint,
	}
}

// MFATrigger values stored in iam_login_risk_events.mfa_trigger.
const (
	MFATriggerUserEnrolled      = "user_enrolled"
	MFATriggerRiskDefaultMedium = "risk_default_medium"
	MFATriggerRiskDefaultHigh   = "risk_default_high"
	MFATriggerRiskPolicy        = "risk_policy"
)

// RiskAssessment represents the result of a risk assessment
type RiskAssessment struct {
	TotalScore   int          `json:"total_score"`
	Level        RiskLevel    `json:"level"`
	Signals      []RiskSignal `json:"signals"`
	Actions      []RiskAction `json:"actions"`
	RequiresMFA  bool         `json:"requires_mfa"`
	Blocked      bool         `json:"blocked"`
	BlockReason  string       `json:"block_reason,omitempty"`
	Warnings     []string     `json:"warnings,omitempty"`
	DelaySeconds int          `json:"delay_seconds,omitempty"`
}

// RiskAction represents an action to take based on risk
type RiskAction struct {
	Type        string `json:"type"` // require_mfa, block, notify_admin, delay, send_email
	Description string `json:"description"`
	PolicyID    string `json:"policy_id,omitempty"`
}

// RiskContext contains context for risk assessment
type RiskContext struct {
	UserID            uuid.UUID  `json:"user_id"`
	TenantID          uuid.UUID  `json:"tenant_id"`
	IPAddress         string     `json:"ip_address"`
	UserAgent         string     `json:"user_agent"`
	// Location is the 2-letter ISO country code derived from Cloudflare's
	// CF-IPCountry request header (middleware.ClientCountry on the raw
	// *http.Request, or middleware.ClientCountryGin on a *gin.Context).
	// Empty when the header is absent or holds CF's "XX"/"T1" markers.
	// Persisted to iam_login_risk_events.location and rendered in the
	// user-facing "Login history" tab alongside the IP.
	Location          string     `json:"location,omitempty"`
	LoginTime         time.Time  `json:"login_time"`
	IsNewDevice       bool       `json:"is_new_device"`
	FailedAttempts    int        `json:"failed_attempts"`
	LastLoginIP       *string    `json:"last_login_ip,omitempty"`
	LastLoginTime     *time.Time `json:"last_login_time,omitempty"`
	AuthMethod        string     `json:"auth_method,omitempty"`         // password, sso, saml
	SSOProvider       string     `json:"sso_provider,omitempty"`        // google, microsoft, github, apple, saml
	IsFirstFederation bool       `json:"is_first_federation,omitempty"` // First time linking via SSO
}

// API Response types

// RiskSignalResponse is the API response for a risk signal
type RiskSignalResponse struct {
	ID             string                 `json:"id"`
	UserID         string                 `json:"user_id"`
	SignalType     string                 `json:"signal_type"`
	RiskScore      int                    `json:"risk_score"`
	IPAddress      string                 `json:"ip_address,omitempty"`
	Details        map[string]interface{} `json:"details,omitempty"`
	ResolvedAt     *time.Time             `json:"resolved_at,omitempty"`
	ResolutionNote string                 `json:"resolution_note,omitempty"`
	CreatedAt      time.Time              `json:"created_at"`
}

// RiskPolicyResponse is the API response for a risk policy
type RiskPolicyResponse struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Description string                 `json:"description,omitempty"`
	Conditions  map[string]interface{} `json:"conditions"`
	Actions     map[string]interface{} `json:"actions"`
	Priority    int                    `json:"priority"`
	IsActive    bool                   `json:"is_active"`
	CreatedAt   time.Time              `json:"created_at"`
	UpdatedAt   time.Time              `json:"updated_at"`
}

// RiskThresholdResponse is the API response for risk thresholds
type RiskThresholdResponse struct {
	LowThreshold          int  `json:"low_threshold"`
	MediumThreshold       int  `json:"medium_threshold"`
	HighThreshold         int  `json:"high_threshold"`
	CriticalThreshold     int  `json:"critical_threshold"`
	AutoBlockOnCritical   bool `json:"auto_block_on_critical"`
	BlockDurationMinutes  int  `json:"block_duration_minutes"`
	NotifyUserOnHighRisk  bool `json:"notify_user_on_high_risk"`
	NotifyAdminOnCritical bool `json:"notify_admin_on_critical"`
}

// Request types

// CreateRiskPolicyRequest is the request to create a risk policy
type CreateRiskPolicyRequest struct {
	Name        string                 `json:"name" binding:"required,min=1,max=100"`
	Description string                 `json:"description"`
	Conditions  map[string]interface{} `json:"conditions" binding:"required"`
	Actions     map[string]interface{} `json:"actions" binding:"required"`
	Priority    int                    `json:"priority"`
	IsActive    bool                   `json:"is_active"`
}

// UpdateRiskPolicyRequest is the request to update a risk policy
type UpdateRiskPolicyRequest struct {
	Name        *string                `json:"name,omitempty"`
	Description *string                `json:"description,omitempty"`
	Conditions  map[string]interface{} `json:"conditions,omitempty"`
	Actions     map[string]interface{} `json:"actions,omitempty"`
	Priority    *int                   `json:"priority,omitempty"`
	IsActive    *bool                  `json:"is_active,omitempty"`
}

// UpdateRiskThresholdRequest is the request to update risk thresholds
type UpdateRiskThresholdRequest struct {
	LowThreshold          *int  `json:"low_threshold,omitempty"`
	MediumThreshold       *int  `json:"medium_threshold,omitempty"`
	HighThreshold         *int  `json:"high_threshold,omitempty"`
	CriticalThreshold     *int  `json:"critical_threshold,omitempty"`
	AutoBlockOnCritical   *bool `json:"auto_block_on_critical,omitempty"`
	BlockDurationMinutes  *int  `json:"block_duration_minutes,omitempty"`
	NotifyUserOnHighRisk  *bool `json:"notify_user_on_high_risk,omitempty"`
	NotifyAdminOnCritical *bool `json:"notify_admin_on_critical,omitempty"`
}

// ResolveRiskSignalRequest is the request to resolve a risk signal
type ResolveRiskSignalRequest struct {
	ResolutionNote string `json:"resolution_note"`
}

// ToResponse converts RiskSignal to RiskSignalResponse
func (r *RiskSignal) ToResponse() *RiskSignalResponse {
	resp := &RiskSignalResponse{
		ID:         r.ID.String(),
		UserID:     r.UserID.String(),
		SignalType: string(r.SignalType),
		RiskScore:  r.RiskScore,
		Details:    r.Details,
		ResolvedAt: r.ResolvedAt,
		CreatedAt:  r.CreatedAt,
	}

	if r.IPAddress != nil {
		resp.IPAddress = *r.IPAddress
	}
	if r.ResolutionNote != nil {
		resp.ResolutionNote = *r.ResolutionNote
	}

	return resp
}

// ToResponse converts RiskPolicy to RiskPolicyResponse
func (r *RiskPolicy) ToResponse() *RiskPolicyResponse {
	resp := &RiskPolicyResponse{
		ID:         r.ID.String(),
		Name:       r.Name,
		Conditions: r.Conditions,
		Actions:    r.Actions,
		Priority:   r.Priority,
		IsActive:   r.IsActive,
		CreatedAt:  r.CreatedAt,
		UpdatedAt:  r.UpdatedAt,
	}

	if r.Description != nil {
		resp.Description = *r.Description
	}

	return resp
}

// ToResponse converts RiskThreshold to RiskThresholdResponse
func (r *RiskThreshold) ToResponse() *RiskThresholdResponse {
	return &RiskThresholdResponse{
		LowThreshold:          r.LowThreshold,
		MediumThreshold:       r.MediumThreshold,
		HighThreshold:         r.HighThreshold,
		CriticalThreshold:     r.CriticalThreshold,
		AutoBlockOnCritical:   r.AutoBlockOnCritical,
		BlockDurationMinutes:  r.BlockDurationMinutes,
		NotifyUserOnHighRisk:  r.NotifyUserOnHighRisk,
		NotifyAdminOnCritical: r.NotifyAdminOnCritical,
	}
}

// TrustedDevice represents a device that the user has marked as trusted
type TrustedDevice struct {
	ID            uuid.UUID  `json:"id" db:"id"`
	UserID        uuid.UUID  `json:"user_id" db:"user_id"`
	DeviceID      string     `json:"device_id" db:"device_id"` // Client-generated device fingerprint
	DeviceInfo    *string    `json:"device_info,omitempty" db:"device_info"`
	UserAgent     *string    `json:"user_agent,omitempty" db:"user_agent"`
	IPAddress     *string    `json:"ip_address,omitempty" db:"ip_address"`
	LastUsedAt    time.Time  `json:"last_used_at" db:"last_used_at"`
	TrustedAt     time.Time  `json:"trusted_at" db:"trusted_at"`
	ExpiresAt     *time.Time `json:"expires_at,omitempty" db:"expires_at"` // Optional expiry for trusted status
	RevokedAt     *time.Time `json:"revoked_at,omitempty" db:"revoked_at"`
	RevokedReason *string    `json:"revoked_reason,omitempty" db:"revoked_reason"`
}

// IsValid checks if the trusted device is still valid
func (t *TrustedDevice) IsValid() bool {
	if t.RevokedAt != nil {
		return false
	}
	if t.ExpiresAt != nil && time.Now().After(*t.ExpiresAt) {
		return false
	}
	return true
}

// TrustedDeviceResponse is the API response for a trusted device
type TrustedDeviceResponse struct {
	ID         string     `json:"id"`
	DeviceID   string     `json:"device_id"`
	DeviceInfo string     `json:"device_info,omitempty"`
	IPAddress  string     `json:"ip_address,omitempty"`
	LastUsedAt time.Time  `json:"last_used_at"`
	TrustedAt  time.Time  `json:"trusted_at"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`
}

// ToResponse converts TrustedDevice to TrustedDeviceResponse
func (t *TrustedDevice) ToResponse() *TrustedDeviceResponse {
	resp := &TrustedDeviceResponse{
		ID:         t.ID.String(),
		DeviceID:   t.DeviceID,
		LastUsedAt: t.LastUsedAt,
		TrustedAt:  t.TrustedAt,
		ExpiresAt:  t.ExpiresAt,
	}
	if t.DeviceInfo != nil {
		resp.DeviceInfo = *t.DeviceInfo
	}
	if t.IPAddress != nil {
		resp.IPAddress = *t.IPAddress
	}
	return resp
}
