// SPDX-License-Identifier: AGPL-3.0-or-later

package models

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// ==================== Threat Signal ====================

// ThreatSignalType identifies the detection technique that produced a signal.
type ThreatSignalType string

const (
	// ThreatSignalTypeImpossibleTravel fires when consecutive logins arrive from
	// locations that are physically unreachable within the elapsed time.
	ThreatSignalTypeImpossibleTravel ThreatSignalType = "impossible_travel"

	// ThreatSignalTypeCredentialStuffingBurst fires when a single IP exceeds the
	// failed-login velocity threshold within a rolling time window.
	ThreatSignalTypeCredentialStuffingBurst ThreatSignalType = "credential_stuffing_burst" //nolint:gosec // not a credential, this is a threat detection indicator name constant

	// ThreatSignalTypeMFAFatigue fires when too many MFA push prompts are sent to a
	// user within a short window without any successful approval.
	ThreatSignalTypeMFAFatigue ThreatSignalType = "mfa_fatigue"

	// ThreatSignalTypeSessionAnomaly fires when an active session is presented from a
	// different IP address or user-agent than the one used at session creation.
	ThreatSignalTypeSessionAnomaly ThreatSignalType = "session_anomaly"

	// ThreatSignalTypeCompromisedCredential fires when a password's SHA-1 hash prefix
	// appears in the HaveIBeenPwned k-anonymity dataset.
	ThreatSignalTypeCompromisedCredential ThreatSignalType = "compromised_credential"
)

// ThreatSignalSeverity is the assessed impact level for a ThreatSignal.
type ThreatSignalSeverity string

const (
	// ThreatSignalSeverityLow is an exported identifier.
	ThreatSignalSeverityLow ThreatSignalSeverity = "low"
	// ThreatSignalSeverityMedium is an exported identifier.
	ThreatSignalSeverityMedium ThreatSignalSeverity = "medium"
	// ThreatSignalSeverityHigh is an exported identifier.
	ThreatSignalSeverityHigh ThreatSignalSeverity = "high"
	// ThreatSignalSeverityCritical is an exported identifier.
	ThreatSignalSeverityCritical ThreatSignalSeverity = "critical"
)

// ThreatSignalStatus tracks the alert lifecycle for a ThreatSignal.
type ThreatSignalStatus string

const (
	// ThreatSignalStatusOpen is an exported identifier.
	ThreatSignalStatusOpen ThreatSignalStatus = "open"
	// ThreatSignalStatusAcknowledged is an exported identifier.
	ThreatSignalStatusAcknowledged ThreatSignalStatus = "acknowledged"
	// ThreatSignalStatusResolved is an exported identifier.
	ThreatSignalStatusResolved ThreatSignalStatus = "resolved"
)

// ThreatSignal is an atomic security indicator produced by one of the ITDR
// detectors.  Multiple signals can be correlated into a higher-level alert.
//
// DB table: iam_threat_signals
type ThreatSignal struct {
	ID         uuid.UUID            `json:"id" db:"id"`
	SignalType ThreatSignalType     `json:"signal_type" db:"signal_type"`
	Severity   ThreatSignalSeverity `json:"severity" db:"severity"`
	UserID     *uuid.UUID           `json:"user_id,omitempty" db:"user_id"`
	TenantID   *uuid.UUID           `json:"tenant_id,omitempty" db:"tenant_id"`
	// Details holds detector-specific key/value pairs (e.g. distance_km, velocity).
	// Stored as JSONB in PostgreSQL.
	Details   map[string]interface{} `json:"details" db:"details"`
	Status    ThreatSignalStatus     `json:"status" db:"status"`
	CreatedAt time.Time              `json:"created_at" db:"created_at"`
	// UpdatedAt is refreshed whenever the signal is acknowledged or resolved.
	UpdatedAt      time.Time  `json:"updated_at" db:"updated_at"`
	AcknowledgedBy *uuid.UUID `json:"acknowledged_by,omitempty" db:"acknowledged_by"`
	AcknowledgedAt *time.Time `json:"acknowledged_at,omitempty" db:"acknowledged_at"`
}

// ==================== Detection Rule ====================

// ITDRDetectionRuleType mirrors ThreatSignalType and identifies which detector
// the rule configures.
type ITDRDetectionRuleType string

const (
	// ITDRRuleTypeImpossibleTravel is an exported identifier.
	ITDRRuleTypeImpossibleTravel ITDRDetectionRuleType = "impossible_travel"
	// ITDRRuleTypeCredentialStuffingBurst is an exported identifier.
	ITDRRuleTypeCredentialStuffingBurst ITDRDetectionRuleType = "credential_stuffing_burst" //nolint:gosec // not a credential, this is a threat detection indicator name constant
	// ITDRRuleTypeMFAFatigue is an exported identifier.
	ITDRRuleTypeMFAFatigue ITDRDetectionRuleType = "mfa_fatigue"
	// ITDRRuleTypeSessionAnomaly is an exported identifier.
	ITDRRuleTypeSessionAnomaly ITDRDetectionRuleType = "session_anomaly"
	// ITDRRuleTypeCompromisedCredential is an exported identifier.
	ITDRRuleTypeCompromisedCredential ITDRDetectionRuleType = "compromised_credential"
)

// ITDRDetectionRule holds runtime-configurable thresholds and state for a
// single ITDR detector.  Rules are seeded at migration time and updated via
// the admin API.
//
// DB table: iam_detection_rules
type ITDRDetectionRule struct {
	ID       uuid.UUID             `json:"id" db:"id"`
	Name     string                `json:"name" db:"name"`
	RuleType ITDRDetectionRuleType `json:"rule_type" db:"rule_type"`
	Enabled  bool                  `json:"enabled" db:"enabled"`
	// Config holds detector-specific thresholds encoded as JSONB, e.g.
	// {"threshold": 20, "window_seconds": 300, "max_speed_kmh": 500}.
	Config    map[string]interface{} `json:"config" db:"config"`
	CreatedAt time.Time              `json:"created_at" db:"created_at"`
	UpdatedAt time.Time              `json:"updated_at" db:"updated_at"`
}

// ==================== ITDR Alert ====================

// ITDRAlert groups one or more ThreatSignals into a trackable security alert.
//
// DB table: iam_threat_signals (status column drives the alert lifecycle;
// a dedicated alert table is not required at this scale — the signal itself
// acts as the alert unit).

// ==================== Threat Response ====================

// ThreatResponseAction enumerates automated responses the ITDR engine can
// invoke when a signal is emitted.
type ThreatResponseAction string

const (
	// ThreatResponseBlockIP adds the source IP to the deny list.
	ThreatResponseBlockIP ThreatResponseAction = "block_ip"
	// ThreatResponseRequireMFA forces the affected session to re-authenticate with MFA.
	ThreatResponseRequireMFA ThreatResponseAction = "require_mfa"
	// ThreatResponseDisableUser suspends the user account.
	ThreatResponseDisableUser ThreatResponseAction = "disable_user"
	// ThreatResponseNotifyAdmin sends an alert to tenant administrators.
	ThreatResponseNotifyAdmin ThreatResponseAction = "notify_admin"
)

// ThreatResponse is a record of an automated action taken in response to a
// ThreatSignal.
//
// DB table: iam_threat_responses
type ThreatResponse struct {
	ID       uuid.UUID            `json:"id" db:"id"`
	SignalID uuid.UUID            `json:"signal_id" db:"signal_id"`
	Action   ThreatResponseAction `json:"action" db:"action"`
	// Payload stores action-specific data (e.g. the IP that was blocked).
	Payload map[string]interface{} `json:"payload" db:"payload"`
	// Success indicates whether the automated action completed without error.
	Success   bool      `json:"success" db:"success"`
	Error     *string   `json:"error,omitempty" db:"error"`
	CreatedAt time.Time `json:"created_at" db:"created_at"`
}

// ==================== API Request / Response DTOs ====================

// ThreatSignalListParams holds query parameters for listing threat signals.
type ThreatSignalListParams struct {
	Page       int                  `form:"page"`
	PageSize   int                  `form:"page_size"`
	SignalType ThreatSignalType     `form:"signal_type"`
	Severity   ThreatSignalSeverity `form:"severity"`
	Status     ThreatSignalStatus   `form:"status"`
	UserID     *uuid.UUID           `form:"user_id"`
	TenantID   *uuid.UUID           `form:"tenant_id"`
	From       *time.Time           `form:"from"`
	To         *time.Time           `form:"to"`
}

// ThreatSignalResponse is the JSON representation returned by the API.
type ThreatSignalResponse struct {
	ID             uuid.UUID              `json:"id"`
	SignalType     ThreatSignalType       `json:"signal_type"`
	Severity       ThreatSignalSeverity   `json:"severity"`
	UserID         *uuid.UUID             `json:"user_id,omitempty"`
	TenantID       *uuid.UUID             `json:"tenant_id,omitempty"`
	Details        map[string]interface{} `json:"details"`
	Status         ThreatSignalStatus     `json:"status"`
	CreatedAt      time.Time              `json:"created_at"`
	UpdatedAt      time.Time              `json:"updated_at"`
	AcknowledgedBy *uuid.UUID             `json:"acknowledged_by,omitempty"`
	AcknowledgedAt *time.Time             `json:"acknowledged_at,omitempty"`
}

// ThreatSignalListResponse is the paginated API envelope.
type ThreatSignalListResponse struct {
	Signals    []ThreatSignalResponse `json:"signals"`
	Total      int64                  `json:"total"`
	Page       int                    `json:"page"`
	PageSize   int                    `json:"page_size"`
	TotalPages int                    `json:"total_pages"`
}

// AcknowledgeSignalRequest is the request body for the acknowledge endpoint.
type AcknowledgeSignalRequest struct {
	// Note is an optional free-text comment from the analyst.
	Note string `json:"note"`
}

// DetectionRuleResponse is the JSON representation of an ITDRDetectionRule.
type DetectionRuleResponse struct {
	ID        uuid.UUID              `json:"id"`
	Name      string                 `json:"name"`
	RuleType  ITDRDetectionRuleType  `json:"rule_type"`
	Enabled   bool                   `json:"enabled"`
	Config    map[string]interface{} `json:"config"`
	CreatedAt time.Time              `json:"created_at"`
	UpdatedAt time.Time              `json:"updated_at"`
}

// UpdateDetectionRuleRequest is the request body for updating a detection rule.
// All fields are optional to allow partial updates.
type UpdateDetectionRuleRequest struct {
	Enabled *bool                  `json:"enabled"`
	Config  map[string]interface{} `json:"config"`
}

// ==================== Conversion helpers ====================

// ToResponse converts a ThreatSignal to its API response form.
func (s *ThreatSignal) ToResponse() ThreatSignalResponse {
	return ThreatSignalResponse{
		ID:             s.ID,
		SignalType:     s.SignalType,
		Severity:       s.Severity,
		UserID:         s.UserID,
		TenantID:       s.TenantID,
		Details:        s.Details,
		Status:         s.Status,
		CreatedAt:      s.CreatedAt,
		UpdatedAt:      s.UpdatedAt,
		AcknowledgedBy: s.AcknowledgedBy,
		AcknowledgedAt: s.AcknowledgedAt,
	}
}

// ToResponse converts an ITDRDetectionRule to its API response form.
func (r *ITDRDetectionRule) ToResponse() DetectionRuleResponse {
	return DetectionRuleResponse{
		ID:        r.ID,
		Name:      r.Name,
		RuleType:  r.RuleType,
		Enabled:   r.Enabled,
		Config:    r.Config,
		CreatedAt: r.CreatedAt,
		UpdatedAt: r.UpdatedAt,
	}
}

// ==================== Pipeline input context ====================

// ITDRLoginEvent carries all data points the detection pipeline needs when a
// login attempt (successful or failed) occurs.
type ITDRLoginEvent struct {
	UserID    *uuid.UUID
	TenantID  *uuid.UUID
	IPAddress string
	UserAgent string
	// GeoLat and GeoLon are the decimal coordinates derived from the IP.
	// Both are zero when geolocation is unavailable.
	GeoLat  float64
	GeoLon  float64
	Success bool
	// RawPassword is the plaintext password — used only for the compromised
	// credential check (SHA-1 hashed before any network call is made).
	// It must never be stored or logged.
	// SECURITY: json:"-" prevents accidental serialisation of the plaintext password.
	RawPassword string `json:"-"`
	// PasswordSHA1Prefix is the first 5 characters of the upper-case hex SHA-1
	// hash of the password.  It is pre-computed by the caller before constructing
	// this event so that RawPassword can be zeroed out immediately after use.
	// The prefix is the only value sent to the HIBP k-anonymity API.
	PasswordSHA1Prefix string `json:"-"`
	OccurredAt         time.Time
}

// ITDRSessionEvent carries data for session anomaly detection.
type ITDRSessionEvent struct {
	SessionID         uuid.UUID
	UserID            uuid.UUID
	TenantID          uuid.UUID
	CurrentIP         string
	CurrentUserAgent  string
	OriginalIP        string
	OriginalUserAgent string
}

// ITDRMFAEvent carries data for MFA fatigue detection.
type ITDRMFAEvent struct {
	UserID   uuid.UUID
	TenantID uuid.UUID
	// Success is false when the MFA prompt was sent but not yet approved.
	Success bool
}

// ITDRDetectionResult collects any signals emitted by the pipeline for a
// single event.
type ITDRDetectionResult struct {
	Signals []ThreatSignal
}

// HasSignals returns true when at least one signal was produced.
func (r *ITDRDetectionResult) HasSignals() bool {
	return len(r.Signals) > 0
}

// MarshalDetails serialises a map to json.RawMessage for use in ThreatEvent.
func MarshalDetails(d map[string]interface{}) json.RawMessage {
	b, _ := json.Marshal(d)
	return b
}
