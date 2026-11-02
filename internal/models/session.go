// SPDX-License-Identifier: AGPL-3.0-or-later

package models

import (
	"time"

	"github.com/google/uuid"
)

// Session is an exported type.
type Session struct {
	ID               uuid.UUID `json:"id" db:"id"`
	UserID           uuid.UUID `json:"user_id" db:"user_id"`
	SessionTokenHash string    `json:"-" db:"session_token_hash"`
	DeviceInfo       *string   `json:"device_info,omitempty" db:"device_info"`
	IPAddress        *string   `json:"ip_address,omitempty" db:"ip_address"`
	UserAgent        *string   `json:"user_agent,omitempty" db:"user_agent"`
	// Location is the legacy free-form text label. Pre-v0.232.245 it
	// doubled as the country-code home (varchar, no constraint); new
	// writers populate CountryCode below and leave Location nil.
	Location *string `json:"location,omitempty" db:"location"`
	// CountryCode is the ISO 3166-1 alpha-2 country code stamped by
	// middleware.ClientCountry from Cloudflare's CF-IPCountry header.
	// Backed by the typed varchar(2) column added in platform migration
	// v0.232.245; two upper-case A–Z letters or NULL.
	CountryCode *string `json:"country_code,omitempty" db:"country_code"`

	// Edge-stamped geo enrichment added in platform migration
	// v0.232.246 — sourced from the `geo-stamp` Cloudflare
	// Worker (the edge infrastructure repository) which reads request.cf at
	// edge time and stamps X-Geo-* request headers. falcon-id's
	// middleware.ClientGeo reads those, clientctx.WithGeo propagates
	// onto the request ctx, and createSession persists below.
	//
	// All fields nullable: pre-migration rows have no values; sessions
	// created while the Worker is not in path (local-dev, internal
	// service calls, future non-Cloudflare ingress) also have no
	// values. Display surface (accounts.example.com Login History)
	// handles each field as optional.
	//
	// ASN: numeric AS number kept as string to round-trip CF's wire
	//      form unchanged (CF emits e.g. "13335").
	// ASNOrg: human-friendly ASN organization, e.g. "Vodafone Mobile".
	// City / Region: free-form labels from CF's GeoIP DB.
	// IsVPNHint: derived by ClientGeo from a regex match against
	//      ASNOrg. Informational only — surfaces as a [VPN] badge,
	//      never a security verdict / block decision.
	ASN        *string `json:"asn,omitempty" db:"asn"`
	ASNOrg     *string `json:"asn_org,omitempty" db:"asn_org"`
	City       *string `json:"city,omitempty" db:"city"`
	Region     *string `json:"region,omitempty" db:"region"`
	IsVPNHint  *bool   `json:"is_vpn_hint,omitempty" db:"is_vpn_hint"`

	IsActive       bool       `json:"is_active" db:"is_active"`
	CreatedAt      time.Time  `json:"created_at" db:"created_at"`
	LastActivityAt time.Time  `json:"last_activity_at" db:"last_activity_at"`
	ExpiresAt      time.Time  `json:"expires_at" db:"expires_at"`
	EndedAt        *time.Time `json:"ended_at,omitempty" db:"ended_at"`
	EndReason      *string    `json:"end_reason,omitempty" db:"end_reason"`

	// SAML SLO metadata (populated only for SAML SSO sessions)
	SAMLProviderID   *uuid.UUID `json:"saml_provider_id,omitempty" db:"saml_provider_id"`
	SAMLNameID       *string    `json:"saml_name_id,omitempty" db:"saml_name_id"`
	SAMLSessionIndex *string    `json:"saml_session_index,omitempty" db:"saml_session_index"`

	// Session fixation protection fields (migration 060)
	AuthenticatedAt    *time.Time `json:"authenticated_at,omitempty" db:"authenticated_at"`
	PreviousSessionID  *uuid.UUID `json:"previous_session_id,omitempty" db:"previous_session_id"`
	SessionRegenerated bool       `json:"session_regenerated" db:"session_regenerated"`

	// RFC 8176 Authentication Method Reference values captured for this session.
	// Populated at login / MFA completion and snapshotted onto issued OAuth
	// authorization codes and tokens so id_tokens preserve `amr` across
	// refresh-token rotations (migration 211).
	AuthMethodsUsed []string `json:"auth_methods_used,omitempty" db:"auth_methods_used"`
}

// SessionResponse is an exported type.
type SessionResponse struct {
	ID             uuid.UUID `json:"id"`
	UserID         uuid.UUID `json:"user_id"`
	Username       string    `json:"username,omitempty"`
	DeviceInfo     *string   `json:"device_info,omitempty"`
	IPAddress      *string   `json:"ip_address,omitempty"`
	UserAgent      *string   `json:"user_agent,omitempty"`
	Location       *string   `json:"location,omitempty"`
	CountryCode    *string   `json:"country_code,omitempty"`
	// Geo enrichment surface (v0.232.246+). Nullable per-field — UI
	// must tolerate every field being absent independently.
	ASN            *string   `json:"asn,omitempty"`
	ASNOrg         *string   `json:"asn_org,omitempty"`
	City           *string   `json:"city,omitempty"`
	Region         *string   `json:"region,omitempty"`
	IsVPNHint      *bool     `json:"is_vpn_hint,omitempty"`
	IsActive       bool      `json:"is_active"`
	IsCurrent      bool      `json:"is_current"`
	CreatedAt      time.Time `json:"created_at"`
	LastActivityAt time.Time `json:"last_activity_at"`
	ExpiresAt      time.Time `json:"expires_at"`
}

// SessionWithUser holds session data joined with user info
type SessionWithUser struct {
	Session
	Username string `db:"username"`
}

// SessionListResponse is an exported type.
type SessionListResponse struct {
	Sessions []SessionResponse `json:"sessions"`
	Total    int64             `json:"total"`
}

// LoginHistoryEntry represents a single login attempt (success OR failure).
//
// Sourced from iam_login_risk_events as of v0.232.241 — previously this
// model mirrored iam_sessions, but sessions only persist successful
// authentications, so failed attempts (blocked by risk policy, MFA
// failures, etc.) never appeared in the user-facing "Login history" tab.
// Risk events are recorded per attempt regardless of outcome.
//
// Outcome enumerates the same values as iam_login_risk_events.outcome:
//
//	"allowed"        — login completed (may or may not have required MFA).
//	"mfa_challenged" — MFA prompt issued. Whether it was completed is
//	                    tracked via the resulting session's auth_methods_used;
//	                    from this tab's POV the attempt label is "MFA required".
//	"blocked"        — risk engine rejected the attempt. BlockReason carries
//	                    the human-friendly rule label.
type LoginHistoryEntry struct {
	ID          uuid.UUID `json:"id"`
	UserAgent   *string   `json:"user_agent,omitempty"`
	DeviceInfo  *string   `json:"device_info,omitempty"`
	IPAddress   *string   `json:"ip_address,omitempty"`
	Location    *string   `json:"location,omitempty"`
	Outcome     string    `json:"outcome"`
	MFATrigger  *string   `json:"mfa_trigger,omitempty"`
	BlockReason *string   `json:"block_reason,omitempty"`
	RiskLevel   string    `json:"risk_level,omitempty"`
	LoginAt     time.Time `json:"login_at"`
	// Geo enrichment per attempt — sourced from iam_login_risk_events
	// (platform migration v0.232.247) via the same Cloudflare Worker
	// chain that populates iam_sessions geo columns.
	ASN       *string `json:"asn,omitempty"`
	ASNOrg    *string `json:"asn_org,omitempty"`
	City      *string `json:"city,omitempty"`
	Region    *string `json:"region,omitempty"`
	IsVPNHint *bool   `json:"is_vpn_hint,omitempty"`
}

// LoginHistoryResponse represents a paginated login history response
type LoginHistoryResponse struct {
	History    []LoginHistoryEntry `json:"history"`
	Total      int64               `json:"total"`
	Page       int                 `json:"page"`
	PageSize   int                 `json:"page_size"`
	TotalPages int                 `json:"total_pages"`
}

// ToLoginHistoryEntry converts a session to a login history entry.
//
// Deprecated as of v0.232.241: /login-history now sources from
// iam_login_risk_events via LoginRiskEvent.ToLoginHistoryEntry (in
// risk.go). This method stays for backward-compat tests + any caller
// that still treats sessions as the history backing store. New code
// should drive the History tab from the risk-event projection.
func (s *Session) ToLoginHistoryEntry() *LoginHistoryEntry {
	return &LoginHistoryEntry{
		ID:         s.ID,
		DeviceInfo: s.DeviceInfo,
		IPAddress:  s.IPAddress,
		UserAgent:  s.UserAgent,
		Location:   s.Location,
		// A persisted session implies authentication succeeded — outcome
		// is always "allowed" for the legacy session-sourced shape.
		Outcome: "allowed",
		LoginAt: s.CreatedAt,
	}
}

// ToResponse is an exported function.
func (s *Session) ToResponse(currentSessionID *uuid.UUID) *SessionResponse {
	isCurrent := currentSessionID != nil && s.ID == *currentSessionID

	return &SessionResponse{
		ID:             s.ID,
		UserID:         s.UserID,
		DeviceInfo:     s.DeviceInfo,
		IPAddress:      s.IPAddress,
		UserAgent:      s.UserAgent,
		Location:       s.Location,
		CountryCode:    s.CountryCode,
		ASN:            s.ASN,
		ASNOrg:         s.ASNOrg,
		City:           s.City,
		Region:         s.Region,
		IsVPNHint:      s.IsVPNHint,
		IsActive:       s.IsActive,
		IsCurrent:      isCurrent,
		CreatedAt:      s.CreatedAt,
		LastActivityAt: s.LastActivityAt,
		ExpiresAt:      s.ExpiresAt,
	}
}

// ToResponse is an exported function.
func (s *SessionWithUser) ToResponse(currentSessionID *uuid.UUID) *SessionResponse {
	resp := s.Session.ToResponse(currentSessionID)
	resp.Username = s.Username
	return resp
}

// Non-explicit iam_sessions.end_reason values: the SSO session lapsed or was
// swapped for a fresh one without anyone ending it. Refresh tokens bound to
// such a session stay valid (they carry their own lifetime); every other
// reason (logout, revoked, password_change, ...) is an explicit end.
const (
	SessionEndReasonExpired            = "expired"
	SessionEndReasonInactivityTimeout  = "inactivity_timeout"
	SessionEndReasonRegenerated        = "session_regenerated"
	SessionEndReasonRegeneratedOnLogin = "session_regenerated_on_login"
)

// IsExplicitSessionEnd reports whether a session ended for a reason that must
// also terminate the refresh tokens bound to it. Fail-closed: an unknown or
// future reason counts as explicit, only the lapse/rotation reasons above do not.
func IsExplicitSessionEnd(endReason string) bool {
	switch endReason {
	case SessionEndReasonExpired,
		SessionEndReasonInactivityTimeout,
		SessionEndReasonRegenerated,
		SessionEndReasonRegeneratedOnLogin:
		return false
	}
	return true
}
