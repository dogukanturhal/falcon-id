// SPDX-License-Identifier: AGPL-3.0-or-later

package models

import (
	"time"

	"github.com/google/uuid"
)

// FingerprintTrustLevel represents the computed trust state of a device fingerprint record.
type FingerprintTrustLevel string

const (
	// FingerprintTrustLevelTrusted indicates the fingerprint passed MFA at least once and is
	// explicitly marked trusted by the user or a post-MFA auto-trust policy.
	FingerprintTrustLevelTrusted FingerprintTrustLevel = "trusted"

	// FingerprintTrustLevelKnown indicates the fingerprint has been seen before but has not
	// been explicitly trusted (e.g., seen > 1 time but no MFA success recorded).
	FingerprintTrustLevelKnown FingerprintTrustLevel = "known"

	// FingerprintTrustLevelNew indicates the fingerprint is being seen for the first time.
	FingerprintTrustLevelNew FingerprintTrustLevel = "new"

	// FingerprintTrustLevelSuspicious indicates automated or anomaly-detection logic flagged
	// this fingerprint (e.g., rapid logins from multiple IPs, impossible travel).
	FingerprintTrustLevelSuspicious FingerprintTrustLevel = "suspicious"
)

// DeviceFingerprintRecord is the canonical DB-backed fingerprint record stored in
// iam_device_fingerprints. Each row represents a unique (user_id, fingerprint_hash) pair.
type DeviceFingerprintRecord struct {
	ID              uuid.UUID             `json:"id" db:"id"`
	UserID          uuid.UUID             `json:"user_id" db:"user_id"`
	TenantID        uuid.UUID             `json:"tenant_id" db:"tenant_id"`
	FingerprintHash string                `json:"fingerprint_hash" db:"fingerprint_hash"`
	UserAgent       string                `json:"user_agent" db:"user_agent"`
	Platform        string                `json:"platform" db:"platform"`
	Browser         string                `json:"browser" db:"browser"`
	BrowserVersion  string                `json:"browser_version" db:"browser_version"`
	ScreenRes       string                `json:"screen_res" db:"screen_res"`
	Timezone        string                `json:"timezone" db:"timezone"`
	Language        string                `json:"language" db:"language"`
	IPAddress       string                `json:"ip_address" db:"ip_address"`
	GeoCountry      string                `json:"geo_country" db:"geo_country"`
	GeoCity         string                `json:"geo_city" db:"geo_city"`
	FirstSeenAt     time.Time             `json:"first_seen_at" db:"first_seen_at"`
	LastSeenAt      time.Time             `json:"last_seen_at" db:"last_seen_at"`
	TrustLevel      FingerprintTrustLevel `json:"trust_level" db:"trust_level"`
	LoginCount      int                   `json:"login_count" db:"login_count"`
}

// DeviceFingerprintRecordResponse is the API-facing view of a fingerprint record.
// It omits the raw hash and internal IDs that clients do not need.
type DeviceFingerprintRecordResponse struct {
	ID             uuid.UUID             `json:"id"`
	UserAgent      string                `json:"user_agent"`
	Platform       string                `json:"platform"`
	Browser        string                `json:"browser"`
	BrowserVersion string                `json:"browser_version,omitempty"`
	ScreenRes      string                `json:"screen_res,omitempty"`
	Timezone       string                `json:"timezone,omitempty"`
	Language       string                `json:"language,omitempty"`
	IPAddress      string                `json:"ip_address"`
	GeoCountry     string                `json:"geo_country,omitempty"`
	GeoCity        string                `json:"geo_city,omitempty"`
	FirstSeenAt    time.Time             `json:"first_seen_at"`
	LastSeenAt     time.Time             `json:"last_seen_at"`
	TrustLevel     FingerprintTrustLevel `json:"trust_level"`
	LoginCount     int                   `json:"login_count"`
}

// DeviceFingerprintListResponse wraps the full list returned by ListUserDevices.
type DeviceFingerprintListResponse struct {
	Devices []DeviceFingerprintRecordResponse `json:"devices"`
	Total   int                               `json:"total"`
}

// DeviceFingerprintInput carries the raw signals collected at login time.
// Optional fields come from client-side JS signals forwarded in HTTP headers.
type DeviceFingerprintInput struct {
	UserAgent  string // User-Agent header (required)
	IPAddress  string // RemoteAddr / X-Forwarded-For (required)
	Language   string // primary token from Accept-Language header
	ScreenRes  string // X-Device-Screen header (optional, e.g. "1920x1080")
	Timezone   string // X-Device-Timezone header (optional, e.g. "Europe/Istanbul")
	GeoCountry string // resolved by upstream geo-IP layer (optional)
	GeoCity    string // resolved by upstream geo-IP layer (optional)
}

// ToResponse converts a DB record to the API response shape.
func (d *DeviceFingerprintRecord) ToResponse() DeviceFingerprintRecordResponse {
	return DeviceFingerprintRecordResponse{
		ID:             d.ID,
		UserAgent:      d.UserAgent,
		Platform:       d.Platform,
		Browser:        d.Browser,
		BrowserVersion: d.BrowserVersion,
		ScreenRes:      d.ScreenRes,
		Timezone:       d.Timezone,
		Language:       d.Language,
		IPAddress:      d.IPAddress,
		GeoCountry:     d.GeoCountry,
		GeoCity:        d.GeoCity,
		FirstSeenAt:    d.FirstSeenAt,
		LastSeenAt:     d.LastSeenAt,
		TrustLevel:     d.TrustLevel,
		LoginCount:     d.LoginCount,
	}
}
