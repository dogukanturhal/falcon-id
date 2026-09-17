// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import "github.com/google/uuid"

// AuthContext carries the authentication signals used to drive adaptive MFA and
// conditional access decisions.  It is constructed by the middleware layer from
// the HTTP request and the authenticated session.
type AuthContext struct {
	UserID      uuid.UUID
	TenantID    uuid.UUID
	IPAddress   string
	UserAgent   string
	DeviceID    string
	IsNewDevice bool
	RiskScore   int
	GeoLocation *GeoLocation
}

// GeoLocation represents the geographic coordinates of a request, typically
// resolved by a geo-IP middleware.
type GeoLocation struct {
	Country   string  `json:"country"`
	City      string  `json:"city"`
	Latitude  float64 `json:"latitude"`
	Longitude float64 `json:"longitude"`
}

// MFADecisionResult holds the outcome of an adaptive MFA evaluation.
// The middleware reads these fields to determine the HTTP response.
type MFADecisionResult struct {
	Action            string   `json:"action"`
	Reason            string   `json:"reason,omitempty"`
	RiskLevel         string   `json:"risk_level,omitempty"`
	ComputedRiskScore int      `json:"computed_risk_score,omitempty"`
	RequiredMethods   []string `json:"required_methods,omitempty"`
}
