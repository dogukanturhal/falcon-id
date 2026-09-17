// SPDX-License-Identifier: AGPL-3.0-or-later

package models

import (
	"net"
	"time"

	"github.com/google/uuid"
)

// NetworkZone represents a named network zone (corporate, VPN, external, etc.)
// used for IDP routing rule evaluation. Each zone contains a list of CIDR ranges
// that classify incoming request IPs.
type NetworkZone struct {
	ID          uuid.UUID `json:"id" db:"id"`
	TenantID    uuid.UUID `json:"tenant_id" db:"tenant_id"`
	Name        string    `json:"name" db:"name"`
	ZoneType    string    `json:"zone_type" db:"zone_type"` // corporate, external, vpn, trusted, untrusted
	Description *string   `json:"description,omitempty" db:"description"`
	CIDRRanges  []string  `json:"cidr_ranges" db:"cidr_ranges"`
	IsEnabled   bool      `json:"is_enabled" db:"is_enabled"`
	CreatedAt   time.Time `json:"created_at" db:"created_at"`
	UpdatedAt   time.Time `json:"updated_at" db:"updated_at"`
}

// ContainsIP checks whether a given IP address falls within any of the zone's CIDR ranges.
func (z *NetworkZone) ContainsIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}

	for _, cidr := range z.CIDRRanges {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

// CreateNetworkZoneRequest is the DTO for creating a network zone.
type CreateNetworkZoneRequest struct {
	Name        string   `json:"name" binding:"required,min=1,max=100"`
	ZoneType    string   `json:"zone_type" binding:"required,oneof=corporate external vpn trusted untrusted"`
	Description *string  `json:"description,omitempty" binding:"omitempty,max=500"`
	CIDRRanges  []string `json:"cidr_ranges" binding:"required,min=1,max=100"`
	IsEnabled   *bool    `json:"is_enabled"`
}

// UpdateNetworkZoneRequest is the DTO for updating a network zone.
type UpdateNetworkZoneRequest struct {
	Name        *string  `json:"name" binding:"omitempty,min=1,max=100"`
	ZoneType    *string  `json:"zone_type" binding:"omitempty,oneof=corporate external vpn trusted untrusted"`
	Description *string  `json:"description,omitempty" binding:"omitempty,max=500"`
	CIDRRanges  []string `json:"cidr_ranges" binding:"omitempty,max=100"`
	IsEnabled   *bool    `json:"is_enabled"`
}
