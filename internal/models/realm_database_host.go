// SPDX-License-Identifier: AGPL-3.0-or-later

package models

import (
	"time"

	"github.com/google/uuid"
)

// RealmDatabaseHost represents a physical or cloud PostgreSQL server that
// Falcon-ID may provision realm databases on. It maps to the
// iam_realm_database_hosts table created in migration 085 and extended in 142.
type RealmDatabaseHost struct {
	ID                  uuid.UUID  `json:"id"                   db:"id"`
	HostAlias           string     `json:"host_alias"           db:"host_alias"`
	ConnectionStringEnc string     `json:"-"                    db:"connection_string_enc"`
	Region              *string    `json:"region,omitempty"     db:"region"`
	DataResidencyZone   string     `json:"data_residency_zone"  db:"data_residency_zone"`
	Provider            string     `json:"provider"             db:"provider"`
	MaxDatabases        int        `json:"max_databases"        db:"max_databases"`
	CurrentDatabases    int        `json:"current_databases"    db:"current_databases"`
	IsActive            bool       `json:"is_active"            db:"is_active"`
	HealthStatus        string     `json:"health_status"        db:"health_status"`
	LastHealthCheck     *time.Time `json:"last_health_check,omitempty" db:"last_health_check"`
	CreatedAt           time.Time  `json:"created_at"           db:"created_at"`
	UpdatedAt           time.Time  `json:"updated_at"           db:"updated_at"`
}

// HasCapacity reports whether this host can accept at least one additional database.
func (h *RealmDatabaseHost) HasCapacity() bool {
	return h.IsActive &&
		h.HealthStatus == "healthy" &&
		h.CurrentDatabases < h.MaxDatabases
}

// CreateDatabaseHostRequest carries the input for registering a new host.
type CreateDatabaseHostRequest struct {
	HostAlias         string  `json:"host_alias"          binding:"required"`
	ConnectionString  string  `json:"connection_string"   binding:"required"` // plaintext; encrypted by repository
	Region            *string `json:"region,omitempty"`
	DataResidencyZone string  `json:"data_residency_zone"`
	Provider          string  `json:"provider"`
	MaxDatabases      int     `json:"max_databases"`
}

// UpdateDatabaseHostRequest carries fields that may be updated on an existing host.
type UpdateDatabaseHostRequest struct {
	Region            *string `json:"region,omitempty"`
	DataResidencyZone *string `json:"data_residency_zone,omitempty"`
	MaxDatabases      *int    `json:"max_databases,omitempty"`
	IsActive          *bool   `json:"is_active,omitempty"`
	HealthStatus      *string `json:"health_status,omitempty"`
}
