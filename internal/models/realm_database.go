// SPDX-License-Identifier: AGPL-3.0-or-later

package models

import (
	"time"

	"github.com/google/uuid"
)

// RealmDatabaseStatus represents the operational status of a realm database connection.
type RealmDatabaseStatus string

const (
	// RealmDatabaseStatusActive is an exported identifier.
	RealmDatabaseStatusActive RealmDatabaseStatus = "active"
	// RealmDatabaseStatusDegraded is an exported identifier.
	RealmDatabaseStatusDegraded RealmDatabaseStatus = "degraded"
	// RealmDatabaseStatusOffline is an exported identifier.
	RealmDatabaseStatusOffline RealmDatabaseStatus = "offline"
	// RealmDatabaseStatusDecommission is an exported identifier.
	RealmDatabaseStatusDecommission RealmDatabaseStatus = "decommissioned" // not in DB constraint but used for filtering
)

// RealmDatabase holds the connection configuration for a dedicated realm database.
// It maps to the realm_databases table created in migration 030.
//
// Status values are constrained in the DB to: active, degraded, offline.
// The HealthCheckStatus values are: healthy, unhealthy, unknown.
type RealmDatabase struct {
	ID             uuid.UUID `json:"id"              db:"id"`
	RealmID        uuid.UUID `json:"realm_id"        db:"realm_id"`
	ConnectionName string    `json:"connection_name" db:"connection_name"`
	Host           string    `json:"host"            db:"host"`
	Port           int       `json:"port"            db:"port"`
	DatabaseName   string    `json:"database_name"   db:"database_name"`
	Username       string    `json:"username"        db:"username"`

	// PasswordEncrypted stores the AES-GCM encrypted database password
	// (produced by crypto.EncryptionService.Encrypt). It is never sent over the
	// API in plaintext.
	PasswordEncrypted string `json:"-" db:"password_encrypted"`

	SSLMode            string `json:"ssl_mode"               db:"ssl_mode"`
	PoolSize           int    `json:"pool_size"               db:"pool_size"`
	MaxIdleConns       int    `json:"max_idle_conns"          db:"max_idle_conns"`
	ConnMaxLifetimeMin int    `json:"conn_max_lifetime_minutes" db:"conn_max_lifetime_minutes"`
	Status             string `json:"status"                  db:"status"`

	// Health tracking
	LastHealthCheck    *time.Time `json:"last_health_check,omitempty"  db:"last_health_check"`
	HealthCheckStatus  *string    `json:"health_check_status,omitempty" db:"health_check_status"`
	HealthCheckMessage *string    `json:"health_check_message,omitempty" db:"health_check_message"`

	// Host placement — set when the database was provisioned on a specific host
	// registered in iam_realm_database_hosts (migration 085 / 142).
	// Nil means the database was provisioned on the default master pool.
	HostID    *uuid.UUID `json:"host_id,omitempty"    db:"host_id"`
	HostAlias *string    `json:"host_alias,omitempty" db:"host_alias"`

	CreatedAt time.Time `json:"created_at" db:"created_at"`
	UpdatedAt time.Time `json:"updated_at" db:"updated_at"`
}
