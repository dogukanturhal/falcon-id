// SPDX-License-Identifier: AGPL-3.0-or-later

package models

import (
	"time"

	"github.com/google/uuid"
)

// Instance database status constants.
const (
	InstanceDBStatusPending   = "pending"
	InstanceDBStatusCreating  = "creating"
	InstanceDBStatusMigrating = "migrating"
	InstanceDBStatusActive    = "active"
	InstanceDBStatusFailed    = "failed"
	InstanceDBStatusDeleting  = "deleting"
	InstanceDBStatusDeleted   = "deleted"
)

// InstanceDatabase tracks an individual database connection for a product instance.
// A multi-DB product (like ExampleSuite) will have one InstanceDatabase per database group.
type InstanceDatabase struct {
	ID                   uuid.UUID  `json:"id" db:"id"`
	InstanceID           uuid.UUID  `json:"instance_id" db:"instance_id"`
	DatabaseGroupID      uuid.UUID  `json:"database_group_id" db:"database_group_id"`
	DatabaseHost         *string    `json:"database_host,omitempty" db:"database_host"`
	DatabaseName         string     `json:"database_name" db:"database_name"`
	DatabaseSchema       string     `json:"database_schema" db:"database_schema"`
	DatabaseUsername     *string    `json:"database_username,omitempty" db:"database_username"`
	ConnectionStringEnc  []byte     `json:"-" db:"connection_string_enc"`
	IsolationMode        string     `json:"isolation_mode" db:"isolation_mode"`
	LastMigrationVersion int        `json:"last_migration_version" db:"last_migration_version"`
	Status               string     `json:"status" db:"status"`
	ProvisionedAt        *time.Time `json:"provisioned_at,omitempty" db:"provisioned_at"`
	CreatedAt            time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt            time.Time  `json:"updated_at" db:"updated_at"`
}

// InstanceDatabaseResponse is the API response for an instance database,
// enriched with display info from the database group.
type InstanceDatabaseResponse struct {
	ID                   uuid.UUID  `json:"id"`
	InstanceID           uuid.UUID  `json:"instance_id"`
	DatabaseName         string     `json:"database_name"`
	DisplayName          string     `json:"display_name"`
	IsolationMode        string     `json:"isolation_mode"`
	Status               string     `json:"status"`
	DatabaseHost         *string    `json:"database_host,omitempty"`
	DatabaseSchema       string     `json:"database_schema"`
	LastMigrationVersion int        `json:"last_migration_version"`
	ProvisionedAt        *time.Time `json:"provisioned_at,omitempty"`
}
