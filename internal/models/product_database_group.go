// SPDX-License-Identifier: AGPL-3.0-or-later

package models

import (
	"time"

	"github.com/google/uuid"
)

// ProductDatabaseGroup defines a database that a product requires.
// When a tenant subscribes to a product, the orchestrator provisions
// all databases in the product's database group.
type ProductDatabaseGroup struct {
	ID                 uuid.UUID `json:"id" db:"id"`
	ProductID          uuid.UUID `json:"product_id" db:"product_id"`
	DatabaseName       string    `json:"database_name" db:"database_name"`
	DisplayName        string    `json:"display_name" db:"display_name"`
	MigrationDir       string    `json:"migration_dir" db:"migration_dir"`
	Priority           int       `json:"priority" db:"priority"`
	IsControlPlane     bool      `json:"is_control_plane" db:"is_control_plane"`
	RequiredExtensions []string  `json:"required_extensions" db:"required_extensions"`
	CreatedAt          time.Time `json:"created_at" db:"created_at"`
	UpdatedAt          time.Time `json:"updated_at" db:"updated_at"`
}

// CreateProductDatabaseGroupRequest is the request body for creating a database group.
type CreateProductDatabaseGroupRequest struct {
	DatabaseName       string   `json:"database_name" binding:"required"`
	DisplayName        string   `json:"display_name" binding:"required"`
	MigrationDir       string   `json:"migration_dir" binding:"required"`
	Priority           int      `json:"priority"`
	IsControlPlane     bool     `json:"is_control_plane"`
	RequiredExtensions []string `json:"required_extensions"`
}
