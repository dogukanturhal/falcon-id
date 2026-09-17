// SPDX-License-Identifier: AGPL-3.0-or-later

package models

import (
	"time"

	"github.com/google/uuid"
)

// MigrationPhase represents the current stage of a tenant data migration.
type MigrationPhase string

const (
	// MigrationPhaseExporting is the phase where rows are read from the source database.
	MigrationPhaseExporting MigrationPhase = "exporting"
	// MigrationPhaseImporting is the phase where rows are written to the target database.
	MigrationPhaseImporting MigrationPhase = "importing"
	// MigrationPhaseVerifying is the phase where checksums are compared between source and target.
	MigrationPhaseVerifying MigrationPhase = "verifying"
	// MigrationPhaseSwitching is the phase where the realm connection record is updated.
	MigrationPhaseSwitching MigrationPhase = "switching"
	// MigrationPhaseCompleted indicates the migration finished successfully.
	MigrationPhaseCompleted MigrationPhase = "completed"
	// MigrationPhaseFailed indicates the migration encountered an unrecoverable error.
	MigrationPhaseFailed MigrationPhase = "failed"
	// MigrationPhaseRolledBack indicates the migration was aborted and source data is intact.
	MigrationPhaseRolledBack MigrationPhase = "rolled_back"
)

// MigrationProgress tracks the live status of an in-flight or completed tenant
// migration between realm databases.
type MigrationProgress struct {
	// ID uniquely identifies this migration run.
	ID uuid.UUID `json:"id"`
	// TenantID is the tenant whose data is being moved.
	TenantID uuid.UUID `json:"tenant_id"`
	// SourceRealmID is the realm the tenant is migrating away from.
	SourceRealmID uuid.UUID `json:"source_realm_id"`
	// TargetRealmID is the realm the tenant is migrating to.
	TargetRealmID uuid.UUID `json:"target_realm_id"`
	// Phase is the current lifecycle stage of the migration.
	Phase MigrationPhase `json:"phase"`
	// TablesTotal is the total number of IAM tables scheduled for migration.
	TablesTotal int `json:"tables_total"`
	// TablesCompleted is the number of tables fully exported, imported, and verified.
	TablesCompleted int `json:"tables_completed"`
	// RowsExported is the cumulative count of rows read from the source.
	RowsExported int64 `json:"rows_exported"`
	// RowsImported is the cumulative count of rows written to the target.
	RowsImported int64 `json:"rows_imported"`
	// ErrorMessage holds a human-readable failure reason when Phase is failed or rolled_back.
	ErrorMessage string `json:"error_message,omitempty"`
	// StartedAt is when the migration was initiated.
	StartedAt time.Time `json:"started_at"`
	// CompletedAt is set when the migration reaches a terminal phase (completed, failed, rolled_back).
	CompletedAt *time.Time `json:"completed_at,omitempty"`
}

// TableMigrationResult holds the per-table outcome after both export and import have
// completed for that table.
type TableMigrationResult struct {
	// TableName is the unqualified PostgreSQL table name.
	TableName string `json:"table_name"`
	// RowsExported is the number of rows read from the source for this table.
	RowsExported int64 `json:"rows_exported"`
	// RowsImported is the number of rows written to the target for this table.
	RowsImported int64 `json:"rows_imported"`
	// SourceChecksum is the MD5 digest of the tenant-scoped rows in the source table.
	SourceChecksum string `json:"source_checksum"`
	// TargetChecksum is the MD5 digest of the tenant-scoped rows in the target table after import.
	TargetChecksum string `json:"target_checksum"`
	// Verified is true when SourceChecksum == TargetChecksum.
	Verified bool `json:"verified"`
}
