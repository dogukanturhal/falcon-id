// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"
)

// ---------------------------------------------------------------------------
// Domain type
// ---------------------------------------------------------------------------

// TenantSchemaVersion holds the schema migration state for a single tenant
// database entry recorded in iam_tenant_schema_versions.
type TenantSchemaVersion struct {
	TenantID         uuid.UUID  `json:"tenant_id"`
	DatabaseName     string     `json:"database_name"`
	CurrentVersion   int        `json:"current_version"`
	TargetVersion    *int       `json:"target_version,omitempty"`
	MigrationStatus  string     `json:"migration_status"`
	LastMigrationAt  *time.Time `json:"last_migration_at,omitempty"`
	LastMigrationErr *string    `json:"last_migration_error,omitempty"`
}

// ---------------------------------------------------------------------------
// Service
// ---------------------------------------------------------------------------

// SchemaVersionTracker tracks and reports per-tenant database schema versions.
// It writes to and reads from the iam_tenant_schema_versions table, enabling
// the platform to identify tenant silo databases that have drifted behind the
// current global migration baseline.
type SchemaVersionTracker struct {
	pool *pgxpool.Pool
	log  *zap.SugaredLogger
}

// NewSchemaVersionTracker creates a SchemaVersionTracker backed by the given pool.
// realmDBRepo is retained for future connectivity use and may be nil.
func NewSchemaVersionTracker(pool *pgxpool.Pool, log *zap.SugaredLogger) *SchemaVersionTracker {
	return &SchemaVersionTracker{
		pool: pool,
		log:  log,
	}
}

// ---------------------------------------------------------------------------
// Queries
// ---------------------------------------------------------------------------

// GetVersions returns the schema version record for every tenant database
// that has been registered in iam_tenant_schema_versions, ordered by tenant
// and database name.
func (t *SchemaVersionTracker) GetVersions(ctx context.Context) ([]TenantSchemaVersion, error) {
	const query = `
		SELECT tenant_id, database_name, current_version, target_version,
		       migration_status, last_migration_at, last_migration_error
		FROM iam_tenant_schema_versions
		ORDER BY tenant_id, database_name`

	rows, err := t.pool.Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("SchemaVersionTracker.GetVersions: %w", err)
	}
	defer rows.Close()

	return scanVersionRows(rows)
}

// GetVersionForTenant returns the schema version record for a specific
// (tenant_id, database_name) pair.  Returns (nil, nil) when no record exists.
func (t *SchemaVersionTracker) GetVersionForTenant(
	ctx context.Context,
	tenantID uuid.UUID,
	dbName string,
) (*TenantSchemaVersion, error) {
	const query = `
		SELECT tenant_id, database_name, current_version, target_version,
		       migration_status, last_migration_at, last_migration_error
		FROM iam_tenant_schema_versions
		WHERE tenant_id = $1 AND database_name = $2`

	v := &TenantSchemaVersion{}
	err := t.pool.QueryRow(ctx, query, tenantID, dbName).Scan(
		&v.TenantID, &v.DatabaseName, &v.CurrentVersion, &v.TargetVersion,
		&v.MigrationStatus, &v.LastMigrationAt, &v.LastMigrationErr,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("SchemaVersionTracker.GetVersionForTenant: %w", err)
	}
	return v, nil
}

// RecordMigration upserts a successful migration record. The current_version
// is advanced to the given version and migration_status is set to 'current'.
// last_migration_error is cleared on success.
func (t *SchemaVersionTracker) RecordMigration(
	ctx context.Context,
	tenantID uuid.UUID,
	dbName string,
	version int,
) error {
	now := time.Now().UTC()
	const query = `
		INSERT INTO iam_tenant_schema_versions
		    (tenant_id, database_name, current_version, migration_status, last_migration_at, last_migration_error)
		VALUES ($1, $2, $3, 'current', $4, NULL)
		ON CONFLICT (tenant_id, database_name) DO UPDATE
		    SET current_version      = EXCLUDED.current_version,
		        migration_status     = 'current',
		        last_migration_at    = EXCLUDED.last_migration_at,
		        last_migration_error = NULL,
		        updated_at           = NOW()`

	if _, err := t.pool.Exec(ctx, query, tenantID, dbName, version, now); err != nil {
		return fmt.Errorf("SchemaVersionTracker.RecordMigration: %w", err)
	}
	t.log.Infow("schema migration recorded",
		"tenant_id", tenantID,
		"database_name", dbName,
		"version", version,
	)
	return nil
}

// RecordMigrationError records a failed migration attempt. The current_version
// is NOT advanced; migration_status is set to 'failed' and the error message
// is persisted so operators can inspect it via the drift report.
func (t *SchemaVersionTracker) RecordMigrationError(
	ctx context.Context,
	tenantID uuid.UUID,
	dbName string,
	version int,
	migErr error,
) error {
	now := time.Now().UTC()
	errMsg := migErr.Error()
	const query = `
		INSERT INTO iam_tenant_schema_versions
		    (tenant_id, database_name, current_version, migration_status, last_migration_at, last_migration_error)
		VALUES ($1, $2, $3, 'failed', $4, $5)
		ON CONFLICT (tenant_id, database_name) DO UPDATE
		    SET migration_status     = 'failed',
		        last_migration_at    = EXCLUDED.last_migration_at,
		        last_migration_error = EXCLUDED.last_migration_error,
		        updated_at           = NOW()`

	if _, err := t.pool.Exec(ctx, query, tenantID, dbName, version, now, errMsg); err != nil {
		return fmt.Errorf("SchemaVersionTracker.RecordMigrationError: %w", err)
	}
	t.log.Warnw("schema migration failure recorded",
		"tenant_id", tenantID,
		"database_name", dbName,
		"version", version,
		"error", errMsg,
	)
	return nil
}

// GetDriftReport returns all tenant schema version records whose
// current_version is less than latestVersion — i.e. databases that are behind
// the global migration baseline.  Results are ordered by current_version ASC
// so the most-drifted databases appear first.
func (t *SchemaVersionTracker) GetDriftReport(
	ctx context.Context,
	latestVersion int,
) ([]TenantSchemaVersion, error) {
	const query = `
		SELECT tenant_id, database_name, current_version, target_version,
		       migration_status, last_migration_at, last_migration_error
		FROM iam_tenant_schema_versions
		WHERE current_version < $1
		ORDER BY current_version ASC, tenant_id, database_name`

	rows, err := t.pool.Query(ctx, query, latestVersion)
	if err != nil {
		return nil, fmt.Errorf("SchemaVersionTracker.GetDriftReport: %w", err)
	}
	defer rows.Close()

	versions, err := scanVersionRows(rows)
	if err != nil {
		return nil, err
	}

	t.log.Infow("drift report generated",
		"latest_version", latestVersion,
		"drifted_count", len(versions),
	)
	return versions, nil
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

func scanVersionRows(rows pgx.Rows) ([]TenantSchemaVersion, error) {
	var result []TenantSchemaVersion
	for rows.Next() {
		var v TenantSchemaVersion
		if err := rows.Scan(
			&v.TenantID, &v.DatabaseName, &v.CurrentVersion, &v.TargetVersion,
			&v.MigrationStatus, &v.LastMigrationAt, &v.LastMigrationErr,
		); err != nil {
			return nil, fmt.Errorf("scanVersionRows: %w", err)
		}
		result = append(result, v)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("scanVersionRows rows.Err: %w", err)
	}
	return result, nil
}
