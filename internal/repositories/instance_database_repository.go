// SPDX-License-Identifier: AGPL-3.0-or-later

package repositories

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

const msgInstanceDatabaseNotFound = "instance database not found"

// InstanceDatabaseRepository handles database operations for instance databases.
type InstanceDatabaseRepository struct {
	pool *pgxpool.Pool
}

// NewInstanceDatabaseRepository creates a new repository.
func NewInstanceDatabaseRepository(pool *pgxpool.Pool) *InstanceDatabaseRepository {
	return &InstanceDatabaseRepository{pool: pool}
}

// Create inserts a new instance database record.
func (r *InstanceDatabaseRepository) Create(ctx context.Context, idb *models.InstanceDatabase) error {
	if idb.ID == uuid.Nil {
		idb.ID = uuid.New()
	}
	if idb.DatabaseSchema == "" {
		idb.DatabaseSchema = "public"
	}
	if idb.IsolationMode == "" {
		idb.IsolationMode = "pool"
	}
	if idb.Status == "" {
		idb.Status = models.InstanceDBStatusPending
	}

	err := r.pool.QueryRow(ctx, `
		INSERT INTO iam_instance_databases
			(id, instance_id, database_group_id, database_host, database_name,
			 database_schema, database_username, connection_string_enc,
			 isolation_mode, status)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		RETURNING created_at, updated_at
	`, idb.ID, idb.InstanceID, idb.DatabaseGroupID, idb.DatabaseHost, idb.DatabaseName,
		idb.DatabaseSchema, idb.DatabaseUsername, idb.ConnectionStringEnc,
		idb.IsolationMode, idb.Status,
	).Scan(&idb.CreatedAt, &idb.UpdatedAt)
	if err != nil {
		return fmt.Errorf("create instance database: %w", err)
	}
	return nil
}

// ListByInstance returns all databases for a product instance.
func (r *InstanceDatabaseRepository) ListByInstance(ctx context.Context, instanceID uuid.UUID) ([]models.InstanceDatabase, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT id, instance_id, database_group_id, database_host, database_name,
		       database_schema, database_username, connection_string_enc,
		       isolation_mode, last_migration_version, status, provisioned_at,
		       created_at, updated_at
		FROM iam_instance_databases
		WHERE instance_id = $1
		ORDER BY created_at
	`, instanceID)
	if err != nil {
		return nil, fmt.Errorf("list instance databases: %w", err)
	}
	defer rows.Close()

	var dbs []models.InstanceDatabase
	for rows.Next() {
		var idb models.InstanceDatabase
		if err := rows.Scan(
			&idb.ID, &idb.InstanceID, &idb.DatabaseGroupID, &idb.DatabaseHost,
			&idb.DatabaseName, &idb.DatabaseSchema, &idb.DatabaseUsername,
			&idb.ConnectionStringEnc, &idb.IsolationMode, &idb.LastMigrationVersion,
			&idb.Status, &idb.ProvisionedAt, &idb.CreatedAt, &idb.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan instance database: %w", err)
		}
		dbs = append(dbs, idb)
	}
	return dbs, rows.Err()
}

// UpdateStatus updates the status of an instance database.
func (r *InstanceDatabaseRepository) UpdateStatus(ctx context.Context, id uuid.UUID, status string) error {
	tag, err := r.pool.Exec(ctx, `
		UPDATE iam_instance_databases SET status = $2, updated_at = NOW()
		WHERE id = $1
	`, id, status)
	if err != nil {
		return fmt.Errorf("update instance database status: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return errors.New(msgInstanceDatabaseNotFound)
	}
	return nil
}

// UpdateDatabaseInfo updates the connection details for an instance database.
func (r *InstanceDatabaseRepository) UpdateDatabaseInfo(ctx context.Context, id uuid.UUID, host, dbName, schema, username string, connEnc []byte) error {
	tag, err := r.pool.Exec(ctx, `
		UPDATE iam_instance_databases
		SET database_host = $2, database_name = $3, database_schema = $4,
		    database_username = $5, connection_string_enc = $6, updated_at = NOW()
		WHERE id = $1
	`, id, host, dbName, schema, username, connEnc)
	if err != nil {
		return fmt.Errorf("update instance database info: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return errors.New(msgInstanceDatabaseNotFound)
	}
	return nil
}

// SetActive marks an instance database as active and records provisioned_at.
func (r *InstanceDatabaseRepository) SetActive(ctx context.Context, id uuid.UUID) error {
	now := time.Now()
	tag, err := r.pool.Exec(ctx, `
		UPDATE iam_instance_databases
		SET status = 'active', provisioned_at = $2, updated_at = NOW()
		WHERE id = $1
	`, id, now)
	if err != nil {
		return fmt.Errorf("set instance database active: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return errors.New(msgInstanceDatabaseNotFound)
	}
	return nil
}

// LookupForTenant finds the instance database for a specific tenant and database name.
// This is the key query for runtime connection routing.
func (r *InstanceDatabaseRepository) LookupForTenant(ctx context.Context, tenantID uuid.UUID, databaseName string) (*models.InstanceDatabase, error) {
	var idb models.InstanceDatabase
	err := r.pool.QueryRow(ctx, `
		SELECT idb.id, idb.instance_id, idb.database_group_id, idb.database_host,
		       idb.database_name, idb.database_schema, idb.database_username,
		       idb.connection_string_enc, idb.isolation_mode, idb.last_migration_version,
		       idb.status, idb.provisioned_at, idb.created_at, idb.updated_at
		FROM iam_instance_databases idb
		JOIN iam_product_instances pi ON pi.id = idb.instance_id
		WHERE pi.tenant_id = $1
		  AND idb.database_name = $2
		  AND idb.status = 'active'
		  AND pi.provisioning_state != 'deleted'
		LIMIT 1
	`, tenantID, databaseName).Scan(
		&idb.ID, &idb.InstanceID, &idb.DatabaseGroupID, &idb.DatabaseHost,
		&idb.DatabaseName, &idb.DatabaseSchema, &idb.DatabaseUsername,
		&idb.ConnectionStringEnc, &idb.IsolationMode, &idb.LastMigrationVersion,
		&idb.Status, &idb.ProvisionedAt, &idb.CreatedAt, &idb.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("lookup tenant database: %w", err)
	}
	return &idb, nil
}

// DeleteByInstance deletes all instance databases for a product instance.
func (r *InstanceDatabaseRepository) DeleteByInstance(ctx context.Context, instanceID uuid.UUID) error {
	_, err := r.pool.Exec(ctx, `
		DELETE FROM iam_instance_databases WHERE instance_id = $1
	`, instanceID)
	if err != nil {
		return fmt.Errorf("delete instance databases: %w", err)
	}
	return nil
}

// ListActive returns all instance databases that are currently active across all
// product instances. This is the core query for fleet-wide operations (migrations,
// health checks, capacity reporting).
func (r *InstanceDatabaseRepository) ListActive(ctx context.Context) ([]models.InstanceDatabase, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT id, instance_id, database_group_id, database_host, database_name,
		       database_schema, database_username, connection_string_enc,
		       isolation_mode, last_migration_version, status, provisioned_at,
		       created_at, updated_at
		FROM iam_instance_databases
		WHERE status = 'active'
		ORDER BY database_host, database_name
	`)
	if err != nil {
		return nil, fmt.Errorf("list active instance databases: %w", err)
	}
	defer rows.Close()

	var dbs []models.InstanceDatabase
	for rows.Next() {
		var idb models.InstanceDatabase
		if err := rows.Scan(
			&idb.ID, &idb.InstanceID, &idb.DatabaseGroupID, &idb.DatabaseHost,
			&idb.DatabaseName, &idb.DatabaseSchema, &idb.DatabaseUsername,
			&idb.ConnectionStringEnc, &idb.IsolationMode, &idb.LastMigrationVersion,
			&idb.Status, &idb.ProvisionedAt, &idb.CreatedAt, &idb.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan active instance database: %w", err)
		}
		dbs = append(dbs, idb)
	}
	return dbs, rows.Err()
}

// ListByInstanceWithGroups returns instance databases enriched with display names.
func (r *InstanceDatabaseRepository) ListByInstanceWithGroups(ctx context.Context, instanceID uuid.UUID) ([]models.InstanceDatabaseResponse, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT idb.id, idb.instance_id, idb.database_name, pdg.display_name,
		       idb.isolation_mode, idb.status, idb.database_host, idb.database_schema,
		       idb.last_migration_version, idb.provisioned_at
		FROM iam_instance_databases idb
		JOIN iam_product_database_groups pdg ON pdg.id = idb.database_group_id
		WHERE idb.instance_id = $1
		ORDER BY pdg.priority, pdg.database_name
	`, instanceID)
	if err != nil {
		return nil, fmt.Errorf("list instance databases with groups: %w", err)
	}
	defer rows.Close()

	var responses []models.InstanceDatabaseResponse
	for rows.Next() {
		var r models.InstanceDatabaseResponse
		if err := rows.Scan(
			&r.ID, &r.InstanceID, &r.DatabaseName, &r.DisplayName,
			&r.IsolationMode, &r.Status, &r.DatabaseHost, &r.DatabaseSchema,
			&r.LastMigrationVersion, &r.ProvisionedAt,
		); err != nil {
			return nil, fmt.Errorf("scan instance database response: %w", err)
		}
		responses = append(responses, r)
	}
	return responses, rows.Err()
}
