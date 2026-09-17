// SPDX-License-Identifier: AGPL-3.0-or-later

package repositories

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

// RealmDatabaseRepository manages the realm_databases table on the control-plane DB.
// All mutations are idempotent-friendly and use explicit column lists to guard
// against future schema additions.
type RealmDatabaseRepository struct {
	db *pgxpool.Pool
}

// NewRealmDatabaseRepository creates a new repository backed by the given
// control-plane pool. The pool is never closed by the repository.
func NewRealmDatabaseRepository(db *pgxpool.Pool) *RealmDatabaseRepository {
	return &RealmDatabaseRepository{db: db}
}

// GetByRealmID retrieves the active database configuration for a realm.
// Returns (nil, nil) when no record exists (realm uses the shared pool).
// Returns an error only on actual DB failures.
func (r *RealmDatabaseRepository) GetByRealmID(ctx context.Context, realmID uuid.UUID) (*models.RealmDatabase, error) {
	const query = `
		SELECT id, realm_id, connection_name, host, port, database_name, username,
		       password_encrypted, ssl_mode, pool_size, max_idle_conns,
		       conn_max_lifetime_minutes, status,
		       last_health_check, health_check_status, health_check_message,
		       host_id, host_alias,
		       created_at, updated_at
		FROM realm_databases
		WHERE realm_id = $1
		  AND status != 'offline'
		ORDER BY created_at DESC
		LIMIT 1`

	rd := &models.RealmDatabase{}
	err := r.db.QueryRow(ctx, query, realmID).Scan(
		&rd.ID, &rd.RealmID, &rd.ConnectionName, &rd.Host, &rd.Port,
		&rd.DatabaseName, &rd.Username, &rd.PasswordEncrypted,
		&rd.SSLMode, &rd.PoolSize, &rd.MaxIdleConns, &rd.ConnMaxLifetimeMin,
		&rd.Status,
		&rd.LastHealthCheck, &rd.HealthCheckStatus, &rd.HealthCheckMessage,
		&rd.HostID, &rd.HostAlias,
		&rd.CreatedAt, &rd.UpdatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("GetByRealmID: %w", err)
	}
	return rd, nil
}

// Create inserts a new realm_databases record. If rd.ID is the zero UUID a new
// random ID is assigned before insertion. The CreatedAt and UpdatedAt fields are
// set to the server time returned from the DB.
// HostID and HostAlias are included when set (non-nil) to record which host the
// database was provisioned on.
func (r *RealmDatabaseRepository) Create(ctx context.Context, rd *models.RealmDatabase) error {
	if rd.ID == uuid.Nil {
		rd.ID = uuid.New()
	}

	const query = `
		INSERT INTO realm_databases (
			id, realm_id, connection_name, host, port, database_name, username,
			password_encrypted, ssl_mode, pool_size, max_idle_conns,
			conn_max_lifetime_minutes, status,
			host_id, host_alias
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
		RETURNING created_at, updated_at`

	return r.db.QueryRow(ctx, query,
		rd.ID, rd.RealmID, rd.ConnectionName, rd.Host, rd.Port,
		rd.DatabaseName, rd.Username, rd.PasswordEncrypted,
		rd.SSLMode, rd.PoolSize, rd.MaxIdleConns, rd.ConnMaxLifetimeMin,
		rd.Status,
		rd.HostID, rd.HostAlias,
	).Scan(&rd.CreatedAt, &rd.UpdatedAt)
}

// UpdateStatus changes the status column for all records belonging to a realm.
// The DB trigger keeps updated_at current.
func (r *RealmDatabaseRepository) UpdateStatus(ctx context.Context, realmID uuid.UUID, status string) error {
	const query = `
		UPDATE realm_databases
		SET    status = $1, updated_at = $2
		WHERE  realm_id = $3`

	_, err := r.db.Exec(ctx, query, status, time.Now().UTC(), realmID)
	if err != nil {
		return fmt.Errorf("UpdateStatus: %w", err)
	}
	return nil
}

// UpdateHealthCheck writes a health probe result for the realm's database record.
// Both health_check_* columns and updated_at are written atomically.
func (r *RealmDatabaseRepository) UpdateHealthCheck(
	ctx context.Context,
	realmID uuid.UUID,
	status string,
	message string,
) error {
	now := time.Now().UTC()
	const query = `
		UPDATE realm_databases
		SET    health_check_status  = $1,
		       health_check_message = $2,
		       last_health_check    = $3,
		       updated_at           = $3
		WHERE  realm_id = $4`

	_, err := r.db.Exec(ctx, query, status, message, now, realmID)
	if err != nil {
		return fmt.Errorf("UpdateHealthCheck: %w", err)
	}
	return nil
}

// GetOldestByHostID returns the oldest active realm_database record whose
// host_id matches the given host. "Oldest" is defined by created_at ASC —
// the assumption is that older tenants tend to have smaller databases.
// Returns (nil, nil) when no active record exists for that host.
func (r *RealmDatabaseRepository) GetOldestByHostID(ctx context.Context, hostID uuid.UUID) (*models.RealmDatabase, error) {
	const query = `
		SELECT id, realm_id, connection_name, host, port, database_name, username,
		       password_encrypted, ssl_mode, pool_size, max_idle_conns,
		       conn_max_lifetime_minutes, status,
		       last_health_check, health_check_status, health_check_message,
		       host_id, host_alias,
		       created_at, updated_at
		FROM realm_databases
		WHERE host_id = $1
		  AND status = 'active'
		ORDER BY created_at ASC
		LIMIT 1`

	rd := &models.RealmDatabase{}
	err := r.db.QueryRow(ctx, query, hostID).Scan(
		&rd.ID, &rd.RealmID, &rd.ConnectionName, &rd.Host, &rd.Port,
		&rd.DatabaseName, &rd.Username, &rd.PasswordEncrypted,
		&rd.SSLMode, &rd.PoolSize, &rd.MaxIdleConns, &rd.ConnMaxLifetimeMin,
		&rd.Status,
		&rd.LastHealthCheck, &rd.HealthCheckStatus, &rd.HealthCheckMessage,
		&rd.HostID, &rd.HostAlias,
		&rd.CreatedAt, &rd.UpdatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("GetOldestByHostID: %w", err)
	}
	return rd, nil
}

// ListActive returns all realm_database records whose status is 'active',
// ordered by creation time so that callers get a stable, predictable list.
func (r *RealmDatabaseRepository) ListActive(ctx context.Context) ([]models.RealmDatabase, error) {
	const query = `
		SELECT id, realm_id, connection_name, host, port, database_name, username,
		       password_encrypted, ssl_mode, pool_size, max_idle_conns,
		       conn_max_lifetime_minutes, status,
		       last_health_check, health_check_status, health_check_message,
		       host_id, host_alias,
		       created_at, updated_at
		FROM realm_databases
		WHERE status = 'active'
		ORDER BY created_at`

	rows, err := r.db.Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("ListActive: %w", err)
	}
	defer rows.Close()

	var result []models.RealmDatabase
	for rows.Next() {
		var rd models.RealmDatabase
		if err := rows.Scan(
			&rd.ID, &rd.RealmID, &rd.ConnectionName, &rd.Host, &rd.Port,
			&rd.DatabaseName, &rd.Username, &rd.PasswordEncrypted,
			&rd.SSLMode, &rd.PoolSize, &rd.MaxIdleConns, &rd.ConnMaxLifetimeMin,
			&rd.Status,
			&rd.LastHealthCheck, &rd.HealthCheckStatus, &rd.HealthCheckMessage,
			&rd.HostID, &rd.HostAlias,
			&rd.CreatedAt, &rd.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("ListActive scan: %w", err)
		}
		result = append(result, rd)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("ListActive rows: %w", err)
	}
	return result, nil
}
