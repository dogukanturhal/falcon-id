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

// DatabaseHostRepository manages the iam_realm_database_hosts table on the
// control-plane database. All query column lists are explicit to guard against
// future schema additions.
type DatabaseHostRepository struct {
	db *pgxpool.Pool
}

// NewDatabaseHostRepository creates a repository backed by the given pool.
// The pool is never closed by the repository itself.
func NewDatabaseHostRepository(db *pgxpool.Pool) *DatabaseHostRepository {
	return &DatabaseHostRepository{db: db}
}

const hostSelectCols = `
	id, host_alias, connection_string_enc, region, data_residency_zone,
	provider, max_databases, current_databases, is_active, health_status,
	last_health_check, created_at, updated_at`

func scanHost(row pgx.Row, h *models.RealmDatabaseHost) error {
	return row.Scan(
		&h.ID, &h.HostAlias, &h.ConnectionStringEnc, &h.Region, &h.DataResidencyZone,
		&h.Provider, &h.MaxDatabases, &h.CurrentDatabases, &h.IsActive, &h.HealthStatus,
		&h.LastHealthCheck, &h.CreatedAt, &h.UpdatedAt,
	)
}

func scanHostRow(rows pgx.Rows, h *models.RealmDatabaseHost) error {
	return rows.Scan(
		&h.ID, &h.HostAlias, &h.ConnectionStringEnc, &h.Region, &h.DataResidencyZone,
		&h.Provider, &h.MaxDatabases, &h.CurrentDatabases, &h.IsActive, &h.HealthStatus,
		&h.LastHealthCheck, &h.CreatedAt, &h.UpdatedAt,
	)
}

// List returns all host records ordered by alias.
func (r *DatabaseHostRepository) List(ctx context.Context) ([]models.RealmDatabaseHost, error) {
	query := `SELECT` + hostSelectCols + `
		FROM iam_realm_database_hosts
		ORDER BY host_alias`

	rows, err := r.db.Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("DatabaseHostRepository.List: %w", err)
	}
	defer rows.Close()

	return collectHosts(rows)
}

// GetByID returns a single host by primary key.
// Returns (nil, nil) when no row exists.
func (r *DatabaseHostRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.RealmDatabaseHost, error) {
	query := `SELECT` + hostSelectCols + `
		FROM iam_realm_database_hosts
		WHERE id = $1`

	h := &models.RealmDatabaseHost{}
	if err := scanHost(r.db.QueryRow(ctx, query, id), h); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("DatabaseHostRepository.GetByID: %w", err)
	}
	return h, nil
}

// Create inserts a new host record. If h.ID is the zero UUID a new random ID is
// assigned. CreatedAt and UpdatedAt are returned from the DB.
func (r *DatabaseHostRepository) Create(ctx context.Context, h *models.RealmDatabaseHost) error {
	if h.ID == uuid.Nil {
		h.ID = uuid.New()
	}

	const query = `
		INSERT INTO iam_realm_database_hosts (
			id, host_alias, connection_string_enc, region, data_residency_zone,
			provider, max_databases, current_databases, is_active, health_status
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		RETURNING created_at, updated_at`

	return r.db.QueryRow(ctx, query,
		h.ID, h.HostAlias, h.ConnectionStringEnc, h.Region, h.DataResidencyZone,
		h.Provider, h.MaxDatabases, h.CurrentDatabases, h.IsActive, h.HealthStatus,
	).Scan(&h.CreatedAt, &h.UpdatedAt)
}

// Update writes mutable fields back to the host record.
func (r *DatabaseHostRepository) Update(ctx context.Context, h *models.RealmDatabaseHost) error {
	const query = `
		UPDATE iam_realm_database_hosts
		SET    host_alias           = $1,
		       connection_string_enc = $2,
		       region               = $3,
		       data_residency_zone  = $4,
		       provider             = $5,
		       max_databases        = $6,
		       is_active            = $7,
		       health_status        = $8,
		       updated_at           = $9
		WHERE  id = $10
		RETURNING updated_at`

	now := time.Now().UTC()
	return r.db.QueryRow(ctx, query,
		h.HostAlias, h.ConnectionStringEnc, h.Region, h.DataResidencyZone,
		h.Provider, h.MaxDatabases, h.IsActive, h.HealthStatus, now, h.ID,
	).Scan(&h.UpdatedAt)
}

// Delete removes a host record by ID. It does not check referential integrity
// with realm_databases — callers must verify there are no active databases on
// the host before deleting it.
func (r *DatabaseHostRepository) Delete(ctx context.Context, id uuid.UUID) error {
	const query = `DELETE FROM iam_realm_database_hosts WHERE id = $1`
	_, err := r.db.Exec(ctx, query, id)
	if err != nil {
		return fmt.Errorf("DatabaseHostRepository.Delete: %w", err)
	}
	return nil
}

// ListActiveByRegion returns all active, healthy hosts in the given region
// ordered by current_databases ascending (least loaded first).
// An empty region string returns all active healthy hosts regardless of region.
func (r *DatabaseHostRepository) ListActiveByRegion(ctx context.Context, region string) ([]models.RealmDatabaseHost, error) {
	var (
		query string
		args  []any
	)

	if region == "" {
		query = `SELECT` + hostSelectCols + `
			FROM  iam_realm_database_hosts
			WHERE is_active = true AND health_status = 'healthy'
			ORDER BY current_databases ASC`
	} else {
		query = `SELECT` + hostSelectCols + `
			FROM  iam_realm_database_hosts
			WHERE is_active = true AND health_status = 'healthy' AND region = $1
			ORDER BY current_databases ASC`
		args = []any{region}
	}

	rows, err := r.db.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("DatabaseHostRepository.ListActiveByRegion: %w", err)
	}
	defer rows.Close()

	return collectHosts(rows)
}

// IncrementDatabaseCount atomically increments current_databases for the host.
func (r *DatabaseHostRepository) IncrementDatabaseCount(ctx context.Context, id uuid.UUID) error {
	const query = `
		UPDATE iam_realm_database_hosts
		SET    current_databases = current_databases + 1,
		       updated_at        = NOW()
		WHERE  id = $1`

	_, err := r.db.Exec(ctx, query, id)
	if err != nil {
		return fmt.Errorf("DatabaseHostRepository.IncrementDatabaseCount: %w", err)
	}
	return nil
}

// DecrementDatabaseCount atomically decrements current_databases for the host,
// never going below zero (the DB CHECK constraint enforces this).
func (r *DatabaseHostRepository) DecrementDatabaseCount(ctx context.Context, id uuid.UUID) error {
	const query = `
		UPDATE iam_realm_database_hosts
		SET    current_databases = GREATEST(current_databases - 1, 0),
		       updated_at        = NOW()
		WHERE  id = $1`

	_, err := r.db.Exec(ctx, query, id)
	if err != nil {
		return fmt.Errorf("DatabaseHostRepository.DecrementDatabaseCount: %w", err)
	}
	return nil
}

// UpdateHealthStatus writes a new health_status and last_health_check timestamp.
func (r *DatabaseHostRepository) UpdateHealthStatus(ctx context.Context, id uuid.UUID, status string) error {
	const query = `
		UPDATE iam_realm_database_hosts
		SET    health_status    = $1,
		       last_health_check = $2,
		       updated_at        = $2
		WHERE  id = $3`

	now := time.Now().UTC()
	_, err := r.db.Exec(ctx, query, status, now, id)
	if err != nil {
		return fmt.Errorf("DatabaseHostRepository.UpdateHealthStatus: %w", err)
	}
	return nil
}

// ListActiveRegions returns distinct region codes from active, healthy hosts.
// Used by the PolicyEngine to derive valid regions dynamically.
func (r *DatabaseHostRepository) ListActiveRegions(ctx context.Context) ([]string, error) {
	rows, err := r.db.Query(ctx,
		`SELECT DISTINCT region FROM iam_realm_database_hosts
		 WHERE is_active = true AND health_status = 'healthy' AND region IS NOT NULL
		 ORDER BY region`)
	if err != nil {
		return nil, fmt.Errorf("DatabaseHostRepository.ListActiveRegions: %w", err)
	}
	defer rows.Close()

	var regions []string
	for rows.Next() {
		var region string
		if err := rows.Scan(&region); err != nil {
			return nil, fmt.Errorf("DatabaseHostRepository.ListActiveRegions scan: %w", err)
		}
		regions = append(regions, region)
	}
	return regions, rows.Err()
}

// collectHosts scans all rows from a host query into a slice.
func collectHosts(rows pgx.Rows) ([]models.RealmDatabaseHost, error) {
	var result []models.RealmDatabaseHost
	for rows.Next() {
		var h models.RealmDatabaseHost
		if err := scanHostRow(rows, &h); err != nil {
			return nil, fmt.Errorf("collectHosts scan: %w", err)
		}
		result = append(result, h)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("collectHosts rows: %w", err)
	}
	return result, nil
}
