// SPDX-License-Identifier: AGPL-3.0-or-later

package repositories

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

// ProductDatabaseGroupRepository handles database operations for product database groups.
type ProductDatabaseGroupRepository struct {
	pool *pgxpool.Pool
}

// NewProductDatabaseGroupRepository creates a new repository.
func NewProductDatabaseGroupRepository(pool *pgxpool.Pool) *ProductDatabaseGroupRepository {
	return &ProductDatabaseGroupRepository{pool: pool}
}

// ListByProduct returns all database groups for a product, ordered by priority.
func (r *ProductDatabaseGroupRepository) ListByProduct(ctx context.Context, productID uuid.UUID) ([]models.ProductDatabaseGroup, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT id, product_id, database_name, display_name, migration_dir,
		       priority, is_control_plane, required_extensions, created_at, updated_at
		FROM iam_product_database_groups
		WHERE product_id = $1
		ORDER BY priority, database_name
	`, productID)
	if err != nil {
		return nil, fmt.Errorf("list database groups: %w", err)
	}
	defer rows.Close()

	var groups []models.ProductDatabaseGroup
	for rows.Next() {
		var g models.ProductDatabaseGroup
		if err := rows.Scan(
			&g.ID, &g.ProductID, &g.DatabaseName, &g.DisplayName, &g.MigrationDir,
			&g.Priority, &g.IsControlPlane, &g.RequiredExtensions, &g.CreatedAt, &g.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan database group: %w", err)
		}
		groups = append(groups, g)
	}
	return groups, rows.Err()
}

// GetByProductAndName returns a specific database group.
func (r *ProductDatabaseGroupRepository) GetByProductAndName(ctx context.Context, productID uuid.UUID, dbName string) (*models.ProductDatabaseGroup, error) {
	var g models.ProductDatabaseGroup
	err := r.pool.QueryRow(ctx, `
		SELECT id, product_id, database_name, display_name, migration_dir,
		       priority, is_control_plane, required_extensions, created_at, updated_at
		FROM iam_product_database_groups
		WHERE product_id = $1 AND database_name = $2
	`, productID, dbName).Scan(
		&g.ID, &g.ProductID, &g.DatabaseName, &g.DisplayName, &g.MigrationDir,
		&g.Priority, &g.IsControlPlane, &g.RequiredExtensions, &g.CreatedAt, &g.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("get database group: %w", err)
	}
	return &g, nil
}

// Create inserts a new database group.
func (r *ProductDatabaseGroupRepository) Create(ctx context.Context, group *models.ProductDatabaseGroup) error {
	if group.ID == uuid.Nil {
		group.ID = uuid.New()
	}
	if group.RequiredExtensions == nil {
		group.RequiredExtensions = []string{}
	}

	err := r.pool.QueryRow(ctx, `
		INSERT INTO iam_product_database_groups
			(id, product_id, database_name, display_name, migration_dir, priority, is_control_plane, required_extensions)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		RETURNING created_at, updated_at
	`, group.ID, group.ProductID, group.DatabaseName, group.DisplayName,
		group.MigrationDir, group.Priority, group.IsControlPlane, group.RequiredExtensions,
	).Scan(&group.CreatedAt, &group.UpdatedAt)
	if err != nil {
		return fmt.Errorf("create database group: %w", err)
	}
	return nil
}

// Delete removes a database group by ID.
func (r *ProductDatabaseGroupRepository) Delete(ctx context.Context, id uuid.UUID) error {
	tag, err := r.pool.Exec(ctx, `DELETE FROM iam_product_database_groups WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("delete database group: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("database group not found")
	}
	return nil
}

// ListAll returns all database groups across all products, for db-migrator registry.
func (r *ProductDatabaseGroupRepository) ListAll(ctx context.Context) ([]models.ProductDatabaseGroup, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT id, product_id, database_name, display_name, migration_dir,
		       priority, is_control_plane, required_extensions, created_at, updated_at
		FROM iam_product_database_groups
		ORDER BY priority, database_name
	`)
	if err != nil {
		return nil, fmt.Errorf("list all database groups: %w", err)
	}
	defer rows.Close()

	var groups []models.ProductDatabaseGroup
	for rows.Next() {
		var g models.ProductDatabaseGroup
		if err := rows.Scan(
			&g.ID, &g.ProductID, &g.DatabaseName, &g.DisplayName, &g.MigrationDir,
			&g.Priority, &g.IsControlPlane, &g.RequiredExtensions, &g.CreatedAt, &g.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan database group: %w", err)
		}
		groups = append(groups, g)
	}
	return groups, rows.Err()
}
