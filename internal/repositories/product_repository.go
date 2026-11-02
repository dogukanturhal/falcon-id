// SPDX-License-Identifier: AGPL-3.0-or-later

package repositories

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/internal/productslug"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ProductRepository handles product database operations.
type ProductRepository struct {
	db *pgxpool.Pool
}

// NewProductRepository creates a new product repository.
func NewProductRepository(db *pgxpool.Pool) *ProductRepository {
	return &ProductRepository{db: db}
}

// Create inserts a new product and populates the ID, CreatedAt, and UpdatedAt fields.
func (r *ProductRepository) Create(ctx context.Context, product *models.Product) error {
	if product.ID == uuid.Nil {
		product.ID = uuid.New()
	}

	metadataJSON, _ := json.Marshal(product.Metadata)

	query := `
		INSERT INTO iam_products (
			id, name, slug, description, type, status,
			icon_url, homepage_url, documentation_url, metadata, created_by
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
		RETURNING created_at, updated_at
	`

	err := r.db.QueryRow(ctx, query,
		product.ID,
		product.Name,
		product.Slug,
		product.Description,
		product.Type,
		product.Status,
		product.IconURL,
		product.HomepageURL,
		product.DocumentationURL,
		metadataJSON,
		product.CreatedBy,
	).Scan(&product.CreatedAt, &product.UpdatedAt)
	if err != nil {
		return fmt.Errorf("ProductRepository.Create: %w", err)
	}
	return nil
}

// GetByID retrieves a product by its UUID.
func (r *ProductRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.Product, error) {
	query := `
		SELECT id, name, slug, description, type, status,
		       icon_url, homepage_url, documentation_url, metadata, capability_manifest, created_by,
		       created_at, updated_at
		FROM iam_products
		WHERE id = $1
	`

	return r.scanProduct(ctx, query, id)
}

// GetBySlug retrieves a product by its slug.
func (r *ProductRepository) GetBySlug(ctx context.Context, slug string) (*models.Product, error) {
	query := `
		SELECT id, name, slug, description, type, status,
		       icon_url, homepage_url, documentation_url, metadata, capability_manifest, created_by,
		       created_at, updated_at
		FROM iam_products
		WHERE slug = ANY($1)
		ORDER BY (slug = $2) DESC
		LIMIT 1
	`

	return r.scanProduct(ctx, query, productslug.Aliases(slug), slug)
}

// scanProduct is a helper that scans a single product row.
//
// capability_manifest MUST be part of the SELECT list passed in — it drives
// DefaultModuleEntitlementChecker.IsTenantEntitled's manifest-permission
// match (internal/services/module_entitlement_checker.go). It was omitted
// here for an unknown period, which meant every module entitlement lookup
// silently fell back to the exact product-slug match only and manifest-declared
// modules (e.g. "marketing") were NEVER entitled for any tenant, no matter
// what capability_manifest held in the database.
func (r *ProductRepository) scanProduct(ctx context.Context, query string, args ...interface{}) (*models.Product, error) {
	var product models.Product
	var metadataJSON []byte

	err := r.db.QueryRow(ctx, query, args...).Scan(
		&product.ID,
		&product.Name,
		&product.Slug,
		&product.Description,
		&product.Type,
		&product.Status,
		&product.IconURL,
		&product.HomepageURL,
		&product.DocumentationURL,
		&metadataJSON,
		&product.CapabilityManifest,
		&product.CreatedBy,
		&product.CreatedAt,
		&product.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("ProductRepository.scanProduct: %w", err)
	}

	if metadataJSON != nil {
		_ = json.Unmarshal(metadataJSON, &product.Metadata)
	}

	return &product, nil
}

// List returns a paginated list of products with optional filters.
func (r *ProductRepository) List(
	ctx context.Context,
	page, pageSize int,
	search, productType, status string,
) ([]models.Product, int64, error) {
	offset := (page - 1) * pageSize

	baseQuery := "FROM iam_products WHERE 1=1"
	args := []interface{}{}
	argIndex := 1

	if search != "" {
		baseQuery += fmt.Sprintf(" AND (name ILIKE $%d OR slug ILIKE $%d)", argIndex, argIndex)
		args = append(args, "%"+search+"%")
		argIndex++
	}

	if productType != "" {
		baseQuery += fmt.Sprintf(" AND type = $%d", argIndex)
		args = append(args, productType)
		argIndex++
	}

	if status != "" {
		baseQuery += fmt.Sprintf(" AND status = $%d", argIndex)
		args = append(args, status)
		argIndex++
	}

	// Count total
	var total int64
	countQuery := "SELECT COUNT(*) " + baseQuery
	if err := r.db.QueryRow(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("ProductRepository.List count: %w", err)
	}

	// Fetch page
	selectQuery := fmt.Sprintf(`
		SELECT id, name, slug, description, type, status,
		       icon_url, homepage_url, documentation_url, metadata, created_by,
		       created_at, updated_at
		%s
		ORDER BY created_at DESC
		LIMIT $%d OFFSET $%d`,
		baseQuery, argIndex, argIndex+1)
	args = append(args, pageSize, offset)

	rows, err := r.db.Query(ctx, selectQuery, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("ProductRepository.List query: %w", err)
	}
	defer rows.Close()

	var products []models.Product
	for rows.Next() {
		var p models.Product
		var metadataJSON []byte

		if err := rows.Scan(
			&p.ID, &p.Name, &p.Slug, &p.Description,
			&p.Type, &p.Status,
			&p.IconURL, &p.HomepageURL, &p.DocumentationURL,
			&metadataJSON, &p.CreatedBy,
			&p.CreatedAt, &p.UpdatedAt,
		); err != nil {
			return nil, 0, fmt.Errorf("ProductRepository.List scan: %w", err)
		}

		if metadataJSON != nil {
			_ = json.Unmarshal(metadataJSON, &p.Metadata)
		}

		products = append(products, p)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("ProductRepository.List rows: %w", err)
	}

	return products, total, nil
}

// Update applies partial updates to a product and returns the updated record.
func (r *ProductRepository) Update(ctx context.Context, id uuid.UUID, req *models.UpdateProductRequest) (*models.Product, error) {
	setClauses := []string{}
	args := []interface{}{}
	argIndex := 1

	if req.Name != nil {
		setClauses = append(setClauses, fmt.Sprintf("name = $%d", argIndex))
		args = append(args, *req.Name)
		argIndex++
	}
	if req.Description != nil {
		setClauses = append(setClauses, fmt.Sprintf("description = $%d", argIndex))
		args = append(args, *req.Description)
		argIndex++
	}
	if req.Status != nil {
		setClauses = append(setClauses, fmt.Sprintf("status = $%d", argIndex))
		args = append(args, *req.Status)
		argIndex++
	}
	if req.IconURL != nil {
		setClauses = append(setClauses, fmt.Sprintf("icon_url = $%d", argIndex))
		args = append(args, *req.IconURL)
		argIndex++
	}
	if req.HomepageURL != nil {
		setClauses = append(setClauses, fmt.Sprintf("homepage_url = $%d", argIndex))
		args = append(args, *req.HomepageURL)
		argIndex++
	}
	if req.DocumentationURL != nil {
		setClauses = append(setClauses, fmt.Sprintf("documentation_url = $%d", argIndex))
		args = append(args, *req.DocumentationURL)
		argIndex++
	}
	if req.Metadata != nil {
		metadataJSON, _ := json.Marshal(req.Metadata)
		setClauses = append(setClauses, fmt.Sprintf("metadata = $%d", argIndex))
		args = append(args, metadataJSON)
		argIndex++
	}

	if len(setClauses) == 0 {
		return r.GetByID(ctx, id)
	}

	setClauses = append(setClauses, "updated_at = NOW()")
	args = append(args, id)

	query := fmt.Sprintf(`
		UPDATE iam_products
		SET %s
		WHERE id = $%d
		RETURNING id, name, slug, description, type, status,
		          icon_url, homepage_url, documentation_url, metadata, created_by,
		          created_at, updated_at`,
		strings.Join(setClauses, ", "), argIndex)

	var product models.Product
	var metadataJSON []byte

	err := r.db.QueryRow(ctx, query, args...).Scan(
		&product.ID, &product.Name, &product.Slug, &product.Description,
		&product.Type, &product.Status,
		&product.IconURL, &product.HomepageURL, &product.DocumentationURL,
		&metadataJSON, &product.CreatedBy,
		&product.CreatedAt, &product.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("ProductRepository.Update: %w", err)
	}

	if metadataJSON != nil {
		_ = json.Unmarshal(metadataJSON, &product.Metadata)
	}

	return &product, nil
}

// Delete removes a product by ID.
func (r *ProductRepository) Delete(ctx context.Context, id uuid.UUID) error {
	_, err := r.db.Exec(ctx, "DELETE FROM iam_products WHERE id = $1", id)
	if err != nil {
		return fmt.Errorf("ProductRepository.Delete: %w", err)
	}
	return nil
}

// ListActive returns a paginated list of products with status "active",
// together with the total count of active products. It satisfies the
// handlers.catalogProductRepo interface consumed by CatalogHandler.
func (r *ProductRepository) ListActive(ctx context.Context, page, pageSize int) ([]models.Product, int64, error) {
	offset := (page - 1) * pageSize

	// Count total active products.
	var total int64
	if err := r.db.QueryRow(ctx,
		"SELECT COUNT(*) FROM iam_products WHERE status = 'active'",
	).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("ProductRepository.ListActive count: %w", err)
	}

	rows, err := r.db.Query(ctx, `
		SELECT id, name, slug, description, type, status,
		       icon_url, homepage_url, documentation_url, metadata, created_by,
		       created_at, updated_at
		FROM iam_products
		WHERE status = 'active'
		ORDER BY created_at DESC
		LIMIT $1 OFFSET $2`,
		pageSize, offset,
	)
	if err != nil {
		return nil, 0, fmt.Errorf("ProductRepository.ListActive query: %w", err)
	}
	defer rows.Close()

	var products []models.Product
	for rows.Next() {
		var p models.Product
		var metadataJSON []byte
		if err := rows.Scan(
			&p.ID, &p.Name, &p.Slug, &p.Description,
			&p.Type, &p.Status,
			&p.IconURL, &p.HomepageURL, &p.DocumentationURL,
			&metadataJSON, &p.CreatedBy,
			&p.CreatedAt, &p.UpdatedAt,
		); err != nil {
			return nil, 0, fmt.Errorf("ProductRepository.ListActive scan: %w", err)
		}
		if metadataJSON != nil {
			_ = json.Unmarshal(metadataJSON, &p.Metadata)
		}
		products = append(products, p)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("ProductRepository.ListActive rows: %w", err)
	}

	return products, total, nil
}

// CreateVersion inserts a new product version.
func (r *ProductRepository) CreateVersion(ctx context.Context, version *models.ProductVersion) error {
	if version.ID == uuid.Nil {
		version.ID = uuid.New()
	}

	query := `
		INSERT INTO iam_product_versions (
			id, product_id, version, release_notes, min_api_version, status, released_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7)
		RETURNING created_at
	`

	err := r.db.QueryRow(ctx, query,
		version.ID,
		version.ProductID,
		version.Version,
		version.ReleaseNotes,
		version.MinAPIVersion,
		version.Status,
		version.ReleasedAt,
	).Scan(&version.CreatedAt)
	if err != nil {
		return fmt.Errorf("ProductRepository.CreateVersion: %w", err)
	}
	return nil
}

// ListVersions returns all versions for a given product.
func (r *ProductRepository) ListVersions(ctx context.Context, productID uuid.UUID) ([]models.ProductVersion, error) {
	query := `
		SELECT id, product_id, version, release_notes, min_api_version, status, released_at, created_at
		FROM iam_product_versions
		WHERE product_id = $1
		ORDER BY created_at DESC
	`

	rows, err := r.db.Query(ctx, query, productID)
	if err != nil {
		return nil, fmt.Errorf("ProductRepository.ListVersions: %w", err)
	}
	defer rows.Close()

	var versions []models.ProductVersion
	for rows.Next() {
		var v models.ProductVersion
		if err := rows.Scan(
			&v.ID, &v.ProductID, &v.Version, &v.ReleaseNotes,
			&v.MinAPIVersion, &v.Status, &v.ReleasedAt, &v.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf("ProductRepository.ListVersions scan: %w", err)
		}
		versions = append(versions, v)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("ProductRepository.ListVersions rows: %w", err)
	}

	return versions, nil
}

// GetVersion retrieves a single product version by ID.
func (r *ProductRepository) GetVersion(ctx context.Context, id uuid.UUID) (*models.ProductVersion, error) {
	query := `
		SELECT id, product_id, version, release_notes, min_api_version, status, released_at, created_at
		FROM iam_product_versions
		WHERE id = $1
	`

	var v models.ProductVersion
	err := r.db.QueryRow(ctx, query, id).Scan(
		&v.ID, &v.ProductID, &v.Version, &v.ReleaseNotes,
		&v.MinAPIVersion, &v.Status, &v.ReleasedAt, &v.CreatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("ProductRepository.GetVersion: %w", err)
	}

	return &v, nil
}

// UpdateVersionStatus updates the lifecycle status of a product version.
func (r *ProductRepository) UpdateVersionStatus(ctx context.Context, id uuid.UUID, status string) error {
	_, err := r.db.Exec(ctx,
		"UPDATE iam_product_versions SET status = $1 WHERE id = $2",
		status, id,
	)
	if err != nil {
		return fmt.Errorf("ProductRepository.UpdateVersionStatus: %w", err)
	}
	return nil
}
