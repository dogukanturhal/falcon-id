// SPDX-License-Identifier: AGPL-3.0-or-later

package repositories

import (
	"context"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/jackc/pgx/v5/pgxpool"
)

// AppRegistrationRepository handles app registration database operations.
type AppRegistrationRepository struct {
	db *pgxpool.Pool
}

// NewAppRegistrationRepository creates a new app registration repository.
func NewAppRegistrationRepository(db *pgxpool.Pool) *AppRegistrationRepository {
	return &AppRegistrationRepository{db: db}
}

// Create inserts a new app registration.
func (r *AppRegistrationRepository) Create(ctx context.Context, reg *models.AppRegistration) error {
	if reg.ID == uuid.Nil {
		reg.ID = uuid.New()
	}

	query := `
		INSERT INTO iam_app_registrations (
			id, product_id, tenant_id, client_id, client_secret_hash, name, description,
			redirect_uris, allowed_origins, grant_types, scopes, logo_url, status, created_by
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
		RETURNING created_at, updated_at
	`

	err := r.db.QueryRow(ctx, query,
		reg.ID,
		reg.ProductID,
		reg.TenantID,
		reg.ClientID,
		reg.ClientSecretHash,
		reg.Name,
		reg.Description,
		reg.RedirectURIs,
		reg.AllowedOrigins,
		reg.GrantTypes,
		reg.Scopes,
		reg.LogoURL,
		reg.Status,
		reg.CreatedBy,
	).Scan(&reg.CreatedAt, &reg.UpdatedAt)
	if err != nil {
		return fmt.Errorf("AppRegistrationRepository.Create: %w", err)
	}
	return nil
}

// GetByID retrieves an app registration by UUID.
func (r *AppRegistrationRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.AppRegistration, error) {
	query := `
		SELECT id, product_id, tenant_id, client_id, client_secret_hash, name, description,
		       redirect_uris, allowed_origins, grant_types, scopes, logo_url, status, created_by,
		       created_at, updated_at
		FROM iam_app_registrations
		WHERE id = $1
	`
	return r.scanAppRegistration(ctx, query, id)
}

// GetByClientID retrieves an app registration by its OAuth client_id.
func (r *AppRegistrationRepository) GetByClientID(ctx context.Context, clientID string) (*models.AppRegistration, error) {
	query := `
		SELECT id, product_id, tenant_id, client_id, client_secret_hash, name, description,
		       redirect_uris, allowed_origins, grant_types, scopes, logo_url, status, created_by,
		       created_at, updated_at
		FROM iam_app_registrations
		WHERE client_id = $1
	`
	return r.scanAppRegistration(ctx, query, clientID)
}

// scanAppRegistration scans a single app registration row.
func (r *AppRegistrationRepository) scanAppRegistration(ctx context.Context, query string, arg interface{}) (*models.AppRegistration, error) {
	var reg models.AppRegistration

	err := r.db.QueryRow(ctx, query, arg).Scan(
		&reg.ID, &reg.ProductID, &reg.TenantID, &reg.ClientID, &reg.ClientSecretHash,
		&reg.Name, &reg.Description,
		&reg.RedirectURIs, &reg.AllowedOrigins, &reg.GrantTypes, &reg.Scopes,
		&reg.LogoURL, &reg.Status, &reg.CreatedBy,
		&reg.CreatedAt, &reg.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("AppRegistrationRepository.scanAppRegistration: %w", err)
	}

	return &reg, nil
}

// List returns a paginated list of app registrations with optional filters.
func (r *AppRegistrationRepository) List(
	ctx context.Context,
	page, pageSize int,
	tenantID, productID *uuid.UUID,
	status string,
) ([]models.AppRegistration, int64, error) {
	offset := (page - 1) * pageSize

	baseQuery := "FROM iam_app_registrations WHERE 1=1"
	args := []interface{}{}
	argIndex := 1

	if tenantID != nil {
		baseQuery += fmt.Sprintf(" AND tenant_id = $%d", argIndex)
		args = append(args, *tenantID)
		argIndex++
	}
	if productID != nil {
		baseQuery += fmt.Sprintf(" AND product_id = $%d", argIndex)
		args = append(args, *productID)
		argIndex++
	}
	if status != "" {
		baseQuery += fmt.Sprintf(" AND status = $%d", argIndex)
		args = append(args, status)
		argIndex++
	}

	var total int64
	if err := r.db.QueryRow(ctx, "SELECT COUNT(*) "+baseQuery, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("AppRegistrationRepository.List count: %w", err)
	}

	selectQuery := fmt.Sprintf(`
		SELECT id, product_id, tenant_id, client_id, client_secret_hash, name, description,
		       redirect_uris, allowed_origins, grant_types, scopes, logo_url, status, created_by,
		       created_at, updated_at
		%s
		ORDER BY created_at DESC
		LIMIT $%d OFFSET $%d`,
		baseQuery, argIndex, argIndex+1)
	args = append(args, pageSize, offset)

	rows, err := r.db.Query(ctx, selectQuery, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("AppRegistrationRepository.List query: %w", err)
	}
	defer rows.Close()

	var registrations []models.AppRegistration
	for rows.Next() {
		var reg models.AppRegistration
		if err := rows.Scan(
			&reg.ID, &reg.ProductID, &reg.TenantID, &reg.ClientID, &reg.ClientSecretHash,
			&reg.Name, &reg.Description,
			&reg.RedirectURIs, &reg.AllowedOrigins, &reg.GrantTypes, &reg.Scopes,
			&reg.LogoURL, &reg.Status, &reg.CreatedBy,
			&reg.CreatedAt, &reg.UpdatedAt,
		); err != nil {
			return nil, 0, fmt.Errorf("AppRegistrationRepository.List scan: %w", err)
		}
		registrations = append(registrations, reg)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("AppRegistrationRepository.List rows: %w", err)
	}

	return registrations, total, nil
}

// Update applies partial updates to an app registration.
func (r *AppRegistrationRepository) Update(ctx context.Context, id uuid.UUID, req *models.UpdateAppRegistrationRequest) (*models.AppRegistration, error) {
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
	if req.RedirectURIs != nil {
		setClauses = append(setClauses, fmt.Sprintf("redirect_uris = $%d", argIndex))
		args = append(args, req.RedirectURIs)
		argIndex++
	}
	if req.AllowedOrigins != nil {
		setClauses = append(setClauses, fmt.Sprintf("allowed_origins = $%d", argIndex))
		args = append(args, req.AllowedOrigins)
		argIndex++
	}
	if req.GrantTypes != nil {
		setClauses = append(setClauses, fmt.Sprintf("grant_types = $%d", argIndex))
		args = append(args, req.GrantTypes)
		argIndex++
	}
	if req.Scopes != nil {
		setClauses = append(setClauses, fmt.Sprintf("scopes = $%d", argIndex))
		args = append(args, req.Scopes)
		argIndex++
	}
	if req.LogoURL != nil {
		setClauses = append(setClauses, fmt.Sprintf("logo_url = $%d", argIndex))
		args = append(args, *req.LogoURL)
		argIndex++
	}
	if req.Status != nil {
		setClauses = append(setClauses, fmt.Sprintf("status = $%d", argIndex))
		args = append(args, *req.Status)
		argIndex++
	}

	if len(setClauses) == 0 {
		return r.GetByID(ctx, id)
	}

	setClauses = append(setClauses, "updated_at = NOW()")
	args = append(args, id)

	query := fmt.Sprintf(`
		UPDATE iam_app_registrations
		SET %s
		WHERE id = $%d
		RETURNING id, product_id, tenant_id, client_id, client_secret_hash, name, description,
		          redirect_uris, allowed_origins, grant_types, scopes, logo_url, status, created_by,
		          created_at, updated_at`,
		strings.Join(setClauses, ", "), argIndex)

	var reg models.AppRegistration
	err := r.db.QueryRow(ctx, query, args...).Scan(
		&reg.ID, &reg.ProductID, &reg.TenantID, &reg.ClientID, &reg.ClientSecretHash,
		&reg.Name, &reg.Description,
		&reg.RedirectURIs, &reg.AllowedOrigins, &reg.GrantTypes, &reg.Scopes,
		&reg.LogoURL, &reg.Status, &reg.CreatedBy,
		&reg.CreatedAt, &reg.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("AppRegistrationRepository.Update: %w", err)
	}

	return &reg, nil
}

// UpdateSecret replaces the hashed client secret.
func (r *AppRegistrationRepository) UpdateSecret(ctx context.Context, id uuid.UUID, secretHash string) error {
	_, err := r.db.Exec(ctx,
		"UPDATE iam_app_registrations SET client_secret_hash = $1, updated_at = NOW() WHERE id = $2",
		secretHash, id,
	)
	if err != nil {
		return fmt.Errorf("AppRegistrationRepository.UpdateSecret: %w", err)
	}
	return nil
}

// UpdateStatus sets the status of an app registration.
func (r *AppRegistrationRepository) UpdateStatus(ctx context.Context, id uuid.UUID, status string) error {
	_, err := r.db.Exec(ctx,
		"UPDATE iam_app_registrations SET status = $1, updated_at = NOW() WHERE id = $2",
		status, id,
	)
	if err != nil {
		return fmt.Errorf("AppRegistrationRepository.UpdateStatus: %w", err)
	}
	return nil
}

// Delete removes an app registration by ID.
func (r *AppRegistrationRepository) Delete(ctx context.Context, id uuid.UUID) error {
	_, err := r.db.Exec(ctx, "DELETE FROM iam_app_registrations WHERE id = $1", id)
	if err != nil {
		return fmt.Errorf("AppRegistrationRepository.Delete: %w", err)
	}
	return nil
}
