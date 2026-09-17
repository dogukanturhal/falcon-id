// SPDX-License-Identifier: AGPL-3.0-or-later

package repositories

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

// AppIdentityProviderRepository handles per-app IDP enablement database operations.
type AppIdentityProviderRepository struct {
	pool *pgxpool.Pool
}

// NewAppIdentityProviderRepository creates a new AppIdentityProviderRepository.
func NewAppIdentityProviderRepository(pool *pgxpool.Pool) *AppIdentityProviderRepository {
	return &AppIdentityProviderRepository{pool: pool}
}

// Add enables an IDP for an application.
func (r *AppIdentityProviderRepository) Add(ctx context.Context, record *models.AppIdentityProvider) error {
	query := `
		INSERT INTO iam_app_identity_providers (application_id, identity_provider_id, is_enabled, priority)
		VALUES ($1, $2, $3, $4)
		RETURNING id, created_at
	`
	return r.pool.QueryRow(ctx, query,
		record.ApplicationID,
		record.IdentityProviderID,
		record.IsEnabled,
		record.Priority,
	).Scan(&record.ID, &record.CreatedAt)
}

// Remove disables/removes an IDP from an application.
func (r *AppIdentityProviderRepository) Remove(ctx context.Context, applicationID, identityProviderID uuid.UUID) error {
	query := `DELETE FROM iam_app_identity_providers WHERE application_id = $1 AND identity_provider_id = $2`
	tag, err := r.pool.Exec(ctx, query, applicationID, identityProviderID)
	if err != nil {
		return fmt.Errorf("failed to remove app IdP: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("app identity provider not found")
	}
	return nil
}

// ListByApp returns all IDPs enabled for an application, joined with provider details.
func (r *AppIdentityProviderRepository) ListByApp(ctx context.Context, applicationID uuid.UUID) ([]models.AppIdentityProvider, error) {
	query := `
		SELECT ai.id, ai.application_id, ai.identity_provider_id, ai.is_enabled, ai.priority, ai.created_at,
		       ip.provider_name, ip.provider_type, ip.display_name
		FROM iam_app_identity_providers ai
		JOIN iam_identity_providers ip ON ip.id = ai.identity_provider_id
		WHERE ai.application_id = $1
		ORDER BY ai.priority ASC, ai.created_at ASC
	`
	rows, err := r.pool.Query(ctx, query, applicationID)
	if err != nil {
		return nil, fmt.Errorf("failed to list app IdPs: %w", err)
	}
	defer rows.Close()

	var records []models.AppIdentityProvider
	for rows.Next() {
		var rec models.AppIdentityProvider
		if err := rows.Scan(
			&rec.ID, &rec.ApplicationID, &rec.IdentityProviderID, &rec.IsEnabled, &rec.Priority, &rec.CreatedAt,
			&rec.ProviderName, &rec.ProviderType, &rec.ProviderDisplayName,
		); err != nil {
			return nil, fmt.Errorf("failed to scan app IdP: %w", err)
		}
		records = append(records, rec)
	}
	return records, rows.Err()
}

// ListByIDP is an exported identifier.
// ListByIDP returns all applications that have a specific IDP enabled.
func (r *AppIdentityProviderRepository) ListByIDP(ctx context.Context, identityProviderID uuid.UUID) ([]models.AppIdentityProvider, error) {
	query := `
		SELECT ai.id, ai.application_id, ai.identity_provider_id, ai.is_enabled, ai.priority, ai.created_at
		FROM iam_app_identity_providers ai
		WHERE ai.identity_provider_id = $1
		ORDER BY ai.created_at ASC
	`
	rows, err := r.pool.Query(ctx, query, identityProviderID)
	if err != nil {
		return nil, fmt.Errorf("failed to list apps by IdP: %w", err)
	}
	defer rows.Close()

	var records []models.AppIdentityProvider
	for rows.Next() {
		var rec models.AppIdentityProvider
		if err := rows.Scan(
			&rec.ID, &rec.ApplicationID, &rec.IdentityProviderID, &rec.IsEnabled, &rec.Priority, &rec.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf("failed to scan app IdP: %w", err)
		}
		records = append(records, rec)
	}
	return records, rows.Err()
}

// IsEnabled checks if a specific IDP is enabled for a specific application.
func (r *AppIdentityProviderRepository) IsEnabled(ctx context.Context, applicationID, identityProviderID uuid.UUID) (bool, error) {
	query := `
		SELECT is_enabled FROM iam_app_identity_providers
		WHERE application_id = $1 AND identity_provider_id = $2
	`
	var enabled bool
	err := r.pool.QueryRow(ctx, query, applicationID, identityProviderID).Scan(&enabled)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return false, nil
		}
		return false, fmt.Errorf("failed to check app IdP status: %w", err)
	}
	return enabled, nil
}

// GetEnabledIDPIDs is an exported identifier.
// GetEnabledIDPIDs returns the set of enabled IDP IDs for an application.
func (r *AppIdentityProviderRepository) GetEnabledIDPIDs(ctx context.Context, applicationID uuid.UUID) ([]uuid.UUID, error) {
	query := `
		SELECT identity_provider_id FROM iam_app_identity_providers
		WHERE application_id = $1 AND is_enabled = true
	`
	rows, err := r.pool.Query(ctx, query, applicationID)
	if err != nil {
		return nil, fmt.Errorf("failed to get enabled IdP IDs: %w", err)
	}
	defer rows.Close()

	var ids []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("failed to scan IdP ID: %w", err)
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}
