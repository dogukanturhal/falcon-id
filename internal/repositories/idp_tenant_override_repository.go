// SPDX-License-Identifier: AGPL-3.0-or-later

package repositories

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

// IDPTenantOverrideRepository is an exported identifier.
// IDPTenantOverrideRepository handles persistence for iam_idp_tenant_overrides.
type IDPTenantOverrideRepository struct {
	db *pgxpool.Pool
}

// NewIDPTenantOverrideRepository is an exported identifier.
// NewIDPTenantOverrideRepository constructs a new IDPTenantOverrideRepository.
func NewIDPTenantOverrideRepository(db *pgxpool.Pool) *IDPTenantOverrideRepository {
	return &IDPTenantOverrideRepository{db: db}
}

// scanOverride scans a single override row.  The caller must supply a
// pre-allocated *models.IDPTenantOverride and a scratch []byte for the
// config_overrides JSONB column.
func (r *IDPTenantOverrideRepository) scanOverride(
	row pgx.Row,
	o *models.IDPTenantOverride,
) error {
	var configJSON []byte

	err := row.Scan(
		&o.ID,
		&o.TenantID,
		&o.ProviderID,
		&o.IsEnabled,
		&o.DisplayName,
		&o.Priority,
		&configJSON,
		&o.AssignMembershipOnLogin,
		&o.IsSignupEnabled,
		&o.ShowAsButton,
		&o.CreatedAt,
		&o.UpdatedAt,
	)
	if err != nil {
		return err
	}

	if configJSON != nil {
		o.ConfigOverrides = json.RawMessage(configJSON)
	} else {
		o.ConfigOverrides = json.RawMessage("{}")
	}

	return nil
}

const selectColumns = `
	id, tenant_id, provider_id, is_enabled, display_name, priority,
	config_overrides,
	assign_membership_on_login, is_signup_enabled, show_as_button,
	created_at, updated_at`

// Upsert inserts or updates an override for (tenant_id, provider_id).
// The record is returned with server-generated timestamps populated.
func (r *IDPTenantOverrideRepository) Upsert(
	ctx context.Context,
	o *models.IDPTenantOverride,
) error {
	configJSON := []byte("{}")
	if o.ConfigOverrides != nil {
		configJSON = o.ConfigOverrides
	}

	if o.ID == uuid.Nil {
		o.ID = uuid.New()
	}

	query := `
		INSERT INTO iam_idp_tenant_overrides (
			id, tenant_id, provider_id, is_enabled, display_name, priority,
			config_overrides,
			assign_membership_on_login, is_signup_enabled, show_as_button
		) VALUES (
			$1,  $2,  $3,  $4,  $5,  $6,
			$7,
			$8,  $9,  $10
		)
		ON CONFLICT (tenant_id, provider_id) DO UPDATE SET
			is_enabled               = EXCLUDED.is_enabled,
			display_name             = EXCLUDED.display_name,
			priority                 = EXCLUDED.priority,
			config_overrides         = EXCLUDED.config_overrides,
			assign_membership_on_login = EXCLUDED.assign_membership_on_login,
			is_signup_enabled        = EXCLUDED.is_signup_enabled,
			show_as_button           = EXCLUDED.show_as_button,
			updated_at               = now()
		RETURNING ` + selectColumns

	row := r.db.QueryRow(ctx, query,
		o.ID,
		o.TenantID,
		o.ProviderID,
		o.IsEnabled,
		o.DisplayName,
		o.Priority,
		configJSON,
		o.AssignMembershipOnLogin,
		o.IsSignupEnabled,
		o.ShowAsButton,
	)

	return r.scanOverride(row, o)
}

// GetByID returns a single override by its primary key, or nil if not found.
func (r *IDPTenantOverrideRepository) GetByID(
	ctx context.Context,
	id uuid.UUID,
) (*models.IDPTenantOverride, error) {
	query := `SELECT ` + selectColumns + ` FROM iam_idp_tenant_overrides WHERE id = $1`

	o := &models.IDPTenantOverride{}
	err := r.scanOverride(r.db.QueryRow(ctx, query, id), o)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("GetByID: %w", err)
	}

	return o, nil
}

// GetByTenantAndProvider returns the override for a specific (tenant, provider)
// pair, or nil if none exists.
func (r *IDPTenantOverrideRepository) GetByTenantAndProvider(
	ctx context.Context,
	tenantID, providerID uuid.UUID,
) (*models.IDPTenantOverride, error) {
	query := `SELECT ` + selectColumns + `
		FROM iam_idp_tenant_overrides
		WHERE tenant_id = $1 AND provider_id = $2`

	o := &models.IDPTenantOverride{}
	err := r.scanOverride(r.db.QueryRow(ctx, query, tenantID, providerID), o)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("GetByTenantAndProvider: %w", err)
	}

	return o, nil
}

// List returns all overrides for a tenant, ordered by priority descending.
func (r *IDPTenantOverrideRepository) List(
	ctx context.Context,
	tenantID uuid.UUID,
) ([]*models.IDPTenantOverride, error) {
	query := `SELECT ` + selectColumns + `
		FROM iam_idp_tenant_overrides
		WHERE tenant_id = $1
		ORDER BY priority DESC, provider_id ASC`

	rows, err := r.db.Query(ctx, query, tenantID)
	if err != nil {
		return nil, fmt.Errorf("List: %w", err)
	}
	defer rows.Close()

	var overrides []*models.IDPTenantOverride
	for rows.Next() {
		o := &models.IDPTenantOverride{}
		var configJSON []byte

		if err := rows.Scan(
			&o.ID,
			&o.TenantID,
			&o.ProviderID,
			&o.IsEnabled,
			&o.DisplayName,
			&o.Priority,
			&configJSON,
			&o.AssignMembershipOnLogin,
			&o.IsSignupEnabled,
			&o.ShowAsButton,
			&o.CreatedAt,
			&o.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("List scan: %w", err)
		}

		if configJSON != nil {
			o.ConfigOverrides = json.RawMessage(configJSON)
		} else {
			o.ConfigOverrides = json.RawMessage("{}")
		}

		overrides = append(overrides, o)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("List rows: %w", err)
	}

	return overrides, nil
}

// Delete removes the override record by its primary key.
func (r *IDPTenantOverrideRepository) Delete(ctx context.Context, id uuid.UUID) error {
	_, err := r.db.Exec(ctx, "DELETE FROM iam_idp_tenant_overrides WHERE id = $1", id)
	if err != nil {
		return fmt.Errorf("Delete: %w", err)
	}
	return nil
}

// GetOverrideMapByTenant returns a map of provider_id → *IDPTenantOverride for a
// tenant.  This is a batch-load optimisation used by the service layer to avoid
// N+1 queries when rendering the login page.
func (r *IDPTenantOverrideRepository) GetOverrideMapByTenant(
	ctx context.Context,
	tenantID uuid.UUID,
) (map[uuid.UUID]*models.IDPTenantOverride, error) {
	overrides, err := r.List(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("GetOverrideMapByTenant: %w", err)
	}

	m := make(map[uuid.UUID]*models.IDPTenantOverride, len(overrides))
	for _, o := range overrides {
		m[o.ProviderID] = o
	}

	return m, nil
}
