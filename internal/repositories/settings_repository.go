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

// SettingsRepository is an exported type.
type SettingsRepository struct {
	pool *pgxpool.Pool
}

// NewSettingsRepository is an exported function.
func NewSettingsRepository(pool *pgxpool.Pool) *SettingsRepository {
	return &SettingsRepository{pool: pool}
}

// GetByTenantID retrieves settings for a specific tenant
func (r *SettingsRepository) GetByTenantID(ctx context.Context, tenantID uuid.UUID) (*models.IAMSettings, error) {
	query := `
		SELECT id, tenant_id, hr_ldap_enabled, hr_ldap_server, hr_ldap_port, hr_ldap_use_tls,
		       hr_ldap_bind_dn, hr_ldap_bind_password, hr_ldap_base_dn, hr_ldap_user_filter,
		       hr_ldap_group_base_dn, hr_ldap_group_filter,
		       COALESCE(abac_enabled, false), COALESCE(abac_fallback_rbac, true), COALESCE(role_expiration_enabled, true),
		       created_at, updated_at, updated_by
		FROM iam_settings
		WHERE tenant_id = $1
	`

	var settings models.IAMSettings
	err := r.pool.QueryRow(ctx, query, tenantID).Scan(
		&settings.ID,
		&settings.TenantID,
		&settings.HRLDAPEnabled,
		&settings.HRLDAPServer,
		&settings.HRLDAPPort,
		&settings.HRLDAPUseTLS,
		&settings.HRLDAPBindDN,
		&settings.HRLDAPBindPassword,
		&settings.HRLDAPBaseDN,
		&settings.HRLDAPUserFilter,
		&settings.HRLDAPGroupBaseDN,
		&settings.HRLDAPGroupFilter,
		&settings.ABACEnabled,
		&settings.ABACFallbackRBAC,
		&settings.RoleExpirationEnabled,
		&settings.CreatedAt,
		&settings.UpdatedAt,
		&settings.UpdatedBy,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			// Return default settings when none exist for this tenant
			return &models.IAMSettings{
				TenantID:              tenantID,
				ABACFallbackRBAC:      true,
				RoleExpirationEnabled: true,
			}, nil
		}
		return nil, fmt.Errorf("failed to get settings: %w", err)
	}

	return &settings, nil
}

// Upsert creates or updates settings for a tenant
func (r *SettingsRepository) Upsert(ctx context.Context, settings *models.IAMSettings) error {
	query := `
		INSERT INTO iam_settings (
			tenant_id, hr_ldap_enabled, hr_ldap_server, hr_ldap_port, hr_ldap_use_tls,
			hr_ldap_bind_dn, hr_ldap_bind_password, hr_ldap_base_dn, hr_ldap_user_filter,
			hr_ldap_group_base_dn, hr_ldap_group_filter,
			abac_enabled, abac_fallback_rbac, role_expiration_enabled, updated_by
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
		ON CONFLICT (tenant_id) DO UPDATE SET
			hr_ldap_enabled = EXCLUDED.hr_ldap_enabled,
			hr_ldap_server = EXCLUDED.hr_ldap_server,
			hr_ldap_port = EXCLUDED.hr_ldap_port,
			hr_ldap_use_tls = EXCLUDED.hr_ldap_use_tls,
			hr_ldap_bind_dn = EXCLUDED.hr_ldap_bind_dn,
			hr_ldap_bind_password = CASE
				WHEN EXCLUDED.hr_ldap_bind_password = '' THEN iam_settings.hr_ldap_bind_password
				ELSE EXCLUDED.hr_ldap_bind_password
			END,
			hr_ldap_base_dn = EXCLUDED.hr_ldap_base_dn,
			hr_ldap_user_filter = EXCLUDED.hr_ldap_user_filter,
			hr_ldap_group_base_dn = EXCLUDED.hr_ldap_group_base_dn,
			hr_ldap_group_filter = EXCLUDED.hr_ldap_group_filter,
			abac_enabled = EXCLUDED.abac_enabled,
			abac_fallback_rbac = EXCLUDED.abac_fallback_rbac,
			role_expiration_enabled = EXCLUDED.role_expiration_enabled,
			updated_at = CURRENT_TIMESTAMP,
			updated_by = EXCLUDED.updated_by
		RETURNING id
	`

	return r.pool.QueryRow(ctx, query,
		settings.TenantID,
		settings.HRLDAPEnabled,
		settings.HRLDAPServer,
		settings.HRLDAPPort,
		settings.HRLDAPUseTLS,
		settings.HRLDAPBindDN,
		settings.HRLDAPBindPassword,
		settings.HRLDAPBaseDN,
		settings.HRLDAPUserFilter,
		settings.HRLDAPGroupBaseDN,
		settings.HRLDAPGroupFilter,
		settings.ABACEnabled,
		settings.ABACFallbackRBAC,
		settings.RoleExpirationEnabled,
		settings.UpdatedBy,
	).Scan(&settings.ID)
}

// GetDefaultSettings returns settings for the default tenant
func (r *SettingsRepository) GetDefaultSettings(ctx context.Context) (*models.IAMSettings, error) {
	return r.GetByTenantID(ctx, models.WellKnownTenantDefaultID)
}
