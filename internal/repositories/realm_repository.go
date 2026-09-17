// SPDX-License-Identifier: AGPL-3.0-or-later

package repositories

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

// RealmRepository handles database operations for realms
// NOTE: This repository uses the Control Plane database, not the Data Plane
type RealmRepository struct {
	db DBPool // Control Plane database connection
}

// NewRealmRepository creates a new realm repository
func NewRealmRepository(controlPlaneDB *pgxpool.Pool) *RealmRepository {
	return &RealmRepository{db: controlPlaneDB}
}

// ==================== Realm CRUD ====================

// Create creates a new realm
func (r *RealmRepository) Create(ctx context.Context, realm *models.Realm) error {
	query := `
		INSERT INTO realms (
			id, slug, display_name, type, status, settings, branding, features,
			max_tenants, max_users_per_tenant, max_total_users, created_by
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
		RETURNING created_at, updated_at
	`

	err := r.db.QueryRow(ctx, query,
		realm.ID,
		realm.Slug,
		realm.DisplayName,
		realm.Type,
		realm.Status,
		realm.Settings,
		realm.Branding,
		realm.Features,
		realm.MaxTenants,
		realm.MaxUsersPerTenant,
		realm.MaxTotalUsers,
		realm.CreatedBy,
	).Scan(&realm.CreatedAt, &realm.UpdatedAt)
	if err != nil {
		if strings.Contains(err.Error(), "realms_slug_key") {
			return fmt.Errorf("realm with slug '%s' already exists", realm.Slug)
		}
		return fmt.Errorf("failed to create realm: %w", err)
	}

	return nil
}

// GetByID retrieves a realm by its ID
func (r *RealmRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.Realm, error) {
	query := `
		SELECT r.id, r.slug, r.display_name, r.type, r.status,
			   r.database_connection_id, r.schema_name, r.settings, r.branding, r.features,
			   r.max_tenants, r.max_users_per_tenant, r.max_total_users,
			   r.created_at, r.updated_at, r.created_by,
			   COALESCE((SELECT COUNT(*) FROM realm_tenants WHERE realm_id = r.id), 0) AS tenant_count,
			   0 AS user_count
		FROM realms r
		WHERE r.id = $1
	`

	realm := &models.Realm{}
	err := r.db.QueryRow(ctx, query, id).Scan(
		&realm.ID, &realm.Slug, &realm.DisplayName, &realm.Type, &realm.Status,
		&realm.DatabaseConnectionID, &realm.SchemaName, &realm.Settings, &realm.Branding, &realm.Features,
		&realm.MaxTenants, &realm.MaxUsersPerTenant, &realm.MaxTotalUsers,
		&realm.CreatedAt, &realm.UpdatedAt, &realm.CreatedBy,
		&realm.TenantCount,
		&realm.UserCount,
	)

	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get realm: %w", err)
	}

	return realm, nil
}

// GetBySlug retrieves a realm by its slug
func (r *RealmRepository) GetBySlug(ctx context.Context, slug string) (*models.Realm, error) {
	query := `
		SELECT r.id, r.slug, r.display_name, r.type, r.status,
			   r.database_connection_id, r.schema_name, r.settings, r.branding, r.features,
			   r.max_tenants, r.max_users_per_tenant, r.max_total_users,
			   r.created_at, r.updated_at, r.created_by,
			   COALESCE((SELECT COUNT(*) FROM realm_tenants WHERE realm_id = r.id), 0) AS tenant_count,
			   0 AS user_count
		FROM realms r
		WHERE r.slug = $1
	`

	realm := &models.Realm{}
	err := r.db.QueryRow(ctx, query, slug).Scan(
		&realm.ID, &realm.Slug, &realm.DisplayName, &realm.Type, &realm.Status,
		&realm.DatabaseConnectionID, &realm.SchemaName, &realm.Settings, &realm.Branding, &realm.Features,
		&realm.MaxTenants, &realm.MaxUsersPerTenant, &realm.MaxTotalUsers,
		&realm.CreatedAt, &realm.UpdatedAt, &realm.CreatedBy,
		&realm.TenantCount,
		&realm.UserCount,
	)

	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get realm by slug: %w", err)
	}

	return realm, nil
}

// Update updates a realm.
//
// IMPORTANT: this is a write-all-columns UPDATE — every field on the
// inbound struct is written unconditionally. Callers MUST load the
// full row via GetByID first; passing a partial struct will wipe
// other columns. See user_repository.go:Update for the durable
// repository-layer guard and history of this class of bug.
func (r *RealmRepository) Update(ctx context.Context, realm *models.Realm) error {
	query := `
		UPDATE realms SET
			display_name = $2,
			settings = $3,
			branding = $4,
			features = $5,
			max_tenants = $6,
			max_users_per_tenant = $7,
			max_total_users = $8,
			updated_at = NOW()
		WHERE id = $1
		RETURNING updated_at
	`

	err := r.db.QueryRow(ctx, query,
		realm.ID,
		realm.DisplayName,
		realm.Settings,
		realm.Branding,
		realm.Features,
		realm.MaxTenants,
		realm.MaxUsersPerTenant,
		realm.MaxTotalUsers,
	).Scan(&realm.UpdatedAt)

	if errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("realm not found")
	}
	if err != nil {
		return fmt.Errorf("failed to update realm: %w", err)
	}

	return nil
}

// UpdateStatus updates a realm's status
func (r *RealmRepository) UpdateStatus(ctx context.Context, id uuid.UUID, status models.RealmStatus) error {
	query := `UPDATE realms SET status = $2, updated_at = NOW() WHERE id = $1`
	result, err := r.db.Exec(ctx, query, id, status)
	if err != nil {
		return fmt.Errorf("failed to update realm status: %w", err)
	}
	if result.RowsAffected() == 0 {
		return fmt.Errorf("realm not found")
	}
	return nil
}

// Delete performs a soft delete (archive) of a realm
func (r *RealmRepository) Delete(ctx context.Context, id uuid.UUID) error {
	return r.UpdateStatus(ctx, id, models.RealmStatusArchived)
}

// List retrieves a paginated list of realms with optional filters
func (r *RealmRepository) List(ctx context.Context, filters RealmFilters) ([]models.Realm, int64, error) {
	var conditions []string
	var args []interface{}
	argNum := 1

	// Build WHERE conditions
	if filters.Type != nil {
		conditions = append(conditions, fmt.Sprintf("r.type = $%d", argNum))
		args = append(args, *filters.Type)
		argNum++
	}

	if filters.Status != nil {
		conditions = append(conditions, fmt.Sprintf("r.status = $%d", argNum))
		args = append(args, *filters.Status)
		argNum++
	} else {
		// Default: exclude archived
		conditions = append(conditions, "r.status != 'archived'")
	}

	if filters.Search != "" {
		conditions = append(conditions, fmt.Sprintf("(r.slug ILIKE $%d OR r.display_name ILIKE $%d)", argNum, argNum))
		args = append(args, "%"+filters.Search+"%")
		argNum++
	}

	whereClause := ""
	if len(conditions) > 0 {
		whereClause = "WHERE " + strings.Join(conditions, " AND ")
	}

	// Count total
	countQuery := fmt.Sprintf(`SELECT COUNT(*) FROM realms r %s`, whereClause)
	var total int64
	if err := r.db.QueryRow(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("failed to count realms: %w", err)
	}

	// Get paginated results
	offset := (filters.Page - 1) * filters.PageSize
	query := fmt.Sprintf(`
		SELECT r.id, r.slug, r.display_name, r.type, r.status,
			   r.database_connection_id, r.schema_name, r.settings, r.branding, r.features,
			   r.max_tenants, r.max_users_per_tenant, r.max_total_users,
			   r.created_at, r.updated_at, r.created_by,
			   COALESCE((SELECT COUNT(*) FROM realm_tenants WHERE realm_id = r.id), 0) AS tenant_count,
			   0 AS user_count
		FROM realms r
		%s
		ORDER BY r.created_at DESC
		LIMIT $%d OFFSET $%d
	`, whereClause, argNum, argNum+1)

	args = append(args, filters.PageSize, offset)

	rows, err := r.db.Query(ctx, query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list realms: %w", err)
	}
	defer rows.Close()

	var realms []models.Realm
	for rows.Next() {
		var realm models.Realm
		err := rows.Scan(
			&realm.ID, &realm.Slug, &realm.DisplayName, &realm.Type, &realm.Status,
			&realm.DatabaseConnectionID, &realm.SchemaName, &realm.Settings, &realm.Branding, &realm.Features,
			&realm.MaxTenants, &realm.MaxUsersPerTenant, &realm.MaxTotalUsers,
			&realm.CreatedAt, &realm.UpdatedAt, &realm.CreatedBy,
			&realm.TenantCount,
			&realm.UserCount,
		)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to scan realm: %w", err)
		}
		realms = append(realms, realm)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("List: rows iteration: %w", err)
	}

	return realms, total, nil
}

// RealmFilters represents filters for listing realms
type RealmFilters struct {
	Type     *models.RealmType
	Status   *models.RealmStatus
	Search   string
	Page     int
	PageSize int
}

// ==================== Security Policy ====================

// GetSecurityPolicy retrieves the security policy for a realm
func (r *RealmRepository) GetSecurityPolicy(ctx context.Context, realmID uuid.UUID) (*models.RealmSecurityPolicy, error) {
	query := `
		SELECT id, realm_id,
			   password_min_length, password_max_length, password_require_uppercase,
			   password_require_lowercase, password_require_digits, password_require_special,
			   password_special_chars, password_max_age_days, password_history_count, password_min_age_hours,
			   mfa_required, mfa_required_for_admins, mfa_methods, mfa_grace_period_days, mfa_remember_device_days,
			   mfa_enrollment_max_skips,
			   session_max_lifetime_hours, session_idle_timeout_minutes, session_absolute_timeout_hours,
			   concurrent_sessions_limit, single_session_per_device,
			   refresh_token_rotation_grace_seconds,
			   max_failed_attempts, lockout_duration_minutes, lockout_threshold_window_minutes, progressive_lockout,
			   ip_whitelist, ip_blacklist, geo_restrictions,
			   risk_authentication_enabled, risk_threshold_low, risk_threshold_medium, risk_threshold_high,
			   audit_retention_days, audit_log_failed_logins, audit_log_successful_logins, audit_log_admin_actions,
			   created_at, updated_at
		FROM realm_security_policies
		WHERE realm_id = $1
	`

	policy := &models.RealmSecurityPolicy{}
	err := r.db.QueryRow(ctx, query, realmID).Scan(
		&policy.ID, &policy.RealmID,
		&policy.PasswordMinLength, &policy.PasswordMaxLength, &policy.PasswordRequireUppercase,
		&policy.PasswordRequireLowercase, &policy.PasswordRequireDigits, &policy.PasswordRequireSpecial,
		&policy.PasswordSpecialChars, &policy.PasswordMaxAgeDays, &policy.PasswordHistoryCount, &policy.PasswordMinAgeHours,
		&policy.MFARequired, &policy.MFARequiredForAdmins, &policy.MFAMethods, &policy.MFAGracePeriodDays, &policy.MFARememberDeviceDays,
		&policy.MFAEnrollmentMaxSkips,
		&policy.SessionMaxLifetimeHours, &policy.SessionIdleTimeoutMinutes, &policy.SessionAbsoluteTimeoutHours,
		&policy.ConcurrentSessionsLimit, &policy.SingleSessionPerDevice,
		&policy.RefreshTokenRotationGraceSeconds,
		&policy.MaxFailedAttempts, &policy.LockoutDurationMinutes, &policy.LockoutThresholdWindowMinutes, &policy.ProgressiveLockout,
		&policy.IPWhitelist, &policy.IPBlacklist, &policy.GeoRestrictions,
		&policy.RiskAuthenticationEnabled, &policy.RiskThresholdLow, &policy.RiskThresholdMedium, &policy.RiskThresholdHigh,
		&policy.AuditRetentionDays, &policy.AuditLogFailedLogins, &policy.AuditLogSuccessfulLogins, &policy.AuditLogAdminActions,
		&policy.CreatedAt, &policy.UpdatedAt,
	)

	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get security policy: %w", err)
	}

	return policy, nil
}

// CreateSecurityPolicy creates a security policy for a realm
func (r *RealmRepository) CreateSecurityPolicy(ctx context.Context, policy *models.RealmSecurityPolicy) error {
	query := `INSERT INTO realm_security_policies (realm_id) VALUES ($1) RETURNING id, created_at, updated_at`
	err := r.db.QueryRow(ctx, query, policy.RealmID).Scan(&policy.ID, &policy.CreatedAt, &policy.UpdatedAt)
	if err != nil {
		return fmt.Errorf("failed to create security policy: %w", err)
	}
	return nil
}

// UpdateSecurityPolicy updates a realm's security policy
func (r *RealmRepository) UpdateSecurityPolicy(ctx context.Context, policy *models.RealmSecurityPolicy) error {
	query := `
		UPDATE realm_security_policies SET
			password_min_length = $2, password_max_length = $3,
			password_require_uppercase = $4, password_require_lowercase = $5,
			password_require_digits = $6, password_require_special = $7,
			password_special_chars = $8, password_max_age_days = $9, password_history_count = $10,
			mfa_required = $11, mfa_required_for_admins = $12, mfa_methods = $13,
			mfa_grace_period_days = $14, mfa_remember_device_days = $15,
			mfa_enrollment_max_skips = $16,
			session_max_lifetime_hours = $17, session_idle_timeout_minutes = $18,
			concurrent_sessions_limit = $19, single_session_per_device = $20,
			max_failed_attempts = $21, lockout_duration_minutes = $22, progressive_lockout = $23,
			ip_whitelist = $24, ip_blacklist = $25,
			updated_at = NOW()
		WHERE realm_id = $1
		RETURNING updated_at
	`

	err := r.db.QueryRow(ctx, query,
		policy.RealmID,
		policy.PasswordMinLength, policy.PasswordMaxLength,
		policy.PasswordRequireUppercase, policy.PasswordRequireLowercase,
		policy.PasswordRequireDigits, policy.PasswordRequireSpecial,
		policy.PasswordSpecialChars, policy.PasswordMaxAgeDays, policy.PasswordHistoryCount,
		policy.MFARequired, policy.MFARequiredForAdmins, policy.MFAMethods,
		policy.MFAGracePeriodDays, policy.MFARememberDeviceDays,
		policy.MFAEnrollmentMaxSkips,
		policy.SessionMaxLifetimeHours, policy.SessionIdleTimeoutMinutes,
		policy.ConcurrentSessionsLimit, policy.SingleSessionPerDevice,
		policy.MaxFailedAttempts, policy.LockoutDurationMinutes, policy.ProgressiveLockout,
		policy.IPWhitelist, policy.IPBlacklist,
	).Scan(&policy.UpdatedAt)

	if errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("security policy not found")
	}
	if err != nil {
		return fmt.Errorf("failed to update security policy: %w", err)
	}

	return nil
}

// ==================== Identity Providers ====================

// CreateIdentityProvider creates a new identity provider for a realm
func (r *RealmRepository) CreateIdentityProvider(ctx context.Context, idp *models.RealmIdentityProvider) error {
	query := `
		INSERT INTO realm_identity_providers (
			id, realm_id, name, display_name, type, is_enabled, is_default, priority,
			config, attribute_mapping, sync_enabled, sync_interval_minutes,
			auto_provision_users, auto_update_users, auto_deactivate_users
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
		RETURNING created_at, updated_at
	`

	err := r.db.QueryRow(ctx, query,
		idp.ID, idp.RealmID, idp.Name, idp.DisplayName, idp.Type,
		idp.IsEnabled, idp.IsDefault, idp.Priority,
		idp.Config, idp.AttributeMapping, idp.SyncEnabled, idp.SyncInterval,
		idp.AutoProvisionUsers, idp.AutoUpdateUsers, idp.AutoDeactivateUsers,
	).Scan(&idp.CreatedAt, &idp.UpdatedAt)
	if err != nil {
		if strings.Contains(err.Error(), "realm_idp_unique_name") {
			return fmt.Errorf("identity provider with name '%s' already exists in this realm", idp.Name)
		}
		return fmt.Errorf("failed to create identity provider: %w", err)
	}

	return nil
}

// GetIdentityProviderByID retrieves an identity provider by ID
func (r *RealmRepository) GetIdentityProviderByID(ctx context.Context, id uuid.UUID) (*models.RealmIdentityProvider, error) {
	query := `
		SELECT id, realm_id, name, display_name, type, is_enabled, is_default, priority,
			   config, attribute_mapping, sync_enabled, sync_interval_minutes,
			   last_sync_at, last_sync_status, last_sync_message,
			   auto_provision_users, auto_update_users, auto_deactivate_users,
			   created_at, updated_at
		FROM realm_identity_providers
		WHERE id = $1
	`

	idp := &models.RealmIdentityProvider{}
	err := r.db.QueryRow(ctx, query, id).Scan(
		&idp.ID, &idp.RealmID, &idp.Name, &idp.DisplayName, &idp.Type,
		&idp.IsEnabled, &idp.IsDefault, &idp.Priority,
		&idp.Config, &idp.AttributeMapping, &idp.SyncEnabled, &idp.SyncInterval,
		&idp.LastSyncAt, &idp.LastSyncStatus, &idp.LastSyncMessage,
		&idp.AutoProvisionUsers, &idp.AutoUpdateUsers, &idp.AutoDeactivateUsers,
		&idp.CreatedAt, &idp.UpdatedAt,
	)

	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get identity provider: %w", err)
	}

	return idp, nil
}

// GetIdentityProvider retrieves an identity provider by ID (alias for GetIdentityProviderByID)
func (r *RealmRepository) GetIdentityProvider(ctx context.Context, id uuid.UUID) (*models.RealmIdentityProvider, error) {
	return r.GetIdentityProviderByID(ctx, id)
}

// ListIdentityProviders lists identity providers for a realm
func (r *RealmRepository) ListIdentityProviders(ctx context.Context, realmID uuid.UUID) ([]models.RealmIdentityProvider, error) {
	query := `
		SELECT id, realm_id, name, display_name, type, is_enabled, is_default, priority,
			   config, attribute_mapping, sync_enabled, sync_interval_minutes,
			   last_sync_at, last_sync_status, last_sync_message,
			   auto_provision_users, auto_update_users, auto_deactivate_users,
			   created_at, updated_at
		FROM realm_identity_providers
		WHERE realm_id = $1
		ORDER BY priority ASC, created_at ASC
	`

	rows, err := r.db.Query(ctx, query, realmID)
	if err != nil {
		return nil, fmt.Errorf("failed to list identity providers: %w", err)
	}
	defer rows.Close()

	var providers []models.RealmIdentityProvider
	for rows.Next() {
		var idp models.RealmIdentityProvider
		err := rows.Scan(
			&idp.ID, &idp.RealmID, &idp.Name, &idp.DisplayName, &idp.Type,
			&idp.IsEnabled, &idp.IsDefault, &idp.Priority,
			&idp.Config, &idp.AttributeMapping, &idp.SyncEnabled, &idp.SyncInterval,
			&idp.LastSyncAt, &idp.LastSyncStatus, &idp.LastSyncMessage,
			&idp.AutoProvisionUsers, &idp.AutoUpdateUsers, &idp.AutoDeactivateUsers,
			&idp.CreatedAt, &idp.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan identity provider: %w", err)
		}
		providers = append(providers, idp)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("ListIdentityProviders: rows iteration: %w", err)
	}

	return providers, nil
}

// UpdateIdentityProvider updates an identity provider
func (r *RealmRepository) UpdateIdentityProvider(ctx context.Context, idp *models.RealmIdentityProvider) error {
	query := `
		UPDATE realm_identity_providers SET
			display_name = $2, is_enabled = $3, is_default = $4, priority = $5,
			config = $6, attribute_mapping = $7, sync_enabled = $8, sync_interval_minutes = $9,
			auto_provision_users = $10, auto_update_users = $11, auto_deactivate_users = $12,
			updated_at = NOW()
		WHERE id = $1
		RETURNING updated_at
	`

	err := r.db.QueryRow(ctx, query,
		idp.ID, idp.DisplayName, idp.IsEnabled, idp.IsDefault, idp.Priority,
		idp.Config, idp.AttributeMapping, idp.SyncEnabled, idp.SyncInterval,
		idp.AutoProvisionUsers, idp.AutoUpdateUsers, idp.AutoDeactivateUsers,
	).Scan(&idp.UpdatedAt)

	if errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("identity provider not found")
	}
	if err != nil {
		return fmt.Errorf("failed to update identity provider: %w", err)
	}

	return nil
}

// DeleteIdentityProvider deletes an identity provider
func (r *RealmRepository) DeleteIdentityProvider(ctx context.Context, id uuid.UUID) error {
	query := `DELETE FROM realm_identity_providers WHERE id = $1`
	result, err := r.db.Exec(ctx, query, id)
	if err != nil {
		return fmt.Errorf("failed to delete identity provider: %w", err)
	}
	if result.RowsAffected() == 0 {
		return fmt.Errorf("identity provider not found")
	}
	return nil
}

// ListTenantIdentityProviders returns all iam_identity_providers for tenants in this realm.
// Used by platform-admin to show tenant IDP configs in the realm context.
func (r *RealmRepository) ListTenantIdentityProviders(ctx context.Context, realmID uuid.UUID) ([]models.TenantIdentityProviderSummary, error) {
	query := `
		SELECT ip.id, ip.tenant_id, t.name, t.slug,
		       ip.provider_type, ip.provider_name, ip.display_name,
		       ip.is_active, ip.priority, ip.created_at, ip.updated_at
		FROM iam_identity_providers ip
		JOIN realm_tenants rt ON ip.tenant_id = rt.tenant_id
		JOIN iam_tenants t ON ip.tenant_id = t.id
		WHERE rt.realm_id = $1
		ORDER BY t.name ASC, ip.priority DESC, ip.provider_name ASC
	`

	rows, err := r.db.Query(ctx, query, realmID)
	if err != nil {
		return nil, fmt.Errorf("failed to list tenant identity providers: %w", err)
	}
	defer rows.Close()

	var providers []models.TenantIdentityProviderSummary
	for rows.Next() {
		var p models.TenantIdentityProviderSummary
		err := rows.Scan(
			&p.ID, &p.TenantID, &p.TenantName, &p.TenantSlug,
			&p.Type, &p.Name, &p.DisplayName,
			&p.IsEnabled, &p.Priority, &p.CreatedAt, &p.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan tenant identity provider: %w", err)
		}
		providers = append(providers, p)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("ListTenantIdentityProviders: rows iteration: %w", err)
	}

	return providers, nil
}

// Tenant mapping, admin assignments, audit logging, domains, helpers,
// and user-facing methods are in realm_repository_admin.go
