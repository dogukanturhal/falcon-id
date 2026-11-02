// SPDX-License-Identifier: AGPL-3.0-or-later

package repositories

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

const msgDomainNotFound = "domain not found"

// ==================== Tenant Mapping ====================

// AssignTenant assigns a tenant to a realm.
//
// NOTE on `assigned_by`: the underlying SchemaDefinition
// (falcon-id-control-public-desired) does NOT declare an `assigned_by`
// column on `realm_tenants` — the column is in the Go struct + this
// query but missing from the live keystone-managed table (verified live
// 2026-05-07: `column "assigned_by" of relation "realm_tenants" does
// not exist`). This is repo-vs-SD drift slated for reconciliation in a
// follow-up MR. Until then, this query fails at runtime when called.
// Callers that need a runtime-safe path should use EnsureRealmTenant
// (below), which is scoped to the columns the live SD currently
// declares.
func (r *RealmRepository) AssignTenant(ctx context.Context, realmID, tenantID uuid.UUID, assignedBy *uuid.UUID) error {
	query := `
		INSERT INTO realm_tenants (realm_id, tenant_id, assigned_by)
		VALUES ($1, $2, $3)
		ON CONFLICT (tenant_id) DO UPDATE SET
			realm_id = $1,
			previous_realm_id = realm_tenants.realm_id,
			migrated_at = NOW(),
			assigned_by = $3
	`

	_, err := r.db.Exec(ctx, query, realmID, tenantID, assignedBy)
	if err != nil {
		return fmt.Errorf("failed to assign tenant to realm: %w", err)
	}

	return nil
}

// EnsureRealmTenant idempotently inserts a (realm_id, tenant_id)
// mapping into realm_tenants, scoped to the columns the live keystone
// SchemaDefinition declares (no `assigned_by`, no migration-history
// fields). Used by cmd/realm_tenant_bootstrap.go.
//
// ON CONFLICT (tenant_id) DO NOTHING — first-write-wins. Operator-
// driven re-mappings should go through services.RealmService.AssignTenant
// once the SD reconciliation lands; this helper is bootstrap-seed only.
func (r *RealmRepository) EnsureRealmTenant(ctx context.Context, realmID, tenantID uuid.UUID) error {
	query := `
		INSERT INTO realm_tenants (realm_id, tenant_id)
		VALUES ($1, $2)
		ON CONFLICT (tenant_id) DO NOTHING
	`
	_, err := r.db.Exec(ctx, query, realmID, tenantID)
	if err != nil {
		return fmt.Errorf("EnsureRealmTenant: %w", err)
	}
	return nil
}

// GetTenantRealm gets the realm for a tenant
func (r *RealmRepository) GetTenantRealm(ctx context.Context, tenantID uuid.UUID) (*models.Realm, error) {
	query := `
		SELECT r.id, r.slug, r.display_name, r.type, r.status,
			   r.database_connection_id, r.schema_name, r.settings, r.branding, r.features,
			   r.max_tenants, r.max_users_per_tenant, r.max_total_users,
			   r.created_at, r.updated_at, r.created_by
		FROM realms r
		JOIN realm_tenants rt ON r.id = rt.realm_id
		WHERE rt.tenant_id = $1
	`

	realm := &models.Realm{}
	err := r.db.QueryRow(ctx, query, tenantID).Scan(
		&realm.ID, &realm.Slug, &realm.DisplayName, &realm.Type, &realm.Status,
		&realm.DatabaseConnectionID, &realm.SchemaName, &realm.Settings, &realm.Branding, &realm.Features,
		&realm.MaxTenants, &realm.MaxUsersPerTenant, &realm.MaxTotalUsers,
		&realm.CreatedAt, &realm.UpdatedAt, &realm.CreatedBy,
	)

	if errors.Is(err, pgx.ErrNoRows) {
		// Return default realm if tenant has no explicit assignment
		return r.GetByID(ctx, models.DefaultRealmID)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get tenant realm: %w", err)
	}

	return realm, nil
}

// ListRealmTenants lists all tenants in a realm
func (r *RealmRepository) ListRealmTenants(ctx context.Context, realmID uuid.UUID) ([]models.RealmTenant, error) {
	query := `
		SELECT realm_id, tenant_id, assigned_at, assigned_by, previous_realm_id, migrated_at
		FROM realm_tenants
		WHERE realm_id = $1
		ORDER BY assigned_at DESC
	`

	rows, err := r.db.Query(ctx, query, realmID)
	if err != nil {
		return nil, fmt.Errorf("failed to list realm tenants: %w", err)
	}
	defer rows.Close()

	var tenants []models.RealmTenant
	for rows.Next() {
		var t models.RealmTenant
		err := rows.Scan(&t.RealmID, &t.TenantID, &t.AssignedAt, &t.AssignedBy, &t.PreviousRealmID, &t.MigratedAt)
		if err != nil {
			return nil, fmt.Errorf("failed to scan realm tenant: %w", err)
		}
		tenants = append(tenants, t)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("ListRealmTenants: rows iteration: %w", err)
	}

	return tenants, nil
}

// RemoveTenant removes a tenant from a realm (assigns to default)
func (r *RealmRepository) RemoveTenant(ctx context.Context, _, tenantID uuid.UUID) error {
	// Move tenant to default realm instead of deleting
	return r.AssignTenant(ctx, models.DefaultRealmID, tenantID, nil)
}

// ==================== Admin Assignments ====================

// AssignAdmin assigns a platform admin to a realm
func (r *RealmRepository) AssignAdmin(ctx context.Context, assignment *models.RealmAdminAssignment) error {
	query := `
		INSERT INTO realm_admin_assignments (
			id, realm_id, admin_id, role, permissions, allowed_tenant_ids, created_by
		) VALUES ($1, $2, $3, $4, $5, $6, $7)
		ON CONFLICT (realm_id, admin_id) DO UPDATE SET
			role = $4,
			permissions = $5,
			allowed_tenant_ids = $6
		RETURNING created_at
	`

	err := r.db.QueryRow(ctx, query,
		assignment.ID, assignment.RealmID, assignment.AdminID, assignment.Role,
		assignment.Permissions, assignment.AllowedTenantIDs, assignment.CreatedBy,
	).Scan(&assignment.CreatedAt)
	if err != nil {
		return fmt.Errorf("failed to assign admin to realm: %w", err)
	}

	return nil
}

// ListRealmAdmins lists all admin assignments for a realm
func (r *RealmRepository) ListRealmAdmins(ctx context.Context, realmID uuid.UUID) ([]models.RealmAdminAssignment, error) {
	query := `
		SELECT id, realm_id, admin_id, role, permissions, allowed_tenant_ids, created_at, created_by
		FROM realm_admin_assignments
		WHERE realm_id = $1
		ORDER BY created_at DESC
	`

	rows, err := r.db.Query(ctx, query, realmID)
	if err != nil {
		return nil, fmt.Errorf("failed to list realm admins: %w", err)
	}
	defer rows.Close()

	var assignments []models.RealmAdminAssignment
	for rows.Next() {
		var a models.RealmAdminAssignment
		err := rows.Scan(&a.ID, &a.RealmID, &a.AdminID, &a.Role, &a.Permissions, &a.AllowedTenantIDs, &a.CreatedAt, &a.CreatedBy)
		if err != nil {
			return nil, fmt.Errorf("failed to scan admin assignment: %w", err)
		}
		assignments = append(assignments, a)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("ListRealmAdmins: rows iteration: %w", err)
	}

	return assignments, nil
}

// GetAdminRealms lists all realms an admin has access to
func (r *RealmRepository) GetAdminRealms(ctx context.Context, adminID uuid.UUID) ([]models.RealmAdminAssignment, error) {
	query := `
		SELECT id, realm_id, admin_id, role, permissions, allowed_tenant_ids, created_at, created_by
		FROM realm_admin_assignments
		WHERE admin_id = $1
		ORDER BY created_at DESC
	`

	rows, err := r.db.Query(ctx, query, adminID)
	if err != nil {
		return nil, fmt.Errorf("failed to get admin realms: %w", err)
	}
	defer rows.Close()

	var assignments []models.RealmAdminAssignment
	for rows.Next() {
		var a models.RealmAdminAssignment
		err := rows.Scan(&a.ID, &a.RealmID, &a.AdminID, &a.Role, &a.Permissions, &a.AllowedTenantIDs, &a.CreatedAt, &a.CreatedBy)
		if err != nil {
			return nil, fmt.Errorf("failed to scan admin assignment: %w", err)
		}
		assignments = append(assignments, a)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("GetAdminRealms: rows iteration: %w", err)
	}

	return assignments, nil
}

// RemoveAdmin removes an admin from a realm
func (r *RealmRepository) RemoveAdmin(ctx context.Context, realmID, adminID uuid.UUID) error {
	query := `DELETE FROM realm_admin_assignments WHERE realm_id = $1 AND admin_id = $2`
	result, err := r.db.Exec(ctx, query, realmID, adminID)
	if err != nil {
		return fmt.Errorf("failed to remove admin from realm: %w", err)
	}
	if result.RowsAffected() == 0 {
		return fmt.Errorf("admin assignment not found")
	}
	return nil
}

// ==================== Audit Logging ====================

// LogAudit creates an audit log entry for realm operations
func (r *RealmRepository) LogAudit(ctx context.Context, log *models.RealmAuditLog) error {
	query := `
		INSERT INTO realm_audit_log (
			realm_id, admin_id, admin_email, action, action_category,
			target_type, target_id, tenant_id, request_ip, user_agent,
			request_method, request_path, details, previous_value, new_value
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
	`

	_, err := r.db.Exec(ctx, query,
		log.RealmID, log.AdminID, log.AdminEmail, log.Action, log.ActionCategory,
		log.TargetType, log.TargetID, log.TenantID, log.RequestIP, log.UserAgent,
		log.RequestMethod, log.RequestPath, log.Details, log.PreviousValue, log.NewValue,
	)
	if err != nil {
		return fmt.Errorf("failed to log realm audit: %w", err)
	}

	return nil
}

// ListAuditLogs lists audit logs for a realm
func (r *RealmRepository) ListAuditLogs(ctx context.Context, realmID uuid.UUID, filters AuditLogFilters) ([]models.RealmAuditLog, int64, error) {
	var conditions []string
	var args []interface{}
	conditions = append(conditions, "realm_id = $1")
	args = append(args, realmID)
	argNum := 2

	if filters.Action != "" {
		conditions = append(conditions, fmt.Sprintf("action = $%d", argNum))
		args = append(args, filters.Action)
		argNum++
	}

	if filters.ActionCategory != "" {
		conditions = append(conditions, fmt.Sprintf("action_category = $%d", argNum))
		args = append(args, filters.ActionCategory)
		argNum++
	}

	if filters.AdminID != nil {
		conditions = append(conditions, fmt.Sprintf("admin_id = $%d", argNum))
		args = append(args, *filters.AdminID)
		argNum++
	}

	whereClause := strings.Join(conditions, " AND ")

	// Count total
	countQuery := fmt.Sprintf(`SELECT COUNT(*) FROM realm_audit_log WHERE %s`, whereClause)
	var total int64
	if err := r.db.QueryRow(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("failed to count audit logs: %w", err)
	}

	// Get paginated results
	offset := (filters.Page - 1) * filters.PageSize
	query := fmt.Sprintf(`
		SELECT id, realm_id, admin_id, admin_email, action, action_category,
			   target_type, target_id, tenant_id, request_ip, user_agent,
			   request_method, request_path, details, previous_value, new_value, created_at
		FROM realm_audit_log
		WHERE %s
		ORDER BY created_at DESC
		LIMIT $%d OFFSET $%d
	`, whereClause, argNum, argNum+1)

	args = append(args, filters.PageSize, offset)

	rows, err := r.db.Query(ctx, query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list audit logs: %w", err)
	}
	defer rows.Close()

	var logs []models.RealmAuditLog
	for rows.Next() {
		var log models.RealmAuditLog
		err := rows.Scan(
			&log.ID, &log.RealmID, &log.AdminID, &log.AdminEmail, &log.Action, &log.ActionCategory,
			&log.TargetType, &log.TargetID, &log.TenantID, &log.RequestIP, &log.UserAgent,
			&log.RequestMethod, &log.RequestPath, &log.Details, &log.PreviousValue, &log.NewValue, &log.CreatedAt,
		)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to scan audit log: %w", err)
		}
		logs = append(logs, log)
	}

	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("ListAuditLogs: rows iteration: %w", err)
	}

	return logs, total, nil
}

// AuditLogFilters represents filters for listing audit logs
type AuditLogFilters struct {
	Action         string
	ActionCategory string
	AdminID        *uuid.UUID
	Page           int
	PageSize       int
}

// ==================== Domains ====================

// CreateDomain creates a custom domain mapping for a realm
func (r *RealmRepository) CreateDomain(ctx context.Context, domain *models.RealmDomain) error {
	query := `
		INSERT INTO realm_domains (
			id, realm_id, domain, is_primary, verification_token, verification_method, ssl_enabled
		) VALUES ($1, $2, $3, $4, $5, $6, $7)
		RETURNING created_at, updated_at
	`

	err := r.db.QueryRow(ctx, query,
		domain.ID, domain.RealmID, domain.Domain, domain.IsPrimary,
		domain.VerificationToken, domain.VerificationMethod, domain.SSLEnabled,
	).Scan(&domain.CreatedAt, &domain.UpdatedAt)
	if err != nil {
		if strings.Contains(err.Error(), "realm_domains_domain_key") {
			return fmt.Errorf("domain '%s' is already registered", domain.Domain)
		}
		return fmt.Errorf("failed to create domain: %w", err)
	}

	return nil
}

// GetDomainByName retrieves a domain by its name
func (r *RealmRepository) GetDomainByName(ctx context.Context, domainName string) (*models.RealmDomain, error) {
	query := `
		SELECT id, realm_id, domain, is_primary, is_verified, verification_token,
			   verification_method, verified_at, ssl_enabled, ssl_certificate_expires_at,
			   created_at, updated_at
		FROM realm_domains
		WHERE domain = $1
	`

	domain := &models.RealmDomain{}
	err := r.db.QueryRow(ctx, query, domainName).Scan(
		&domain.ID, &domain.RealmID, &domain.Domain, &domain.IsPrimary, &domain.IsVerified,
		&domain.VerificationToken, &domain.VerificationMethod, &domain.VerifiedAt,
		&domain.SSLEnabled, &domain.SSLCertificateExpiresAt, &domain.CreatedAt, &domain.UpdatedAt,
	)

	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get domain: %w", err)
	}

	return domain, nil
}

// ListRealmDomains lists all domains for a realm
func (r *RealmRepository) ListRealmDomains(ctx context.Context, realmID uuid.UUID) ([]models.RealmDomain, error) {
	query := `
		SELECT id, realm_id, domain, is_primary, is_verified, verification_token,
			   verification_method, verified_at, ssl_enabled, ssl_certificate_expires_at,
			   created_at, updated_at
		FROM realm_domains
		WHERE realm_id = $1
		ORDER BY is_primary DESC, created_at ASC
	`

	rows, err := r.db.Query(ctx, query, realmID)
	if err != nil {
		return nil, fmt.Errorf("failed to list realm domains: %w", err)
	}
	defer rows.Close()

	var domains []models.RealmDomain
	for rows.Next() {
		var d models.RealmDomain
		err := rows.Scan(
			&d.ID, &d.RealmID, &d.Domain, &d.IsPrimary, &d.IsVerified,
			&d.VerificationToken, &d.VerificationMethod, &d.VerifiedAt,
			&d.SSLEnabled, &d.SSLCertificateExpiresAt, &d.CreatedAt, &d.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan domain: %w", err)
		}
		domains = append(domains, d)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("ListRealmDomains: rows iteration: %w", err)
	}

	return domains, nil
}

// GetDomainByID retrieves a domain by its ID
func (r *RealmRepository) GetDomainByID(ctx context.Context, domainID uuid.UUID) (*models.RealmDomain, error) {
	query := `
		SELECT id, realm_id, domain, is_primary, is_verified, verification_token,
			   verification_method, verified_at, ssl_enabled, ssl_certificate_expires_at,
			   created_at, updated_at
		FROM realm_domains
		WHERE id = $1
	`

	domain := &models.RealmDomain{}
	err := r.db.QueryRow(ctx, query, domainID).Scan(
		&domain.ID, &domain.RealmID, &domain.Domain, &domain.IsPrimary, &domain.IsVerified,
		&domain.VerificationToken, &domain.VerificationMethod, &domain.VerifiedAt,
		&domain.SSLEnabled, &domain.SSLCertificateExpiresAt, &domain.CreatedAt, &domain.UpdatedAt,
	)

	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get domain by ID: %w", err)
	}

	return domain, nil
}

// ListDomains lists all domains for a realm (alias for ListRealmDomains)
func (r *RealmRepository) ListDomains(ctx context.Context, realmID uuid.UUID) ([]models.RealmDomain, error) {
	return r.ListRealmDomains(ctx, realmID)
}

// UpdateDomain updates a domain
func (r *RealmRepository) UpdateDomain(ctx context.Context, domain *models.RealmDomain) error {
	query := `
		UPDATE realm_domains SET
			is_primary = $2,
			is_verified = $3,
			verified_at = $4,
			ssl_enabled = $5,
			ssl_certificate_expires_at = $6,
			updated_at = NOW()
		WHERE id = $1
		RETURNING updated_at
	`

	err := r.db.QueryRow(ctx, query,
		domain.ID, domain.IsPrimary, domain.IsVerified, domain.VerifiedAt,
		domain.SSLEnabled, domain.SSLCertificateExpiresAt,
	).Scan(&domain.UpdatedAt)

	if errors.Is(err, pgx.ErrNoRows) {
		return errors.New(msgDomainNotFound)
	}
	if err != nil {
		return fmt.Errorf("failed to update domain: %w", err)
	}

	return nil
}

// SetPrimaryDomain sets a domain as the primary domain for a realm
func (r *RealmRepository) SetPrimaryDomain(ctx context.Context, realmID, domainID uuid.UUID) error {
	// First, unset any existing primary domain for this realm
	_, err := r.db.Exec(ctx,
		`UPDATE realm_domains SET is_primary = false, updated_at = NOW() WHERE realm_id = $1`,
		realmID,
	)
	if err != nil {
		return fmt.Errorf("failed to unset primary domain: %w", err)
	}

	// Set the new primary domain
	result, err := r.db.Exec(ctx,
		`UPDATE realm_domains SET is_primary = true, updated_at = NOW() WHERE id = $1 AND realm_id = $2`,
		domainID, realmID,
	)
	if err != nil {
		return fmt.Errorf("failed to set primary domain: %w", err)
	}
	if result.RowsAffected() == 0 {
		return fmt.Errorf("domain not found in realm")
	}

	return nil
}

// VerifyDomain marks a domain as verified
func (r *RealmRepository) VerifyDomain(ctx context.Context, domainID uuid.UUID) error {
	query := `UPDATE realm_domains SET is_verified = true, verified_at = NOW(), updated_at = NOW() WHERE id = $1`
	result, err := r.db.Exec(ctx, query, domainID)
	if err != nil {
		return fmt.Errorf("failed to verify domain: %w", err)
	}
	if result.RowsAffected() == 0 {
		return errors.New(msgDomainNotFound)
	}
	return nil
}

// DeleteDomain removes a domain mapping
func (r *RealmRepository) DeleteDomain(ctx context.Context, domainID uuid.UUID) error {
	query := `DELETE FROM realm_domains WHERE id = $1`
	result, err := r.db.Exec(ctx, query, domainID)
	if err != nil {
		return fmt.Errorf("failed to delete domain: %w", err)
	}
	if result.RowsAffected() == 0 {
		return errors.New(msgDomainNotFound)
	}
	return nil
}

// GetRealmByDomain retrieves a realm by custom domain
func (r *RealmRepository) GetRealmByDomain(ctx context.Context, domainName string) (*models.Realm, error) {
	query := `
		SELECT r.id, r.slug, r.display_name, r.type, r.status,
			   r.database_connection_id, r.schema_name, r.settings, r.branding, r.features,
			   r.max_tenants, r.max_users_per_tenant, r.max_total_users,
			   r.created_at, r.updated_at, r.created_by
		FROM realms r
		JOIN realm_domains rd ON r.id = rd.realm_id
		WHERE rd.domain = $1 AND rd.is_verified = true
	`

	realm := &models.Realm{}
	err := r.db.QueryRow(ctx, query, domainName).Scan(
		&realm.ID, &realm.Slug, &realm.DisplayName, &realm.Type, &realm.Status,
		&realm.DatabaseConnectionID, &realm.SchemaName, &realm.Settings, &realm.Branding, &realm.Features,
		&realm.MaxTenants, &realm.MaxUsersPerTenant, &realm.MaxTotalUsers,
		&realm.CreatedAt, &realm.UpdatedAt, &realm.CreatedBy,
	)

	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get realm by domain: %w", err)
	}

	return realm, nil
}

// ==================== Helper Methods ====================

// CountTenantsInRealm returns the number of tenants in a realm
func (r *RealmRepository) CountTenantsInRealm(ctx context.Context, realmID uuid.UUID) (int, error) {
	var count int
	err := r.db.QueryRow(ctx, `SELECT COUNT(*) FROM realm_tenants WHERE realm_id = $1`, realmID).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("failed to count tenants: %w", err)
	}
	return count, nil
}

// GetDefaultRealm returns the default shared realm
func (r *RealmRepository) GetDefaultRealm(ctx context.Context) (*models.Realm, error) {
	return r.GetByID(ctx, models.DefaultRealmID)
}

// SlugExists checks if a realm slug already exists
func (r *RealmRepository) SlugExists(ctx context.Context, slug string) (bool, error) {
	var exists bool
	err := r.db.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM realms WHERE slug = $1)`, slug).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("failed to check slug existence: %w", err)
	}
	return exists, nil
}

// ==================== User-facing Methods ====================

// GetUserAvailableRealms returns all realms a user has access to
// This includes:
// 1. The user's primary realm (passed via primaryRealmID from auth context)
// 2. Realms where the user is assigned as an admin (realm_admin_assignments)
func (r *RealmRepository) GetUserAvailableRealms(ctx context.Context, userID uuid.UUID, primaryRealmID uuid.UUID) ([]*models.Realm, error) {
	query := `
		SELECT DISTINCT ON (r.id) r.id, r.slug, r.display_name, r.type, r.status,
			   r.database_connection_id, r.schema_name, r.settings, r.branding, r.features,
			   r.max_tenants, r.max_users_per_tenant, r.max_total_users,
			   r.created_at, r.updated_at, r.created_by
		FROM realms r
		WHERE (
			r.id IN (
				SELECT realm_id FROM realm_admin_assignments WHERE admin_id = $1
			)
			OR r.id = $2
		)
		AND r.status = 'active'
		ORDER BY r.id, r.created_at ASC
	`

	rows, err := r.db.Query(ctx, query, userID, primaryRealmID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user available realms: %w", err)
	}
	defer rows.Close()

	var realms []*models.Realm
	for rows.Next() {
		realm := &models.Realm{}
		err := rows.Scan(
			&realm.ID, &realm.Slug, &realm.DisplayName, &realm.Type, &realm.Status,
			&realm.DatabaseConnectionID, &realm.SchemaName, &realm.Settings, &realm.Branding, &realm.Features,
			&realm.MaxTenants, &realm.MaxUsersPerTenant, &realm.MaxTotalUsers,
			&realm.CreatedAt, &realm.UpdatedAt, &realm.CreatedBy,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan realm: %w", err)
		}
		realms = append(realms, realm)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("GetUserAvailableRealms: rows iteration: %w", err)
	}

	return realms, nil
}

// UserHasRealmAccess checks if a user has access to a specific realm.
// primaryRealmID is the user's current realm (from auth context / JWT),
// so we don't need to query iam_users (which lives on the data-plane DB).
func (r *RealmRepository) UserHasRealmAccess(ctx context.Context, userID, realmID, primaryRealmID uuid.UUID) (bool, error) {
	// Fast path: user is checking access to their own realm
	if realmID == primaryRealmID && primaryRealmID != uuid.Nil {
		return true, nil
	}

	query := `
		SELECT EXISTS(
			SELECT 1 FROM realm_admin_assignments WHERE admin_id = $1 AND realm_id = $2
		)
	`

	var exists bool
	err := r.db.QueryRow(ctx, query, userID, realmID).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("failed to check realm access: %w", err)
	}

	return exists, nil
}

// DeviceWitnessTOTPAllowed reports the realm flag device_witness_totp_allowed
// for the realm the tenant belongs to. A tenant without a realm assignment
// uses the default realm; a missing row defaults to true (the column default).
func (r *RealmRepository) DeviceWitnessTOTPAllowed(ctx context.Context, tenantID uuid.UUID) (bool, error) {
	const q = `
		SELECT r.device_witness_totp_allowed
		FROM realms r
		JOIN realm_tenants rt ON r.id = rt.realm_id
		WHERE rt.tenant_id = $1`
	var allowed bool
	err := r.db.QueryRow(ctx, q, tenantID).Scan(&allowed)
	if errors.Is(err, pgx.ErrNoRows) {
		err = r.db.QueryRow(ctx, `SELECT device_witness_totp_allowed FROM realms WHERE id = $1`, models.DefaultRealmID).Scan(&allowed)
		if errors.Is(err, pgx.ErrNoRows) {
			return true, nil
		}
	}
	if err != nil {
		return false, fmt.Errorf("DeviceWitnessTOTPAllowed: %w", err)
	}
	return allowed, nil
}

// GetDeviceWitnessTOTPAllowedByRealm returns the flag for one realm.
func (r *RealmRepository) GetDeviceWitnessTOTPAllowedByRealm(ctx context.Context, realmID uuid.UUID) (bool, error) {
	var allowed bool
	err := r.db.QueryRow(ctx, `SELECT device_witness_totp_allowed FROM realms WHERE id = $1`, realmID).Scan(&allowed)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, fmt.Errorf("realm not found")
	}
	if err != nil {
		return false, fmt.Errorf("GetDeviceWitnessTOTPAllowedByRealm: %w", err)
	}
	return allowed, nil
}

// SetDeviceWitnessTOTPAllowed updates the flag for one realm.
func (r *RealmRepository) SetDeviceWitnessTOTPAllowed(ctx context.Context, realmID uuid.UUID, allowed bool) error {
	res, err := r.db.Exec(ctx, `UPDATE realms SET device_witness_totp_allowed = $2, updated_at = NOW() WHERE id = $1`, realmID, allowed)
	if err != nil {
		return fmt.Errorf("SetDeviceWitnessTOTPAllowed: %w", err)
	}
	if res.RowsAffected() == 0 {
		return fmt.Errorf("realm not found")
	}
	return nil
}

// SessionAbsoluteTTLSecondsByTenant returns the SSO session absolute lifetime
// (seconds) of the realm the tenant belongs to. ok=false when the realm has no
// policy (NULL) or the tenant has no realm assignment.
func (r *RealmRepository) SessionAbsoluteTTLSecondsByTenant(ctx context.Context, tenantID uuid.UUID) (int, bool, error) {
	const q = `
		SELECT r.session_absolute_ttl_seconds
		FROM realms r
		JOIN realm_tenants rt ON r.id = rt.realm_id
		WHERE rt.tenant_id = $1`
	var secs *int
	err := r.db.QueryRow(ctx, q, tenantID).Scan(&secs)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, fmt.Errorf("SessionAbsoluteTTLSecondsByTenant: %w", err)
	}
	if secs == nil {
		return 0, false, nil
	}
	return *secs, true, nil
}

// GetSessionAbsoluteTTLSeconds returns the realm's SSO session cap (nil = global default).
func (r *RealmRepository) GetSessionAbsoluteTTLSeconds(ctx context.Context, realmID uuid.UUID) (*int, error) {
	var secs *int
	err := r.db.QueryRow(ctx, `SELECT session_absolute_ttl_seconds FROM realms WHERE id = $1`, realmID).Scan(&secs)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("realm not found")
	}
	if err != nil {
		return nil, fmt.Errorf("GetSessionAbsoluteTTLSeconds: %w", err)
	}
	return secs, nil
}

// SetSessionAbsoluteTTLSeconds updates the realm's SSO session cap (nil clears it).
func (r *RealmRepository) SetSessionAbsoluteTTLSeconds(ctx context.Context, realmID uuid.UUID, secs *int) error {
	res, err := r.db.Exec(ctx, `UPDATE realms SET session_absolute_ttl_seconds = $2, updated_at = NOW() WHERE id = $1`, realmID, secs)
	if err != nil {
		return fmt.Errorf("SetSessionAbsoluteTTLSeconds: %w", err)
	}
	if res.RowsAffected() == 0 {
		return fmt.Errorf("realm not found")
	}
	return nil
}
