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
	"github.com/dogukanturhal/falcon-id/pkg/crypto"
)

const msgRoleList = "List: %w"

// RoleRepository is an exported type.
type RoleRepository struct {
	db                DBPool
	encryptionService *crypto.EncryptionService
}

// NewRoleRepository is an exported function.
func NewRoleRepository(db *pgxpool.Pool) *RoleRepository {
	return &RoleRepository{db: db}
}

// SetEncryptionService wires the encryption service so JOINed iam_users PII
// (email + display_name via COALESCE) on role-member listings is decrypted
// post-scan. Without this, the role-members API surfaces ciphertext.
func (r *RoleRepository) SetEncryptionService(es *crypto.EncryptionService) {
	r.encryptionService = es
}

// Create is an exported function.
func (r *RoleRepository) Create(ctx context.Context, role *models.Role) error {
	query := `
		INSERT INTO iam_roles (id, tenant_id, name, display_name, description, is_system, is_default, priority, created_by)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		RETURNING created_at, updated_at`

	if role.ID == uuid.Nil {
		role.ID = uuid.New()
	}

	return r.db.QueryRow(ctx, query,
		role.ID, role.TenantID, role.Name, role.DisplayName, role.Description,
		role.IsSystem, role.IsDefault, role.Priority, role.CreatedBy,
	).Scan(&role.CreatedAt, &role.UpdatedAt)
}

// GetByID is an exported function.
func (r *RoleRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.Role, error) {
	role := &models.Role{}
	query := `
		SELECT id, tenant_id, name, display_name, description, is_system, is_default, priority,
			   created_at, updated_at, created_by, updated_by
		FROM iam_roles WHERE id = $1`

	err := r.db.QueryRow(ctx, query, id).Scan(
		&role.ID, &role.TenantID, &role.Name, &role.DisplayName, &role.Description,
		&role.IsSystem, &role.IsDefault, &role.Priority,
		&role.CreatedAt, &role.UpdatedAt, &role.CreatedBy, &role.UpdatedBy,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("GetByID: %w", err)
	}
	return role, nil
}

// GetByIDAndTenant returns the role only if it belongs to the given tenant.
func (r *RoleRepository) GetByIDAndTenant(ctx context.Context, id, tenantID uuid.UUID) (*models.Role, error) {
	return r.getByIDAndTenant(ctx, id, tenantID, "")
}

// GetByIDAndTenantForShare holds the role's tenant/system/priority facts stable
// for an enclosing authorization transaction.
func (r *RoleRepository) GetByIDAndTenantForShare(ctx context.Context, id, tenantID uuid.UUID) (*models.Role, error) {
	return r.getByIDAndTenant(ctx, id, tenantID, " FOR SHARE")
}

func (r *RoleRepository) getByIDAndTenant(ctx context.Context, id, tenantID uuid.UUID, lock string) (*models.Role, error) {
	role := &models.Role{}
	query := `
		SELECT id, tenant_id, name, display_name, description, is_system, is_default, priority,
			   created_at, updated_at, created_by, updated_by
		FROM iam_roles WHERE id = $1 AND tenant_id = $2` + lock

	err := r.db.QueryRow(ctx, query, id, tenantID).Scan(
		&role.ID, &role.TenantID, &role.Name, &role.DisplayName, &role.Description,
		&role.IsSystem, &role.IsDefault, &role.Priority,
		&role.CreatedAt, &role.UpdatedAt, &role.CreatedBy, &role.UpdatedBy,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("GetByIDAndTenant: %w", err)
	}
	return role, nil
}

// GetMaxPriorityForUser returns the highest priority among the user's non-expired roles within a tenant.
func (r *RoleRepository) GetMaxPriorityForUser(ctx context.Context, userID, tenantID uuid.UUID) (int, error) {
	query := `
		SELECT COALESCE(MAX(r.priority), 0)
		FROM iam_roles r
		INNER JOIN iam_user_roles ur ON ur.role_id = r.id
		WHERE ur.user_id = $1
		  AND r.tenant_id = $2
		  AND (ur.expires_at IS NULL OR ur.expires_at > NOW())`

	var maxPriority int
	err := r.db.QueryRow(ctx, query, userID, tenantID).Scan(&maxPriority)
	if err != nil {
		return 0, fmt.Errorf("GetMaxPriorityForUser: %w", err)
	}
	return maxPriority, nil
}

// GetByName is an exported function.
func (r *RoleRepository) GetByName(ctx context.Context, tenantID uuid.UUID, name string) (*models.Role, error) {
	role := &models.Role{}
	query := `
		SELECT id, tenant_id, name, display_name, description, is_system, is_default, priority,
			   created_at, updated_at, created_by, updated_by
		FROM iam_roles WHERE tenant_id = $1 AND name = $2`

	err := r.db.QueryRow(ctx, query, tenantID, name).Scan(
		&role.ID, &role.TenantID, &role.Name, &role.DisplayName, &role.Description,
		&role.IsSystem, &role.IsDefault, &role.Priority,
		&role.CreatedAt, &role.UpdatedAt, &role.CreatedBy, &role.UpdatedBy,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("GetByName: %w", err)
	}
	return role, nil
}

// Update updates a role.
//
// IMPORTANT: this is a write-all-columns UPDATE — every field on the
// inbound struct is written unconditionally. Callers MUST load the
// full row via GetByID first; passing a partial struct will wipe
// other columns. See user_repository.go:Update for the durable
// repository-layer guard and history of this class of bug.
func (r *RoleRepository) Update(ctx context.Context, role *models.Role) error {
	query := `
		UPDATE iam_roles SET
			display_name = $2, description = $3, is_default = $4, priority = $5, updated_by = $6
		WHERE id = $1
		RETURNING updated_at`

	return r.db.QueryRow(ctx, query,
		role.ID, role.DisplayName, role.Description, role.IsDefault, role.Priority, role.UpdatedBy,
	).Scan(&role.UpdatedAt)
}

// Delete is an exported function.
func (r *RoleRepository) Delete(ctx context.Context, id uuid.UUID) error {
	// Check if system role
	var isSystem bool
	err := r.db.QueryRow(ctx, "SELECT is_system FROM iam_roles WHERE id = $1", id).Scan(&isSystem)
	if err != nil {
		return fmt.Errorf("Delete: %w", err)
	}
	if isSystem {
		return fmt.Errorf("cannot delete system role")
	}

	_, err = r.db.Exec(ctx, "DELETE FROM iam_roles WHERE id = $1", id)
	if err != nil {
		return fmt.Errorf("Delete: %w", err)
	}
	return nil
}

// List is an exported function.
func (r *RoleRepository) List(ctx context.Context, tenantID uuid.UUID, page, pageSize int, search string) ([]models.Role, int64, error) {
	offset := (page - 1) * pageSize

	// Count total
	countQuery := `SELECT COUNT(*) FROM iam_roles WHERE tenant_id = $1`
	args := []interface{}{tenantID}

	if search != "" {
		countQuery += ` AND (name ILIKE $2 OR display_name ILIKE $2)`
		args = append(args, "%"+search+"%")
	}

	var total int64
	err := r.db.QueryRow(ctx, countQuery, args...).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf(msgRoleList, err)
	}

	// Get roles
	query := `
		SELECT id, tenant_id, name, display_name, description, is_system, is_default, priority,
			   created_at, updated_at, created_by, updated_by
		FROM iam_roles WHERE tenant_id = $1`

	if search != "" {
		query += ` AND (name ILIKE $2 OR display_name ILIKE $2)`
	}
	query += fmt.Sprintf(` ORDER BY priority DESC, name ASC, id ASC LIMIT %d OFFSET %d`, pageSize, offset)

	rows, err := r.db.Query(ctx, query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf(msgRoleList, err)
	}
	defer rows.Close()

	var roles []models.Role
	for rows.Next() {
		var role models.Role
		err := rows.Scan(
			&role.ID, &role.TenantID, &role.Name, &role.DisplayName, &role.Description,
			&role.IsSystem, &role.IsDefault, &role.Priority,
			&role.CreatedAt, &role.UpdatedAt, &role.CreatedBy, &role.UpdatedBy,
		)
		if err != nil {
			return nil, 0, fmt.Errorf(msgRoleList, err)
		}
		roles = append(roles, role)
	}

	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("List: rows iteration: %w", err)
	}

	return roles, total, nil
}

// ListForModules is List, additionally scoped to roles whose complete
// effective permission bundle belongs to the given modules.
//
// A role "belongs" to modules through iam_role_permissions -> iam_permissions
// (the same module attribution already used for permission-level entitlement
// scoping — see PermissionRepository.ListByModules, RoleService.
// getEntitledModules). Roles are NOT re-scoped by adding a new column: a
// role qualifies only when no effective permission falls outside the
// allow-list. A role with no permissions qualifies vacuously: it cannot grant
// access until permissions are assigned and it has no separate module scope.
//
// A nil modules value is retained only for platform-admin callers that
// deliberately request the unscoped repository method. Tenant self-service
// callers always supply the fail-closed entitlement result.
func (r *RoleRepository) ListForModules(
	ctx context.Context, tenantID uuid.UUID, page, pageSize int, search string, modules []string,
) ([]models.Role, int64, error) {
	if modules == nil {
		return r.List(ctx, tenantID, page, pageSize, search)
	}

	offset := (page - 1) * pageSize

	const moduleScope = `
		AND (
			NOT EXISTS (
				SELECT 1 FROM iam_role_permissions rp
				INNER JOIN iam_permissions p ON p.id = rp.permission_id
				WHERE rp.role_id = iam_roles.id AND NOT (p.module = ANY($%d))
			)
		)`

	// Count total
	countQuery := `SELECT COUNT(*) FROM iam_roles WHERE tenant_id = $1`
	args := []interface{}{tenantID}

	if search != "" {
		countQuery += ` AND (name ILIKE $2 OR display_name ILIKE $2)`
		args = append(args, "%"+search+"%")
	}
	args = append(args, modules)
	countQuery += fmt.Sprintf(moduleScope, len(args))

	var total int64
	err := r.db.QueryRow(ctx, countQuery, args...).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf(msgRoleList, err)
	}

	// Get roles — same args/placeholders as the count query, so the module
	// placeholder index matches.
	query := `
		SELECT id, tenant_id, name, display_name, description, is_system, is_default, priority,
			   created_at, updated_at, created_by, updated_by
		FROM iam_roles WHERE tenant_id = $1`
	if search != "" {
		query += ` AND (name ILIKE $2 OR display_name ILIKE $2)`
	}
	query += fmt.Sprintf(moduleScope, len(args))
	query += fmt.Sprintf(` ORDER BY priority DESC, name ASC, id ASC LIMIT %d OFFSET %d`, pageSize, offset)

	rows, err := r.db.Query(ctx, query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf(msgRoleList, err)
	}
	defer rows.Close()

	var roles []models.Role
	for rows.Next() {
		var role models.Role
		err := rows.Scan(
			&role.ID, &role.TenantID, &role.Name, &role.DisplayName, &role.Description,
			&role.IsSystem, &role.IsDefault, &role.Priority,
			&role.CreatedAt, &role.UpdatedAt, &role.CreatedBy, &role.UpdatedBy,
		)
		if err != nil {
			return nil, 0, fmt.Errorf(msgRoleList, err)
		}
		roles = append(roles, role)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("ListForModules: rows iteration: %w", err)
	}

	return roles, total, nil
}

// HasOnlyPermissionsInModules reports whether every effective permission of a
// role is in modules. It is transaction-safe when called on WithDB(tx), and is
// used at the final invitation-acceptance authorization point.
func (r *RoleRepository) HasOnlyPermissionsInModules(ctx context.Context, roleID uuid.UUID, modules []string) (bool, error) {
	var allowed bool
	err := r.db.QueryRow(ctx, `SELECT NOT EXISTS (
		SELECT 1 FROM iam_role_permissions rp
		JOIN iam_permissions p ON p.id = rp.permission_id
		WHERE rp.role_id = $1 AND NOT (p.module = ANY($2))
	)`, roleID, modules).Scan(&allowed)
	if err != nil {
		return false, fmt.Errorf("HasOnlyPermissionsInModules: %w", err)
	}
	return allowed, nil
}

// LockPermissionCatalogue serializes a final entitlement decision against
// permission and role-permission writes for the enclosing transaction.
func (r *RoleRepository) LockPermissionCatalogue(ctx context.Context) error {
	_, err := r.db.Exec(ctx, "LOCK TABLE iam_permissions, iam_role_permissions IN SHARE MODE")
	if err != nil {
		return fmt.Errorf("LockPermissionCatalogue: %w", err)
	}
	return nil
}

// GetDefaultRoles is an exported function.
func (r *RoleRepository) GetDefaultRoles(ctx context.Context, tenantID uuid.UUID) ([]models.Role, error) {
	query := `
		SELECT id, tenant_id, name, display_name, description, is_system, is_default, priority,
			   created_at, updated_at, created_by, updated_by
		FROM iam_roles WHERE tenant_id = $1 AND is_default = true`

	rows, err := r.db.Query(ctx, query, tenantID)
	if err != nil {
		return nil, fmt.Errorf("GetDefaultRoles: %w", err)
	}
	defer rows.Close()

	var roles []models.Role
	for rows.Next() {
		var role models.Role
		err := rows.Scan(
			&role.ID, &role.TenantID, &role.Name, &role.DisplayName, &role.Description,
			&role.IsSystem, &role.IsDefault, &role.Priority,
			&role.CreatedAt, &role.UpdatedAt, &role.CreatedBy, &role.UpdatedBy,
		)
		if err != nil {
			return nil, fmt.Errorf("GetDefaultRoles: %w", err)
		}
		roles = append(roles, role)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("GetDefaultRoles: rows iteration: %w", err)
	}

	return roles, nil
}

// AssignPermissions is an exported function.
func (r *RoleRepository) AssignPermissions(ctx context.Context, roleID uuid.UUID, permissionIDs []uuid.UUID, assignedBy *uuid.UUID) error {
	// Delete existing permissions
	_, err := r.db.Exec(ctx, "DELETE FROM iam_role_permissions WHERE role_id = $1", roleID)
	if err != nil {
		return fmt.Errorf("AssignPermissions: %w", err)
	}

	// Insert new permissions
	for _, permID := range permissionIDs {
		_, err := r.db.Exec(ctx,
			"INSERT INTO iam_role_permissions (role_id, permission_id, created_by) VALUES ($1, $2, $3)",
			roleID, permID, assignedBy,
		)
		if err != nil {
			return fmt.Errorf("AssignPermissions: %w", err)
		}
	}

	return nil
}

// GrantPermissionsByName adds exact permissions without replacing grants the
// role already holds. The catalogue is resolved inside the same transaction so
// a missing definition cannot leave a partial administrator role grant.
func (r *RoleRepository) GrantPermissionsByName(ctx context.Context, roleID uuid.UUID, permissionNames []string) error {
	if len(permissionNames) == 0 {
		return nil
	}

	tx, err := r.db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("GrantPermissionsByName begin: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	var resolved int
	err = tx.QueryRow(ctx, `
		SELECT COUNT(DISTINCT name)
		FROM iam_permissions
		WHERE name = ANY($1::text[])`, permissionNames).Scan(&resolved)
	if err != nil {
		return fmt.Errorf("GrantPermissionsByName resolve: %w", err)
	}
	if resolved != len(permissionNames) {
		return fmt.Errorf("GrantPermissionsByName: resolved %d of %d required permissions", resolved, len(permissionNames))
	}

	_, err = tx.Exec(ctx, `
		INSERT INTO iam_role_permissions (role_id, permission_id)
		SELECT $1, id
		FROM iam_permissions
		WHERE name = ANY($2::text[])
		ON CONFLICT (role_id, permission_id) DO NOTHING`, roleID, permissionNames)
	if err != nil {
		return fmt.Errorf("GrantPermissionsByName insert: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("GrantPermissionsByName commit: %w", err)
	}
	return nil
}

// GetRolePermissions is an exported function.
func (r *RoleRepository) GetRolePermissions(ctx context.Context, roleID uuid.UUID) ([]models.Permission, error) {
	query := `
		SELECT p.id, p.module, p.resource, p.action, p.name, p.display_name, p.description, p.is_system, p.created_at
		FROM iam_permissions p
		INNER JOIN iam_role_permissions rp ON p.id = rp.permission_id
		WHERE rp.role_id = $1
		ORDER BY p.module, p.resource, p.action`

	rows, err := r.db.Query(ctx, query, roleID)
	if err != nil {
		return nil, fmt.Errorf("GetRolePermissions: %w", err)
	}
	defer rows.Close()

	var permissions []models.Permission
	for rows.Next() {
		var perm models.Permission
		err := rows.Scan(
			&perm.ID, &perm.Module, &perm.Resource, &perm.Action, &perm.Name,
			&perm.DisplayName, &perm.Description, &perm.IsSystem, &perm.CreatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("GetRolePermissions: %w", err)
		}
		permissions = append(permissions, perm)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("GetRolePermissions: rows iteration: %w", err)
	}

	return permissions, nil
}

// RoleMemberResult is the raw DB result for a role member query.
type RoleMemberResult struct {
	UserID   uuid.UUID
	UserName string
	Email    string
}

// GetRoleMembers returns the paginated list of users who hold the given role.
// roleIdentifier may be a UUID string or a role name (e.g. "crm:manager").
// When it is a name the lookup is scoped to tenantID.
func (r *RoleRepository) GetRoleMembers(ctx context.Context, tenantID uuid.UUID, roleIdentifier string, page, pageSize int) ([]RoleMemberResult, int, error) {
	offset := (page - 1) * pageSize

	// Build the WHERE clause. If the identifier parses as a UUID we match by
	// role id only (cross-tenant system roles are intentionally supported for
	// platform admin callers). Otherwise we scope to the tenant.
	_, parseErr := uuid.Parse(roleIdentifier)
	byUUID := parseErr == nil

	var countQuery, dataQuery string
	if byUUID {
		countQuery = `
			SELECT COUNT(*)
			FROM iam_user_roles ur
			JOIN iam_roles r ON ur.role_id = r.id
			WHERE r.id = $1
			  AND (ur.expires_at IS NULL OR ur.expires_at > NOW())`

		dataQuery = `
			SELECT u.id, COALESCE(u.display_name, u.username) AS user_name, u.email
			FROM iam_user_roles ur
			JOIN iam_roles r ON ur.role_id = r.id
			JOIN iam_users u ON ur.user_id = u.id
			WHERE r.id = $1
			  AND (ur.expires_at IS NULL OR ur.expires_at > NOW())
			ORDER BY u.email ASC
			LIMIT $2 OFFSET $3`
	} else {
		countQuery = `
			SELECT COUNT(*)
			FROM iam_user_roles ur
			JOIN iam_roles r ON ur.role_id = r.id
			WHERE r.name = $1 AND r.tenant_id = $2
			  AND (ur.expires_at IS NULL OR ur.expires_at > NOW())`

		dataQuery = `
			SELECT u.id, COALESCE(u.display_name, u.username) AS user_name, u.email
			FROM iam_user_roles ur
			JOIN iam_roles r ON ur.role_id = r.id
			JOIN iam_users u ON ur.user_id = u.id
			WHERE r.name = $1 AND r.tenant_id = $2
			  AND (ur.expires_at IS NULL OR ur.expires_at > NOW())
			ORDER BY u.email ASC
			LIMIT $3 OFFSET $4`
	}

	var total int
	if byUUID {
		if err := r.db.QueryRow(ctx, countQuery, roleIdentifier).Scan(&total); err != nil {
			return nil, 0, fmt.Errorf("GetRoleMembers count: %w", err)
		}
	} else {
		if err := r.db.QueryRow(ctx, countQuery, roleIdentifier, tenantID).Scan(&total); err != nil {
			return nil, 0, fmt.Errorf("GetRoleMembers count: %w", err)
		}
	}

	var rows pgx.Rows
	var err error
	if byUUID {
		rows, err = r.db.Query(ctx, dataQuery, roleIdentifier, pageSize, offset)
	} else {
		rows, err = r.db.Query(ctx, dataQuery, roleIdentifier, tenantID, pageSize, offset)
	}
	if err != nil {
		return nil, 0, fmt.Errorf("GetRoleMembers query: %w", err)
	}
	defer rows.Close()

	var members []RoleMemberResult
	for rows.Next() {
		var m RoleMemberResult
		if err := rows.Scan(&m.UserID, &m.UserName, &m.Email); err != nil {
			return nil, 0, fmt.Errorf("GetRoleMembers scan: %w", err)
		}
		// Decrypt JOINed PII so the API response carries plaintext.
		// `user_name` is `COALESCE(display_name, username)`: when display_name
		// is populated (encrypted) it wins and needs decryption; when null,
		// the COALESCE falls through to plaintext username — Decrypt would
		// fail on plaintext, so try only if the value looks like ciphertext
		// (starts with the EncryptedPrefix).
		if err := r.encryptionService.DecryptStringInPlace(&m.Email); err != nil {
			return nil, 0, fmt.Errorf("GetRoleMembers: decrypt email: %w", err)
		}
		if r.encryptionService != nil && strings.HasPrefix(m.UserName, crypto.EncryptedPrefix) {
			if dec, decErr := r.encryptionService.Decrypt(m.UserName); decErr == nil {
				m.UserName = dec
			}
		}
		members = append(members, m)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("GetRoleMembers rows: %w", err)
	}

	return members, total, nil
}

// CreateSystemRoles creates default system roles for a tenant
func (r *RoleRepository) CreateSystemRoles(ctx context.Context, tenantID uuid.UUID) error {
	systemRoles := []struct {
		Name        string
		DisplayName string
		Description string
		Priority    int
		IsDefault   bool
	}{
		{"admin", "Administrator", "Full system access", 100, false},
		{"manager", "Manager", "Management access to assigned modules", 75, false},
		{"user", "User", "Standard user access", 50, true},
		{"viewer", "Viewer", "Read-only access", 25, false},
	}

	for _, sr := range systemRoles {
		role := &models.Role{
			TenantID:    tenantID,
			Name:        sr.Name,
			DisplayName: sr.DisplayName,
			Description: &sr.Description,
			IsSystem:    true,
			IsDefault:   sr.IsDefault,
			Priority:    sr.Priority,
		}
		if err := r.Create(ctx, role); err != nil {
			return fmt.Errorf("failed to create system role %s: %w", sr.Name, err)
		}
	}

	return nil
}
