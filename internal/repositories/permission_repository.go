// SPDX-License-Identifier: AGPL-3.0-or-later

package repositories

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

// validPermSegment validates module/resource/action segments.
var validPermSegment = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,49}$`)

const msgRegisterPermissionsBatch = "RegisterPermissionsBatch: %w"

// PermissionRepository is an exported type.
type PermissionRepository struct {
	db      DBPool
	realmID *uuid.UUID
}

// WithRealmID returns a shallow clone of PermissionRepository scoped to the given realm.
func (r *PermissionRepository) WithRealmID(realmID uuid.UUID) *PermissionRepository {
	clone := *r
	clone.realmID = &realmID
	return &clone
}

// NewPermissionRepository is an exported function.
func NewPermissionRepository(db *pgxpool.Pool) *PermissionRepository {
	return &PermissionRepository{db: db}
}

// GetByID is an exported function.
func (r *PermissionRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.Permission, error) {
	perm := &models.Permission{}
	query := `
		SELECT id, module, resource, action, name, display_name, description, is_system, source, created_at
		FROM iam_permissions WHERE id = $1`

	err := r.db.QueryRow(ctx, query, id).Scan(
		&perm.ID, &perm.Module, &perm.Resource, &perm.Action, &perm.Name,
		&perm.DisplayName, &perm.Description, &perm.IsSystem, &perm.Source, &perm.CreatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("GetByID: %w", err)
	}
	return perm, nil
}

// GetByName is an exported function.
func (r *PermissionRepository) GetByName(ctx context.Context, name string) (*models.Permission, error) {
	perm := &models.Permission{}
	query := `
		SELECT id, module, resource, action, name, display_name, description, is_system, source, created_at
		FROM iam_permissions WHERE name = $1`

	err := r.db.QueryRow(ctx, query, name).Scan(
		&perm.ID, &perm.Module, &perm.Resource, &perm.Action, &perm.Name,
		&perm.DisplayName, &perm.Description, &perm.IsSystem, &perm.Source, &perm.CreatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("GetByName: %w", err)
	}
	return perm, nil
}

// List is an exported function.
func (r *PermissionRepository) List(ctx context.Context) ([]models.Permission, error) {
	query := `
		SELECT id, module, resource, action, name, display_name, description, is_system, source, created_at
		FROM iam_permissions
		ORDER BY module, resource, action
		LIMIT 1000`

	rows, err := r.db.Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("List: %w", err)
	}
	defer rows.Close()

	var permissions []models.Permission
	for rows.Next() {
		var perm models.Permission
		err := rows.Scan(
			&perm.ID, &perm.Module, &perm.Resource, &perm.Action, &perm.Name,
			&perm.DisplayName, &perm.Description, &perm.IsSystem, &perm.Source, &perm.CreatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("List: %w", err)
		}
		permissions = append(permissions, perm)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("List: rows iteration: %w", err)
	}

	return permissions, nil
}

// ListConcreteNames returns the names of every non-wildcard permission in the
// catalog. It is the authoritative set wildcard grants are expanded against.
func (r *PermissionRepository) ListConcreteNames(ctx context.Context) ([]string, error) {
	rows, err := r.db.Query(ctx, `SELECT name FROM iam_permissions WHERE position('*' in name) = 0 ORDER BY name`)
	if err != nil {
		return nil, fmt.Errorf("ListConcreteNames: %w", err)
	}
	defer rows.Close()

	var names []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			return nil, fmt.Errorf("ListConcreteNames: %w", err)
		}
		names = append(names, n)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("ListConcreteNames: rows iteration: %w", err)
	}
	return names, nil
}

// ListByModule is an exported function.
func (r *PermissionRepository) ListByModule(ctx context.Context, module string) ([]models.Permission, error) {
	query := `
		SELECT id, module, resource, action, name, display_name, description, is_system, source, created_at
		FROM iam_permissions WHERE module = $1
		ORDER BY resource, action
		LIMIT 1000`

	rows, err := r.db.Query(ctx, query, module)
	if err != nil {
		return nil, fmt.Errorf("ListByModule: %w", err)
	}
	defer rows.Close()

	var permissions []models.Permission
	for rows.Next() {
		var perm models.Permission
		err := rows.Scan(
			&perm.ID, &perm.Module, &perm.Resource, &perm.Action, &perm.Name,
			&perm.DisplayName, &perm.Description, &perm.IsSystem, &perm.Source, &perm.CreatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("ListByModule: %w", err)
		}
		permissions = append(permissions, perm)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("ListByModule: rows iteration: %w", err)
	}

	return permissions, nil
}

// ListByModules is an exported function.
func (r *PermissionRepository) ListByModules(ctx context.Context, modules []string) ([]models.Permission, error) {
	query := `
		SELECT id, module, resource, action, name, display_name, description, is_system, source, created_at
		FROM iam_permissions WHERE module = ANY($1)
		ORDER BY module, resource, action
		LIMIT 1000`

	rows, err := r.db.Query(ctx, query, modules)
	if err != nil {
		return nil, fmt.Errorf("ListByModules: %w", err)
	}
	defer rows.Close()

	var permissions []models.Permission
	for rows.Next() {
		var perm models.Permission
		err := rows.Scan(
			&perm.ID, &perm.Module, &perm.Resource, &perm.Action, &perm.Name,
			&perm.DisplayName, &perm.Description, &perm.IsSystem, &perm.Source, &perm.CreatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("ListByModules: %w", err)
		}
		permissions = append(permissions, perm)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("ListByModules: rows iteration: %w", err)
	}

	return permissions, nil
}

// GetModules is an exported function.
func (r *PermissionRepository) GetModules(ctx context.Context) ([]string, error) {
	query := `SELECT DISTINCT module FROM iam_permissions ORDER BY module`

	rows, err := r.db.Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("GetModules: %w", err)
	}
	defer rows.Close()

	var modules []string
	for rows.Next() {
		var module string
		if err := rows.Scan(&module); err != nil {
			return nil, fmt.Errorf("GetModules: %w", err)
		}
		modules = append(modules, module)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("GetModules: rows iteration: %w", err)
	}

	return modules, nil
}

// GetByIDs is an exported function.
func (r *PermissionRepository) GetByIDs(ctx context.Context, ids []uuid.UUID) ([]models.Permission, error) {
	if len(ids) == 0 {
		return []models.Permission{}, nil
	}

	query := `
		SELECT id, module, resource, action, name, display_name, description, is_system, source, created_at
		FROM iam_permissions WHERE id = ANY($1)
		ORDER BY module, resource, action`

	rows, err := r.db.Query(ctx, query, ids)
	if err != nil {
		return nil, fmt.Errorf("GetByIDs: %w", err)
	}
	defer rows.Close()

	var permissions []models.Permission
	for rows.Next() {
		var perm models.Permission
		err := rows.Scan(
			&perm.ID, &perm.Module, &perm.Resource, &perm.Action, &perm.Name,
			&perm.DisplayName, &perm.Description, &perm.IsSystem, &perm.Source, &perm.CreatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("GetByIDs: %w", err)
		}
		permissions = append(permissions, perm)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("GetByIDs: rows iteration: %w", err)
	}

	return permissions, nil
}

// RegisterPermission registers a new permission (used by modules)
func (r *PermissionRepository) RegisterPermission(ctx context.Context, perm *models.Permission) error {
	if !validPermSegment.MatchString(perm.Module) {
		return fmt.Errorf("invalid module segment: %q", perm.Module)
	}
	if perm.Resource != "*" && !validPermSegment.MatchString(perm.Resource) {
		return fmt.Errorf("invalid resource segment: %q", perm.Resource)
	}
	if perm.Action != "*" && !validPermSegment.MatchString(perm.Action) {
		return fmt.Errorf("invalid action segment: %q", perm.Action)
	}

	query := `
		INSERT INTO iam_permissions (module, resource, action, name, display_name, description, is_system, source)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		ON CONFLICT (name) DO UPDATE SET
			display_name = EXCLUDED.display_name,
			description = EXCLUDED.description,
			source = EXCLUDED.source
		RETURNING id, created_at`

	return r.db.QueryRow(ctx, query,
		perm.Module, perm.Resource, perm.Action, perm.Name,
		perm.DisplayName, perm.Description, perm.IsSystem, perm.Source,
	).Scan(&perm.ID, &perm.CreatedAt)
}

// validatePermissionSegments validates the module, resource, and action segments
// of a permission against the allowed pattern.
func validatePermissionSegments(perm *models.Permission) error {
	if !validPermSegment.MatchString(perm.Module) {
		return fmt.Errorf("invalid module segment: %q", perm.Module)
	}
	if perm.Resource != "*" && !validPermSegment.MatchString(perm.Resource) {
		return fmt.Errorf("invalid resource segment: %q", perm.Resource)
	}
	if perm.Action != "*" && !validPermSegment.MatchString(perm.Action) {
		return fmt.Errorf("invalid action segment: %q", perm.Action)
	}
	return nil
}

// upsertPermission inserts or updates a single permission inside a transaction
// and increments the appropriate counter.
func upsertPermission(ctx context.Context, tx pgx.Tx, query string, perm *models.Permission) (inserted bool, err error) {
	var isInsert bool
	err = tx.QueryRow(ctx, query,
		perm.Module, perm.Resource, perm.Action, perm.Name,
		perm.DisplayName, perm.Description, perm.IsSystem, perm.Source,
	).Scan(&perm.ID, &perm.CreatedAt, &isInsert)
	if err != nil {
		return false, fmt.Errorf(msgRegisterPermissionsBatch, err)
	}
	return isInsert, nil
}

// RegisterPermissionsBatch registers multiple permissions in a single transaction
func (r *PermissionRepository) RegisterPermissionsBatch(ctx context.Context, permissions []*models.Permission) (registered, updated int, err error) {
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return 0, 0, fmt.Errorf(msgRegisterPermissionsBatch, err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	query := `
		INSERT INTO iam_permissions (module, resource, action, name, display_name, description, is_system, source)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		ON CONFLICT (name) DO UPDATE SET
			display_name = EXCLUDED.display_name,
			description = EXCLUDED.description,
			source = EXCLUDED.source
		RETURNING id, created_at, (xmax = 0) as is_insert`

	for _, perm := range permissions {
		if err := validatePermissionSegments(perm); err != nil {
			return 0, 0, err
		}
		isInsert, err := upsertPermission(ctx, tx, query, perm)
		if err != nil {
			return 0, 0, err
		}
		if isInsert {
			registered++
		} else {
			updated++
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return 0, 0, fmt.Errorf(msgRegisterPermissionsBatch, err)
	}

	return registered, updated, nil
}

// DeprecateUnlistedInModule soft-deprecates every catalog row for the given
// `module` whose `name` is not present in `activePermissionNames`. The
// transition is:
//
//	deprecated_at = COALESCE(deprecated_at, now())
//	sunset_at     = COALESCE(sunset_at,     now() + sunsetWindow)
//
// COALESCE makes the operation idempotent: a row that has already been
// deprecated retains its original timestamps. System rows (`is_system=true`)
// are skipped entirely — those are platform invariants and never touched by
// sync-mode registration.
//
// The default sunsetWindow recommendation is 30 days, giving operators time
// to spot orphans in monitoring before they actually disappear. A caller may
// pass any positive duration. The actual hard-delete is a separate sweep
// that validates `iam_role_permissions` referential safety before deleting.
//
// Returns the number of rows transitioned (= rows where `deprecated_at` was
// NULL on entry).
func (r *PermissionRepository) DeprecateUnlistedInModule(
	ctx context.Context,
	module string,
	activePermissionNames []string,
	sunsetWindow time.Duration,
) (int, error) {
	if module == "" {
		return 0, fmt.Errorf("DeprecateUnlistedInModule: module is required")
	}
	if sunsetWindow <= 0 {
		return 0, fmt.Errorf("DeprecateUnlistedInModule: sunsetWindow must be positive")
	}

	// The interval is built by concatenating a seconds count into a Postgres
	// interval literal: ($3 || ' seconds')::interval. The `||` operator forces
	// $3 to bind as TEXT (OID 25), so $3 MUST be a string. Passing an int64
	// makes pgx v5 fail at encode time with "cannot find encode plan"
	// (int64 -> text has no implicit codec). Format the seconds as a string.
	sunsetSeconds := strconv.FormatInt(int64(sunsetWindow.Seconds()), 10)

	// $2 is the list of names to PRESERVE (i.e. still in the manifest).
	// An empty list is legal — it deprecates EVERY non-system row in the
	// module, which is the right semantic for "this module no longer
	// publishes any permissions".
	query := `
		UPDATE iam_permissions
		SET    deprecated_at = COALESCE(deprecated_at, now()),
		       sunset_at     = COALESCE(sunset_at,     now() + ($3 || ' seconds')::interval)
		WHERE  module        = $1
		  AND  NOT (name = ANY($2))
		  AND  deprecated_at IS NULL
		  AND  is_system     = false
		RETURNING name`

	rows, err := r.db.Query(ctx, query, module, activePermissionNames, sunsetSeconds)
	if err != nil {
		return 0, fmt.Errorf("DeprecateUnlistedInModule: %w", err)
	}
	defer rows.Close()

	count := 0
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return 0, fmt.Errorf("DeprecateUnlistedInModule: scan: %w", err)
		}
		count++
	}
	if err := rows.Err(); err != nil {
		return 0, fmt.Errorf("DeprecateUnlistedInModule: rows iteration: %w", err)
	}
	return count, nil
}

// GetUserPermissions returns all permissions for a user (via roles) scoped to a specific tenant.
// The tenantID guard ensures that role assignments from other tenants are never included,
// preventing cross-tenant privilege escalation.
func (r *PermissionRepository) GetUserPermissions(ctx context.Context, userID, tenantID uuid.UUID) ([]models.Permission, error) {
	query := `
		SELECT DISTINCT p.id, p.module, p.resource, p.action, p.name, p.display_name, p.description, p.is_system, p.source, p.created_at
		FROM iam_permissions p
		INNER JOIN iam_role_permissions rp ON rp.permission_id = p.id
		INNER JOIN iam_user_roles ur ON ur.role_id = rp.role_id
		INNER JOIN iam_roles r ON r.id = ur.role_id
		WHERE ur.user_id = $1
		  AND r.tenant_id = $2
		  AND (ur.expires_at IS NULL OR ur.expires_at > NOW())
		ORDER BY p.module, p.resource, p.action`

	rows, err := r.db.Query(ctx, query, userID, tenantID)
	if err != nil {
		return nil, fmt.Errorf("GetUserPermissions: %w", err)
	}
	defer rows.Close()

	var permissions []models.Permission
	for rows.Next() {
		var perm models.Permission
		err := rows.Scan(
			&perm.ID, &perm.Module, &perm.Resource, &perm.Action, &perm.Name,
			&perm.DisplayName, &perm.Description, &perm.IsSystem, &perm.Source, &perm.CreatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("GetUserPermissions: %w", err)
		}
		permissions = append(permissions, perm)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("GetUserPermissions: rows iteration: %w", err)
	}

	return permissions, nil
}

// GetUserRoles returns all role names for a user scoped to a specific tenant.
// The tenantID guard ensures that roles from other tenants are never included,
// preventing cross-tenant privilege escalation.
func (r *PermissionRepository) GetUserRoles(ctx context.Context, userID, tenantID uuid.UUID) ([]string, error) {
	query := `
		SELECT r.name
		FROM iam_roles r
		INNER JOIN iam_user_roles ur ON ur.role_id = r.id
		WHERE ur.user_id = $1
		  AND r.tenant_id = $2
		  AND (ur.expires_at IS NULL OR ur.expires_at > NOW())
		ORDER BY r.name`

	rows, err := r.db.Query(ctx, query, userID, tenantID)
	if err != nil {
		return nil, fmt.Errorf("GetUserRoles: %w", err)
	}
	defer rows.Close()

	var roles []string
	for rows.Next() {
		var role string
		if err := rows.Scan(&role); err != nil {
			return nil, fmt.Errorf("GetUserRoles: %w", err)
		}
		roles = append(roles, role)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("GetUserRoles: rows iteration: %w", err)
	}

	return roles, nil
}

// GetRoleNameByID returns the name of a role given its ID
func (r *PermissionRepository) GetRoleNameByID(ctx context.Context, roleID uuid.UUID) (string, error) {
	var name string
	query := `SELECT name FROM iam_roles WHERE id = $1`
	err := r.db.QueryRow(ctx, query, roleID).Scan(&name)
	if err != nil {
		return "", fmt.Errorf("GetRoleNameByID: %w", err)
	}
	return name, nil
}

// Create inserts a new permission (strict insert, NOT upsert).
// Returns a pgconn unique violation error if the permission name already exists.
func (r *PermissionRepository) Create(ctx context.Context, perm *models.Permission) error {
	query := `INSERT INTO iam_permissions (module, resource, action, name, display_name, description, is_system, source)
              VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING id, created_at`

	err := r.db.QueryRow(ctx, query,
		perm.Module, perm.Resource, perm.Action, perm.Name,
		perm.DisplayName, perm.Description, perm.IsSystem, perm.Source,
	).Scan(&perm.ID, &perm.CreatedAt)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return fmt.Errorf("permission with name %q already exists", perm.Name)
		}
		return fmt.Errorf("Create: %w", err)
	}
	return nil
}

// Update updates only the display_name and description fields.
func (r *PermissionRepository) Update(ctx context.Context, id uuid.UUID, displayName *string, description *string) error {
	query := `UPDATE iam_permissions SET
                display_name = COALESCE($2, display_name),
                description = COALESCE($3, description)
              WHERE id = $1`

	tag, err := r.db.Exec(ctx, query, id, displayName, description)
	if err != nil {
		return fmt.Errorf("Update: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("permission not found")
	}
	return nil
}

// DeleteIfNotInUse deletes a permission inside a transaction with a SELECT FOR UPDATE lock.
// It blocks deletion of system permissions and permissions assigned to roles.
func (r *PermissionRepository) DeleteIfNotInUse(ctx context.Context, id uuid.UUID) error {
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("DeleteIfNotInUse: begin tx: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	// 1. Lock the row
	var isSystem bool
	err = tx.QueryRow(ctx,
		`SELECT is_system FROM iam_permissions WHERE id = $1 FOR UPDATE`, id,
	).Scan(&isSystem)
	if errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("permission not found")
	}
	if err != nil {
		return fmt.Errorf("DeleteIfNotInUse: lock: %w", err)
	}

	// 2. Block system permissions
	if isSystem {
		return fmt.Errorf("system permissions cannot be deleted")
	}

	// 3. Check in-use via role assignments
	var count int
	err = tx.QueryRow(ctx,
		`SELECT COUNT(*) FROM iam_role_permissions WHERE permission_id = $1`, id,
	).Scan(&count)
	if err != nil {
		return fmt.Errorf("DeleteIfNotInUse: count: %w", err)
	}
	if count > 0 {
		return fmt.Errorf("permission is assigned to %d role(s); remove from all roles first", count)
	}

	// 4. Delete
	_, err = tx.Exec(ctx, `DELETE FROM iam_permissions WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("DeleteIfNotInUse: delete: %w", err)
	}

	// 5. Commit
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("DeleteIfNotInUse: commit: %w", err)
	}
	return nil
}

// GetUserPermissionIDs returns the IDs of all permissions held by a user within a tenant (via their roles).
func (r *PermissionRepository) GetUserPermissionIDs(ctx context.Context, userID, tenantID uuid.UUID) ([]uuid.UUID, error) {
	query := `
		SELECT DISTINCT p.id
		FROM iam_permissions p
		INNER JOIN iam_role_permissions rp ON rp.permission_id = p.id
		INNER JOIN iam_user_roles ur ON ur.role_id = rp.role_id
		INNER JOIN iam_roles r ON r.id = ur.role_id
		WHERE ur.user_id = $1
		  AND r.tenant_id = $2
		  AND (ur.expires_at IS NULL OR ur.expires_at > NOW())`

	rows, err := r.db.Query(ctx, query, userID, tenantID)
	if err != nil {
		return nil, fmt.Errorf("GetUserPermissionIDs: %w", err)
	}
	defer rows.Close()

	var ids []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("GetUserPermissionIDs: %w", err)
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("GetUserPermissionIDs: rows iteration: %w", err)
	}

	return ids, nil
}

// GetUserPermissionNames returns the names of all permissions held by a user
// within a tenant (via their roles). Used by the C-2 check to support wildcard
// matching (e.g. a caller holding crm:*:* can assign crm:companies:read).
func (r *PermissionRepository) GetUserPermissionNames(ctx context.Context, userID, tenantID uuid.UUID) ([]string, error) {
	query := `
		SELECT DISTINCT p.name
		FROM iam_permissions p
		INNER JOIN iam_role_permissions rp ON rp.permission_id = p.id
		INNER JOIN iam_user_roles ur ON ur.role_id = rp.role_id
		INNER JOIN iam_roles r ON r.id = ur.role_id
		WHERE ur.user_id = $1
		  AND r.tenant_id = $2
		  AND (ur.expires_at IS NULL OR ur.expires_at > NOW())`

	rows, err := r.db.Query(ctx, query, userID, tenantID)
	if err != nil {
		return nil, fmt.Errorf("GetUserPermissionNames: %w", err)
	}
	defer rows.Close()

	var names []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, fmt.Errorf("GetUserPermissionNames: %w", err)
		}
		names = append(names, name)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("GetUserPermissionNames: rows iteration: %w", err)
	}

	return names, nil
}

// GetPermissionNamesByIDs returns a map of permission ID → name for the given IDs.
func (r *PermissionRepository) GetPermissionNamesByIDs(ctx context.Context, ids []uuid.UUID) (map[uuid.UUID]string, error) {
	if len(ids) == 0 {
		return map[uuid.UUID]string{}, nil
	}

	query := `SELECT id, name FROM iam_permissions WHERE id = ANY($1)`
	rows, err := r.db.Query(ctx, query, ids)
	if err != nil {
		return nil, fmt.Errorf("GetPermissionNamesByIDs: %w", err)
	}
	defer rows.Close()

	result := make(map[uuid.UUID]string, len(ids))
	for rows.Next() {
		var id uuid.UUID
		var name string
		if err := rows.Scan(&id, &name); err != nil {
			return nil, fmt.Errorf("GetPermissionNamesByIDs: %w", err)
		}
		result[id] = name
	}
	return result, rows.Err()
}

// HasPermission checks if a user has a specific permission (supports wildcards)
// scoped to the given tenant.
//
// SECURITY: tenantID is mandatory. The query joins iam_roles to filter by
// r.tenant_id = $3, which prevents a user who holds a role in one tenant from
// passing permission checks in another tenant (cross-tenant privilege
// escalation). Before this fix (GAP 5) the method lacked any tenant filter.
func (r *PermissionRepository) HasPermission(ctx context.Context, userID, tenantID uuid.UUID, permission string) (bool, error) {
	query := `
		SELECT EXISTS (
			SELECT 1 FROM iam_permissions p
			INNER JOIN iam_role_permissions rp ON rp.permission_id = p.id
			INNER JOIN iam_user_roles ur ON ur.role_id = rp.role_id
			INNER JOIN iam_roles ro ON ro.id = ur.role_id
			WHERE ur.user_id = $1
			  AND (ur.expires_at IS NULL OR ur.expires_at > NOW())
			  AND ro.tenant_id = $3
			  AND (
				p.name = $2
				OR p.name = '*'
				OR (p.module || ':*') = $2
				OR (p.module || ':' || p.resource || ':*') = $2
				OR $2 LIKE (p.module || ':%') AND p.action = '*'
				OR $2 LIKE (p.module || ':' || p.resource || ':%') AND p.action = '*'
			  )
		)`

	var exists bool
	err := r.db.QueryRow(ctx, query, userID, permission, tenantID).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("HasPermission: %w", err)
	}
	return exists, nil
}
