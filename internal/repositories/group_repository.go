// SPDX-License-Identifier: AGPL-3.0-or-later

package repositories

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/pkg/crypto"
)

const (
	msgGroupNotFound   = "group not found"
	msgFailedScanGroup = "failed to scan group: %w"
)

// GroupRepository handles group database operations
type GroupRepository struct {
	pool              DBPool
	realmID           *uuid.UUID
	encryptionService *crypto.EncryptionService
}

// WithRealmID returns a shallow clone of GroupRepository scoped to the given realm.
func (r *GroupRepository) WithRealmID(realmID uuid.UUID) *GroupRepository {
	clone := *r
	clone.realmID = &realmID
	return &clone
}

// NewGroupRepository creates a new GroupRepository
func NewGroupRepository(pool *pgxpool.Pool) *GroupRepository {
	return &GroupRepository{pool: pool}
}

// SetEncryptionService wires the encryption service so JOINed iam_users PII
// (email/first_name/last_name/display_name) on member listings is decrypted
// post-scan. Without this, the group-members API surfaces ciphertext.
func (r *GroupRepository) SetEncryptionService(es *crypto.EncryptionService) {
	r.encryptionService = es
}

// ==================== Group CRUD Operations ====================

// Create creates a new group
func (r *GroupRepository) Create(ctx context.Context, group *models.Group) error {
	metadataJSON, err := json.Marshal(group.Metadata)
	if err != nil {
		metadataJSON = []byte("{}")
	}

	query := `
		INSERT INTO iam_groups (
			id, tenant_id, name, display_name, description, parent_group_id,
			is_system, metadata, created_at, updated_at, created_by
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`

	_, err = r.pool.Exec(ctx, query,
		group.ID, group.TenantID, group.Name, group.DisplayName, group.Description,
		group.ParentGroupID, group.IsSystem, metadataJSON, group.CreatedAt,
		group.UpdatedAt, group.CreatedBy,
	)
	if err != nil {
		return fmt.Errorf("failed to create group: %w", err)
	}

	return nil
}

// GetByID retrieves a group by ID
func (r *GroupRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.Group, error) {
	query := `
		SELECT g.id, g.tenant_id, g.name, g.display_name, g.description, g.parent_group_id,
		       g.is_system, g.metadata, g.created_at, g.updated_at, g.created_by,
		       (SELECT COUNT(*) FROM iam_group_members WHERE group_id = g.id) as member_count,
		       (SELECT COUNT(*) FROM iam_group_roles WHERE group_id = g.id) as role_count
		FROM iam_groups g
		WHERE g.id = $1`

	group := &models.Group{}
	var metadataJSON []byte
	err := r.pool.QueryRow(ctx, query, id).Scan(
		&group.ID, &group.TenantID, &group.Name, &group.DisplayName, &group.Description,
		&group.ParentGroupID, &group.IsSystem, &metadataJSON, &group.CreatedAt,
		&group.UpdatedAt, &group.CreatedBy, &group.MemberCount, &group.RoleCount,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, errors.New(msgGroupNotFound)
		}
		return nil, fmt.Errorf("failed to get group: %w", err)
	}

	if metadataJSON != nil {
		_ = json.Unmarshal(metadataJSON, &group.Metadata)
	}

	return group, nil
}

// GetByName retrieves a group by name within a tenant
func (r *GroupRepository) GetByName(ctx context.Context, tenantID uuid.UUID, name string) (*models.Group, error) {
	query := `
		SELECT g.id, g.tenant_id, g.name, g.display_name, g.description, g.parent_group_id,
		       g.is_system, g.metadata, g.created_at, g.updated_at, g.created_by,
		       (SELECT COUNT(*) FROM iam_group_members WHERE group_id = g.id) as member_count,
		       (SELECT COUNT(*) FROM iam_group_roles WHERE group_id = g.id) as role_count
		FROM iam_groups g
		WHERE g.tenant_id = $1 AND g.name = $2`

	group := &models.Group{}
	var metadataJSON []byte
	err := r.pool.QueryRow(ctx, query, tenantID, name).Scan(
		&group.ID, &group.TenantID, &group.Name, &group.DisplayName, &group.Description,
		&group.ParentGroupID, &group.IsSystem, &metadataJSON, &group.CreatedAt,
		&group.UpdatedAt, &group.CreatedBy, &group.MemberCount, &group.RoleCount,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, errors.New(msgGroupNotFound)
		}
		return nil, fmt.Errorf("failed to get group: %w", err)
	}

	if metadataJSON != nil {
		_ = json.Unmarshal(metadataJSON, &group.Metadata)
	}

	return group, nil
}

// List lists all groups for a tenant with pagination
func (r *GroupRepository) List(ctx context.Context, tenantID uuid.UUID, page, pageSize int, search string) ([]*models.Group, int, error) {
	offset := (page - 1) * pageSize

	// Count query
	countQuery := `SELECT COUNT(*) FROM iam_groups WHERE tenant_id = $1`
	args := []interface{}{tenantID}

	if search != "" {
		countQuery += ` AND (name ILIKE $2 OR display_name ILIKE $2 OR description ILIKE $2)`
		args = append(args, "%"+search+"%")
	}

	var total int
	err := r.pool.QueryRow(ctx, countQuery, args...).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to count groups: %w", err)
	}

	// List query
	listQuery := `
		SELECT g.id, g.tenant_id, g.name, g.display_name, g.description, g.parent_group_id,
		       g.is_system, g.metadata, g.created_at, g.updated_at, g.created_by,
		       (SELECT COUNT(*) FROM iam_group_members WHERE group_id = g.id) as member_count,
		       (SELECT COUNT(*) FROM iam_group_roles WHERE group_id = g.id) as role_count
		FROM iam_groups g
		WHERE g.tenant_id = $1`

	if search != "" {
		listQuery += ` AND (g.name ILIKE $2 OR g.display_name ILIKE $2 OR g.description ILIKE $2)`
		listQuery += ` ORDER BY g.name LIMIT $3 OFFSET $4`
		args = append(args, pageSize, offset)
	} else {
		listQuery += ` ORDER BY g.name LIMIT $2 OFFSET $3`
		args = append(args, pageSize, offset)
	}

	rows, err := r.pool.Query(ctx, listQuery, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list groups: %w", err)
	}
	defer rows.Close()

	var groups []*models.Group
	for rows.Next() {
		group := &models.Group{}
		var metadataJSON []byte
		err := rows.Scan(
			&group.ID, &group.TenantID, &group.Name, &group.DisplayName, &group.Description,
			&group.ParentGroupID, &group.IsSystem, &metadataJSON, &group.CreatedAt,
			&group.UpdatedAt, &group.CreatedBy, &group.MemberCount, &group.RoleCount,
		)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to scan group: %w", err)
		}
		if metadataJSON != nil {
			_ = json.Unmarshal(metadataJSON, &group.Metadata)
		}
		groups = append(groups, group)
	}

	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("List: rows iteration: %w", err)
	}

	return groups, total, nil
}

// Update updates a group
func (r *GroupRepository) Update(ctx context.Context, group *models.Group) error {
	metadataJSON, err := json.Marshal(group.Metadata)
	if err != nil {
		metadataJSON = []byte("{}")
	}

	query := `
		UPDATE iam_groups SET
			name = $1, display_name = $2, description = $3, parent_group_id = $4,
			metadata = $5, updated_at = $6
		WHERE id = $7`

	result, err := r.pool.Exec(ctx, query,
		group.Name, group.DisplayName, group.Description, group.ParentGroupID,
		metadataJSON, time.Now(), group.ID,
	)
	if err != nil {
		return fmt.Errorf("failed to update group: %w", err)
	}

	if result.RowsAffected() == 0 {
		return errors.New(msgGroupNotFound)
	}

	return nil
}

// Delete deletes a group
func (r *GroupRepository) Delete(ctx context.Context, id uuid.UUID) error {
	query := `DELETE FROM iam_groups WHERE id = $1 AND is_system = false`
	result, err := r.pool.Exec(ctx, query, id)
	if err != nil {
		return fmt.Errorf("failed to delete group: %w", err)
	}

	if result.RowsAffected() == 0 {
		return fmt.Errorf("group not found or is a system group")
	}

	return nil
}

// ==================== Group Members Operations ====================

// AddMember adds a user to a group
func (r *GroupRepository) AddMember(ctx context.Context, groupID, userID uuid.UUID, addedBy *uuid.UUID) error {
	query := `
		INSERT INTO iam_group_members (id, group_id, user_id, added_at, added_by)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (group_id, user_id) DO NOTHING`

	_, err := r.pool.Exec(ctx, query, uuid.New(), groupID, userID, time.Now(), addedBy)
	if err != nil {
		return fmt.Errorf("failed to add member to group: %w", err)
	}

	return nil
}

// RemoveMember removes a user from a group
func (r *GroupRepository) RemoveMember(ctx context.Context, groupID, userID uuid.UUID) error {
	query := `DELETE FROM iam_group_members WHERE group_id = $1 AND user_id = $2`
	_, err := r.pool.Exec(ctx, query, groupID, userID)
	if err != nil {
		return fmt.Errorf("failed to remove member from group: %w", err)
	}
	return nil
}

// GetMembers gets all members of a group
func (r *GroupRepository) GetMembers(ctx context.Context, groupID uuid.UUID, page, pageSize int) ([]*models.GroupMember, int, error) {
	offset := (page - 1) * pageSize

	// Count
	var total int
	err := r.pool.QueryRow(ctx, `SELECT COUNT(*) FROM iam_group_members WHERE group_id = $1`, groupID).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to count members: %w", err)
	}

	// List with user details
	query := `
		SELECT gm.id, gm.group_id, gm.user_id, gm.added_at, gm.added_by,
		       u.username, u.email, u.first_name, u.last_name, u.display_name, u.is_active
		FROM iam_group_members gm
		JOIN iam_users u ON u.id = gm.user_id
		WHERE gm.group_id = $1
		ORDER BY u.username
		LIMIT $2 OFFSET $3`

	rows, err := r.pool.Query(ctx, query, groupID, pageSize, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list members: %w", err)
	}
	defer rows.Close()

	var members []*models.GroupMember
	for rows.Next() {
		member := &models.GroupMember{
			User: &models.User{},
		}
		err := rows.Scan(
			&member.ID, &member.GroupID, &member.UserID, &member.AddedAt, &member.AddedBy,
			&member.User.Username, &member.User.Email, &member.User.FirstName,
			&member.User.LastName, &member.User.DisplayName, &member.User.IsActive,
		)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to scan member: %w", err)
		}
		member.User.ID = member.UserID
		// Decrypt JOINed PII so the API response carries plaintext.
		if err := r.encryptionService.DecryptStringInPlace(&member.User.Email); err != nil {
			return nil, 0, fmt.Errorf("GetMembers: decrypt email: %w", err)
		}
		if err := r.encryptionService.DecryptStringPtr(&member.User.FirstName); err != nil {
			return nil, 0, fmt.Errorf("GetMembers: decrypt first_name: %w", err)
		}
		if err := r.encryptionService.DecryptStringPtr(&member.User.LastName); err != nil {
			return nil, 0, fmt.Errorf("GetMembers: decrypt last_name: %w", err)
		}
		if err := r.encryptionService.DecryptStringPtr(&member.User.DisplayName); err != nil {
			return nil, 0, fmt.Errorf("GetMembers: decrypt display_name: %w", err)
		}
		members = append(members, member)
	}

	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("GetMembers: rows iteration: %w", err)
	}

	return members, total, nil
}

// GetUserGroups gets all groups a user belongs to
func (r *GroupRepository) GetUserGroups(ctx context.Context, userID uuid.UUID) ([]*models.Group, error) {
	query := `
		SELECT g.id, g.tenant_id, g.name, g.display_name, g.description, g.parent_group_id,
		       g.is_system, g.metadata, g.created_at, g.updated_at, g.created_by
		FROM iam_groups g
		JOIN iam_group_members gm ON gm.group_id = g.id
		WHERE gm.user_id = $1
		ORDER BY g.name`

	rows, err := r.pool.Query(ctx, query, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user groups: %w", err)
	}
	defer rows.Close()

	var groups []*models.Group
	for rows.Next() {
		group := &models.Group{}
		var metadataJSON []byte
		err := rows.Scan(
			&group.ID, &group.TenantID, &group.Name, &group.DisplayName, &group.Description,
			&group.ParentGroupID, &group.IsSystem, &metadataJSON, &group.CreatedAt,
			&group.UpdatedAt, &group.CreatedBy,
		)
		if err != nil {
			return nil, fmt.Errorf(msgFailedScanGroup, err)
		}
		if metadataJSON != nil {
			_ = json.Unmarshal(metadataJSON, &group.Metadata)
		}
		groups = append(groups, group)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("GetUserGroups: rows iteration: %w", err)
	}

	return groups, nil
}

// IsMember checks if a user is a member of a group
func (r *GroupRepository) IsMember(ctx context.Context, groupID, userID uuid.UUID) (bool, error) {
	var exists bool
	query := `SELECT EXISTS(SELECT 1 FROM iam_group_members WHERE group_id = $1 AND user_id = $2)`
	err := r.pool.QueryRow(ctx, query, groupID, userID).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("failed to check membership: %w", err)
	}
	return exists, nil
}

// ==================== Group Roles Operations ====================

// AssignRole assigns a role to a group
func (r *GroupRepository) AssignRole(ctx context.Context, groupID, roleID uuid.UUID, assignedBy *uuid.UUID) error {
	query := `
		INSERT INTO iam_group_roles (id, group_id, role_id, assigned_at, assigned_by)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (group_id, role_id) DO NOTHING`

	_, err := r.pool.Exec(ctx, query, uuid.New(), groupID, roleID, time.Now(), assignedBy)
	if err != nil {
		return fmt.Errorf("failed to assign role to group: %w", err)
	}

	return nil
}

// RemoveRole removes a role from a group
func (r *GroupRepository) RemoveRole(ctx context.Context, groupID, roleID uuid.UUID) error {
	query := `DELETE FROM iam_group_roles WHERE group_id = $1 AND role_id = $2`
	_, err := r.pool.Exec(ctx, query, groupID, roleID)
	if err != nil {
		return fmt.Errorf("failed to remove role from group: %w", err)
	}
	return nil
}

// GetRoles gets all roles assigned to a group
func (r *GroupRepository) GetRoles(ctx context.Context, groupID uuid.UUID) ([]*models.Role, error) {
	query := `
		SELECT r.id, r.tenant_id, r.name, r.display_name, r.description, r.is_system, r.is_default, r.priority
		FROM iam_roles r
		JOIN iam_group_roles gr ON gr.role_id = r.id
		WHERE gr.group_id = $1
		ORDER BY r.priority DESC, r.name`

	rows, err := r.pool.Query(ctx, query, groupID)
	if err != nil {
		return nil, fmt.Errorf("failed to get group roles: %w", err)
	}
	defer rows.Close()

	var roles []*models.Role
	for rows.Next() {
		role := &models.Role{}
		err := rows.Scan(
			&role.ID, &role.TenantID, &role.Name, &role.DisplayName, &role.Description,
			&role.IsSystem, &role.IsDefault, &role.Priority,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan role: %w", err)
		}
		roles = append(roles, role)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("GetRoles: rows iteration: %w", err)
	}

	return roles, nil
}

// GetUserEffectiveRoles gets all roles for a user including inherited from groups and organizations
func (r *GroupRepository) GetUserEffectiveRoles(ctx context.Context, userID uuid.UUID) ([]*models.EffectiveRole, error) {
	query := `SELECT role_id, role_name, source, source_id, source_name FROM get_user_effective_roles($1)`

	rows, err := r.pool.Query(ctx, query, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get effective roles: %w", err)
	}
	defer rows.Close()

	var roles []*models.EffectiveRole
	for rows.Next() {
		role := &models.EffectiveRole{}
		err := rows.Scan(&role.RoleID, &role.RoleName, &role.Source, &role.SourceID, &role.SourceName)
		if err != nil {
			return nil, fmt.Errorf("failed to scan effective role: %w", err)
		}
		roles = append(roles, role)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("GetUserEffectiveRoles: rows iteration: %w", err)
	}

	return roles, nil
}

// ==================== Hierarchy Operations ====================

// GetChildGroups gets all direct child groups
func (r *GroupRepository) GetChildGroups(ctx context.Context, parentID uuid.UUID) ([]*models.Group, error) {
	query := `
		SELECT g.id, g.tenant_id, g.name, g.display_name, g.description, g.parent_group_id,
		       g.is_system, g.metadata, g.created_at, g.updated_at, g.created_by,
		       (SELECT COUNT(*) FROM iam_group_members WHERE group_id = g.id) as member_count,
		       (SELECT COUNT(*) FROM iam_group_roles WHERE group_id = g.id) as role_count
		FROM iam_groups g
		WHERE g.parent_group_id = $1
		ORDER BY g.name`

	rows, err := r.pool.Query(ctx, query, parentID)
	if err != nil {
		return nil, fmt.Errorf("failed to get child groups: %w", err)
	}
	defer rows.Close()

	var groups []*models.Group
	for rows.Next() {
		group := &models.Group{}
		var metadataJSON []byte
		err := rows.Scan(
			&group.ID, &group.TenantID, &group.Name, &group.DisplayName, &group.Description,
			&group.ParentGroupID, &group.IsSystem, &metadataJSON, &group.CreatedAt,
			&group.UpdatedAt, &group.CreatedBy, &group.MemberCount, &group.RoleCount,
		)
		if err != nil {
			return nil, fmt.Errorf(msgFailedScanGroup, err)
		}
		if metadataJSON != nil {
			_ = json.Unmarshal(metadataJSON, &group.Metadata)
		}
		groups = append(groups, group)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("GetChildGroups: rows iteration: %w", err)
	}

	return groups, nil
}

// GetRootGroups gets all groups without a parent (top-level groups)
func (r *GroupRepository) GetRootGroups(ctx context.Context, tenantID uuid.UUID) ([]*models.Group, error) {
	query := `
		SELECT g.id, g.tenant_id, g.name, g.display_name, g.description, g.parent_group_id,
		       g.is_system, g.metadata, g.created_at, g.updated_at, g.created_by,
		       (SELECT COUNT(*) FROM iam_group_members WHERE group_id = g.id) as member_count,
		       (SELECT COUNT(*) FROM iam_group_roles WHERE group_id = g.id) as role_count
		FROM iam_groups g
		WHERE g.tenant_id = $1 AND g.parent_group_id IS NULL
		ORDER BY g.name`

	rows, err := r.pool.Query(ctx, query, tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to get root groups: %w", err)
	}
	defer rows.Close()

	var groups []*models.Group
	for rows.Next() {
		group := &models.Group{}
		var metadataJSON []byte
		err := rows.Scan(
			&group.ID, &group.TenantID, &group.Name, &group.DisplayName, &group.Description,
			&group.ParentGroupID, &group.IsSystem, &metadataJSON, &group.CreatedAt,
			&group.UpdatedAt, &group.CreatedBy, &group.MemberCount, &group.RoleCount,
		)
		if err != nil {
			return nil, fmt.Errorf(msgFailedScanGroup, err)
		}
		if metadataJSON != nil {
			_ = json.Unmarshal(metadataJSON, &group.Metadata)
		}
		groups = append(groups, group)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("GetRootGroups: rows iteration: %w", err)
	}

	return groups, nil
}
