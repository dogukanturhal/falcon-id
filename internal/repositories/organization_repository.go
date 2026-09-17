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
	msgOrganizationNotFound   = "organization not found"
	msgFailedScanOrganization = "failed to scan organization: %w"
)

// OrganizationRepository handles organization database operations
type OrganizationRepository struct {
	pool              DBPool
	realmID           *uuid.UUID
	encryptionService *crypto.EncryptionService
}

// WithRealmID returns a shallow clone of OrganizationRepository scoped to the given realm.
func (r *OrganizationRepository) WithRealmID(realmID uuid.UUID) *OrganizationRepository {
	clone := *r
	clone.realmID = &realmID
	return &clone
}

// NewOrganizationRepository creates a new OrganizationRepository
func NewOrganizationRepository(pool *pgxpool.Pool) *OrganizationRepository {
	return &OrganizationRepository{pool: pool}
}

// SetEncryptionService wires the encryption service so JOINed iam_users PII
// (email/first_name/last_name/display_name) on member listings is decrypted
// post-scan. Without this, the org-members API surfaces ciphertext.
func (r *OrganizationRepository) SetEncryptionService(es *crypto.EncryptionService) {
	r.encryptionService = es
}

// ==================== Organization CRUD Operations ====================

// Create creates a new organization
func (r *OrganizationRepository) Create(ctx context.Context, org *models.Organization) error {
	metadataJSON, err := json.Marshal(org.Metadata)
	if err != nil {
		metadataJSON = []byte("{}")
	}

	query := `
		INSERT INTO iam_organizations (
			id, tenant_id, parent_id, name, display_name, description, org_type,
			code, metadata, is_active, created_at, updated_at, created_by
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
		RETURNING path, level`

	err = r.pool.QueryRow(ctx, query,
		org.ID, org.TenantID, org.ParentID, org.Name, org.DisplayName, org.Description,
		org.OrgType, org.Code, metadataJSON, org.IsActive, org.CreatedAt, org.UpdatedAt, org.CreatedBy,
	).Scan(&org.Path, &org.Level)
	if err != nil {
		return fmt.Errorf("failed to create organization: %w", err)
	}

	return nil
}

// GetByID retrieves an organization by ID
func (r *OrganizationRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.Organization, error) {
	query := `
		SELECT o.id, o.tenant_id, o.parent_id, o.name, o.display_name, o.description, o.org_type,
		       o.code, o.path, o.level, o.metadata, o.is_active, o.created_at, o.updated_at, o.created_by,
		       (SELECT COUNT(*) FROM iam_organization_members WHERE organization_id = o.id) as member_count,
		       (SELECT COUNT(*) FROM iam_organizations WHERE parent_id = o.id) as child_count
		FROM iam_organizations o
		WHERE o.id = $1`

	org := &models.Organization{}
	var metadataJSON []byte
	err := r.pool.QueryRow(ctx, query, id).Scan(
		&org.ID, &org.TenantID, &org.ParentID, &org.Name, &org.DisplayName, &org.Description,
		&org.OrgType, &org.Code, &org.Path, &org.Level, &metadataJSON, &org.IsActive,
		&org.CreatedAt, &org.UpdatedAt, &org.CreatedBy, &org.MemberCount, &org.ChildCount,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, errors.New(msgOrganizationNotFound)
		}
		return nil, fmt.Errorf("failed to get organization: %w", err)
	}

	if metadataJSON != nil {
		_ = json.Unmarshal(metadataJSON, &org.Metadata)
	}

	return org, nil
}

// GetByName retrieves an organization by name within a tenant
func (r *OrganizationRepository) GetByName(ctx context.Context, tenantID uuid.UUID, name string, parentID *uuid.UUID) (*models.Organization, error) {
	query := `
		SELECT o.id, o.tenant_id, o.parent_id, o.name, o.display_name, o.description, o.org_type,
		       o.code, o.path, o.level, o.metadata, o.is_active, o.created_at, o.updated_at, o.created_by
		FROM iam_organizations o
		WHERE o.tenant_id = $1 AND o.name = $2`

	args := []interface{}{tenantID, name}
	if parentID != nil {
		query += " AND o.parent_id = $3"
		args = append(args, *parentID)
	} else {
		query += " AND o.parent_id IS NULL"
	}

	org := &models.Organization{}
	var metadataJSON []byte
	err := r.pool.QueryRow(ctx, query, args...).Scan(
		&org.ID, &org.TenantID, &org.ParentID, &org.Name, &org.DisplayName, &org.Description,
		&org.OrgType, &org.Code, &org.Path, &org.Level, &metadataJSON, &org.IsActive,
		&org.CreatedAt, &org.UpdatedAt, &org.CreatedBy,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, errors.New(msgOrganizationNotFound)
		}
		return nil, fmt.Errorf("failed to get organization: %w", err)
	}

	if metadataJSON != nil {
		_ = json.Unmarshal(metadataJSON, &org.Metadata)
	}

	return org, nil
}

// List lists all organizations for a tenant with pagination
func (r *OrganizationRepository) List(ctx context.Context, tenantID uuid.UUID, page, pageSize int, search string, orgType string) ([]*models.Organization, int, error) {
	offset := (page - 1) * pageSize

	// Build count query
	countQuery := `SELECT COUNT(*) FROM iam_organizations WHERE tenant_id = $1`
	args := []interface{}{tenantID}
	argCount := 1

	if search != "" {
		argCount++
		countQuery += fmt.Sprintf(` AND (name ILIKE $%d OR display_name ILIKE $%d OR description ILIKE $%d)`, argCount, argCount, argCount)
		args = append(args, "%"+search+"%")
	}
	if orgType != "" {
		argCount++
		countQuery += fmt.Sprintf(` AND org_type = $%d`, argCount)
		args = append(args, orgType)
	}

	var total int
	err := r.pool.QueryRow(ctx, countQuery, args...).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to count organizations: %w", err)
	}

	// Build list query
	listQuery := `
		SELECT o.id, o.tenant_id, o.parent_id, o.name, o.display_name, o.description, o.org_type,
		       o.code, o.path, o.level, o.metadata, o.is_active, o.created_at, o.updated_at, o.created_by,
		       (SELECT COUNT(*) FROM iam_organization_members WHERE organization_id = o.id) as member_count,
		       (SELECT COUNT(*) FROM iam_organizations WHERE parent_id = o.id) as child_count
		FROM iam_organizations o
		WHERE o.tenant_id = $1`

	if search != "" {
		listQuery += ` AND (o.name ILIKE $2 OR o.display_name ILIKE $2 OR o.description ILIKE $2)`
	}
	if orgType != "" {
		if search != "" {
			listQuery += ` AND o.org_type = $3`
		} else {
			listQuery += ` AND o.org_type = $2`
		}
	}

	listQuery += ` ORDER BY o.path, o.name`
	listQuery += fmt.Sprintf(` LIMIT $%d OFFSET $%d`, len(args)+1, len(args)+2)
	args = append(args, pageSize, offset)

	rows, err := r.pool.Query(ctx, listQuery, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list organizations: %w", err)
	}
	defer rows.Close()

	var orgs []*models.Organization
	for rows.Next() {
		org := &models.Organization{}
		var metadataJSON []byte
		err := rows.Scan(
			&org.ID, &org.TenantID, &org.ParentID, &org.Name, &org.DisplayName, &org.Description,
			&org.OrgType, &org.Code, &org.Path, &org.Level, &metadataJSON, &org.IsActive,
			&org.CreatedAt, &org.UpdatedAt, &org.CreatedBy, &org.MemberCount, &org.ChildCount,
		)
		if err != nil {
			return nil, 0, fmt.Errorf(msgFailedScanOrganization, err)
		}
		if metadataJSON != nil {
			_ = json.Unmarshal(metadataJSON, &org.Metadata)
		}
		orgs = append(orgs, org)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("List: rows iteration: %w", err)
	}

	return orgs, total, nil
}

// Update updates an organization
func (r *OrganizationRepository) Update(ctx context.Context, org *models.Organization) error {
	metadataJSON, err := json.Marshal(org.Metadata)
	if err != nil {
		metadataJSON = []byte("{}")
	}

	query := `
		UPDATE iam_organizations SET
			name = $1, display_name = $2, description = $3, parent_id = $4,
			org_type = $5, code = $6, metadata = $7, is_active = $8, updated_at = $9
		WHERE id = $10
		RETURNING path, level`

	err = r.pool.QueryRow(ctx, query,
		org.Name, org.DisplayName, org.Description, org.ParentID,
		org.OrgType, org.Code, metadataJSON, org.IsActive, time.Now(), org.ID,
	).Scan(&org.Path, &org.Level)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return errors.New(msgOrganizationNotFound)
		}
		return fmt.Errorf("failed to update organization: %w", err)
	}

	return nil
}

// Delete deletes an organization
func (r *OrganizationRepository) Delete(ctx context.Context, id uuid.UUID) error {
	query := `DELETE FROM iam_organizations WHERE id = $1`
	result, err := r.pool.Exec(ctx, query, id)
	if err != nil {
		return fmt.Errorf("failed to delete organization: %w", err)
	}

	if result.RowsAffected() == 0 {
		return errors.New(msgOrganizationNotFound)
	}

	return nil
}

// ==================== Organization Members Operations ====================

// AddMember adds a user to an organization
func (r *OrganizationRepository) AddMember(ctx context.Context, orgID, userID uuid.UUID, role string, title *string, isPrimary bool, addedBy *uuid.UUID) error {
	if role == "" {
		role = models.OrgRoleMember
	}

	// If this is primary, unset other primary memberships for this user
	if isPrimary {
		_, err := r.pool.Exec(ctx,
			`UPDATE iam_organization_members SET is_primary = false WHERE user_id = $1`,
			userID,
		)
		if err != nil {
			return fmt.Errorf("failed to unset primary membership: %w", err)
		}
	}

	query := `
		INSERT INTO iam_organization_members (id, organization_id, user_id, role, title, is_primary, joined_at, joined_by)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		ON CONFLICT (organization_id, user_id) DO UPDATE SET
			role = EXCLUDED.role,
			title = EXCLUDED.title,
			is_primary = EXCLUDED.is_primary`

	_, err := r.pool.Exec(ctx, query, uuid.New(), orgID, userID, role, title, isPrimary, time.Now(), addedBy)
	if err != nil {
		return fmt.Errorf("failed to add member to organization: %w", err)
	}

	return nil
}

// RemoveMember removes a user from an organization
func (r *OrganizationRepository) RemoveMember(ctx context.Context, orgID, userID uuid.UUID) error {
	query := `DELETE FROM iam_organization_members WHERE organization_id = $1 AND user_id = $2`
	_, err := r.pool.Exec(ctx, query, orgID, userID)
	if err != nil {
		return fmt.Errorf("failed to remove member from organization: %w", err)
	}
	return nil
}

// UpdateMember updates a member's role/title
func (r *OrganizationRepository) UpdateMember(ctx context.Context, orgID, userID uuid.UUID, role *string, title *string, isPrimary *bool) error {
	// Build dynamic update query
	setClauses := []string{}
	args := []interface{}{}
	argCount := 0

	if role != nil {
		argCount++
		setClauses = append(setClauses, fmt.Sprintf("role = $%d", argCount))
		args = append(args, *role)
	}
	if title != nil {
		argCount++
		setClauses = append(setClauses, fmt.Sprintf("title = $%d", argCount))
		args = append(args, *title)
	}
	if isPrimary != nil {
		if *isPrimary {
			// Unset other primary memberships for this user
			_, err := r.pool.Exec(ctx,
				`UPDATE iam_organization_members SET is_primary = false WHERE user_id = $1`,
				userID,
			)
			if err != nil {
				return fmt.Errorf("failed to unset primary membership: %w", err)
			}
		}
		argCount++
		setClauses = append(setClauses, fmt.Sprintf("is_primary = $%d", argCount))
		args = append(args, *isPrimary)
	}

	if len(setClauses) == 0 {
		return nil
	}

	query := "UPDATE iam_organization_members SET "
	for i, clause := range setClauses {
		if i > 0 {
			query += ", "
		}
		query += clause
	}
	query += fmt.Sprintf(" WHERE organization_id = $%d AND user_id = $%d", argCount+1, argCount+2)
	args = append(args, orgID, userID)

	_, err := r.pool.Exec(ctx, query, args...)
	if err != nil {
		return fmt.Errorf("failed to update member: %w", err)
	}

	return nil
}

// GetMembers gets all members of an organization
func (r *OrganizationRepository) GetMembers(ctx context.Context, orgID uuid.UUID, page, pageSize int) ([]*models.OrgMember, int, error) {
	offset := (page - 1) * pageSize

	// Count
	var total int
	err := r.pool.QueryRow(ctx, `SELECT COUNT(*) FROM iam_organization_members WHERE organization_id = $1`, orgID).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to count members: %w", err)
	}

	// List with user details
	query := `
		SELECT om.id, om.organization_id, om.user_id, om.role, om.title, om.is_primary, om.joined_at, om.joined_by,
		       u.username, u.email, u.first_name, u.last_name, u.display_name, u.is_active
		FROM iam_organization_members om
		JOIN iam_users u ON u.id = om.user_id
		WHERE om.organization_id = $1
		ORDER BY
			CASE om.role
				WHEN 'owner' THEN 1
				WHEN 'lead' THEN 2
				WHEN 'manager' THEN 3
				ELSE 4
			END,
			u.username
		LIMIT $2 OFFSET $3`

	rows, err := r.pool.Query(ctx, query, orgID, pageSize, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list members: %w", err)
	}
	defer rows.Close()

	var members []*models.OrgMember
	for rows.Next() {
		member := &models.OrgMember{
			User: &models.User{},
		}
		err := rows.Scan(
			&member.ID, &member.OrganizationID, &member.UserID, &member.Role, &member.Title,
			&member.IsPrimary, &member.JoinedAt, &member.JoinedBy,
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

// GetUserOrganizations gets all organizations a user belongs to
func (r *OrganizationRepository) GetUserOrganizations(ctx context.Context, userID uuid.UUID) ([]*models.OrgMember, error) {
	query := `
		SELECT om.id, om.organization_id, om.user_id, om.role, om.title, om.is_primary, om.joined_at,
		       o.name, o.display_name, o.org_type, o.level
		FROM iam_organization_members om
		JOIN iam_organizations o ON o.id = om.organization_id
		WHERE om.user_id = $1
		ORDER BY om.is_primary DESC, o.name`

	rows, err := r.pool.Query(ctx, query, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user organizations: %w", err)
	}
	defer rows.Close()

	var members []*models.OrgMember
	for rows.Next() {
		member := &models.OrgMember{
			Organization: &models.Organization{},
		}
		err := rows.Scan(
			&member.ID, &member.OrganizationID, &member.UserID, &member.Role, &member.Title,
			&member.IsPrimary, &member.JoinedAt,
			&member.Organization.Name, &member.Organization.DisplayName, &member.Organization.OrgType,
			&member.Organization.Level,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan membership: %w", err)
		}
		member.Organization.ID = member.OrganizationID
		members = append(members, member)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("GetUserOrganizations: rows iteration: %w", err)
	}

	return members, nil
}

// GetUserPrimaryOrganization gets a user's primary organization
func (r *OrganizationRepository) GetUserPrimaryOrganization(ctx context.Context, userID uuid.UUID) (*models.OrgMember, error) {
	query := `
		SELECT om.id, om.organization_id, om.user_id, om.role, om.title, om.is_primary, om.joined_at,
		       o.id, o.name, o.display_name, o.org_type, o.level
		FROM iam_organization_members om
		JOIN iam_organizations o ON o.id = om.organization_id
		WHERE om.user_id = $1 AND om.is_primary = true
		LIMIT 1`

	member := &models.OrgMember{
		Organization: &models.Organization{},
	}
	err := r.pool.QueryRow(ctx, query, userID).Scan(
		&member.ID, &member.OrganizationID, &member.UserID, &member.Role, &member.Title,
		&member.IsPrimary, &member.JoinedAt,
		&member.Organization.ID, &member.Organization.Name, &member.Organization.DisplayName,
		&member.Organization.OrgType, &member.Organization.Level,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get primary organization: %w", err)
	}

	return member, nil
}

// ==================== Organization Role Assignment Operations ====================

// GetOrgRoleAssignments gets all IAM roles assigned to an organization.
func (r *OrganizationRepository) GetOrgRoleAssignments(ctx context.Context, orgID uuid.UUID) ([]models.OrgRoleAssignment, error) {
	query := `
		SELECT orr.id, orr.organization_id, orr.role_id, r.name, COALESCE(r.display_name, r.name),
		       orr.inherit, orr.assigned_at, orr.assigned_by
		FROM iam_organization_roles orr
		JOIN iam_roles r ON r.id = orr.role_id
		WHERE orr.organization_id = $1
		ORDER BY r.name`

	rows, err := r.pool.Query(ctx, query, orgID)
	if err != nil {
		return nil, fmt.Errorf("GetOrgRoleAssignments: %w", err)
	}
	defer rows.Close()

	var result []models.OrgRoleAssignment
	for rows.Next() {
		var a models.OrgRoleAssignment
		if err := rows.Scan(
			&a.ID, &a.OrganizationID, &a.RoleID, &a.RoleName, &a.RoleDisplayName,
			&a.Inherit, &a.AssignedAt, &a.AssignedBy,
		); err != nil {
			return nil, fmt.Errorf("GetOrgRoleAssignments scan: %w", err)
		}
		result = append(result, a)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("GetOrgRoleAssignments: rows iteration: %w", err)
	}
	if result == nil {
		result = []models.OrgRoleAssignment{}
	}
	return result, nil
}

// AssignOrgRole assigns (or upserts) a role to an organization.
func (r *OrganizationRepository) AssignOrgRole(ctx context.Context, orgID, roleID uuid.UUID, inherit bool, assignedBy *uuid.UUID) error {
	query := `
		INSERT INTO iam_organization_roles (organization_id, role_id, inherit, assigned_by)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (organization_id, role_id) DO UPDATE SET inherit = EXCLUDED.inherit`
	if _, err := r.pool.Exec(ctx, query, orgID, roleID, inherit, assignedBy); err != nil {
		return fmt.Errorf("AssignOrgRole: %w", err)
	}
	return nil
}

// RemoveOrgRole removes a role from an organization.
func (r *OrganizationRepository) RemoveOrgRole(ctx context.Context, orgID, roleID uuid.UUID) error {
	if _, err := r.pool.Exec(ctx,
		`DELETE FROM iam_organization_roles WHERE organization_id = $1 AND role_id = $2`,
		orgID, roleID,
	); err != nil {
		return fmt.Errorf("RemoveOrgRole: %w", err)
	}
	return nil
}

// ==================== Hierarchy Operations ====================

// GetChildren gets all direct children of an organization
func (r *OrganizationRepository) GetChildren(ctx context.Context, parentID uuid.UUID) ([]*models.Organization, error) {
	query := `
		SELECT o.id, o.tenant_id, o.parent_id, o.name, o.display_name, o.description, o.org_type,
		       o.code, o.path, o.level, o.metadata, o.is_active, o.created_at, o.updated_at, o.created_by,
		       (SELECT COUNT(*) FROM iam_organization_members WHERE organization_id = o.id) as member_count,
		       (SELECT COUNT(*) FROM iam_organizations WHERE parent_id = o.id) as child_count
		FROM iam_organizations o
		WHERE o.parent_id = $1 AND o.is_active = true
		ORDER BY o.name`

	rows, err := r.pool.Query(ctx, query, parentID)
	if err != nil {
		return nil, fmt.Errorf("failed to get children: %w", err)
	}
	defer rows.Close()

	var orgs []*models.Organization
	for rows.Next() {
		org := &models.Organization{}
		var metadataJSON []byte
		err := rows.Scan(
			&org.ID, &org.TenantID, &org.ParentID, &org.Name, &org.DisplayName, &org.Description,
			&org.OrgType, &org.Code, &org.Path, &org.Level, &metadataJSON, &org.IsActive,
			&org.CreatedAt, &org.UpdatedAt, &org.CreatedBy, &org.MemberCount, &org.ChildCount,
		)
		if err != nil {
			return nil, fmt.Errorf(msgFailedScanOrganization, err)
		}
		if metadataJSON != nil {
			_ = json.Unmarshal(metadataJSON, &org.Metadata)
		}
		orgs = append(orgs, org)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("GetChildren: rows iteration: %w", err)
	}

	return orgs, nil
}

// GetRootOrganizations gets all root organizations (no parent)
func (r *OrganizationRepository) GetRootOrganizations(ctx context.Context, tenantID uuid.UUID) ([]*models.Organization, error) {
	query := `
		SELECT o.id, o.tenant_id, o.parent_id, o.name, o.display_name, o.description, o.org_type,
		       o.code, o.path, o.level, o.metadata, o.is_active, o.created_at, o.updated_at, o.created_by,
		       (SELECT COUNT(*) FROM iam_organization_members WHERE organization_id = o.id) as member_count,
		       (SELECT COUNT(*) FROM iam_organizations WHERE parent_id = o.id) as child_count
		FROM iam_organizations o
		WHERE o.tenant_id = $1 AND o.parent_id IS NULL AND o.is_active = true
		ORDER BY o.name`

	rows, err := r.pool.Query(ctx, query, tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to get root organizations: %w", err)
	}
	defer rows.Close()

	var orgs []*models.Organization
	for rows.Next() {
		org := &models.Organization{}
		var metadataJSON []byte
		err := rows.Scan(
			&org.ID, &org.TenantID, &org.ParentID, &org.Name, &org.DisplayName, &org.Description,
			&org.OrgType, &org.Code, &org.Path, &org.Level, &metadataJSON, &org.IsActive,
			&org.CreatedAt, &org.UpdatedAt, &org.CreatedBy, &org.MemberCount, &org.ChildCount,
		)
		if err != nil {
			return nil, fmt.Errorf(msgFailedScanOrganization, err)
		}
		if metadataJSON != nil {
			_ = json.Unmarshal(metadataJSON, &org.Metadata)
		}
		orgs = append(orgs, org)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("GetRootOrganizations: rows iteration: %w", err)
	}

	return orgs, nil
}

// GetDescendants gets all descendants of an organization
func (r *OrganizationRepository) GetDescendants(ctx context.Context, orgID uuid.UUID) ([]*models.Organization, error) {
	query := `SELECT id, name, display_name, level, path FROM get_organization_descendants($1)`

	rows, err := r.pool.Query(ctx, query, orgID)
	if err != nil {
		return nil, fmt.Errorf("failed to get descendants: %w", err)
	}
	defer rows.Close()

	var orgs []*models.Organization
	for rows.Next() {
		org := &models.Organization{}
		err := rows.Scan(&org.ID, &org.Name, &org.DisplayName, &org.Level, &org.Path)
		if err != nil {
			return nil, fmt.Errorf("failed to scan descendant: %w", err)
		}
		orgs = append(orgs, org)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("GetDescendants: rows iteration: %w", err)
	}

	return orgs, nil
}

// GetAncestors gets all ancestors of an organization
func (r *OrganizationRepository) GetAncestors(ctx context.Context, orgID uuid.UUID) ([]*models.Organization, error) {
	query := `SELECT id, name, display_name, level FROM get_organization_ancestors($1)`

	rows, err := r.pool.Query(ctx, query, orgID)
	if err != nil {
		return nil, fmt.Errorf("failed to get ancestors: %w", err)
	}
	defer rows.Close()

	var orgs []*models.Organization
	for rows.Next() {
		org := &models.Organization{}
		err := rows.Scan(&org.ID, &org.Name, &org.DisplayName, &org.Level)
		if err != nil {
			return nil, fmt.Errorf("failed to scan ancestor: %w", err)
		}
		orgs = append(orgs, org)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("GetAncestors: rows iteration: %w", err)
	}

	return orgs, nil
}
