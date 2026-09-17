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

// GuestUserRepositoryInterface declares all operations on guest users.
// Accepting an interface lets callers (services, tests) depend on the
// contract rather than the concrete type.
type GuestUserRepositoryInterface interface {
	Create(ctx context.Context, g *models.GuestUser) error
	GetByID(ctx context.Context, id uuid.UUID) (*models.GuestUser, error)
	GetByHomeUser(ctx context.Context, hostTenantID, homeUserID uuid.UUID) (*models.GuestUser, error)
	List(ctx context.Context, hostTenantID uuid.UUID, filter models.GuestUserListFilter) ([]*models.GuestUser, int64, error)
	Update(ctx context.Context, g *models.GuestUser) error
	Delete(ctx context.Context, id uuid.UUID) error

	// Role management
	AddRole(ctx context.Context, a *models.GuestRoleAssignment) error
	RemoveRole(ctx context.Context, guestUserID, roleID uuid.UUID) error
	ListRoles(ctx context.Context, guestUserID uuid.UUID) ([]*models.GuestRoleAssignment, error)

	// Access logging
	LogAccess(ctx context.Context, log *models.GuestAccessLog) error
}

// GuestUserRepository provides database access for B2B guest user records.
type GuestUserRepository struct {
	db DBPool
}

// NewGuestUserRepository constructs a GuestUserRepository backed by pool.
func NewGuestUserRepository(db *pgxpool.Pool) *GuestUserRepository {
	return &GuestUserRepository{db: db}
}

// Create inserts a new guest user record and back-fills server-set timestamps.
func (r *GuestUserRepository) Create(ctx context.Context, g *models.GuestUser) error {
	if g.ID == uuid.Nil {
		g.ID = uuid.New()
	}

	query := `
		INSERT INTO iam_guest_users (
			id, host_tenant_id, host_realm_id, home_tenant_id, home_user_id,
			email, display_name, guest_type, status,
			invited_by, invitation_message, expires_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
		RETURNING created_at, updated_at`

	return r.db.QueryRow(ctx, query,
		g.ID, g.HostTenantID, g.HostRealmID, g.HomeTenantID, g.HomeUserID,
		g.Email, g.DisplayName, g.GuestType, g.Status,
		g.InvitedBy, g.InvitationMessage, g.ExpiresAt,
	).Scan(&g.CreatedAt, &g.UpdatedAt)
}

// GetByID retrieves a guest user by primary key. Returns (nil, nil) when not found.
func (r *GuestUserRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.GuestUser, error) {
	g := &models.GuestUser{}
	query := `
		SELECT id, host_tenant_id, host_realm_id, home_tenant_id, home_user_id,
		       email, display_name, guest_type, status,
		       invited_by, invitation_message, accepted_at, expires_at,
		       last_access_at, access_count, created_at, updated_at
		FROM iam_guest_users
		WHERE id = $1`

	err := r.db.QueryRow(ctx, query, id).Scan(
		&g.ID, &g.HostTenantID, &g.HostRealmID, &g.HomeTenantID, &g.HomeUserID,
		&g.Email, &g.DisplayName, &g.GuestType, &g.Status,
		&g.InvitedBy, &g.InvitationMessage, &g.AcceptedAt, &g.ExpiresAt,
		&g.LastAccessAt, &g.AccessCount, &g.CreatedAt, &g.UpdatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("GuestUserRepository.GetByID: %w", err)
	}
	return g, nil
}

// GetByHomeUser fetches an existing guest record for the given home user in the given host tenant.
func (r *GuestUserRepository) GetByHomeUser(ctx context.Context, hostTenantID, homeUserID uuid.UUID) (*models.GuestUser, error) {
	g := &models.GuestUser{}
	query := `
		SELECT id, host_tenant_id, host_realm_id, home_tenant_id, home_user_id,
		       email, display_name, guest_type, status,
		       invited_by, invitation_message, accepted_at, expires_at,
		       last_access_at, access_count, created_at, updated_at
		FROM iam_guest_users
		WHERE host_tenant_id = $1 AND home_user_id = $2`

	err := r.db.QueryRow(ctx, query, hostTenantID, homeUserID).Scan(
		&g.ID, &g.HostTenantID, &g.HostRealmID, &g.HomeTenantID, &g.HomeUserID,
		&g.Email, &g.DisplayName, &g.GuestType, &g.Status,
		&g.InvitedBy, &g.InvitationMessage, &g.AcceptedAt, &g.ExpiresAt,
		&g.LastAccessAt, &g.AccessCount, &g.CreatedAt, &g.UpdatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("GuestUserRepository.GetByHomeUser: %w", err)
	}
	return g, nil
}

// List returns a filtered, paginated slice of guest users for a host tenant.
func (r *GuestUserRepository) List(ctx context.Context, hostTenantID uuid.UUID, filter models.GuestUserListFilter) ([]*models.GuestUser, int64, error) {
	args := []interface{}{hostTenantID}
	where := "WHERE host_tenant_id = $1"
	argIdx := 2

	if filter.Status != nil {
		where += fmt.Sprintf(" AND status = $%d", argIdx)
		args = append(args, *filter.Status)
		argIdx++
	}
	if filter.Email != "" {
		where += fmt.Sprintf(" AND email ILIKE $%d", argIdx)
		args = append(args, "%"+filter.Email+"%")
		argIdx++
	}

	// Count
	var total int64
	if err := r.db.QueryRow(ctx,
		"SELECT COUNT(*) FROM iam_guest_users "+where, args...,
	).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("GuestUserRepository.List count: %w", err)
	}

	// Page
	page := filter.Page
	if page < 1 {
		page = 1
	}
	pageSize := filter.PageSize
	if pageSize < 1 || pageSize > 200 {
		pageSize = 20
	}
	offset := (page - 1) * pageSize

	listQuery := `
		SELECT id, host_tenant_id, host_realm_id, home_tenant_id, home_user_id,
		       email, display_name, guest_type, status,
		       invited_by, invitation_message, accepted_at, expires_at,
		       last_access_at, access_count, created_at, updated_at
		FROM iam_guest_users ` + where + fmt.Sprintf(` ORDER BY created_at DESC LIMIT $%d OFFSET $%d`, argIdx, argIdx+1)
	args = append(args, pageSize, offset)

	rows, err := r.db.Query(ctx, listQuery, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("GuestUserRepository.List query: %w", err)
	}
	defer rows.Close()

	var guests []*models.GuestUser
	for rows.Next() {
		g := &models.GuestUser{}
		if err := rows.Scan(
			&g.ID, &g.HostTenantID, &g.HostRealmID, &g.HomeTenantID, &g.HomeUserID,
			&g.Email, &g.DisplayName, &g.GuestType, &g.Status,
			&g.InvitedBy, &g.InvitationMessage, &g.AcceptedAt, &g.ExpiresAt,
			&g.LastAccessAt, &g.AccessCount, &g.CreatedAt, &g.UpdatedAt,
		); err != nil {
			return nil, 0, fmt.Errorf("GuestUserRepository.List scan: %w", err)
		}
		guests = append(guests, g)
	}
	return guests, total, rows.Err()
}

// Update persists mutable fields to the database.
func (r *GuestUserRepository) Update(ctx context.Context, g *models.GuestUser) error {
	query := `
		UPDATE iam_guest_users SET
			guest_type = $1, status = $2, display_name = $3,
			expires_at = $4, accepted_at = $5,
			last_access_at = $6, access_count = $7,
			updated_at = NOW()
		WHERE id = $8
		RETURNING updated_at`

	err := r.db.QueryRow(ctx, query,
		g.GuestType, g.Status, g.DisplayName,
		g.ExpiresAt, g.AcceptedAt,
		g.LastAccessAt, g.AccessCount,
		g.ID,
	).Scan(&g.UpdatedAt)
	if err != nil {
		return fmt.Errorf("GuestUserRepository.Update: %w", err)
	}
	return nil
}

// Delete hard-deletes a guest user record.
func (r *GuestUserRepository) Delete(ctx context.Context, id uuid.UUID) error {
	_, err := r.db.Exec(ctx, `DELETE FROM iam_guest_users WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("GuestUserRepository.Delete: %w", err)
	}
	return nil
}

// AddRole assigns a host-tenant role to a guest user.
func (r *GuestUserRepository) AddRole(ctx context.Context, a *models.GuestRoleAssignment) error {
	if a.ID == uuid.Nil {
		a.ID = uuid.New()
	}
	query := `
		INSERT INTO iam_guest_role_assignments (id, guest_user_id, role_id, assigned_by, expires_at)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (guest_user_id, role_id) DO UPDATE SET
			assigned_by = EXCLUDED.assigned_by,
			assigned_at = NOW(),
			expires_at  = EXCLUDED.expires_at
		RETURNING assigned_at`

	return r.db.QueryRow(ctx, query, a.ID, a.GuestUserID, a.RoleID, a.AssignedBy, a.ExpiresAt).
		Scan(&a.AssignedAt)
}

// RemoveRole removes a role assignment from a guest user.
func (r *GuestUserRepository) RemoveRole(ctx context.Context, guestUserID, roleID uuid.UUID) error {
	_, err := r.db.Exec(ctx,
		`DELETE FROM iam_guest_role_assignments WHERE guest_user_id = $1 AND role_id = $2`,
		guestUserID, roleID,
	)
	if err != nil {
		return fmt.Errorf("GuestUserRepository.RemoveRole: %w", err)
	}
	return nil
}

// ListRoles returns all role assignments for a guest user.
func (r *GuestUserRepository) ListRoles(ctx context.Context, guestUserID uuid.UUID) ([]*models.GuestRoleAssignment, error) {
	rows, err := r.db.Query(ctx,
		`SELECT id, guest_user_id, role_id, assigned_by, assigned_at, expires_at
		 FROM iam_guest_role_assignments
		 WHERE guest_user_id = $1
		 ORDER BY assigned_at DESC`,
		guestUserID,
	)
	if err != nil {
		return nil, fmt.Errorf("GuestUserRepository.ListRoles: %w", err)
	}
	defer rows.Close()

	var assignments []*models.GuestRoleAssignment
	for rows.Next() {
		a := &models.GuestRoleAssignment{}
		if err := rows.Scan(&a.ID, &a.GuestUserID, &a.RoleID, &a.AssignedBy, &a.AssignedAt, &a.ExpiresAt); err != nil {
			return nil, fmt.Errorf("GuestUserRepository.ListRoles scan: %w", err)
		}
		assignments = append(assignments, a)
	}
	return assignments, rows.Err()
}

// LogAccess appends an immutable access log entry.
func (r *GuestUserRepository) LogAccess(ctx context.Context, log *models.GuestAccessLog) error {
	if log.ID == uuid.Nil {
		log.ID = uuid.New()
	}
	query := `
		INSERT INTO iam_guest_access_logs (
			id, guest_user_id, host_tenant_id, action,
			resource_type, resource_id, ip_address, user_agent, details
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		RETURNING created_at`

	return r.db.QueryRow(ctx, query,
		log.ID, log.GuestUserID, log.HostTenantID, log.Action,
		log.ResourceType, log.ResourceID, log.IPAddress, log.UserAgent, log.Details,
	).Scan(&log.CreatedAt)
}
