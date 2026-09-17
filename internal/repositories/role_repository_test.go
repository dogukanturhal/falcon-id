// SPDX-License-Identifier: AGPL-3.0-or-later

package repositories

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/pashagolub/pgxmock/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

// newRoleRepoMock creates a RoleRepository backed by pgxmock for unit testing.
func newRoleRepoMock(t *testing.T) (*RoleRepository, pgxmock.PgxPoolIface) {
	t.Helper()
	mock, err := pgxmock.NewPool()
	require.NoError(t, err, "pgxmock.NewPool should not fail")
	repo := &RoleRepository{db: mock}
	return repo, mock
}

// ─── helpers ─────────────────────────────────────────────────────────────────

func roleColumns() []string {
	return []string{
		"id", "tenant_id", "name", "display_name", "description",
		"is_system", "is_default", "priority",
		"created_at", "updated_at", "created_by", "updated_by",
	}
}

func newTestRole(tenantID uuid.UUID) *models.Role {
	desc := "Test role description"
	createdBy := uuid.New()
	return &models.Role{
		ID:          uuid.New(),
		TenantID:    tenantID,
		Name:        "test-role",
		DisplayName: "Test Role",
		Description: &desc,
		IsSystem:    false,
		IsDefault:   false,
		Priority:    50,
		CreatedAt:   time.Now().UTC(),
		UpdatedAt:   time.Now().UTC(),
		CreatedBy:   &createdBy,
	}
}

// ─── Create ──────────────────────────────────────────────────────────────────

func TestRoleRepository_Create(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		repo, mock := newRoleRepoMock(t)
		ctx := context.Background()

		tenantID := uuid.New()
		role := newTestRole(tenantID)
		now := time.Now().UTC()

		mock.ExpectQuery(`INSERT INTO iam_roles`).
			WithArgs(role.ID, role.TenantID, role.Name, role.DisplayName, role.Description,
				role.IsSystem, role.IsDefault, role.Priority, role.CreatedBy).
			WillReturnRows(pgxmock.NewRows([]string{"created_at", "updated_at"}).
				AddRow(now, now))

		err := repo.Create(ctx, role)
		require.NoError(t, err)
		assert.Equal(t, now, role.CreatedAt)
		assert.Equal(t, now, role.UpdatedAt)
		require.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("generates UUID when nil", func(t *testing.T) {
		repo, mock := newRoleRepoMock(t)
		ctx := context.Background()

		role := &models.Role{
			ID:          uuid.Nil, // will be auto-generated
			TenantID:    uuid.New(),
			Name:        "auto-id-role",
			DisplayName: "Auto ID Role",
		}
		now := time.Now().UTC()

		mock.ExpectQuery(`INSERT INTO iam_roles`).
			WithArgs(
				pgxmock.AnyArg(), role.TenantID, role.Name, role.DisplayName, role.Description,
				role.IsSystem, role.IsDefault, role.Priority, role.CreatedBy,
			).
			WillReturnRows(pgxmock.NewRows([]string{"created_at", "updated_at"}).
				AddRow(now, now))

		err := repo.Create(ctx, role)
		require.NoError(t, err)
		assert.NotEqual(t, uuid.Nil, role.ID, "UUID should be generated")
		require.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("db error propagates", func(t *testing.T) {
		repo, mock := newRoleRepoMock(t)
		ctx := context.Background()

		role := newTestRole(uuid.New())
		dbErr := errors.New("connection refused")

		mock.ExpectQuery(`INSERT INTO iam_roles`).
			WithArgs(
				role.ID, role.TenantID, role.Name, role.DisplayName, role.Description,
				role.IsSystem, role.IsDefault, role.Priority, role.CreatedBy,
			).
			WillReturnError(dbErr)

		err := repo.Create(ctx, role)
		require.Error(t, err)
		assert.ErrorIs(t, err, dbErr)
		require.NoError(t, mock.ExpectationsWereMet())
	})
}

// ─── GetByID ─────────────────────────────────────────────────────────────────

func TestRoleRepository_GetByID(t *testing.T) {
	t.Run("found", func(t *testing.T) {
		repo, mock := newRoleRepoMock(t)
		ctx := context.Background()

		role := newTestRole(uuid.New())
		rows := pgxmock.NewRows(roleColumns()).
			AddRow(role.ID, role.TenantID, role.Name, role.DisplayName, role.Description,
				role.IsSystem, role.IsDefault, role.Priority,
				role.CreatedAt, role.UpdatedAt, role.CreatedBy, role.UpdatedBy)

		mock.ExpectQuery(`SELECT .+ FROM iam_roles WHERE id = \$1`).
			WithArgs(role.ID).
			WillReturnRows(rows)

		got, err := repo.GetByID(ctx, role.ID)
		require.NoError(t, err)
		require.NotNil(t, got)
		assert.Equal(t, role.ID, got.ID)
		assert.Equal(t, role.Name, got.Name)
		require.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("not found returns nil", func(t *testing.T) {
		repo, mock := newRoleRepoMock(t)
		ctx := context.Background()

		id := uuid.New()
		mock.ExpectQuery(`SELECT .+ FROM iam_roles WHERE id = \$1`).
			WithArgs(id).
			WillReturnRows(pgxmock.NewRows(roleColumns()))

		got, err := repo.GetByID(ctx, id)
		require.NoError(t, err)
		assert.Nil(t, got)
		require.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("db error propagates", func(t *testing.T) {
		repo, mock := newRoleRepoMock(t)
		ctx := context.Background()

		id := uuid.New()
		mock.ExpectQuery(`SELECT .+ FROM iam_roles WHERE id = \$1`).
			WithArgs(id).
			WillReturnError(errors.New("timeout"))

		got, err := repo.GetByID(ctx, id)
		require.Error(t, err)
		assert.Nil(t, got)
		require.NoError(t, mock.ExpectationsWereMet())
	})
}

// ─── GetByName ───────────────────────────────────────────────────────────────

func TestRoleRepository_GetByName(t *testing.T) {
	t.Run("found", func(t *testing.T) {
		repo, mock := newRoleRepoMock(t)
		ctx := context.Background()

		tenantID := uuid.New()
		role := newTestRole(tenantID)

		rows := pgxmock.NewRows(roleColumns()).
			AddRow(role.ID, role.TenantID, role.Name, role.DisplayName, role.Description,
				role.IsSystem, role.IsDefault, role.Priority,
				role.CreatedAt, role.UpdatedAt, role.CreatedBy, role.UpdatedBy)

		mock.ExpectQuery(`SELECT .+ FROM iam_roles WHERE tenant_id = \$1 AND name = \$2`).
			WithArgs(tenantID, "test-role").
			WillReturnRows(rows)

		got, err := repo.GetByName(ctx, tenantID, "test-role")
		require.NoError(t, err)
		require.NotNil(t, got)
		assert.Equal(t, "test-role", got.Name)
		require.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("not found returns nil", func(t *testing.T) {
		repo, mock := newRoleRepoMock(t)
		ctx := context.Background()

		tenantID := uuid.New()
		mock.ExpectQuery(`SELECT .+ FROM iam_roles WHERE tenant_id = \$1 AND name = \$2`).
			WithArgs(tenantID, "missing").
			WillReturnRows(pgxmock.NewRows(roleColumns()))

		got, err := repo.GetByName(ctx, tenantID, "missing")
		require.NoError(t, err)
		assert.Nil(t, got)
		require.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("db error propagates", func(t *testing.T) {
		repo, mock := newRoleRepoMock(t)
		ctx := context.Background()

		tenantID := uuid.New()
		mock.ExpectQuery(`SELECT .+ FROM iam_roles WHERE tenant_id = \$1 AND name = \$2`).
			WithArgs(tenantID, "any-name").
			WillReturnError(errors.New("db error"))

		_, err := repo.GetByName(ctx, tenantID, "any-name")
		require.Error(t, err)
		require.NoError(t, mock.ExpectationsWereMet())
	})
}

// ─── Update ──────────────────────────────────────────────────────────────────

func TestRoleRepository_Update(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		repo, mock := newRoleRepoMock(t)
		ctx := context.Background()

		role := newTestRole(uuid.New())
		updatedBy := uuid.New()
		role.UpdatedBy = &updatedBy
		newTime := time.Now().UTC()

		mock.ExpectQuery(`UPDATE iam_roles SET`).
			WithArgs(role.ID, role.DisplayName, role.Description, role.IsDefault, role.Priority, role.UpdatedBy).
			WillReturnRows(pgxmock.NewRows([]string{"updated_at"}).AddRow(newTime))

		err := repo.Update(ctx, role)
		require.NoError(t, err)
		assert.Equal(t, newTime, role.UpdatedAt)
		require.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("db error propagates", func(t *testing.T) {
		repo, mock := newRoleRepoMock(t)
		ctx := context.Background()

		role := newTestRole(uuid.New())
		mock.ExpectQuery(`UPDATE iam_roles SET`).
			WithArgs(
				role.ID, role.DisplayName, role.Description, role.IsDefault, role.Priority, role.UpdatedBy,
			).
			WillReturnError(errors.New("constraint violation"))

		err := repo.Update(ctx, role)
		require.Error(t, err)
		require.NoError(t, mock.ExpectationsWereMet())
	})
}

// ─── Delete ──────────────────────────────────────────────────────────────────

func TestRoleRepository_Delete(t *testing.T) {
	t.Run("success non-system role", func(t *testing.T) {
		repo, mock := newRoleRepoMock(t)
		ctx := context.Background()

		id := uuid.New()

		mock.ExpectQuery(`SELECT is_system FROM iam_roles WHERE id = \$1`).
			WithArgs(id).
			WillReturnRows(pgxmock.NewRows([]string{"is_system"}).AddRow(false))

		mock.ExpectExec(`DELETE FROM iam_roles WHERE id = \$1`).
			WithArgs(id).
			WillReturnResult(pgxmock.NewResult("DELETE", 1))

		err := repo.Delete(ctx, id)
		require.NoError(t, err)
		require.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("reject system role", func(t *testing.T) {
		repo, mock := newRoleRepoMock(t)
		ctx := context.Background()

		id := uuid.New()

		mock.ExpectQuery(`SELECT is_system FROM iam_roles WHERE id = \$1`).
			WithArgs(id).
			WillReturnRows(pgxmock.NewRows([]string{"is_system"}).AddRow(true))

		err := repo.Delete(ctx, id)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "cannot delete system role")
		require.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("check query error propagates", func(t *testing.T) {
		repo, mock := newRoleRepoMock(t)
		ctx := context.Background()

		id := uuid.New()
		mock.ExpectQuery(`SELECT is_system FROM iam_roles WHERE id = \$1`).
			WithArgs(id).
			WillReturnError(errors.New("db down"))

		err := repo.Delete(ctx, id)
		require.Error(t, err)
		require.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("delete exec error propagates", func(t *testing.T) {
		repo, mock := newRoleRepoMock(t)
		ctx := context.Background()

		id := uuid.New()

		mock.ExpectQuery(`SELECT is_system FROM iam_roles WHERE id = \$1`).
			WithArgs(id).
			WillReturnRows(pgxmock.NewRows([]string{"is_system"}).AddRow(false))

		mock.ExpectExec(`DELETE FROM iam_roles WHERE id = \$1`).
			WithArgs(id).
			WillReturnError(errors.New("delete failed"))

		err := repo.Delete(ctx, id)
		require.Error(t, err)
		require.NoError(t, mock.ExpectationsWereMet())
	})
}

// ─── List ────────────────────────────────────────────────────────────────────

func TestRoleRepository_List(t *testing.T) {
	t.Run("no search returns all roles", func(t *testing.T) {
		repo, mock := newRoleRepoMock(t)
		ctx := context.Background()

		tenantID := uuid.New()
		role1 := newTestRole(tenantID)
		role1.Name = "admin"
		role2 := newTestRole(tenantID)
		role2.Name = "user"

		// count query - only tenantID arg (no search)
		mock.ExpectQuery(`SELECT COUNT\(\*\) FROM iam_roles WHERE tenant_id = \$1`).
			WithArgs(tenantID).
			WillReturnRows(pgxmock.NewRows([]string{"count"}).AddRow(int64(2)))

		// list query - tenantID + pageSize + offset args (LIMIT/OFFSET parameterized)
		listRows := pgxmock.NewRows(roleColumns()).
			AddRow(role1.ID, role1.TenantID, role1.Name, role1.DisplayName, role1.Description,
				role1.IsSystem, role1.IsDefault, role1.Priority,
				role1.CreatedAt, role1.UpdatedAt, role1.CreatedBy, role1.UpdatedBy).
			AddRow(role2.ID, role2.TenantID, role2.Name, role2.DisplayName, role2.Description,
				role2.IsSystem, role2.IsDefault, role2.Priority,
				role2.CreatedAt, role2.UpdatedAt, role2.CreatedBy, role2.UpdatedBy)

		// LIMIT and OFFSET are embedded in SQL via fmt.Sprintf, not as query parameters
		mock.ExpectQuery(`SELECT .+ FROM iam_roles WHERE tenant_id = \$1`).
			WithArgs(tenantID).
			WillReturnRows(listRows)

		roles, total, err := repo.List(ctx, tenantID, 1, 10, "")
		require.NoError(t, err)
		assert.Equal(t, int64(2), total)
		assert.Len(t, roles, 2)
		require.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("with search filters roles", func(t *testing.T) {
		repo, mock := newRoleRepoMock(t)
		ctx := context.Background()

		tenantID := uuid.New()
		role := newTestRole(tenantID)
		role.Name = "admin"
		search := "adm"

		mock.ExpectQuery(`SELECT COUNT\(\*\) FROM iam_roles WHERE tenant_id = \$1`).
			WithArgs(tenantID, "%"+search+"%").
			WillReturnRows(pgxmock.NewRows([]string{"count"}).AddRow(int64(1)))

		listRows := pgxmock.NewRows(roleColumns()).
			AddRow(role.ID, role.TenantID, role.Name, role.DisplayName, role.Description,
				role.IsSystem, role.IsDefault, role.Priority,
				role.CreatedAt, role.UpdatedAt, role.CreatedBy, role.UpdatedBy)

		// LIMIT and OFFSET are embedded in SQL via fmt.Sprintf, not as query parameters
		mock.ExpectQuery(`SELECT .+ FROM iam_roles WHERE tenant_id = \$1`).
			WithArgs(tenantID, "%"+search+"%").
			WillReturnRows(listRows)

		roles, total, err := repo.List(ctx, tenantID, 1, 10, search)
		require.NoError(t, err)
		assert.Equal(t, int64(1), total)
		assert.Len(t, roles, 1)
		require.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("count error propagates", func(t *testing.T) {
		repo, mock := newRoleRepoMock(t)
		ctx := context.Background()

		tenantID := uuid.New()
		mock.ExpectQuery(`SELECT COUNT\(\*\) FROM iam_roles WHERE tenant_id = \$1`).
			WithArgs(tenantID).
			WillReturnError(errors.New("db error"))

		_, _, err := repo.List(ctx, tenantID, 1, 10, "")
		require.Error(t, err)
		require.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("list query error propagates", func(t *testing.T) {
		repo, mock := newRoleRepoMock(t)
		ctx := context.Background()

		tenantID := uuid.New()
		mock.ExpectQuery(`SELECT COUNT\(\*\) FROM iam_roles WHERE tenant_id = \$1`).
			WithArgs(tenantID).
			WillReturnRows(pgxmock.NewRows([]string{"count"}).AddRow(int64(1)))

		// LIMIT and OFFSET are embedded in SQL via fmt.Sprintf, not as query parameters
		mock.ExpectQuery(`SELECT .+ FROM iam_roles WHERE tenant_id = \$1`).
			WithArgs(tenantID).
			WillReturnError(errors.New("list error"))

		_, _, err := repo.List(ctx, tenantID, 1, 10, "")
		require.Error(t, err)
		require.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("empty result set returns empty slice", func(t *testing.T) {
		repo, mock := newRoleRepoMock(t)
		ctx := context.Background()

		tenantID := uuid.New()
		mock.ExpectQuery(`SELECT COUNT\(\*\) FROM iam_roles WHERE tenant_id = \$1`).
			WithArgs(tenantID).
			WillReturnRows(pgxmock.NewRows([]string{"count"}).AddRow(int64(0)))

		// LIMIT and OFFSET are embedded in SQL via fmt.Sprintf, not as query parameters
		mock.ExpectQuery(`SELECT .+ FROM iam_roles WHERE tenant_id = \$1`).
			WithArgs(tenantID).
			WillReturnRows(pgxmock.NewRows(roleColumns()))

		roles, total, err := repo.List(ctx, tenantID, 1, 10, "")
		require.NoError(t, err)
		assert.Equal(t, int64(0), total)
		assert.Empty(t, roles)
		require.NoError(t, mock.ExpectationsWereMet())
	})
}

// ─── AssignPermissions ───────────────────────────────────────────────────────

func TestRoleRepository_AssignPermissions(t *testing.T) {
	t.Run("assigns multiple permissions", func(t *testing.T) {
		repo, mock := newRoleRepoMock(t)
		ctx := context.Background()

		roleID := uuid.New()
		perm1 := uuid.New()
		perm2 := uuid.New()
		assignedBy := uuid.New()

		// Delete existing
		mock.ExpectExec(`DELETE FROM iam_role_permissions WHERE role_id = \$1`).
			WithArgs(roleID).
			WillReturnResult(pgxmock.NewResult("DELETE", 0))

		// Insert perm1
		mock.ExpectExec(`INSERT INTO iam_role_permissions`).
			WithArgs(roleID, perm1, &assignedBy).
			WillReturnResult(pgxmock.NewResult("INSERT", 1))

		// Insert perm2
		mock.ExpectExec(`INSERT INTO iam_role_permissions`).
			WithArgs(roleID, perm2, &assignedBy).
			WillReturnResult(pgxmock.NewResult("INSERT", 1))

		err := repo.AssignPermissions(ctx, roleID, []uuid.UUID{perm1, perm2}, &assignedBy)
		require.NoError(t, err)
		require.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("assigns zero permissions clears all", func(t *testing.T) {
		repo, mock := newRoleRepoMock(t)
		ctx := context.Background()

		roleID := uuid.New()
		assignedBy := uuid.New()

		mock.ExpectExec(`DELETE FROM iam_role_permissions WHERE role_id = \$1`).
			WithArgs(roleID).
			WillReturnResult(pgxmock.NewResult("DELETE", 3))

		err := repo.AssignPermissions(ctx, roleID, []uuid.UUID{}, &assignedBy)
		require.NoError(t, err)
		require.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("delete error propagates", func(t *testing.T) {
		repo, mock := newRoleRepoMock(t)
		ctx := context.Background()

		roleID := uuid.New()
		mock.ExpectExec(`DELETE FROM iam_role_permissions WHERE role_id = \$1`).
			WithArgs(roleID).
			WillReturnError(errors.New("delete error"))

		err := repo.AssignPermissions(ctx, roleID, []uuid.UUID{uuid.New()}, nil)
		require.Error(t, err)
		require.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("insert error propagates", func(t *testing.T) {
		repo, mock := newRoleRepoMock(t)
		ctx := context.Background()

		roleID := uuid.New()
		permID := uuid.New()

		mock.ExpectExec(`DELETE FROM iam_role_permissions WHERE role_id = \$1`).
			WithArgs(roleID).
			WillReturnResult(pgxmock.NewResult("DELETE", 0))

		mock.ExpectExec(`INSERT INTO iam_role_permissions`).
			WithArgs(roleID, permID, (*uuid.UUID)(nil)).
			WillReturnError(errors.New("insert error"))

		err := repo.AssignPermissions(ctx, roleID, []uuid.UUID{permID}, nil)
		require.Error(t, err)
		require.NoError(t, mock.ExpectationsWereMet())
	})
}

func TestRoleRepository_GrantPermissionsByName(t *testing.T) {
	t.Run("adds exact grants transactionally", func(t *testing.T) {
		repo, mock := newRoleRepoMock(t)
		ctx := context.Background()
		roleID := uuid.New()
		permissionNames := []string{"iam:invitations:read", "core:roles:read"}

		mock.ExpectBegin()
		mock.ExpectQuery(`SELECT COUNT\(DISTINCT name\)`).
			WithArgs(permissionNames).
			WillReturnRows(pgxmock.NewRows([]string{"count"}).AddRow(2))
		mock.ExpectExec(`INSERT INTO iam_role_permissions`).
			WithArgs(roleID, permissionNames).
			WillReturnResult(pgxmock.NewResult("INSERT", 2))
		mock.ExpectCommit()

		require.NoError(t, repo.GrantPermissionsByName(ctx, roleID, permissionNames))
		require.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("missing definition rolls back without partial grants", func(t *testing.T) {
		repo, mock := newRoleRepoMock(t)
		ctx := context.Background()
		permissionNames := []string{"iam:invitations:read", "core:roles:read"}

		mock.ExpectBegin()
		mock.ExpectQuery(`SELECT COUNT\(DISTINCT name\)`).
			WithArgs(permissionNames).
			WillReturnRows(pgxmock.NewRows([]string{"count"}).AddRow(1))
		mock.ExpectRollback()

		err := repo.GrantPermissionsByName(ctx, uuid.New(), permissionNames)
		require.ErrorContains(t, err, "resolved 1 of 2 required permissions")
		require.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("empty list is a no-op", func(t *testing.T) {
		repo, mock := newRoleRepoMock(t)
		require.NoError(t, repo.GrantPermissionsByName(context.Background(), uuid.New(), nil))
		require.NoError(t, mock.ExpectationsWereMet())
	})
}

// ─── GetRolePermissions ──────────────────────────────────────────────────────

func TestRoleRepository_GetRolePermissions(t *testing.T) {
	permCols := []string{
		"id", "module", "resource", "action", "name",
		"display_name", "description", "is_system", "created_at",
	}

	t.Run("returns permissions", func(t *testing.T) {
		repo, mock := newRoleRepoMock(t)
		ctx := context.Background()

		roleID := uuid.New()
		permID := uuid.New()
		desc := "perm description"
		now := time.Now().UTC()

		rows := pgxmock.NewRows(permCols).
			AddRow(permID, "crm", "contacts", "read", "crm:contacts:read",
				"CRM Read", &desc, true, now)

		mock.ExpectQuery(`SELECT p\.id.+ FROM iam_permissions p`).
			WithArgs(roleID).
			WillReturnRows(rows)

		perms, err := repo.GetRolePermissions(ctx, roleID)
		require.NoError(t, err)
		assert.Len(t, perms, 1)
		assert.Equal(t, permID, perms[0].ID)
		assert.Equal(t, "crm", perms[0].Module)
		require.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("empty permissions returns empty slice", func(t *testing.T) {
		repo, mock := newRoleRepoMock(t)
		ctx := context.Background()

		roleID := uuid.New()
		mock.ExpectQuery(`SELECT p\.id.+ FROM iam_permissions p`).
			WithArgs(roleID).
			WillReturnRows(pgxmock.NewRows(permCols))

		perms, err := repo.GetRolePermissions(ctx, roleID)
		require.NoError(t, err)
		assert.Empty(t, perms)
		require.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("db error propagates", func(t *testing.T) {
		repo, mock := newRoleRepoMock(t)
		ctx := context.Background()

		roleID := uuid.New()
		mock.ExpectQuery(`SELECT p\.id.+ FROM iam_permissions p`).
			WithArgs(roleID).
			WillReturnError(errors.New("query error"))

		_, err := repo.GetRolePermissions(ctx, roleID)
		require.Error(t, err)
		require.NoError(t, mock.ExpectationsWereMet())
	})
}

// ─── CreateSystemRoles ───────────────────────────────────────────────────────

func TestRoleRepository_CreateSystemRoles(t *testing.T) {
	t.Run("creates 4 system roles", func(t *testing.T) {
		repo, mock := newRoleRepoMock(t)
		ctx := context.Background()

		tenantID := uuid.New()
		now := time.Now().UTC()

		// 4 system roles: admin, manager, user, viewer
		for i := 0; i < 4; i++ {
			mock.ExpectQuery(`INSERT INTO iam_roles`).
				WithArgs(
					pgxmock.AnyArg(), // auto-generated ID
					tenantID,
					pgxmock.AnyArg(),  // name
					pgxmock.AnyArg(),  // display_name
					pgxmock.AnyArg(),  // description
					true,              // is_system
					pgxmock.AnyArg(),  // is_default
					pgxmock.AnyArg(),  // priority
					(*uuid.UUID)(nil), // created_by
				).
				WillReturnRows(pgxmock.NewRows([]string{"created_at", "updated_at"}).
					AddRow(now, now))
		}

		err := repo.CreateSystemRoles(ctx, tenantID)
		require.NoError(t, err)
		require.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("error on first role aborts", func(t *testing.T) {
		repo, mock := newRoleRepoMock(t)
		ctx := context.Background()

		tenantID := uuid.New()

		mock.ExpectQuery(`INSERT INTO iam_roles`).
			WithArgs(
				pgxmock.AnyArg(), tenantID,
				pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(),
				true, pgxmock.AnyArg(), pgxmock.AnyArg(), (*uuid.UUID)(nil),
			).
			WillReturnError(errors.New("role exists"))

		err := repo.CreateSystemRoles(ctx, tenantID)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "admin")
		require.NoError(t, mock.ExpectationsWereMet())
	})
}
