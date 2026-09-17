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

// newGroupRepoMock creates a GroupRepository backed by pgxmock.
func newGroupRepoMock(t *testing.T) (*GroupRepository, pgxmock.PgxPoolIface) {
	t.Helper()
	mock, err := pgxmock.NewPool()
	require.NoError(t, err)
	repo := &GroupRepository{pool: mock}
	return repo, mock
}

// groupColumns returns the full column list returned by group SELECT queries
// that include member_count and role_count.
func groupColumns() []string {
	return []string{
		"id", "tenant_id", "name", "display_name", "description",
		"parent_group_id", "is_system", "metadata",
		"created_at", "updated_at", "created_by",
		"member_count", "role_count",
	}
}

// groupColumnsBasic is the subset returned by queries without counts (e.g. GetUserGroups).
func groupColumnsBasic() []string {
	return []string{
		"id", "tenant_id", "name", "display_name", "description",
		"parent_group_id", "is_system", "metadata",
		"created_at", "updated_at", "created_by",
	}
}

func newTestGroup(tenantID uuid.UUID) *models.Group {
	name := "Engineering"
	desc := "Engineering department"
	createdBy := uuid.New()
	return &models.Group{
		ID:          uuid.New(),
		TenantID:    tenantID,
		Name:        "engineering",
		DisplayName: &name,
		Description: &desc,
		IsSystem:    false,
		Metadata:    map[string]interface{}{"dept": "eng"},
		CreatedAt:   time.Now().UTC(),
		UpdatedAt:   time.Now().UTC(),
		CreatedBy:   &createdBy,
	}
}

func groupRow(g *models.Group) []interface{} {
	return []interface{}{
		g.ID, g.TenantID, g.Name, g.DisplayName, g.Description,
		g.ParentGroupID, g.IsSystem, []byte(`{"dept":"eng"}`),
		g.CreatedAt, g.UpdatedAt, g.CreatedBy,
		g.MemberCount, g.RoleCount,
	}
}

func groupRowBasic(g *models.Group) []interface{} {
	return []interface{}{
		g.ID, g.TenantID, g.Name, g.DisplayName, g.Description,
		g.ParentGroupID, g.IsSystem, []byte(`{}`),
		g.CreatedAt, g.UpdatedAt, g.CreatedBy,
	}
}

// ─── Create ──────────────────────────────────────────────────────────────────

func TestGroupRepository_Create(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		repo, mock := newGroupRepoMock(t)
		ctx := context.Background()

		g := newTestGroup(uuid.New())

		mock.ExpectExec(`INSERT INTO iam_groups`).
			WithArgs(
				g.ID, g.TenantID, g.Name, g.DisplayName, g.Description,
				g.ParentGroupID, g.IsSystem, pgxmock.AnyArg(), // metadataJSON
				g.CreatedAt, g.UpdatedAt, g.CreatedBy,
			).
			WillReturnResult(pgxmock.NewResult("INSERT", 1))

		err := repo.Create(ctx, g)
		require.NoError(t, err)
		require.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("db error propagates", func(t *testing.T) {
		repo, mock := newGroupRepoMock(t)
		ctx := context.Background()

		g := newTestGroup(uuid.New())
		mock.ExpectExec(`INSERT INTO iam_groups`).
			WithArgs(
				g.ID, g.TenantID, g.Name, g.DisplayName, g.Description,
				g.ParentGroupID, g.IsSystem, pgxmock.AnyArg(),
				g.CreatedAt, g.UpdatedAt, g.CreatedBy,
			).
			WillReturnError(errors.New("unique violation"))

		err := repo.Create(ctx, g)
		require.Error(t, err)
		require.NoError(t, mock.ExpectationsWereMet())
	})
}

// ─── GetByID ─────────────────────────────────────────────────────────────────

func TestGroupRepository_GetByID(t *testing.T) {
	t.Run("found", func(t *testing.T) {
		repo, mock := newGroupRepoMock(t)
		ctx := context.Background()

		g := newTestGroup(uuid.New())
		rows := pgxmock.NewRows(groupColumns()).AddRow(groupRow(g)...)

		mock.ExpectQuery(`SELECT g\.id.+ FROM iam_groups g\s+WHERE g\.id = \$1`).
			WithArgs(g.ID).
			WillReturnRows(rows)

		got, err := repo.GetByID(ctx, g.ID)
		require.NoError(t, err)
		require.NotNil(t, got)
		assert.Equal(t, g.ID, got.ID)
		assert.Equal(t, g.Name, got.Name)
		require.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("not found returns error", func(t *testing.T) {
		repo, mock := newGroupRepoMock(t)
		ctx := context.Background()

		id := uuid.New()
		mock.ExpectQuery(`SELECT g\.id.+`).
			WithArgs(id).
			WillReturnRows(pgxmock.NewRows(groupColumns()))

		got, err := repo.GetByID(ctx, id)
		require.Error(t, err)
		assert.Nil(t, got)
		assert.Contains(t, err.Error(), "group not found")
		require.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("db error propagates", func(t *testing.T) {
		repo, mock := newGroupRepoMock(t)
		ctx := context.Background()

		id := uuid.New()
		mock.ExpectQuery(`SELECT g\.id.+`).
			WithArgs(id).
			WillReturnError(errors.New("connection error"))

		_, err := repo.GetByID(ctx, id)
		require.Error(t, err)
		require.NoError(t, mock.ExpectationsWereMet())
	})
}

// ─── GetByName ───────────────────────────────────────────────────────────────

func TestGroupRepository_GetByName(t *testing.T) {
	t.Run("found", func(t *testing.T) {
		repo, mock := newGroupRepoMock(t)
		ctx := context.Background()

		tenantID := uuid.New()
		g := newTestGroup(tenantID)
		rows := pgxmock.NewRows(groupColumns()).AddRow(groupRow(g)...)

		mock.ExpectQuery(`SELECT g\.id.+ WHERE g\.tenant_id = \$1 AND g\.name = \$2`).
			WithArgs(tenantID, g.Name).
			WillReturnRows(rows)

		got, err := repo.GetByName(ctx, tenantID, g.Name)
		require.NoError(t, err)
		require.NotNil(t, got)
		assert.Equal(t, g.Name, got.Name)
		require.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("not found returns error", func(t *testing.T) {
		repo, mock := newGroupRepoMock(t)
		ctx := context.Background()

		tenantID := uuid.New()
		mock.ExpectQuery(`SELECT g\.id.+`).
			WithArgs(tenantID, "missing").
			WillReturnRows(pgxmock.NewRows(groupColumns()))

		_, err := repo.GetByName(ctx, tenantID, "missing")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "group not found")
		require.NoError(t, mock.ExpectationsWereMet())
	})
}

// ─── List ────────────────────────────────────────────────────────────────────

func TestGroupRepository_List(t *testing.T) {
	t.Run("no search returns all groups with pagination", func(t *testing.T) {
		repo, mock := newGroupRepoMock(t)
		ctx := context.Background()

		tenantID := uuid.New()
		g1 := newTestGroup(tenantID)
		g1.Name = "alpha"
		g2 := newTestGroup(tenantID)
		g2.Name = "beta"

		// count query
		mock.ExpectQuery(`SELECT COUNT\(\*\) FROM iam_groups WHERE tenant_id = \$1`).
			WithArgs(tenantID).
			WillReturnRows(pgxmock.NewRows([]string{"count"}).AddRow(2))

		// list query (without search: args are tenantID, pageSize, offset)
		listRows := pgxmock.NewRows(groupColumns()).
			AddRow(groupRow(g1)...).
			AddRow(groupRow(g2)...)

		mock.ExpectQuery(`SELECT g\.id.+ WHERE g\.tenant_id = \$1`).
			WithArgs(tenantID, 10, 0).
			WillReturnRows(listRows)

		groups, total, err := repo.List(ctx, tenantID, 1, 10, "")
		require.NoError(t, err)
		assert.Equal(t, 2, total)
		assert.Len(t, groups, 2)
		require.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("with search filters groups", func(t *testing.T) {
		repo, mock := newGroupRepoMock(t)
		ctx := context.Background()

		tenantID := uuid.New()
		g := newTestGroup(tenantID)
		g.Name = "engineering"
		search := "eng"

		mock.ExpectQuery(`SELECT COUNT\(\*\) FROM iam_groups WHERE tenant_id = \$1`).
			WithArgs(tenantID, "%"+search+"%").
			WillReturnRows(pgxmock.NewRows([]string{"count"}).AddRow(1))

		listRows := pgxmock.NewRows(groupColumns()).AddRow(groupRow(g)...)

		mock.ExpectQuery(`SELECT g\.id.+ WHERE g\.tenant_id = \$1`).
			WithArgs(tenantID, "%"+search+"%", 10, 0).
			WillReturnRows(listRows)

		groups, total, err := repo.List(ctx, tenantID, 1, 10, search)
		require.NoError(t, err)
		assert.Equal(t, 1, total)
		assert.Len(t, groups, 1)
		require.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("count error propagates", func(t *testing.T) {
		repo, mock := newGroupRepoMock(t)
		ctx := context.Background()

		tenantID := uuid.New()
		mock.ExpectQuery(`SELECT COUNT\(\*\) FROM iam_groups`).
			WithArgs(tenantID).
			WillReturnError(errors.New("db error"))

		_, _, err := repo.List(ctx, tenantID, 1, 10, "")
		require.Error(t, err)
		require.NoError(t, mock.ExpectationsWereMet())
	})
}

// ─── Update ──────────────────────────────────────────────────────────────────

func TestGroupRepository_Update(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		repo, mock := newGroupRepoMock(t)
		ctx := context.Background()

		g := newTestGroup(uuid.New())

		mock.ExpectExec(`UPDATE iam_groups SET`).
			WithArgs(
				g.Name, g.DisplayName, g.Description, g.ParentGroupID,
				pgxmock.AnyArg(), // metadataJSON
				pgxmock.AnyArg(), // time.Now()
				g.ID,
			).
			WillReturnResult(pgxmock.NewResult("UPDATE", 1))

		err := repo.Update(ctx, g)
		require.NoError(t, err)
		require.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("not found returns error", func(t *testing.T) {
		repo, mock := newGroupRepoMock(t)
		ctx := context.Background()

		g := newTestGroup(uuid.New())
		mock.ExpectExec(`UPDATE iam_groups SET`).
			WithArgs(
				g.Name, g.DisplayName, g.Description, g.ParentGroupID,
				pgxmock.AnyArg(), pgxmock.AnyArg(), g.ID,
			).
			WillReturnResult(pgxmock.NewResult("UPDATE", 0))

		err := repo.Update(ctx, g)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "group not found")
		require.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("db error propagates", func(t *testing.T) {
		repo, mock := newGroupRepoMock(t)
		ctx := context.Background()

		g := newTestGroup(uuid.New())
		mock.ExpectExec(`UPDATE iam_groups SET`).
			WithArgs(
				g.Name, g.DisplayName, g.Description, g.ParentGroupID,
				pgxmock.AnyArg(), pgxmock.AnyArg(), g.ID,
			).
			WillReturnError(errors.New("constraint error"))

		err := repo.Update(ctx, g)
		require.Error(t, err)
		require.NoError(t, mock.ExpectationsWereMet())
	})
}

// ─── Delete ──────────────────────────────────────────────────────────────────

func TestGroupRepository_Delete(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		repo, mock := newGroupRepoMock(t)
		ctx := context.Background()

		id := uuid.New()
		mock.ExpectExec(`DELETE FROM iam_groups WHERE id = \$1 AND is_system = false`).
			WithArgs(id).
			WillReturnResult(pgxmock.NewResult("DELETE", 1))

		err := repo.Delete(ctx, id)
		require.NoError(t, err)
		require.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("not found or system group returns error", func(t *testing.T) {
		repo, mock := newGroupRepoMock(t)
		ctx := context.Background()

		id := uuid.New()
		mock.ExpectExec(`DELETE FROM iam_groups`).
			WithArgs(id).
			WillReturnResult(pgxmock.NewResult("DELETE", 0))

		err := repo.Delete(ctx, id)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "group not found or is a system group")
		require.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("db error propagates", func(t *testing.T) {
		repo, mock := newGroupRepoMock(t)
		ctx := context.Background()

		id := uuid.New()
		mock.ExpectExec(`DELETE FROM iam_groups`).
			WithArgs(id).
			WillReturnError(errors.New("delete error"))

		err := repo.Delete(ctx, id)
		require.Error(t, err)
		require.NoError(t, mock.ExpectationsWereMet())
	})
}

// ─── AddMember ───────────────────────────────────────────────────────────────

func TestGroupRepository_AddMember(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		repo, mock := newGroupRepoMock(t)
		ctx := context.Background()

		groupID := uuid.New()
		userID := uuid.New()
		addedBy := uuid.New()

		mock.ExpectExec(`INSERT INTO iam_group_members`).
			WithArgs(pgxmock.AnyArg(), groupID, userID, pgxmock.AnyArg(), &addedBy).
			WillReturnResult(pgxmock.NewResult("INSERT", 1))

		err := repo.AddMember(ctx, groupID, userID, &addedBy)
		require.NoError(t, err)
		require.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("db error propagates", func(t *testing.T) {
		repo, mock := newGroupRepoMock(t)
		ctx := context.Background()

		groupID := uuid.New()
		userID := uuid.New()
		mock.ExpectExec(`INSERT INTO iam_group_members`).
			WithArgs(pgxmock.AnyArg(), groupID, userID, pgxmock.AnyArg(), (*uuid.UUID)(nil)).
			WillReturnError(errors.New("fk violation"))

		err := repo.AddMember(ctx, groupID, userID, nil)
		require.Error(t, err)
		require.NoError(t, mock.ExpectationsWereMet())
	})
}

// ─── RemoveMember ────────────────────────────────────────────────────────────

func TestGroupRepository_RemoveMember(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		repo, mock := newGroupRepoMock(t)
		ctx := context.Background()

		groupID := uuid.New()
		userID := uuid.New()

		mock.ExpectExec(`DELETE FROM iam_group_members WHERE group_id = \$1 AND user_id = \$2`).
			WithArgs(groupID, userID).
			WillReturnResult(pgxmock.NewResult("DELETE", 1))

		err := repo.RemoveMember(ctx, groupID, userID)
		require.NoError(t, err)
		require.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("db error propagates", func(t *testing.T) {
		repo, mock := newGroupRepoMock(t)
		ctx := context.Background()

		groupID := uuid.New()
		userID := uuid.New()
		mock.ExpectExec(`DELETE FROM iam_group_members`).
			WithArgs(groupID, userID).
			WillReturnError(errors.New("db error"))

		err := repo.RemoveMember(ctx, groupID, userID)
		require.Error(t, err)
		require.NoError(t, mock.ExpectationsWereMet())
	})
}

// ─── GetMembers ──────────────────────────────────────────────────────────────

func TestGroupRepository_GetMembers(t *testing.T) {
	memberCols := []string{
		"id", "group_id", "user_id", "added_at", "added_by",
		"username", "email", "first_name", "last_name", "display_name", "is_active",
	}

	t.Run("returns members with user details", func(t *testing.T) {
		repo, mock := newGroupRepoMock(t)
		ctx := context.Background()

		groupID := uuid.New()
		memberID := uuid.New()
		userID := uuid.New()
		addedBy := uuid.New()
		firstName := "John"
		lastName := "Doe"
		displayName := "John Doe"

		// count query
		mock.ExpectQuery(`SELECT COUNT\(\*\) FROM iam_group_members WHERE group_id = \$1`).
			WithArgs(groupID).
			WillReturnRows(pgxmock.NewRows([]string{"count"}).AddRow(1))

		// list query
		rows := pgxmock.NewRows(memberCols).
			AddRow(memberID, groupID, userID, time.Now(), &addedBy,
				"jdoe", "john@example.com", &firstName, &lastName, &displayName, true)

		mock.ExpectQuery(`SELECT gm\.id.+ FROM iam_group_members gm`).
			WithArgs(groupID, 10, 0).
			WillReturnRows(rows)

		members, total, err := repo.GetMembers(ctx, groupID, 1, 10)
		require.NoError(t, err)
		assert.Equal(t, 1, total)
		assert.Len(t, members, 1)
		assert.Equal(t, userID, members[0].UserID)
		assert.Equal(t, "jdoe", members[0].User.Username)
		require.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("count error propagates", func(t *testing.T) {
		repo, mock := newGroupRepoMock(t)
		ctx := context.Background()

		groupID := uuid.New()
		mock.ExpectQuery(`SELECT COUNT\(\*\) FROM iam_group_members`).
			WithArgs(groupID).
			WillReturnError(errors.New("db error"))

		_, _, err := repo.GetMembers(ctx, groupID, 1, 10)
		require.Error(t, err)
		require.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("empty group returns empty members", func(t *testing.T) {
		repo, mock := newGroupRepoMock(t)
		ctx := context.Background()

		groupID := uuid.New()

		mock.ExpectQuery(`SELECT COUNT\(\*\) FROM iam_group_members`).
			WithArgs(groupID).
			WillReturnRows(pgxmock.NewRows([]string{"count"}).AddRow(0))

		mock.ExpectQuery(`SELECT gm\.id.+`).
			WithArgs(groupID, 10, 0).
			WillReturnRows(pgxmock.NewRows(memberCols))

		members, total, err := repo.GetMembers(ctx, groupID, 1, 10)
		require.NoError(t, err)
		assert.Equal(t, 0, total)
		assert.Empty(t, members)
		require.NoError(t, mock.ExpectationsWereMet())
	})
}

// ─── AssignRole ──────────────────────────────────────────────────────────────

func TestGroupRepository_AssignRole(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		repo, mock := newGroupRepoMock(t)
		ctx := context.Background()

		groupID := uuid.New()
		roleID := uuid.New()
		assignedBy := uuid.New()

		mock.ExpectExec(`INSERT INTO iam_group_roles`).
			WithArgs(pgxmock.AnyArg(), groupID, roleID, pgxmock.AnyArg(), &assignedBy).
			WillReturnResult(pgxmock.NewResult("INSERT", 1))

		err := repo.AssignRole(ctx, groupID, roleID, &assignedBy)
		require.NoError(t, err)
		require.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("db error propagates", func(t *testing.T) {
		repo, mock := newGroupRepoMock(t)
		ctx := context.Background()

		groupID := uuid.New()
		roleID := uuid.New()
		mock.ExpectExec(`INSERT INTO iam_group_roles`).
			WithArgs(pgxmock.AnyArg(), groupID, roleID, pgxmock.AnyArg(), (*uuid.UUID)(nil)).
			WillReturnError(errors.New("fk error"))

		err := repo.AssignRole(ctx, groupID, roleID, nil)
		require.Error(t, err)
		require.NoError(t, mock.ExpectationsWereMet())
	})
}

// ─── RemoveRole ──────────────────────────────────────────────────────────────

func TestGroupRepository_RemoveRole(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		repo, mock := newGroupRepoMock(t)
		ctx := context.Background()

		groupID := uuid.New()
		roleID := uuid.New()

		mock.ExpectExec(`DELETE FROM iam_group_roles WHERE group_id = \$1 AND role_id = \$2`).
			WithArgs(groupID, roleID).
			WillReturnResult(pgxmock.NewResult("DELETE", 1))

		err := repo.RemoveRole(ctx, groupID, roleID)
		require.NoError(t, err)
		require.NoError(t, mock.ExpectationsWereMet())
	})
}

// ─── GetRoles ────────────────────────────────────────────────────────────────

func TestGroupRepository_GetRoles(t *testing.T) {
	roleCols := []string{
		"id", "tenant_id", "name", "display_name", "description",
		"is_system", "is_default", "priority",
	}

	t.Run("returns group roles", func(t *testing.T) {
		repo, mock := newGroupRepoMock(t)
		ctx := context.Background()

		groupID := uuid.New()
		roleID := uuid.New()
		tenantID := uuid.New()
		desc := "Admin role"

		rows := pgxmock.NewRows(roleCols).
			AddRow(roleID, tenantID, "admin", "Administrator", &desc, true, false, 100)

		mock.ExpectQuery(`SELECT r\.id.+ FROM iam_roles r\s+JOIN iam_group_roles gr`).
			WithArgs(groupID).
			WillReturnRows(rows)

		roles, err := repo.GetRoles(ctx, groupID)
		require.NoError(t, err)
		assert.Len(t, roles, 1)
		assert.Equal(t, "admin", roles[0].Name)
		require.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("no roles returns empty", func(t *testing.T) {
		repo, mock := newGroupRepoMock(t)
		ctx := context.Background()

		groupID := uuid.New()
		mock.ExpectQuery(`SELECT r\.id.+`).
			WithArgs(groupID).
			WillReturnRows(pgxmock.NewRows(roleCols))

		roles, err := repo.GetRoles(ctx, groupID)
		require.NoError(t, err)
		assert.Empty(t, roles)
		require.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("db error propagates", func(t *testing.T) {
		repo, mock := newGroupRepoMock(t)
		ctx := context.Background()

		groupID := uuid.New()
		mock.ExpectQuery(`SELECT r\.id.+`).
			WithArgs(groupID).
			WillReturnError(errors.New("query error"))

		_, err := repo.GetRoles(ctx, groupID)
		require.Error(t, err)
		require.NoError(t, mock.ExpectationsWereMet())
	})
}

// ─── GetChildGroups ──────────────────────────────────────────────────────────

func TestGroupRepository_GetChildGroups(t *testing.T) {
	t.Run("returns children", func(t *testing.T) {
		repo, mock := newGroupRepoMock(t)
		ctx := context.Background()

		parentID := uuid.New()
		tenantID := uuid.New()
		child := newTestGroup(tenantID)
		pID := parentID
		child.ParentGroupID = &pID

		rows := pgxmock.NewRows(groupColumns()).AddRow(groupRow(child)...)

		mock.ExpectQuery(`SELECT g\.id.+ WHERE g\.parent_group_id = \$1`).
			WithArgs(parentID).
			WillReturnRows(rows)

		children, err := repo.GetChildGroups(ctx, parentID)
		require.NoError(t, err)
		assert.Len(t, children, 1)
		assert.Equal(t, child.ID, children[0].ID)
		require.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("no children returns empty", func(t *testing.T) {
		repo, mock := newGroupRepoMock(t)
		ctx := context.Background()

		parentID := uuid.New()
		mock.ExpectQuery(`SELECT g\.id.+ WHERE g\.parent_group_id = \$1`).
			WithArgs(parentID).
			WillReturnRows(pgxmock.NewRows(groupColumns()))

		children, err := repo.GetChildGroups(ctx, parentID)
		require.NoError(t, err)
		assert.Empty(t, children)
		require.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("db error propagates", func(t *testing.T) {
		repo, mock := newGroupRepoMock(t)
		ctx := context.Background()

		parentID := uuid.New()
		mock.ExpectQuery(`SELECT g\.id.+`).
			WithArgs(parentID).
			WillReturnError(errors.New("db error"))

		_, err := repo.GetChildGroups(ctx, parentID)
		require.Error(t, err)
		require.NoError(t, mock.ExpectationsWereMet())
	})
}

// ─── GetRootGroups ───────────────────────────────────────────────────────────

func TestGroupRepository_GetRootGroups(t *testing.T) {
	t.Run("returns root groups for tenant", func(t *testing.T) {
		repo, mock := newGroupRepoMock(t)
		ctx := context.Background()

		tenantID := uuid.New()
		g := newTestGroup(tenantID)

		rows := pgxmock.NewRows(groupColumns()).AddRow(groupRow(g)...)

		mock.ExpectQuery(`SELECT g\.id.+ WHERE g\.tenant_id = \$1 AND g\.parent_group_id IS NULL`).
			WithArgs(tenantID).
			WillReturnRows(rows)

		groups, err := repo.GetRootGroups(ctx, tenantID)
		require.NoError(t, err)
		assert.Len(t, groups, 1)
		require.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("db error propagates", func(t *testing.T) {
		repo, mock := newGroupRepoMock(t)
		ctx := context.Background()

		tenantID := uuid.New()
		mock.ExpectQuery(`SELECT g\.id.+`).
			WithArgs(tenantID).
			WillReturnError(errors.New("db error"))

		_, err := repo.GetRootGroups(ctx, tenantID)
		require.Error(t, err)
		require.NoError(t, mock.ExpectationsWereMet())
	})
}

// ─── GetUserGroups ───────────────────────────────────────────────────────────

func TestGroupRepository_GetUserGroups(t *testing.T) {
	t.Run("returns groups user belongs to", func(t *testing.T) {
		repo, mock := newGroupRepoMock(t)
		ctx := context.Background()

		userID := uuid.New()
		tenantID := uuid.New()
		g := newTestGroup(tenantID)

		rows := pgxmock.NewRows(groupColumnsBasic()).
			AddRow(groupRowBasic(g)...)

		mock.ExpectQuery(`SELECT g\.id.+ FROM iam_groups g\s+JOIN iam_group_members gm`).
			WithArgs(userID).
			WillReturnRows(rows)

		groups, err := repo.GetUserGroups(ctx, userID)
		require.NoError(t, err)
		assert.Len(t, groups, 1)
		require.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("user in no groups returns empty", func(t *testing.T) {
		repo, mock := newGroupRepoMock(t)
		ctx := context.Background()

		userID := uuid.New()
		mock.ExpectQuery(`SELECT g\.id.+`).
			WithArgs(userID).
			WillReturnRows(pgxmock.NewRows(groupColumnsBasic()))

		groups, err := repo.GetUserGroups(ctx, userID)
		require.NoError(t, err)
		assert.Empty(t, groups)
		require.NoError(t, mock.ExpectationsWereMet())
	})
}

// ─── GetUserEffectiveRoles ───────────────────────────────────────────────────

func TestGroupRepository_GetUserEffectiveRoles(t *testing.T) {
	effectiveCols := []string{"role_id", "role_name", "source", "source_id", "source_name"}

	t.Run("returns direct and group-inherited roles", func(t *testing.T) {
		repo, mock := newGroupRepoMock(t)
		ctx := context.Background()

		userID := uuid.New()
		directRoleID := uuid.New()
		groupRoleID := uuid.New()
		groupSourceID := uuid.New()

		rows := pgxmock.NewRows(effectiveCols).
			AddRow(directRoleID, "admin", "direct", nil, nil).
			AddRow(groupRoleID, "viewer", "group", &groupSourceID, nil)

		mock.ExpectQuery(`SELECT role_id, role_name, source, source_id, source_name FROM get_user_effective_roles\(\$1\)`).
			WithArgs(userID).
			WillReturnRows(rows)

		roles, err := repo.GetUserEffectiveRoles(ctx, userID)
		require.NoError(t, err)
		assert.Len(t, roles, 2)
		assert.Equal(t, "direct", roles[0].Source)
		assert.Equal(t, "group", roles[1].Source)
		require.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("db error propagates", func(t *testing.T) {
		repo, mock := newGroupRepoMock(t)
		ctx := context.Background()

		userID := uuid.New()
		mock.ExpectQuery(`SELECT .+ FROM get_user_effective_roles`).
			WithArgs(userID).
			WillReturnError(errors.New("function not found"))

		_, err := repo.GetUserEffectiveRoles(ctx, userID)
		require.Error(t, err)
		require.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("user with no roles returns empty", func(t *testing.T) {
		repo, mock := newGroupRepoMock(t)
		ctx := context.Background()

		userID := uuid.New()
		mock.ExpectQuery(`SELECT .+ FROM get_user_effective_roles`).
			WithArgs(userID).
			WillReturnRows(pgxmock.NewRows(effectiveCols))

		roles, err := repo.GetUserEffectiveRoles(ctx, userID)
		require.NoError(t, err)
		assert.Empty(t, roles)
		require.NoError(t, mock.ExpectationsWereMet())
	})
}
