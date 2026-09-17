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

// newPermRepoMock creates a PermissionRepository backed by pgxmock.
func newPermRepoMock(t *testing.T) (*PermissionRepository, pgxmock.PgxPoolIface) {
	t.Helper()
	mock, err := pgxmock.NewPool()
	require.NoError(t, err)
	repo := &PermissionRepository{db: mock}
	return repo, mock
}

// permissionColumns returns the column list used by all permission queries.
func permissionColumns() []string {
	return []string{
		"id", "module", "resource", "action", "name",
		"display_name", "description", "is_system", "source", "created_at",
	}
}

func newTestPermission() *models.Permission {
	desc := "Read CRM contacts"
	return &models.Permission{
		ID:          uuid.New(),
		Module:      "crm",
		Resource:    "contacts",
		Action:      "read",
		Name:        "crm:contacts:read",
		DisplayName: "CRM Contacts Read",
		Description: &desc,
		IsSystem:    true,
		Source:      "seed",
		CreatedAt:   time.Now().UTC(),
	}
}

func permRow(p *models.Permission) []interface{} {
	return []interface{}{
		p.ID, p.Module, p.Resource, p.Action, p.Name,
		p.DisplayName, p.Description, p.IsSystem, p.Source, p.CreatedAt,
	}
}

// ─── RegisterPermissionsBatch ─────────────────────────────────────────────────

func TestPermissionRepository_RegisterPermissionsBatch(t *testing.T) {
	t.Run("registers new and updates existing permissions", func(t *testing.T) {
		repo, mock := newPermRepoMock(t)
		ctx := context.Background()

		p1 := newTestPermission()
		p2 := newTestPermission()
		p2.Name = "crm:contacts:write"
		p2.Action = "write"
		now := time.Now().UTC()

		mock.ExpectBegin()

		// p1 is new (xmax=0 → isInsert=true)
		mock.ExpectQuery(`INSERT INTO iam_permissions`).
			WithArgs(p1.Module, p1.Resource, p1.Action, p1.Name,
				p1.DisplayName, p1.Description, p1.IsSystem, p1.Source).
			WillReturnRows(pgxmock.NewRows([]string{"id", "created_at", "is_insert"}).
				AddRow(p1.ID, now, true))

		// p2 is an update (xmax!=0 → isInsert=false)
		mock.ExpectQuery(`INSERT INTO iam_permissions`).
			WithArgs(p2.Module, p2.Resource, p2.Action, p2.Name,
				p2.DisplayName, p2.Description, p2.IsSystem, p2.Source).
			WillReturnRows(pgxmock.NewRows([]string{"id", "created_at", "is_insert"}).
				AddRow(p2.ID, now, false))

		mock.ExpectCommit()

		registered, updated, err := repo.RegisterPermissionsBatch(ctx, []*models.Permission{p1, p2})
		require.NoError(t, err)
		assert.Equal(t, 1, registered)
		assert.Equal(t, 1, updated)
		require.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("begin error propagates", func(t *testing.T) {
		repo, mock := newPermRepoMock(t)
		ctx := context.Background()

		mock.ExpectBegin().WillReturnError(errors.New("begin failed"))

		_, _, err := repo.RegisterPermissionsBatch(ctx, []*models.Permission{newTestPermission()})
		require.Error(t, err)
		require.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("insert error causes rollback", func(t *testing.T) {
		repo, mock := newPermRepoMock(t)
		ctx := context.Background()

		p := newTestPermission()
		mock.ExpectBegin()
		mock.ExpectQuery(`INSERT INTO iam_permissions`).
			WithArgs(p.Module, p.Resource, p.Action, p.Name,
				p.DisplayName, p.Description, p.IsSystem, p.Source).
			WillReturnError(errors.New("unique violation"))
		mock.ExpectRollback()

		_, _, err := repo.RegisterPermissionsBatch(ctx, []*models.Permission{p})
		require.Error(t, err)
		require.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("commit error propagates", func(t *testing.T) {
		repo, mock := newPermRepoMock(t)
		ctx := context.Background()

		p := newTestPermission()
		now := time.Now().UTC()

		mock.ExpectBegin()
		mock.ExpectQuery(`INSERT INTO iam_permissions`).
			WithArgs(p.Module, p.Resource, p.Action, p.Name,
				p.DisplayName, p.Description, p.IsSystem, p.Source).
			WillReturnRows(pgxmock.NewRows([]string{"id", "created_at", "is_insert"}).
				AddRow(p.ID, now, true))
		mock.ExpectCommit().WillReturnError(errors.New("commit failed"))

		_, _, err := repo.RegisterPermissionsBatch(ctx, []*models.Permission{p})
		require.Error(t, err)
		require.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("empty batch commits with zero counts", func(t *testing.T) {
		repo, mock := newPermRepoMock(t)
		ctx := context.Background()

		mock.ExpectBegin()
		mock.ExpectCommit()

		registered, updated, err := repo.RegisterPermissionsBatch(ctx, []*models.Permission{})
		require.NoError(t, err)
		assert.Equal(t, 0, registered)
		assert.Equal(t, 0, updated)
		require.NoError(t, mock.ExpectationsWereMet())
	})
}

// ─── List ────────────────────────────────────────────────────────────────────

func TestPermissionRepository_List(t *testing.T) {
	t.Run("returns all permissions", func(t *testing.T) {
		repo, mock := newPermRepoMock(t)
		ctx := context.Background()

		p1 := newTestPermission()
		p2 := newTestPermission()
		p2.Name = "crm:contacts:write"

		rows := pgxmock.NewRows(permissionColumns()).
			AddRow(permRow(p1)...).
			AddRow(permRow(p2)...)

		mock.ExpectQuery(`SELECT .+ FROM iam_permissions`).
			WillReturnRows(rows)

		perms, err := repo.List(ctx)
		require.NoError(t, err)
		assert.Len(t, perms, 2)
		require.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("empty table returns empty slice", func(t *testing.T) {
		repo, mock := newPermRepoMock(t)
		ctx := context.Background()

		mock.ExpectQuery(`SELECT .+ FROM iam_permissions`).
			WillReturnRows(pgxmock.NewRows(permissionColumns()))

		perms, err := repo.List(ctx)
		require.NoError(t, err)
		assert.Empty(t, perms)
		require.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("db error propagates", func(t *testing.T) {
		repo, mock := newPermRepoMock(t)
		ctx := context.Background()

		mock.ExpectQuery(`SELECT .+ FROM iam_permissions`).
			WillReturnError(errors.New("db error"))

		_, err := repo.List(ctx)
		require.Error(t, err)
		require.NoError(t, mock.ExpectationsWereMet())
	})
}

// ─── ListByModule ────────────────────────────────────────────────────────────

func TestPermissionRepository_ListByModule(t *testing.T) {
	t.Run("returns permissions for module", func(t *testing.T) {
		repo, mock := newPermRepoMock(t)
		ctx := context.Background()

		p := newTestPermission()

		rows := pgxmock.NewRows(permissionColumns()).
			AddRow(permRow(p)...)

		mock.ExpectQuery(`SELECT .+ FROM iam_permissions WHERE module = \$1`).
			WithArgs("crm").
			WillReturnRows(rows)

		perms, err := repo.ListByModule(ctx, "crm")
		require.NoError(t, err)
		assert.Len(t, perms, 1)
		assert.Equal(t, "crm", perms[0].Module)
		require.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("unknown module returns empty slice", func(t *testing.T) {
		repo, mock := newPermRepoMock(t)
		ctx := context.Background()

		mock.ExpectQuery(`SELECT .+ FROM iam_permissions WHERE module = \$1`).
			WithArgs("nonexistent").
			WillReturnRows(pgxmock.NewRows(permissionColumns()))

		perms, err := repo.ListByModule(ctx, "nonexistent")
		require.NoError(t, err)
		assert.Empty(t, perms)
		require.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("db error propagates", func(t *testing.T) {
		repo, mock := newPermRepoMock(t)
		ctx := context.Background()

		mock.ExpectQuery(`SELECT .+ FROM iam_permissions WHERE module = \$1`).
			WithArgs("crm").
			WillReturnError(errors.New("timeout"))

		_, err := repo.ListByModule(ctx, "crm")
		require.Error(t, err)
		require.NoError(t, mock.ExpectationsWereMet())
	})
}

// ─── GetModules ──────────────────────────────────────────────────────────────

func TestPermissionRepository_GetModules(t *testing.T) {
	t.Run("returns distinct modules", func(t *testing.T) {
		repo, mock := newPermRepoMock(t)
		ctx := context.Background()

		rows := pgxmock.NewRows([]string{"module"}).
			AddRow("crm").
			AddRow("hr").
			AddRow("iam")

		mock.ExpectQuery(`SELECT DISTINCT module FROM iam_permissions ORDER BY module`).
			WillReturnRows(rows)

		modules, err := repo.GetModules(ctx)
		require.NoError(t, err)
		assert.Equal(t, []string{"crm", "hr", "iam"}, modules)
		require.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("no modules returns empty slice", func(t *testing.T) {
		repo, mock := newPermRepoMock(t)
		ctx := context.Background()

		mock.ExpectQuery(`SELECT DISTINCT module FROM iam_permissions`).
			WillReturnRows(pgxmock.NewRows([]string{"module"}))

		modules, err := repo.GetModules(ctx)
		require.NoError(t, err)
		assert.Empty(t, modules)
		require.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("db error propagates", func(t *testing.T) {
		repo, mock := newPermRepoMock(t)
		ctx := context.Background()

		mock.ExpectQuery(`SELECT DISTINCT module FROM iam_permissions`).
			WillReturnError(errors.New("db error"))

		_, err := repo.GetModules(ctx)
		require.Error(t, err)
		require.NoError(t, mock.ExpectationsWereMet())
	})
}
