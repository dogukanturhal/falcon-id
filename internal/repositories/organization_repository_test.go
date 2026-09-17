// SPDX-License-Identifier: AGPL-3.0-or-later

package repositories

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/pashagolub/pgxmock/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

const (
	testOrgSlug = "test-org"
)

func newOrganizationMock(t *testing.T) (pgxmock.PgxPoolIface, *OrganizationRepository) {
	t.Helper()
	mock, err := pgxmock.NewPool()
	require.NoError(t, err)
	return mock, newOrganizationRepositoryWithMock(mock)
}

var orgCols = []string{
	"id", "tenant_id", "parent_id", "name", "display_name", "description", "org_type",
	"code", "path", "level", "metadata", "is_active", "created_at", "updated_at", "created_by",
	"member_count", "child_count",
}

var orgColsNoCount = []string{
	"id", "tenant_id", "parent_id", "name", "display_name", "description", "org_type",
	"code", "path", "level", "metadata", "is_active", "created_at", "updated_at", "created_by",
}

func sampleOrganization() *models.Organization {
	displayName := "Test Organization"
	return &models.Organization{
		ID:          uuid.New(),
		TenantID:    uuid.New(),
		Name:        testOrgSlug,
		DisplayName: &displayName,
		OrgType:     models.OrgTypeDepartment,
		IsActive:    true,
		Level:       0,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}
}

func TestOrganizationRepository_Create(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		mock, repo := newOrganizationMock(t)
		defer mock.Close()

		org := sampleOrganization()
		path := testOrgSlug
		rows := mock.NewRows([]string{"path", "level"}).AddRow(&path, 0)
		mock.ExpectQuery(`INSERT INTO iam_organizations`).
			WithArgs(anyArgs(13)...).
			WillReturnRows(rows)

		err := repo.Create(context.Background(), org)
		assert.NoError(t, err)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("db error", func(t *testing.T) {
		mock, repo := newOrganizationMock(t)
		defer mock.Close()

		org := sampleOrganization()
		mock.ExpectQuery(`INSERT INTO iam_organizations`).
			WithArgs(anyArgs(13)...).
			WillReturnError(fmt.Errorf("unique constraint violation"))

		err := repo.Create(context.Background(), org)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to create organization")
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

func TestOrganizationRepository_GetByID(t *testing.T) {
	now := time.Now()
	org := sampleOrganization()

	t.Run("found", func(t *testing.T) {
		mock, repo := newOrganizationMock(t)
		defer mock.Close()

		path := testOrgSlug
		rows := mock.NewRows(orgCols).AddRow(
			org.ID, org.TenantID, nil, org.Name, org.DisplayName, nil, org.OrgType,
			nil, &path, 0, []byte("{}"), org.IsActive, now, now, nil,
			0, 0,
		)
		mock.ExpectQuery(`SELECT`).WithArgs(org.ID).WillReturnRows(rows)

		got, err := repo.GetByID(context.Background(), org.ID)
		require.NoError(t, err)
		require.NotNil(t, got)
		assert.Equal(t, org.ID, got.ID)
		assert.Equal(t, org.Name, got.Name)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("not found", func(t *testing.T) {
		mock, repo := newOrganizationMock(t)
		defer mock.Close()

		mock.ExpectQuery(`SELECT`).WithArgs(org.ID).
			WillReturnError(fmt.Errorf("no rows in result set"))

		got, err := repo.GetByID(context.Background(), org.ID)
		assert.Error(t, err)
		assert.Nil(t, got)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

func TestOrganizationRepository_GetByName(t *testing.T) {
	now := time.Now()
	org := sampleOrganization()

	t.Run("found without parent", func(t *testing.T) {
		mock, repo := newOrganizationMock(t)
		defer mock.Close()

		path := testOrgSlug
		rows := mock.NewRows(orgColsNoCount).AddRow(
			org.ID, org.TenantID, nil, org.Name, org.DisplayName, nil, org.OrgType,
			nil, &path, 0, []byte("{}"), org.IsActive, now, now, nil,
		)
		mock.ExpectQuery(`SELECT`).WithArgs(org.TenantID, org.Name).WillReturnRows(rows)

		got, err := repo.GetByName(context.Background(), org.TenantID, org.Name, nil)
		require.NoError(t, err)
		require.NotNil(t, got)
		assert.Equal(t, org.Name, got.Name)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("found with parent", func(t *testing.T) {
		mock, repo := newOrganizationMock(t)
		defer mock.Close()

		parentID := uuid.New()
		path := "parent/test-org"
		rows := mock.NewRows(orgColsNoCount).AddRow(
			org.ID, org.TenantID, &parentID, org.Name, org.DisplayName, nil, org.OrgType,
			nil, &path, 1, []byte("{}"), org.IsActive, now, now, nil,
		)
		mock.ExpectQuery(`SELECT`).WithArgs(org.TenantID, org.Name, parentID).WillReturnRows(rows)

		got, err := repo.GetByName(context.Background(), org.TenantID, org.Name, &parentID)
		require.NoError(t, err)
		require.NotNil(t, got)
		assert.Equal(t, org.Name, got.Name)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("not found", func(t *testing.T) {
		mock, repo := newOrganizationMock(t)
		defer mock.Close()

		rows := mock.NewRows(orgColsNoCount)
		mock.ExpectQuery(`SELECT`).WithArgs(org.TenantID, org.Name).WillReturnRows(rows)

		got, err := repo.GetByName(context.Background(), org.TenantID, org.Name, nil)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "organization not found")
		assert.Nil(t, got)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

func TestOrganizationRepository_List(t *testing.T) {
	now := time.Now()
	org := sampleOrganization()

	t.Run("list all", func(t *testing.T) {
		mock, repo := newOrganizationMock(t)
		defer mock.Close()

		countRows := mock.NewRows([]string{"count"}).AddRow(1)
		mock.ExpectQuery(`SELECT COUNT`).WithArgs(org.TenantID).WillReturnRows(countRows)

		path := testOrgSlug
		listRows := mock.NewRows(orgCols).AddRow(
			org.ID, org.TenantID, nil, org.Name, org.DisplayName, nil, org.OrgType,
			nil, &path, 0, []byte("{}"), org.IsActive, now, now, nil,
			0, 0,
		)
		mock.ExpectQuery(`SELECT`).WithArgs(org.TenantID, 10, 0).WillReturnRows(listRows)

		orgs, total, err := repo.List(context.Background(), org.TenantID, 1, 10, "", "")
		require.NoError(t, err)
		assert.Equal(t, 1, total)
		assert.Len(t, orgs, 1)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("list with search", func(t *testing.T) {
		mock, repo := newOrganizationMock(t)
		defer mock.Close()

		countRows := mock.NewRows([]string{"count"}).AddRow(1)
		mock.ExpectQuery(`SELECT COUNT`).WithArgs(org.TenantID, "%test%").WillReturnRows(countRows)

		path := testOrgSlug
		listRows := mock.NewRows(orgCols).AddRow(
			org.ID, org.TenantID, nil, org.Name, org.DisplayName, nil, org.OrgType,
			nil, &path, 0, []byte("{}"), org.IsActive, now, now, nil,
			0, 0,
		)
		mock.ExpectQuery(`SELECT`).WithArgs(org.TenantID, "%test%", 10, 0).WillReturnRows(listRows)

		orgs, total, err := repo.List(context.Background(), org.TenantID, 1, 10, "test", "")
		require.NoError(t, err)
		assert.Equal(t, 1, total)
		assert.Len(t, orgs, 1)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

func TestOrganizationRepository_Update(t *testing.T) {
	org := sampleOrganization()

	t.Run("success", func(t *testing.T) {
		mock, repo := newOrganizationMock(t)
		defer mock.Close()

		path := "updated-org"
		rows := mock.NewRows([]string{"path", "level"}).AddRow(&path, 0)
		mock.ExpectQuery(`UPDATE iam_organizations`).
			WithArgs(anyArgs(10)...).
			WillReturnRows(rows)

		err := repo.Update(context.Background(), org)
		assert.NoError(t, err)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("not found", func(t *testing.T) {
		mock, repo := newOrganizationMock(t)
		defer mock.Close()

		rows := mock.NewRows([]string{"path", "level"})
		mock.ExpectQuery(`UPDATE iam_organizations`).
			WithArgs(anyArgs(10)...).
			WillReturnRows(rows)

		err := repo.Update(context.Background(), org)
		assert.Error(t, err)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

func TestOrganizationRepository_Delete(t *testing.T) {
	orgID := uuid.New()

	t.Run("success", func(t *testing.T) {
		mock, repo := newOrganizationMock(t)
		defer mock.Close()

		mock.ExpectExec(`DELETE FROM iam_organizations`).
			WithArgs(orgID).
			WillReturnResult(pgxmock.NewResult("DELETE", 1))

		err := repo.Delete(context.Background(), orgID)
		assert.NoError(t, err)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("not found", func(t *testing.T) {
		mock, repo := newOrganizationMock(t)
		defer mock.Close()

		mock.ExpectExec(`DELETE FROM iam_organizations`).
			WithArgs(orgID).
			WillReturnResult(pgxmock.NewResult("DELETE", 0))

		err := repo.Delete(context.Background(), orgID)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "organization not found")
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

func TestOrganizationRepository_AddMember(t *testing.T) {
	orgID := uuid.New()
	userID := uuid.New()

	t.Run("success non-primary", func(t *testing.T) {
		mock, repo := newOrganizationMock(t)
		defer mock.Close()

		mock.ExpectExec(`INSERT INTO iam_organization_members`).
			WithArgs(anyArgs(8)...).
			WillReturnResult(pgxmock.NewResult("INSERT", 1))

		err := repo.AddMember(context.Background(), orgID, userID, models.OrgRoleMember, nil, false, nil)
		assert.NoError(t, err)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("success primary — unsets others first", func(t *testing.T) {
		mock, repo := newOrganizationMock(t)
		defer mock.Close()

		mock.ExpectExec(`UPDATE iam_organization_members SET is_primary`).
			WithArgs(userID).
			WillReturnResult(pgxmock.NewResult("UPDATE", 0))
		mock.ExpectExec(`INSERT INTO iam_organization_members`).
			WithArgs(anyArgs(8)...).
			WillReturnResult(pgxmock.NewResult("INSERT", 1))

		err := repo.AddMember(context.Background(), orgID, userID, models.OrgRoleMember, nil, true, nil)
		assert.NoError(t, err)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("db error on insert", func(t *testing.T) {
		mock, repo := newOrganizationMock(t)
		defer mock.Close()

		mock.ExpectExec(`INSERT INTO iam_organization_members`).
			WithArgs(anyArgs(8)...).
			WillReturnError(fmt.Errorf("unique constraint"))

		err := repo.AddMember(context.Background(), orgID, userID, models.OrgRoleMember, nil, false, nil)
		assert.Error(t, err)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

func TestOrganizationRepository_RemoveMember(t *testing.T) {
	orgID := uuid.New()
	userID := uuid.New()

	t.Run("success", func(t *testing.T) {
		mock, repo := newOrganizationMock(t)
		defer mock.Close()

		mock.ExpectExec(`DELETE FROM iam_organization_members`).
			WithArgs(orgID, userID).
			WillReturnResult(pgxmock.NewResult("DELETE", 1))

		err := repo.RemoveMember(context.Background(), orgID, userID)
		assert.NoError(t, err)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

func TestOrganizationRepository_GetMembers(t *testing.T) {
	now := time.Now()
	orgID := uuid.New()
	userID := uuid.New()

	t.Run("returns members", func(t *testing.T) {
		mock, repo := newOrganizationMock(t)
		defer mock.Close()

		countRows := mock.NewRows([]string{"count"}).AddRow(1)
		mock.ExpectQuery(`SELECT COUNT`).WithArgs(orgID).WillReturnRows(countRows)

		memberCols := []string{
			"id", "organization_id", "user_id", "role", "title", "is_primary", "joined_at", "joined_by",
			"username", "email", "first_name", "last_name", "display_name", "is_active",
		}
		firstName := "Test"
		lastName := "User"
		listRows := mock.NewRows(memberCols).AddRow(
			uuid.New(), orgID, userID, models.OrgRoleMember, nil, false, now, nil,
			"testuser", "test@example.com", &firstName, &lastName, nil, true,
		)
		mock.ExpectQuery(`SELECT`).WithArgs(orgID, 10, 0).WillReturnRows(listRows)

		members, total, err := repo.GetMembers(context.Background(), orgID, 1, 10)
		require.NoError(t, err)
		assert.Equal(t, 1, total)
		assert.Len(t, members, 1)
		assert.Equal(t, userID, members[0].UserID)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

func TestOrganizationRepository_GetUserOrganizations(t *testing.T) {
	now := time.Now()
	userID := uuid.New()
	orgID := uuid.New()

	t.Run("returns org memberships", func(t *testing.T) {
		mock, repo := newOrganizationMock(t)
		defer mock.Close()

		cols := []string{
			"id", "organization_id", "user_id", "role", "title", "is_primary", "joined_at",
			"name", "display_name", "org_type", "level",
		}
		displayName := "Test Org"
		rows := mock.NewRows(cols).AddRow(
			uuid.New(), orgID, userID, models.OrgRoleMember, nil, true, now,
			testOrgSlug, &displayName, models.OrgTypeDepartment, 0,
		)
		mock.ExpectQuery(`SELECT`).WithArgs(userID).WillReturnRows(rows)

		memberships, err := repo.GetUserOrganizations(context.Background(), userID)
		require.NoError(t, err)
		assert.Len(t, memberships, 1)
		assert.Equal(t, userID, memberships[0].UserID)
		assert.Equal(t, orgID, memberships[0].OrganizationID)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

func TestOrganizationRepository_GetChildren(t *testing.T) {
	now := time.Now()
	parentID := uuid.New()

	t.Run("returns children", func(t *testing.T) {
		mock, repo := newOrganizationMock(t)
		defer mock.Close()

		path := "parent/child"
		rows := mock.NewRows(orgCols).AddRow(
			uuid.New(), uuid.New(), &parentID, "child-org", nil, nil, models.OrgTypeTeam,
			nil, &path, 1, []byte("{}"), true, now, now, nil,
			0, 0,
		)
		mock.ExpectQuery(`SELECT`).WithArgs(parentID).WillReturnRows(rows)

		children, err := repo.GetChildren(context.Background(), parentID)
		require.NoError(t, err)
		assert.Len(t, children, 1)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("no children", func(t *testing.T) {
		mock, repo := newOrganizationMock(t)
		defer mock.Close()

		rows := mock.NewRows(orgCols)
		mock.ExpectQuery(`SELECT`).WithArgs(parentID).WillReturnRows(rows)

		children, err := repo.GetChildren(context.Background(), parentID)
		require.NoError(t, err)
		assert.Empty(t, children)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

func TestOrganizationRepository_GetRootOrganizations(t *testing.T) {
	now := time.Now()
	tenantID := uuid.New()

	t.Run("returns root orgs", func(t *testing.T) {
		mock, repo := newOrganizationMock(t)
		defer mock.Close()

		path := "root-org"
		rows := mock.NewRows(orgCols).AddRow(
			uuid.New(), tenantID, nil, "root-org", nil, nil, models.OrgTypeCompany,
			nil, &path, 0, []byte("{}"), true, now, now, nil,
			2, 1,
		)
		mock.ExpectQuery(`SELECT`).WithArgs(tenantID).WillReturnRows(rows)

		orgs, err := repo.GetRootOrganizations(context.Background(), tenantID)
		require.NoError(t, err)
		assert.Len(t, orgs, 1)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

func TestOrganizationRepository_GetDescendants(t *testing.T) {
	orgID := uuid.New()

	t.Run("returns descendants", func(t *testing.T) {
		mock, repo := newOrganizationMock(t)
		defer mock.Close()

		cols := []string{"id", "name", "display_name", "level", "path"}
		displayName := "Child Org"
		path := "root/child"
		rows := mock.NewRows(cols).
			AddRow(uuid.New(), "child-org", &displayName, 1, &path).
			AddRow(uuid.New(), "grandchild-org", nil, 2, nil)

		mock.ExpectQuery(`SELECT`).WithArgs(orgID).WillReturnRows(rows)

		descendants, err := repo.GetDescendants(context.Background(), orgID)
		require.NoError(t, err)
		assert.Len(t, descendants, 2)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}
