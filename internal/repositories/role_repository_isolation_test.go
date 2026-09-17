// SPDX-License-Identifier: AGPL-3.0-or-later

package repositories

// role_repository_isolation_test.go verifies that every RoleRepository query
// that accepts a tenantID propagates it as an explicit SQL bind parameter.
//
// SECURITY: Roles are the primary mechanism for permission assignment. If a
// role query lacks a tenant filter it could expose administrative roles from
// one tenant to another, granting unintended privileges.
//
// Test categories:
//   1. GetByName  – tenant_id is $1
//   2. List       – tenant_id is $1 in both COUNT and SELECT
//   3. GetDefaultRoles – tenant_id is $1
//   4. Cross-tenant isolation: same role name in different tenants returns
//      the correct row only for the owning tenant.

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/pashagolub/pgxmock/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// roleColumns mirrors the SELECT list used throughout role_repository.go.
var roleCols = []string{
	"id", "tenant_id", "name", "display_name", "description",
	"is_system", "is_default", "priority",
	"created_at", "updated_at", "created_by", "updated_by",
}

// nilRoleRow returns a complete row with stable zero/nil values for non-key
// columns so that Scan() succeeds without needing a real database.
func nilRoleRow(id, tenantID uuid.UUID, name string) []interface{} {
	now := time.Now().UTC()
	return []interface{}{
		id, tenantID, name, name, // id, tenant_id, name, display_name
		nil,             // description (*string)
		false, false, 0, // is_system, is_default, priority
		now, now, nil, nil, // created_at, updated_at, created_by, updated_by
	}
}

// newRoleRepoWithMock constructs a RoleRepository using the mock pool.
// RoleRepository.db is of type DBPool (= DBTX); pgxmock satisfies that interface.
func newRoleRepoWithMock(mock pgxmock.PgxPoolIface) *RoleRepository {
	return &RoleRepository{db: mock}
}

// ---------------------------------------------------------------------------
// GetByName
// ---------------------------------------------------------------------------

// TestRoleGetByName_IncludesTenantFilter verifies the WHERE clause uses
// tenant_id = $1 AND name = $2.
func TestRoleGetByName_IncludesTenantFilter(t *testing.T) {
	mock, err := pgxmock.NewPool()
	require.NoError(t, err)
	defer mock.Close()

	tenantID := uuid.New()

	mock.ExpectQuery(`FROM iam_roles WHERE tenant_id = \$1 AND name = \$2`).
		WithArgs(tenantID, "admin").
		WillReturnRows(pgxmock.NewRows(roleCols))

	repo := newRoleRepoWithMock(mock)
	role, err := repo.GetByName(context.Background(), tenantID, "admin")
	assert.NoError(t, err)
	assert.Nil(t, role) // empty result — only the query args matter here
	assert.NoError(t, mock.ExpectationsWereMet())
}

// TestRoleGetByName_CrossTenantIsolation asserts that querying the same role
// name in two different tenants issues separate tenant-scoped queries and
// never returns tenantA's role when tenantB is queried.
func TestRoleGetByName_CrossTenantIsolation(t *testing.T) {
	mock, err := pgxmock.NewPool()
	require.NoError(t, err)
	defer mock.Close()

	tenantA := uuid.MustParse("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
	tenantB := uuid.MustParse("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb")
	roleAID := uuid.New()

	// tenantA owns the "admin" role
	mock.ExpectQuery(`FROM iam_roles WHERE tenant_id = \$1 AND name = \$2`).
		WithArgs(tenantA, "admin").
		WillReturnRows(pgxmock.NewRows(roleCols).AddRow(nilRoleRow(roleAID, tenantA, "admin")...))

	// tenantB has no "admin" role
	mock.ExpectQuery(`FROM iam_roles WHERE tenant_id = \$1 AND name = \$2`).
		WithArgs(tenantB, "admin").
		WillReturnRows(pgxmock.NewRows(roleCols))

	repo := newRoleRepoWithMock(mock)

	roleA, errA := repo.GetByName(context.Background(), tenantA, "admin")
	require.NoError(t, errA)
	require.NotNil(t, roleA, "tenantA should return the admin role")
	assert.Equal(t, tenantA, roleA.TenantID)

	roleB, errB := repo.GetByName(context.Background(), tenantB, "admin")
	require.NoError(t, errB)
	assert.Nil(t, roleB, "tenantB must not see tenantA's admin role")

	assert.NoError(t, mock.ExpectationsWereMet())
}

// TestRoleGetByName_SuperAdminRoleNotLeakedAcrossTenants is a targeted test
// for the most sensitive role name. A super_admin role belonging to tenantA
// must never be returned when tenantB queries for it.
func TestRoleGetByName_SuperAdminRoleNotLeakedAcrossTenants(t *testing.T) {
	mock, err := pgxmock.NewPool()
	require.NoError(t, err)
	defer mock.Close()

	tenantA := uuid.New()
	tenantB := uuid.New()

	// tenantA query — returns row
	mock.ExpectQuery(`FROM iam_roles WHERE tenant_id = \$1 AND name = \$2`).
		WithArgs(tenantA, "super_admin").
		WillReturnRows(pgxmock.NewRows(roleCols).
			AddRow(nilRoleRow(uuid.New(), tenantA, "super_admin")...))

	// tenantB query — returns nothing
	mock.ExpectQuery(`FROM iam_roles WHERE tenant_id = \$1 AND name = \$2`).
		WithArgs(tenantB, "super_admin").
		WillReturnRows(pgxmock.NewRows(roleCols))

	repo := newRoleRepoWithMock(mock)

	superA, _ := repo.GetByName(context.Background(), tenantA, "super_admin")
	require.NotNil(t, superA)

	superB, errB := repo.GetByName(context.Background(), tenantB, "super_admin")
	require.NoError(t, errB)
	assert.Nil(t, superB, "super_admin must be isolated to its owning tenant")

	assert.NoError(t, mock.ExpectationsWereMet())
}

// ---------------------------------------------------------------------------
// List
// ---------------------------------------------------------------------------

// TestRoleList_IncludesTenantFilter verifies that the role listing query's
// COUNT and SELECT both carry tenant_id as $1.
func TestRoleList_IncludesTenantFilter(t *testing.T) {
	mock, err := pgxmock.NewPool()
	require.NoError(t, err)
	defer mock.Close()

	tenantID := uuid.New()

	// COUNT query
	mock.ExpectQuery(`SELECT COUNT\(\*\) FROM iam_roles WHERE tenant_id = \$1`).
		WithArgs(tenantID).
		WillReturnRows(pgxmock.NewRows([]string{"count"}).AddRow(0))

	// Data SELECT — LIMIT and OFFSET are embedded in SQL via fmt.Sprintf, not as parameters
	mock.ExpectQuery(`FROM iam_roles WHERE tenant_id = \$1`).
		WithArgs(tenantID).
		WillReturnRows(pgxmock.NewRows(roleCols))

	repo := newRoleRepoWithMock(mock)
	roles, total, err := repo.List(context.Background(), tenantID, 1, 10, "")
	assert.NoError(t, err)
	assert.Empty(t, roles)
	assert.Equal(t, int64(0), total)
	assert.NoError(t, mock.ExpectationsWereMet())
}

// TestRoleList_TenantIsolationDifferentCounts verifies that two tenants
// receive independent role counts and that a non-zero count for tenantA does
// not bleed into tenantB.
func TestRoleList_TenantIsolationDifferentCounts(t *testing.T) {
	mock, err := pgxmock.NewPool()
	require.NoError(t, err)
	defer mock.Close()

	tenantA := uuid.MustParse("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
	tenantB := uuid.MustParse("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb")

	// tenantA: 5 roles
	mock.ExpectQuery(`SELECT COUNT\(\*\) FROM iam_roles WHERE tenant_id = \$1`).
		WithArgs(tenantA).
		WillReturnRows(pgxmock.NewRows([]string{"count"}).AddRow(5))
	mock.ExpectQuery(`FROM iam_roles WHERE tenant_id = \$1`).
		WithArgs(tenantA).
		WillReturnRows(pgxmock.NewRows(roleCols))

	// tenantB: 0 roles
	mock.ExpectQuery(`SELECT COUNT\(\*\) FROM iam_roles WHERE tenant_id = \$1`).
		WithArgs(tenantB).
		WillReturnRows(pgxmock.NewRows([]string{"count"}).AddRow(0))
	mock.ExpectQuery(`FROM iam_roles WHERE tenant_id = \$1`).
		WithArgs(tenantB).
		WillReturnRows(pgxmock.NewRows(roleCols))

	repo := newRoleRepoWithMock(mock)

	_, countA, errA := repo.List(context.Background(), tenantA, 1, 10, "")
	require.NoError(t, errA)
	assert.Equal(t, int64(5), countA)

	_, countB, errB := repo.List(context.Background(), tenantB, 1, 10, "")
	require.NoError(t, errB)
	assert.Equal(t, int64(0), countB, "tenantB must not see tenantA roles")

	assert.NoError(t, mock.ExpectationsWereMet())
}

// ---------------------------------------------------------------------------
// GetDefaultRoles
// ---------------------------------------------------------------------------

// TestRoleGetDefaultRoles_IncludesTenantFilter verifies that GetDefaultRoles
// passes tenant_id as $1 and filters on is_default = true.
func TestRoleGetDefaultRoles_IncludesTenantFilter(t *testing.T) {
	mock, err := pgxmock.NewPool()
	require.NoError(t, err)
	defer mock.Close()

	tenantID := uuid.New()

	mock.ExpectQuery(`FROM iam_roles WHERE tenant_id = \$1 AND is_default = true`).
		WithArgs(tenantID).
		WillReturnRows(pgxmock.NewRows(roleCols))

	repo := newRoleRepoWithMock(mock)
	roles, err := repo.GetDefaultRoles(context.Background(), tenantID)
	assert.NoError(t, err)
	assert.Empty(t, roles)
	assert.NoError(t, mock.ExpectationsWereMet())
}

// TestRoleGetDefaultRoles_CrossTenantIsolation verifies that default roles
// from tenantA are not returned when tenantB calls GetDefaultRoles.
func TestRoleGetDefaultRoles_CrossTenantIsolation(t *testing.T) {
	mock, err := pgxmock.NewPool()
	require.NoError(t, err)
	defer mock.Close()

	tenantA := uuid.New()
	tenantB := uuid.New()

	// tenantA has 2 default roles
	mock.ExpectQuery(`FROM iam_roles WHERE tenant_id = \$1 AND is_default = true`).
		WithArgs(tenantA).
		WillReturnRows(pgxmock.NewRows(roleCols).
			AddRow(nilRoleRow(uuid.New(), tenantA, "member")...).
			AddRow(nilRoleRow(uuid.New(), tenantA, "viewer")...))

	// tenantB has 0 default roles
	mock.ExpectQuery(`FROM iam_roles WHERE tenant_id = \$1 AND is_default = true`).
		WithArgs(tenantB).
		WillReturnRows(pgxmock.NewRows(roleCols))

	repo := newRoleRepoWithMock(mock)

	rolesA, errA := repo.GetDefaultRoles(context.Background(), tenantA)
	require.NoError(t, errA)
	assert.Len(t, rolesA, 2, "tenantA should return its default roles")

	rolesB, errB := repo.GetDefaultRoles(context.Background(), tenantB)
	require.NoError(t, errB)
	assert.Empty(t, rolesB, "tenantB must not receive tenantA's default roles")

	assert.NoError(t, mock.ExpectationsWereMet())
}

// ---------------------------------------------------------------------------
// Table-driven cross-tenant GetByName matrix
// ---------------------------------------------------------------------------

// TestRoleGetByName_CrossTenantTableDriven sweeps through a realistic set of
// tenant-role combinations to confirm isolation in all directions.
func TestRoleGetByName_CrossTenantTableDriven(t *testing.T) {
	tenantA := uuid.MustParse("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
	tenantB := uuid.MustParse("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb")
	tenantC := uuid.MustParse("cccccccc-cccc-cccc-cccc-cccccccccccc")

	tests := []struct {
		name        string
		queryTenant uuid.UUID
		roleName    string
		returnsRow  bool
		description string
	}{
		{
			name:        "tenantA admin found",
			queryTenant: tenantA,
			roleName:    "admin",
			returnsRow:  true,
			description: "tenantA has the admin role — must be returned",
		},
		{
			name:        "tenantB admin not found",
			queryTenant: tenantB,
			roleName:    "admin",
			returnsRow:  false,
			description: "tenantB does not have admin — must return nil",
		},
		{
			name:        "tenantC admin not found",
			queryTenant: tenantC,
			roleName:    "admin",
			returnsRow:  false,
			description: "unrelated tenant must never see another tenant's role",
		},
		{
			name:        "tenantA platform_admin not found",
			queryTenant: tenantA,
			roleName:    "platform_admin",
			returnsRow:  false,
			description: "even within a tenant, absent roles must return nil",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock, err := pgxmock.NewPool()
			require.NoError(t, err)
			defer mock.Close()

			rows := pgxmock.NewRows(roleCols)
			if tt.returnsRow {
				rows.AddRow(nilRoleRow(uuid.New(), tt.queryTenant, tt.roleName)...)
			}

			mock.ExpectQuery(`FROM iam_roles WHERE tenant_id = \$1 AND name = \$2`).
				WithArgs(tt.queryTenant, tt.roleName).
				WillReturnRows(rows)

			repo := newRoleRepoWithMock(mock)
			role, err := repo.GetByName(context.Background(), tt.queryTenant, tt.roleName)
			require.NoError(t, err, tt.description)

			if tt.returnsRow {
				require.NotNil(t, role, tt.description)
				assert.Equal(t, tt.queryTenant, role.TenantID)
			} else {
				assert.Nil(t, role, tt.description)
			}

			assert.NoError(t, mock.ExpectationsWereMet())
		})
	}
}
