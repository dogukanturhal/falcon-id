// SPDX-License-Identifier: AGPL-3.0-or-later

package repositories

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/pashagolub/pgxmock/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestGetUserPermissions_IncludesTenantFilter verifies that the SQL query
// issued by GetUserPermissions carries the tenantID as the second bind
// parameter ($2), guaranteeing cross-tenant isolation at the DB layer.
func TestGetUserPermissions_IncludesTenantFilter(t *testing.T) {
	mock, err := pgxmock.NewPool()
	require.NoError(t, err)
	defer mock.Close()

	userID := uuid.New()
	tenantID := uuid.New()

	// The matcher uses a substring of the real query so that minor whitespace
	// changes in the query string do not break the test.
	mock.ExpectQuery("SELECT DISTINCT p.id").
		WithArgs(userID, tenantID).
		WillReturnRows(pgxmock.NewRows([]string{
			"id", "module", "resource", "action", "name",
			"display_name", "description", "is_system", "source", "created_at",
		}))

	repo := newPermissionRepositoryWithMock(mock)
	perms, err := repo.GetUserPermissions(context.Background(), userID, tenantID)
	assert.NoError(t, err)
	assert.Empty(t, perms) // empty result set — we only care that the query ran with both args
	assert.NoError(t, mock.ExpectationsWereMet())
}

// TestGetUserPermissions_ReturnsTenantScopedRows verifies that rows returned
// from the DB are correctly scanned into Permission structs.
func TestGetUserPermissions_ReturnsTenantScopedRows(t *testing.T) {
	mock, err := pgxmock.NewPool()
	require.NoError(t, err)
	defer mock.Close()

	userID := uuid.New()
	tenantID := uuid.New()
	permID := uuid.New()
	now := time.Now().UTC().Truncate(time.Millisecond)

	// Description is *string in the model, so pass nil to represent NULL.
	var descNil *string

	rows := pgxmock.NewRows([]string{
		"id", "module", "resource", "action", "name",
		"display_name", "description", "is_system", "source", "created_at",
	}).AddRow(permID, "crm", "contacts", "read", "crm:contacts:read",
		"Read Contacts", descNil, false, "system", now)

	mock.ExpectQuery("SELECT DISTINCT p.id").
		WithArgs(userID, tenantID).
		WillReturnRows(rows)

	repo := newPermissionRepositoryWithMock(mock)
	perms, err := repo.GetUserPermissions(context.Background(), userID, tenantID)
	require.NoError(t, err)
	require.Len(t, perms, 1)
	assert.Equal(t, permID, perms[0].ID)
	assert.Equal(t, "crm", perms[0].Module)
	assert.Equal(t, "contacts", perms[0].Resource)
	assert.Equal(t, "read", perms[0].Action)
	assert.Equal(t, "crm:contacts:read", perms[0].Name)
	assert.Nil(t, perms[0].Description)
	assert.NoError(t, mock.ExpectationsWereMet())
}

// TestGetUserPermissions_DifferentTenantIDs asserts that two calls with the
// same userID but different tenantIDs each propagate the correct tenantID
// to the database — i.e., the repo does not cache or ignore the argument.
func TestGetUserPermissions_DifferentTenantIDs(t *testing.T) {
	mock, err := pgxmock.NewPool()
	require.NoError(t, err)
	defer mock.Close()

	userID := uuid.New()
	tenantA := uuid.New()
	tenantB := uuid.New()

	// Description is *string in the model; pass nil to represent SQL NULL.
	var descNil *string

	// First call: tenantA — returns one permission
	mock.ExpectQuery("SELECT DISTINCT p.id").
		WithArgs(userID, tenantA).
		WillReturnRows(pgxmock.NewRows([]string{
			"id", "module", "resource", "action", "name",
			"display_name", "description", "is_system", "source", "created_at",
		}).AddRow(uuid.New(), "crm", "contacts", "read", "crm:contacts:read",
			"Read Contacts", descNil, false, "system", time.Now()))

	// Second call: tenantB — returns empty (user has no roles in tenantB)
	mock.ExpectQuery("SELECT DISTINCT p.id").
		WithArgs(userID, tenantB).
		WillReturnRows(pgxmock.NewRows([]string{
			"id", "module", "resource", "action", "name",
			"display_name", "description", "is_system", "source", "created_at",
		}))

	repo := newPermissionRepositoryWithMock(mock)

	permsA, errA := repo.GetUserPermissions(context.Background(), userID, tenantA)
	require.NoError(t, errA)
	assert.Len(t, permsA, 1, "tenantA should return the assigned permission")

	permsB, errB := repo.GetUserPermissions(context.Background(), userID, tenantB)
	require.NoError(t, errB)
	assert.Empty(t, permsB, "tenantB should return no permissions (isolation)")

	assert.NoError(t, mock.ExpectationsWereMet())
}

// TestGetUserRoles_IncludesTenantFilter verifies that the SQL query issued by
// GetUserRoles carries the tenantID as the second bind parameter ($2).
func TestGetUserRoles_IncludesTenantFilter(t *testing.T) {
	mock, err := pgxmock.NewPool()
	require.NoError(t, err)
	defer mock.Close()

	userID := uuid.New()
	tenantID := uuid.New()

	mock.ExpectQuery("SELECT r.name").
		WithArgs(userID, tenantID).
		WillReturnRows(pgxmock.NewRows([]string{"name"}))

	repo := newPermissionRepositoryWithMock(mock)
	roles, err := repo.GetUserRoles(context.Background(), userID, tenantID)
	assert.NoError(t, err)
	assert.Empty(t, roles)
	assert.NoError(t, mock.ExpectationsWereMet())
}

// TestGetUserRoles_ReturnsTenantScopedRoles verifies that role names returned
// from the DB are correctly scanned into a string slice.
func TestGetUserRoles_ReturnsTenantScopedRoles(t *testing.T) {
	mock, err := pgxmock.NewPool()
	require.NoError(t, err)
	defer mock.Close()

	userID := uuid.New()
	tenantID := uuid.New()

	mock.ExpectQuery("SELECT r.name").
		WithArgs(userID, tenantID).
		WillReturnRows(pgxmock.NewRows([]string{"name"}).
			AddRow("admin").
			AddRow("manager"))

	repo := newPermissionRepositoryWithMock(mock)
	roles, err := repo.GetUserRoles(context.Background(), userID, tenantID)
	require.NoError(t, err)
	require.Len(t, roles, 2)
	assert.Equal(t, "admin", roles[0])
	assert.Equal(t, "manager", roles[1])
	assert.NoError(t, mock.ExpectationsWereMet())
}

// TestGetUserRoles_DifferentTenantIDs asserts that two calls with the same
// userID but different tenantIDs each propagate the correct tenantID to the
// database — guaranteeing the tenant filter is never collapsed.
func TestGetUserRoles_DifferentTenantIDs(t *testing.T) {
	mock, err := pgxmock.NewPool()
	require.NoError(t, err)
	defer mock.Close()

	userID := uuid.New()
	tenantA := uuid.New()
	tenantB := uuid.New()

	// First call: tenantA — has roles
	mock.ExpectQuery("SELECT r.name").
		WithArgs(userID, tenantA).
		WillReturnRows(pgxmock.NewRows([]string{"name"}).AddRow("editor"))

	// Second call: tenantB — no roles (isolated)
	mock.ExpectQuery("SELECT r.name").
		WithArgs(userID, tenantB).
		WillReturnRows(pgxmock.NewRows([]string{"name"}))

	repo := newPermissionRepositoryWithMock(mock)

	rolesA, errA := repo.GetUserRoles(context.Background(), userID, tenantA)
	require.NoError(t, errA)
	assert.Equal(t, []string{"editor"}, rolesA)

	rolesB, errB := repo.GetUserRoles(context.Background(), userID, tenantB)
	require.NoError(t, errB)
	assert.Empty(t, rolesB, "user's roles in tenantA must not bleed into tenantB")

	assert.NoError(t, mock.ExpectationsWereMet())
}
