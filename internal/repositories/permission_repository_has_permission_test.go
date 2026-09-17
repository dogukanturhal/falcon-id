// SPDX-License-Identifier: AGPL-3.0-or-later

package repositories

// permission_repository_has_permission_test.go verifies the tenant-scoping
// security fix for HasPermission (GAP 5).
//
// Before the fix, HasPermission lacked a tenant_id filter, allowing a user
// who holds a role in Tenant A to pass permission checks for Tenant B.
// After the fix, HasPermission requires a tenantID parameter and injects
// AND r.tenant_id = $3 into the JOIN on iam_roles.

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/pashagolub/pgxmock/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ─── HasPermission ────────────────────────────────────────────────────────────

// TestHasPermission_IncludesTenantFilter is the primary security regression
// test.  It verifies that the SQL sent to the DB carries BOTH the userID ($1)
// and the tenantID ($3) as bind parameters.  pgxmock rejects the query if the
// expected argument list does not match exactly, so a missing $3 will cause
// mock.ExpectationsWereMet() to fail.
func TestHasPermission_IncludesTenantFilter(t *testing.T) {
	mock, err := pgxmock.NewPool()
	require.NoError(t, err)
	defer mock.Close()

	userID := uuid.New()
	tenantID := uuid.New()

	mock.ExpectQuery(`SELECT EXISTS`).
		WithArgs(userID, "crm:contacts:read", tenantID).
		WillReturnRows(pgxmock.NewRows([]string{"exists"}).AddRow(false))

	repo := newPermissionRepositoryWithMock(mock)
	exists, err := repo.HasPermission(context.Background(), userID, tenantID, "crm:contacts:read")
	require.NoError(t, err)
	assert.False(t, exists)
	assert.NoError(t, mock.ExpectationsWereMet())
}

// TestHasPermission_ReturnsTrue verifies that a true result from the DB is
// propagated correctly back to the caller.
func TestHasPermission_ReturnsTrue(t *testing.T) {
	mock, err := pgxmock.NewPool()
	require.NoError(t, err)
	defer mock.Close()

	userID := uuid.New()
	tenantID := uuid.New()

	mock.ExpectQuery(`SELECT EXISTS`).
		WithArgs(userID, "crm:contacts:read", tenantID).
		WillReturnRows(pgxmock.NewRows([]string{"exists"}).AddRow(true))

	repo := newPermissionRepositoryWithMock(mock)
	exists, err := repo.HasPermission(context.Background(), userID, tenantID, "crm:contacts:read")
	require.NoError(t, err)
	assert.True(t, exists)
	assert.NoError(t, mock.ExpectationsWereMet())
}

// TestHasPermission_DifferentTenantIDs is the cross-tenant isolation test.
// The same userID is checked against two different tenants.  pgxmock enforces
// that each query carries the correct tenantID, so any implementation that
// ignores the tenantID will fail because the second query expectation will
// receive the wrong arguments.
func TestHasPermission_DifferentTenantIDs(t *testing.T) {
	mock, err := pgxmock.NewPool()
	require.NoError(t, err)
	defer mock.Close()

	userID := uuid.New()
	tenantA := uuid.New()
	tenantB := uuid.New()

	// TenantA: user has the permission
	mock.ExpectQuery(`SELECT EXISTS`).
		WithArgs(userID, "crm:contacts:read", tenantA).
		WillReturnRows(pgxmock.NewRows([]string{"exists"}).AddRow(true))

	// TenantB: user does NOT have the permission (different tenant, different roles)
	mock.ExpectQuery(`SELECT EXISTS`).
		WithArgs(userID, "crm:contacts:read", tenantB).
		WillReturnRows(pgxmock.NewRows([]string{"exists"}).AddRow(false))

	repo := newPermissionRepositoryWithMock(mock)

	existsA, errA := repo.HasPermission(context.Background(), userID, tenantA, "crm:contacts:read")
	require.NoError(t, errA)
	assert.True(t, existsA, "user should have permission in tenantA")

	existsB, errB := repo.HasPermission(context.Background(), userID, tenantB, "crm:contacts:read")
	require.NoError(t, errB)
	assert.False(t, existsB, "tenantA permission must not bleed into tenantB")

	assert.NoError(t, mock.ExpectationsWereMet())
}

// TestHasPermission_DBError verifies that a database error is wrapped and
// returned to the caller unchanged.
func TestHasPermission_DBError(t *testing.T) {
	mock, err := pgxmock.NewPool()
	require.NoError(t, err)
	defer mock.Close()

	userID := uuid.New()
	tenantID := uuid.New()

	mock.ExpectQuery(`SELECT EXISTS`).
		WithArgs(userID, "crm:contacts:read", tenantID).
		WillReturnError(errors.New("connection refused"))

	repo := newPermissionRepositoryWithMock(mock)
	_, err = repo.HasPermission(context.Background(), userID, tenantID, "crm:contacts:read")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "HasPermission")
	assert.NoError(t, mock.ExpectationsWereMet())
}
