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

// ---------------------------------------------------------------------------
// List: soft-deleted exclusion
// ---------------------------------------------------------------------------

// TestList_ExcludesSoftDeletedUsers is the behavioural test proving List's
// COUNT and SELECT both carry the activation_status exclusion clause —
// the "verify every list/read path filters it" requirement.
// CONTROL: TestUserRepository_List_NoSearch (user_repository_test.go)
// is the pre-existing test with the OLD query shape; if it still passes
// unmodified while this test's stricter regex (requiring the exclusion
// clause literally in the SQL) also passes, that confirms the clause was
// added without breaking the base query shape.
func TestList_ExcludesSoftDeletedUsers(t *testing.T) {
	ctx := context.Background()
	repo, mock := newUserRepo(t)
	tenantID := uuid.New()

	mock.ExpectQuery(`SELECT COUNT\(\*\) FROM iam_users WHERE tenant_id = \$1 AND \(activation_status IS NULL OR activation_status NOT IN \('pending_deletion', 'admin_deleted'\)\)`).
		WithArgs(tenantID).
		WillReturnRows(pgxmock.NewRows([]string{"count"}).AddRow(int64(0)))

	mock.ExpectQuery(`SELECT .+ FROM iam_users WHERE tenant_id = \$1 AND \(activation_status IS NULL OR activation_status NOT IN \('pending_deletion', 'admin_deleted'\)\)`).
		WithArgs(tenantID, 20, 0).
		WillReturnRows(pgxmock.NewRows(testUserColumns))

	_, total, err := repo.List(ctx, tenantID, 1, 20, "")
	require.NoError(t, err)
	assert.Equal(t, int64(0), total)
	require.NoError(t, mock.ExpectationsWereMet())
}

// ---------------------------------------------------------------------------
// SetDeletionState
// ---------------------------------------------------------------------------

func TestSetDeletionState_UpdatesAllFourColumns(t *testing.T) {
	ctx := context.Background()
	repo, mock := newUserRepo(t)
	userID := uuid.New()
	now := time.Now().UTC()
	grace := now.Add(30 * 24 * time.Hour)
	reason := "admin action"

	mock.ExpectExec(`UPDATE iam_users\s+SET activation_status = \$2,\s+deletion_scheduled_at = \$3,\s+deletion_grace_period_ends_at = \$4,\s+deletion_reason = \$5,\s+updated_at = NOW\(\)\s+WHERE id = \$1`).
		WithArgs(userID, "admin_deleted", &now, &grace, &reason).
		WillReturnResult(pgxmock.NewResult("UPDATE", 1))

	err := repo.SetDeletionState(ctx, userID, "admin_deleted", &now, &grace, &reason)
	require.NoError(t, err)
	require.NoError(t, mock.ExpectationsWereMet())
}

// TestSetDeletionState_NoRowsAffectedIsError is the control proving a
// no-op UPDATE (target row missing) is reported as an error rather than
// silently accepted as success — this is exactly the class of bug that
// motivated adding this method (Update() silently dropping the write).
func TestSetDeletionState_NoRowsAffectedIsError(t *testing.T) {
	ctx := context.Background()
	repo, mock := newUserRepo(t)
	userID := uuid.New()

	mock.ExpectExec(`UPDATE iam_users`).
		WithArgs(userID, "active", pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg()).
		WillReturnResult(pgxmock.NewResult("UPDATE", 0))

	err := repo.SetDeletionState(ctx, userID, "active", nil, nil, nil)
	require.Error(t, err)
	require.NoError(t, mock.ExpectationsWereMet())
}

// ---------------------------------------------------------------------------
// CountActiveOwners
// ---------------------------------------------------------------------------

func TestCountActiveOwners_ScopesToTenantAndOwnerRole(t *testing.T) {
	ctx := context.Background()
	repo, mock := newUserRepo(t)
	tenantID := uuid.New()

	mock.ExpectQuery(`lower\(r\.name\) = 'owner'`).
		WithArgs(tenantID).
		WillReturnRows(pgxmock.NewRows([]string{"count"}).AddRow(2))

	count, err := repo.CountActiveOwners(ctx, tenantID)
	require.NoError(t, err)
	assert.Equal(t, 2, count)
	require.NoError(t, mock.ExpectationsWereMet())
}

// ---------------------------------------------------------------------------
// HardDeleteUser: transactional completeness guarantee
// ---------------------------------------------------------------------------

// TestHardDeleteUser_CommitsWhenResidualIsZero is the control: every
// child table reports zero residual rows, so the transaction commits.
func TestHardDeleteUser_CommitsWhenResidualIsZero(t *testing.T) {
	ctx := context.Background()
	repo, mock := newUserRepo(t)
	userID := uuid.New()

	// CountResidualRowsTx iterates a Go map, so query order across the
	// three swept tables is nondeterministic; match regardless of order.
	mock.MatchExpectationsInOrder(false)

	mock.ExpectBegin()
	mock.ExpectExec(`DELETE FROM iam_user_roles WHERE user_id = \$1`).WithArgs(userID).WillReturnResult(pgxmock.NewResult("DELETE", 0))
	mock.ExpectExec(`DELETE FROM iam_sessions WHERE user_id = \$1`).WithArgs(userID).WillReturnResult(pgxmock.NewResult("DELETE", 0))
	mock.ExpectExec(`DELETE FROM iam_user_recovery_methods WHERE user_id = \$1`).WithArgs(userID).WillReturnResult(pgxmock.NewResult("DELETE", 0))
	expectMembershipRelease(mock, userID)
	mock.ExpectExec(`DELETE FROM iam_users WHERE id = \$1`).WithArgs(userID).WillReturnResult(pgxmock.NewResult("DELETE", 1))
	// CountResidualRowsTx: 3 tables, all zero.
	mock.ExpectQuery(`SELECT COUNT\(\*\) FROM iam_user_roles WHERE user_id = \$1`).WithArgs(userID).WillReturnRows(pgxmock.NewRows([]string{"count"}).AddRow(0))
	mock.ExpectQuery(`SELECT COUNT\(\*\) FROM iam_sessions WHERE user_id = \$1`).WithArgs(userID).WillReturnRows(pgxmock.NewRows([]string{"count"}).AddRow(0))
	mock.ExpectQuery(`SELECT COUNT\(\*\) FROM iam_user_recovery_methods WHERE user_id = \$1`).WithArgs(userID).WillReturnRows(pgxmock.NewRows([]string{"count"}).AddRow(0))
	mock.ExpectCommit()

	residual, err := repo.HardDeleteUser(ctx, userID)
	require.NoError(t, err)
	for table, n := range residual {
		assert.Equalf(t, 0, n, "table %s should report zero residual rows", table)
	}
	require.NoError(t, mock.ExpectationsWereMet())
}

// TestHardDeleteUser_RollsBackWhenResidualNonzero is the behavioural
// test for the completeness guarantee: if the value-sweep finds a
// leftover row in ANY swept table, the whole transaction must roll back
// instead of reporting success. This is the control-bearing case for
// TestHardDeleteUser_CommitsWhenResidualIsZero above — same call shape,
// one count changed from 0 to 1, and the outcome flips from commit to
// rollback + error.
func TestHardDeleteUser_RollsBackWhenResidualNonzero(t *testing.T) {
	ctx := context.Background()
	repo, mock := newUserRepo(t)
	userID := uuid.New()

	mock.MatchExpectationsInOrder(false)

	mock.ExpectBegin()
	mock.ExpectExec(`DELETE FROM iam_user_roles WHERE user_id = \$1`).WithArgs(userID).WillReturnResult(pgxmock.NewResult("DELETE", 0))
	mock.ExpectExec(`DELETE FROM iam_sessions WHERE user_id = \$1`).WithArgs(userID).WillReturnResult(pgxmock.NewResult("DELETE", 0))
	mock.ExpectExec(`DELETE FROM iam_user_recovery_methods WHERE user_id = \$1`).WithArgs(userID).WillReturnResult(pgxmock.NewResult("DELETE", 0))
	expectMembershipRelease(mock, userID)
	mock.ExpectExec(`DELETE FROM iam_users WHERE id = \$1`).WithArgs(userID).WillReturnResult(pgxmock.NewResult("DELETE", 1))
	// One table reports a residual row despite the deletes above — e.g. a
	// row inserted concurrently between the deletes and the sweep.
	mock.ExpectQuery(`SELECT COUNT\(\*\) FROM iam_user_roles WHERE user_id = \$1`).WithArgs(userID).WillReturnRows(pgxmock.NewRows([]string{"count"}).AddRow(1))
	mock.ExpectQuery(`SELECT COUNT\(\*\) FROM iam_sessions WHERE user_id = \$1`).WithArgs(userID).WillReturnRows(pgxmock.NewRows([]string{"count"}).AddRow(0))
	mock.ExpectQuery(`SELECT COUNT\(\*\) FROM iam_user_recovery_methods WHERE user_id = \$1`).WithArgs(userID).WillReturnRows(pgxmock.NewRows([]string{"count"}).AddRow(0))
	mock.ExpectRollback()

	_, err := repo.HardDeleteUser(ctx, userID)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "iam_user_roles")
	require.NoError(t, mock.ExpectationsWereMet())
}

// TestHardDeleteUser_MissingUserRollsBack proves HardDeleteUserTx's
// "0 rows affected" guard actually aborts the transaction rather than
// reporting success for a user that no longer exists (double-delete /
// race).
func TestHardDeleteUser_MissingUserRollsBack(t *testing.T) {
	ctx := context.Background()
	repo, mock := newUserRepo(t)
	userID := uuid.New()

	mock.ExpectBegin()
	mock.ExpectExec(`DELETE FROM iam_user_roles WHERE user_id = \$1`).WithArgs(userID).WillReturnResult(pgxmock.NewResult("DELETE", 0))
	mock.ExpectExec(`DELETE FROM iam_sessions WHERE user_id = \$1`).WithArgs(userID).WillReturnResult(pgxmock.NewResult("DELETE", 0))
	mock.ExpectExec(`DELETE FROM iam_user_recovery_methods WHERE user_id = \$1`).WithArgs(userID).WillReturnResult(pgxmock.NewResult("DELETE", 0))
	expectMembershipRelease(mock, userID)
	mock.ExpectExec(`DELETE FROM iam_users WHERE id = \$1`).WithArgs(userID).WillReturnResult(pgxmock.NewResult("DELETE", 0))
	mock.ExpectRollback()

	_, err := repo.HardDeleteUser(ctx, userID)
	require.Error(t, err)
	require.NoError(t, mock.ExpectationsWereMet())
}

// expectMembershipRelease scripts releaseMembershipsTx for a user with no membership row: tenant lookup, then
// UserMembershipRepository.Delete in a nested tenant-scoped transaction.
func expectMembershipRelease(mock pgxmock.PgxPoolIface, userID uuid.UUID) {
	tenantID := uuid.New()
	mock.ExpectQuery(`SELECT tenant_id FROM iam_users WHERE id = \$1`).WithArgs(userID).
		WillReturnRows(pgxmock.NewRows([]string{"tenant_id"}).AddRow(tenantID))
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config`).WithArgs(tenantID.String()).WillReturnResult(pgxmock.NewResult("SELECT", 1))
	mock.ExpectQuery(`DELETE FROM iam_user_memberships`).WithArgs(tenantID, userID).
		WillReturnRows(pgxmock.NewRows([]string{"seat_class", "status"}))
	mock.ExpectCommit()
}
