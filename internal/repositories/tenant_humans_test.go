// SPDX-License-Identifier: AGPL-3.0-or-later

package repositories

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/pashagolub/pgxmock/v4"
	"github.com/stretchr/testify/require"
)

func TestListTenantHumans_FiltersBeforeCountAndPagination(t *testing.T) {
	for _, status := range []string{"active", "inactive", "all"} {
		t.Run(status, func(t *testing.T) {
			repo, mock := newUserRepo(t)
			tenant := uuid.New()
			mock.ExpectBegin()
			mock.ExpectExec(`set_config`).WithArgs(tenant.String()).WillReturnResult(pgxmock.NewResult("SELECT", 1))
			predicate := `.*username NOT ILIKE 'svc-%'.*m.seat_class = 'service'`
			if status == "active" {
				predicate += `.*AND \(is_active = true AND deletion_scheduled_at IS NULL.*m.status = 'deactivated'`
			}
			if status == "inactive" {
				predicate += `.*AND NOT \(is_active = true AND deletion_scheduled_at IS NULL.*m.status = 'deactivated'`
			}
			mock.ExpectQuery(`SELECT COUNT\(\*\) FROM iam_users WHERE tenant_id = \$1`+predicate).
				WithArgs(tenant, "%alice%", computeEmailHash("alice")).
				WillReturnRows(pgxmock.NewRows([]string{"count"}).AddRow(int64(3)))
			mock.ExpectQuery(`SELECT .+ FROM iam_users WHERE tenant_id = \$1`+predicate+`.*ORDER BY created_at DESC LIMIT \$4 OFFSET \$5`).
				WithArgs(tenant, "%alice%", computeEmailHash("alice"), 1, 1).
				WillReturnRows(pgxmock.NewRows(testUserColumns).AddRow(buildUserRow(t, newTestEncryptionService(t), sampleUser(tenant))...))
			mock.ExpectCommit()
			users, total, err := repo.ListTenantHumans(context.Background(), tenant, 2, 1, "alice", status)
			require.NoError(t, err)
			require.Len(t, users, 1)
			require.Equal(t, int64(3), total, "total is the filtered result, not the page length")
			require.NoError(t, mock.ExpectationsWereMet())
		})
	}
}

func TestListTenantHumans_RejectsUnknownStatus(t *testing.T) {
	repo, mock := newUserRepo(t)
	_, _, err := repo.ListTenantHumans(context.Background(), uuid.New(), 1, 10, "", "unexpected")
	require.Error(t, err)
	require.NoError(t, mock.ExpectationsWereMet(), "invalid filter must not touch the DB")
}
