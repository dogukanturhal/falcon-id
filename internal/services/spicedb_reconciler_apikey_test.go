// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/pashagolub/pgxmock/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A live key desires its role_ids; a revoked or expired key desires none, so
// reconcileAPIKeyRoles removes whatever edges SpiceDB still holds for it.
func TestLoadAPIKeyRoleStates_LiveVersusDeadKeys(t *testing.T) {
	mock, err := pgxmock.NewPool()
	require.NoError(t, err)
	defer mock.Close()

	tenantID := uuid.New()
	liveKey, deadKey := uuid.New(), uuid.New()
	roleA, roleB := uuid.New(), uuid.New()
	expiry := time.Now().Add(time.Hour)

	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_tenant_id'`).WithArgs(tenantID.String()).
		WillReturnResult(pgxmock.NewResult("SELECT", 1))
	mock.ExpectQuery(`FROM iam_api_keys\s+WHERE tenant_id = \$1 AND kind = 'tenant'`).WithArgs(tenantID).
		WillReturnRows(mock.NewRows([]string{"id", "role_ids", "expires_at", "live"}).
			AddRow(liveKey, []uuid.UUID{roleA, roleB}, &expiry, true).
			AddRow(deadKey, []uuid.UUID{roleA}, &expiry, false))
	mock.ExpectCommit()

	states, err := loadAPIKeyRoleStates(context.Background(), mock, tenantID)
	require.NoError(t, err)
	require.Len(t, states, 2)
	assert.Len(t, states[liveKey].desired, 2)
	assert.Empty(t, states[deadKey].desired, "a revoked/expired key must desire no roles")
	require.NoError(t, mock.ExpectationsWereMet())
}
