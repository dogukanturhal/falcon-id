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

var tenantAPIKeyCols = []string{
	"id", "tenant_id", "user_id", "name", "description", "key_prefix", "key_hash",
	"scopes", "ip_whitelist", "usage_count",
	"is_active", "last_used_at", "last_used_ip", "created_at", "expires_at", "revoked_at", "created_by",
	"kind", "key_id", "hash_alg", "access", "role_ids", "company_ids",
	"prev_hash", "prev_valid_until", "rotated_at",
	"company_sync_state", "company_sync_attempts", "company_sync_next_at",
}

func TestAPIKeyRepository_GetByKeyID(t *testing.T) {
	id, tenantID, userID, roleID, companyID := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	keyID := "abcdefghijklmnop"
	now := time.Now()

	t.Run("found", func(t *testing.T) {
		mock, repo := newAPIKeyMock(t)
		defer mock.Close()
		rows := mock.NewRows(tenantAPIKeyCols).AddRow(
			id, tenantID, userID, "ERP sync", nil, keyID, "hash",
			[]string{}, []string{}, int64(0),
			true, nil, nil, now, nil, nil, &userID,
			"tenant", &keyID, "hmac-sha256", strPtr("read"), []uuid.UUID{roleID}, []uuid.UUID{companyID},
			nil, nil, nil,
			"synced", 0, nil,
		)
		mock.ExpectQuery(`FROM iam_api_keys WHERE key_id = \$1 AND kind = 'tenant'`).WithArgs(keyID).WillReturnRows(rows)

		key, err := repo.GetByKeyID(context.Background(), keyID)
		require.NoError(t, err)
		require.NotNil(t, key)
		assert.Equal(t, id, key.ID)
		assert.Equal(t, "hmac-sha256", key.HashAlg)
		assert.Equal(t, []uuid.UUID{roleID}, key.RoleIDs)
		assert.Equal(t, []uuid.UUID{companyID}, key.CompanyIDs)
		require.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("not found returns nil", func(t *testing.T) {
		mock, repo := newAPIKeyMock(t)
		defer mock.Close()
		mock.ExpectQuery(`FROM iam_api_keys WHERE key_id`).WithArgs(keyID).
			WillReturnRows(mock.NewRows(tenantAPIKeyCols))
		key, err := repo.GetByKeyID(context.Background(), keyID)
		require.NoError(t, err)
		assert.Nil(t, key)
	})
}

func TestAPIKeyRepository_ActiveCountByTenant(t *testing.T) {
	mock, repo := newAPIKeyMock(t)
	defer mock.Close()
	tenantID := uuid.New()
	mock.ExpectQuery(`SELECT COUNT\(\*\) FROM iam_api_keys\s+WHERE tenant_id = \$1 AND kind = 'tenant' AND is_active = TRUE AND revoked_at IS NULL`).
		WithArgs(tenantID).WillReturnRows(mock.NewRows([]string{"count"}).AddRow(7))

	n, err := repo.ActiveCountByTenant(context.Background(), tenantID)
	require.NoError(t, err)
	assert.Equal(t, 7, n)
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestAPIKeyRepository_RotateSecretKeepsPreviousHashDuringGrace(t *testing.T) {
	mock, repo := newAPIKeyMock(t)
	defer mock.Close()
	id := uuid.New()
	until := time.Now().Add(24 * time.Hour)
	mock.ExpectExec(`UPDATE iam_api_keys\s+SET prev_hash = CASE`).WithArgs(id, "newhash", &until, "hmac-sha256:v2").
		WillReturnResult(pgxmock.NewResult("UPDATE", 1))

	require.NoError(t, repo.RotateSecret(context.Background(), id, "newhash", "hmac-sha256:v2", until))
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestAPIKeyRepository_RevokeTenantKeyNotFound(t *testing.T) {
	mock, repo := newAPIKeyMock(t)
	defer mock.Close()
	id := uuid.New()
	mock.ExpectExec(`UPDATE iam_api_keys`).WithArgs(id).WillReturnResult(pgxmock.NewResult("UPDATE", 0))
	require.Error(t, repo.RevokeTenantKey(context.Background(), id))
}

func TestAPIKeyRepository_SetCompanySyncIsCompareAndSet(t *testing.T) {
	mock, repo := newAPIKeyMock(t)
	defer mock.Close()
	id := uuid.New()
	mock.ExpectExec(`UPDATE iam_api_keys\s+SET company_sync_state = \$3.*company_sync_state = \$2`).
		WithArgs(id, "pending_add", "synced", 0, (*time.Time)(nil)).
		WillReturnResult(pgxmock.NewResult("UPDATE", 1))
	mock.ExpectExec(`UPDATE iam_api_keys`).
		WithArgs(id, "pending_add", "synced", 0, (*time.Time)(nil)).
		WillReturnResult(pgxmock.NewResult("UPDATE", 0))

	ok, err := repo.SetCompanySync(context.Background(), id, "pending_add", "synced", 0, nil)
	require.NoError(t, err)
	assert.True(t, ok)
	ok, err = repo.SetCompanySync(context.Background(), id, "pending_add", "synced", 0, nil)
	require.NoError(t, err)
	assert.False(t, ok, "zero rows means the state changed under us")
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestAPIKeyRepository_ListPendingCompanySyncClaimsWithSkipLocked(t *testing.T) {
	mock, repo := newAPIKeyMock(t)
	defer mock.Close()
	mock.ExpectQuery(`UPDATE iam_api_keys[\s\S]*FOR UPDATE SKIP LOCKED[\s\S]*RETURNING`).
		WithArgs(10, companySyncLease.Seconds()).
		WillReturnRows(mock.NewRows(tenantAPIKeyCols))

	keys, err := repo.ListPendingCompanySync(context.Background(), 10)
	require.NoError(t, err)
	assert.Empty(t, keys)
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestAPIKeyRepository_RevokeTenantKeyQueuesCompanyRemoval(t *testing.T) {
	mock, repo := newAPIKeyMock(t)
	defer mock.Close()
	id := uuid.New()
	mock.ExpectExec(`SET revoked_at = NOW\(\)[\s\S]*'pending_remove'`).WithArgs(id).
		WillReturnResult(pgxmock.NewResult("UPDATE", 1))
	require.NoError(t, repo.RevokeTenantKey(context.Background(), id))
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestAPIKeyRepository_DeleteTenantKeyRequiresRevokedAndSynced(t *testing.T) {
	mock, repo := newAPIKeyMock(t)
	defer mock.Close()
	id, tenantID := uuid.New(), uuid.New()
	mock.ExpectExec(`DELETE FROM iam_api_keys[\s\S]*revoked_at IS NOT NULL AND company_sync_state = 'synced'`).
		WithArgs(id, tenantID).WillReturnResult(pgxmock.NewResult("DELETE", 0))
	require.Error(t, repo.DeleteTenantKey(context.Background(), tenantID, id))
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestAPIKeyRepository_HardDeleteTenantKeyIgnoresSyncState(t *testing.T) {
	mock, repo := newAPIKeyMock(t)
	defer mock.Close()
	id, tenantID := uuid.New(), uuid.New()
	mock.ExpectExec(`DELETE FROM iam_api_keys WHERE id = \$1 AND tenant_id = \$2 AND kind = 'tenant'`).
		WithArgs(id, tenantID).WillReturnResult(pgxmock.NewResult("DELETE", 1))
	require.NoError(t, repo.HardDeleteTenantKey(context.Background(), tenantID, id))
	require.NoError(t, mock.ExpectationsWereMet())
}
