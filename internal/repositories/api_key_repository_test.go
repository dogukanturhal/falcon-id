// SPDX-License-Identifier: AGPL-3.0-or-later

package repositories

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
	"github.com/pashagolub/pgxmock/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

func newAPIKeyMock(t *testing.T) (pgxmock.PgxPoolIface, *APIKeyRepository) {
	t.Helper()
	mock, err := pgxmock.NewPool()
	require.NoError(t, err)
	return mock, newAPIKeyRepositoryWithMock(mock)
}

var apiKeyCols = []string{
	"id", "tenant_id", "user_id", "name", "description", "key_prefix", "key_hash",
	"scopes", "ip_whitelist", "allowed_endpoints", "rate_limit_override",
	"environment", "is_active", "usage_count",
	"last_used_at", "last_used_ip", "created_at", "expires_at", "revoked_at", "created_by",
}

func sampleAPIKey() *models.APIKey {
	desc := "Test API Key"
	env := "production"
	return &models.APIKey{
		ID:          uuid.New(),
		TenantID:    uuid.New(),
		UserID:      uuid.New(),
		Name:        "My API Key",
		Description: &desc,
		KeyPrefix:   "mykey_",
		KeyHash:     "hashedvalue",
		Scopes:      pq.StringArray{"read", "write"},
		Environment: env,
		IsActive:    true,
		CreatedAt:   time.Now(),
	}
}

func TestAPIKeyRepository_Create(t *testing.T) {
	now := time.Now()
	keyID := uuid.New()

	t.Run("success", func(t *testing.T) {
		mock, repo := newAPIKeyMock(t)
		defer mock.Close()

		key := sampleAPIKey()
		rows := mock.NewRows([]string{"id", "created_at"}).AddRow(keyID, now)
		// Create passes 14 args: tenant_id, user_id, name, description, key_prefix, key_hash,
		// scopes, ip_whitelist, allowed_endpoints, rate_limit_override,
		// environment, is_active, expires_at, created_by
		mock.ExpectQuery(`INSERT INTO iam_api_keys`).
			WithArgs(
				pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(),
				pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(),
				pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(),
				pgxmock.AnyArg(), pgxmock.AnyArg(),
			).
			WillReturnRows(rows)

		err := repo.Create(context.Background(), key)
		assert.NoError(t, err)
		assert.Equal(t, keyID, key.ID)
		assert.Equal(t, now, key.CreatedAt)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("db error", func(t *testing.T) {
		mock, repo := newAPIKeyMock(t)
		defer mock.Close()

		key := sampleAPIKey()
		mock.ExpectQuery(`INSERT INTO iam_api_keys`).
			WithArgs(
				pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(),
				pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(),
				pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(),
				pgxmock.AnyArg(), pgxmock.AnyArg(),
			).
			WillReturnError(fmt.Errorf("duplicate key_prefix"))

		err := repo.Create(context.Background(), key)
		assert.Error(t, err)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

func TestAPIKeyRepository_GetByID(t *testing.T) {
	now := time.Now()
	key := sampleAPIKey()

	t.Run("found", func(t *testing.T) {
		mock, repo := newAPIKeyMock(t)
		defer mock.Close()

		rows := mock.NewRows(apiKeyCols).AddRow(
			key.ID, key.TenantID, key.UserID, key.Name, key.Description,
			key.KeyPrefix, key.KeyHash, key.Scopes, pq.StringArray{}, pq.StringArray{},
			nil, key.Environment, key.IsActive, int64(0),
			nil, nil, now, nil, nil, nil,
		)
		mock.ExpectQuery(`SELECT`).WithArgs(key.ID).WillReturnRows(rows)

		got, err := repo.GetByID(context.Background(), key.ID)
		require.NoError(t, err)
		require.NotNil(t, got)
		assert.Equal(t, key.ID, got.ID)
		assert.Equal(t, key.Name, got.Name)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("not found returns nil", func(t *testing.T) {
		mock, repo := newAPIKeyMock(t)
		defer mock.Close()

		rows := mock.NewRows(apiKeyCols)
		mock.ExpectQuery(`SELECT`).WithArgs(key.ID).WillReturnRows(rows)

		got, err := repo.GetByID(context.Background(), key.ID)
		assert.NoError(t, err)
		assert.Nil(t, got)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

func TestAPIKeyRepository_GetByPrefix(t *testing.T) {
	now := time.Now()
	key := sampleAPIKey()

	t.Run("found active key", func(t *testing.T) {
		mock, repo := newAPIKeyMock(t)
		defer mock.Close()

		rows := mock.NewRows(apiKeyCols).AddRow(
			key.ID, key.TenantID, key.UserID, key.Name, key.Description,
			key.KeyPrefix, key.KeyHash, key.Scopes, pq.StringArray{}, pq.StringArray{},
			nil, key.Environment, key.IsActive, int64(0),
			nil, nil, now, nil, nil, nil,
		)
		mock.ExpectQuery(`SELECT`).WithArgs(key.KeyPrefix).WillReturnRows(rows)

		got, err := repo.GetByPrefix(context.Background(), key.KeyPrefix)
		require.NoError(t, err)
		require.NotNil(t, got)
		assert.Equal(t, key.KeyPrefix, got.KeyPrefix)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("not found", func(t *testing.T) {
		mock, repo := newAPIKeyMock(t)
		defer mock.Close()

		rows := mock.NewRows(apiKeyCols)
		mock.ExpectQuery(`SELECT`).WithArgs(key.KeyPrefix).WillReturnRows(rows)

		got, err := repo.GetByPrefix(context.Background(), key.KeyPrefix)
		assert.NoError(t, err)
		assert.Nil(t, got)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

func TestAPIKeyRepository_GetByTenantID(t *testing.T) {
	now := time.Now()
	key := sampleAPIKey()

	t.Run("returns keys for tenant", func(t *testing.T) {
		mock, repo := newAPIKeyMock(t)
		defer mock.Close()

		rows := mock.NewRows(apiKeyCols).AddRow(
			key.ID, key.TenantID, key.UserID, key.Name, key.Description,
			key.KeyPrefix, key.KeyHash, key.Scopes, pq.StringArray{}, pq.StringArray{},
			nil, key.Environment, key.IsActive, int64(0),
			nil, nil, now, nil, nil, nil,
		)
		mock.ExpectQuery(`SELECT`).WithArgs(key.TenantID).WillReturnRows(rows)

		keys, err := repo.GetByTenantID(context.Background(), key.TenantID)
		require.NoError(t, err)
		assert.Len(t, keys, 1)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

func TestAPIKeyRepository_GetByUserID(t *testing.T) {
	now := time.Now()
	key := sampleAPIKey()

	t.Run("returns keys for user", func(t *testing.T) {
		mock, repo := newAPIKeyMock(t)
		defer mock.Close()

		rows := mock.NewRows(apiKeyCols).AddRow(
			key.ID, key.TenantID, key.UserID, key.Name, key.Description,
			key.KeyPrefix, key.KeyHash, key.Scopes, pq.StringArray{}, pq.StringArray{},
			nil, key.Environment, key.IsActive, int64(0),
			nil, nil, now, nil, nil, nil,
		)
		mock.ExpectQuery(`SELECT`).WithArgs(key.UserID).WillReturnRows(rows)

		keys, err := repo.GetByUserID(context.Background(), key.UserID)
		require.NoError(t, err)
		assert.Len(t, keys, 1)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

func TestAPIKeyRepository_Update(t *testing.T) {
	key := sampleAPIKey()

	t.Run("success", func(t *testing.T) {
		mock, repo := newAPIKeyMock(t)
		defer mock.Close()

		// Update passes 10 args: name, description, scopes, ip_whitelist,
		// allowed_endpoints, rate_limit_override, environment, is_active, expires_at, id
		mock.ExpectExec(`UPDATE iam_api_keys`).
			WithArgs(
				pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(),
				pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(),
				pgxmock.AnyArg(), pgxmock.AnyArg(),
			).
			WillReturnResult(pgxmock.NewResult("UPDATE", 1))

		err := repo.Update(context.Background(), key)
		assert.NoError(t, err)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("not found", func(t *testing.T) {
		mock, repo := newAPIKeyMock(t)
		defer mock.Close()

		mock.ExpectExec(`UPDATE iam_api_keys`).
			WithArgs(
				pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(),
				pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(),
				pgxmock.AnyArg(), pgxmock.AnyArg(),
			).
			WillReturnResult(pgxmock.NewResult("UPDATE", 0))

		err := repo.Update(context.Background(), key)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "not found")
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

func TestAPIKeyRepository_Revoke(t *testing.T) {
	keyID := uuid.New()

	t.Run("success", func(t *testing.T) {
		mock, repo := newAPIKeyMock(t)
		defer mock.Close()

		// Revoke passes 1 arg: id
		mock.ExpectExec(`UPDATE iam_api_keys SET revoked_at`).
			WithArgs(pgxmock.AnyArg()).
			WillReturnResult(pgxmock.NewResult("UPDATE", 1))

		err := repo.Revoke(context.Background(), keyID)
		assert.NoError(t, err)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("not found", func(t *testing.T) {
		mock, repo := newAPIKeyMock(t)
		defer mock.Close()

		mock.ExpectExec(`UPDATE iam_api_keys SET revoked_at`).
			WithArgs(pgxmock.AnyArg()).
			WillReturnResult(pgxmock.NewResult("UPDATE", 0))

		err := repo.Revoke(context.Background(), keyID)
		assert.Error(t, err)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

func TestAPIKeyRepository_Delete(t *testing.T) {
	keyID := uuid.New()

	t.Run("success", func(t *testing.T) {
		mock, repo := newAPIKeyMock(t)
		defer mock.Close()

		// Delete passes 1 arg: id
		mock.ExpectExec(`DELETE FROM iam_api_keys`).
			WithArgs(pgxmock.AnyArg()).
			WillReturnResult(pgxmock.NewResult("DELETE", 1))

		err := repo.Delete(context.Background(), keyID)
		assert.NoError(t, err)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("not found", func(t *testing.T) {
		mock, repo := newAPIKeyMock(t)
		defer mock.Close()

		mock.ExpectExec(`DELETE FROM iam_api_keys`).
			WithArgs(pgxmock.AnyArg()).
			WillReturnResult(pgxmock.NewResult("DELETE", 0))

		err := repo.Delete(context.Background(), keyID)
		assert.Error(t, err)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

func TestAPIKeyRepository_UpdateLastUsed(t *testing.T) {
	keyID := uuid.New()
	ip := "10.0.0.5"

	t.Run("success", func(t *testing.T) {
		mock, repo := newAPIKeyMock(t)
		defer mock.Close()

		// UpdateLastUsed passes 2 args: ip, id
		mock.ExpectExec(`UPDATE iam_api_keys`).
			WithArgs(pgxmock.AnyArg(), pgxmock.AnyArg()).
			WillReturnResult(pgxmock.NewResult("UPDATE", 1))

		err := repo.UpdateLastUsed(context.Background(), keyID, ip)
		assert.NoError(t, err)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

func TestAPIKeyRepository_LogUsage(t *testing.T) {
	now := time.Now()
	usageID := uuid.New()

	t.Run("success", func(t *testing.T) {
		mock, repo := newAPIKeyMock(t)
		defer mock.Close()

		usage := &models.APIKeyUsage{
			APIKeyID: uuid.New(),
			TenantID: uuid.New(),
			Endpoint: "/api/v1/users",
			Method:   "GET",
		}

		rows := mock.NewRows([]string{"id", "created_at"}).AddRow(usageID, now)
		// LogUsage passes 8 args: api_key_id, tenant_id, endpoint, method,
		// status_code, response_time_ms, ip_address, user_agent
		mock.ExpectQuery(`INSERT INTO iam_api_key_usage`).
			WithArgs(
				pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(),
				pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(),
			).
			WillReturnRows(rows)

		err := repo.LogUsage(context.Background(), usage)
		assert.NoError(t, err)
		assert.Equal(t, usageID, usage.ID)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

func TestAPIKeyRepository_CleanupOldUsageLogs(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		mock, repo := newAPIKeyMock(t)
		defer mock.Close()

		// CleanupOldUsageLogs passes 1 arg: daysToKeep
		mock.ExpectExec(`DELETE FROM iam_api_key_usage`).
			WithArgs(pgxmock.AnyArg()).
			WillReturnResult(pgxmock.NewResult("DELETE", 100))

		count, err := repo.CleanupOldUsageLogs(context.Background(), 90)
		assert.NoError(t, err)
		assert.Equal(t, int64(100), count)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}
