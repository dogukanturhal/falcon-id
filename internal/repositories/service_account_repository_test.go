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

func newServiceAccountMock(t *testing.T) (pgxmock.PgxPoolIface, *ServiceAccountRepository) {
	t.Helper()
	mock, err := pgxmock.NewPool()
	require.NoError(t, err)
	return mock, newServiceAccountRepositoryWithMock(mock)
}

var serviceAccountCols = []string{
	"id", "tenant_id", "name", "description", "client_id", "client_secret_hash",
	"role_ids", "allowed_ips", "allowed_endpoints", "is_active",
	"last_used_at", "last_used_ip", "token_lifetime_minutes",
	"created_at", "updated_at", "created_by",
}

func sampleServiceAccount() *models.ServiceAccount {
	desc := "Backend service account"
	return &models.ServiceAccount{
		ID:                   uuid.New(),
		TenantID:             uuid.New(),
		Name:                 "backend-service",
		Description:          &desc,
		ClientID:             "client_" + uuid.New().String(),
		ClientSecretHash:     "hashed_secret",
		RoleIDs:              pq.StringArray{"role_admin"},
		AllowedIPs:           pq.StringArray{},
		AllowedEndpoints:     pq.StringArray{},
		IsActive:             true,
		TokenLifetimeMinutes: 60,
		CreatedAt:            time.Now(),
		UpdatedAt:            time.Now(),
	}
}

func TestServiceAccountRepository_Create(t *testing.T) {
	now := time.Now()
	saID := uuid.New()

	t.Run("success", func(t *testing.T) {
		mock, repo := newServiceAccountMock(t)
		defer mock.Close()

		sa := sampleServiceAccount()
		rows := mock.NewRows([]string{"id", "created_at", "updated_at"}).AddRow(saID, now, now)
		mock.ExpectQuery(`INSERT INTO iam_service_accounts`).
			WithArgs(anyArgs(11)...).
			WillReturnRows(rows)

		err := repo.Create(context.Background(), sa)
		assert.NoError(t, err)
		assert.Equal(t, saID, sa.ID)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("db error", func(t *testing.T) {
		mock, repo := newServiceAccountMock(t)
		defer mock.Close()

		sa := sampleServiceAccount()
		mock.ExpectQuery(`INSERT INTO iam_service_accounts`).
			WithArgs(anyArgs(11)...).
			WillReturnError(fmt.Errorf("unique constraint on client_id"))

		err := repo.Create(context.Background(), sa)
		assert.Error(t, err)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

func TestServiceAccountRepository_GetByID(t *testing.T) {
	now := time.Now()
	sa := sampleServiceAccount()

	t.Run("found", func(t *testing.T) {
		mock, repo := newServiceAccountMock(t)
		defer mock.Close()

		rows := mock.NewRows(serviceAccountCols).AddRow(
			sa.ID, sa.TenantID, sa.Name, sa.Description, sa.ClientID, sa.ClientSecretHash,
			sa.RoleIDs, sa.AllowedIPs, sa.AllowedEndpoints, sa.IsActive,
			nil, nil, sa.TokenLifetimeMinutes,
			now, now, nil,
		)
		mock.ExpectQuery(`SELECT`).WithArgs(sa.ID).WillReturnRows(rows)

		got, err := repo.GetByID(context.Background(), sa.ID)
		require.NoError(t, err)
		require.NotNil(t, got)
		assert.Equal(t, sa.ID, got.ID)
		assert.Equal(t, sa.Name, got.Name)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("not found returns nil", func(t *testing.T) {
		mock, repo := newServiceAccountMock(t)
		defer mock.Close()

		rows := mock.NewRows(serviceAccountCols)
		mock.ExpectQuery(`SELECT`).WithArgs(sa.ID).WillReturnRows(rows)

		got, err := repo.GetByID(context.Background(), sa.ID)
		assert.NoError(t, err)
		assert.Nil(t, got)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

func TestServiceAccountRepository_GetByClientID(t *testing.T) {
	now := time.Now()
	sa := sampleServiceAccount()

	t.Run("found", func(t *testing.T) {
		mock, repo := newServiceAccountMock(t)
		defer mock.Close()

		rows := mock.NewRows(serviceAccountCols).AddRow(
			sa.ID, sa.TenantID, sa.Name, sa.Description, sa.ClientID, sa.ClientSecretHash,
			sa.RoleIDs, sa.AllowedIPs, sa.AllowedEndpoints, sa.IsActive,
			nil, nil, sa.TokenLifetimeMinutes,
			now, now, nil,
		)
		mock.ExpectQuery(`SELECT`).WithArgs(sa.ClientID).WillReturnRows(rows)

		got, err := repo.GetByClientID(context.Background(), sa.ClientID)
		require.NoError(t, err)
		require.NotNil(t, got)
		assert.Equal(t, sa.ClientID, got.ClientID)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("not found", func(t *testing.T) {
		mock, repo := newServiceAccountMock(t)
		defer mock.Close()

		rows := mock.NewRows(serviceAccountCols)
		mock.ExpectQuery(`SELECT`).WithArgs(sa.ClientID).WillReturnRows(rows)

		got, err := repo.GetByClientID(context.Background(), sa.ClientID)
		assert.NoError(t, err)
		assert.Nil(t, got)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

func TestServiceAccountRepository_GetByTenantID(t *testing.T) {
	now := time.Now()
	sa := sampleServiceAccount()

	t.Run("returns accounts for tenant", func(t *testing.T) {
		mock, repo := newServiceAccountMock(t)
		defer mock.Close()

		rows := mock.NewRows(serviceAccountCols).AddRow(
			sa.ID, sa.TenantID, sa.Name, sa.Description, sa.ClientID, sa.ClientSecretHash,
			sa.RoleIDs, sa.AllowedIPs, sa.AllowedEndpoints, sa.IsActive,
			nil, nil, sa.TokenLifetimeMinutes,
			now, now, nil,
		)
		mock.ExpectQuery(`SELECT`).WithArgs(sa.TenantID).WillReturnRows(rows)

		accounts, err := repo.GetByTenantID(context.Background(), sa.TenantID)
		require.NoError(t, err)
		assert.Len(t, accounts, 1)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

func TestServiceAccountRepository_Update(t *testing.T) {
	sa := sampleServiceAccount()

	t.Run("success", func(t *testing.T) {
		mock, repo := newServiceAccountMock(t)
		defer mock.Close()

		mock.ExpectExec(`UPDATE iam_service_accounts`).
			WithArgs(anyArgs(8)...).
			WillReturnResult(pgxmock.NewResult("UPDATE", 1))

		err := repo.Update(context.Background(), sa)
		assert.NoError(t, err)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("not found", func(t *testing.T) {
		mock, repo := newServiceAccountMock(t)
		defer mock.Close()

		mock.ExpectExec(`UPDATE iam_service_accounts`).
			WithArgs(anyArgs(8)...).
			WillReturnResult(pgxmock.NewResult("UPDATE", 0))

		err := repo.Update(context.Background(), sa)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "not found")
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

func TestServiceAccountRepository_UpdateSecret(t *testing.T) {
	saID := uuid.New()
	newHash := "new_secret_hash"

	t.Run("success", func(t *testing.T) {
		mock, repo := newServiceAccountMock(t)
		defer mock.Close()

		mock.ExpectExec(`UPDATE iam_service_accounts SET client_secret_hash`).
			WithArgs(anyArgs(2)...).
			WillReturnResult(pgxmock.NewResult("UPDATE", 1))

		err := repo.UpdateSecret(context.Background(), saID, newHash)
		assert.NoError(t, err)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("not found", func(t *testing.T) {
		mock, repo := newServiceAccountMock(t)
		defer mock.Close()

		mock.ExpectExec(`UPDATE iam_service_accounts SET client_secret_hash`).
			WithArgs(anyArgs(2)...).
			WillReturnResult(pgxmock.NewResult("UPDATE", 0))

		err := repo.UpdateSecret(context.Background(), saID, newHash)
		assert.Error(t, err)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

func TestServiceAccountRepository_Delete(t *testing.T) {
	saID := uuid.New()

	t.Run("success", func(t *testing.T) {
		mock, repo := newServiceAccountMock(t)
		defer mock.Close()

		mock.ExpectExec(`DELETE FROM iam_service_accounts`).
			WithArgs(anyArgs(1)...).
			WillReturnResult(pgxmock.NewResult("DELETE", 1))

		err := repo.Delete(context.Background(), saID)
		assert.NoError(t, err)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("not found", func(t *testing.T) {
		mock, repo := newServiceAccountMock(t)
		defer mock.Close()

		mock.ExpectExec(`DELETE FROM iam_service_accounts`).
			WithArgs(anyArgs(1)...).
			WillReturnResult(pgxmock.NewResult("DELETE", 0))

		err := repo.Delete(context.Background(), saID)
		assert.Error(t, err)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

func TestServiceAccountRepository_UpdateLastUsed(t *testing.T) {
	saID := uuid.New()
	ip := "172.16.0.1"

	t.Run("success", func(t *testing.T) {
		mock, repo := newServiceAccountMock(t)
		defer mock.Close()

		mock.ExpectExec(`UPDATE iam_service_accounts`).
			WithArgs(anyArgs(2)...).
			WillReturnResult(pgxmock.NewResult("UPDATE", 1))

		err := repo.UpdateLastUsed(context.Background(), saID, ip)
		assert.NoError(t, err)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

func TestServiceAccountRepository_CreateToken(t *testing.T) {
	now := time.Now()
	tokenID := uuid.New()

	t.Run("success", func(t *testing.T) {
		mock, repo := newServiceAccountMock(t)
		defer mock.Close()

		ip := "10.0.0.1"
		token := &models.ServiceAccountToken{
			ServiceAccountID: uuid.New(),
			TokenHash:        "token_hash_xyz",
			IPAddress:        &ip,
			ExpiresAt:        time.Now().Add(time.Hour),
		}

		rows := mock.NewRows([]string{"id", "created_at"}).AddRow(tokenID, now)
		mock.ExpectQuery(`INSERT INTO iam_service_account_tokens`).
			WithArgs(anyArgs(4)...).
			WillReturnRows(rows)

		err := repo.CreateToken(context.Background(), token)
		assert.NoError(t, err)
		assert.Equal(t, tokenID, token.ID)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

func TestServiceAccountRepository_GetActiveTokenByHash(t *testing.T) {
	now := time.Now()
	tokenID := uuid.New()
	saID := uuid.New()
	tokenHash := "active_token_hash"

	t.Run("found active token", func(t *testing.T) {
		mock, repo := newServiceAccountMock(t)
		defer mock.Close()

		rows := mock.NewRows([]string{"id", "service_account_id", "token_hash", "ip_address", "created_at", "expires_at", "revoked_at"}).
			AddRow(tokenID, saID, tokenHash, nil, now, now.Add(time.Hour), nil)
		mock.ExpectQuery(`SELECT`).WithArgs(tokenHash).WillReturnRows(rows)

		got, err := repo.GetActiveTokenByHash(context.Background(), tokenHash)
		require.NoError(t, err)
		require.NotNil(t, got)
		assert.Equal(t, tokenHash, got.TokenHash)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("not found returns nil", func(t *testing.T) {
		mock, repo := newServiceAccountMock(t)
		defer mock.Close()

		rows := mock.NewRows([]string{"id", "service_account_id", "token_hash", "ip_address", "created_at", "expires_at", "revoked_at"})
		mock.ExpectQuery(`SELECT`).WithArgs(tokenHash).WillReturnRows(rows)

		got, err := repo.GetActiveTokenByHash(context.Background(), tokenHash)
		assert.NoError(t, err)
		assert.Nil(t, got)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

func TestServiceAccountRepository_RevokeToken(t *testing.T) {
	tokenID := uuid.New()

	t.Run("success", func(t *testing.T) {
		mock, repo := newServiceAccountMock(t)
		defer mock.Close()

		mock.ExpectExec(`UPDATE iam_service_account_tokens SET revoked_at`).
			WithArgs(anyArgs(1)...).
			WillReturnResult(pgxmock.NewResult("UPDATE", 1))

		err := repo.RevokeToken(context.Background(), tokenID)
		assert.NoError(t, err)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

func TestServiceAccountRepository_RevokeAllTokens(t *testing.T) {
	saID := uuid.New()

	t.Run("success", func(t *testing.T) {
		mock, repo := newServiceAccountMock(t)
		defer mock.Close()

		mock.ExpectExec(`UPDATE iam_service_account_tokens`).
			WithArgs(anyArgs(1)...).
			WillReturnResult(pgxmock.NewResult("UPDATE", 3))

		err := repo.RevokeAllTokens(context.Background(), saID)
		assert.NoError(t, err)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

func TestServiceAccountRepository_CleanupExpiredTokens(t *testing.T) {
	t.Run("returns deleted count", func(t *testing.T) {
		mock, repo := newServiceAccountMock(t)
		defer mock.Close()

		mock.ExpectExec(`DELETE FROM iam_service_account_tokens`).
			WillReturnResult(pgxmock.NewResult("DELETE", 15))

		count, err := repo.CleanupExpiredTokens(context.Background())
		assert.NoError(t, err)
		assert.Equal(t, int64(15), count)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}
