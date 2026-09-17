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
	"github.com/dogukanturhal/falcon-id/pkg/crypto"
)

// ─── helpers ─────────────────────────────────────────────────────────────────

func newFederatedAccountMock(t *testing.T) (pgxmock.PgxPoolIface, *FederatedAccountRepository) {
	t.Helper()
	mock, err := pgxmock.NewPool()
	require.NoError(t, err)
	return mock, newFederatedAccountRepositoryWithMock(mock)
}

var federatedAccountCols = []string{
	"id", "user_id", "provider_id", "provider_user_id", "provider_username", "provider_email",
	"access_token", "refresh_token", "token_expires_at", "profile_data",
	"first_linked_at", "last_used_at", "created_at", "updated_at",
}

func sampleFederatedAccount() *models.FederatedAccount {
	now := time.Now()
	username := "jdoe"
	email := "jdoe@example.com"
	return &models.FederatedAccount{
		ID:               uuid.New(),
		UserID:           uuid.New(),
		ProviderID:       uuid.New(),
		ProviderUserID:   "google-sub-12345",
		ProviderUsername: &username,
		ProviderEmail:    &email,
		ProfileData:      map[string]interface{}{"locale": "en"},
		FirstLinkedAt:    now,
		CreatedAt:        now,
		UpdatedAt:        now,
	}
}

// addFederatedAccountRow adds a row for federatedAccountCols scan.
// ProfileData is encoded as JSON bytes.
func addFederatedAccountRow(rows *pgxmock.Rows, a *models.FederatedAccount) *pgxmock.Rows {
	return rows.AddRow(
		a.ID, a.UserID, a.ProviderID, a.ProviderUserID,
		a.ProviderUsername, a.ProviderEmail,
		a.AccessToken, a.RefreshToken, a.TokenExpiresAt,
		[]byte(`{"locale":"en"}`), // profile_data as JSON bytes
		a.FirstLinkedAt, a.LastUsedAt, a.CreatedAt, a.UpdatedAt,
	)
}

// newFederatedAccountMockWithEncryption returns a repo with a real EncryptionService
// so that encryptTokens does not fail immediately when the service is nil.
func newFederatedAccountMockWithEncryption(t *testing.T) (pgxmock.PgxPoolIface, *FederatedAccountRepository) {
	t.Helper()
	mock, repo := newFederatedAccountMock(t)
	// Wire a real encryption service to bypass the "not configured" guard.
	svc, err := crypto.NewEncryptionService("0123456789abcdef0123456789abcdef")
	require.NoError(t, err)
	repo.encryptionService = svc
	return mock, repo
}

// ─── Create ──────────────────────────────────────────────────────────────────

func TestFederatedAccountRepository_Create(t *testing.T) {
	// encryptTokens requires encryptionService to be set unconditionally.
	// Tests that reach the DB layer must wire a real EncryptionService.

	t.Run("success — encryption service wired, no tokens", func(t *testing.T) {
		mock, repo := newFederatedAccountMockWithEncryption(t)
		defer mock.Close()

		account := sampleFederatedAccount()
		now := time.Now()
		rows := mock.NewRows([]string{"created_at", "updated_at"}).AddRow(now, now)
		mock.ExpectQuery(`INSERT INTO iam_federated_accounts`).
			WithArgs(anyArgs(11)...).
			WillReturnRows(rows)

		err := repo.Create(context.Background(), account)
		require.NoError(t, err)
		assert.Equal(t, now, account.CreatedAt)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("auto-assigns UUID when nil", func(t *testing.T) {
		mock, repo := newFederatedAccountMockWithEncryption(t)
		defer mock.Close()

		account := sampleFederatedAccount()
		account.ID = uuid.Nil

		now := time.Now()
		rows := mock.NewRows([]string{"created_at", "updated_at"}).AddRow(now, now)
		mock.ExpectQuery(`INSERT INTO iam_federated_accounts`).
			WithArgs(anyArgs(11)...).
			WillReturnRows(rows)

		err := repo.Create(context.Background(), account)
		require.NoError(t, err)
		assert.NotEqual(t, uuid.Nil, account.ID)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("no encryption service always returns error", func(t *testing.T) {
		_, repo := newFederatedAccountMock(t)

		account := sampleFederatedAccount()
		// encryptTokens returns error immediately when service is nil.
		err := repo.Create(context.Background(), account)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "encryption service not configured")
	})

	t.Run("db error propagates", func(t *testing.T) {
		mock, repo := newFederatedAccountMockWithEncryption(t)
		defer mock.Close()

		account := sampleFederatedAccount()
		mock.ExpectQuery(`INSERT INTO iam_federated_accounts`).
			WithArgs(anyArgs(11)...).
			WillReturnError(fmt.Errorf("unique constraint violation"))

		err := repo.Create(context.Background(), account)
		assert.Error(t, err)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

// ─── GetByID ─────────────────────────────────────────────────────────────────

func TestFederatedAccountRepository_GetByID(t *testing.T) {
	t.Run("found", func(t *testing.T) {
		mock, repo := newFederatedAccountMock(t)
		defer mock.Close()

		account := sampleFederatedAccount()
		rows := addFederatedAccountRow(mock.NewRows(federatedAccountCols), account)
		mock.ExpectQuery(`SELECT`).WithArgs(account.ID).WillReturnRows(rows)

		got, err := repo.GetByID(context.Background(), account.ID)
		require.NoError(t, err)
		require.NotNil(t, got)
		assert.Equal(t, account.ID, got.ID)
		assert.Equal(t, account.ProviderUserID, got.ProviderUserID)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("not found returns nil", func(t *testing.T) {
		mock, repo := newFederatedAccountMock(t)
		defer mock.Close()

		id := uuid.New()
		mock.ExpectQuery(`SELECT`).WithArgs(id).WillReturnRows(mock.NewRows(federatedAccountCols))

		got, err := repo.GetByID(context.Background(), id)
		assert.NoError(t, err)
		assert.Nil(t, got)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("db error propagates", func(t *testing.T) {
		mock, repo := newFederatedAccountMock(t)
		defer mock.Close()

		id := uuid.New()
		mock.ExpectQuery(`SELECT`).WithArgs(id).WillReturnError(fmt.Errorf("db down"))

		got, err := repo.GetByID(context.Background(), id)
		assert.Error(t, err)
		assert.Nil(t, got)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

// ─── GetByUserAndProvider ────────────────────────────────────────────────────

func TestFederatedAccountRepository_GetByUserAndProvider(t *testing.T) {
	t.Run("found", func(t *testing.T) {
		mock, repo := newFederatedAccountMock(t)
		defer mock.Close()

		account := sampleFederatedAccount()
		rows := addFederatedAccountRow(mock.NewRows(federatedAccountCols), account)
		mock.ExpectQuery(`SELECT`).WithArgs(account.UserID, account.ProviderID).WillReturnRows(rows)

		got, err := repo.GetByUserAndProvider(context.Background(), account.UserID, account.ProviderID)
		require.NoError(t, err)
		require.NotNil(t, got)
		assert.Equal(t, account.UserID, got.UserID)
		assert.Equal(t, account.ProviderID, got.ProviderID)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("not found returns nil", func(t *testing.T) {
		mock, repo := newFederatedAccountMock(t)
		defer mock.Close()

		userID := uuid.New()
		providerID := uuid.New()
		mock.ExpectQuery(`SELECT`).WithArgs(userID, providerID).WillReturnRows(mock.NewRows(federatedAccountCols))

		got, err := repo.GetByUserAndProvider(context.Background(), userID, providerID)
		assert.NoError(t, err)
		assert.Nil(t, got)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

// ─── GetByProviderUserID ─────────────────────────────────────────────────────

func TestFederatedAccountRepository_GetByProviderUserID(t *testing.T) {
	t.Run("found", func(t *testing.T) {
		mock, repo := newFederatedAccountMock(t)
		defer mock.Close()

		account := sampleFederatedAccount()
		rows := addFederatedAccountRow(mock.NewRows(federatedAccountCols), account)
		mock.ExpectQuery(`SELECT`).WithArgs(account.ProviderID, account.ProviderUserID).WillReturnRows(rows)

		got, err := repo.GetByProviderUserID(context.Background(), account.ProviderID, account.ProviderUserID)
		require.NoError(t, err)
		require.NotNil(t, got)
		assert.Equal(t, account.ProviderUserID, got.ProviderUserID)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("not found returns nil", func(t *testing.T) {
		mock, repo := newFederatedAccountMock(t)
		defer mock.Close()

		providerID := uuid.New()
		mock.ExpectQuery(`SELECT`).WithArgs(providerID, "unknown-sub").WillReturnRows(mock.NewRows(federatedAccountCols))

		got, err := repo.GetByProviderUserID(context.Background(), providerID, "unknown-sub")
		assert.NoError(t, err)
		assert.Nil(t, got)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

// ─── GetByUser ───────────────────────────────────────────────────────────────

func TestFederatedAccountRepository_GetByUser(t *testing.T) {
	t.Run("returns all accounts for user", func(t *testing.T) {
		mock, repo := newFederatedAccountMock(t)
		defer mock.Close()

		account1 := sampleFederatedAccount()
		account2 := sampleFederatedAccount()
		account2.ID = uuid.New()
		account2.ProviderID = uuid.New()
		account2.ProviderUserID = "github-67890"

		rows := mock.NewRows(federatedAccountCols)
		rows = addFederatedAccountRow(rows, account1)
		rows = addFederatedAccountRow(rows, account2)
		mock.ExpectQuery(`SELECT`).WithArgs(account1.UserID).WillReturnRows(rows)

		accounts, err := repo.GetByUser(context.Background(), account1.UserID)
		require.NoError(t, err)
		assert.Len(t, accounts, 2)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("user with no federated accounts returns empty slice", func(t *testing.T) {
		mock, repo := newFederatedAccountMock(t)
		defer mock.Close()

		userID := uuid.New()
		mock.ExpectQuery(`SELECT`).WithArgs(userID).WillReturnRows(mock.NewRows(federatedAccountCols))

		accounts, err := repo.GetByUser(context.Background(), userID)
		require.NoError(t, err)
		assert.Empty(t, accounts)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("db error propagates", func(t *testing.T) {
		mock, repo := newFederatedAccountMock(t)
		defer mock.Close()

		userID := uuid.New()
		mock.ExpectQuery(`SELECT`).WithArgs(userID).WillReturnError(fmt.Errorf("query timeout"))

		_, err := repo.GetByUser(context.Background(), userID)
		assert.Error(t, err)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

// ─── Update ──────────────────────────────────────────────────────────────────

func TestFederatedAccountRepository_Update(t *testing.T) {
	// encryptTokens requires encryptionService to be set unconditionally.

	t.Run("success — encryption service wired, no tokens", func(t *testing.T) {
		mock, repo := newFederatedAccountMockWithEncryption(t)
		defer mock.Close()

		account := sampleFederatedAccount()
		now := time.Now()

		// UPDATE ... RETURNING updated_at: 8 args ($1=id, $2=username, $3=email, $4=access, $5=refresh, $6=expires, $7=profile, $8=last_used)
		mock.ExpectQuery(`UPDATE iam_federated_accounts SET`).
			WithArgs(anyArgs(8)...).
			WillReturnRows(mock.NewRows([]string{"updated_at"}).AddRow(now))

		err := repo.Update(context.Background(), account)
		require.NoError(t, err)
		assert.Equal(t, now, account.UpdatedAt)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("no encryption service always returns error", func(t *testing.T) {
		_, repo := newFederatedAccountMock(t)

		account := sampleFederatedAccount()
		err := repo.Update(context.Background(), account)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "encryption service not configured")
	})

	t.Run("db error propagates", func(t *testing.T) {
		mock, repo := newFederatedAccountMockWithEncryption(t)
		defer mock.Close()

		account := sampleFederatedAccount()
		mock.ExpectQuery(`UPDATE iam_federated_accounts SET`).
			WithArgs(anyArgs(8)...).
			WillReturnError(fmt.Errorf("db error"))

		err := repo.Update(context.Background(), account)
		assert.Error(t, err)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

// ─── UpdateLastUsed ──────────────────────────────────────────────────────────

func TestFederatedAccountRepository_UpdateLastUsed(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		mock, repo := newFederatedAccountMock(t)
		defer mock.Close()

		id := uuid.New()
		mock.ExpectExec(`UPDATE iam_federated_accounts SET last_used_at`).
			WithArgs(id).
			WillReturnResult(pgxmock.NewResult("UPDATE", 1))

		err := repo.UpdateLastUsed(context.Background(), id)
		assert.NoError(t, err)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("db error propagates", func(t *testing.T) {
		mock, repo := newFederatedAccountMock(t)
		defer mock.Close()

		id := uuid.New()
		mock.ExpectExec(`UPDATE iam_federated_accounts SET last_used_at`).
			WithArgs(id).
			WillReturnError(fmt.Errorf("db down"))

		err := repo.UpdateLastUsed(context.Background(), id)
		assert.Error(t, err)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

// ─── Delete ──────────────────────────────────────────────────────────────────

func TestFederatedAccountRepository_Delete(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		mock, repo := newFederatedAccountMock(t)
		defer mock.Close()

		id := uuid.New()
		mock.ExpectExec(`DELETE FROM iam_federated_accounts`).
			WithArgs(id).
			WillReturnResult(pgxmock.NewResult("DELETE", 1))

		err := repo.Delete(context.Background(), id)
		assert.NoError(t, err)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("not found silently succeeds (no rows affected)", func(t *testing.T) {
		mock, repo := newFederatedAccountMock(t)
		defer mock.Close()

		id := uuid.New()
		mock.ExpectExec(`DELETE FROM iam_federated_accounts`).
			WithArgs(id).
			WillReturnResult(pgxmock.NewResult("DELETE", 0))

		err := repo.Delete(context.Background(), id)
		// The repo does not error on 0 rows affected for deletes
		assert.NoError(t, err)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("db error propagates", func(t *testing.T) {
		mock, repo := newFederatedAccountMock(t)
		defer mock.Close()

		id := uuid.New()
		mock.ExpectExec(`DELETE FROM iam_federated_accounts`).
			WithArgs(id).
			WillReturnError(fmt.Errorf("constraint violation"))

		err := repo.Delete(context.Background(), id)
		assert.Error(t, err)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

// ─── DeleteByUserAndProvider ─────────────────────────────────────────────────

func TestFederatedAccountRepository_DeleteByUserAndProvider(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		mock, repo := newFederatedAccountMock(t)
		defer mock.Close()

		userID := uuid.New()
		providerID := uuid.New()
		mock.ExpectExec(`DELETE FROM iam_federated_accounts`).
			WithArgs(userID, providerID).
			WillReturnResult(pgxmock.NewResult("DELETE", 1))

		err := repo.DeleteByUserAndProvider(context.Background(), userID, providerID)
		assert.NoError(t, err)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("db error propagates", func(t *testing.T) {
		mock, repo := newFederatedAccountMock(t)
		defer mock.Close()

		userID := uuid.New()
		providerID := uuid.New()
		mock.ExpectExec(`DELETE FROM iam_federated_accounts`).
			WithArgs(userID, providerID).
			WillReturnError(fmt.Errorf("db error"))

		err := repo.DeleteByUserAndProvider(context.Background(), userID, providerID)
		assert.Error(t, err)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}
