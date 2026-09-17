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
)

func newMFAMock(t *testing.T) (pgxmock.PgxPoolIface, *MFARepository) {
	t.Helper()
	mock, err := pgxmock.NewPool()
	require.NoError(t, err)
	return mock, newMFARepositoryWithMock(mock)
}

// ==================== Email Verification ====================

func TestMFARepository_CreateEmailVerification(t *testing.T) {
	userID := uuid.New()

	t.Run("success", func(t *testing.T) {
		mock, repo := newMFAMock(t)
		defer mock.Close()

		mock.ExpectExec(`INSERT INTO iam_email_verifications`).
			WithArgs(anyArgs(6)...).
			WillReturnResult(pgxmock.NewResult("INSERT", 1))

		ev, err := repo.CreateEmailVerification(
			context.Background(), userID, "user@example.com", "123456",
			time.Now().Add(15*time.Minute),
		)
		require.NoError(t, err)
		require.NotNil(t, ev)
		assert.Equal(t, userID, ev.UserID)
		assert.Equal(t, "user@example.com", ev.Email)
		assert.Equal(t, "123456", ev.Code)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("db error", func(t *testing.T) {
		mock, repo := newMFAMock(t)
		defer mock.Close()

		mock.ExpectExec(`INSERT INTO iam_email_verifications`).
			WithArgs(anyArgs(6)...).
			WillReturnError(fmt.Errorf("unique constraint"))

		ev, err := repo.CreateEmailVerification(
			context.Background(), userID, "user@example.com", "123456",
			time.Now().Add(15*time.Minute),
		)
		assert.Error(t, err)
		assert.Nil(t, ev)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

func TestMFARepository_GetEmailVerification(t *testing.T) {
	now := time.Now()
	userID := uuid.New()
	evID := uuid.New()
	code := "654321"

	t.Run("found", func(t *testing.T) {
		mock, repo := newMFAMock(t)
		defer mock.Close()

		cols := []string{"id", "user_id", "email", "code", "expires_at", "verified_at", "created_at"}
		rows := mock.NewRows(cols).AddRow(
			evID, userID, "user@example.com", code, now.Add(10*time.Minute), nil, now,
		)
		mock.ExpectQuery(`SELECT`).WithArgs(userID, code).WillReturnRows(rows)

		got, err := repo.GetEmailVerification(context.Background(), userID, code)
		require.NoError(t, err)
		require.NotNil(t, got)
		assert.Equal(t, evID, got.ID)
		assert.Equal(t, code, got.Code)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("not found returns nil", func(t *testing.T) {
		mock, repo := newMFAMock(t)
		defer mock.Close()

		cols := []string{"id", "user_id", "email", "code", "expires_at", "verified_at", "created_at"}
		rows := mock.NewRows(cols)
		mock.ExpectQuery(`SELECT`).WithArgs(userID, code).WillReturnRows(rows)

		got, err := repo.GetEmailVerification(context.Background(), userID, code)
		assert.NoError(t, err)
		assert.Nil(t, got)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

func TestMFARepository_MarkEmailVerified(t *testing.T) {
	evID := uuid.New()

	t.Run("success", func(t *testing.T) {
		mock, repo := newMFAMock(t)
		defer mock.Close()

		mock.ExpectExec(`UPDATE iam_email_verifications`).
			WithArgs(evID).
			WillReturnResult(pgxmock.NewResult("UPDATE", 1))

		err := repo.MarkEmailVerified(context.Background(), evID)
		assert.NoError(t, err)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("db error", func(t *testing.T) {
		mock, repo := newMFAMock(t)
		defer mock.Close()

		mock.ExpectExec(`UPDATE iam_email_verifications`).
			WithArgs(evID).
			WillReturnError(fmt.Errorf("connection lost"))

		err := repo.MarkEmailVerified(context.Background(), evID)
		assert.Error(t, err)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

// ==================== MFA Email Codes ====================

func TestMFARepository_CreateMFAEmailCode(t *testing.T) {
	userID := uuid.New()
	codeHash := "bcrypt_hashed_123456"

	t.Run("success — invalidates old codes then inserts", func(t *testing.T) {
		mock, repo := newMFAMock(t)
		defer mock.Close()

		mock.ExpectExec(`DELETE FROM iam_mfa_email_codes`).
			WithArgs(userID).
			WillReturnResult(pgxmock.NewResult("DELETE", 0))
		mock.ExpectExec(`INSERT INTO iam_mfa_email_codes`).
			WithArgs(anyArgs(5)...).
			WillReturnResult(pgxmock.NewResult("INSERT", 1))

		code, err := repo.CreateMFAEmailCode(
			context.Background(), userID, codeHash, time.Now().Add(5*time.Minute),
		)
		require.NoError(t, err)
		require.NotNil(t, code)
		assert.Equal(t, userID, code.UserID)
		assert.Equal(t, codeHash, code.CodeHash)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("delete error", func(t *testing.T) {
		mock, repo := newMFAMock(t)
		defer mock.Close()

		mock.ExpectExec(`DELETE FROM iam_mfa_email_codes`).
			WithArgs(userID).
			WillReturnError(fmt.Errorf("connection refused"))

		code, err := repo.CreateMFAEmailCode(
			context.Background(), userID, codeHash, time.Now().Add(5*time.Minute),
		)
		assert.Error(t, err)
		assert.Nil(t, code)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("insert error", func(t *testing.T) {
		mock, repo := newMFAMock(t)
		defer mock.Close()

		mock.ExpectExec(`DELETE FROM iam_mfa_email_codes`).
			WithArgs(userID).
			WillReturnResult(pgxmock.NewResult("DELETE", 0))
		mock.ExpectExec(`INSERT INTO iam_mfa_email_codes`).
			WithArgs(anyArgs(5)...).
			WillReturnError(fmt.Errorf("insert failed"))

		code, err := repo.CreateMFAEmailCode(
			context.Background(), userID, codeHash, time.Now().Add(5*time.Minute),
		)
		assert.Error(t, err)
		assert.Nil(t, code)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

func TestMFARepository_GetActiveMFAEmailCode(t *testing.T) {
	now := time.Now()
	userID := uuid.New()
	codeID := uuid.New()

	t.Run("found active code", func(t *testing.T) {
		mock, repo := newMFAMock(t)
		defer mock.Close()

		cols := []string{"id", "user_id", "code_hash", "expires_at", "used_at", "created_at"}
		rows := mock.NewRows(cols).AddRow(
			codeID, userID, "hash_abc", now.Add(3*time.Minute), nil, now,
		)
		mock.ExpectQuery(`SELECT`).WithArgs(userID).WillReturnRows(rows)

		got, err := repo.GetActiveMFAEmailCode(context.Background(), userID)
		require.NoError(t, err)
		require.NotNil(t, got)
		assert.Equal(t, codeID, got.ID)
		assert.Nil(t, got.UsedAt)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("no active code returns nil", func(t *testing.T) {
		mock, repo := newMFAMock(t)
		defer mock.Close()

		cols := []string{"id", "user_id", "code_hash", "expires_at", "used_at", "created_at"}
		rows := mock.NewRows(cols)
		mock.ExpectQuery(`SELECT`).WithArgs(userID).WillReturnRows(rows)

		got, err := repo.GetActiveMFAEmailCode(context.Background(), userID)
		assert.NoError(t, err)
		assert.Nil(t, got)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

func TestMFARepository_MarkMFAEmailCodeUsed(t *testing.T) {
	codeID := uuid.New()

	t.Run("success", func(t *testing.T) {
		mock, repo := newMFAMock(t)
		defer mock.Close()

		mock.ExpectExec(`UPDATE iam_mfa_email_codes`).
			WithArgs(codeID).
			WillReturnResult(pgxmock.NewResult("UPDATE", 1))

		err := repo.MarkMFAEmailCodeUsed(context.Background(), codeID)
		assert.NoError(t, err)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("db error", func(t *testing.T) {
		mock, repo := newMFAMock(t)
		defer mock.Close()

		mock.ExpectExec(`UPDATE iam_mfa_email_codes`).
			WithArgs(codeID).
			WillReturnError(fmt.Errorf("timeout"))

		err := repo.MarkMFAEmailCodeUsed(context.Background(), codeID)
		assert.Error(t, err)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

// ==================== MFA Pending Setup ====================

func TestMFARepository_CreateMFAPendingSetup(t *testing.T) {
	userID := uuid.New()
	secret := "JBSWY3DPEHPK3PXP" //nolint:gosec // test fixture value, not a real credential

	t.Run("success — clears old then inserts", func(t *testing.T) {
		mock, repo := newMFAMock(t)
		defer mock.Close()

		mock.ExpectExec(`DELETE FROM iam_mfa_pending_setup`).
			WithArgs(userID).
			WillReturnResult(pgxmock.NewResult("DELETE", 0))
		mock.ExpectExec(`INSERT INTO iam_mfa_pending_setup`).
			WithArgs(anyArgs(6)...).
			WillReturnResult(pgxmock.NewResult("INSERT", 1))

		setup, err := repo.CreateMFAPendingSetup(
			context.Background(), userID, secret, "totp", time.Now().Add(10*time.Minute),
		)
		require.NoError(t, err)
		require.NotNil(t, setup)
		assert.Equal(t, userID, setup.UserID)
		assert.Equal(t, secret, setup.Secret)
		assert.Equal(t, "totp", setup.MFAType)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("delete error", func(t *testing.T) {
		mock, repo := newMFAMock(t)
		defer mock.Close()

		mock.ExpectExec(`DELETE FROM iam_mfa_pending_setup`).
			WithArgs(userID).
			WillReturnError(fmt.Errorf("connection lost"))

		setup, err := repo.CreateMFAPendingSetup(
			context.Background(), userID, secret, "totp", time.Now().Add(10*time.Minute),
		)
		assert.Error(t, err)
		assert.Nil(t, setup)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

func TestMFARepository_GetMFAPendingSetup(t *testing.T) {
	now := time.Now()
	userID := uuid.New()
	setupID := uuid.New()

	t.Run("found", func(t *testing.T) {
		mock, repo := newMFAMock(t)
		defer mock.Close()

		cols := []string{"id", "user_id", "secret", "mfa_type", "expires_at", "created_at"}
		rows := mock.NewRows(cols).AddRow(
			setupID, userID, "JBSWY3DPEHPK3PXP", "totp", now.Add(5*time.Minute), now,
		)
		mock.ExpectQuery(`SELECT`).WithArgs(userID).WillReturnRows(rows)

		got, err := repo.GetMFAPendingSetup(context.Background(), userID)
		require.NoError(t, err)
		require.NotNil(t, got)
		assert.Equal(t, setupID, got.ID)
		assert.Equal(t, "totp", got.MFAType)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("not found returns nil", func(t *testing.T) {
		mock, repo := newMFAMock(t)
		defer mock.Close()

		cols := []string{"id", "user_id", "secret", "mfa_type", "expires_at", "created_at"}
		rows := mock.NewRows(cols)
		mock.ExpectQuery(`SELECT`).WithArgs(userID).WillReturnRows(rows)

		got, err := repo.GetMFAPendingSetup(context.Background(), userID)
		assert.NoError(t, err)
		assert.Nil(t, got)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

func TestMFARepository_DeleteMFAPendingSetup(t *testing.T) {
	userID := uuid.New()

	t.Run("success", func(t *testing.T) {
		mock, repo := newMFAMock(t)
		defer mock.Close()

		mock.ExpectExec(`DELETE FROM iam_mfa_pending_setup`).
			WithArgs(userID).
			WillReturnResult(pgxmock.NewResult("DELETE", 1))

		err := repo.DeleteMFAPendingSetup(context.Background(), userID)
		assert.NoError(t, err)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("db error", func(t *testing.T) {
		mock, repo := newMFAMock(t)
		defer mock.Close()

		mock.ExpectExec(`DELETE FROM iam_mfa_pending_setup`).
			WithArgs(userID).
			WillReturnError(fmt.Errorf("timeout"))

		err := repo.DeleteMFAPendingSetup(context.Background(), userID)
		assert.Error(t, err)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

// ==================== Recovery Codes ====================

func TestMFARepository_CreateRecoveryCodes(t *testing.T) {
	userID := uuid.New()
	hashes := []string{"hash1", "hash2", "hash3", "hash4", "hash5", "hash6", "hash7", "hash8"}

	t.Run("success", func(t *testing.T) {
		mock, repo := newMFAMock(t)
		defer mock.Close()

		// First deletes unused codes
		mock.ExpectExec(`DELETE FROM iam_mfa_recovery_codes`).
			WithArgs(userID).
			WillReturnResult(pgxmock.NewResult("DELETE", 0))
		// Then inserts each hash individually
		for range hashes {
			mock.ExpectExec(`INSERT INTO iam_mfa_recovery_codes`).
				WithArgs(anyArgs(2)...).
				WillReturnResult(pgxmock.NewResult("INSERT", 1))
		}

		err := repo.CreateRecoveryCodes(context.Background(), userID, hashes)
		assert.NoError(t, err)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("delete error", func(t *testing.T) {
		mock, repo := newMFAMock(t)
		defer mock.Close()

		mock.ExpectExec(`DELETE FROM iam_mfa_recovery_codes`).
			WithArgs(userID).
			WillReturnError(fmt.Errorf("connection refused"))

		err := repo.CreateRecoveryCodes(context.Background(), userID, hashes)
		assert.Error(t, err)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("insert error on second hash", func(t *testing.T) {
		mock, repo := newMFAMock(t)
		defer mock.Close()

		mock.ExpectExec(`DELETE FROM iam_mfa_recovery_codes`).
			WithArgs(userID).
			WillReturnResult(pgxmock.NewResult("DELETE", 0))
		mock.ExpectExec(`INSERT INTO iam_mfa_recovery_codes`).
			WithArgs(anyArgs(2)...).
			WillReturnResult(pgxmock.NewResult("INSERT", 1))
		mock.ExpectExec(`INSERT INTO iam_mfa_recovery_codes`).
			WithArgs(anyArgs(2)...).
			WillReturnError(fmt.Errorf("duplicate key"))

		err := repo.CreateRecoveryCodes(context.Background(), userID, hashes[:2])
		assert.Error(t, err)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

func TestMFARepository_GetUnusedRecoveryCodes(t *testing.T) {
	now := time.Now()
	userID := uuid.New()

	t.Run("returns unused codes", func(t *testing.T) {
		mock, repo := newMFAMock(t)
		defer mock.Close()

		cols := []string{"id", "user_id", "code_hash", "created_at", "used_at"}
		rows := mock.NewRows(cols).
			AddRow(uuid.New(), userID, "hash1", now, nil).
			AddRow(uuid.New(), userID, "hash2", now, nil)

		mock.ExpectQuery(`SELECT`).WithArgs(userID).WillReturnRows(rows)

		codes, err := repo.GetUnusedRecoveryCodes(context.Background(), userID)
		require.NoError(t, err)
		assert.Len(t, codes, 2)
		assert.Nil(t, codes[0].UsedAt)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("no unused codes", func(t *testing.T) {
		mock, repo := newMFAMock(t)
		defer mock.Close()

		cols := []string{"id", "user_id", "code_hash", "created_at", "used_at"}
		rows := mock.NewRows(cols)
		mock.ExpectQuery(`SELECT`).WithArgs(userID).WillReturnRows(rows)

		codes, err := repo.GetUnusedRecoveryCodes(context.Background(), userID)
		require.NoError(t, err)
		assert.Empty(t, codes)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

func TestMFARepository_UseRecoveryCode(t *testing.T) {
	codeID := uuid.New()

	t.Run("success", func(t *testing.T) {
		mock, repo := newMFAMock(t)
		defer mock.Close()

		mock.ExpectExec(`UPDATE iam_mfa_recovery_codes`).
			WithArgs(codeID).
			WillReturnResult(pgxmock.NewResult("UPDATE", 1))

		err := repo.UseRecoveryCode(context.Background(), codeID)
		assert.NoError(t, err)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("db error", func(t *testing.T) {
		mock, repo := newMFAMock(t)
		defer mock.Close()

		mock.ExpectExec(`UPDATE iam_mfa_recovery_codes`).
			WithArgs(codeID).
			WillReturnError(fmt.Errorf("connection refused"))

		err := repo.UseRecoveryCode(context.Background(), codeID)
		assert.Error(t, err)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

func TestMFARepository_DeleteAllRecoveryCodes(t *testing.T) {
	userID := uuid.New()

	t.Run("success", func(t *testing.T) {
		mock, repo := newMFAMock(t)
		defer mock.Close()

		mock.ExpectExec(`DELETE FROM iam_mfa_recovery_codes`).
			WithArgs(userID).
			WillReturnResult(pgxmock.NewResult("DELETE", 8))

		err := repo.DeleteAllRecoveryCodes(context.Background(), userID)
		assert.NoError(t, err)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("db error", func(t *testing.T) {
		mock, repo := newMFAMock(t)
		defer mock.Close()

		mock.ExpectExec(`DELETE FROM iam_mfa_recovery_codes`).
			WithArgs(userID).
			WillReturnError(fmt.Errorf("timeout"))

		err := repo.DeleteAllRecoveryCodes(context.Background(), userID)
		assert.Error(t, err)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

func TestMFARepository_CleanupExpired(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		mock, repo := newMFAMock(t)
		defer mock.Close()

		mock.ExpectExec(`SELECT cleanup_expired_mfa_records`).
			WillReturnResult(pgxmock.NewResult("SELECT", 0))

		err := repo.CleanupExpired(context.Background())
		assert.NoError(t, err)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("db error", func(t *testing.T) {
		mock, repo := newMFAMock(t)
		defer mock.Close()

		mock.ExpectExec(`SELECT cleanup_expired_mfa_records`).
			WillReturnError(fmt.Errorf("function does not exist"))

		err := repo.CleanupExpired(context.Background())
		assert.Error(t, err)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}
