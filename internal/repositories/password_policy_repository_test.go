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
)

func newPasswordPolicyMock(t *testing.T) (pgxmock.PgxPoolIface, *PasswordPolicyRepository) {
	t.Helper()
	mock, err := pgxmock.NewPool()
	require.NoError(t, err)
	return mock, newPasswordPolicyRepositoryWithMock(mock)
}

var passwordPolicyCols = []string{
	"id", "tenant_id", "min_length", "max_length", "require_uppercase", "require_lowercase",
	"require_numbers", "require_special", "disallow_username", "disallow_common_passwords",
	"max_age_days", "warning_days_before_expiry", "history_count", "lockout_threshold",
	"lockout_duration_minutes", "lockout_increment_factor", "require_password_change_on_first_login",
	"created_at", "updated_at", "created_by", "updated_by",
}

func intPtr(v int) *int { return &v }

func samplePasswordPolicy() *models.PasswordPolicy {
	return &models.PasswordPolicy{
		ID:                                uuid.New(),
		TenantID:                          uuid.New(),
		MinLength:                         8,
		MaxLength:                         intPtr(128),
		RequireUppercase:                  true,
		RequireLowercase:                  true,
		RequireNumbers:                    true,
		RequireSpecial:                    false,
		DisallowUsername:                  true,
		DisallowCommonPasswords:           true,
		MaxAgeDays:                        90,
		WarningDaysBeforeExpiry:           7,
		HistoryCount:                      5,
		LockoutThreshold:                  5,
		LockoutDurationMinutes:            30,
		LockoutIncrementFactor:            2.0,
		RequirePasswordChangeOnFirstLogin: false,
		CreatedAt:                         time.Now(),
		UpdatedAt:                         time.Now(),
	}
}

func TestPasswordPolicyRepository_GetByTenantID(t *testing.T) {
	now := time.Now()
	policy := samplePasswordPolicy()

	t.Run("found", func(t *testing.T) {
		mock, repo := newPasswordPolicyMock(t)
		defer mock.Close()

		rows := mock.NewRows(passwordPolicyCols).AddRow(
			policy.ID, policy.TenantID, policy.MinLength, policy.MaxLength,
			policy.RequireUppercase, policy.RequireLowercase, policy.RequireNumbers,
			policy.RequireSpecial, policy.DisallowUsername, policy.DisallowCommonPasswords,
			policy.MaxAgeDays, policy.WarningDaysBeforeExpiry, policy.HistoryCount,
			policy.LockoutThreshold, policy.LockoutDurationMinutes, policy.LockoutIncrementFactor,
			policy.RequirePasswordChangeOnFirstLogin, now, now, nil, nil,
		)
		mock.ExpectQuery(`SELECT`).WithArgs(policy.TenantID).WillReturnRows(rows)

		got, err := repo.GetByTenantID(context.Background(), policy.TenantID)
		require.NoError(t, err)
		require.NotNil(t, got)
		assert.Equal(t, policy.ID, got.ID)
		assert.Equal(t, policy.MinLength, got.MinLength)
		assert.Equal(t, policy.LockoutThreshold, got.LockoutThreshold)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("not found returns nil", func(t *testing.T) {
		mock, repo := newPasswordPolicyMock(t)
		defer mock.Close()

		rows := mock.NewRows(passwordPolicyCols)
		mock.ExpectQuery(`SELECT`).WithArgs(policy.TenantID).WillReturnRows(rows)

		got, err := repo.GetByTenantID(context.Background(), policy.TenantID)
		assert.NoError(t, err)
		assert.Nil(t, got)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("db error", func(t *testing.T) {
		mock, repo := newPasswordPolicyMock(t)
		defer mock.Close()

		mock.ExpectQuery(`SELECT`).WithArgs(policy.TenantID).
			WillReturnError(fmt.Errorf("connection refused"))

		got, err := repo.GetByTenantID(context.Background(), policy.TenantID)
		assert.Error(t, err)
		assert.Nil(t, got)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

func TestPasswordPolicyRepository_Create(t *testing.T) {
	now := time.Now()

	t.Run("success", func(t *testing.T) {
		mock, repo := newPasswordPolicyMock(t)
		defer mock.Close()

		policy := samplePasswordPolicy()
		rows := mock.NewRows([]string{"created_at", "updated_at"}).AddRow(now, now)
		mock.ExpectQuery(`INSERT INTO iam_password_policies`).
			WithArgs(anyArgs(19)...).
			WillReturnRows(rows)

		err := repo.Create(context.Background(), policy)
		assert.NoError(t, err)
		assert.Equal(t, now, policy.CreatedAt)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("db error", func(t *testing.T) {
		mock, repo := newPasswordPolicyMock(t)
		defer mock.Close()

		policy := samplePasswordPolicy()
		mock.ExpectQuery(`INSERT INTO iam_password_policies`).
			WithArgs(anyArgs(19)...).
			WillReturnError(fmt.Errorf("unique constraint on tenant_id"))

		err := repo.Create(context.Background(), policy)
		assert.Error(t, err)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

func TestPasswordPolicyRepository_Update(t *testing.T) {
	now := time.Now()

	t.Run("success", func(t *testing.T) {
		mock, repo := newPasswordPolicyMock(t)
		defer mock.Close()

		policy := samplePasswordPolicy()
		rows := mock.NewRows([]string{"updated_at"}).AddRow(now)
		mock.ExpectQuery(`UPDATE iam_password_policies`).
			WithArgs(anyArgs(17)...).
			WillReturnRows(rows)

		err := repo.Update(context.Background(), policy)
		assert.NoError(t, err)
		assert.Equal(t, now, policy.UpdatedAt)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("not found", func(t *testing.T) {
		mock, repo := newPasswordPolicyMock(t)
		defer mock.Close()

		policy := samplePasswordPolicy()
		rows := mock.NewRows([]string{"updated_at"})
		mock.ExpectQuery(`UPDATE iam_password_policies`).
			WithArgs(anyArgs(17)...).
			WillReturnRows(rows)

		err := repo.Update(context.Background(), policy)
		assert.Error(t, err)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

func TestPasswordPolicyRepository_Upsert(t *testing.T) {
	now := time.Now()
	policyID := uuid.New()

	t.Run("success insert", func(t *testing.T) {
		mock, repo := newPasswordPolicyMock(t)
		defer mock.Close()

		policy := samplePasswordPolicy()
		rows := mock.NewRows([]string{"id", "created_at", "updated_at"}).AddRow(policyID, now, now)
		mock.ExpectQuery(`INSERT INTO iam_password_policies`).
			WithArgs(anyArgs(19)...).
			WillReturnRows(rows)

		err := repo.Upsert(context.Background(), policy)
		assert.NoError(t, err)
		assert.Equal(t, policyID, policy.ID)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("db error", func(t *testing.T) {
		mock, repo := newPasswordPolicyMock(t)
		defer mock.Close()

		policy := samplePasswordPolicy()
		mock.ExpectQuery(`INSERT INTO iam_password_policies`).
			WithArgs(anyArgs(19)...).
			WillReturnError(fmt.Errorf("constraint violation"))

		err := repo.Upsert(context.Background(), policy)
		assert.Error(t, err)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

func TestPasswordPolicyRepository_AddPasswordHistory(t *testing.T) {
	userID := uuid.New()
	hash := "$argon2id$v=19$m=65536,t=1,p=4$..."

	t.Run("success", func(t *testing.T) {
		mock, repo := newPasswordPolicyMock(t)
		defer mock.Close()

		mock.ExpectExec(`INSERT INTO iam_password_history`).
			WithArgs(userID, hash).
			WillReturnResult(pgxmock.NewResult("INSERT", 1))

		err := repo.AddPasswordHistory(context.Background(), userID, hash)
		assert.NoError(t, err)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("db error", func(t *testing.T) {
		mock, repo := newPasswordPolicyMock(t)
		defer mock.Close()

		mock.ExpectExec(`INSERT INTO iam_password_history`).
			WithArgs(userID, hash).
			WillReturnError(fmt.Errorf("foreign key violation"))

		err := repo.AddPasswordHistory(context.Background(), userID, hash)
		assert.Error(t, err)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

func TestPasswordPolicyRepository_GetPasswordHistory(t *testing.T) {
	now := time.Now()
	userID := uuid.New()

	t.Run("returns history", func(t *testing.T) {
		mock, repo := newPasswordPolicyMock(t)
		defer mock.Close()

		cols := []string{"id", "user_id", "password_hash", "created_at"}
		rows := mock.NewRows(cols).
			AddRow(uuid.New(), userID, "hash1", now).
			AddRow(uuid.New(), userID, "hash2", now.Add(-24*time.Hour))

		mock.ExpectQuery(`SELECT`).WithArgs(userID, 5).WillReturnRows(rows)

		history, err := repo.GetPasswordHistory(context.Background(), userID, 5)
		require.NoError(t, err)
		assert.Len(t, history, 2)
		assert.Equal(t, "hash1", history[0].PasswordHash)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("empty history", func(t *testing.T) {
		mock, repo := newPasswordPolicyMock(t)
		defer mock.Close()

		cols := []string{"id", "user_id", "password_hash", "created_at"}
		rows := mock.NewRows(cols)
		mock.ExpectQuery(`SELECT`).WithArgs(userID, 10).WillReturnRows(rows)

		history, err := repo.GetPasswordHistory(context.Background(), userID, 10)
		require.NoError(t, err)
		assert.Empty(t, history)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

func TestPasswordPolicyRepository_IsPasswordInHistory(t *testing.T) {
	userID := uuid.New()
	hash := "targethash"

	t.Run("password in history", func(t *testing.T) {
		mock, repo := newPasswordPolicyMock(t)
		defer mock.Close()

		rows := mock.NewRows([]string{"exists"}).AddRow(true)
		mock.ExpectQuery(`SELECT EXISTS`).WithArgs(userID, 5, hash).WillReturnRows(rows)

		inHistory, err := repo.IsPasswordInHistory(context.Background(), userID, hash, 5)
		assert.NoError(t, err)
		assert.True(t, inHistory)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("password not in history", func(t *testing.T) {
		mock, repo := newPasswordPolicyMock(t)
		defer mock.Close()

		rows := mock.NewRows([]string{"exists"}).AddRow(false)
		mock.ExpectQuery(`SELECT EXISTS`).WithArgs(userID, 5, hash).WillReturnRows(rows)

		inHistory, err := repo.IsPasswordInHistory(context.Background(), userID, hash, 5)
		assert.NoError(t, err)
		assert.False(t, inHistory)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

func TestPasswordPolicyRepository_ClearPasswordHistory(t *testing.T) {
	userID := uuid.New()

	t.Run("success", func(t *testing.T) {
		mock, repo := newPasswordPolicyMock(t)
		defer mock.Close()

		mock.ExpectExec(`DELETE FROM iam_password_history`).
			WithArgs(userID).
			WillReturnResult(pgxmock.NewResult("DELETE", 5))

		err := repo.ClearPasswordHistory(context.Background(), userID)
		assert.NoError(t, err)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("db error", func(t *testing.T) {
		mock, repo := newPasswordPolicyMock(t)
		defer mock.Close()

		mock.ExpectExec(`DELETE FROM iam_password_history`).
			WithArgs(userID).
			WillReturnError(fmt.Errorf("connection lost"))

		err := repo.ClearPasswordHistory(context.Background(), userID)
		assert.Error(t, err)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

func TestPasswordPolicyRepository_IsCommonPassword(t *testing.T) {
	t.Run("is common password", func(t *testing.T) {
		mock, repo := newPasswordPolicyMock(t)
		defer mock.Close()

		rows := mock.NewRows([]string{"exists"}).AddRow(true)
		mock.ExpectQuery(`SELECT EXISTS`).WithArgs("password123hash").WillReturnRows(rows)

		isCommon, err := repo.IsCommonPassword(context.Background(), "password123hash")
		assert.NoError(t, err)
		assert.True(t, isCommon)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("not a common password", func(t *testing.T) {
		mock, repo := newPasswordPolicyMock(t)
		defer mock.Close()

		rows := mock.NewRows([]string{"exists"}).AddRow(false)
		mock.ExpectQuery(`SELECT EXISTS`).WithArgs("uniquehash").WillReturnRows(rows)

		isCommon, err := repo.IsCommonPassword(context.Background(), "uniquehash")
		assert.NoError(t, err)
		assert.False(t, isCommon)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}
