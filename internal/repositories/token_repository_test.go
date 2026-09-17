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

	"github.com/dogukanturhal/falcon-id/internal/models"
)

// ──────────────────────────────────────────────────────────────────────────────
// Helper
// ──────────────────────────────────────────────────────────────────────────────

// newTokenRepo creates a TokenRepository backed by a pgxmock pool using regex
// query matching.
func newTokenRepo(t *testing.T) (*TokenRepository, pgxmock.PgxPoolIface) {
	t.Helper()
	mock, err := pgxmock.NewPool(pgxmock.QueryMatcherOption(pgxmock.QueryMatcherRegexp))
	require.NoError(t, err)
	repo := NewTokenRepository(mock)
	t.Cleanup(func() { mock.Close() })
	return repo, mock
}

// ──────────────────────────────────────────────────────────────────────────────
// API keys
// ──────────────────────────────────────────────────────────────────────────────

func TestTokenRepository_CreateAPIKey(t *testing.T) {
	ctx := context.Background()
	repo, mock := newTokenRepo(t)

	now := time.Now().UTC().Truncate(time.Second)
	tenantID := uuid.New()
	userID := uuid.New()

	key := &models.APIKey{
		TenantID:  tenantID,
		UserID:    userID,
		Name:      "My API Key",
		KeyPrefix: "fal_abc",
		KeyHash:   "sha256ofkey",
	}

	mock.ExpectQuery(`INSERT INTO iam_api_keys`).
		WithArgs(
			pgxmock.AnyArg(), // id
			key.TenantID,
			key.UserID,
			key.Name,
			key.KeyPrefix,
			key.KeyHash,
			key.Scopes,
			key.IPWhitelist,
			key.ExpiresAt,
		).
		WillReturnRows(pgxmock.NewRows([]string{"created_at"}).AddRow(now))

	err := repo.CreateAPIKey(ctx, key)
	require.NoError(t, err)
	assert.Equal(t, now, key.CreatedAt)

	require.NoError(t, mock.ExpectationsWereMet())
}

func TestTokenRepository_GetAPIKeyByPrefix_Found(t *testing.T) {
	ctx := context.Background()
	repo, mock := newTokenRepo(t)

	prefix := "fal_abc"
	keyID := uuid.New()
	tenantID := uuid.New()
	now := time.Now().UTC().Truncate(time.Second)

	cols := []string{
		"id", "tenant_id", "user_id", "name", "key_prefix", "key_hash",
		"scopes", "ip_whitelist",
		"is_active", "last_used_at", "last_used_ip", "created_at", "expires_at", "revoked_at",
	}

	mock.ExpectQuery(`SELECT .+ FROM iam_api_keys WHERE key_prefix = \$1`).
		WithArgs(prefix).
		WillReturnRows(pgxmock.NewRows(cols).
			AddRow(keyID, tenantID, nil, "My API Key", prefix, "sha256hash", nil, nil, true, nil, nil, now, nil, nil))

	got, err := repo.GetAPIKeyByPrefix(ctx, prefix)
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, keyID, got.ID)
	assert.Equal(t, prefix, got.KeyPrefix)
	assert.True(t, got.IsActive)

	require.NoError(t, mock.ExpectationsWereMet())
}

func TestTokenRepository_GetAPIKeyByPrefix_NotFound(t *testing.T) {
	ctx := context.Background()
	repo, mock := newTokenRepo(t)

	cols := []string{
		"id", "tenant_id", "user_id", "name", "key_prefix", "key_hash",
		"scopes", "ip_whitelist",
		"is_active", "last_used_at", "last_used_ip", "created_at", "expires_at", "revoked_at",
	}

	mock.ExpectQuery(`SELECT .+ FROM iam_api_keys WHERE key_prefix = \$1`).
		WithArgs("unknown_prefix").
		WillReturnRows(pgxmock.NewRows(cols))

	got, err := repo.GetAPIKeyByPrefix(ctx, "unknown_prefix")
	require.NoError(t, err)
	assert.Nil(t, got)

	require.NoError(t, mock.ExpectationsWereMet())
}

func TestTokenRepository_RevokeAPIKey(t *testing.T) {
	ctx := context.Background()
	repo, mock := newTokenRepo(t)
	id := uuid.New()

	mock.ExpectExec(`UPDATE iam_api_keys SET is_active = false, revoked_at = NOW\(\) WHERE id = \$1`).
		WithArgs(id).
		WillReturnResult(pgxmock.NewResult("UPDATE", 1))

	err := repo.RevokeAPIKey(ctx, id)
	require.NoError(t, err)

	require.NoError(t, mock.ExpectationsWereMet())
}

func TestTokenRepository_ListUserAPIKeys(t *testing.T) {
	ctx := context.Background()
	repo, mock := newTokenRepo(t)

	userID := uuid.New()
	tenantID := uuid.New()
	keyID := uuid.New()
	now := time.Now().UTC().Truncate(time.Second)

	cols := []string{
		"id", "tenant_id", "user_id", "name", "key_prefix", "key_hash",
		"scopes", "ip_whitelist",
		"is_active", "last_used_at", "last_used_ip", "created_at", "expires_at", "revoked_at",
	}

	mock.ExpectQuery(`SELECT .+ FROM iam_api_keys WHERE user_id = \$1 AND revoked_at IS NULL`).
		WithArgs(userID).
		WillReturnRows(pgxmock.NewRows(cols).
			AddRow(keyID, tenantID, userID, "My Key", "fal_abc", "hash", nil, nil, true, nil, nil, now, nil, nil))

	keys, err := repo.ListUserAPIKeys(ctx, userID)
	require.NoError(t, err)
	require.Len(t, keys, 1)
	assert.Equal(t, keyID, keys[0].ID)

	require.NoError(t, mock.ExpectationsWereMet())
}

func TestTokenRepository_UpdateAPIKeyUsage(t *testing.T) {
	ctx := context.Background()
	repo, mock := newTokenRepo(t)

	keyID := uuid.New()
	ip := "10.0.0.1"

	mock.ExpectExec(`UPDATE iam_api_keys SET last_used_at = NOW\(\), last_used_ip`).
		WithArgs(keyID, ip).
		WillReturnResult(pgxmock.NewResult("UPDATE", 1))

	err := repo.UpdateAPIKeyUsage(ctx, keyID, ip)
	require.NoError(t, err)

	require.NoError(t, mock.ExpectationsWereMet())
}

// ──────────────────────────────────────────────────────────────────────────────
// Password resets
// ──────────────────────────────────────────────────────────────────────────────

func TestTokenRepository_CreatePasswordReset(t *testing.T) {
	ctx := context.Background()
	repo, mock := newTokenRepo(t)

	now := time.Now().UTC().Truncate(time.Second)
	expires := now.Add(1 * time.Hour)
	userID := uuid.New()
	ip := "192.168.1.1"

	reset := &models.PasswordReset{
		UserID:    userID,
		TokenHash: "resethash",
		IPAddress: &ip,
		ExpiresAt: expires,
	}

	mock.ExpectQuery(`INSERT INTO iam_password_resets`).
		WithArgs(
			pgxmock.AnyArg(), // id
			reset.UserID,
			reset.TokenHash,
			reset.IPAddress,
			reset.ExpiresAt,
		).
		WillReturnRows(pgxmock.NewRows([]string{"created_at"}).AddRow(now))

	err := repo.CreatePasswordReset(ctx, reset)
	require.NoError(t, err)
	assert.Equal(t, now, reset.CreatedAt)

	require.NoError(t, mock.ExpectationsWereMet())
}

func TestTokenRepository_GetPasswordReset_Found(t *testing.T) {
	ctx := context.Background()
	repo, mock := newTokenRepo(t)

	resetID := uuid.New()
	userID := uuid.New()
	now := time.Now().UTC().Truncate(time.Second)
	expires := now.Add(1 * time.Hour)
	tokenHash := "resethash"

	cols := []string{"id", "user_id", "token_hash", "ip_address", "created_at", "expires_at", "used_at"}

	mock.ExpectQuery(`SELECT .+ FROM iam_password_resets WHERE token_hash = \$1`).
		WithArgs(tokenHash).
		WillReturnRows(pgxmock.NewRows(cols).
			AddRow(resetID, userID, tokenHash, nil, now, expires, nil))

	got, err := repo.GetPasswordReset(ctx, tokenHash)
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, resetID, got.ID)
	assert.Equal(t, tokenHash, got.TokenHash)

	require.NoError(t, mock.ExpectationsWereMet())
}

func TestTokenRepository_GetPasswordReset_NotFound(t *testing.T) {
	ctx := context.Background()
	repo, mock := newTokenRepo(t)

	cols := []string{"id", "user_id", "token_hash", "ip_address", "created_at", "expires_at", "used_at"}

	mock.ExpectQuery(`SELECT .+ FROM iam_password_resets WHERE token_hash = \$1`).
		WithArgs("badtoken").
		WillReturnRows(pgxmock.NewRows(cols))

	got, err := repo.GetPasswordReset(ctx, "badtoken")
	require.NoError(t, err)
	assert.Nil(t, got)

	require.NoError(t, mock.ExpectationsWereMet())
}

func TestTokenRepository_MarkPasswordResetUsed(t *testing.T) {
	ctx := context.Background()
	repo, mock := newTokenRepo(t)
	id := uuid.New()

	mock.ExpectExec(`UPDATE iam_password_resets SET used_at = NOW\(\) WHERE id = \$1`).
		WithArgs(id).
		WillReturnResult(pgxmock.NewResult("UPDATE", 1))

	err := repo.MarkPasswordResetUsed(ctx, id)
	require.NoError(t, err)

	require.NoError(t, mock.ExpectationsWereMet())
}

func TestTokenRepository_InvalidateUserPasswordResets(t *testing.T) {
	ctx := context.Background()
	repo, mock := newTokenRepo(t)
	userID := uuid.New()

	mock.ExpectExec(`UPDATE iam_password_resets SET used_at = NOW\(\) WHERE user_id = \$1 AND used_at IS NULL`).
		WithArgs(userID).
		WillReturnResult(pgxmock.NewResult("UPDATE", 2))

	err := repo.InvalidateUserPasswordResets(ctx, userID)
	require.NoError(t, err)

	require.NoError(t, mock.ExpectationsWereMet())
}

// ──────────────────────────────────────────────────────────────────────────────
// MFA recovery codes
// ──────────────────────────────────────────────────────────────────────────────

func TestTokenRepository_CreateMFARecoveryCodes(t *testing.T) {
	ctx := context.Background()
	repo, mock := newTokenRepo(t)
	userID := uuid.New()
	codes := []string{"hash1", "hash2", "hash3"}

	// The operation is now wrapped in a transaction (Fix 7).
	mock.ExpectBegin()

	// DELETE existing codes inside the transaction
	mock.ExpectExec(`DELETE FROM iam_mfa_recovery_codes WHERE user_id = \$1`).
		WithArgs(userID).
		WillReturnResult(pgxmock.NewResult("DELETE", 0))

	// INSERT each code inside the transaction
	for _, h := range codes {
		mock.ExpectExec(`INSERT INTO iam_mfa_recovery_codes \(user_id, code_hash\) VALUES`).
			WithArgs(userID, h).
			WillReturnResult(pgxmock.NewResult("INSERT", 1))
	}

	mock.ExpectCommit()

	err := repo.CreateMFARecoveryCodes(ctx, userID, codes)
	require.NoError(t, err)

	require.NoError(t, mock.ExpectationsWereMet())
}

func TestTokenRepository_GetUnusedMFARecoveryCodes(t *testing.T) {
	ctx := context.Background()
	repo, mock := newTokenRepo(t)
	userID := uuid.New()

	codeID := uuid.New()
	now := time.Now().UTC().Truncate(time.Second)

	cols := []string{"id", "user_id", "code_hash", "created_at", "used_at"}
	mock.ExpectQuery(`SELECT .+ FROM iam_mfa_recovery_codes WHERE user_id = \$1 AND used_at IS NULL`).
		WithArgs(userID).
		WillReturnRows(pgxmock.NewRows(cols).
			AddRow(codeID, userID, "hash1", now, nil))

	codes, err := repo.GetUnusedMFARecoveryCodes(ctx, userID)
	require.NoError(t, err)
	require.Len(t, codes, 1)
	assert.Equal(t, codeID, codes[0].ID)
	assert.Equal(t, "hash1", codes[0].CodeHash)

	require.NoError(t, mock.ExpectationsWereMet())
}

func TestTokenRepository_MarkMFARecoveryCodeUsed(t *testing.T) {
	ctx := context.Background()
	repo, mock := newTokenRepo(t)
	userID := uuid.New()
	codeHash := "hash1"

	mock.ExpectExec(`UPDATE iam_mfa_recovery_codes SET used_at = NOW\(\) WHERE user_id = \$1 AND code_hash = \$2`).
		WithArgs(userID, codeHash).
		WillReturnResult(pgxmock.NewResult("UPDATE", 1))

	err := repo.MarkMFARecoveryCodeUsed(ctx, userID, codeHash)
	require.NoError(t, err)

	require.NoError(t, mock.ExpectationsWereMet())
}

func TestTokenRepository_DeleteUserMFARecoveryCodes(t *testing.T) {
	ctx := context.Background()
	repo, mock := newTokenRepo(t)
	userID := uuid.New()

	mock.ExpectExec(`DELETE FROM iam_mfa_recovery_codes WHERE user_id = \$1`).
		WithArgs(userID).
		WillReturnResult(pgxmock.NewResult("DELETE", 8))

	err := repo.DeleteUserMFARecoveryCodes(ctx, userID)
	require.NoError(t, err)

	require.NoError(t, mock.ExpectationsWereMet())
}

// ──────────────────────────────────────────────────────────────────────────────
// Audit log
// ──────────────────────────────────────────────────────────────────────────────

func TestTokenRepository_CreateAuditLog(t *testing.T) {
	ctx := context.Background()
	repo, mock := newTokenRepo(t)

	logID := uuid.New()
	now := time.Now().UTC().Truncate(time.Second)
	tenantID := uuid.New()
	userID := uuid.New()
	resourceType := "user"

	entry := &models.AuditLog{
		TenantID:     tenantID,
		UserID:       &userID,
		Action:       "user.login",
		ResourceType: &resourceType,
		Success:      true,
	}

	mock.ExpectQuery(`INSERT INTO iam_audit_log`).
		WithArgs(
			entry.TenantID,
			entry.UserID,
			entry.TargetUserID,
			entry.Action,
			entry.ResourceType,
			entry.ResourceID,
			entry.Details,
			entry.IPAddress,
			entry.CountryCode,
			entry.UserAgent,
			entry.Success,
			entry.ErrorMessage,
		).
		WillReturnRows(pgxmock.NewRows([]string{"id", "created_at"}).AddRow(logID, now))

	err := repo.CreateAuditLog(ctx, entry)
	require.NoError(t, err)
	assert.Equal(t, logID, entry.ID)
	assert.Equal(t, now, entry.CreatedAt)

	require.NoError(t, mock.ExpectationsWereMet())
}

func TestTokenRepository_DeleteOldAuditLogs(t *testing.T) {
	ctx := context.Background()
	repo, mock := newTokenRepo(t)

	cutoff := time.Now().UTC().Add(-90 * 24 * time.Hour)

	mock.ExpectExec(`DELETE FROM iam_audit_log WHERE created_at < \$1`).
		WithArgs(cutoff).
		WillReturnResult(pgxmock.NewResult("DELETE", 100))

	n, err := repo.DeleteOldAuditLogs(ctx, cutoff)
	require.NoError(t, err)
	assert.Equal(t, int64(100), n)

	require.NoError(t, mock.ExpectationsWereMet())
}
