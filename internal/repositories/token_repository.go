// SPDX-License-Identifier: AGPL-3.0-or-later

package repositories

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

const msgListAuditLogs = "ListAuditLogs: %w"

// TokenRepository is an exported type.
type TokenRepository struct {
	db      DBPool
	realmID *uuid.UUID
}

// WithRealmID returns a shallow clone of TokenRepository scoped to the given realm.
func (r *TokenRepository) WithRealmID(realmID uuid.UUID) *TokenRepository {
	clone := *r
	clone.realmID = &realmID
	return &clone
}

// NewTokenRepository is an exported function.
func NewTokenRepository(db DBPool) *TokenRepository {
	return &TokenRepository{db: db}
}

// CreateAPIKey is an exported identifier.
func (r *TokenRepository) CreateAPIKey(ctx context.Context, key *models.APIKey) error {
	query := `
		INSERT INTO iam_api_keys (id, tenant_id, user_id, name, key_prefix, key_hash, scopes, ip_whitelist, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		RETURNING created_at`

	if key.ID == uuid.Nil {
		key.ID = uuid.New()
	}

	return r.db.QueryRow(ctx, query,
		key.ID, key.TenantID, key.UserID, key.Name, key.KeyPrefix, key.KeyHash,
		key.Scopes, key.IPWhitelist, key.ExpiresAt,
	).Scan(&key.CreatedAt)
}

// GetAPIKeyByPrefix is an exported function.
func (r *TokenRepository) GetAPIKeyByPrefix(ctx context.Context, prefix string) (*models.APIKey, error) {
	key := &models.APIKey{}
	query := `
		SELECT id, tenant_id, user_id, name, key_prefix, key_hash, scopes, ip_whitelist,
			   is_active, last_used_at, last_used_ip, created_at, expires_at, revoked_at
		FROM iam_api_keys WHERE key_prefix = $1`

	err := r.db.QueryRow(ctx, query, prefix).Scan(
		&key.ID, &key.TenantID, &key.UserID, &key.Name, &key.KeyPrefix, &key.KeyHash,
		&key.Scopes, &key.IPWhitelist,
		&key.IsActive, &key.LastUsedAt, &key.LastUsedIP, &key.CreatedAt, &key.ExpiresAt, &key.RevokedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("GetAPIKeyByPrefix: %w", err)
	}
	return key, nil
}

// GetAPIKeyByID is an exported function.
func (r *TokenRepository) GetAPIKeyByID(ctx context.Context, id uuid.UUID) (*models.APIKey, error) {
	key := &models.APIKey{}
	query := `
		SELECT id, tenant_id, user_id, name, key_prefix, key_hash, scopes, ip_whitelist,
			   is_active, last_used_at, last_used_ip, created_at, expires_at, revoked_at
		FROM iam_api_keys WHERE id = $1`

	err := r.db.QueryRow(ctx, query, id).Scan(
		&key.ID, &key.TenantID, &key.UserID, &key.Name, &key.KeyPrefix, &key.KeyHash,
		&key.Scopes, &key.IPWhitelist,
		&key.IsActive, &key.LastUsedAt, &key.LastUsedIP, &key.CreatedAt, &key.ExpiresAt, &key.RevokedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("GetAPIKeyByID: %w", err)
	}
	return key, nil
}

// ListUserAPIKeys is an exported function.
func (r *TokenRepository) ListUserAPIKeys(ctx context.Context, userID uuid.UUID) ([]models.APIKey, error) {
	query := `
		SELECT id, tenant_id, user_id, name, key_prefix, key_hash, scopes, ip_whitelist,
			   is_active, last_used_at, last_used_ip, created_at, expires_at, revoked_at
		FROM iam_api_keys WHERE user_id = $1 AND revoked_at IS NULL
		ORDER BY created_at DESC`

	rows, err := r.db.Query(ctx, query, userID)
	if err != nil {
		return nil, fmt.Errorf("ListUserAPIKeys: %w", err)
	}
	defer rows.Close()

	var keys []models.APIKey
	for rows.Next() {
		var key models.APIKey
		err := rows.Scan(
			&key.ID, &key.TenantID, &key.UserID, &key.Name, &key.KeyPrefix, &key.KeyHash,
			&key.Scopes, &key.IPWhitelist,
			&key.IsActive, &key.LastUsedAt, &key.LastUsedIP, &key.CreatedAt, &key.ExpiresAt, &key.RevokedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("ListUserAPIKeys: %w", err)
		}
		keys = append(keys, key)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("ListUserAPIKeys: rows iteration: %w", err)
	}

	return keys, nil
}

// RevokeAPIKey is an exported function.
func (r *TokenRepository) RevokeAPIKey(ctx context.Context, id uuid.UUID) error {
	_, err := r.db.Exec(ctx,
		`UPDATE iam_api_keys SET is_active = false, revoked_at = NOW() WHERE id = $1`,
		id,
	)
	if err != nil {
		return fmt.Errorf("RevokeAPIKey: %w", err)
	}
	return nil
}

// UpdateAPIKeyUsage is an exported function.
func (r *TokenRepository) UpdateAPIKeyUsage(ctx context.Context, id uuid.UUID, ip string) error {
	_, err := r.db.Exec(ctx,
		`UPDATE iam_api_keys SET last_used_at = NOW(), last_used_ip = $2 WHERE id = $1`,
		id, ip,
	)
	if err != nil {
		return fmt.Errorf("UpdateAPIKeyUsage: %w", err)
	}
	return nil
}

// CreatePasswordReset is an exported identifier.
func (r *TokenRepository) CreatePasswordReset(ctx context.Context, reset *models.PasswordReset) error {
	query := `
		INSERT INTO iam_password_resets (id, user_id, token_hash, ip_address, expires_at)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING created_at`

	if reset.ID == uuid.Nil {
		reset.ID = uuid.New()
	}

	return r.db.QueryRow(ctx, query,
		reset.ID, reset.UserID, reset.TokenHash, reset.IPAddress, reset.ExpiresAt,
	).Scan(&reset.CreatedAt)
}

// GetPasswordReset is an exported function.
func (r *TokenRepository) GetPasswordReset(ctx context.Context, tokenHash string) (*models.PasswordReset, error) {
	reset := &models.PasswordReset{}
	query := `
		SELECT id, user_id, token_hash, ip_address, created_at, expires_at, used_at
		FROM iam_password_resets WHERE token_hash = $1`

	err := r.db.QueryRow(ctx, query, tokenHash).Scan(
		&reset.ID, &reset.UserID, &reset.TokenHash, &reset.IPAddress,
		&reset.CreatedAt, &reset.ExpiresAt, &reset.UsedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("GetPasswordReset: %w", err)
	}
	return reset, nil
}

// MarkPasswordResetUsed is an exported function.
func (r *TokenRepository) MarkPasswordResetUsed(ctx context.Context, id uuid.UUID) error {
	_, err := r.db.Exec(ctx,
		`UPDATE iam_password_resets SET used_at = NOW() WHERE id = $1`,
		id,
	)
	if err != nil {
		return fmt.Errorf("MarkPasswordResetUsed: %w", err)
	}
	return nil
}

// InvalidateUserPasswordResets is an exported function.
func (r *TokenRepository) InvalidateUserPasswordResets(ctx context.Context, userID uuid.UUID) error {
	_, err := r.db.Exec(ctx,
		`UPDATE iam_password_resets SET used_at = NOW() WHERE user_id = $1 AND used_at IS NULL`,
		userID,
	)
	if err != nil {
		return fmt.Errorf("InvalidateUserPasswordResets: %w", err)
	}
	return nil
}

// CleanupExpiredPasswordResets is an exported function.
func (r *TokenRepository) CleanupExpiredPasswordResets(ctx context.Context) (int64, error) {
	result, err := r.db.Exec(ctx,
		`DELETE FROM iam_password_resets WHERE expires_at < NOW() OR used_at IS NOT NULL`,
	)
	if err != nil {
		return 0, fmt.Errorf("CleanupExpiredPasswordResets: %w", err)
	}
	return result.RowsAffected(), nil
}

// CreateMFARecoveryCodes is an exported identifier.
func (r *TokenRepository) CreateMFARecoveryCodes(ctx context.Context, userID uuid.UUID, codeHashes []string) error {
	// SECURITY: Wrap delete+insert in a single transaction so a crash or error between
	// the two operations cannot leave the user with zero recovery codes (lockout) or
	// a mix of old and new codes (partial replacement).
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("CreateMFARecoveryCodes: begin tx: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	_, err = tx.Exec(ctx, `DELETE FROM iam_mfa_recovery_codes WHERE user_id = $1`, userID)
	if err != nil {
		return fmt.Errorf("CreateMFARecoveryCodes: delete: %w", err)
	}

	for _, hash := range codeHashes {
		_, err := tx.Exec(ctx,
			`INSERT INTO iam_mfa_recovery_codes (user_id, code_hash) VALUES ($1, $2)`,
			userID, hash,
		)
		if err != nil {
			return fmt.Errorf("CreateMFARecoveryCodes: insert: %w", err)
		}
	}

	return tx.Commit(ctx)
}

// GetUnusedMFARecoveryCodes is an exported function.
func (r *TokenRepository) GetUnusedMFARecoveryCodes(ctx context.Context, userID uuid.UUID) ([]models.MFARecoveryCode, error) {
	query := `
		SELECT id, user_id, code_hash, created_at, used_at
		FROM iam_mfa_recovery_codes WHERE user_id = $1 AND used_at IS NULL`

	rows, err := r.db.Query(ctx, query, userID)
	if err != nil {
		return nil, fmt.Errorf("GetUnusedMFARecoveryCodes: %w", err)
	}
	defer rows.Close()

	var codes []models.MFARecoveryCode
	for rows.Next() {
		var code models.MFARecoveryCode
		err := rows.Scan(&code.ID, &code.UserID, &code.CodeHash, &code.CreatedAt, &code.UsedAt)
		if err != nil {
			return nil, fmt.Errorf("GetUnusedMFARecoveryCodes: Scan failed: %w", err)
		}
		codes = append(codes, code)
	}

	return codes, nil
}

// MarkMFARecoveryCodeUsed is an exported function.
func (r *TokenRepository) MarkMFARecoveryCodeUsed(ctx context.Context, userID uuid.UUID, codeHash string) error {
	_, err := r.db.Exec(ctx,
		`UPDATE iam_mfa_recovery_codes SET used_at = NOW() WHERE user_id = $1 AND code_hash = $2`,
		userID, codeHash,
	)
	if err != nil {
		return fmt.Errorf("MarkMFARecoveryCodeUsed: %w", err)
	}
	return nil
}

// DeleteUserMFARecoveryCodes is an exported function.
func (r *TokenRepository) DeleteUserMFARecoveryCodes(ctx context.Context, userID uuid.UUID) error {
	_, err := r.db.Exec(ctx, `DELETE FROM iam_mfa_recovery_codes WHERE user_id = $1`, userID)
	if err != nil {
		return fmt.Errorf("DeleteUserMFARecoveryCodes: %w", err)
	}
	return nil
}

// CreateAuditLog is an exported identifier.
func (r *TokenRepository) CreateAuditLog(ctx context.Context, log *models.AuditLog) error {
	query := `
		INSERT INTO iam_audit_log (tenant_id, user_id, target_user_id, action, resource_type, resource_id, details, ip_address, country_code, user_agent, success, error_message)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
		RETURNING id, created_at`

	return r.db.QueryRow(ctx, query,
		log.TenantID, log.UserID, log.TargetUserID, log.Action, log.ResourceType, log.ResourceID,
		log.Details, log.IPAddress, log.CountryCode, log.UserAgent, log.Success, log.ErrorMessage,
	).Scan(&log.ID, &log.CreatedAt)
}

// GetAuditLogByID is an exported function.
func (r *TokenRepository) GetAuditLogByID(ctx context.Context, id uuid.UUID, tenantID uuid.UUID) (*models.AuditLog, error) {
	query := `
		SELECT a.id, a.tenant_id, a.user_id, u.username, a.target_user_id, a.action, a.resource_type, a.resource_id,
			   a.details, a.ip_address, a.country_code, a.user_agent, a.success, a.error_message, a.created_at
		FROM iam_audit_log a
		LEFT JOIN iam_users u ON u.id = a.user_id
		WHERE a.id = $1 AND a.tenant_id = $2`

	var log models.AuditLog
	err := r.db.QueryRow(ctx, query, id, tenantID).Scan(
		&log.ID, &log.TenantID, &log.UserID, &log.Username, &log.TargetUserID, &log.Action,
		&log.ResourceType, &log.ResourceID, &log.Details, &log.IPAddress, &log.CountryCode,
		&log.UserAgent, &log.Success, &log.ErrorMessage, &log.CreatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("GetAuditLogByID: %w", err)
	}
	return &log, nil
}

// ListAuditLogs is an exported function.
func (r *TokenRepository) ListAuditLogs(ctx context.Context, tenantID uuid.UUID, page, pageSize int, filters map[string]interface{}) ([]models.AuditLog, int64, error) {
	offset := (page - 1) * pageSize

	// Build dynamic WHERE clause from filters
	whereClause := `WHERE a.tenant_id = $1`
	args := []interface{}{tenantID}
	argIdx := 2

	if action, ok := filters["action"].(string); ok && action != "" {
		whereClause += fmt.Sprintf(` AND a.action = $%d`, argIdx)
		args = append(args, action)
		argIdx++
	}
	if userID, ok := filters["user_id"].(uuid.UUID); ok && userID != uuid.Nil {
		whereClause += fmt.Sprintf(` AND a.user_id = $%d`, argIdx)
		args = append(args, userID)
		argIdx++
	}
	if resourceType, ok := filters["resource_type"].(string); ok && resourceType != "" {
		whereClause += fmt.Sprintf(` AND a.resource_type = $%d`, argIdx)
		args = append(args, resourceType)
		argIdx++
	}
	if success, ok := filters["success"].(bool); ok {
		whereClause += fmt.Sprintf(` AND a.success = $%d`, argIdx)
		args = append(args, success)
		argIdx++
	}

	// Count total with filters applied
	countQuery := `SELECT COUNT(*) FROM iam_audit_log a ` + whereClause

	var total int64
	err := r.db.QueryRow(ctx, countQuery, args...).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf(msgListAuditLogs, err)
	}

	// Get logs with username
	query := fmt.Sprintf(`
		SELECT a.id, a.tenant_id, a.user_id, u.username, a.target_user_id, a.action, a.resource_type, a.resource_id,
			   a.details, a.ip_address, a.country_code, a.user_agent, a.success, a.error_message, a.created_at
		FROM iam_audit_log a
		LEFT JOIN iam_users u ON u.id = a.user_id
		%s
		ORDER BY a.created_at DESC
		LIMIT $%d OFFSET $%d`, whereClause, argIdx, argIdx+1)

	args = append(args, pageSize, offset)
	rows, err := r.db.Query(ctx, query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf(msgListAuditLogs, err)
	}
	defer rows.Close()

	var logs []models.AuditLog
	for rows.Next() {
		var log models.AuditLog
		err := rows.Scan(
			&log.ID, &log.TenantID, &log.UserID, &log.Username, &log.TargetUserID, &log.Action,
			&log.ResourceType, &log.ResourceID, &log.Details, &log.IPAddress, &log.CountryCode,
			&log.UserAgent, &log.Success, &log.ErrorMessage, &log.CreatedAt,
		)
		if err != nil {
			return nil, 0, fmt.Errorf(msgListAuditLogs, err)
		}
		logs = append(logs, log)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("ListAuditLogs: rows iteration: %w", err)
	}

	return logs, total, nil
}

// DeleteOldAuditLogs is an exported function.
func (r *TokenRepository) DeleteOldAuditLogs(ctx context.Context, before time.Time) (int64, error) {
	result, err := r.db.Exec(ctx,
		`DELETE FROM iam_audit_log WHERE created_at < $1`,
		before,
	)
	if err != nil {
		return 0, fmt.Errorf("DeleteOldAuditLogs: %w", err)
	}
	return result.RowsAffected(), nil
}
