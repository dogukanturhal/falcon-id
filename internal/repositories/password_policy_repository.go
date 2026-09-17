// SPDX-License-Identifier: AGPL-3.0-or-later

package repositories

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

// PasswordPolicyRepository is an exported type.
type PasswordPolicyRepository struct {
	db      DBPool
	realmID *uuid.UUID
}

// WithRealmID returns a shallow clone of PasswordPolicyRepository scoped to the given realm.
func (r *PasswordPolicyRepository) WithRealmID(realmID uuid.UUID) *PasswordPolicyRepository {
	clone := *r
	clone.realmID = &realmID
	return &clone
}

// NewPasswordPolicyRepository is an exported function.
func NewPasswordPolicyRepository(db *pgxpool.Pool) *PasswordPolicyRepository {
	return &PasswordPolicyRepository{db: db}
}

// GetByTenantID retrieves the password policy for a tenant
func (r *PasswordPolicyRepository) GetByTenantID(ctx context.Context, tenantID uuid.UUID) (*models.PasswordPolicy, error) {
	policy := &models.PasswordPolicy{}
	query := `
		SELECT id, tenant_id, min_length, max_length, require_uppercase, require_lowercase,
			   require_numbers, require_special, disallow_username, disallow_common_passwords,
			   max_age_days, warning_days_before_expiry, history_count, lockout_threshold,
			   lockout_duration_minutes, lockout_increment_factor, require_password_change_on_first_login,
			   created_at, updated_at, created_by, updated_by
		FROM iam_password_policies
		WHERE tenant_id = $1`

	err := r.db.QueryRow(ctx, query, tenantID).Scan(
		&policy.ID, &policy.TenantID, &policy.MinLength, &policy.MaxLength,
		&policy.RequireUppercase, &policy.RequireLowercase, &policy.RequireNumbers,
		&policy.RequireSpecial, &policy.DisallowUsername, &policy.DisallowCommonPasswords,
		&policy.MaxAgeDays, &policy.WarningDaysBeforeExpiry, &policy.HistoryCount,
		&policy.LockoutThreshold, &policy.LockoutDurationMinutes, &policy.LockoutIncrementFactor,
		&policy.RequirePasswordChangeOnFirstLogin, &policy.CreatedAt, &policy.UpdatedAt,
		&policy.CreatedBy, &policy.UpdatedBy,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("GetByTenantID: %w", err)
	}
	return policy, nil
}

// Create creates a new password policy
func (r *PasswordPolicyRepository) Create(ctx context.Context, policy *models.PasswordPolicy) error {
	if policy.ID == uuid.Nil {
		policy.ID = uuid.New()
	}

	query := `
		INSERT INTO iam_password_policies (
			id, tenant_id, min_length, max_length, require_uppercase, require_lowercase,
			require_numbers, require_special, disallow_username, disallow_common_passwords,
			max_age_days, warning_days_before_expiry, history_count, lockout_threshold,
			lockout_duration_minutes, lockout_increment_factor, require_password_change_on_first_login,
			created_by, updated_by
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19)
		RETURNING created_at, updated_at`

	return r.db.QueryRow(ctx, query,
		policy.ID, policy.TenantID, policy.MinLength, policy.MaxLength,
		policy.RequireUppercase, policy.RequireLowercase, policy.RequireNumbers,
		policy.RequireSpecial, policy.DisallowUsername, policy.DisallowCommonPasswords,
		policy.MaxAgeDays, policy.WarningDaysBeforeExpiry, policy.HistoryCount,
		policy.LockoutThreshold, policy.LockoutDurationMinutes, policy.LockoutIncrementFactor,
		policy.RequirePasswordChangeOnFirstLogin, policy.CreatedBy, policy.UpdatedBy,
	).Scan(&policy.CreatedAt, &policy.UpdatedAt)
}

// Update updates an existing password policy
func (r *PasswordPolicyRepository) Update(ctx context.Context, policy *models.PasswordPolicy) error {
	query := `
		UPDATE iam_password_policies SET
			min_length = $2, max_length = $3, require_uppercase = $4, require_lowercase = $5,
			require_numbers = $6, require_special = $7, disallow_username = $8, disallow_common_passwords = $9,
			max_age_days = $10, warning_days_before_expiry = $11, history_count = $12, lockout_threshold = $13,
			lockout_duration_minutes = $14, lockout_increment_factor = $15, require_password_change_on_first_login = $16,
			updated_by = $17
		WHERE id = $1
		RETURNING updated_at`

	return r.db.QueryRow(ctx, query,
		policy.ID, policy.MinLength, policy.MaxLength, policy.RequireUppercase, policy.RequireLowercase,
		policy.RequireNumbers, policy.RequireSpecial, policy.DisallowUsername, policy.DisallowCommonPasswords,
		policy.MaxAgeDays, policy.WarningDaysBeforeExpiry, policy.HistoryCount, policy.LockoutThreshold,
		policy.LockoutDurationMinutes, policy.LockoutIncrementFactor, policy.RequirePasswordChangeOnFirstLogin,
		policy.UpdatedBy,
	).Scan(&policy.UpdatedAt)
}

// Upsert creates or updates a password policy for a tenant
func (r *PasswordPolicyRepository) Upsert(ctx context.Context, policy *models.PasswordPolicy) error {
	if policy.ID == uuid.Nil {
		policy.ID = uuid.New()
	}

	query := `
		INSERT INTO iam_password_policies (
			id, tenant_id, min_length, max_length, require_uppercase, require_lowercase,
			require_numbers, require_special, disallow_username, disallow_common_passwords,
			max_age_days, warning_days_before_expiry, history_count, lockout_threshold,
			lockout_duration_minutes, lockout_increment_factor, require_password_change_on_first_login,
			created_by, updated_by
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19)
		ON CONFLICT (tenant_id) DO UPDATE SET
			min_length = EXCLUDED.min_length,
			max_length = EXCLUDED.max_length,
			require_uppercase = EXCLUDED.require_uppercase,
			require_lowercase = EXCLUDED.require_lowercase,
			require_numbers = EXCLUDED.require_numbers,
			require_special = EXCLUDED.require_special,
			disallow_username = EXCLUDED.disallow_username,
			disallow_common_passwords = EXCLUDED.disallow_common_passwords,
			max_age_days = EXCLUDED.max_age_days,
			warning_days_before_expiry = EXCLUDED.warning_days_before_expiry,
			history_count = EXCLUDED.history_count,
			lockout_threshold = EXCLUDED.lockout_threshold,
			lockout_duration_minutes = EXCLUDED.lockout_duration_minutes,
			lockout_increment_factor = EXCLUDED.lockout_increment_factor,
			require_password_change_on_first_login = EXCLUDED.require_password_change_on_first_login,
			updated_by = EXCLUDED.updated_by
		RETURNING id, created_at, updated_at`

	return r.db.QueryRow(ctx, query,
		policy.ID, policy.TenantID, policy.MinLength, policy.MaxLength,
		policy.RequireUppercase, policy.RequireLowercase, policy.RequireNumbers,
		policy.RequireSpecial, policy.DisallowUsername, policy.DisallowCommonPasswords,
		policy.MaxAgeDays, policy.WarningDaysBeforeExpiry, policy.HistoryCount,
		policy.LockoutThreshold, policy.LockoutDurationMinutes, policy.LockoutIncrementFactor,
		policy.RequirePasswordChangeOnFirstLogin, policy.CreatedBy, policy.UpdatedBy,
	).Scan(&policy.ID, &policy.CreatedAt, &policy.UpdatedAt)
}

// ==================== Password History ====================

// AddPasswordHistory adds a password hash to the user's history
func (r *PasswordPolicyRepository) AddPasswordHistory(ctx context.Context, userID uuid.UUID, passwordHash string) error {
	query := `INSERT INTO iam_password_history (user_id, password_hash) VALUES ($1, $2)`
	_, err := r.db.Exec(ctx, query, userID, passwordHash)
	if err != nil {
		return fmt.Errorf("AddPasswordHistory: %w", err)
	}
	return nil
}

// GetPasswordHistory retrieves password history for a user
func (r *PasswordPolicyRepository) GetPasswordHistory(ctx context.Context, userID uuid.UUID, limit int) ([]models.PasswordHistory, error) {
	query := `
		SELECT id, user_id, password_hash, created_at
		FROM iam_password_history
		WHERE user_id = $1
		ORDER BY created_at DESC
		LIMIT $2`

	rows, err := r.db.Query(ctx, query, userID, limit)
	if err != nil {
		return nil, fmt.Errorf("GetPasswordHistory: %w", err)
	}
	defer rows.Close()

	var history []models.PasswordHistory
	for rows.Next() {
		var h models.PasswordHistory
		if err := rows.Scan(&h.ID, &h.UserID, &h.PasswordHash, &h.CreatedAt); err != nil {
			return nil, fmt.Errorf("GetPasswordHistory: %w", err)
		}
		history = append(history, h)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("GetPasswordHistory: rows iteration: %w", err)
	}

	return history, nil
}

// IsPasswordInHistory checks if a password hash exists in user's history
func (r *PasswordPolicyRepository) IsPasswordInHistory(ctx context.Context, userID uuid.UUID, passwordHash string, historyCount int) (bool, error) {
	query := `
		SELECT EXISTS(
			SELECT 1 FROM (
				SELECT password_hash FROM iam_password_history
				WHERE user_id = $1
				ORDER BY created_at DESC
				LIMIT $2
			) recent
			WHERE password_hash = $3
		)`

	var exists bool
	err := r.db.QueryRow(ctx, query, userID, historyCount, passwordHash).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("IsPasswordInHistory: %w", err)
	}
	return exists, nil
}

// ClearPasswordHistory clears password history for a user
func (r *PasswordPolicyRepository) ClearPasswordHistory(ctx context.Context, userID uuid.UUID) error {
	_, err := r.db.Exec(ctx, `DELETE FROM iam_password_history WHERE user_id = $1`, userID)
	if err != nil {
		return fmt.Errorf("ClearPasswordHistory: %w", err)
	}
	return nil
}

// ==================== Common Passwords ====================

// IsCommonPassword checks if a password hash is in the common passwords list
func (r *PasswordPolicyRepository) IsCommonPassword(ctx context.Context, passwordHash string) (bool, error) {
	query := `SELECT EXISTS(SELECT 1 FROM iam_common_passwords WHERE password_hash = $1)`
	var exists bool
	err := r.db.QueryRow(ctx, query, passwordHash).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("IsCommonPassword: %w", err)
	}
	return exists, nil
}
