// SPDX-License-Identifier: AGPL-3.0-or-later

package repositories

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/dogukanturhal/falcon-id/pkg/crypto"
)

// MFARepository is an exported type.
type MFARepository struct {
	db                DBPool
	encryptionService *crypto.EncryptionService
}

// NewMFARepository is an exported function.
func NewMFARepository(db *pgxpool.Pool) *MFARepository {
	return &MFARepository{db: db}
}

// SetEncryptionService wires the encryption service for TOTP secret encryption in pending setup
func (r *MFARepository) SetEncryptionService(es *crypto.EncryptionService) {
	r.encryptionService = es
}

// EmailVerification is an exported identifier.
type EmailVerification struct {
	ID         uuid.UUID
	UserID     uuid.UUID
	Email      string
	Code       string
	ExpiresAt  time.Time
	VerifiedAt *time.Time
	CreatedAt  time.Time
}

// CreateEmailVerification is an exported function.
func (r *MFARepository) CreateEmailVerification(ctx context.Context, userID uuid.UUID, email, code string, expiresAt time.Time) (*EmailVerification, error) {
	ev := &EmailVerification{
		ID:        uuid.New(),
		UserID:    userID,
		Email:     email,
		Code:      code,
		ExpiresAt: expiresAt,
		CreatedAt: time.Now(),
	}

	query := `
		INSERT INTO iam_email_verifications (id, user_id, email, code, expires_at, created_at)
		VALUES ($1, $2, $3, $4, $5, $6)`

	_, err := r.db.Exec(ctx, query, ev.ID, ev.UserID, ev.Email, ev.Code, ev.ExpiresAt, ev.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("CreateEmailVerification: %w", err)
	}

	return ev, nil
}

// GetEmailVerification is an exported function.
func (r *MFARepository) GetEmailVerification(ctx context.Context, userID uuid.UUID, code string) (*EmailVerification, error) {
	ev := &EmailVerification{}
	query := `
		SELECT id, user_id, email, code, expires_at, verified_at, created_at
		FROM iam_email_verifications
		WHERE user_id = $1 AND code = $2 AND expires_at > NOW() AND verified_at IS NULL
		ORDER BY created_at DESC
		LIMIT 1`

	err := r.db.QueryRow(ctx, query, userID, code).Scan(
		&ev.ID, &ev.UserID, &ev.Email, &ev.Code, &ev.ExpiresAt, &ev.VerifiedAt, &ev.CreatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("GetEmailVerification: %w", err)
	}
	return ev, nil
}

// GetPendingEmailVerification is an exported function.
func (r *MFARepository) GetPendingEmailVerification(ctx context.Context, userID uuid.UUID) (*EmailVerification, error) {
	ev := &EmailVerification{}
	query := `
		SELECT id, user_id, email, code, expires_at, verified_at, created_at
		FROM iam_email_verifications
		WHERE user_id = $1 AND expires_at > NOW() AND verified_at IS NULL
		ORDER BY created_at DESC
		LIMIT 1`

	err := r.db.QueryRow(ctx, query, userID).Scan(
		&ev.ID, &ev.UserID, &ev.Email, &ev.Code, &ev.ExpiresAt, &ev.VerifiedAt, &ev.CreatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("GetPendingEmailVerification: %w", err)
	}
	return ev, nil
}

// MarkEmailVerified is an exported function.
func (r *MFARepository) MarkEmailVerified(ctx context.Context, id uuid.UUID) error {
	query := `UPDATE iam_email_verifications SET verified_at = NOW() WHERE id = $1`
	_, err := r.db.Exec(ctx, query, id)
	if err != nil {
		return fmt.Errorf("MarkEmailVerified: %w", err)
	}
	return nil
}

// DeleteUserEmailVerifications is an exported function.
func (r *MFARepository) DeleteUserEmailVerifications(ctx context.Context, userID uuid.UUID) error {
	query := `DELETE FROM iam_email_verifications WHERE user_id = $1`
	_, err := r.db.Exec(ctx, query, userID)
	if err != nil {
		return fmt.Errorf("DeleteUserEmailVerifications: %w", err)
	}
	return nil
}

// GetEmailVerificationByToken gets email verification by token only (for public verification links)
func (r *MFARepository) GetEmailVerificationByToken(ctx context.Context, token string) (*EmailVerification, error) {
	ev := &EmailVerification{}
	query := `
		SELECT id, user_id, email, code, expires_at, verified_at, created_at
		FROM iam_email_verifications
		WHERE code = $1 AND expires_at > NOW() AND verified_at IS NULL
		ORDER BY created_at DESC
		LIMIT 1`

	err := r.db.QueryRow(ctx, query, token).Scan(
		&ev.ID, &ev.UserID, &ev.Email, &ev.Code, &ev.ExpiresAt, &ev.VerifiedAt, &ev.CreatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("GetEmailVerificationByToken: %w", err)
	}
	return ev, nil
}

// MFAEmailCode is an exported identifier.
type MFAEmailCode struct {
	ID        uuid.UUID
	UserID    uuid.UUID
	CodeHash  string
	ExpiresAt time.Time
	UsedAt    *time.Time
	CreatedAt time.Time
}

// CreateMFAEmailCode is an exported function.
func (r *MFARepository) CreateMFAEmailCode(ctx context.Context, userID uuid.UUID, codeHash string, expiresAt time.Time) (*MFAEmailCode, error) {
	// First, invalidate any existing codes
	_, err := r.db.Exec(ctx, `DELETE FROM iam_mfa_email_codes WHERE user_id = $1 AND used_at IS NULL`, userID)
	if err != nil {
		return nil, fmt.Errorf("CreateMFAEmailCode: %w", err)
	}

	code := &MFAEmailCode{
		ID:        uuid.New(),
		UserID:    userID,
		CodeHash:  codeHash,
		ExpiresAt: expiresAt,
		CreatedAt: time.Now(),
	}

	query := `
		INSERT INTO iam_mfa_email_codes (id, user_id, code_hash, expires_at, created_at)
		VALUES ($1, $2, $3, $4, $5)`

	_, err = r.db.Exec(ctx, query, code.ID, code.UserID, code.CodeHash, code.ExpiresAt, code.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("CreateMFAEmailCode: %w", err)
	}

	return code, nil
}

// GetActiveMFAEmailCode is an exported function.
func (r *MFARepository) GetActiveMFAEmailCode(ctx context.Context, userID uuid.UUID) (*MFAEmailCode, error) {
	code := &MFAEmailCode{}
	query := `
		SELECT id, user_id, code_hash, expires_at, used_at, created_at
		FROM iam_mfa_email_codes
		WHERE user_id = $1 AND expires_at > NOW() AND used_at IS NULL
		ORDER BY created_at DESC
		LIMIT 1`

	err := r.db.QueryRow(ctx, query, userID).Scan(
		&code.ID, &code.UserID, &code.CodeHash, &code.ExpiresAt, &code.UsedAt, &code.CreatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("GetActiveMFAEmailCode: %w", err)
	}
	return code, nil
}

// MarkMFAEmailCodeUsed is an exported function.
func (r *MFARepository) MarkMFAEmailCodeUsed(ctx context.Context, id uuid.UUID) error {
	query := `UPDATE iam_mfa_email_codes SET used_at = NOW() WHERE id = $1`
	_, err := r.db.Exec(ctx, query, id)
	if err != nil {
		return fmt.Errorf("MarkMFAEmailCodeUsed: %w", err)
	}
	return nil
}

// MFAPendingSetup is an exported identifier.
type MFAPendingSetup struct {
	ID        uuid.UUID
	UserID    uuid.UUID
	Secret    string
	MFAType   string
	ExpiresAt time.Time
	CreatedAt time.Time
}

// CreateMFAPendingSetup is an exported function.
func (r *MFARepository) CreateMFAPendingSetup(ctx context.Context, userID uuid.UUID, secret, mfaType string, expiresAt time.Time) (*MFAPendingSetup, error) {
	// Delete any existing pending setup
	_, err := r.db.Exec(ctx, `DELETE FROM iam_mfa_pending_setup WHERE user_id = $1`, userID)
	if err != nil {
		return nil, fmt.Errorf("CreateMFAPendingSetup: %w", err)
	}

	// SECURITY: Encrypt TOTP secret before storage
	storedSecret := secret
	if r.encryptionService != nil && secret != "" {
		encrypted, err := r.encryptionService.Encrypt(secret)
		if err != nil {
			return nil, fmt.Errorf("CreateMFAPendingSetup: failed to encrypt secret: %w", err)
		}
		storedSecret = encrypted
	}

	setup := &MFAPendingSetup{
		ID:        uuid.New(),
		UserID:    userID,
		Secret:    secret, // Return plaintext to caller
		MFAType:   mfaType,
		ExpiresAt: expiresAt,
		CreatedAt: time.Now(),
	}

	query := `
		INSERT INTO iam_mfa_pending_setup (id, user_id, secret, mfa_type, expires_at, created_at)
		VALUES ($1, $2, $3, $4, $5, $6)`

	_, err = r.db.Exec(ctx, query, setup.ID, setup.UserID, storedSecret, setup.MFAType, setup.ExpiresAt, setup.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("CreateMFAPendingSetup: %w", err)
	}

	return setup, nil
}

// GetMFAPendingSetup is an exported function.
func (r *MFARepository) GetMFAPendingSetup(ctx context.Context, userID uuid.UUID) (*MFAPendingSetup, error) {
	setup := &MFAPendingSetup{}
	query := `
		SELECT id, user_id, secret, mfa_type, expires_at, created_at
		FROM iam_mfa_pending_setup
		WHERE user_id = $1 AND expires_at > NOW()
		LIMIT 1`

	err := r.db.QueryRow(ctx, query, userID).Scan(
		&setup.ID, &setup.UserID, &setup.Secret, &setup.MFAType, &setup.ExpiresAt, &setup.CreatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("GetMFAPendingSetup: %w", err)
	}

	// SECURITY: Decrypt TOTP secret after reading from DB
	if r.encryptionService != nil && setup.Secret != "" {
		decrypted, err := r.encryptionService.Decrypt(setup.Secret)
		if err == nil {
			setup.Secret = decrypted
		}
		// If decryption fails, secret may be plaintext (pre-migration) — leave as-is
	}

	return setup, nil
}

// DeleteMFAPendingSetup is an exported function.
func (r *MFARepository) DeleteMFAPendingSetup(ctx context.Context, userID uuid.UUID) error {
	query := `DELETE FROM iam_mfa_pending_setup WHERE user_id = $1`
	_, err := r.db.Exec(ctx, query, userID)
	if err != nil {
		return fmt.Errorf("DeleteMFAPendingSetup: %w", err)
	}
	return nil
}

// RecoveryCode is an exported identifier.
type RecoveryCode struct {
	ID        uuid.UUID
	UserID    uuid.UUID
	CodeHash  string
	CreatedAt time.Time
	UsedAt    *time.Time
}

// CreateRecoveryCodes is an exported function.
func (r *MFARepository) CreateRecoveryCodes(ctx context.Context, userID uuid.UUID, codeHashes []string) error {
	// Delete existing unused codes
	_, err := r.db.Exec(ctx, `DELETE FROM iam_mfa_recovery_codes WHERE user_id = $1 AND used_at IS NULL`, userID)
	if err != nil {
		return fmt.Errorf("CreateRecoveryCodes: %w", err)
	}

	// Insert new codes
	for _, hash := range codeHashes {
		_, err := r.db.Exec(ctx,
			`INSERT INTO iam_mfa_recovery_codes (user_id, code_hash) VALUES ($1, $2)`,
			userID, hash,
		)
		if err != nil {
			return fmt.Errorf("CreateRecoveryCodes: %w", err)
		}
	}

	return nil
}

// GetUnusedRecoveryCodesCount is an exported function.
func (r *MFARepository) GetUnusedRecoveryCodesCount(ctx context.Context, userID uuid.UUID) (int, error) {
	var count int
	query := `SELECT COUNT(*) FROM iam_mfa_recovery_codes WHERE user_id = $1 AND used_at IS NULL`
	err := r.db.QueryRow(ctx, query, userID).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("GetUnusedRecoveryCodesCount: %w", err)
	}
	return count, nil
}

// GetUnusedRecoveryCodes is an exported function.
func (r *MFARepository) GetUnusedRecoveryCodes(ctx context.Context, userID uuid.UUID) ([]RecoveryCode, error) {
	query := `
		SELECT id, user_id, code_hash, created_at, used_at
		FROM iam_mfa_recovery_codes
		WHERE user_id = $1 AND used_at IS NULL
		ORDER BY created_at`

	rows, err := r.db.Query(ctx, query, userID)
	if err != nil {
		return nil, fmt.Errorf("GetUnusedRecoveryCodes: %w", err)
	}
	defer rows.Close()

	var codes []RecoveryCode
	for rows.Next() {
		var code RecoveryCode
		if err := rows.Scan(&code.ID, &code.UserID, &code.CodeHash, &code.CreatedAt, &code.UsedAt); err != nil {
			return nil, fmt.Errorf("GetUnusedRecoveryCodes: %w", err)
		}
		codes = append(codes, code)
	}

	return codes, rows.Err()
}

// UseRecoveryCode is an exported function.
func (r *MFARepository) UseRecoveryCode(ctx context.Context, id uuid.UUID) error {
	query := `UPDATE iam_mfa_recovery_codes SET used_at = NOW() WHERE id = $1`
	_, err := r.db.Exec(ctx, query, id)
	if err != nil {
		return fmt.Errorf("UseRecoveryCode: %w", err)
	}
	return nil
}

// DeleteAllRecoveryCodes is an exported function.
func (r *MFARepository) DeleteAllRecoveryCodes(ctx context.Context, userID uuid.UUID) error {
	query := `DELETE FROM iam_mfa_recovery_codes WHERE user_id = $1`
	_, err := r.db.Exec(ctx, query, userID)
	if err != nil {
		return fmt.Errorf("DeleteAllRecoveryCodes: %w", err)
	}
	return nil
}

// CleanupExpired is an exported identifier.
func (r *MFARepository) CleanupExpired(ctx context.Context) error {
	_, err := r.db.Exec(ctx, `SELECT cleanup_expired_mfa_records()`)
	if err != nil {
		return fmt.Errorf("CleanupExpired: %w", err)
	}
	return nil
}
