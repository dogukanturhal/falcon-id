// SPDX-License-Identifier: AGPL-3.0-or-later

package repositories

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

// SPCredentialRepository handles SP credential database operations.
type SPCredentialRepository struct {
	pool *pgxpool.Pool
}

// NewSPCredentialRepository creates a new SPCredentialRepository.
func NewSPCredentialRepository(pool *pgxpool.Pool) *SPCredentialRepository {
	return &SPCredentialRepository{pool: pool}
}

// spCredentialColumns is the full column list used for SELECT queries (includes last_used_at and certificate fields).
const spCredentialColumns = `id, sp_id, credential_type, key_id, public_key_pem, secret_hash, display_hint, status, expires_at, created_at, revoked_at, last_used_at, thumbprint_sha1, thumbprint_sha256, subject, issuer, serial_number, not_before` //nolint:gosec // not a credential, this is a column name constant

// spCredentialInsertColumns is the column list used for INSERT (excludes last_used_at which defaults to NULL).
const spCredentialInsertColumns = `id, sp_id, credential_type, key_id, public_key_pem, secret_hash, display_hint, status, expires_at, created_at, revoked_at, thumbprint_sha1, thumbprint_sha256, subject, issuer, serial_number, not_before` //nolint:gosec // not a credential, this is a column name constant

func scanSPCredential(scanner interface {
	Scan(dest ...interface{}) error
},
) (*models.SPCredential, error) {
	var c models.SPCredential
	err := scanner.Scan(
		&c.ID, &c.SPID, &c.CredentialType, &c.KeyID,
		&c.PublicKeyPEM, &c.SecretHash, &c.DisplayHint,
		&c.Status, &c.ExpiresAt, &c.CreatedAt, &c.RevokedAt,
		&c.LastUsedAt,
		&c.ThumbprintSHA1, &c.ThumbprintSHA256, &c.Subject,
		&c.Issuer, &c.SerialNumber, &c.NotBefore,
	)
	if err != nil {
		return nil, err
	}
	return &c, nil
}

// Create inserts a new SP credential.
func (r *SPCredentialRepository) Create(ctx context.Context, cred *models.SPCredential) error {
	if cred.ID == uuid.Nil {
		cred.ID = uuid.New()
	}

	query := fmt.Sprintf(`
		INSERT INTO iam_sp_credentials (%s)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17)
		RETURNING created_at`, spCredentialInsertColumns)

	err := r.pool.QueryRow(ctx, query,
		cred.ID, cred.SPID, cred.CredentialType, cred.KeyID,
		cred.PublicKeyPEM, cred.SecretHash, cred.DisplayHint,
		cred.Status, cred.ExpiresAt, cred.CreatedAt, cred.RevokedAt,
		cred.ThumbprintSHA1, cred.ThumbprintSHA256, cred.Subject,
		cred.Issuer, cred.SerialNumber, cred.NotBefore,
	).Scan(&cred.CreatedAt)
	if err != nil {
		return fmt.Errorf("SPCredentialRepository.Create: %w", err)
	}
	return nil
}

// GetByID retrieves a credential by UUID.
func (r *SPCredentialRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.SPCredential, error) {
	query := fmt.Sprintf(`SELECT %s FROM iam_sp_credentials WHERE id = $1`, spCredentialColumns)
	cred, err := scanSPCredential(r.pool.QueryRow(ctx, query, id))
	if err != nil {
		return nil, fmt.Errorf("SPCredentialRepository.GetByID: %w", err)
	}
	return cred, nil
}

// ListBySP returns all active credentials for a service principal.
func (r *SPCredentialRepository) ListBySP(ctx context.Context, spID uuid.UUID) ([]models.SPCredential, error) {
	query := fmt.Sprintf(`SELECT %s FROM iam_sp_credentials WHERE sp_id = $1 AND status = 'active' ORDER BY created_at DESC`, spCredentialColumns)

	rows, err := r.pool.Query(ctx, query, spID)
	if err != nil {
		return nil, fmt.Errorf("SPCredentialRepository.ListBySP: %w", err)
	}
	defer rows.Close()

	var creds []models.SPCredential
	for rows.Next() {
		cred, err := scanSPCredential(rows)
		if err != nil {
			return nil, fmt.Errorf("SPCredentialRepository.ListBySP scan: %w", err)
		}
		creds = append(creds, *cred)
	}
	return creds, rows.Err()
}

// Revoke marks a credential as revoked.
func (r *SPCredentialRepository) Revoke(ctx context.Context, id uuid.UUID) error {
	now := time.Now()
	_, err := r.pool.Exec(ctx,
		`UPDATE iam_sp_credentials SET status = 'revoked', revoked_at = $1 WHERE id = $2`,
		now, id,
	)
	if err != nil {
		return fmt.Errorf("SPCredentialRepository.Revoke: %w", err)
	}
	return nil
}

// CleanupExpired marks all expired-but-still-active credentials as expired.
func (r *SPCredentialRepository) CleanupExpired(ctx context.Context) (int64, error) {
	tag, err := r.pool.Exec(ctx,
		`UPDATE iam_sp_credentials SET status = 'expired' WHERE status = 'active' AND expires_at IS NOT NULL AND expires_at < NOW()`,
	)
	if err != nil {
		return 0, fmt.Errorf("SPCredentialRepository.CleanupExpired: %w", err)
	}
	return tag.RowsAffected(), nil
}

// DeleteBySP deletes all credentials for a service principal (hard delete on SP removal).
func (r *SPCredentialRepository) DeleteBySP(ctx context.Context, spID uuid.UUID) error {
	_, err := r.pool.Exec(ctx, `DELETE FROM iam_sp_credentials WHERE sp_id = $1`, spID)
	if err != nil {
		return fmt.Errorf("SPCredentialRepository.DeleteBySP: %w", err)
	}
	return nil
}

// RecordUsage stamps the current time as last_used_at for the given credential.
func (r *SPCredentialRepository) RecordUsage(ctx context.Context, credID uuid.UUID) error {
	_, err := r.pool.Exec(ctx,
		`UPDATE iam_sp_credentials SET last_used_at = now() WHERE id = $1`,
		credID,
	)
	if err != nil {
		return fmt.Errorf("SPCredentialRepository.RecordUsage: %w", err)
	}
	return nil
}

// ListUnused returns all active credentials whose last_used_at is NULL or older than unusedDays days ago.
func (r *SPCredentialRepository) ListUnused(ctx context.Context, unusedDays int) ([]models.SPCredential, error) {
	query := fmt.Sprintf(`
		SELECT %s FROM iam_sp_credentials
		WHERE status = 'active'
		  AND (last_used_at IS NULL OR last_used_at < now() - interval '1 day' * $1)
		ORDER BY created_at ASC`, spCredentialColumns)

	rows, err := r.pool.Query(ctx, query, unusedDays)
	if err != nil {
		return nil, fmt.Errorf("SPCredentialRepository.ListUnused: %w", err)
	}
	defer rows.Close()

	var creds []models.SPCredential
	for rows.Next() {
		cred, err := scanSPCredential(rows)
		if err != nil {
			return nil, fmt.Errorf("SPCredentialRepository.ListUnused scan: %w", err)
		}
		creds = append(creds, *cred)
	}
	return creds, rows.Err()
}

// ListExpiringSoon returns all active credentials that expire within withinDays days,
// ordered by earliest expiry first.
func (r *SPCredentialRepository) ListExpiringSoon(ctx context.Context, withinDays int) ([]models.SPCredential, error) {
	query := fmt.Sprintf(`
		SELECT %s FROM iam_sp_credentials
		WHERE status = 'active'
		  AND expires_at IS NOT NULL
		  AND expires_at BETWEEN now() AND now() + interval '1 day' * $1
		ORDER BY expires_at ASC`, spCredentialColumns)

	rows, err := r.pool.Query(ctx, query, withinDays)
	if err != nil {
		return nil, fmt.Errorf("SPCredentialRepository.ListExpiringSoon: %w", err)
	}
	defer rows.Close()

	var creds []models.SPCredential
	for rows.Next() {
		cred, err := scanSPCredential(rows)
		if err != nil {
			return nil, fmt.Errorf("SPCredentialRepository.ListExpiringSoon scan: %w", err)
		}
		creds = append(creds, *cred)
	}
	return creds, rows.Err()
}
