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

// BootstrapTokenRepository handles persistence for service bootstrap tokens.
type BootstrapTokenRepository struct {
	db *pgxpool.Pool
}

// NewBootstrapTokenRepository creates a new BootstrapTokenRepository.
func NewBootstrapTokenRepository(db *pgxpool.Pool) *BootstrapTokenRepository {
	return &BootstrapTokenRepository{db: db}
}

// CreateBootstrapToken persists a new bootstrap token.
func (r *BootstrapTokenRepository) CreateBootstrapToken(ctx context.Context, token *models.BootstrapToken) error {
	query := `
		INSERT INTO iam_service_bootstrap_tokens
		(id, token_hash, service_slug, allowed_scopes, ip_allowlist, max_uses, used_count, expires_at, created_by, created_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`

	_, err := r.db.Exec(ctx, query,
		token.ID, token.TokenHash, token.ServiceSlug,
		token.AllowedScopes, token.IPAllowlist,
		token.MaxUses, token.UsedCount,
		token.ExpiresAt, token.CreatedBy, token.CreatedAt,
	)
	if err != nil {
		return fmt.Errorf("BootstrapTokenRepository.CreateBootstrapToken: %w", err)
	}
	return nil
}

// GetBootstrapTokenByHash returns the token matching the given SHA-256 hash.
func (r *BootstrapTokenRepository) GetBootstrapTokenByHash(ctx context.Context, hash string) (*models.BootstrapToken, error) {
	query := `
		SELECT id, token_hash, service_slug, allowed_scopes, ip_allowlist,
		       max_uses, used_count, expires_at, created_by, created_at
		FROM iam_service_bootstrap_tokens
		WHERE token_hash = $1`

	var t models.BootstrapToken
	err := r.db.QueryRow(ctx, query, hash).Scan(
		&t.ID, &t.TokenHash, &t.ServiceSlug, &t.AllowedScopes, &t.IPAllowlist,
		&t.MaxUses, &t.UsedCount, &t.ExpiresAt, &t.CreatedBy, &t.CreatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("BootstrapTokenRepository.GetBootstrapTokenByHash: %w", err)
	}
	return &t, nil
}

// ListBootstrapTokens returns all tokens, optionally filtered by service slug.
func (r *BootstrapTokenRepository) ListBootstrapTokens(ctx context.Context, serviceSlug string) ([]models.BootstrapToken, error) {
	query := `
		SELECT id, token_hash, service_slug, allowed_scopes, ip_allowlist,
		       max_uses, used_count, expires_at, created_by, created_at
		FROM iam_service_bootstrap_tokens
		WHERE ($1::text = '' OR service_slug = $1)
		ORDER BY created_at DESC`

	rows, err := r.db.Query(ctx, query, serviceSlug)
	if err != nil {
		return nil, fmt.Errorf("BootstrapTokenRepository.ListBootstrapTokens: %w", err)
	}
	defer rows.Close()

	var tokens []models.BootstrapToken
	for rows.Next() {
		var t models.BootstrapToken
		if err := rows.Scan(
			&t.ID, &t.TokenHash, &t.ServiceSlug, &t.AllowedScopes, &t.IPAllowlist,
			&t.MaxUses, &t.UsedCount, &t.ExpiresAt, &t.CreatedBy, &t.CreatedAt,
		); err != nil {
			continue
		}
		tokens = append(tokens, t)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("BootstrapTokenRepository.ListBootstrapTokens: rows: %w", err)
	}
	return tokens, nil
}

// DeleteBootstrapToken removes a bootstrap token by ID.
func (r *BootstrapTokenRepository) DeleteBootstrapToken(ctx context.Context, id uuid.UUID) error {
	_, err := r.db.Exec(ctx, `DELETE FROM iam_service_bootstrap_tokens WHERE id=$1`, id)
	if err != nil {
		return fmt.Errorf("BootstrapTokenRepository.DeleteBootstrapToken: %w", err)
	}
	return nil
}

// IncrementBootstrapTokenUsage atomically increments the used_count for a token.
// Expired or exhausted tokens are also purged as a side-effect.
func (r *BootstrapTokenRepository) IncrementBootstrapTokenUsage(ctx context.Context, id uuid.UUID) error {
	_, err := r.db.Exec(ctx,
		`UPDATE iam_service_bootstrap_tokens SET used_count = used_count + 1 WHERE id=$1`,
		id,
	)
	if err != nil {
		return fmt.Errorf("BootstrapTokenRepository.IncrementBootstrapTokenUsage: %w", err)
	}
	return nil
}

// PurgeExpired removes tokens that have passed their expiry time.
// This is intended to be called from a periodic maintenance job.
func (r *BootstrapTokenRepository) PurgeExpired(ctx context.Context) (int64, error) {
	tag, err := r.db.Exec(ctx,
		`DELETE FROM iam_service_bootstrap_tokens WHERE expires_at < $1`,
		time.Now(),
	)
	if err != nil {
		return 0, fmt.Errorf("BootstrapTokenRepository.PurgeExpired: %w", err)
	}
	return tag.RowsAffected(), nil
}
