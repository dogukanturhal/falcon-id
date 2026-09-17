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

	"github.com/dogukanturhal/falcon-id/internal/models"
)

const msgSCIMTokenNotFound = "SCIM token not found" //nolint:gosec // not a credential, this is a SCIM schema constant

// SCIMRepository handles SCIM token database operations
type SCIMRepository struct {
	pool *pgxpool.Pool
}

// NewSCIMRepository creates a new SCIMRepository
func NewSCIMRepository(pool *pgxpool.Pool) *SCIMRepository {
	return &SCIMRepository{pool: pool}
}

// ==================== SCIM Token Operations ====================

// GetByID retrieves a SCIM token by its UUID
func (r *SCIMRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.SCIMToken, error) {
	query := `
		SELECT id, tenant_id, name, description, token_hash, is_active,
		       last_used_at, last_used_ip, created_at, created_by, expires_at
		FROM iam_scim_tokens
		WHERE id = $1`

	token := &models.SCIMToken{}
	err := r.pool.QueryRow(ctx, query, id).Scan(
		&token.ID, &token.TenantID, &token.Name, &token.Description, &token.TokenHash,
		&token.IsActive, &token.LastUsedAt, &token.LastUsedIP, &token.CreatedAt,
		&token.CreatedBy, &token.ExpiresAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, errors.New(msgSCIMTokenNotFound)
		}
		return nil, fmt.Errorf("failed to get SCIM token: %w", err)
	}

	return token, nil
}

// GetByTokenHash retrieves a SCIM token by its hash, regardless of
// whether the token is currently active.
//
// The query intentionally does NOT filter on `is_active`. The caller
// (SCIMService.ValidateToken) inspects `token.IsActive` and decides
// whether to allow the request — pre-2026-05-21 the repo applied the
// filter directly, collapsing "revoked token replay attempt" with
// "unknown token hash" and losing the SOC's pivot signal. See
// docs/audits/2026-05-21-repo-state-filter-audit.md.
//
// Expiration is also kept at the service layer so the structured
// audit-trail emit lives in one place.
func (r *SCIMRepository) GetByTokenHash(ctx context.Context, tokenHash string) (*models.SCIMToken, error) {
	query := `
		SELECT id, tenant_id, name, description, token_hash, is_active,
		       last_used_at, last_used_ip, created_at, created_by, expires_at
		FROM iam_scim_tokens
		WHERE token_hash = $1`

	token := &models.SCIMToken{}
	err := r.pool.QueryRow(ctx, query, tokenHash).Scan(
		&token.ID, &token.TenantID, &token.Name, &token.Description, &token.TokenHash,
		&token.IsActive, &token.LastUsedAt, &token.LastUsedIP, &token.CreatedAt,
		&token.CreatedBy, &token.ExpiresAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, errors.New(msgSCIMTokenNotFound)
		}
		return nil, fmt.Errorf("failed to get SCIM token: %w", err)
	}

	return token, nil
}

// GetByTenantID retrieves all SCIM tokens for a tenant
func (r *SCIMRepository) GetByTenantID(ctx context.Context, tenantID uuid.UUID) ([]*models.SCIMToken, error) {
	query := `
		SELECT id, tenant_id, name, description, token_hash, is_active,
		       last_used_at, last_used_ip, created_at, created_by, expires_at
		FROM iam_scim_tokens
		WHERE tenant_id = $1
		ORDER BY created_at DESC`

	rows, err := r.pool.Query(ctx, query, tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to list SCIM tokens: %w", err)
	}
	defer rows.Close()

	var tokens []*models.SCIMToken
	for rows.Next() {
		token := &models.SCIMToken{}
		err := rows.Scan(
			&token.ID, &token.TenantID, &token.Name, &token.Description, &token.TokenHash,
			&token.IsActive, &token.LastUsedAt, &token.LastUsedIP, &token.CreatedAt,
			&token.CreatedBy, &token.ExpiresAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan SCIM token: %w", err)
		}
		tokens = append(tokens, token)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("GetByTenantID: rows iteration: %w", err)
	}

	return tokens, nil
}

// Create creates a new SCIM token
func (r *SCIMRepository) Create(ctx context.Context, token *models.SCIMToken) error {
	query := `
		INSERT INTO iam_scim_tokens (
			id, tenant_id, name, description, token_hash, is_active,
			created_at, created_by, expires_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`

	_, err := r.pool.Exec(ctx, query,
		token.ID, token.TenantID, token.Name, token.Description, token.TokenHash,
		token.IsActive, token.CreatedAt, token.CreatedBy, token.ExpiresAt,
	)
	if err != nil {
		return fmt.Errorf("failed to create SCIM token: %w", err)
	}

	return nil
}

// Update updates a SCIM token
func (r *SCIMRepository) Update(ctx context.Context, token *models.SCIMToken) error {
	query := `
		UPDATE iam_scim_tokens SET
			name = $1, description = $2, is_active = $3
		WHERE id = $4`

	result, err := r.pool.Exec(ctx, query,
		token.Name, token.Description, token.IsActive, token.ID,
	)
	if err != nil {
		return fmt.Errorf("failed to update SCIM token: %w", err)
	}

	if result.RowsAffected() == 0 {
		return errors.New(msgSCIMTokenNotFound)
	}

	return nil
}

// Delete deletes a SCIM token
func (r *SCIMRepository) Delete(ctx context.Context, id uuid.UUID) error {
	query := `DELETE FROM iam_scim_tokens WHERE id = $1`
	result, err := r.pool.Exec(ctx, query, id)
	if err != nil {
		return fmt.Errorf("failed to delete SCIM token: %w", err)
	}

	if result.RowsAffected() == 0 {
		return errors.New(msgSCIMTokenNotFound)
	}

	return nil
}

// UpdateLastUsed updates the last used timestamp and IP
func (r *SCIMRepository) UpdateLastUsed(ctx context.Context, id uuid.UUID, ip string) error {
	query := `
		UPDATE iam_scim_tokens SET
			last_used_at = $1, last_used_ip = $2
		WHERE id = $3`

	_, err := r.pool.Exec(ctx, query, time.Now(), ip, id)
	if err != nil {
		return fmt.Errorf("failed to update last used: %w", err)
	}

	return nil
}

// Revoke revokes a SCIM token
func (r *SCIMRepository) Revoke(ctx context.Context, id uuid.UUID) error {
	query := `UPDATE iam_scim_tokens SET is_active = false WHERE id = $1`
	result, err := r.pool.Exec(ctx, query, id)
	if err != nil {
		return fmt.Errorf("failed to revoke SCIM token: %w", err)
	}

	if result.RowsAffected() == 0 {
		return errors.New(msgSCIMTokenNotFound)
	}

	return nil
}

// CleanupExpired removes expired tokens
func (r *SCIMRepository) CleanupExpired(ctx context.Context) error {
	query := `DELETE FROM iam_scim_tokens WHERE expires_at IS NOT NULL AND expires_at < $1`
	_, err := r.pool.Exec(ctx, query, time.Now())
	if err != nil {
		return fmt.Errorf("failed to cleanup expired tokens: %w", err)
	}
	return nil
}
