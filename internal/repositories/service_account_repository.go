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

const msgServiceAccountNotFound = "service account not found"

// ServiceAccountRepository is an exported type.
type ServiceAccountRepository struct {
	pool    DBPool
	realmID *uuid.UUID
}

// WithRealmID returns a shallow clone of ServiceAccountRepository scoped to the given realm.
func (r *ServiceAccountRepository) WithRealmID(realmID uuid.UUID) *ServiceAccountRepository {
	clone := *r
	clone.realmID = &realmID
	return &clone
}

// NewServiceAccountRepository is an exported function.
func NewServiceAccountRepository(pool *pgxpool.Pool) *ServiceAccountRepository {
	return &ServiceAccountRepository{pool: pool}
}

// GetByID retrieves a service account by ID
func (r *ServiceAccountRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.ServiceAccount, error) {
	query := `
		SELECT id, tenant_id, name, description, client_id, client_secret_hash,
			   role_ids, allowed_ips, allowed_endpoints, is_active,
			   last_used_at, last_used_ip, COALESCE(token_lifetime_minutes, 60) as token_lifetime_minutes,
			   created_at, updated_at, created_by
		FROM iam_service_accounts
		WHERE id = $1
	`

	var sa models.ServiceAccount
	err := r.pool.QueryRow(ctx, query, id).Scan(
		&sa.ID, &sa.TenantID, &sa.Name, &sa.Description,
		&sa.ClientID, &sa.ClientSecretHash, &sa.RoleIDs,
		&sa.AllowedIPs, &sa.AllowedEndpoints, &sa.IsActive,
		&sa.LastUsedAt, &sa.LastUsedIP, &sa.TokenLifetimeMinutes,
		&sa.CreatedAt, &sa.UpdatedAt, &sa.CreatedBy,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get service account: %w", err)
	}

	return &sa, nil
}

// GetByClientID retrieves a service account by client ID, regardless
// of whether the account is currently active.
//
// The query intentionally does NOT filter on `is_active`. The caller
// (ServiceAccountService.Authenticate) inspects `sa.IsActive` and
// decides — pre-2026-05-21 the repo applied the filter directly,
// collapsing "deactivated SA replay attempt" with "unknown client_id"
// and losing the SOC's pivot signal for an attacker holding a
// recently-rotated SA credential. See
// docs/audits/2026-05-21-repo-state-filter-audit.md.
//
// SECURITY: Authenticate runs the client-secret hash check BEFORE
// the IsActive branch so callers without the full secret get an
// identical "authentication failed" response whether or not the
// client_id matches a deactivated account (no client_id-oracle).
func (r *ServiceAccountRepository) GetByClientID(ctx context.Context, clientID string) (*models.ServiceAccount, error) {
	query := `
		SELECT id, tenant_id, name, description, client_id, client_secret_hash,
			   role_ids, allowed_ips, allowed_endpoints, is_active,
			   last_used_at, last_used_ip, COALESCE(token_lifetime_minutes, 60) as token_lifetime_minutes,
			   created_at, updated_at, created_by
		FROM iam_service_accounts
		WHERE client_id = $1
	`

	var sa models.ServiceAccount
	err := r.pool.QueryRow(ctx, query, clientID).Scan(
		&sa.ID, &sa.TenantID, &sa.Name, &sa.Description,
		&sa.ClientID, &sa.ClientSecretHash, &sa.RoleIDs,
		&sa.AllowedIPs, &sa.AllowedEndpoints, &sa.IsActive,
		&sa.LastUsedAt, &sa.LastUsedIP, &sa.TokenLifetimeMinutes,
		&sa.CreatedAt, &sa.UpdatedAt, &sa.CreatedBy,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get service account by client ID: %w", err)
	}

	return &sa, nil
}

// GetByTenantID retrieves all service accounts for a tenant
func (r *ServiceAccountRepository) GetByTenantID(ctx context.Context, tenantID uuid.UUID) ([]*models.ServiceAccount, error) {
	query := `
		SELECT id, tenant_id, name, description, client_id, client_secret_hash,
			   role_ids, allowed_ips, allowed_endpoints, is_active,
			   last_used_at, last_used_ip, COALESCE(token_lifetime_minutes, 60) as token_lifetime_minutes,
			   created_at, updated_at, created_by
		FROM iam_service_accounts
		WHERE tenant_id = $1
		ORDER BY created_at DESC
	`

	rows, err := r.pool.Query(ctx, query, tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to query service accounts: %w", err)
	}
	defer rows.Close()

	var accounts []*models.ServiceAccount
	for rows.Next() {
		var sa models.ServiceAccount
		err := rows.Scan(
			&sa.ID, &sa.TenantID, &sa.Name, &sa.Description,
			&sa.ClientID, &sa.ClientSecretHash, &sa.RoleIDs,
			&sa.AllowedIPs, &sa.AllowedEndpoints, &sa.IsActive,
			&sa.LastUsedAt, &sa.LastUsedIP, &sa.TokenLifetimeMinutes,
			&sa.CreatedAt, &sa.UpdatedAt, &sa.CreatedBy,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan service account: %w", err)
		}
		accounts = append(accounts, &sa)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("GetByTenantID: rows iteration: %w", err)
	}

	return accounts, nil
}

// ListTenantInventory returns only fields safe for a signed-tenant machine
// inventory. Credentials and client identifiers are intentionally not read.
func (r *ServiceAccountRepository) ListTenantInventory(ctx context.Context, tenantID uuid.UUID, page, pageSize int) ([]models.TenantMachinePrincipal, int64, error) {
	var total int64
	if err := r.pool.QueryRow(ctx, `SELECT COUNT(*) FROM iam_service_accounts WHERE tenant_id = $1`, tenantID).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count tenant service accounts: %w", err)
	}
	rows, err := r.pool.Query(ctx, `SELECT id, name, is_active, created_at FROM iam_service_accounts
		WHERE tenant_id = $1 ORDER BY created_at DESC, id DESC LIMIT $2 OFFSET $3`, tenantID, pageSize, (page-1)*pageSize)
	if err != nil {
		return nil, 0, fmt.Errorf("list tenant service accounts: %w", err)
	}
	defer rows.Close()
	items := make([]models.TenantMachinePrincipal, 0)
	for rows.Next() {
		var item models.TenantMachinePrincipal
		var active bool
		if err := rows.Scan(&item.ID, &item.Name, &active, &item.CreatedAt); err != nil {
			return nil, 0, fmt.Errorf("scan tenant service account: %w", err)
		}
		item.Kind, item.Source = "service_account", "iam_service_accounts"
		if active {
			item.Status = "active"
		} else {
			item.Status = "inactive"
		}
		items = append(items, item)
	}
	return items, total, rows.Err()
}

// Create creates a new service account
func (r *ServiceAccountRepository) Create(ctx context.Context, sa *models.ServiceAccount) error {
	query := `
		INSERT INTO iam_service_accounts (
			tenant_id, name, description, client_id, client_secret_hash,
			role_ids, allowed_ips, allowed_endpoints, is_active,
			token_lifetime_minutes, created_by
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
		RETURNING id, created_at, updated_at
	`

	err := r.pool.QueryRow(ctx, query,
		sa.TenantID, sa.Name, sa.Description, sa.ClientID, sa.ClientSecretHash,
		sa.RoleIDs, sa.AllowedIPs, sa.AllowedEndpoints, sa.IsActive,
		sa.TokenLifetimeMinutes, sa.CreatedBy,
	).Scan(&sa.ID, &sa.CreatedAt, &sa.UpdatedAt)
	if err != nil {
		return fmt.Errorf("failed to create service account: %w", err)
	}

	return nil
}

// Update updates an existing service account
func (r *ServiceAccountRepository) Update(ctx context.Context, sa *models.ServiceAccount) error {
	query := `
		UPDATE iam_service_accounts
		SET name = $1, description = $2, role_ids = $3, allowed_ips = $4,
			allowed_endpoints = $5, is_active = $6, token_lifetime_minutes = $7
		WHERE id = $8
	`

	result, err := r.pool.Exec(ctx, query,
		sa.Name, sa.Description, sa.RoleIDs, sa.AllowedIPs,
		sa.AllowedEndpoints, sa.IsActive, sa.TokenLifetimeMinutes, sa.ID,
	)
	if err != nil {
		return fmt.Errorf("failed to update service account: %w", err)
	}

	if result.RowsAffected() == 0 {
		return errors.New(msgServiceAccountNotFound)
	}

	return nil
}

// UpdateSecret updates the client secret hash
func (r *ServiceAccountRepository) UpdateSecret(ctx context.Context, id uuid.UUID, secretHash string) error {
	query := `UPDATE iam_service_accounts SET client_secret_hash = $1 WHERE id = $2`

	result, err := r.pool.Exec(ctx, query, secretHash, id)
	if err != nil {
		return fmt.Errorf("failed to update service account secret: %w", err)
	}

	if result.RowsAffected() == 0 {
		return errors.New(msgServiceAccountNotFound)
	}

	return nil
}

// Delete permanently deletes a service account
func (r *ServiceAccountRepository) Delete(ctx context.Context, id uuid.UUID) error {
	query := `DELETE FROM iam_service_accounts WHERE id = $1`

	result, err := r.pool.Exec(ctx, query, id)
	if err != nil {
		return fmt.Errorf("failed to delete service account: %w", err)
	}

	if result.RowsAffected() == 0 {
		return errors.New(msgServiceAccountNotFound)
	}

	return nil
}

// UpdateLastUsed updates the last used timestamp
func (r *ServiceAccountRepository) UpdateLastUsed(ctx context.Context, id uuid.UUID, ip string) error {
	query := `
		UPDATE iam_service_accounts
		SET last_used_at = NOW(), last_used_ip = $1
		WHERE id = $2
	`

	_, err := r.pool.Exec(ctx, query, ip, id)
	if err != nil {
		return fmt.Errorf("failed to update service account last used: %w", err)
	}

	return nil
}

// Token management

// CreateToken creates a new service account token
func (r *ServiceAccountRepository) CreateToken(ctx context.Context, token *models.ServiceAccountToken) error {
	query := `
		INSERT INTO iam_service_account_tokens (
			service_account_id, token_hash, ip_address, expires_at
		) VALUES ($1, $2, $3, $4)
		RETURNING id, created_at
	`

	err := r.pool.QueryRow(ctx, query,
		token.ServiceAccountID, token.TokenHash, token.IPAddress, token.ExpiresAt,
	).Scan(&token.ID, &token.CreatedAt)
	if err != nil {
		return fmt.Errorf("failed to create service account token: %w", err)
	}

	return nil
}

// GetActiveTokenByHash retrieves an active token by its hash
func (r *ServiceAccountRepository) GetActiveTokenByHash(ctx context.Context, tokenHash string) (*models.ServiceAccountToken, error) {
	query := `
		SELECT id, service_account_id, token_hash, ip_address, created_at, expires_at, revoked_at
		FROM iam_service_account_tokens
		WHERE token_hash = $1 AND revoked_at IS NULL AND expires_at > NOW()
	`

	var token models.ServiceAccountToken
	err := r.pool.QueryRow(ctx, query, tokenHash).Scan(
		&token.ID, &token.ServiceAccountID, &token.TokenHash,
		&token.IPAddress, &token.CreatedAt, &token.ExpiresAt, &token.RevokedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get service account token: %w", err)
	}

	return &token, nil
}

// RevokeToken revokes a service account token
func (r *ServiceAccountRepository) RevokeToken(ctx context.Context, tokenID uuid.UUID) error {
	query := `UPDATE iam_service_account_tokens SET revoked_at = NOW() WHERE id = $1`

	_, err := r.pool.Exec(ctx, query, tokenID)
	if err != nil {
		return fmt.Errorf("failed to revoke service account token: %w", err)
	}

	return nil
}

// RevokeAllTokens revokes all tokens for a service account
func (r *ServiceAccountRepository) RevokeAllTokens(ctx context.Context, serviceAccountID uuid.UUID) error {
	query := `
		UPDATE iam_service_account_tokens
		SET revoked_at = NOW()
		WHERE service_account_id = $1 AND revoked_at IS NULL
	`

	_, err := r.pool.Exec(ctx, query, serviceAccountID)
	if err != nil {
		return fmt.Errorf("failed to revoke service account tokens: %w", err)
	}

	return nil
}

// CleanupExpiredTokens removes expired tokens older than 7 days
func (r *ServiceAccountRepository) CleanupExpiredTokens(ctx context.Context) (int64, error) {
	query := `DELETE FROM iam_service_account_tokens WHERE expires_at < NOW() - INTERVAL '7 days'`

	result, err := r.pool.Exec(ctx, query)
	if err != nil {
		return 0, fmt.Errorf("failed to cleanup expired service account tokens: %w", err)
	}

	return result.RowsAffected(), nil
}
