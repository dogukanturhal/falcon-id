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

// tenantAPIKeyColumns is the select list for tenant (lgk_live_) keys. The
// legacy hxk_ queries in api_key_repository.go keep their own narrower list.
const tenantAPIKeyColumns = `id, tenant_id, user_id, name, description, key_prefix, key_hash,
	COALESCE(scopes, '{}'), COALESCE(ip_whitelist, '{}'), COALESCE(usage_count, 0),
	is_active, last_used_at, last_used_ip, created_at, expires_at, revoked_at, created_by,
	kind, key_id, hash_alg, access, role_ids, company_ids,
	prev_hash, prev_valid_until, rotated_at,
	company_sync_state, company_sync_attempts, company_sync_next_at`

func scanTenantAPIKey(row pgx.Row) (*models.APIKey, error) {
	var key models.APIKey
	err := row.Scan(
		&key.ID, &key.TenantID, &key.UserID, &key.Name, &key.Description,
		&key.KeyPrefix, &key.KeyHash, &key.Scopes, &key.IPWhitelist, &key.UsageCount,
		&key.IsActive, &key.LastUsedAt, &key.LastUsedIP, &key.CreatedAt, &key.ExpiresAt,
		&key.RevokedAt, &key.CreatedBy,
		&key.Kind, &key.KeyID, &key.HashAlg, &key.Access, &key.RoleIDs, &key.CompanyIDs,
		&key.PrevHash, &key.PrevValidUntil, &key.RotatedAt,
		&key.CompanySyncState, &key.CompanySyncAttempt, &key.CompanySyncNextAt,
	)
	if err != nil {
		return nil, err
	}
	key.Environment = "production"
	return &key, nil
}

func collectTenantAPIKeys(rows pgx.Rows, what string) ([]*models.APIKey, error) {
	var keys []*models.APIKey
	for rows.Next() {
		key, err := scanTenantAPIKey(rows)
		if err != nil {
			return nil, fmt.Errorf("failed to scan %s: %w", what, err)
		}
		keys = append(keys, key)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("%s: rows iteration: %w", what, err)
	}
	return keys, nil
}

// GetByKeyID looks a tenant key up by its public key_id (the lookup half of
// lgk_live_<key_id>_<secret>). Like GetByPrefix it does NOT filter on state:
// the caller decides, so revoked/expired replays stay distinguishable.
func (r *APIKeyRepository) GetByKeyID(ctx context.Context, keyID string) (*models.APIKey, error) {
	row := r.pool.QueryRow(ctx,
		`SELECT `+tenantAPIKeyColumns+` FROM iam_api_keys WHERE key_id = $1 AND kind = 'tenant'`, keyID)
	key, err := scanTenantAPIKey(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get API key by key_id: %w", err)
	}
	return key, nil
}

// GetTenantKey returns a tenant key by row id, scoped to its tenant.
func (r *APIKeyRepository) GetTenantKey(ctx context.Context, tenantID, id uuid.UUID) (*models.APIKey, error) {
	row := r.pool.QueryRow(ctx,
		`SELECT `+tenantAPIKeyColumns+` FROM iam_api_keys WHERE id = $1 AND tenant_id = $2 AND kind = 'tenant'`, id, tenantID)
	key, err := scanTenantAPIKey(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get tenant API key: %w", err)
	}
	return key, nil
}

// ListTenantKeys lists a tenant's keys, newest first (capped at 100).
func (r *APIKeyRepository) ListTenantKeys(ctx context.Context, tenantID uuid.UUID) ([]*models.APIKey, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT `+tenantAPIKeyColumns+` FROM iam_api_keys
		 WHERE tenant_id = $1 AND kind = 'tenant' ORDER BY created_at DESC LIMIT 100`, tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to list tenant API keys: %w", err)
	}
	defer rows.Close()
	return collectTenantAPIKeys(rows, "tenant API key")
}

// ActiveCountByTenant counts a tenant's active, unrevoked, unexpired keys
// (backed by idx_iam_api_keys_tenant_kind_active).
func (r *APIKeyRepository) ActiveCountByTenant(ctx context.Context, tenantID uuid.UUID) (int, error) {
	var n int
	err := r.pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM iam_api_keys
		WHERE tenant_id = $1 AND kind = 'tenant' AND is_active = TRUE AND revoked_at IS NULL
		  AND (expires_at IS NULL OR expires_at > NOW())`, tenantID).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("failed to count active API keys: %w", err)
	}
	return n, nil
}

// CreateTenantKey inserts a tenant key. key_prefix mirrors key_id so the
// legacy unique index on key_prefix keeps holding.
func (r *APIKeyRepository) CreateTenantKey(ctx context.Context, key *models.APIKey) error {
	err := r.pool.QueryRow(ctx, `
		INSERT INTO iam_api_keys (
			tenant_id, user_id, name, description, key_prefix, key_hash, scopes,
			ip_whitelist, environment, is_active, expires_at, created_by,
			kind, key_id, hash_alg, access, role_ids, company_ids,
			company_sync_state, company_sync_attempts, company_sync_next_at
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,'production',TRUE,$9,$10,
			'tenant',$11,$12,$13,$14,$15,$16,0,$17)
		RETURNING id, created_at`,
		key.TenantID, key.UserID, key.Name, key.Description, key.KeyPrefix, key.KeyHash, key.Scopes,
		key.IPWhitelist, key.ExpiresAt, key.CreatedBy,
		key.KeyID, key.HashAlg, key.Access, nonNilUUIDs(key.RoleIDs), nonNilUUIDs(key.CompanyIDs),
		key.CompanySyncState, key.CompanySyncNextAt,
	).Scan(&key.ID, &key.CreatedAt)
	if err != nil {
		return fmt.Errorf("failed to create tenant API key: %w", err)
	}
	return nil
}

// RotateSecret swaps in a new secret hash and keeps the old one valid until
// prevValidUntil (zero time = no grace). hashAlg is the pepper-versioned
// algorithm tag the new hash was made with; the previous hash is verified
// against every configured pepper while its grace window is open.
func (r *APIKeyRepository) RotateSecret(ctx context.Context, id uuid.UUID, newHash, hashAlg string, prevValidUntil time.Time) error {
	var until *time.Time
	if !prevValidUntil.IsZero() {
		until = &prevValidUntil
	}
	tag, err := r.pool.Exec(ctx, `
		UPDATE iam_api_keys
		SET prev_hash = CASE WHEN $3::timestamptz IS NULL THEN NULL ELSE key_hash END,
		    prev_valid_until = $3, key_hash = $2, hash_alg = $4, rotated_at = NOW()
		WHERE id = $1 AND kind = 'tenant'`, id, newHash, until, hashAlg)
	if err != nil {
		return fmt.Errorf("failed to rotate API key: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return errors.New(msgAPIKeyNotFound)
	}
	return nil
}

// RevokeTenantKey revokes a key and drops any rotation-grace secret with it.
// In the same statement it queues the removal of the key's business company
// edges (pending_remove), so a revoked key can never be left without that
// outbox entry, whatever the state it was in (including an in-flight add).
func (r *APIKeyRepository) RevokeTenantKey(ctx context.Context, id uuid.UUID) error {
	tag, err := r.pool.Exec(ctx, `
		UPDATE iam_api_keys
		SET revoked_at = NOW(), is_active = FALSE, prev_hash = NULL, prev_valid_until = NULL,
		    company_sync_state = CASE WHEN cardinality(company_ids) > 0 THEN 'pending_remove' ELSE company_sync_state END,
		    company_sync_attempts = CASE WHEN cardinality(company_ids) > 0 THEN 0 ELSE company_sync_attempts END,
		    company_sync_next_at = CASE WHEN cardinality(company_ids) > 0 THEN NOW() ELSE company_sync_next_at END
		WHERE id = $1 AND kind = 'tenant'`, id)
	if err != nil {
		return fmt.Errorf("failed revoke tenant API key: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return errors.New(msgAPIKeyNotFound)
	}
	return nil
}

// DeleteTenantKey permanently removes a revoked key whose company edges are
// gone (company_sync_state = synced). Anything else matches no row.
func (r *APIKeyRepository) DeleteTenantKey(ctx context.Context, tenantID, id uuid.UUID) error {
	tag, err := r.pool.Exec(ctx,
		`DELETE FROM iam_api_keys
		 WHERE id = $1 AND tenant_id = $2 AND kind = 'tenant'
		   AND revoked_at IS NOT NULL AND company_sync_state = 'synced'`, id, tenantID)
	if err != nil {
		return fmt.Errorf("failed delete tenant API key: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return errors.New(msgAPIKeyNotFound)
	}
	return nil
}

// HardDeleteTenantKey removes the row regardless of revoke or sync state. It is
// only for Create's cap-race back-out, where no edges were ever written.
func (r *APIKeyRepository) HardDeleteTenantKey(ctx context.Context, tenantID, id uuid.UUID) error {
	tag, err := r.pool.Exec(ctx,
		`DELETE FROM iam_api_keys WHERE id = $1 AND tenant_id = $2 AND kind = 'tenant'`, id, tenantID)
	if err != nil {
		return fmt.Errorf("failed hard delete tenant API key: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return errors.New(msgAPIKeyNotFound)
	}
	return nil
}

// SetCompanySync records company-edge outbox state as a compare-and-set: the
// row is only updated while company_sync_state still equals expectedState, so a
// worker that raced a revoke (or another replica) cannot overwrite the newer
// state. It reports whether a row was updated.
func (r *APIKeyRepository) SetCompanySync(ctx context.Context, id uuid.UUID, expectedState, state string, attempts int, nextAt *time.Time) (bool, error) {
	tag, err := r.pool.Exec(ctx, `
		UPDATE iam_api_keys
		SET company_sync_state = $3, company_sync_attempts = $4, company_sync_next_at = $5
		WHERE id = $1 AND kind = 'tenant' AND company_sync_state = $2`,
		id, expectedState, state, attempts, nextAt)
	if err != nil {
		return false, fmt.Errorf("failed set company sync state: %w", err)
	}
	return tag.RowsAffected() > 0, nil
}

// companySyncLease is how long a claimed pending key is hidden from other
// replicas. A processor that finishes (or fails) rewrites company_sync_next_at
// well before this; a crashed one is retried after it.
const companySyncLease = 2 * time.Minute

// ListPendingCompanySync claims keys whose business company edges still need
// an add/remove call and are due. The claim is a single statement: rows are
// picked with FOR UPDATE SKIP LOCKED and pushed out by the lease, so replicas
// running the worker concurrently never process the same key.
func (r *APIKeyRepository) ListPendingCompanySync(ctx context.Context, limit int) ([]*models.APIKey, error) {
	rows, err := r.pool.Query(ctx, `
		UPDATE iam_api_keys
		SET company_sync_next_at = NOW() + make_interval(secs => $2)
		WHERE id IN (
			SELECT id FROM iam_api_keys
			WHERE kind = 'tenant' AND company_sync_state IN ('pending_add', 'pending_remove')
			  AND (company_sync_next_at IS NULL OR company_sync_next_at <= NOW())
			ORDER BY company_sync_next_at NULLS FIRST
			LIMIT $1
			FOR UPDATE SKIP LOCKED)
		RETURNING `+tenantAPIKeyColumns, limit, companySyncLease.Seconds())
	if err != nil {
		return nil, fmt.Errorf("failed to claim pending company sync: %w", err)
	}
	defer rows.Close()
	return collectTenantAPIKeys(rows, "pending company sync key")
}

// ListActiveTenantKeysByTenant returns a tenant's active, unexpired tenant
// keys for the SpiceDB reconciler.
func (r *APIKeyRepository) ListActiveTenantKeysByTenant(ctx context.Context, tenantID uuid.UUID) ([]*models.APIKey, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT `+tenantAPIKeyColumns+` FROM iam_api_keys
		WHERE tenant_id = $1 AND kind = 'tenant' AND is_active = TRUE AND revoked_at IS NULL
		  AND (expires_at IS NULL OR expires_at > NOW())`, tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to list active tenant API keys: %w", err)
	}
	defer rows.Close()
	return collectTenantAPIKeys(rows, "active tenant API key")
}

func nonNilUUIDs(in []uuid.UUID) []uuid.UUID {
	if in == nil {
		return []uuid.UUID{}
	}
	return in
}

// CountActiveTenantKeysByRole counts the tenant's active keys whose role_ids
// contain roleID.
func (r *APIKeyRepository) CountActiveTenantKeysByRole(ctx context.Context, tenantID, roleID uuid.UUID) (int, error) {
	var n int
	err := r.pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM iam_api_keys
		WHERE tenant_id = $1 AND kind = 'tenant' AND is_active = TRUE AND revoked_at IS NULL
		  AND (expires_at IS NULL OR expires_at > NOW())
		  AND $2 = ANY(role_ids)`, tenantID, roleID).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("failed count API keys by role: %w", err)
	}
	return n, nil
}
