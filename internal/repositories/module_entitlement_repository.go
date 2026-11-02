// SPDX-License-Identifier: AGPL-3.0-or-later

package repositories

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

// ModuleEntitlementRepository persists iam_tenant_module_entitlements and
// iam_tenant_entitlement_flags (migration
// 0014_iam_tenant_module_entitlements.sql). It is the single place that
// enforces the monotonic event_version guard: an incoming snapshot whose
// event_version is <= the row's stored event_version is a stale/duplicate
// redelivery and is silently ignored (not an error) by the UPSERT's WHERE
// clause, so both the Kafka consumer (internal/entitlementsync) and the
// internal PUT handler can call the same UpsertModule/UpsertFlags method
// without either needing to re-implement ordering logic.
type ModuleEntitlementRepository struct {
	db *pgxpool.Pool
}

// NewModuleEntitlementRepository creates a new repository instance.
func NewModuleEntitlementRepository(db *pgxpool.Pool) *ModuleEntitlementRepository {
	return &ModuleEntitlementRepository{db: db}
}

// UpsertModule idempotently inserts or updates a single tenant+module
// entitlement row. Returns applied=false (no error) when an equal-or-newer
// event_version already exists for this (tenant_id, module_code) -- this
// is the expected, non-exceptional outcome for a redelivered or
// out-of-order Kafka message, never treated as a failure by callers.
func (r *ModuleEntitlementRepository) UpsertModule(ctx context.Context, e *models.ModuleEntitlement) (applied bool, err error) {
	query := `
		INSERT INTO iam_tenant_module_entitlements (
			tenant_id, module_code, status, seats, expires_at,
			ever_trialed, ever_subscribed, event_version, source_updated_at, source, tier_code, read_only
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
		ON CONFLICT (tenant_id, module_code) DO UPDATE SET
			status             = EXCLUDED.status,
			seats              = EXCLUDED.seats,
			expires_at         = EXCLUDED.expires_at,
			ever_trialed       = EXCLUDED.ever_trialed,
			ever_subscribed    = EXCLUDED.ever_subscribed,
			event_version      = EXCLUDED.event_version,
			source_updated_at  = EXCLUDED.source_updated_at,
			source             = EXCLUDED.source,
			tier_code          = EXCLUDED.tier_code,
			read_only          = EXCLUDED.read_only,
			updated_at         = NOW()
		WHERE iam_tenant_module_entitlements.event_version < EXCLUDED.event_version
	`
	tag, err := r.db.Exec(ctx, query,
		e.TenantID, e.ModuleCode, e.Status, e.Seats, e.ExpiresAt,
		e.EverTrialed, e.EverSubscribed, e.EventVersion, e.SourceUpdatedAt,
		e.Source, e.TierCode, e.ReadOnly,
	)
	if err != nil {
		return false, fmt.Errorf("ModuleEntitlementRepository.UpsertModule: %w", err)
	}
	// RowsAffected() is 0 both when the WHERE guard rejected a stale
	// version on conflict AND (extremely unlikely, but possible under
	// concurrent identical inserts) a race on the initial INSERT; either
	// way, "not applied" is the correct signal to the caller -- it must
	// never be treated as a hard error, only logged at debug/info level.
	return tag.RowsAffected() > 0, nil
}

// UpsertFlags idempotently inserts or updates the tenant-wide flags row,
// with the same monotonic event_version guard as UpsertModule.
func (r *ModuleEntitlementRepository) UpsertFlags(ctx context.Context, f *models.TenantEntitlementFlags) (applied bool, err error) {
	// A nil map is "not part of this snapshot" -> SQL NULL -> the stored
	// value is kept on update and '{}' on first insert (migration 0020).
	var flagsJSON, limitsJSON []byte
	if f.Flags != nil {
		if flagsJSON, err = json.Marshal(f.Flags); err != nil {
			return false, fmt.Errorf("ModuleEntitlementRepository.UpsertFlags marshal: %w", err)
		}
	}
	if f.Limits != nil {
		if limitsJSON, err = json.Marshal(f.Limits); err != nil {
			return false, fmt.Errorf("ModuleEntitlementRepository.UpsertFlags marshal limits: %w", err)
		}
	}

	query := `
		INSERT INTO iam_tenant_entitlement_flags (
			tenant_id, flags, limits, event_version, source_updated_at
		) VALUES ($1, COALESCE($2::jsonb, '{}'::jsonb), COALESCE($3::jsonb, '{}'::jsonb), $4, $5)
		ON CONFLICT (tenant_id) DO UPDATE SET
			flags              = COALESCE($2::jsonb, iam_tenant_entitlement_flags.flags),
			limits             = COALESCE($3::jsonb, iam_tenant_entitlement_flags.limits),
			event_version      = EXCLUDED.event_version,
			source_updated_at  = EXCLUDED.source_updated_at,
			updated_at         = NOW()
		WHERE iam_tenant_entitlement_flags.event_version < EXCLUDED.event_version
	`
	tag, err := r.db.Exec(ctx, query, f.TenantID, nullableJSONDoc(flagsJSON), nullableJSONDoc(limitsJSON), f.EventVersion, f.SourceUpdatedAt)
	if err != nil {
		return false, fmt.Errorf("ModuleEntitlementRepository.UpsertFlags: %w", err)
	}
	return tag.RowsAffected() > 0, nil
}

// nullableJSONDoc maps an absent (nil) JSON document to SQL NULL.
func nullableJSONDoc(b []byte) any {
	if b == nil {
		return nil
	}
	return string(b)
}

// GetByTenant returns every module entitlement row for a tenant. An empty
// (nil) slice with a nil error means the tenant has no entitlement rows at
// all -- callers MUST treat that as "no modules", never as "fetch failed,
// try LKG/fail-closed elsewhere"; the LKG/fail-closed decision belongs to
// the caching layer in services.TenantEntitlementService, not here.
func (r *ModuleEntitlementRepository) GetByTenant(ctx context.Context, tenantID uuid.UUID) ([]models.ModuleEntitlement, error) {
	query := `
		SELECT id, tenant_id, module_code, status, seats, expires_at,
		       ever_trialed, ever_subscribed, event_version, source_updated_at,
		       created_at, updated_at, source, tier_code, read_only
		FROM iam_tenant_module_entitlements
		WHERE tenant_id = $1
		ORDER BY module_code
	`
	rows, err := r.db.Query(ctx, query, tenantID)
	if err != nil {
		return nil, fmt.Errorf("ModuleEntitlementRepository.GetByTenant: %w", err)
	}
	defer rows.Close()

	var out []models.ModuleEntitlement
	for rows.Next() {
		var e models.ModuleEntitlement
		if err := rows.Scan(
			&e.ID, &e.TenantID, &e.ModuleCode, &e.Status, &e.Seats, &e.ExpiresAt,
			&e.EverTrialed, &e.EverSubscribed, &e.EventVersion, &e.SourceUpdatedAt,
			&e.CreatedAt, &e.UpdatedAt,
			&e.Source, &e.TierCode, &e.ReadOnly,
		); err != nil {
			return nil, fmt.Errorf("ModuleEntitlementRepository.GetByTenant scan: %w", err)
		}
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("ModuleEntitlementRepository.GetByTenant rows: %w", err)
	}
	return out, nil
}

// GetFlags returns the tenant-wide flags row, or (nil, nil) if the tenant
// has no flags row yet -- callers must treat that as "no flags" (empty
// object), not as an error.
func (r *ModuleEntitlementRepository) GetFlags(ctx context.Context, tenantID uuid.UUID) (*models.TenantEntitlementFlags, error) {
	query := `
		SELECT tenant_id, flags, limits, event_version, source_updated_at
		FROM iam_tenant_entitlement_flags
		WHERE tenant_id = $1
	`
	var f models.TenantEntitlementFlags
	var flagsJSON, limitsJSON []byte
	err := r.db.QueryRow(ctx, query, tenantID).Scan(&f.TenantID, &flagsJSON, &limitsJSON, &f.EventVersion, &f.SourceUpdatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("ModuleEntitlementRepository.GetFlags: %w", err)
	}
	if len(flagsJSON) > 0 {
		if err := json.Unmarshal(flagsJSON, &f.Flags); err != nil {
			return nil, fmt.Errorf("ModuleEntitlementRepository.GetFlags unmarshal: %w", err)
		}
	}
	if len(limitsJSON) > 0 {
		if err := json.Unmarshal(limitsJSON, &f.Limits); err != nil {
			return nil, fmt.Errorf("ModuleEntitlementRepository.GetFlags unmarshal limits: %w", err)
		}
	}
	return &f, nil
}

// TenantModuleGrant is one (tenant, module_code) pair whose entitlement
// currently grants access.
type TenantModuleGrant struct {
	TenantID   uuid.UUID
	ModuleCode string
}

// ListGrantingTenantModules returns every (tenant, module_code) whose stored
// status grants access (active, trialing, grace). Used by the module-access
// reconcile to find tenants that need role materialization.
func (r *ModuleEntitlementRepository) ListGrantingTenantModules(ctx context.Context) ([]TenantModuleGrant, error) {
	query := `
		SELECT tenant_id, module_code
		FROM iam_tenant_module_entitlements
		WHERE status IN ('active', 'trialing', 'grace')
		ORDER BY tenant_id, module_code`
	rows, err := r.db.Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("ModuleEntitlementRepository.ListGrantingTenantModules: %w", err)
	}
	defer rows.Close()

	var out []TenantModuleGrant
	for rows.Next() {
		var g TenantModuleGrant
		if err := rows.Scan(&g.TenantID, &g.ModuleCode); err != nil {
			return nil, fmt.Errorf("ModuleEntitlementRepository.ListGrantingTenantModules scan: %w", err)
		}
		out = append(out, g)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("ModuleEntitlementRepository.ListGrantingTenantModules rows: %w", err)
	}
	return out, nil
}
