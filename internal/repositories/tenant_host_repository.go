// SPDX-License-Identifier: AGPL-3.0-or-later

package repositories

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

// TenantHostRepository handles persistence for the iam_tenant_hosts
// registry — host→tenant bindings that power custom-domain discovery
// for the multi-tenant SaaS app layer (e.g. crm.acme-corp.com →
// tenant Acme). Sibling of RealmRepository.GetRealmByDomain which
// operates at the IdP-auth-host layer (auth.acme-corp.com); the two
// are deliberately separate tables because their lifecycle, cert
// provisioning, and operator model diverge.
type TenantHostRepository struct {
	db DBPool
}

// NewTenantHostRepository constructs a TenantHostRepository.
func NewTenantHostRepository(db DBPool) *TenantHostRepository {
	return &TenantHostRepository{db: db}
}

// tenantHostColumns is the canonical column list for SELECT.
const tenantHostColumns = `id, host, tenant_id, canonical_url, status, ` +
	`verification_token, verification_method, verified_at, last_verified_at, ` +
	`verification_failures, default_client_id, branding_override, ` +
	`created_at, updated_at`

func scanTenantHost(row pgx.Row) (*models.TenantHost, error) {
	h := &models.TenantHost{}
	var status string
	var method string
	err := row.Scan(
		&h.ID, &h.Host, &h.TenantID, &h.CanonicalURL, &status,
		&h.VerificationToken, &method, &h.VerifiedAt, &h.LastVerifiedAt,
		&h.VerificationFailures, &h.DefaultClientID, &h.BrandingOverride,
		&h.CreatedAt, &h.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	h.Status = models.TenantHostStatus(status)
	h.VerificationMethod = models.TenantHostVerificationMethod(method)
	return h, nil
}

// GetByID looks up a tenant_host row by primary key. Used by admin
// endpoints that operate on a specific host record (verify/suspend/
// delete by ID).
func (r *TenantHostRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.TenantHost, error) {
	query := `SELECT ` + tenantHostColumns + ` FROM iam_tenant_hosts WHERE id = $1`
	row := r.db.QueryRow(ctx, query, id)
	h, err := scanTenantHost(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("GetByID: %w", err)
	}
	return h, nil
}

// GetByHost looks up a tenant_host row by its exact normalized host.
// Callers MUST pass an already-normalized value (lowercase + IDNA-
// encoded) — the service layer owns normalization to keep this method
// pure-storage. Returns (nil, nil) on not-found (no error) to match
// the pattern used by realm_repository_admin.GetRealmByDomain.
func (r *TenantHostRepository) GetByHost(ctx context.Context, host string) (*models.TenantHost, error) {
	query := `SELECT ` + tenantHostColumns + ` FROM iam_tenant_hosts WHERE host = $1`
	row := r.db.QueryRow(ctx, query, host)
	h, err := scanTenantHost(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("GetByHost: %w", err)
	}
	return h, nil
}

// GetByTenantID returns every host registered to a tenant (verified or
// not). Used by tenant-admin UIs to list custom domains. Ordered by
// created_at ASC for deterministic display.
func (r *TenantHostRepository) GetByTenantID(ctx context.Context, tenantID uuid.UUID) ([]*models.TenantHost, error) {
	query := `SELECT ` + tenantHostColumns + ` FROM iam_tenant_hosts ` +
		`WHERE tenant_id = $1 ORDER BY created_at ASC`
	rows, err := r.db.Query(ctx, query, tenantID)
	if err != nil {
		return nil, fmt.Errorf("GetByTenantID: query: %w", err)
	}
	defer rows.Close()

	var out []*models.TenantHost
	for rows.Next() {
		h := &models.TenantHost{}
		var status, method string
		if err := rows.Scan(
			&h.ID, &h.Host, &h.TenantID, &h.CanonicalURL, &status,
			&h.VerificationToken, &method, &h.VerifiedAt, &h.LastVerifiedAt,
			&h.VerificationFailures, &h.DefaultClientID, &h.BrandingOverride,
			&h.CreatedAt, &h.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("GetByTenantID: scan: %w", err)
		}
		h.Status = models.TenantHostStatus(status)
		h.VerificationMethod = models.TenantHostVerificationMethod(method)
		out = append(out, h)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("GetByTenantID: rows: %w", err)
	}
	return out, nil
}

// Create inserts a new tenant_host row. The caller is responsible for
// normalizing host + generating verification_token before this call.
// status defaults to pending_verification at the schema layer; if
// VerifiedAt is set the CHECK constraint allows status=active.
func (r *TenantHostRepository) Create(ctx context.Context, h *models.TenantHost) error {
	query := `INSERT INTO iam_tenant_hosts (
		host, tenant_id, canonical_url, status, verification_token,
		verification_method, default_client_id, branding_override
	) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
	RETURNING id, created_at, updated_at`
	row := r.db.QueryRow(ctx, query,
		h.Host, h.TenantID, h.CanonicalURL, string(h.Status), h.VerificationToken,
		string(h.VerificationMethod), h.DefaultClientID, h.BrandingOverride,
	)
	if err := row.Scan(&h.ID, &h.CreatedAt, &h.UpdatedAt); err != nil {
		return fmt.Errorf("Create: %w", err)
	}
	return nil
}

// MarkVerified transitions a pending host to active, stamping
// verified_at + last_verified_at to NOW() and resetting the failures
// counter. Returns pgx.ErrNoRows-equivalent (nil, nil) if the row was
// not in pending_verification — protects against double-verify races.
func (r *TenantHostRepository) MarkVerified(ctx context.Context, id uuid.UUID) error {
	query := `UPDATE iam_tenant_hosts
		SET status = 'active',
		    verified_at = COALESCE(verified_at, now()),
		    last_verified_at = now(),
		    verification_failures = 0,
		    updated_at = now()
		WHERE id = $1 AND status = 'pending_verification'`
	tag, err := r.db.Exec(ctx, query, id)
	if err != nil {
		return fmt.Errorf("MarkVerified: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("MarkVerified: row %s not in pending_verification", id)
	}
	return nil
}

// RecordVerificationFailure increments the verification_failures
// counter. The cron caller is responsible for transitioning to
// suspended once the count crosses the policy threshold.
func (r *TenantHostRepository) RecordVerificationFailure(ctx context.Context, id uuid.UUID) error {
	query := `UPDATE iam_tenant_hosts
		SET verification_failures = verification_failures + 1,
		    updated_at = now()
		WHERE id = $1`
	_, err := r.db.Exec(ctx, query, id)
	if err != nil {
		return fmt.Errorf("RecordVerificationFailure: %w", err)
	}
	return nil
}

// Suspend transitions a host to status=suspended. Does NOT clear
// verified_at — the CHECK constraint only requires it for active.
// Keeping the timestamp preserves audit history.
func (r *TenantHostRepository) Suspend(ctx context.Context, id uuid.UUID) error {
	query := `UPDATE iam_tenant_hosts
		SET status = 'suspended', updated_at = now()
		WHERE id = $1`
	_, err := r.db.Exec(ctx, query, id)
	if err != nil {
		return fmt.Errorf("Suspend: %w", err)
	}
	return nil
}

// Delete removes a tenant_host row. Hard-delete; the audit log on the
// admin handler captures the operator + reason.
func (r *TenantHostRepository) Delete(ctx context.Context, id uuid.UUID) error {
	_, err := r.db.Exec(ctx, `DELETE FROM iam_tenant_hosts WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("Delete: %w", err)
	}
	return nil
}

// ListForRecheck returns up to `limit` rows whose last_verified_at is
// older than the cron interval and are still in a re-checkable state.
// Used by the daily verification cron. NULL last_verified_at is
// sorted FIRST so pending hosts are picked up on every tick.
func (r *TenantHostRepository) ListForRecheck(ctx context.Context, limit int) ([]*models.TenantHost, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	query := `SELECT ` + tenantHostColumns + ` FROM iam_tenant_hosts
		WHERE status IN ('active','pending_verification')
		ORDER BY last_verified_at ASC NULLS FIRST
		LIMIT $1`
	rows, err := r.db.Query(ctx, query, limit)
	if err != nil {
		return nil, fmt.Errorf("ListForRecheck: %w", err)
	}
	defer rows.Close()
	var out []*models.TenantHost
	for rows.Next() {
		h := &models.TenantHost{}
		var status, method string
		if err := rows.Scan(
			&h.ID, &h.Host, &h.TenantID, &h.CanonicalURL, &status,
			&h.VerificationToken, &method, &h.VerifiedAt, &h.LastVerifiedAt,
			&h.VerificationFailures, &h.DefaultClientID, &h.BrandingOverride,
			&h.CreatedAt, &h.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("ListForRecheck: scan: %w", err)
		}
		h.Status = models.TenantHostStatus(status)
		h.VerificationMethod = models.TenantHostVerificationMethod(method)
		out = append(out, h)
	}
	return out, rows.Err()
}
