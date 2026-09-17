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

// WorkloadIdentityRepository handles persistence for workload_identity_providers.
type WorkloadIdentityRepository struct {
	pool DBPool
}

// NewWorkloadIdentityRepository creates a WorkloadIdentityRepository.
func NewWorkloadIdentityRepository(pool DBPool) *WorkloadIdentityRepository {
	return &WorkloadIdentityRepository{pool: pool}
}

// Create persists a new WorkloadIdentityProvider, populating its ID and timestamps.
func (r *WorkloadIdentityRepository) Create(ctx context.Context, p *models.WorkloadIdentityProvider) error {
	now := time.Now().UTC()
	p.ID = uuid.New()
	p.CreatedAt = now
	p.UpdatedAt = now

	const query = `
		INSERT INTO workload_identity_providers (
			id, tenant_id, name, provider_type, issuer_url,
			audience_match, subject_mapping, jwks_endpoint,
			allowed_subjects, role_bindings, is_active,
			created_at, updated_at, created_by, updated_by
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)`

	_, err := r.pool.Exec(ctx, query,
		p.ID, p.TenantID, p.Name, string(p.ProviderType), p.IssuerURL,
		p.AudienceMatch, p.SubjectMapping, p.JWKSEndpoint,
		p.AllowedSubjects, p.RoleBindings, p.IsActive,
		p.CreatedAt, p.UpdatedAt, p.CreatedBy, p.UpdatedBy,
	)
	if err != nil {
		return fmt.Errorf("workload_identity_repository.Create: %w", err)
	}
	return nil
}

// GetByID returns a provider by its primary key.
func (r *WorkloadIdentityRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.WorkloadIdentityProvider, error) {
	const query = `
		SELECT
			id, tenant_id, name, provider_type, issuer_url,
			audience_match, subject_mapping, jwks_endpoint,
			allowed_subjects, role_bindings, is_active,
			created_at, updated_at, created_by, updated_by
		FROM workload_identity_providers
		WHERE id = $1`

	row := r.pool.QueryRow(ctx, query, id)
	p, err := scanWorkloadProvider(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("workload_identity_repository.GetByID: %w", err)
	}
	return p, nil
}

// GetByIssuer returns the provider matching the given tenant and
// issuer URL, regardless of whether the provider is currently active.
//
// The query intentionally does NOT filter on `is_active`. The caller
// (TokenExchangeService.Exchange) inspects `provider.IsActive` and
// decides — pre-2026-05-21 the repo applied the filter directly,
// collapsing "deactivated provider replay" with "unknown issuer" and
// losing the SOC's pivot signal for an attacker replaying a JWT
// signed by a recently-rotated workload-identity provider. See
// docs/audits/2026-05-21-repo-state-filter-audit.md.
func (r *WorkloadIdentityRepository) GetByIssuer(ctx context.Context, tenantID uuid.UUID, issuerURL string) (*models.WorkloadIdentityProvider, error) {
	const query = `
		SELECT
			id, tenant_id, name, provider_type, issuer_url,
			audience_match, subject_mapping, jwks_endpoint,
			allowed_subjects, role_bindings, is_active,
			created_at, updated_at, created_by, updated_by
		FROM workload_identity_providers
		WHERE tenant_id = $1
		  AND issuer_url = $2
		LIMIT 1`

	row := r.pool.QueryRow(ctx, query, tenantID, issuerURL)
	p, err := scanWorkloadProvider(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("workload_identity_repository.GetByIssuer: %w", err)
	}
	return p, nil
}

// List returns all providers for a tenant with optional pagination.
func (r *WorkloadIdentityRepository) List(ctx context.Context, tenantID uuid.UUID, page, pageSize int) ([]*models.WorkloadIdentityProvider, int64, error) {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 {
		pageSize = 20
	}
	offset := (page - 1) * pageSize

	const countQuery = `SELECT COUNT(*) FROM workload_identity_providers WHERE tenant_id = $1`
	var total int64
	if err := r.pool.QueryRow(ctx, countQuery, tenantID).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("workload_identity_repository.List count: %w", err)
	}

	const listQuery = `
		SELECT
			id, tenant_id, name, provider_type, issuer_url,
			audience_match, subject_mapping, jwks_endpoint,
			allowed_subjects, role_bindings, is_active,
			created_at, updated_at, created_by, updated_by
		FROM workload_identity_providers
		WHERE tenant_id = $1
		ORDER BY created_at DESC
		LIMIT $2 OFFSET $3`

	rows, err := r.pool.Query(ctx, listQuery, tenantID, pageSize, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("workload_identity_repository.List query: %w", err)
	}
	defer rows.Close()

	var providers []*models.WorkloadIdentityProvider
	for rows.Next() {
		p, err := scanWorkloadProviderFromRows(rows)
		if err != nil {
			return nil, 0, fmt.Errorf("workload_identity_repository.List scan: %w", err)
		}
		providers = append(providers, p)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("workload_identity_repository.List rows: %w", err)
	}

	return providers, total, nil
}

// Update applies a full replacement of the mutable fields for the given provider.
func (r *WorkloadIdentityRepository) Update(ctx context.Context, p *models.WorkloadIdentityProvider) error {
	p.UpdatedAt = time.Now().UTC()

	const query = `
		UPDATE workload_identity_providers SET
			name             = $2,
			provider_type    = $3,
			issuer_url       = $4,
			audience_match   = $5,
			subject_mapping  = $6,
			jwks_endpoint    = $7,
			allowed_subjects = $8,
			role_bindings    = $9,
			is_active        = $10,
			updated_at       = $11,
			updated_by       = $12
		WHERE id = $1`

	tag, err := r.pool.Exec(ctx, query,
		p.ID, p.Name, string(p.ProviderType), p.IssuerURL,
		p.AudienceMatch, p.SubjectMapping, p.JWKSEndpoint,
		p.AllowedSubjects, p.RoleBindings, p.IsActive,
		p.UpdatedAt, p.UpdatedBy,
	)
	if err != nil {
		return fmt.Errorf("workload_identity_repository.Update: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("workload_identity_repository.Update: provider not found")
	}
	return nil
}

// Delete removes a provider by ID.
func (r *WorkloadIdentityRepository) Delete(ctx context.Context, id uuid.UUID) error {
	const query = `DELETE FROM workload_identity_providers WHERE id = $1`
	_, err := r.pool.Exec(ctx, query, id)
	if err != nil {
		return fmt.Errorf("workload_identity_repository.Delete: %w", err)
	}
	return nil
}

// ============================================================
// Helpers
// ============================================================

func scanWorkloadProvider(row pgx.Row) (*models.WorkloadIdentityProvider, error) {
	var p models.WorkloadIdentityProvider
	var typeStr string
	err := row.Scan(
		&p.ID, &p.TenantID, &p.Name, &typeStr, &p.IssuerURL,
		&p.AudienceMatch, &p.SubjectMapping, &p.JWKSEndpoint,
		&p.AllowedSubjects, &p.RoleBindings, &p.IsActive,
		&p.CreatedAt, &p.UpdatedAt, &p.CreatedBy, &p.UpdatedBy,
	)
	if err != nil {
		return nil, err
	}
	p.ProviderType = models.WorkloadProviderType(typeStr)
	return &p, nil
}

func scanWorkloadProviderFromRows(rows pgx.Rows) (*models.WorkloadIdentityProvider, error) {
	var p models.WorkloadIdentityProvider
	var typeStr string
	err := rows.Scan(
		&p.ID, &p.TenantID, &p.Name, &typeStr, &p.IssuerURL,
		&p.AudienceMatch, &p.SubjectMapping, &p.JWKSEndpoint,
		&p.AllowedSubjects, &p.RoleBindings, &p.IsActive,
		&p.CreatedAt, &p.UpdatedAt, &p.CreatedBy, &p.UpdatedBy,
	)
	if err != nil {
		return nil, err
	}
	p.ProviderType = models.WorkloadProviderType(typeStr)
	return &p, nil
}
