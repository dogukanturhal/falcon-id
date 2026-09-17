// SPDX-License-Identifier: AGPL-3.0-or-later

package repositories

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

// TenantDomainRepository handles persistence for the tenant_domains table.
// These records power identifier-first realm discovery (HRD): given an email
// domain the service determines which tenant owns it and what discovery policy
// (managed, federated, or consumer_pool) applies.
type TenantDomainRepository struct {
	db DBPool
}

// NewTenantDomainRepository creates a new TenantDomainRepository.
func NewTenantDomainRepository(db DBPool) *TenantDomainRepository {
	return &TenantDomainRepository{db: db}
}

const tenantDomainColumns = `id, domain, tenant_id, verified, verification_token, verification_method, discovery_policy, federated_idp_url, federated_idp_type, created_at, updated_at`

// scanTenantDomain scans a pgx.Row into a TenantDomain value.
func scanTenantDomain(row pgx.Row) (*models.TenantDomain, error) {
	td := &models.TenantDomain{}
	err := row.Scan(
		&td.ID,
		&td.Domain,
		&td.TenantID,
		&td.Verified,
		&td.VerificationToken,
		&td.VerificationMethod,
		&td.DiscoveryPolicy,
		&td.FederatedIdpURL,
		&td.FederatedIdpType,
		&td.CreatedAt,
		&td.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	return td, nil
}

// FindByDomain looks up a verified domain record by exact domain name.
// Returns (nil, nil) when no verified record exists for the given domain.
func (r *TenantDomainRepository) FindByDomain(ctx context.Context, domain string) (*models.TenantDomain, error) {
	query := fmt.Sprintf(
		`SELECT %s FROM tenant_domains WHERE domain = $1 AND verified = true`,
		tenantDomainColumns,
	)
	td, err := scanTenantDomain(r.db.QueryRow(ctx, query, domain))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("FindByDomain: %w", err)
	}
	return td, nil
}
