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

// EmailDomainRegistryRepository handles persistence for email domain → tenant mappings.
// These mappings power Home Realm Discovery (HRD): given an email address the service
// can determine which tenant owns the domain and route authentication accordingly.
type EmailDomainRegistryRepository struct {
	db DBPool
}

// NewEmailDomainRegistryRepository creates a new EmailDomainRegistryRepository.
func NewEmailDomainRegistryRepository(db DBPool) *EmailDomainRegistryRepository {
	return &EmailDomainRegistryRepository{db: db}
}

// emailDomainColumns is the canonical column list for all SELECT queries.
const emailDomainColumns = `id, tenant_id, domain, is_verified, verification_token, verification_method, verified_at, auto_enroll, created_at, updated_at`

// scanEmailDomain scans a pgx.Row into an EmailDomainRegistry value.
func scanEmailDomain(row pgx.Row) (*models.EmailDomainRegistry, error) {
	e := &models.EmailDomainRegistry{}
	err := row.Scan(
		&e.ID, &e.TenantID, &e.Domain, &e.IsVerified,
		&e.VerificationToken, &e.VerificationMethod, &e.VerifiedAt,
		&e.AutoEnroll, &e.CreatedAt, &e.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	return e, nil
}

// scanEmailDomainRows scans a pgx.Rows cursor into a slice.
func scanEmailDomainRows(rows pgx.Rows) ([]*models.EmailDomainRegistry, error) {
	var entries []*models.EmailDomainRegistry
	for rows.Next() {
		e := &models.EmailDomainRegistry{}
		if err := rows.Scan(
			&e.ID, &e.TenantID, &e.Domain, &e.IsVerified,
			&e.VerificationToken, &e.VerificationMethod, &e.VerifiedAt,
			&e.AutoEnroll, &e.CreatedAt, &e.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("scanEmailDomainRows: %w", err)
		}
		entries = append(entries, e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("scanEmailDomainRows iteration: %w", err)
	}
	return entries, nil
}

// GetVerifiedByDomain looks up a verified domain mapping.
// Returns (nil, nil) when no verified record exists for the given domain.
func (r *EmailDomainRegistryRepository) GetVerifiedByDomain(ctx context.Context, domain string) (*models.EmailDomainRegistry, error) {
	query := fmt.Sprintf(
		`SELECT %s FROM iam_email_domain_registry WHERE domain = $1 AND is_verified = true`,
		emailDomainColumns,
	)
	entry, err := scanEmailDomain(r.db.QueryRow(ctx, query, domain))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("GetVerifiedByDomain: %w", err)
	}
	return entry, nil
}

// GetByID retrieves a specific domain registration by its primary key.
// Returns (nil, nil) when no record with the given ID exists.
func (r *EmailDomainRegistryRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.EmailDomainRegistry, error) {
	query := fmt.Sprintf(
		`SELECT %s FROM iam_email_domain_registry WHERE id = $1`,
		emailDomainColumns,
	)
	entry, err := scanEmailDomain(r.db.QueryRow(ctx, query, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("GetByID: %w", err)
	}
	return entry, nil
}

// ListByTenant returns all domain registrations (verified and unverified) for a tenant,
// ordered alphabetically by domain name.
func (r *EmailDomainRegistryRepository) ListByTenant(ctx context.Context, tenantID uuid.UUID) ([]*models.EmailDomainRegistry, error) {
	query := fmt.Sprintf(
		`SELECT %s FROM iam_email_domain_registry WHERE tenant_id = $1 ORDER BY domain`,
		emailDomainColumns,
	)
	rows, err := r.db.Query(ctx, query, tenantID)
	if err != nil {
		return nil, fmt.Errorf("ListByTenant: %w", err)
	}
	defer rows.Close()

	entries, err := scanEmailDomainRows(rows)
	if err != nil {
		return nil, fmt.Errorf("ListByTenant: %w", err)
	}
	return entries, nil
}

// Create inserts a new domain registration with its verification token.
// A new UUID is assigned when entry.ID is uuid.Nil.
// The entry is populated with the database-generated created_at and updated_at timestamps.
func (r *EmailDomainRegistryRepository) Create(ctx context.Context, entry *models.EmailDomainRegistry) error {
	if entry.ID == uuid.Nil {
		entry.ID = uuid.New()
	}

	query := `
		INSERT INTO iam_email_domain_registry
			(id, tenant_id, domain, verification_token, verification_method, auto_enroll)
		VALUES ($1, $2, $3, $4, $5, $6)
		RETURNING is_verified, verified_at, created_at, updated_at`

	return r.db.QueryRow(ctx, query,
		entry.ID, entry.TenantID, entry.Domain,
		entry.VerificationToken, entry.VerificationMethod, entry.AutoEnroll,
	).Scan(&entry.IsVerified, &entry.VerifiedAt, &entry.CreatedAt, &entry.UpdatedAt)
}

// Verify marks a domain registration as verified and stamps the verified_at timestamp.
func (r *EmailDomainRegistryRepository) Verify(ctx context.Context, id uuid.UUID) error {
	tag, err := r.db.Exec(ctx,
		`UPDATE iam_email_domain_registry
		 SET is_verified = true, verified_at = $2, updated_at = $2
		 WHERE id = $1`,
		id, time.Now().UTC(),
	)
	if err != nil {
		return fmt.Errorf("Verify: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("Verify: domain registration %s not found", id)
	}
	return nil
}

// UpdateAutoEnroll toggles the auto_enroll flag on a domain registration.
func (r *EmailDomainRegistryRepository) UpdateAutoEnroll(ctx context.Context, id uuid.UUID, autoEnroll bool) error {
	tag, err := r.db.Exec(ctx,
		`UPDATE iam_email_domain_registry
		 SET auto_enroll = $2, updated_at = $3
		 WHERE id = $1`,
		id, autoEnroll, time.Now().UTC(),
	)
	if err != nil {
		return fmt.Errorf("UpdateAutoEnroll: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("UpdateAutoEnroll: domain registration %s not found", id)
	}
	return nil
}

// ListUnverified returns all unverified domain registrations across all tenants.
// Used by the domain verification worker to perform periodic DNS TXT checks.
func (r *EmailDomainRegistryRepository) ListUnverified(ctx context.Context) ([]*models.EmailDomainRegistry, error) {
	query := fmt.Sprintf(
		`SELECT %s FROM iam_email_domain_registry WHERE is_verified = false ORDER BY created_at`,
		emailDomainColumns,
	)
	rows, err := r.db.Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("ListUnverified: %w", err)
	}
	defer rows.Close()

	entries, err := scanEmailDomainRows(rows)
	if err != nil {
		return nil, fmt.Errorf("ListUnverified: %w", err)
	}
	return entries, nil
}

// Delete removes a domain registration by ID.
func (r *EmailDomainRegistryRepository) Delete(ctx context.Context, id uuid.UUID) error {
	_, err := r.db.Exec(ctx,
		`DELETE FROM iam_email_domain_registry WHERE id = $1`,
		id,
	)
	if err != nil {
		return fmt.Errorf("Delete: %w", err)
	}
	return nil
}
