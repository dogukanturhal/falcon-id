// SPDX-License-Identifier: AGPL-3.0-or-later

package repositories

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

// TenantRepository handles tenant database operations
type TenantRepository struct {
	db DBPool
}

// NewTenantRepository creates a new tenant repository
func NewTenantRepository(db DBPool) *TenantRepository {
	return &TenantRepository{db: db}
}

// GetByID retrieves a tenant by ID, or (nil, nil) when no row matches.
//
// The (nil, nil) sentinel for ErrNoRows matches the contract every other
// GetByID-style accessor in this package returns (UserRepository,
// RealmRepository, etc.) — callers use the pattern
//
//	existing, err := repos.X.GetByID(ctx, id)
//	if err != nil { ... } // genuine DB error
//	if existing == nil { ... } // row missing, e.g. seed-row path
//
// Wrapping ErrNoRows as a fmt.Errorf would force every caller to
// errors.Is-check pgx.ErrNoRows, breaking the existing convention
// and surfacing as a silent skip in bootstrap functions (caught
// 2026-05-22 — bootstrapConsumerTenant returned early on the
// row-missing path instead of creating the consumer-tenant row).
//
// ADR-0029 (Phase 3): iam_tenants.plan and iam_tenants.type were dropped
// by the GitOps repository !699. Type and Plan fields are populated with
// sentinel defaults here; the authoritative values live in
// tenant-management.tenants (the real SoR post-ADR-0029).
func (r *TenantRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.Tenant, error) {
	query := `
		SELECT id, name, slug, display_name, domain, status,
		       COALESCE(billing_exempt, false) as billing_exempt,
		       settings, metadata, billing_email, stripe_customer_id,
		       max_users, max_storage, trial_ends_at,
		       created_at, updated_at, suspended_at, cancelled_at,
		       COALESCE(timezone, 'UTC') as timezone,
		       default_sender_domain_id
		FROM iam_tenants
		WHERE id = $1
	`

	var tenant models.Tenant
	var settingsJSON, metadataJSON []byte

	err := r.db.QueryRow(ctx, query, id).Scan(
		&tenant.ID,
		&tenant.Name,
		&tenant.Slug,
		&tenant.DisplayName,
		&tenant.Domain,
		&tenant.Status,
		&tenant.BillingExempt,
		&settingsJSON,
		&metadataJSON,
		&tenant.BillingEmail,
		&tenant.StripeCustomerID,
		&tenant.MaxUsers,
		&tenant.MaxStorage,
		&tenant.TrialEndsAt,
		&tenant.CreatedAt,
		&tenant.UpdatedAt,
		&tenant.SuspendedAt,
		&tenant.CancelledAt,
		&tenant.Timezone,
		&tenant.DefaultSenderDomainID,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("GetByID: %w", err)
	}

	// ADR-0029: type and plan are no longer stored in iam_tenants.
	// Set application-layer defaults; the real SoR is tenant-management.
	tenant.Type = models.TenantTypeCustomer
	tenant.Plan = ""

	if settingsJSON != nil {
		_ = json.Unmarshal(settingsJSON, &tenant.Settings)
	}
	if metadataJSON != nil {
		_ = json.Unmarshal(metadataJSON, &tenant.Metadata)
	}

	return &tenant, nil
}

// GetBySlug retrieves a tenant by slug
func (r *TenantRepository) GetBySlug(ctx context.Context, slug string) (*models.Tenant, error) {
	query := `
		SELECT id, name, slug, display_name, domain, status,
		       COALESCE(billing_exempt, false) as billing_exempt,
		       settings, metadata, billing_email, stripe_customer_id,
		       max_users, max_storage, trial_ends_at,
		       created_at, updated_at, suspended_at, cancelled_at,
		       COALESCE(timezone, 'UTC') as timezone,
		       default_sender_domain_id
		FROM iam_tenants
		WHERE slug = $1
	`

	var tenant models.Tenant
	var settingsJSON, metadataJSON []byte

	err := r.db.QueryRow(ctx, query, slug).Scan(
		&tenant.ID,
		&tenant.Name,
		&tenant.Slug,
		&tenant.DisplayName,
		&tenant.Domain,
		&tenant.Status,
		&tenant.BillingExempt,
		&settingsJSON,
		&metadataJSON,
		&tenant.BillingEmail,
		&tenant.StripeCustomerID,
		&tenant.MaxUsers,
		&tenant.MaxStorage,
		&tenant.TrialEndsAt,
		&tenant.CreatedAt,
		&tenant.UpdatedAt,
		&tenant.SuspendedAt,
		&tenant.CancelledAt,
		&tenant.Timezone,
		&tenant.DefaultSenderDomainID,
	)
	if err != nil {
		return nil, fmt.Errorf("GetBySlug: %w", err)
	}

	// ADR-0029: type and plan are no longer stored in iam_tenants.
	tenant.Type = models.TenantTypeCustomer
	tenant.Plan = ""

	if settingsJSON != nil {
		_ = json.Unmarshal(settingsJSON, &tenant.Settings)
	}
	if metadataJSON != nil {
		_ = json.Unmarshal(metadataJSON, &tenant.Metadata)
	}

	return &tenant, nil
}

// Update updates a tenant.
//
// IMPORTANT: this is a write-all-columns UPDATE — every field on the
// inbound struct is written unconditionally. Callers MUST load the
// full row via GetByID first; passing a partial struct will wipe
// other columns. See user_repository.go:Update for the durable
// repository-layer guard and history of this class of bug.
//
// ADR-0029 (Phase 3): type and plan columns were dropped from iam_tenants.
// Those fields are intentionally excluded from the UPDATE.
func (r *TenantRepository) Update(ctx context.Context, tenant *models.Tenant) error {
	settingsJSON, _ := json.Marshal(tenant.Settings)
	metadataJSON, _ := json.Marshal(tenant.Metadata)

	query := `
		UPDATE iam_tenants SET
			display_name = $1,
			domain = $2,
			status = $3,
			billing_exempt = $4,
			settings = $5,
			metadata = $6,
			billing_email = $7,
			max_users = $8,
			max_storage = $9,
			updated_at = NOW()
		WHERE id = $10
	`

	_, err := r.db.Exec(ctx, query,
		tenant.DisplayName,
		tenant.Domain,
		tenant.Status,
		tenant.BillingExempt,
		settingsJSON,
		metadataJSON,
		tenant.BillingEmail,
		tenant.MaxUsers,
		tenant.MaxStorage,
		tenant.ID,
	)
	if err != nil {
		return fmt.Errorf("Update: %w", err)
	}
	return nil
}

// Create creates a new tenant
//
// ADR-0029 (Phase 3): type and plan columns were dropped from iam_tenants.
// Those fields are intentionally excluded from the INSERT.
func (r *TenantRepository) Create(ctx context.Context, tenant *models.Tenant) error {
	settingsJSON, _ := json.Marshal(tenant.Settings)
	metadataJSON, _ := json.Marshal(tenant.Metadata)

	query := `
		INSERT INTO iam_tenants (
			id, name, slug, display_name, domain, status,
			billing_exempt, settings, metadata, billing_email, max_users, max_storage
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
	`

	if tenant.ID == uuid.Nil {
		tenant.ID = uuid.New()
	}

	_, err := r.db.Exec(ctx, query,
		tenant.ID,
		tenant.Name,
		tenant.Slug,
		tenant.DisplayName,
		tenant.Domain,
		tenant.Status,
		tenant.BillingExempt,
		settingsJSON,
		metadataJSON,
		tenant.BillingEmail,
		tenant.MaxUsers,
		tenant.MaxStorage,
	)
	if err != nil {
		return fmt.Errorf("Create: %w", err)
	}
	return nil
}

// UpdateSettings persists only the Phase 2 settings columns (timezone,
// default_sender_domain_id) for a tenant. This is a narrow UPDATE that
// only touches those two columns, so it does not overwrite other fields
// the way the broad Update() method does.
func (r *TenantRepository) UpdateSettings(ctx context.Context, tenant *models.Tenant) error {
	query := `
		UPDATE iam_tenants SET
			display_name              = $1,
			timezone                  = $2,
			default_sender_domain_id  = $3,
			updated_at                = NOW()
		WHERE id = $4
		RETURNING updated_at`

	return r.db.QueryRow(ctx, query,
		tenant.DisplayName,
		tenant.Timezone,
		tenant.DefaultSenderDomainID,
		tenant.ID,
	).Scan(&tenant.UpdatedAt)
}

// TenantNameState is the slice of an iam_tenants row the workspace-name
// backfill reads: enough to decide whether a tenant still carries the signup
// placeholder, nothing more.
type TenantNameState struct {
	ID          uuid.UUID
	Slug        string
	DisplayName string
}

// RenameDisplayNameIfPlaceholder sets display_name to name only while it is
// still the signup placeholder. The check lives in the UPDATE's WHERE clause so
// two racing callers (the first-run form and the legal-entity hook) cannot
// overwrite a name a user just chose. Reports whether a row changed; false means
// the tenant is missing or already has a real name. iam_tenants.name stays the
// immutable identifier and is never touched.
func (r *TenantRepository) RenameDisplayNameIfPlaceholder(ctx context.Context, id uuid.UUID, name string) (bool, error) {
	tag, err := r.db.Exec(ctx, `
		UPDATE iam_tenants SET
			display_name = $1,
			updated_at   = NOW()
		WHERE id = $2 AND LOWER(BTRIM(display_name)) = LOWER($3)`,
		name, id, models.PlaceholderTenantName,
	)
	if err != nil {
		return false, fmt.Errorf("RenameDisplayNameIfPlaceholder: %w", err)
	}
	return tag.RowsAffected() > 0, nil
}

// ListNameStates returns id, slug and display_name of every live tenant
// (cancelled ones excluded), oldest first, for the placeholder-name backfill.
func (r *TenantRepository) ListNameStates(ctx context.Context) ([]TenantNameState, error) {
	rows, err := r.db.Query(ctx, `
		SELECT id, slug, display_name
		FROM iam_tenants
		WHERE cancelled_at IS NULL
		ORDER BY created_at ASC`)
	if err != nil {
		return nil, fmt.Errorf("ListNameStates: %w", err)
	}
	defer rows.Close()

	var out []TenantNameState
	for rows.Next() {
		var t TenantNameState
		if err := rows.Scan(&t.ID, &t.Slug, &t.DisplayName); err != nil {
			return nil, fmt.Errorf("ListNameStates scan: %w", err)
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// ErrTenantSlugTaken is returned by UpdateSlug when the requested slug
// collides with another tenant's iam_tenants_slug_key unique index entry.
// Callers must surface this as a distinct "slug unavailable" condition,
// never a generic 500 — see OnboardingSlugService.ConfirmSlug, which maps
// it to the same message it already uses for a host-table collision
// (ErrHostClaimed), so a taken slug fails identically regardless of which
// of the two tables detects it first.
var ErrTenantSlugTaken = errors.New("tenant slug already taken")

// UpdateSlug persists a confirmed tenant slug directly into iam_tenants —
// the local write-back half of the onboarding "choose your subdomain"
// step. Narrow, single-purpose UPDATE (same shape as UpdateSettings)
// rather than routing through the write-all-columns Update: prior to this
// method, NO code path in falcon-id ever wrote iam_tenants.slug after
// Create, which is the root cause of a confirmed slug applying in
// tenant-management (the system of record for the rename) while
// DiscoverBySlug — which reads iam_tenants, not tenant-management —
// kept resolving the tenant at its provisioning-time fallback slug
// forever. See ConfirmSlug for call-site ordering: this MUST run only
// after the host is registered, and its result MUST be pushed to
// tenant-management afterward, so a mid-sequence failure never leaves
// iam_tenants.slug pointing at a host nothing else agrees exists.
func (r *TenantRepository) UpdateSlug(ctx context.Context, tenantID uuid.UUID, slug string) error {
	query := `
		UPDATE iam_tenants SET
			slug       = $1,
			updated_at = NOW()
		WHERE id = $2`

	_, err := r.db.Exec(ctx, query, slug, tenantID)
	if err != nil {
		if pgUniqueViolation(err) {
			return ErrTenantSlugTaken
		}
		return fmt.Errorf("UpdateSlug: %w", err)
	}
	return nil
}

// GetInternalTenant retrieves the HexxLock internal tenant
func (r *TenantRepository) GetInternalTenant(ctx context.Context) (*models.Tenant, error) {
	return r.GetBySlug(ctx, "exampletenant")
}

// ListByType retrieves all tenants of a specific type.
//
// ADR-0029 (Phase 3): iam_tenants.type was dropped. This method now returns
// all tenants regardless of the requested type and logs a deprecation
// warning via the returned error annotation. Callers that need type-filtered
// results must query the tenant-management service (the authoritative SoR).
//
// Deprecated: filter by type via tenant-management, not iam_tenants.
func (r *TenantRepository) ListByType(ctx context.Context, tenantType models.TenantType) ([]*models.Tenant, error) {
	query := `
		SELECT id, name, slug, display_name, domain, status,
		       COALESCE(billing_exempt, false) as billing_exempt,
		       settings, metadata, billing_email, stripe_customer_id,
		       max_users, max_storage, trial_ends_at,
		       created_at, updated_at, suspended_at, cancelled_at,
		       COALESCE(timezone, 'UTC') as timezone,
		       default_sender_domain_id
		FROM iam_tenants
		ORDER BY created_at DESC
	`

	rows, err := r.db.Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("ListByType: %w", err)
	}
	defer rows.Close()

	var tenants []*models.Tenant
	for rows.Next() {
		var tenant models.Tenant
		var settingsJSON, metadataJSON []byte

		err := rows.Scan(
			&tenant.ID,
			&tenant.Name,
			&tenant.Slug,
			&tenant.DisplayName,
			&tenant.Domain,
			&tenant.Status,
			&tenant.BillingExempt,
			&settingsJSON,
			&metadataJSON,
			&tenant.BillingEmail,
			&tenant.StripeCustomerID,
			&tenant.MaxUsers,
			&tenant.MaxStorage,
			&tenant.TrialEndsAt,
			&tenant.CreatedAt,
			&tenant.UpdatedAt,
			&tenant.SuspendedAt,
			&tenant.CancelledAt,
			&tenant.Timezone,
			&tenant.DefaultSenderDomainID,
		)
		if err != nil {
			return nil, fmt.Errorf("ListByType: %w", err)
		}

		// ADR-0029: type and plan are no longer stored in iam_tenants.
		tenant.Type = models.TenantTypeCustomer
		tenant.Plan = ""

		if settingsJSON != nil {
			_ = json.Unmarshal(settingsJSON, &tenant.Settings)
		}
		if metadataJSON != nil {
			_ = json.Unmarshal(metadataJSON, &tenant.Metadata)
		}

		tenants = append(tenants, &tenant)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("ListByType: rows iteration: %w", err)
	}

	return tenants, nil
}
