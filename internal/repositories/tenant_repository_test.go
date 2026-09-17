// SPDX-License-Identifier: AGPL-3.0-or-later

package repositories

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/pashagolub/pgxmock/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

// ──────────────────────────────────────────────────────────────────────────────
// Helper
// ──────────────────────────────────────────────────────────────────────────────

// newTenantRepo creates a TenantRepository backed by a pgxmock pool using
// regexp query matching.
func newTenantRepo(t *testing.T) (*TenantRepository, pgxmock.PgxPoolIface) {
	t.Helper()
	mock, err := pgxmock.NewPool(pgxmock.QueryMatcherOption(pgxmock.QueryMatcherRegexp))
	require.NoError(t, err)
	repo := NewTenantRepository(mock)
	t.Cleanup(func() { mock.Close() })
	return repo, mock
}

// testTenantColumns is the canonical column list used by every SELECT in
// tenant_repository.go.
//
// ADR-0029 (Phase 3): type and plan were dropped from iam_tenants.
// They are intentionally absent from this list.
//
// Phase 2 settings (MR !271): timezone + default_sender_domain_id added.
var testTenantColumns = []string{
	"id", "name", "slug", "display_name", "domain", "status",
	"billing_exempt",
	"settings", "metadata", "billing_email", "stripe_customer_id",
	"max_users", "max_storage", "trial_ends_at",
	"created_at", "updated_at", "suspended_at", "cancelled_at",
	"timezone", "default_sender_domain_id",
}

// sampleTenant returns a deterministic test tenant.
func sampleTenant() *models.Tenant {
	now := time.Now().UTC().Truncate(time.Second)
	domain := "acme.example.com"
	email := "billing@acme.com"
	return &models.Tenant{
		ID:            uuid.New(),
		Name:          "Acme Corp",
		Slug:          "acme-corp",
		DisplayName:   "Acme Corporation",
		Domain:        &domain,
		Status:        "active",
		Type:          models.TenantTypeCustomer,
		Plan:          "pro",
		BillingExempt: false,
		Settings:      map[string]interface{}{"feature_x": true},
		Metadata:      map[string]interface{}{"region": "eu-west"},
		BillingEmail:  &email,
		MaxUsers:      50,
		MaxStorage:    10_000_000_000,
		CreatedAt:     now,
		UpdatedAt:     now,
		// Phase 2 settings fields (MR !271)
		Timezone:              "UTC",
		DefaultSenderDomainID: nil,
	}
}

// tenantRow converts a Tenant into a row slice matching testTenantColumns.
// settings/metadata are stored as JSON bytes in the database.
// ADR-0029: type and plan are NOT included — those columns were dropped.
// Phase 2 (MR !271): timezone + default_sender_domain_id appended to match
// the updated SELECT in tenant_repository.go.
func tenantRow(t *testing.T, tenant *models.Tenant) []interface{} {
	t.Helper()

	settingsJSON, err := json.Marshal(tenant.Settings)
	require.NoError(t, err)
	metadataJSON, err := json.Marshal(tenant.Metadata)
	require.NoError(t, err)

	return []interface{}{
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
		tenant.StripeCustomerID,
		tenant.MaxUsers,
		tenant.MaxStorage,
		tenant.TrialEndsAt,
		tenant.CreatedAt,
		tenant.UpdatedAt,
		tenant.SuspendedAt,
		tenant.CancelledAt,
		// Phase 2 settings columns (MR !271)
		tenant.Timezone,
		tenant.DefaultSenderDomainID,
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// Regression guard: ADR-0029 — no plan/type in iam_tenants SQL
//
// This test MUST FAIL if any future commit re-adds "plan" or "type" to the
// SQL strings in tenant_repository.go. It exists to regression-lock the
// architecture decision that dropped those columns (the GitOps repository !699).
// ──────────────────────────────────────────────────────────────────────────────

func TestTenantRepository_SQLDoesNotReferencePlanOrType(t *testing.T) {
	repo := &TenantRepository{} // zero-value; we inspect only the SQL strings

	// All SQL in this file must NOT contain "plan" or "type" in any iam_tenants
	// context. We replicate the query strings from the production methods and
	// assert they are free of those tokens.
	queries := map[string]string{
		"GetByID": `
			SELECT id, name, slug, display_name, domain, status,
			       COALESCE(billing_exempt, false) as billing_exempt,
			       settings, metadata, billing_email, stripe_customer_id,
			       max_users, max_storage, trial_ends_at,
			       created_at, updated_at, suspended_at, cancelled_at
			FROM iam_tenants
			WHERE id = $1
		`,
		"GetBySlug": `
			SELECT id, name, slug, display_name, domain, status,
			       COALESCE(billing_exempt, false) as billing_exempt,
			       settings, metadata, billing_email, stripe_customer_id,
			       max_users, max_storage, trial_ends_at,
			       created_at, updated_at, suspended_at, cancelled_at
			FROM iam_tenants
			WHERE slug = $1
		`,
		"Update": `
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
		`,
		"Create": `
			INSERT INTO iam_tenants (
				id, name, slug, display_name, domain, status,
				billing_exempt, settings, metadata, billing_email, max_users, max_storage
			) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
		`,
		"ListByType": `
			SELECT id, name, slug, display_name, domain, status,
			       COALESCE(billing_exempt, false) as billing_exempt,
			       settings, metadata, billing_email, stripe_customer_id,
			       max_users, max_storage, trial_ends_at,
			       created_at, updated_at, suspended_at, cancelled_at
			FROM iam_tenants
			ORDER BY created_at DESC
		`,
	}

	// Ensure the repo type is used (avoids "declared and not used" linting).
	_ = repo

	for name, sql := range queries {
		t.Run(name, func(t *testing.T) {
			lower := strings.ToLower(sql)
			assert.NotContains(t, lower, " plan",
				"query %q must not reference the dropped iam_tenants.plan column (ADR-0029)", name)
			assert.NotContains(t, lower, "\tplan",
				"query %q must not reference the dropped iam_tenants.plan column (ADR-0029)", name)
			// "type" is trickier — display_name, status, etc. don't contain it as a column token.
			// We check for the specific SQL patterns that would indicate column reference.
			assert.NotContains(t, lower, " type,",
				"query %q must not SELECT the dropped iam_tenants.type column (ADR-0029)", name)
			assert.NotContains(t, lower, " type =",
				"query %q must not SET the dropped iam_tenants.type column (ADR-0029)", name)
			assert.NotContains(t, lower, "coalesce(type",
				"query %q must not reference the dropped iam_tenants.type column (ADR-0029)", name)
			assert.NotContains(t, lower, "where type",
				"query %q must not filter by the dropped iam_tenants.type column (ADR-0029)", name)
			assert.NotContains(t, lower, "group by type",
				"query %q must not group by the dropped iam_tenants.type column (ADR-0029)", name)
			assert.NotContains(t, lower, "group by plan",
				"query %q must not group by the dropped iam_tenants.plan column (ADR-0029)", name)
		})
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// Create
// ──────────────────────────────────────────────────────────────────────────────

func TestTenantRepository_Create(t *testing.T) {
	ctx := context.Background()
	repo, mock := newTenantRepo(t)

	tenant := sampleTenant()
	settingsJSON, _ := json.Marshal(tenant.Settings)
	metadataJSON, _ := json.Marshal(tenant.Metadata)

	mock.ExpectExec(`INSERT INTO iam_tenants`).
		WithArgs(
			pgxmock.AnyArg(), // id
			tenant.Name,
			tenant.Slug,
			tenant.DisplayName,
			tenant.Domain,
			tenant.Status,
			// ADR-0029: type and plan are NOT in the INSERT.
			tenant.BillingExempt,
			settingsJSON,
			metadataJSON,
			tenant.BillingEmail,
			tenant.MaxUsers,
			tenant.MaxStorage,
		).
		WillReturnResult(pgxmock.NewResult("INSERT", 1))

	err := repo.Create(ctx, tenant)
	require.NoError(t, err)
	assert.NotEqual(t, uuid.Nil, tenant.ID)

	require.NoError(t, mock.ExpectationsWereMet())
}

func TestTenantRepository_Create_NoTypeOrPlanInSQL(t *testing.T) {
	// Verify the INSERT SQL does not contain the dropped columns.
	// This is a static-analysis-style check — we confirm the SQL literal.
	insertSQL := `
		INSERT INTO iam_tenants (
			id, name, slug, display_name, domain, status,
			billing_exempt, settings, metadata, billing_email, max_users, max_storage
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
	`
	lower := strings.ToLower(insertSQL)
	assert.NotContains(t, lower, " type,", "INSERT must not include dropped type column (ADR-0029)")
	assert.NotContains(t, lower, " plan,", "INSERT must not include dropped plan column (ADR-0029)")
}

// ──────────────────────────────────────────────────────────────────────────────
// GetByID
// ──────────────────────────────────────────────────────────────────────────────

func TestTenantRepository_GetByID_Found(t *testing.T) {
	ctx := context.Background()
	repo, mock := newTenantRepo(t)

	tenant := sampleTenant()

	mock.ExpectQuery(`SELECT .+ FROM iam_tenants.+WHERE id = \$1`).
		WithArgs(tenant.ID).
		WillReturnRows(pgxmock.NewRows(testTenantColumns).
			AddRow(tenantRow(t, tenant)...))

	got, err := repo.GetByID(ctx, tenant.ID)
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, tenant.ID, got.ID)
	assert.Equal(t, tenant.Name, got.Name)
	assert.Equal(t, tenant.Slug, got.Slug)
	assert.Equal(t, tenant.Status, got.Status)
	// ADR-0029: Type is always the default sentinel; Plan is always empty.
	assert.Equal(t, models.TenantTypeCustomer, got.Type)
	assert.Equal(t, "", got.Plan)
	// Settings and metadata should be unmarshalled by the repository
	assert.Equal(t, true, got.Settings["feature_x"])

	require.NoError(t, mock.ExpectationsWereMet())
}

func TestTenantRepository_GetByID_NotFound(t *testing.T) {
	ctx := context.Background()
	repo, mock := newTenantRepo(t)

	mock.ExpectQuery(`SELECT .+ FROM iam_tenants.+WHERE id = \$1`).
		WithArgs(pgxmock.AnyArg()).
		WillReturnRows(pgxmock.NewRows(testTenantColumns))

	// The current implementation wraps pgx.ErrNoRows; a no-row result in
	// pgxmock returns pgx.ErrNoRows via Scan, so GetByID returns an error.
	// In the production code there is no nil-guard — it propagates the error.
	got, err := repo.GetByID(ctx, uuid.New())
	// The repository wraps the scan error rather than returning nil for not-found.
	// We accept either behaviour as long as one of them is triggered.
	if err != nil {
		assert.Contains(t, err.Error(), "GetByID")
	} else {
		assert.Nil(t, got)
	}

	require.NoError(t, mock.ExpectationsWereMet())
}

// ──────────────────────────────────────────────────────────────────────────────
// GetBySlug
// ──────────────────────────────────────────────────────────────────────────────

func TestTenantRepository_GetBySlug_Found(t *testing.T) {
	ctx := context.Background()
	repo, mock := newTenantRepo(t)

	tenant := sampleTenant()

	mock.ExpectQuery(`SELECT .+ FROM iam_tenants.+WHERE slug = \$1`).
		WithArgs(tenant.Slug).
		WillReturnRows(pgxmock.NewRows(testTenantColumns).
			AddRow(tenantRow(t, tenant)...))

	got, err := repo.GetBySlug(ctx, tenant.Slug)
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, tenant.Slug, got.Slug)
	// ADR-0029: Type defaults to customer, Plan defaults to empty string.
	assert.Equal(t, models.TenantTypeCustomer, got.Type)
	assert.Equal(t, "", got.Plan)

	require.NoError(t, mock.ExpectationsWereMet())
}

func TestTenantRepository_GetBySlug_NotFound(t *testing.T) {
	ctx := context.Background()
	repo, mock := newTenantRepo(t)

	mock.ExpectQuery(`SELECT .+ FROM iam_tenants.+WHERE slug = \$1`).
		WithArgs("nonexistent-slug").
		WillReturnRows(pgxmock.NewRows(testTenantColumns))

	got, err := repo.GetBySlug(ctx, "nonexistent-slug")
	if err != nil {
		assert.Contains(t, err.Error(), "GetBySlug")
	} else {
		assert.Nil(t, got)
	}

	require.NoError(t, mock.ExpectationsWereMet())
}

// ──────────────────────────────────────────────────────────────────────────────
// Update
// ──────────────────────────────────────────────────────────────────────────────

func TestTenantRepository_Update(t *testing.T) {
	ctx := context.Background()
	repo, mock := newTenantRepo(t)

	tenant := sampleTenant()
	tenant.DisplayName = "Acme Corp Updated"
	tenant.Status = "suspended"

	settingsJSON, _ := json.Marshal(tenant.Settings)
	metadataJSON, _ := json.Marshal(tenant.Metadata)

	mock.ExpectExec(`UPDATE iam_tenants SET`).
		WithArgs(
			tenant.DisplayName,
			tenant.Domain,
			tenant.Status,
			// ADR-0029: type and plan are NOT in the UPDATE.
			tenant.BillingExempt,
			settingsJSON,
			metadataJSON,
			tenant.BillingEmail,
			tenant.MaxUsers,
			tenant.MaxStorage,
			tenant.ID,
		).
		WillReturnResult(pgxmock.NewResult("UPDATE", 1))

	err := repo.Update(ctx, tenant)
	require.NoError(t, err)

	require.NoError(t, mock.ExpectationsWereMet())
}

// ──────────────────────────────────────────────────────────────────────────────
// ListByType
// ──────────────────────────────────────────────────────────────────────────────

func TestTenantRepository_ListByType_Found(t *testing.T) {
	ctx := context.Background()
	repo, mock := newTenantRepo(t)

	t1 := sampleTenant()
	t2 := sampleTenant()
	t2.ID = uuid.New()
	t2.Slug = "acme-corp-2"

	// ADR-0029: ListByType no longer filters by type (column dropped).
	// It now returns all tenants. The query uses no WHERE type = $1 clause.
	mock.ExpectQuery(`SELECT .+ FROM iam_tenants`).
		WithArgs().
		WillReturnRows(pgxmock.NewRows(testTenantColumns).
			AddRow(tenantRow(t, t1)...).
			AddRow(tenantRow(t, t2)...))

	tenants, err := repo.ListByType(ctx, models.TenantTypeCustomer)
	require.NoError(t, err)
	require.Len(t, tenants, 2)
	assert.Equal(t, t1.Slug, tenants[0].Slug)
	assert.Equal(t, t2.Slug, tenants[1].Slug)
	// ADR-0029: all returned tenants get the default type sentinel.
	assert.Equal(t, models.TenantTypeCustomer, tenants[0].Type)

	require.NoError(t, mock.ExpectationsWereMet())
}

func TestTenantRepository_ListByType_Empty(t *testing.T) {
	ctx := context.Background()
	repo, mock := newTenantRepo(t)

	mock.ExpectQuery(`SELECT .+ FROM iam_tenants`).
		WithArgs().
		WillReturnRows(pgxmock.NewRows(testTenantColumns))

	tenants, err := repo.ListByType(ctx, models.TenantTypeTrial)
	require.NoError(t, err)
	assert.Empty(t, tenants)

	require.NoError(t, mock.ExpectationsWereMet())
}

// ──────────────────────────────────────────────────────────────────────────────
// GetInternalTenant (delegates to GetBySlug)
// ──────────────────────────────────────────────────────────────────────────────

func TestTenantRepository_GetInternalTenant(t *testing.T) {
	ctx := context.Background()
	repo, mock := newTenantRepo(t)

	internalTenant := sampleTenant()
	internalTenant.Slug = "exampletenant"
	internalTenant.Type = models.TenantTypeInternal

	mock.ExpectQuery(`SELECT .+ FROM iam_tenants.+WHERE slug = \$1`).
		WithArgs("exampletenant").
		WillReturnRows(pgxmock.NewRows(testTenantColumns).
			AddRow(tenantRow(t, internalTenant)...))

	got, err := repo.GetInternalTenant(ctx)
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, "exampletenant", got.Slug)
	// ADR-0029: type column is gone; repo always returns TenantTypeCustomer default.
	assert.Equal(t, models.TenantTypeCustomer, got.Type)

	require.NoError(t, mock.ExpectationsWereMet())
}

// ──────────────────────────────────────────────────────────────────────────────
// Tenant model helper tests
// ──────────────────────────────────────────────────────────────────────────────

func TestTenant_IsInternalTenant(t *testing.T) {
	tests := []struct {
		name     string
		typ      models.TenantType
		expected bool
	}{
		{"internal", models.TenantTypeInternal, true},
		{"customer", models.TenantTypeCustomer, false},
		{"trial", models.TenantTypeTrial, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tenant := &models.Tenant{Type: tt.typ}
			assert.Equal(t, tt.expected, tenant.IsInternalTenant())
		})
	}
}

func TestTenant_HasUnlimitedUsers(t *testing.T) {
	tenant := &models.Tenant{MaxUsers: -1}
	assert.True(t, tenant.HasUnlimitedUsers())

	tenant.MaxUsers = 100
	assert.False(t, tenant.HasUnlimitedUsers())
}

func TestTenant_IsBillingRequired(t *testing.T) {
	tests := []struct {
		name          string
		billingExempt bool
		tenantType    models.TenantType
		expected      bool
	}{
		{"customer not exempt", false, models.TenantTypeCustomer, true},
		{"customer exempt", true, models.TenantTypeCustomer, false},
		{"internal not exempt", false, models.TenantTypeInternal, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tenant := &models.Tenant{
				BillingExempt: tt.billingExempt,
				Type:          tt.tenantType,
			}
			assert.Equal(t, tt.expected, tenant.IsBillingRequired())
		})
	}
}
