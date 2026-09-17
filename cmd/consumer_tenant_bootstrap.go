// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/pkg/logger"
)

// consumerTenantBootstrapRepo is the minimal interface
// tryBootstrapConsumerTenant needs against repos.Tenant — extracted so
// the bootstrap logic can be unit-tested without spinning up Postgres.
type consumerTenantBootstrapRepo interface {
	GetByID(ctx context.Context, id uuid.UUID) (*models.Tenant, error)
	Create(ctx context.Context, tenant *models.Tenant) error
}

// bootstrapConsumerTenant idempotently ensures the WellKnownTenantConsumer
// row exists in `iam_tenants`. The consumer tenant is the shared home for
// every self-registered HexxLock end-user — gmail / outlook / personal
// email signups land here as MEMBERS, not as owners of their own per-user
// tenant.
//
// Why a shared consumer tenant (instead of per-user "personal-XXXX"):
//
//   - Industry-standard pattern. Microsoft Entra ID holds every personal
//     Microsoft account in a single tenant (9188040d-6c67-4c5b-b112-
//     36a304b66dad); Auth0/Okta CIC/Keycloak use one "consumer" realm.
//     Per-user tenants are not how mature IAM platforms scale B2C.
//
//   - Tenant-table scale. A per-user model produces one iam_tenants row
//     per signup; at 100K consumer users that's 100K tenant rows + 100K
//     realm_tenants rows + 100K rounds of keystone schema-bundle
//     application per release. The shared model collapses this to O(1).
//
//   - OWASP Multi-Tenant Cheat Sheet + NIST SP 800-207 (Zero Trust)
//     prescribe logical isolation via access control within a tenant
//     rather than physical tenant-per-user explosion.
//
//   - HexxLock-specific: RealmDBProvisioner cost compounds with per-user
//     tenants on a single-server cluster (per memory
//     internal engineering notes). One consumer tenant
//     means one realm/DB total for all gmail/outlook signups.
//
// Why this lives in the application boot path (same rationale as
// bootstrapPlatformRealm / bootstrapAdminUser):
//
//   - Keystone manages the `iam_tenants` table STRUCTURE; INSERTs are
//     operational data, not schema. The consumer tenant is a well-known
//     sentinel row the signup flow requires to function.
//
//   - The seed runs through the application's repository layer (not raw
//     SQL) so any future row-shape evolution flows through one code
//     path.
//
//   - Uses repos.Tenant.Create (low-level) instead of services.Tenant
//     so we can pin the well-known sentinel UUID
//     (00000000-0000-0000-0000-000000000004) — services.Tenant always
//     allocates a fresh UUID.
//
// Idempotency:
//
//   - GetByID first; if the tenant exists, log and return.
//   - Insert with the well-known UUID + canonical "B2C consumer"
//     attributes (type=consumer, plan=consumer, status=active).
//
// Failure mode (fail-fast, since 2026-05-22):
//
//   - On error, log Fatal — crash-loop the pod. Same posture as
//     repositories.RequireEmailHashKey: the consumer tenant is now
//     load-bearing for every personal signup; a silent absence
//     would surface as signup failures hours later when the first
//     gmail user tries to register. Fail-fast surfaces the misconfig
//     at pod startup so the operator can fix it immediately.
//
// This function is safe to call on every restart.
func bootstrapConsumerTenant(repos *Repositories) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := tryBootstrapConsumerTenant(ctx, repos.Tenant); err != nil {
		// Fail-fast: the consumer tenant is load-bearing for every
		// personal signup. Same posture as
		// repositories.RequireEmailHashKey (cmd/main.go:54). Crash-
		// loop the pod so a misconfig surfaces at startup, not at
		// first signup attempt.
		logger.Fatal("bootstrapConsumerTenant: "+err.Error(),
			zap.String("tenant_id", models.WellKnownTenantConsumer.String()),
		)
	}
}

// tryBootstrapConsumerTenant is the testable core. Returns nil on
// success (created or already-exists), error on any failure mode.
// The caller decides what to do with the error (production: Fatal;
// tests: assert).
func tryBootstrapConsumerTenant(ctx context.Context, repo consumerTenantBootstrapRepo) error {
	tenantID := models.WellKnownTenantConsumer

	existing, err := repo.GetByID(ctx, tenantID)
	if err != nil {
		return fmt.Errorf("failed to check for existing tenant: %w", err)
	}
	if existing != nil {
		logger.Info("bootstrapConsumerTenant: consumer tenant already exists, skipping",
			zap.String("tenant_id", tenantID.String()),
			zap.String("slug", existing.Slug),
		)
		return nil
	}

	// Canonical attributes for the shared B2C consumer tenant.
	//
	// - type = "personal" — the existing tenant_type enum value
	//   (customer, internal, trial, partner, demo, personal); the
	//   shared consumer tenant is semantically a "personal-accounts
	//   pool" + reuses the same downstream type-filtering as the
	//   legacy per-user "personal-<rand>" tenants. Adding a new
	//   "consumer" enum value would require a Keystone schema
	//   migration; using the existing one keeps this MR
	//   schema-free + frontend conditional rendering can switch on
	//   the well-known tenant ID itself (WellKnownTenantConsumer) for
	//   "is shared consumer tenant" UX decisions.
	// - plan = "consumer" — billing-class string used by quota/feature
	//   resolution; identifies "this is the shared consumer pool" so
	//   the billing pipeline doesn't treat it like a customer-tier
	//   tenant for invoicing or seat counts.
	// - billing_exempt = true — the platform absorbs cost for the
	//   shared consumer tenant; individual users are not billed via
	//   the tenant-level billing pipeline.
	tenant := &models.Tenant{
		ID:            tenantID,
		Name:          "hexxlock-consumer",
		Slug:          "hexxlock-consumer",
		DisplayName:   "HexxLock Personal Accounts",
		Status:        "active",
		Type:          models.TenantType("personal"),
		Plan:          "consumer",
		BillingExempt: true,
	}

	if err := repo.Create(ctx, tenant); err != nil {
		return fmt.Errorf("failed to create consumer tenant: %w", err)
	}

	logger.Info("bootstrapConsumerTenant: consumer tenant created",
		zap.String("tenant_id", tenantID.String()),
		zap.String("slug", tenant.Slug),
		zap.String("type", string(tenant.Type)),
	)
	return nil
}
