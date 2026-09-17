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

// consumerRoleBootstrapRepo is the minimal interface
// tryBootstrapConsumerRole needs against repos.Role — same testability
// pattern as consumerTenantBootstrapRepo (extracted so the bootstrap
// logic can be unit-tested without spinning up Postgres).
type consumerRoleBootstrapRepo interface {
	GetByName(ctx context.Context, tenantID uuid.UUID, name string) (*models.Role, error)
	Create(ctx context.Context, role *models.Role) error
}

// ConsumerUserRoleName is the well-known role assigned to every personal-
// account signup landing in models.WellKnownTenantConsumer. Exported so
// the signup post-hook (services.PostSignupProvisioner) can reference it
// without re-declaring the magic string.
const ConsumerUserRoleName = "consumer_user"

// bootstrapConsumerRole idempotently ensures the `consumer_user` role row
// exists in `iam_roles` scoped to the WellKnownTenantConsumer tenant. The
// role is assigned to every personal-account signup at completion time
// (see services.PostSignupProvisioner.OnSignupComplete), giving the
// authorization engine a stable role-handle for "this is a consumer
// user" decisions.
//
// Why a dedicated role (instead of relying on tenant-default roles):
//
//   - Tenant-default roles vary across customer / personal / internal
//     tenants and aren't enumerated centrally. The consumer tenant has
//     no roles seeded by default, so without this bootstrap every
//     personal signup would land with ZERO role assignments — a
//     hidden hole in any future `RequireRole`-style gate.
//
//   - Frontend conditional rendering (Phase 5) can switch on
//     "user.roles contains consumer_user" as a robust signal, distinct
//     from the legacy per-user "personal-XXXX" tenants where role-
//     based identification of consumers was impossible (no shared
//     role across all of them).
//
//   - SOC dashboards / SIEM queries get a clean "filter consumers
//     out of admin-action alerts" predicate via the role.
//
// Permissions on the role (Phase 1 of ENT-2): empty for now. Consumer
// users access their own data via the user-id + session-context path
// in handlers (`middleware.GetCurrentUser` matches the URL :id param),
// not via explicit permission grants. Adding minimum permissions (read
// own profile, manage own sessions, manage own consents, request own
// GDPR export) is a future follow-up — the role NAME is the load-
// bearing artifact for "is this a consumer user" decisions; the
// permission set is operationally orthogonal.
//
// Idempotency:
//
//   - GetByName(consumer tenant, "consumer_user") → if non-nil, skip.
//   - Insert with stable name + canonical attributes.
//
// Failure mode (fail-fast, same posture as bootstrapConsumerTenant):
//
//   - On error, the production wrapper logger.Fatals so the misconfig
//     surfaces at pod startup. The signup flow needs this role to
//     exist — a silent absence would surface as broken authorization
//     gates after the first consumer signup.
//
// Safe to call on every restart.
func bootstrapConsumerRole(repos *Repositories) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := tryBootstrapConsumerRole(ctx, repos.Role); err != nil {
		logger.Fatal("bootstrapConsumerRole: "+err.Error(),
			zap.String("tenant_id", models.WellKnownTenantConsumer.String()),
			zap.String("role_name", ConsumerUserRoleName),
		)
	}
}

// tryBootstrapConsumerRole is the testable core. Returns nil on success
// (created or already-exists), error on failure.
func tryBootstrapConsumerRole(ctx context.Context, repo consumerRoleBootstrapRepo) error {
	tenantID := models.WellKnownTenantConsumer

	existing, err := repo.GetByName(ctx, tenantID, ConsumerUserRoleName)
	if err != nil {
		return fmt.Errorf("failed to check for existing role: %w", err)
	}
	if existing != nil {
		logger.Info("bootstrapConsumerRole: consumer role already exists, skipping",
			zap.String("tenant_id", tenantID.String()),
			zap.String("role_name", existing.Name),
		)
		return nil
	}

	desc := "Default role for HexxLock personal-account users. Assigned to every signup landing in WellKnownTenantConsumer. Backs frontend conditional rendering for consumer-tenant UX + SOC consumer-vs-admin filtering."
	role := &models.Role{
		ID:          uuid.New(),
		TenantID:    tenantID,
		Name:        ConsumerUserRoleName,
		DisplayName: "Consumer User",
		Description: &desc,
		IsSystem:    true,  // system-managed; cannot be deleted via UI
		IsDefault:   false, // assigned at signup explicitly, not via default-roles lookup
	}

	if err := repo.Create(ctx, role); err != nil {
		return fmt.Errorf("failed to create consumer role: %w", err)
	}

	logger.Info("bootstrapConsumerRole: consumer role created",
		zap.String("tenant_id", tenantID.String()),
		zap.String("role_id", role.ID.String()),
		zap.String("role_name", role.Name),
	)
	return nil
}
