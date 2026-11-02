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

// bootstrapInternalTenant idempotently ensures the exampletenant platform
// tenant (models.HexxlockInternalTenantID) exists in `iam_tenants`.
//
// In production the row is provisioned out-of-band, so this is a no-op there.
// On a clean database (docker compose quickstart / standalone) nothing else
// creates it, and everything keyed on it (platform realm mapping, admin user,
// provisioner OAuth client, /api/v1/internal/oauth-clients) fails without it.
//
// Non-fatal: on error it logs and returns so the server still serves health
// probes; the next restart retries.
func bootstrapInternalTenant(repos *Repositories) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := tryBootstrapInternalTenant(ctx, repos.Tenant); err != nil {
		logger.Error("bootstrapInternalTenant: "+err.Error(),
			zap.String("tenant_id", models.HexxlockInternalTenantID),
		)
	}
}

// tryBootstrapInternalTenant is the testable core; nil means created or
// already present.
func tryBootstrapInternalTenant(ctx context.Context, repo consumerTenantBootstrapRepo) error {
	tenantID, err := uuid.Parse(models.HexxlockInternalTenantID)
	if err != nil {
		return fmt.Errorf("parse HexxlockInternalTenantID: %w", err)
	}

	existing, err := repo.GetByID(ctx, tenantID)
	if err != nil {
		return fmt.Errorf("failed to check for existing tenant: %w", err)
	}
	if existing != nil {
		logger.Info("bootstrapInternalTenant: internal tenant already exists, skipping",
			zap.String("tenant_id", tenantID.String()),
		)
		return nil
	}

	tenant := &models.Tenant{
		ID:            tenantID,
		Name:          "exampletenant",
		Slug:          "exampletenant",
		DisplayName:   "HexxLock Internal",
		Status:        "active",
		Type:          models.TenantType("internal"),
		BillingExempt: true,
		MaxUsers:      1000,
		MaxStorage:    107374182400,
	}
	if err := repo.Create(ctx, tenant); err != nil {
		// Another replica may have created it between the check and insert.
		if again, gerr := repo.GetByID(ctx, tenantID); gerr == nil && again != nil {
			return nil
		}
		return fmt.Errorf("failed to create internal tenant: %w", err)
	}
	logger.Info("bootstrapInternalTenant: internal tenant created",
		zap.String("tenant_id", tenantID.String()),
		zap.String("slug", tenant.Slug),
	)
	return nil
}
