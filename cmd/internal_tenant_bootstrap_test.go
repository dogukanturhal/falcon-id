// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"testing"

	"github.com/google/uuid"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

type fakeInternalTenantRepo struct {
	row     *models.Tenant
	creates int
}

func (f *fakeInternalTenantRepo) GetByID(context.Context, uuid.UUID) (*models.Tenant, error) {
	return f.row, nil
}

func (f *fakeInternalTenantRepo) Create(_ context.Context, t *models.Tenant) error {
	f.creates++
	f.row = t
	return nil
}

func TestTryBootstrapInternalTenant_CreatesOnceIdempotent(t *testing.T) {
	repo := &fakeInternalTenantRepo{}
	for i := 0; i < 2; i++ {
		if err := tryBootstrapInternalTenant(context.Background(), repo); err != nil {
			t.Fatalf("run %d: %v", i, err)
		}
	}
	if repo.creates != 1 {
		t.Fatalf("creates = %d, want 1", repo.creates)
	}
	if repo.row.ID.String() != models.HexxlockInternalTenantID || repo.row.Slug != "exampletenant" {
		t.Fatalf("unexpected row %+v", repo.row)
	}
}
