// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

type fakeInternalTenantRepo struct {
	row     *models.Tenant
	creates int
	getErr  error
	// createErr, when set, makes Create fail; createRow is then stored as if
	// another replica inserted it.
	createErr error
	createRow *models.Tenant
}

func (f *fakeInternalTenantRepo) GetByID(context.Context, uuid.UUID) (*models.Tenant, error) {
	if f.getErr != nil {
		return nil, f.getErr
	}
	return f.row, nil
}

func (f *fakeInternalTenantRepo) Create(_ context.Context, t *models.Tenant) error {
	f.creates++
	if f.createErr != nil {
		f.row = f.createRow
		return f.createErr
	}
	f.row = t
	return nil
}

func TestTryBootstrapInternalTenant_CreatesOnceIdempotent(t *testing.T) {
	repo := &fakeInternalTenantRepo{}
	for i := 0; i < 2; i++ {
		if err := tryBootstrapInternalTenant(context.Background(), repo, true); err != nil {
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

func TestTryBootstrapInternalTenant_CreateRaceReReadsRow(t *testing.T) {
	repo := &fakeInternalTenantRepo{
		createErr: errors.New("duplicate key"),
		createRow: &models.Tenant{Slug: "exampletenant"},
	}
	if err := tryBootstrapInternalTenant(context.Background(), repo, true); err != nil {
		t.Fatalf("want nil after re-read finds row, got %v", err)
	}
	if repo.creates != 1 {
		t.Fatalf("creates = %d, want 1", repo.creates)
	}
}

func TestTryBootstrapInternalTenant_GetByIDErrorNoCreate(t *testing.T) {
	repo := &fakeInternalTenantRepo{getErr: errors.New("db down")}
	if err := tryBootstrapInternalTenant(context.Background(), repo, true); err == nil {
		t.Fatal("want error")
	}
	if repo.creates != 0 {
		t.Fatalf("creates = %d, want 0", repo.creates)
	}
}

func TestTryBootstrapInternalTenant_NonStandaloneMissingNoCreate(t *testing.T) {
	repo := &fakeInternalTenantRepo{}
	if err := tryBootstrapInternalTenant(context.Background(), repo, false); err != nil {
		t.Fatalf("want nil, got %v", err)
	}
	if repo.creates != 0 {
		t.Fatalf("creates = %d, want 0", repo.creates)
	}
}
