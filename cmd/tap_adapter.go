// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// tap_adapter.go wires TempAccessPassRepository (repositories package) to
// TempAccessPassService (services package) without introducing a circular
// import between those two packages.
//
// The services package defines TempAccessPass and the tempAccessPassRepo
// interface (unexported). The repositories package defines TempAccessPassRepository
// which operates on its own local TAPRecord type to avoid importing services.
//
// This file, as part of the cmd (composition root) package, is the only place
// that can see both packages and knows how to convert between the two record
// types. tempAccessPassRepoAdapter implements the unexported
// services.tempAccessPassRepo interface by forwarding every call to
// TempAccessPassRepository after converting the argument/return types.

import (
	"context"
	"fmt"

	"github.com/google/uuid"

	"github.com/dogukanturhal/falcon-id/internal/repositories"
	"github.com/dogukanturhal/falcon-id/internal/services"
)

// tempAccessPassRepoAdapter bridges repositories.TempAccessPassRepository and
// the services.tempAccessPassRepo interface.
type tempAccessPassRepoAdapter struct {
	repo *repositories.TempAccessPassRepository
}

// newTempAccessPassRepoAdapter wraps a TempAccessPassRepository so it satisfies
// the services.tempAccessPassRepo interface.
func newTempAccessPassRepoAdapter(repo *repositories.TempAccessPassRepository) *tempAccessPassRepoAdapter {
	return &tempAccessPassRepoAdapter{repo: repo}
}

// Create persists a new Temporary Access Pass. The services.TempAccessPass
// value is mapped field-for-field to a repositories.TAPRecord. The database
// DEFAULT for created_at is scanned back into tap.CreatedAt.
func (a *tempAccessPassRepoAdapter) Create(ctx context.Context, tap *services.TempAccessPass) error {
	rec := &repositories.TAPRecord{
		ID:            tap.ID,
		UserID:        tap.UserID,
		TenantID:      tap.TenantID,
		PassHash:      tap.PassHash,
		IsOneTime:     tap.IsOneTime,
		MaxUses:       tap.MaxUses,
		UsesRemaining: tap.UsesRemaining,
		ExpiresAt:     tap.ExpiresAt,
		CreatedBy:     tap.CreatedBy,
		CreatedAt:     tap.CreatedAt,
	}

	if err := a.repo.Create(ctx, rec); err != nil {
		return fmt.Errorf("tempAccessPassRepoAdapter.Create: %w", err)
	}

	// Propagate the database-generated created_at back to the caller.
	tap.ID = rec.ID
	tap.CreatedAt = rec.CreatedAt
	return nil
}

// GetByUserAndHash looks up the first active TAP for the given user whose
// stored hash matches passHash. Returns (nil, nil) when no match is found.
func (a *tempAccessPassRepoAdapter) GetByUserAndHash(
	ctx context.Context,
	userID, tenantID uuid.UUID,
	passHash string,
) (*services.TempAccessPass, error) {
	rec, err := a.repo.GetByUserAndHash(ctx, userID, tenantID, passHash)
	if err != nil {
		return nil, fmt.Errorf("tempAccessPassRepoAdapter.GetByUserAndHash: %w", err)
	}
	if rec == nil {
		return nil, nil
	}

	return tapRecordToService(rec), nil
}

// DecrementUses atomically decrements the uses_remaining counter for the TAP
// identified by id.
func (a *tempAccessPassRepoAdapter) DecrementUses(ctx context.Context, id uuid.UUID) error {
	if err := a.repo.DecrementUses(ctx, id); err != nil {
		return fmt.Errorf("tempAccessPassRepoAdapter.DecrementUses: %w", err)
	}
	return nil
}

// DeleteExpired removes all expired TAP rows. Returns the number of deleted rows.
func (a *tempAccessPassRepoAdapter) DeleteExpired(ctx context.Context) (int64, error) {
	count, err := a.repo.DeleteExpired(ctx)
	if err != nil {
		return 0, fmt.Errorf("tempAccessPassRepoAdapter.DeleteExpired: %w", err)
	}
	return count, nil
}

// ListByUser returns all TAPs for the given user/tenant pair.
func (a *tempAccessPassRepoAdapter) ListByUser(
	ctx context.Context,
	userID, tenantID uuid.UUID,
) ([]*services.TempAccessPass, error) {
	records, err := a.repo.ListByUser(ctx, userID, tenantID)
	if err != nil {
		return nil, fmt.Errorf("tempAccessPassRepoAdapter.ListByUser: %w", err)
	}

	passes := make([]*services.TempAccessPass, 0, len(records))
	for _, rec := range records {
		passes = append(passes, tapRecordToService(rec))
	}

	return passes, nil
}

// Delete removes a TAP by ID (idempotent revocation).
func (a *tempAccessPassRepoAdapter) Delete(ctx context.Context, id uuid.UUID) error {
	if err := a.repo.Delete(ctx, id); err != nil {
		return fmt.Errorf("tempAccessPassRepoAdapter.Delete: %w", err)
	}
	return nil
}

// tapRecordToService converts a repositories.TAPRecord into a services.TempAccessPass.
func tapRecordToService(rec *repositories.TAPRecord) *services.TempAccessPass {
	return &services.TempAccessPass{
		ID:            rec.ID,
		UserID:        rec.UserID,
		TenantID:      rec.TenantID,
		PassHash:      rec.PassHash,
		IsOneTime:     rec.IsOneTime,
		MaxUses:       rec.MaxUses,
		UsesRemaining: rec.UsesRemaining,
		ExpiresAt:     rec.ExpiresAt,
		CreatedBy:     rec.CreatedBy,
		CreatedAt:     rec.CreatedAt,
	}
}
