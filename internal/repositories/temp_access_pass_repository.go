// SPDX-License-Identifier: AGPL-3.0-or-later

package repositories

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// TAPRecord is the repository-layer representation of a Temporary Access Pass.
// It mirrors services.TempAccessPass field-for-field so that the wiring code in
// cmd/ can copy values between the two without reflection.
//
// The services package owns the domain struct (TempAccessPass) and the
// tempAccessPassRepo interface. Importing services from repositories would create
// a circular dependency, so the repository operates on this local record type.
// A thin adapter (TempAccessPassAdapter) is wired in cmd/ to satisfy the
// services.tempAccessPassRepo interface.
type TAPRecord struct {
	ID            uuid.UUID
	UserID        uuid.UUID
	TenantID      uuid.UUID
	PassHash      string // SHA-256 hex digest
	IsOneTime     bool
	MaxUses       int
	UsesRemaining int
	ExpiresAt     time.Time
	CreatedBy     uuid.UUID
	CreatedAt     time.Time
}

// TempAccessPassRepository handles persistence for iam_temp_access_passes.
// All write operations are performed against the provided DBPool; reads are
// filtered by uses_remaining > 0 and expires_at in the future where appropriate.
type TempAccessPassRepository struct {
	pool DBPool
}

// NewTempAccessPassRepository creates a new TempAccessPassRepository backed by
// the provided connection pool.
func NewTempAccessPassRepository(pool DBPool) *TempAccessPassRepository {
	return &TempAccessPassRepository{pool: pool}
}

// Create persists a new TAPRecord.
// The record must have all required fields populated by the caller (including
// ID, PassHash, and ExpiresAt). CreatedAt is populated by the database DEFAULT
// and scanned back into rec.CreatedAt.
func (r *TempAccessPassRepository) Create(ctx context.Context, rec *TAPRecord) error {
	if rec.ID == uuid.Nil {
		rec.ID = uuid.New()
	}

	err := r.pool.QueryRow(ctx,
		`INSERT INTO iam_temp_access_passes
		 (id, user_id, tenant_id, pass_hash, is_one_time, max_uses, uses_remaining, expires_at, created_by)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		 RETURNING created_at`,
		rec.ID,
		rec.UserID,
		rec.TenantID,
		rec.PassHash,
		rec.IsOneTime,
		rec.MaxUses,
		rec.UsesRemaining,
		rec.ExpiresAt,
		rec.CreatedBy,
	).Scan(&rec.CreatedAt)
	if err != nil {
		return fmt.Errorf("TempAccessPassRepository.Create: %w", err)
	}

	return nil
}

// GetByUserAndHash returns the first active TAP for the given user whose stored
// pass_hash matches the provided hash. Returns (nil, nil) when no matching row
// is found. Only rows with uses_remaining > 0 are considered.
func (r *TempAccessPassRepository) GetByUserAndHash(
	ctx context.Context,
	userID, tenantID uuid.UUID,
	passHash string,
) (*TAPRecord, error) {
	var rec TAPRecord

	err := r.pool.QueryRow(ctx,
		`SELECT id, user_id, tenant_id, pass_hash, is_one_time, max_uses,
		        uses_remaining, expires_at, created_by, created_at
		 FROM iam_temp_access_passes
		 WHERE user_id = $1
		   AND tenant_id = $2
		   AND pass_hash = $3
		   AND uses_remaining > 0
		 ORDER BY expires_at DESC
		 LIMIT 1`,
		userID, tenantID, passHash,
	).Scan(
		&rec.ID, &rec.UserID, &rec.TenantID, &rec.PassHash, &rec.IsOneTime,
		&rec.MaxUses, &rec.UsesRemaining, &rec.ExpiresAt, &rec.CreatedBy, &rec.CreatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("TempAccessPassRepository.GetByUserAndHash: %w", err)
	}

	return &rec, nil
}

// DecrementUses atomically decrements uses_remaining for the identified TAP.
// The update is a no-op when uses_remaining is already 0, preventing underflow.
func (r *TempAccessPassRepository) DecrementUses(ctx context.Context, id uuid.UUID) error {
	_, err := r.pool.Exec(ctx,
		`UPDATE iam_temp_access_passes
		 SET uses_remaining = uses_remaining - 1
		 WHERE id = $1 AND uses_remaining > 0`,
		id,
	)
	if err != nil {
		return fmt.Errorf("TempAccessPassRepository.DecrementUses: %w", err)
	}

	return nil
}

// DeleteExpired removes all rows whose expires_at is in the past.
// Returns the number of rows deleted. Intended to be called from a background
// maintenance goroutine.
func (r *TempAccessPassRepository) DeleteExpired(ctx context.Context) (int64, error) {
	tag, err := r.pool.Exec(ctx,
		`DELETE FROM iam_temp_access_passes WHERE expires_at < $1`,
		time.Now().UTC(),
	)
	if err != nil {
		return 0, fmt.Errorf("TempAccessPassRepository.DeleteExpired: %w", err)
	}

	return tag.RowsAffected(), nil
}

// ListByUser returns all Temporary Access Passes for the given user/tenant pair,
// regardless of expiry or remaining uses. Callers are responsible for filtering
// if only active passes are needed.
func (r *TempAccessPassRepository) ListByUser(
	ctx context.Context,
	userID, tenantID uuid.UUID,
) ([]*TAPRecord, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT id, user_id, tenant_id, pass_hash, is_one_time, max_uses,
		        uses_remaining, expires_at, created_by, created_at
		 FROM iam_temp_access_passes
		 WHERE user_id = $1 AND tenant_id = $2
		 ORDER BY expires_at DESC`,
		userID, tenantID,
	)
	if err != nil {
		return nil, fmt.Errorf("TempAccessPassRepository.ListByUser: %w", err)
	}
	defer rows.Close()

	var records []*TAPRecord
	for rows.Next() {
		var rec TAPRecord
		if err := rows.Scan(
			&rec.ID, &rec.UserID, &rec.TenantID, &rec.PassHash, &rec.IsOneTime,
			&rec.MaxUses, &rec.UsesRemaining, &rec.ExpiresAt, &rec.CreatedBy, &rec.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf("TempAccessPassRepository.ListByUser: scan: %w", err)
		}
		records = append(records, &rec)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("TempAccessPassRepository.ListByUser: rows: %w", err)
	}

	return records, nil
}

// Delete removes a single TAP by ID. It is not an error to delete a row that
// does not exist (idempotent revocation).
func (r *TempAccessPassRepository) Delete(ctx context.Context, id uuid.UUID) error {
	_, err := r.pool.Exec(ctx,
		`DELETE FROM iam_temp_access_passes WHERE id = $1`,
		id,
	)
	if err != nil {
		return fmt.Errorf("TempAccessPassRepository.Delete: %w", err)
	}

	return nil
}
