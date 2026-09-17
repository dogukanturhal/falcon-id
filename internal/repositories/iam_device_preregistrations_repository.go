// SPDX-License-Identifier: AGPL-3.0-or-later

package repositories

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// IAMDevicePreRegRow mirrors a row in iam_device_preregistrations
// (migration 0007). It is the corporate-asset allowlist: the second trust
// layer above hardware attestation. jess consults it at attest time and
// downgrades TIER_CORP -> TIER_BYOD for any genuine-TPM device that is NOT a
// pre-registered corporate asset. See the migration header for the full
// rationale.
//
// At least one of EKPubkeyHash / SerialNumber is non-empty (DB CHECK
// iam_device_prereg_identifier_present). Nullable text columns use pointers so
// nil maps to SQL NULL.
type IAMDevicePreRegRow struct {
	ID       uuid.UUID
	TenantID uuid.UUID
	// sha256(EK pubkey PEM), 32 bytes raw (nil when the entry is serial-only).
	EKPubkeyHash []byte
	SerialNumber *string
	AssetTag     *string
	Model        *string
	Note         *string
	// Falcon-ID sub of the admin who imported this entry.
	CreatedBy *string
	CreatedAt time.Time
}

// PreRegInput is one device to pre-register. EKPubkeyHash, when present, is the
// 64-char lowercase hex SHA-256 of the EK pubkey PEM (the same encoding the
// jess enrollment store uses). At least one of EKPubkeyHash / SerialNumber
// must be supplied.
type PreRegInput struct {
	EKPubkeyHash string
	SerialNumber string
	AssetTag     string
	Model        string
	Note         string
}

// PreRegRowError pairs a 0-based input index with the reason it could not be
// pre-registered, so a bulk import can report partial success.
type PreRegRowError struct {
	Index int    `json:"row"`
	Error string `json:"error"`
}

// IAMDevicePreRegRepository is the accessor for the corporate-asset allowlist.
type IAMDevicePreRegRepository struct {
	pool DBTX
}

// NewIAMDevicePreRegRepository constructs a repository against the supplied
// pool (non-nil; *pgxpool.Pool in prod, pgxmock in tests).
func NewIAMDevicePreRegRepository(pool DBTX) *IAMDevicePreRegRepository {
	return &IAMDevicePreRegRepository{pool: pool}
}

// decodeEKHash validates + decodes a 64-char hex EK pubkey hash to 32 raw bytes.
func decodeEKHash(hash string) ([]byte, error) {
	if len(hash) != 64 {
		return nil, fmt.Errorf("ek_pubkey_hash must be 64 hex chars, got %d", len(hash))
	}
	b, err := hex.DecodeString(hash)
	if err != nil {
		return nil, fmt.Errorf("ek_pubkey_hash is not valid hex: %w", err)
	}
	return b, nil
}

func strPtrOrNil(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// BulkInsert pre-registers a batch of devices for a tenant. Each row is
// inserted with ON CONFLICT DO NOTHING so re-importing an already-known device
// is a benign no-op (not counted as inserted, not an error). Per-row
// validation failures (no identifier, malformed EK hash) are collected and
// returned so the caller can report partial success; they never abort the
// batch. Returns the number of NEW rows inserted plus any per-row errors.
func (r *IAMDevicePreRegRepository) BulkInsert(
	ctx context.Context, tenantID uuid.UUID, createdBy string, inputs []PreRegInput,
) (int, []PreRegRowError, error) {
	const q = `
INSERT INTO iam_device_preregistrations (
    tenant_id, ek_pubkey_hash, serial_number, asset_tag, model, note, created_by
) VALUES ($1, $2, $3, $4, $5, $6, $7)
ON CONFLICT DO NOTHING
RETURNING id`

	createdByPtr := strPtrOrNil(createdBy)
	inserted := 0
	var rowErrs []PreRegRowError

	for i, in := range inputs {
		var ekBytes []byte
		if in.EKPubkeyHash != "" {
			b, err := decodeEKHash(in.EKPubkeyHash)
			if err != nil {
				rowErrs = append(rowErrs, PreRegRowError{Index: i, Error: err.Error()})
				continue
			}
			ekBytes = b
		}
		if ekBytes == nil && in.SerialNumber == "" {
			rowErrs = append(rowErrs, PreRegRowError{
				Index: i,
				Error: "row has neither ek_pubkey_hash nor serial_number",
			})
			continue
		}

		var id uuid.UUID
		err := r.pool.QueryRow(ctx, q,
			tenantID, ekBytes, strPtrOrNil(in.SerialNumber),
			strPtrOrNil(in.AssetTag), strPtrOrNil(in.Model), strPtrOrNil(in.Note),
			createdByPtr,
		).Scan(&id)
		switch {
		case err == nil:
			inserted++
		case errors.Is(err, pgx.ErrNoRows):
			// ON CONFLICT DO NOTHING -> already pre-registered. Benign.
		default:
			rowErrs = append(rowErrs, PreRegRowError{Index: i, Error: err.Error()})
		}
	}
	return inserted, rowErrs, nil
}

// GetByEKPubkeyHash returns the pre-registration row for an EK pubkey hash, or
// pgx.ErrNoRows (wrapped) if the device is not a known corporate asset. This is
// the attest-time check jess calls. hash is 64-char lowercase hex.
func (r *IAMDevicePreRegRepository) GetByEKPubkeyHash(ctx context.Context, hash string) (IAMDevicePreRegRow, error) {
	b, err := decodeEKHash(hash)
	if err != nil {
		return IAMDevicePreRegRow{}, fmt.Errorf("iam_device_preregistrations: get_by_ek_pubkey_hash: %w", err)
	}
	const q = `
SELECT id, tenant_id, ek_pubkey_hash, serial_number, asset_tag, model, note, created_by, created_at
  FROM iam_device_preregistrations
 WHERE ek_pubkey_hash = $1`

	var row IAMDevicePreRegRow
	err = r.pool.QueryRow(ctx, q, b).Scan(
		&row.ID, &row.TenantID, &row.EKPubkeyHash, &row.SerialNumber,
		&row.AssetTag, &row.Model, &row.Note, &row.CreatedBy, &row.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return IAMDevicePreRegRow{}, fmt.Errorf("iam_device_preregistrations: get_by_ek_pubkey_hash: %w", pgx.ErrNoRows)
		}
		return IAMDevicePreRegRow{}, fmt.Errorf("iam_device_preregistrations: get_by_ek_pubkey_hash: %w", err)
	}
	return row, nil
}

// ListByTenant returns all pre-registrations for a tenant, newest first. An
// empty slice (not nil) is returned when the tenant has none.
func (r *IAMDevicePreRegRepository) ListByTenant(ctx context.Context, tenantID uuid.UUID) ([]IAMDevicePreRegRow, error) {
	const q = `
SELECT id, tenant_id, ek_pubkey_hash, serial_number, asset_tag, model, note, created_by, created_at
  FROM iam_device_preregistrations
 WHERE tenant_id = $1
 ORDER BY created_at DESC`

	rows, err := r.pool.Query(ctx, q, tenantID)
	if err != nil {
		return nil, fmt.Errorf("iam_device_preregistrations: list_by_tenant: %w", err)
	}
	defer rows.Close()

	out := make([]IAMDevicePreRegRow, 0)
	for rows.Next() {
		var row IAMDevicePreRegRow
		if err := rows.Scan(
			&row.ID, &row.TenantID, &row.EKPubkeyHash, &row.SerialNumber,
			&row.AssetTag, &row.Model, &row.Note, &row.CreatedBy, &row.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf("iam_device_preregistrations: list_by_tenant: scan: %w", err)
		}
		out = append(out, row)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iam_device_preregistrations: list_by_tenant: %w", err)
	}
	return out, nil
}

// DeleteByID removes a single pre-registration, scoped to its tenant so one
// tenant's admin cannot delete another's entry. Returns pgx.ErrNoRows (wrapped)
// when no matching row exists.
func (r *IAMDevicePreRegRepository) DeleteByID(ctx context.Context, tenantID, id uuid.UUID) error {
	const q = `DELETE FROM iam_device_preregistrations WHERE id = $1 AND tenant_id = $2`
	tag, err := r.pool.Exec(ctx, q, id, tenantID)
	if err != nil {
		return fmt.Errorf("iam_device_preregistrations: delete_by_id: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("iam_device_preregistrations: delete_by_id: %w", pgx.ErrNoRows)
	}
	return nil
}
