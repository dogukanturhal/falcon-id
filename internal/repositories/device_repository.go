// SPDX-License-Identifier: AGPL-3.0-or-later

// Package repositories — DeviceRepository (legacy browser-fingerprint
// trusted-device store).
//
// Table rename history: backed `iam_devices` until 2026-06-14, then
// renamed to `iam_user_devices` to free the `iam_devices` name for the
// ZTNA Phase 3 hardware-cert registry (ADR 0043 / falcon-id!284). The
// rename was atomic with a `CREATE TABLE iam_devices` of the new schema
// in the same Keystone MigrationBundle; the two tables coexist
// post-rename and serve distinct concerns:
//   * iam_user_devices — this repository — browser fingerprint +
//     "remember-this-browser" trust per (user_id, fingerprint_hash).
//   * iam_devices — IAMDevicesRepository — hardware cert registry
//     (TPM/SE/StrongBox EK pubkey hash, device_uuid, attestation_path,
//     tier). Owned by jess-controller device-attest flow.
//
// The two tables share NO foreign-key relationship; jess looks up by
// EK pubkey hash (UNIQUE), the legacy login flow looks up by
// (user_id, fingerprint_hash). Keeping them separate avoids dragging
// legacy nullable columns into the ZTNA schema and vice versa.
package repositories

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

const msgDeviceGetByUserID = "GetByUserID: %w"

// DeviceRepository is an exported type.
type DeviceRepository struct {
	db      DBPool
	realmID *uuid.UUID
}

// WithRealmID returns a shallow clone of DeviceRepository scoped to the given realm.
func (r *DeviceRepository) WithRealmID(realmID uuid.UUID) *DeviceRepository {
	clone := *r
	clone.realmID = &realmID
	return &clone
}

// NewDeviceRepository is an exported function.
func NewDeviceRepository(db *pgxpool.Pool) *DeviceRepository {
	return &DeviceRepository{db: db}
}

// Create creates a new device record
func (r *DeviceRepository) Create(ctx context.Context, device *models.Device) error {
	query := `
		INSERT INTO iam_user_devices (
			id, user_id, fingerprint_hash, device_name, device_type,
			browser, os, is_trusted, last_ip, trust_expires_at
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		RETURNING first_seen_at, last_seen_at, created_at, updated_at`

	if device.ID == uuid.Nil {
		device.ID = uuid.New()
	}

	return r.db.QueryRow(ctx, query,
		device.ID, device.UserID, device.FingerprintHash, device.DeviceName,
		device.DeviceType, device.Browser, device.OS, device.IsTrusted,
		device.LastIP, device.TrustExpiresAt,
	).Scan(&device.FirstSeenAt, &device.LastSeenAt, &device.CreatedAt, &device.UpdatedAt)
}

// GetByID retrieves a device by ID
func (r *DeviceRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.Device, error) {
	device := &models.Device{}
	query := `
		SELECT id, user_id, fingerprint_hash, device_name, device_type,
			   browser, os, is_trusted, first_seen_at, last_seen_at,
			   last_ip, trust_expires_at, created_at, updated_at
		FROM iam_user_devices WHERE id = $1`

	err := r.db.QueryRow(ctx, query, id).Scan(
		&device.ID, &device.UserID, &device.FingerprintHash, &device.DeviceName,
		&device.DeviceType, &device.Browser, &device.OS, &device.IsTrusted,
		&device.FirstSeenAt, &device.LastSeenAt, &device.LastIP,
		&device.TrustExpiresAt, &device.CreatedAt, &device.UpdatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("GetByID: %w", err)
	}
	return device, nil
}

// GetByFingerprint retrieves a device by user ID and fingerprint hash
func (r *DeviceRepository) GetByFingerprint(ctx context.Context, userID uuid.UUID, fingerprintHash string) (*models.Device, error) {
	device := &models.Device{}
	query := `
		SELECT id, user_id, fingerprint_hash, device_name, device_type,
			   browser, os, is_trusted, first_seen_at, last_seen_at,
			   last_ip, trust_expires_at, created_at, updated_at
		FROM iam_user_devices
		WHERE user_id = $1 AND fingerprint_hash = $2`

	err := r.db.QueryRow(ctx, query, userID, fingerprintHash).Scan(
		&device.ID, &device.UserID, &device.FingerprintHash, &device.DeviceName,
		&device.DeviceType, &device.Browser, &device.OS, &device.IsTrusted,
		&device.FirstSeenAt, &device.LastSeenAt, &device.LastIP,
		&device.TrustExpiresAt, &device.CreatedAt, &device.UpdatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return device, fmt.Errorf("GetByFingerprint: %w", err)
	}
	return device, nil
}

// GetByUserID retrieves all devices for a user with pagination
func (r *DeviceRepository) GetByUserID(ctx context.Context, userID uuid.UUID, page, pageSize int) ([]models.Device, int64, error) {
	// Count total
	var total int64
	err := r.db.QueryRow(ctx,
		`SELECT COUNT(*) FROM iam_user_devices WHERE user_id = $1`,
		userID,
	).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf(msgDeviceGetByUserID, err)
	}

	// Get paginated results
	offset := (page - 1) * pageSize
	query := `
		SELECT id, user_id, fingerprint_hash, device_name, device_type,
			   browser, os, is_trusted, first_seen_at, last_seen_at,
			   last_ip, trust_expires_at, created_at, updated_at
		FROM iam_user_devices
		WHERE user_id = $1
		ORDER BY last_seen_at DESC
		LIMIT $2 OFFSET $3`

	rows, err := r.db.Query(ctx, query, userID, pageSize, offset)
	if err != nil {
		return nil, 0, fmt.Errorf(msgDeviceGetByUserID, err)
	}
	defer rows.Close()

	var devices []models.Device
	for rows.Next() {
		var device models.Device
		err := rows.Scan(
			&device.ID, &device.UserID, &device.FingerprintHash, &device.DeviceName,
			&device.DeviceType, &device.Browser, &device.OS, &device.IsTrusted,
			&device.FirstSeenAt, &device.LastSeenAt, &device.LastIP,
			&device.TrustExpiresAt, &device.CreatedAt, &device.UpdatedAt,
		)
		if err != nil {
			return nil, 0, fmt.Errorf(msgDeviceGetByUserID, err)
		}
		devices = append(devices, device)
	}

	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("GetByUserID: rows iteration: %w", err)
	}

	return devices, total, nil
}

// GetTrustedDevices retrieves all trusted devices for a user
func (r *DeviceRepository) GetTrustedDevices(ctx context.Context, userID uuid.UUID) ([]models.Device, error) {
	query := `
		SELECT id, user_id, fingerprint_hash, device_name, device_type,
			   browser, os, is_trusted, first_seen_at, last_seen_at,
			   last_ip, trust_expires_at, created_at, updated_at
		FROM iam_user_devices
		WHERE user_id = $1 AND is_trusted = true
		  AND (trust_expires_at IS NULL OR trust_expires_at > NOW())
		ORDER BY last_seen_at DESC`

	rows, err := r.db.Query(ctx, query, userID)
	if err != nil {
		return nil, fmt.Errorf("GetTrustedDevices: %w", err)
	}
	defer rows.Close()

	var devices []models.Device
	for rows.Next() {
		var device models.Device
		err := rows.Scan(
			&device.ID, &device.UserID, &device.FingerprintHash, &device.DeviceName,
			&device.DeviceType, &device.Browser, &device.OS, &device.IsTrusted,
			&device.FirstSeenAt, &device.LastSeenAt, &device.LastIP,
			&device.TrustExpiresAt, &device.CreatedAt, &device.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("GetTrustedDevices: %w", err)
		}
		devices = append(devices, device)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("GetTrustedDevices: rows iteration: %w", err)
	}

	return devices, nil
}

// Update updates a device
func (r *DeviceRepository) Update(ctx context.Context, device *models.Device) error {
	query := `
		UPDATE iam_user_devices SET
			device_name = $2, device_type = $3, browser = $4, os = $5,
			is_trusted = $6, last_seen_at = $7, last_ip = $8, trust_expires_at = $9
		WHERE id = $1
		RETURNING updated_at`

	return r.db.QueryRow(ctx, query,
		device.ID, device.DeviceName, device.DeviceType, device.Browser,
		device.OS, device.IsTrusted, device.LastSeenAt, device.LastIP,
		device.TrustExpiresAt,
	).Scan(&device.UpdatedAt)
}

// UpdateLastSeen updates the last seen timestamp and IP for a device
func (r *DeviceRepository) UpdateLastSeen(ctx context.Context, id uuid.UUID, ip string) error {
	_, err := r.db.Exec(ctx,
		`UPDATE iam_user_devices SET last_seen_at = NOW(), last_ip = $2 WHERE id = $1`,
		id, ip,
	)
	if err != nil {
		return fmt.Errorf("UpdateLastSeen: %w", err)
	}
	return nil
}

// TrustDevice marks a device as trusted
func (r *DeviceRepository) TrustDevice(ctx context.Context, id uuid.UUID, expiresAt *time.Time) error {
	_, err := r.db.Exec(ctx,
		`UPDATE iam_user_devices SET is_trusted = true, trust_expires_at = $2 WHERE id = $1`,
		id, expiresAt,
	)
	if err != nil {
		return fmt.Errorf("TrustDevice: %w", err)
	}
	return nil
}

// UntrustDevice removes trust from a device
func (r *DeviceRepository) UntrustDevice(ctx context.Context, id uuid.UUID) error {
	_, err := r.db.Exec(ctx,
		`UPDATE iam_user_devices SET is_trusted = false, trust_expires_at = NULL WHERE id = $1`,
		id,
	)
	if err != nil {
		return fmt.Errorf("UntrustDevice: %w", err)
	}
	return nil
}

// Delete deletes a device
func (r *DeviceRepository) Delete(ctx context.Context, id uuid.UUID) error {
	_, err := r.db.Exec(ctx, `DELETE FROM iam_user_devices WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("Delete: %w", err)
	}
	return nil
}

// DeleteByUserID deletes all devices for a user
func (r *DeviceRepository) DeleteByUserID(ctx context.Context, userID uuid.UUID) error {
	_, err := r.db.Exec(ctx, `DELETE FROM iam_user_devices WHERE user_id = $1`, userID)
	if err != nil {
		return fmt.Errorf("DeleteByUserID: %w", err)
	}
	return nil
}

// UpsertDevice inserts or updates a device based on fingerprint
func (r *DeviceRepository) UpsertDevice(ctx context.Context, device *models.Device) error {
	query := `
		INSERT INTO iam_user_devices (
			id, user_id, fingerprint_hash, device_name, device_type,
			browser, os, is_trusted, last_ip
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		ON CONFLICT (user_id, fingerprint_hash) DO UPDATE SET
			device_name = EXCLUDED.device_name,
			device_type = EXCLUDED.device_type,
			browser = EXCLUDED.browser,
			os = EXCLUDED.os,
			last_seen_at = NOW(),
			last_ip = EXCLUDED.last_ip
		RETURNING id, first_seen_at, last_seen_at, is_trusted, trust_expires_at, created_at, updated_at`

	if device.ID == uuid.Nil {
		device.ID = uuid.New()
	}

	return r.db.QueryRow(ctx, query,
		device.ID, device.UserID, device.FingerprintHash, device.DeviceName,
		device.DeviceType, device.Browser, device.OS, device.IsTrusted, device.LastIP,
	).Scan(
		&device.ID, &device.FirstSeenAt, &device.LastSeenAt,
		&device.IsTrusted, &device.TrustExpiresAt, &device.CreatedAt, &device.UpdatedAt,
	)
}

// CountUserDevices counts the number of devices for a user
func (r *DeviceRepository) CountUserDevices(ctx context.Context, userID uuid.UUID) (int64, error) {
	var count int64
	err := r.db.QueryRow(ctx,
		`SELECT COUNT(*) FROM iam_user_devices WHERE user_id = $1`,
		userID,
	).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("CountUserDevices: %w", err)
	}
	return count, nil
}

// CleanupExpiredTrust removes trust from devices with expired trust
func (r *DeviceRepository) CleanupExpiredTrust(ctx context.Context) (int64, error) {
	result, err := r.db.Exec(ctx,
		`UPDATE iam_user_devices SET is_trusted = false, trust_expires_at = NULL
		 WHERE is_trusted = true AND trust_expires_at IS NOT NULL AND trust_expires_at < NOW()`,
	)
	if err != nil {
		return 0, fmt.Errorf("CleanupExpiredTrust: %w", err)
	}
	return result.RowsAffected(), nil
}

// IsTrustedDevice checks if a device with the given fingerprint is trusted for a user
func (r *DeviceRepository) IsTrustedDevice(ctx context.Context, userID uuid.UUID, fingerprintHash string) (bool, error) {
	var isTrusted bool
	err := r.db.QueryRow(ctx,
		`SELECT is_trusted FROM iam_user_devices
		 WHERE user_id = $1 AND fingerprint_hash = $2
		   AND is_trusted = true
		   AND (trust_expires_at IS NULL OR trust_expires_at > NOW())`,
		userID, fingerprintHash,
	).Scan(&isTrusted)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("IsTrustedDevice: %w", err)
	}
	return isTrusted, nil
}
