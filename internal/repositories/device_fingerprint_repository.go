// SPDX-License-Identifier: AGPL-3.0-or-later

package repositories

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

// DeviceFingerprintRepository handles persistence for iam_device_fingerprints.
type DeviceFingerprintRepository struct {
	db DBPool
}

// NewDeviceFingerprintRepository creates a new DeviceFingerprintRepository.
func NewDeviceFingerprintRepository(db *pgxpool.Pool) *DeviceFingerprintRepository {
	return &DeviceFingerprintRepository{db: db}
}

// Upsert inserts a new fingerprint record or updates last_seen_at, ip_address and
// login_count when the (user_id, fingerprint_hash) pair already exists.
// On insert the returned record has all DB-generated fields populated.
// On update only last_seen_at, ip_address, and login_count are mutated; the
// trust_level set by TrustDevice / MarkSuspicious is preserved.
func (r *DeviceFingerprintRepository) Upsert(ctx context.Context, rec *models.DeviceFingerprintRecord) error {
	if rec.ID == uuid.Nil {
		rec.ID = uuid.New()
	}

	query := `
		INSERT INTO iam_device_fingerprints (
			id, user_id, tenant_id, fingerprint_hash,
			user_agent, platform, browser, browser_version,
			screen_res, timezone, language,
			ip_address, geo_country, geo_city,
			trust_level, login_count
		) VALUES (
			$1, $2, $3, $4,
			$5, $6, $7, $8,
			$9, $10, $11,
			$12::inet, $13, $14,
			$15, 1
		)
		ON CONFLICT (user_id, fingerprint_hash) DO UPDATE SET
			last_seen_at  = NOW(),
			ip_address    = EXCLUDED.ip_address,
			login_count   = iam_device_fingerprints.login_count + 1
		RETURNING id, first_seen_at, last_seen_at, trust_level, login_count`

	return r.db.QueryRow(ctx, query,
		rec.ID, rec.UserID, rec.TenantID, rec.FingerprintHash,
		rec.UserAgent, rec.Platform, rec.Browser, rec.BrowserVersion,
		rec.ScreenRes, rec.Timezone, rec.Language,
		nullableString(rec.IPAddress), rec.GeoCountry, rec.GeoCity,
		string(rec.TrustLevel),
	).Scan(&rec.ID, &rec.FirstSeenAt, &rec.LastSeenAt, &rec.TrustLevel, &rec.LoginCount)
}

// GetByID retrieves a fingerprint record by its primary key.
// Returns (nil, nil) when the row does not exist.
func (r *DeviceFingerprintRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.DeviceFingerprintRecord, error) {
	rec := &models.DeviceFingerprintRecord{}
	query := `
		SELECT id, user_id, tenant_id, fingerprint_hash,
		       user_agent, platform, browser, browser_version,
		       screen_res, timezone, language,
		       COALESCE(ip_address::text, ''), geo_country, geo_city,
		       first_seen_at, last_seen_at, trust_level, login_count
		FROM iam_device_fingerprints
		WHERE id = $1`

	err := r.db.QueryRow(ctx, query, id).Scan(
		&rec.ID, &rec.UserID, &rec.TenantID, &rec.FingerprintHash,
		&rec.UserAgent, &rec.Platform, &rec.Browser, &rec.BrowserVersion,
		&rec.ScreenRes, &rec.Timezone, &rec.Language,
		&rec.IPAddress, &rec.GeoCountry, &rec.GeoCity,
		&rec.FirstSeenAt, &rec.LastSeenAt, &rec.TrustLevel, &rec.LoginCount,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("GetByID: %w", err)
	}
	return rec, nil
}

// GetByHash looks up a fingerprint record by (user_id, fingerprint_hash).
// Returns (nil, nil) when no match is found.
func (r *DeviceFingerprintRepository) GetByHash(ctx context.Context, userID uuid.UUID, hash string) (*models.DeviceFingerprintRecord, error) {
	rec := &models.DeviceFingerprintRecord{}
	query := `
		SELECT id, user_id, tenant_id, fingerprint_hash,
		       user_agent, platform, browser, browser_version,
		       screen_res, timezone, language,
		       COALESCE(ip_address::text, ''), geo_country, geo_city,
		       first_seen_at, last_seen_at, trust_level, login_count
		FROM iam_device_fingerprints
		WHERE user_id = $1 AND fingerprint_hash = $2`

	err := r.db.QueryRow(ctx, query, userID, hash).Scan(
		&rec.ID, &rec.UserID, &rec.TenantID, &rec.FingerprintHash,
		&rec.UserAgent, &rec.Platform, &rec.Browser, &rec.BrowserVersion,
		&rec.ScreenRes, &rec.Timezone, &rec.Language,
		&rec.IPAddress, &rec.GeoCountry, &rec.GeoCity,
		&rec.FirstSeenAt, &rec.LastSeenAt, &rec.TrustLevel, &rec.LoginCount,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("GetByHash: %w", err)
	}
	return rec, nil
}

// ListByUser returns all fingerprint records for a given user, ordered by
// last_seen_at descending (most recent first).
func (r *DeviceFingerprintRepository) ListByUser(ctx context.Context, userID, tenantID uuid.UUID) ([]models.DeviceFingerprintRecord, error) {
	query := `
		SELECT id, user_id, tenant_id, fingerprint_hash,
		       user_agent, platform, browser, browser_version,
		       screen_res, timezone, language,
		       COALESCE(ip_address::text, ''), geo_country, geo_city,
		       first_seen_at, last_seen_at, trust_level, login_count
		FROM iam_device_fingerprints
		WHERE user_id = $1 AND tenant_id = $2
		ORDER BY last_seen_at DESC`

	rows, err := r.db.Query(ctx, query, userID, tenantID)
	if err != nil {
		return nil, fmt.Errorf("ListByUser: %w", err)
	}
	defer rows.Close()

	var records []models.DeviceFingerprintRecord
	for rows.Next() {
		var rec models.DeviceFingerprintRecord
		if err := rows.Scan(
			&rec.ID, &rec.UserID, &rec.TenantID, &rec.FingerprintHash,
			&rec.UserAgent, &rec.Platform, &rec.Browser, &rec.BrowserVersion,
			&rec.ScreenRes, &rec.Timezone, &rec.Language,
			&rec.IPAddress, &rec.GeoCountry, &rec.GeoCity,
			&rec.FirstSeenAt, &rec.LastSeenAt, &rec.TrustLevel, &rec.LoginCount,
		); err != nil {
			return nil, fmt.Errorf("ListByUser: scan: %w", err)
		}
		records = append(records, rec)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("ListByUser: rows: %w", err)
	}
	return records, nil
}

// SetTrustLevel updates the trust_level for a single row identified by id.
func (r *DeviceFingerprintRepository) SetTrustLevel(ctx context.Context, id uuid.UUID, level models.FingerprintTrustLevel) error {
	_, err := r.db.Exec(ctx,
		`UPDATE iam_device_fingerprints SET trust_level = $2 WHERE id = $1`,
		id, string(level),
	)
	if err != nil {
		return fmt.Errorf("SetTrustLevel: %w", err)
	}
	return nil
}

// Delete removes a single fingerprint record.
func (r *DeviceFingerprintRepository) Delete(ctx context.Context, id uuid.UUID) error {
	_, err := r.db.Exec(ctx,
		`DELETE FROM iam_device_fingerprints WHERE id = $1`,
		id,
	)
	if err != nil {
		return fmt.Errorf("Delete: %w", err)
	}
	return nil
}

// IsKnownHash returns true when (userID, hash) already exists in the table.
// This is the hot-path for adaptive MFA skip decisions — it avoids a full row
// scan by using the unique index on (user_id, fingerprint_hash).
func (r *DeviceFingerprintRepository) IsKnownHash(ctx context.Context, userID uuid.UUID, hash string) (bool, error) {
	var exists bool
	err := r.db.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM iam_device_fingerprints WHERE user_id = $1 AND fingerprint_hash = $2)`,
		userID, hash,
	).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("IsKnownHash: %w", err)
	}
	return exists, nil
}

// nullableString returns nil for empty strings so PostgreSQL does not
// try to cast an empty string to the inet type.
func nullableString(s string) interface{} {
	if s == "" {
		return nil
	}
	return s
}
