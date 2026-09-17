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

// PushMFARepository persists push-MFA devices and challenges to PostgreSQL.
type PushMFARepository struct {
	db DBPool
}

// NewPushMFARepository creates a new PushMFARepository backed by the given pool.
func NewPushMFARepository(db *pgxpool.Pool) *PushMFARepository {
	return &PushMFARepository{db: db}
}

// --- Devices ---

// CreateDevice persists a new push-MFA device record. The push token must
// already be encrypted by the caller before being stored.
func (r *PushMFARepository) CreateDevice(ctx context.Context, d *models.PushMFADevice) error {
	if d.ID == uuid.Nil {
		d.ID = uuid.New()
	}
	const q = `
		INSERT INTO iam_push_mfa_devices
		    (id, user_id, device_name, platform, push_token_encrypted, public_key, registered_at)
		VALUES ($1, $2, $3, $4, $5, $6, NOW())
		RETURNING registered_at`

	err := r.db.QueryRow(ctx, q,
		d.ID, d.UserID, d.DeviceName, d.Platform,
		d.PushTokenEncrypted, d.PublicKey,
	).Scan(&d.RegisteredAt)
	if err != nil {
		return fmt.Errorf("PushMFARepository.CreateDevice: %w", err)
	}
	return nil
}

// GetDeviceByID returns the device identified by id, or nil if not found.
func (r *PushMFARepository) GetDeviceByID(ctx context.Context, id uuid.UUID) (*models.PushMFADevice, error) {
	const q = `
		SELECT id, user_id, device_name, platform, push_token_encrypted, public_key,
		       registered_at, last_used_at
		FROM iam_push_mfa_devices
		WHERE id = $1`

	d := &models.PushMFADevice{}
	err := r.db.QueryRow(ctx, q, id).Scan(
		&d.ID, &d.UserID, &d.DeviceName, &d.Platform,
		&d.PushTokenEncrypted, &d.PublicKey,
		&d.RegisteredAt, &d.LastUsedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("PushMFARepository.GetDeviceByID: %w", err)
	}
	return d, nil
}

// ListDevicesByUser returns all registered devices for a user.
func (r *PushMFARepository) ListDevicesByUser(ctx context.Context, userID uuid.UUID) ([]*models.PushMFADevice, error) {
	const q = `
		SELECT id, user_id, device_name, platform, push_token_encrypted, public_key,
		       registered_at, last_used_at
		FROM iam_push_mfa_devices
		WHERE user_id = $1
		ORDER BY registered_at DESC`

	rows, err := r.db.Query(ctx, q, userID)
	if err != nil {
		return nil, fmt.Errorf("PushMFARepository.ListDevicesByUser: %w", err)
	}
	defer rows.Close()

	var devices []*models.PushMFADevice
	for rows.Next() {
		d := &models.PushMFADevice{}
		if err := rows.Scan(
			&d.ID, &d.UserID, &d.DeviceName, &d.Platform,
			&d.PushTokenEncrypted, &d.PublicKey,
			&d.RegisteredAt, &d.LastUsedAt,
		); err != nil {
			return nil, fmt.Errorf("PushMFARepository.ListDevicesByUser scan: %w", err)
		}
		devices = append(devices, d)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("PushMFARepository.ListDevicesByUser rows: %w", err)
	}
	return devices, nil
}

// DeleteDevice removes the device only when it belongs to the given user.
// Returns false (no error) when the row was not found.
func (r *PushMFARepository) DeleteDevice(ctx context.Context, deviceID, userID uuid.UUID) (bool, error) {
	const q = `DELETE FROM iam_push_mfa_devices WHERE id = $1 AND user_id = $2`
	tag, err := r.db.Exec(ctx, q, deviceID, userID)
	if err != nil {
		return false, fmt.Errorf("PushMFARepository.DeleteDevice: %w", err)
	}
	return tag.RowsAffected() > 0, nil
}

// TouchDevice updates last_used_at on the device.
func (r *PushMFARepository) TouchDevice(ctx context.Context, deviceID uuid.UUID) error {
	const q = `UPDATE iam_push_mfa_devices SET last_used_at = NOW() WHERE id = $1`
	if _, err := r.db.Exec(ctx, q, deviceID); err != nil {
		return fmt.Errorf("PushMFARepository.TouchDevice: %w", err)
	}
	return nil
}

// --- Challenges ---

// CreateChallenge persists a new push challenge record.
func (r *PushMFARepository) CreateChallenge(ctx context.Context, c *models.PushMFAChallenge) error {
	if c.ID == uuid.Nil {
		c.ID = uuid.New()
	}
	const q = `
		INSERT INTO iam_push_mfa_challenges
		    (id, user_id, tenant_id, device_id, status, ip_address, user_agent,
		     geo_location, expires_at, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NOW())
		RETURNING created_at`

	err := r.db.QueryRow(ctx, q,
		c.ID, c.UserID, c.TenantID, c.DeviceID,
		string(c.Status), nilableString(c.IPAddress), nilableString(c.UserAgent),
		nilableString(c.GeoLocation), c.ExpiresAt,
	).Scan(&c.CreatedAt)
	if err != nil {
		return fmt.Errorf("PushMFARepository.CreateChallenge: %w", err)
	}
	return nil
}

// GetChallengeByID returns the challenge identified by id, or nil if not found.
func (r *PushMFARepository) GetChallengeByID(ctx context.Context, id uuid.UUID) (*models.PushMFAChallenge, error) {
	const q = `
		SELECT id, user_id, tenant_id, device_id, status,
		       COALESCE(ip_address::text, ''), COALESCE(user_agent, ''),
		       COALESCE(geo_location, ''), expires_at, created_at, responded_at
		FROM iam_push_mfa_challenges
		WHERE id = $1`

	c := &models.PushMFAChallenge{}
	var status string
	err := r.db.QueryRow(ctx, q, id).Scan(
		&c.ID, &c.UserID, &c.TenantID, &c.DeviceID, &status,
		&c.IPAddress, &c.UserAgent, &c.GeoLocation,
		&c.ExpiresAt, &c.CreatedAt, &c.RespondedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("PushMFARepository.GetChallengeByID: %w", err)
	}
	c.Status = models.PushMFAChallengeStatus(status)
	return c, nil
}

// UpdateChallengeStatus sets the status and responded_at timestamp on a challenge.
func (r *PushMFARepository) UpdateChallengeStatus(ctx context.Context, id uuid.UUID, status models.PushMFAChallengeStatus) error {
	const q = `
		UPDATE iam_push_mfa_challenges
		SET status = $2, responded_at = NOW()
		WHERE id = $1 AND status = 'pending'`

	tag, err := r.db.Exec(ctx, q, id, string(status))
	if err != nil {
		return fmt.Errorf("PushMFARepository.UpdateChallengeStatus: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("PushMFARepository.UpdateChallengeStatus: challenge not found or already resolved")
	}
	return nil
}

// ExpireChallenge transitions all pending challenges whose expiry has passed
// to the 'expired' status. Intended to be called periodically (e.g. background
// job or on-demand before a status poll returns a result).
func (r *PushMFARepository) ExpireChallenge(ctx context.Context, id uuid.UUID) error {
	const q = `
		UPDATE iam_push_mfa_challenges
		SET status = 'expired', responded_at = NOW()
		WHERE id = $1 AND status = 'pending' AND expires_at <= NOW()`

	if _, err := r.db.Exec(ctx, q, id); err != nil {
		return fmt.Errorf("PushMFARepository.ExpireChallenge: %w", err)
	}
	return nil
}

// ExpireStalePendingChallenges bulk-expires all pending challenges older than
// the configured TTL. Returns the number of rows updated.
func (r *PushMFARepository) ExpireStalePendingChallenges(ctx context.Context) (int64, error) {
	const q = `
		UPDATE iam_push_mfa_challenges
		SET status = 'expired', responded_at = NOW()
		WHERE status = 'pending' AND expires_at <= NOW()`

	tag, err := r.db.Exec(ctx, q)
	if err != nil {
		return 0, fmt.Errorf("PushMFARepository.ExpireStalePendingChallenges: %w", err)
	}
	return tag.RowsAffected(), nil
}

// GetLatestPendingChallenge returns the most recent pending challenge for the
// user, or nil when none exists.
func (r *PushMFARepository) GetLatestPendingChallenge(ctx context.Context, userID uuid.UUID) (*models.PushMFAChallenge, error) {
	const q = `
		SELECT id, user_id, tenant_id, device_id, status,
		       COALESCE(ip_address::text, ''), COALESCE(user_agent, ''),
		       COALESCE(geo_location, ''), expires_at, created_at, responded_at
		FROM iam_push_mfa_challenges
		WHERE user_id = $1 AND status = 'pending' AND expires_at > NOW()
		ORDER BY created_at DESC
		LIMIT 1`

	c := &models.PushMFAChallenge{}
	var status string
	err := r.db.QueryRow(ctx, q, userID).Scan(
		&c.ID, &c.UserID, &c.TenantID, &c.DeviceID, &status,
		&c.IPAddress, &c.UserAgent, &c.GeoLocation,
		&c.ExpiresAt, &c.CreatedAt, &c.RespondedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("PushMFARepository.GetLatestPendingChallenge: %w", err)
	}
	c.Status = models.PushMFAChallengeStatus(status)
	return c, nil
}

// --- helpers ---

// nilableString converts an empty string to nil so that optional text columns
// that map to a TEXT (not NOT NULL) DB column receive NULL instead of ”.
func nilableString(s string) interface{} {
	if s == "" {
		return nil
	}
	return s
}
