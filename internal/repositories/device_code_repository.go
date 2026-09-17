// SPDX-License-Identifier: AGPL-3.0-or-later

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

// DeviceCodeRepository provides database access for OAuth 2.0 device codes (RFC 8628).
type DeviceCodeRepository struct {
	db DBPool
}

// NewDeviceCodeRepository constructs a DeviceCodeRepository.
func NewDeviceCodeRepository(db *pgxpool.Pool) *DeviceCodeRepository {
	return &DeviceCodeRepository{db: db}
}

const deviceCodeSelectColumns = `
	id, tenant_id, client_id, device_code, user_code,
	verification_uri, verification_uri_complete, scopes, status,
	user_id, authorized_at, interval_seconds, last_polled_at, poll_count,
	expires_at, created_at`

func scanDeviceCode(row pgx.Row, d *models.OAuthDeviceCode) error {
	return row.Scan(
		&d.ID, &d.TenantID, &d.ClientID, &d.DeviceCode, &d.UserCode,
		&d.VerificationURI, &d.VerificationURIComplete, &d.Scopes, &d.Status,
		&d.UserID, &d.AuthorizedAt, &d.IntervalSeconds, &d.LastPolledAt, &d.PollCount,
		&d.ExpiresAt, &d.CreatedAt,
	)
}

// Create inserts a new device code record.
func (r *DeviceCodeRepository) Create(ctx context.Context, d *models.OAuthDeviceCode) error {
	if d.ID == uuid.Nil {
		d.ID = uuid.New()
	}
	query := `
		INSERT INTO iam_oauth_device_codes (
			id, tenant_id, client_id, device_code, user_code,
			verification_uri, verification_uri_complete, scopes,
			status, interval_seconds, expires_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
		RETURNING created_at`

	return r.db.QueryRow(ctx, query,
		d.ID, d.TenantID, d.ClientID, d.DeviceCode, d.UserCode,
		d.VerificationURI, d.VerificationURIComplete, d.Scopes,
		d.Status, d.IntervalSeconds, d.ExpiresAt,
	).Scan(&d.CreatedAt)
}

// GetByDeviceCode looks up a record by hashed device code.
func (r *DeviceCodeRepository) GetByDeviceCode(ctx context.Context, deviceCodeHash string) (*models.OAuthDeviceCode, error) {
	d := &models.OAuthDeviceCode{}
	err := scanDeviceCode(
		r.db.QueryRow(ctx,
			`SELECT `+deviceCodeSelectColumns+` FROM iam_oauth_device_codes WHERE device_code = $1`,
			deviceCodeHash,
		), d,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("DeviceCodeRepository.GetByDeviceCode: %w", err)
	}
	return d, nil
}

// GetByUserCode looks up a pending record by the human-readable user code.
func (r *DeviceCodeRepository) GetByUserCode(ctx context.Context, userCode string) (*models.OAuthDeviceCode, error) {
	d := &models.OAuthDeviceCode{}
	err := scanDeviceCode(
		r.db.QueryRow(ctx,
			`SELECT `+deviceCodeSelectColumns+` FROM iam_oauth_device_codes WHERE user_code = $1 AND status = 'pending'`,
			userCode,
		), d,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("DeviceCodeRepository.GetByUserCode: %w", err)
	}
	return d, nil
}

// Authorize marks a device code as authorized by a user.
func (r *DeviceCodeRepository) Authorize(ctx context.Context, id, userID uuid.UUID) error {
	now := time.Now()
	_, err := r.db.Exec(ctx,
		`UPDATE iam_oauth_device_codes
		 SET status = 'authorized', user_id = $1, authorized_at = $2
		 WHERE id = $3 AND status = 'pending'`,
		userID, now, id,
	)
	if err != nil {
		return fmt.Errorf("DeviceCodeRepository.Authorize: %w", err)
	}
	return nil
}

// Deny marks a device code as denied.
func (r *DeviceCodeRepository) Deny(ctx context.Context, id uuid.UUID) error {
	_, err := r.db.Exec(ctx,
		`UPDATE iam_oauth_device_codes SET status = 'denied' WHERE id = $1 AND status = 'pending'`,
		id,
	)
	if err != nil {
		return fmt.Errorf("DeviceCodeRepository.Deny: %w", err)
	}
	return nil
}

// Consume marks an authorized device code as consumed (token issued).
func (r *DeviceCodeRepository) Consume(ctx context.Context, id uuid.UUID) error {
	_, err := r.db.Exec(ctx,
		`UPDATE iam_oauth_device_codes SET status = 'consumed' WHERE id = $1 AND status = 'authorized'`,
		id,
	)
	if err != nil {
		return fmt.Errorf("DeviceCodeRepository.Consume: %w", err)
	}
	return nil
}

// RecordPoll updates the last_polled_at timestamp and increments poll_count.
func (r *DeviceCodeRepository) RecordPoll(ctx context.Context, id uuid.UUID) error {
	_, err := r.db.Exec(ctx,
		`UPDATE iam_oauth_device_codes
		 SET last_polled_at = NOW(), poll_count = poll_count + 1
		 WHERE id = $1`,
		id,
	)
	if err != nil {
		return fmt.Errorf("DeviceCodeRepository.RecordPoll: %w", err)
	}
	return nil
}

// ExpireOld marks all pending/authorized codes past their expiry as expired.
func (r *DeviceCodeRepository) ExpireOld(ctx context.Context) (int64, error) {
	result, err := r.db.Exec(ctx,
		`UPDATE iam_oauth_device_codes
		 SET status = 'expired'
		 WHERE status IN ('pending', 'authorized') AND expires_at < NOW()`,
	)
	if err != nil {
		return 0, fmt.Errorf("DeviceCodeRepository.ExpireOld: %w", err)
	}
	return result.RowsAffected(), nil
}
