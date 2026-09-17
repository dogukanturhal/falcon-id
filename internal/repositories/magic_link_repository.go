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

// MagicLinkRepository is an exported type.
type MagicLinkRepository struct {
	db      DBPool
	realmID *uuid.UUID
}

// WithRealmID returns a shallow clone of MagicLinkRepository scoped to the given realm.
func (r *MagicLinkRepository) WithRealmID(realmID uuid.UUID) *MagicLinkRepository {
	clone := *r
	clone.realmID = &realmID
	return &clone
}

// NewMagicLinkRepository is an exported function.
func NewMagicLinkRepository(db *pgxpool.Pool) *MagicLinkRepository {
	return &MagicLinkRepository{db: db}
}

// Create creates a new magic link
func (r *MagicLinkRepository) Create(ctx context.Context, link *models.MagicLink) error {
	query := `
		INSERT INTO iam_magic_links (id, user_id, email, token_hash, ip_address, user_agent, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		RETURNING created_at`

	if link.ID == uuid.Nil {
		link.ID = uuid.New()
	}

	return r.db.QueryRow(ctx, query,
		link.ID, link.UserID, link.Email, link.TokenHash,
		link.IPAddress, link.UserAgent, link.ExpiresAt,
	).Scan(&link.CreatedAt)
}

// GetByTokenHash retrieves a magic link by token hash
func (r *MagicLinkRepository) GetByTokenHash(ctx context.Context, tokenHash string) (*models.MagicLink, error) {
	link := &models.MagicLink{}
	query := `
		SELECT id, user_id, email, token_hash, ip_address, user_agent, used_at, expires_at, created_at
		FROM iam_magic_links WHERE token_hash = $1`

	err := r.db.QueryRow(ctx, query, tokenHash).Scan(
		&link.ID, &link.UserID, &link.Email, &link.TokenHash,
		&link.IPAddress, &link.UserAgent, &link.UsedAt, &link.ExpiresAt, &link.CreatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("GetByTokenHash: %w", err)
	}
	return link, nil
}

// MarkAsUsed marks a magic link as used
func (r *MagicLinkRepository) MarkAsUsed(ctx context.Context, id uuid.UUID) error {
	_, err := r.db.Exec(ctx,
		`UPDATE iam_magic_links SET used_at = NOW() WHERE id = $1`,
		id,
	)
	if err != nil {
		return fmt.Errorf("MarkAsUsed: %w", err)
	}
	return nil
}

// DeleteExpired deletes expired magic links
func (r *MagicLinkRepository) DeleteExpired(ctx context.Context) (int64, error) {
	result, err := r.db.Exec(ctx,
		`DELETE FROM iam_magic_links WHERE expires_at < NOW()`,
	)
	if err != nil {
		return 0, fmt.Errorf("DeleteExpired: %w", err)
	}
	return result.RowsAffected(), nil
}

// DeleteByEmail deletes all magic links for an email
func (r *MagicLinkRepository) DeleteByEmail(ctx context.Context, email string) error {
	_, err := r.db.Exec(ctx, `DELETE FROM iam_magic_links WHERE email = $1`, email)
	if err != nil {
		return fmt.Errorf("DeleteByEmail: %w", err)
	}
	return nil
}

// CountRecentByEmail counts recent magic links for an email (for rate limiting)
func (r *MagicLinkRepository) CountRecentByEmail(ctx context.Context, email string, since time.Time) (int, error) {
	var count int
	err := r.db.QueryRow(ctx,
		`SELECT COUNT(*) FROM iam_magic_links WHERE email = $1 AND created_at > $2`,
		email, since,
	).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("CountRecentByEmail: %w", err)
	}
	return count, nil
}

// CountRecentByIP counts recent magic links from an IP (for rate limiting)
func (r *MagicLinkRepository) CountRecentByIP(ctx context.Context, ip string, since time.Time) (int, error) {
	var count int
	err := r.db.QueryRow(ctx,
		`SELECT COUNT(*) FROM iam_magic_links WHERE ip_address = $1 AND created_at > $2`,
		ip, since,
	).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("CountRecentByIP: %w", err)
	}
	return count, nil
}
