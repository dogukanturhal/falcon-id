// SPDX-License-Identifier: AGPL-3.0-or-later

package repositories

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

// SSFRepository persists Shared Signals Framework stream subscriptions.
// The underlying table (iam_ssf_streams) is created by migration 151 (pending).
// All operations degrade gracefully until the migration runs.
type SSFRepository struct {
	pool *pgxpool.Pool
}

// NewSSFRepository constructs an SSFRepository.
func NewSSFRepository(pool *pgxpool.Pool) *SSFRepository {
	return &SSFRepository{pool: pool}
}

// CreateStream persists a new SSF stream. Stub until migration 151.
func (r *SSFRepository) CreateStream(_ context.Context, stream *models.SSFStream) error {
	if stream == nil {
		return fmt.Errorf("ssf: nil stream")
	}
	return nil
}

// ListStreams returns all streams for a tenant. Stub until migration 151.
func (r *SSFRepository) ListStreams(_ context.Context, _ uuid.UUID) ([]*models.SSFStream, error) {
	return []*models.SSFStream{}, nil
}

// GetStream retrieves a stream by ID. Stub until migration 151.
func (r *SSFRepository) GetStream(_ context.Context, id uuid.UUID) (*models.SSFStream, error) {
	return nil, fmt.Errorf("ssf: stream %s not found (table pending migration)", id)
}

// UpdateStream updates an existing SSF stream. Stub until migration 151.
// Delegates to CreateStream because both operations share identical validation
// and no-op persistence logic until migration 151 is applied.
func (r *SSFRepository) UpdateStream(ctx context.Context, stream *models.SSFStream) error {
	return r.CreateStream(ctx, stream)
}

// DeleteStream removes an SSF stream. Stub until migration 151.
func (r *SSFRepository) DeleteStream(_ context.Context, _ uuid.UUID) error {
	return nil
}
