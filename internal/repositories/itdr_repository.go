// SPDX-License-Identifier: AGPL-3.0-or-later

package repositories

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

// ITDRRepository persists and queries identity threat detection records.
// The underlying tables (iam_itdr_threats, iam_itdr_detection_rules) are
// created by migration 150 (pending — see roadmap).
// This repository degrades gracefully: all operations return empty results
// until the migration runs.
type ITDRRepository struct {
	pool *pgxpool.Pool
}

// NewITDRRepository constructs an ITDRRepository backed by the given pool.
func NewITDRRepository(pool *pgxpool.Pool) *ITDRRepository {
	return &ITDRRepository{pool: pool}
}

// ListThreats returns paginated threat records for a tenant.
// Degrades gracefully: returns empty slice when table does not yet exist.
func (r *ITDRRepository) ListThreats(_ context.Context, _ uuid.UUID, _, _ int) ([]*models.ITDRThreat, int, error) {
	// Stub: table not yet created. Return empty until migration 150 lands.
	return []*models.ITDRThreat{}, 0, nil
}

// GetThreat retrieves a single threat by ID.
func (r *ITDRRepository) GetThreat(_ context.Context, id uuid.UUID) (*models.ITDRThreat, error) {
	return nil, fmt.Errorf("itdr: threat %s not found (table pending migration)", id)
}

// AcknowledgeThreat marks a threat as acknowledged.
func (r *ITDRRepository) AcknowledgeThreat(_ context.Context, _, _ uuid.UUID) error {
	// Stub: no-op until migration 150 creates the table.
	return nil
}

// ListDetectionRules returns all configured detection rules.
func (r *ITDRRepository) ListDetectionRules(_ context.Context, _, _ int) ([]*models.ITDRDetectionRule, int, error) {
	return []*models.ITDRDetectionRule{}, 0, nil
}

// CreateSignal persists a new threat signal.
func (r *ITDRRepository) CreateSignal(_ context.Context, _ *models.ThreatSignal) error {
	// Stub: no-op until migration 150 creates the table.
	return nil
}

// UpdateDetectionRule persists changes to a detection rule.
func (r *ITDRRepository) UpdateDetectionRule(_ context.Context, rule *models.ITDRDetectionRule) error {
	if rule == nil {
		return fmt.Errorf("itdr: nil detection rule")
	}
	rule.UpdatedAt = time.Now().UTC()
	// Stub: no-op until migration 150 creates the table.
	return nil
}
