// SPDX-License-Identifier: AGPL-3.0-or-later

// Package repositories implements data access layer.
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

// AccessReviewRepository handles persistence for access review campaigns and items.
type AccessReviewRepository struct {
	db DBPool
}

// NewAccessReviewRepository creates a new AccessReviewRepository.
func NewAccessReviewRepository(db *pgxpool.Pool) *AccessReviewRepository {
	return &AccessReviewRepository{db: db}
}

// CreateCampaign persists a new access review campaign and populates its generated fields.
func (r *AccessReviewRepository) CreateCampaign(ctx context.Context, c *models.AccessReviewCampaign) error {
	if c.ID == uuid.Nil {
		c.ID = uuid.New()
	}

	query := `
		INSERT INTO access_review_campaigns (
			id, tenant_id, name, description, resource_type, reviewer_type,
			frequency, duration_days, auto_revoke, status, starts_at, ends_at, created_by
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
		RETURNING created_at, updated_at`

	return r.db.QueryRow(ctx, query,
		c.ID, c.TenantID, c.Name, c.Description, c.ResourceType, c.ReviewerType,
		c.Frequency, c.DurationDays, c.AutoRevoke, c.Status, c.StartsAt, c.EndsAt, c.CreatedBy,
	).Scan(&c.CreatedAt, &c.UpdatedAt)
}

// GetCampaignByID retrieves a single campaign scoped to a tenant.
func (r *AccessReviewRepository) GetCampaignByID(ctx context.Context, campaignID, tenantID uuid.UUID) (*models.AccessReviewCampaign, error) {
	query := `
		SELECT id, tenant_id, name, description, resource_type, reviewer_type,
		       frequency, duration_days, auto_revoke, status, starts_at, ends_at,
		       created_by, created_at, updated_at
		FROM access_review_campaigns
		WHERE id = $1 AND tenant_id = $2`

	c := &models.AccessReviewCampaign{}
	err := r.db.QueryRow(ctx, query, campaignID, tenantID).Scan(
		&c.ID, &c.TenantID, &c.Name, &c.Description, &c.ResourceType, &c.ReviewerType,
		&c.Frequency, &c.DurationDays, &c.AutoRevoke, &c.Status, &c.StartsAt, &c.EndsAt,
		&c.CreatedBy, &c.CreatedAt, &c.UpdatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("GetCampaignByID: %w", err)
	}
	return c, nil
}

// ListCampaigns returns a paginated list of campaigns for a tenant, optionally filtered by status.
func (r *AccessReviewRepository) ListCampaigns(ctx context.Context, tenantID uuid.UUID, status string, page, pageSize int) ([]*models.AccessReviewCampaign, int64, error) {
	offset := (page - 1) * pageSize

	args := []interface{}{tenantID}
	where := "WHERE tenant_id = $1"
	argIdx := 2

	if status != "" {
		where += fmt.Sprintf(" AND status = $%d", argIdx)
		args = append(args, status)
		argIdx++
	}

	var total int64
	countQuery := "SELECT COUNT(*) FROM access_review_campaigns " + where
	if err := r.db.QueryRow(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("ListCampaigns count: %w", err)
	}

	listQuery := fmt.Sprintf(`
		SELECT id, tenant_id, name, description, resource_type, reviewer_type,
		       frequency, duration_days, auto_revoke, status, starts_at, ends_at,
		       created_by, created_at, updated_at
		FROM access_review_campaigns
		%s
		ORDER BY created_at DESC
		LIMIT $%d OFFSET $%d`, where, argIdx, argIdx+1)

	args = append(args, pageSize, offset)

	rows, err := r.db.Query(ctx, listQuery, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("ListCampaigns: %w", err)
	}
	defer rows.Close()

	var campaigns []*models.AccessReviewCampaign
	for rows.Next() {
		c := &models.AccessReviewCampaign{}
		if err := rows.Scan(
			&c.ID, &c.TenantID, &c.Name, &c.Description, &c.ResourceType, &c.ReviewerType,
			&c.Frequency, &c.DurationDays, &c.AutoRevoke, &c.Status, &c.StartsAt, &c.EndsAt,
			&c.CreatedBy, &c.CreatedAt, &c.UpdatedAt,
		); err != nil {
			return nil, 0, fmt.Errorf("ListCampaigns scan: %w", err)
		}
		campaigns = append(campaigns, c)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("ListCampaigns rows: %w", err)
	}

	return campaigns, total, nil
}

// UpdateCampaignStatus transitions a campaign to a new status.
func (r *AccessReviewRepository) UpdateCampaignStatus(ctx context.Context, campaignID uuid.UUID, status models.AccessReviewCampaignStatus) error {
	query := `UPDATE access_review_campaigns SET status = $2, updated_at = NOW() WHERE id = $1`
	tag, err := r.db.Exec(ctx, query, campaignID, status)
	if err != nil {
		return fmt.Errorf("UpdateCampaignStatus: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("UpdateCampaignStatus: campaign %s not found", campaignID)
	}
	return nil
}

// CreateReviewItems batch-inserts review items for a campaign.
func (r *AccessReviewRepository) CreateReviewItems(ctx context.Context, items []*models.AccessReviewItem) error {
	if len(items) == 0 {
		return nil
	}

	query := `
		INSERT INTO access_review_items (
			id, campaign_id, tenant_id, user_id, resource_type, resource_id,
			resource_name, reviewer_id, decision
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		RETURNING created_at`

	for _, item := range items {
		if item.ID == uuid.Nil {
			item.ID = uuid.New()
		}
		if item.Decision == "" {
			item.Decision = models.DecisionPending
		}
		if err := r.db.QueryRow(ctx, query,
			item.ID, item.CampaignID, item.TenantID, item.UserID,
			item.ResourceType, item.ResourceID, item.ResourceName,
			item.ReviewerID, item.Decision,
		).Scan(&item.CreatedAt); err != nil {
			return fmt.Errorf("CreateReviewItems insert item %s: %w", item.ID, err)
		}
	}
	return nil
}

// GetReviewItem retrieves a single review item scoped to a tenant.
func (r *AccessReviewRepository) GetReviewItem(ctx context.Context, itemID, tenantID uuid.UUID) (*models.AccessReviewItem, error) {
	query := `
		SELECT id, campaign_id, tenant_id, user_id, resource_type, resource_id,
		       resource_name, reviewer_id, decision, justification, decided_at, created_at
		FROM access_review_items
		WHERE id = $1 AND tenant_id = $2`

	item := &models.AccessReviewItem{}
	err := r.db.QueryRow(ctx, query, itemID, tenantID).Scan(
		&item.ID, &item.CampaignID, &item.TenantID, &item.UserID, &item.ResourceType,
		&item.ResourceID, &item.ResourceName, &item.ReviewerID, &item.Decision,
		&item.Justification, &item.DecidedAt, &item.CreatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("GetReviewItem: %w", err)
	}
	return item, nil
}

// ListPendingItems returns all pending review items assigned to a specific reviewer.
func (r *AccessReviewRepository) ListPendingItems(ctx context.Context, reviewerID, tenantID uuid.UUID) ([]*models.AccessReviewItem, error) {
	query := `
		SELECT id, campaign_id, tenant_id, user_id, resource_type, resource_id,
		       resource_name, reviewer_id, decision, justification, decided_at, created_at
		FROM access_review_items
		WHERE reviewer_id = $1 AND tenant_id = $2 AND decision = 'pending'
		ORDER BY created_at ASC`

	rows, err := r.db.Query(ctx, query, reviewerID, tenantID)
	if err != nil {
		return nil, fmt.Errorf("ListPendingItems: %w", err)
	}
	defer rows.Close()

	return r.scanItems(rows)
}

// SubmitDecision records an approve/deny decision on a review item.
func (r *AccessReviewRepository) SubmitDecision(ctx context.Context, itemID uuid.UUID, decision models.ReviewDecision, justification string) error {
	now := time.Now().UTC()
	query := `
		UPDATE access_review_items
		SET decision = $2, justification = $3, decided_at = $4
		WHERE id = $1 AND decision = 'pending'`

	tag, err := r.db.Exec(ctx, query, itemID, decision, justification, now)
	if err != nil {
		return fmt.Errorf("SubmitDecision: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("SubmitDecision: item %s not found or already decided", itemID)
	}
	return nil
}

// GetCampaignStats returns aggregate decision counts for a campaign.
func (r *AccessReviewRepository) GetCampaignStats(ctx context.Context, campaignID uuid.UUID) (*models.AccessReviewCampaignStats, error) {
	query := `
		SELECT
			COUNT(*) FILTER (WHERE decision = 'pending')  AS pending_items,
			COUNT(*) FILTER (WHERE decision = 'approved') AS approved_items,
			COUNT(*) FILTER (WHERE decision = 'denied')   AS denied_items,
			COUNT(*) FILTER (WHERE decision = 'expired')  AS expired_items,
			COUNT(*)                                      AS total_items
		FROM access_review_items
		WHERE campaign_id = $1`

	stats := &models.AccessReviewCampaignStats{}
	err := r.db.QueryRow(ctx, query, campaignID).Scan(
		&stats.PendingItems, &stats.ApprovedItems,
		&stats.DeniedItems, &stats.ExpiredItems, &stats.TotalItems,
	)
	if err != nil {
		return nil, fmt.Errorf("GetCampaignStats: %w", err)
	}
	return stats, nil
}

// ListExpiredPendingItems returns all still-pending items for a campaign.
// Used during finalization to bulk-expire undecided items.
func (r *AccessReviewRepository) ListExpiredPendingItems(ctx context.Context, campaignID uuid.UUID) ([]*models.AccessReviewItem, error) {
	query := `
		SELECT id, campaign_id, tenant_id, user_id, resource_type, resource_id,
		       resource_name, reviewer_id, decision, justification, decided_at, created_at
		FROM access_review_items
		WHERE campaign_id = $1 AND decision = 'pending'`

	rows, err := r.db.Query(ctx, query, campaignID)
	if err != nil {
		return nil, fmt.Errorf("ListExpiredPendingItems: %w", err)
	}
	defer rows.Close()

	return r.scanItems(rows)
}

// scanItems is a shared helper for scanning review item rows.
func (r *AccessReviewRepository) scanItems(rows pgx.Rows) ([]*models.AccessReviewItem, error) {
	var items []*models.AccessReviewItem
	for rows.Next() {
		item := &models.AccessReviewItem{}
		if err := rows.Scan(
			&item.ID, &item.CampaignID, &item.TenantID, &item.UserID, &item.ResourceType,
			&item.ResourceID, &item.ResourceName, &item.ReviewerID, &item.Decision,
			&item.Justification, &item.DecidedAt, &item.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan review item: %w", err)
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("review items rows: %w", err)
	}
	return items, nil
}
