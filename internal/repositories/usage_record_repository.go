// SPDX-License-Identifier: AGPL-3.0-or-later

package repositories

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/jackc/pgx/v5/pgxpool"
)

// UsageRecordRepository handles database operations for tenant usage metering records.
type UsageRecordRepository struct {
	db *pgxpool.Pool
}

// NewUsageRecordRepository creates a new UsageRecordRepository.
func NewUsageRecordRepository(db *pgxpool.Pool) *UsageRecordRepository {
	return &UsageRecordRepository{db: db}
}

// Record performs an idempotent upsert of a usage record.
// On conflict on (tenant_id, product_id, metric_name, period_start) the value
// and metadata are updated in place, matching the billing aggregator contract.
// The server-generated ID and RecordedAt timestamp are populated on the record.
func (r *UsageRecordRepository) Record(ctx context.Context, record *models.UsageRecord) error {
	if record.ID == uuid.Nil {
		record.ID = uuid.New()
	}

	metadataJSON, err := json.Marshal(record.Metadata)
	if err != nil {
		return fmt.Errorf("UsageRecordRepository.Record marshal metadata: %w", err)
	}

	query := `
		INSERT INTO iam_usage_records (
			id, tenant_id, product_id, metric_name, value,
			period_start, period_end, metadata
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		ON CONFLICT (tenant_id, product_id, metric_name, period_start)
		DO UPDATE SET
			value       = EXCLUDED.value,
			period_end  = EXCLUDED.period_end,
			metadata    = EXCLUDED.metadata,
			recorded_at = NOW()
		RETURNING id, recorded_at
	`

	err = r.db.QueryRow(ctx, query,
		record.ID,
		record.TenantID,
		record.ProductID,
		record.MetricName,
		record.Value,
		record.PeriodStart,
		record.PeriodEnd,
		metadataJSON,
	).Scan(&record.ID, &record.RecordedAt)
	if err != nil {
		return fmt.Errorf("UsageRecordRepository.Record: %w", err)
	}
	return nil
}

// GetByTenantAndProduct retrieves the usage record that matches the given tenant,
// product, metric name, and period window (period_start, period_end).
// Returns an error wrapping pgx.ErrNoRows when no record is found.
func (r *UsageRecordRepository) GetByTenantAndProduct(
	ctx context.Context,
	tenantID, productID uuid.UUID,
	metricName string,
	periodStart, periodEnd time.Time,
) (*models.UsageRecord, error) {
	query := `
		SELECT id, tenant_id, product_id, metric_name, value,
		       period_start, period_end, recorded_at, metadata
		FROM iam_usage_records
		WHERE tenant_id   = $1
		  AND product_id  = $2
		  AND metric_name = $3
		  AND period_start = $4
		  AND period_end   = $5
	`

	return r.scanOne(ctx, query, tenantID, productID, metricName, periodStart, periodEnd)
}

// scanOne scans a single row from iam_usage_records.
func (r *UsageRecordRepository) scanOne(ctx context.Context, query string, args ...interface{}) (*models.UsageRecord, error) {
	var rec models.UsageRecord
	var metadataJSON []byte

	err := r.db.QueryRow(ctx, query, args...).Scan(
		&rec.ID,
		&rec.TenantID,
		&rec.ProductID,
		&rec.MetricName,
		&rec.Value,
		&rec.PeriodStart,
		&rec.PeriodEnd,
		&rec.RecordedAt,
		&metadataJSON,
	)
	if err != nil {
		return nil, fmt.Errorf("UsageRecordRepository.scanOne: %w", err)
	}

	if len(metadataJSON) > 0 {
		if err := json.Unmarshal(metadataJSON, &rec.Metadata); err != nil {
			return nil, fmt.Errorf("UsageRecordRepository.scanOne unmarshal metadata: %w", err)
		}
	}

	return &rec, nil
}

// ListByTenant returns a paginated slice of usage records for a tenant within
// the given time range (period_start overlapping [periodStart, periodEnd]).
// It also returns the total count of matching rows for pagination metadata.
func (r *UsageRecordRepository) ListByTenant(
	ctx context.Context,
	tenantID uuid.UUID,
	periodStart, periodEnd time.Time,
	page, pageSize int,
) ([]models.UsageRecord, int64, error) {
	offset := (page - 1) * pageSize

	baseQuery := `
		FROM iam_usage_records
		WHERE tenant_id   = $1
		  AND period_start >= $2
		  AND period_end   <= $3
	`
	args := []interface{}{tenantID, periodStart, periodEnd}

	// Count total matching rows.
	var total int64
	if err := r.db.QueryRow(ctx, "SELECT COUNT(*) "+baseQuery, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("UsageRecordRepository.ListByTenant count: %w", err)
	}

	// Fetch the requested page.
	selectQuery := fmt.Sprintf(`
		SELECT id, tenant_id, product_id, metric_name, value,
		       period_start, period_end, recorded_at, metadata
		%s
		ORDER BY period_start DESC, recorded_at DESC
		LIMIT $4 OFFSET $5`,
		baseQuery)
	args = append(args, pageSize, offset)

	rows, err := r.db.Query(ctx, selectQuery, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("UsageRecordRepository.ListByTenant query: %w", err)
	}
	defer rows.Close()

	var records []models.UsageRecord
	for rows.Next() {
		var rec models.UsageRecord
		var metadataJSON []byte

		if err := rows.Scan(
			&rec.ID,
			&rec.TenantID,
			&rec.ProductID,
			&rec.MetricName,
			&rec.Value,
			&rec.PeriodStart,
			&rec.PeriodEnd,
			&rec.RecordedAt,
			&metadataJSON,
		); err != nil {
			return nil, 0, fmt.Errorf("UsageRecordRepository.ListByTenant scan: %w", err)
		}

		if len(metadataJSON) > 0 {
			if err := json.Unmarshal(metadataJSON, &rec.Metadata); err != nil {
				return nil, 0, fmt.Errorf("UsageRecordRepository.ListByTenant unmarshal metadata: %w", err)
			}
		}

		records = append(records, rec)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("UsageRecordRepository.ListByTenant rows: %w", err)
	}

	return records, total, nil
}

// Aggregate returns the sum of recorded values for the given tenant, product,
// and metric over the specified time range. Returns 0 when no matching rows exist.
func (r *UsageRecordRepository) Aggregate(
	ctx context.Context,
	tenantID, productID uuid.UUID,
	metricName string,
	from, to time.Time,
) (int64, error) {
	query := `
		SELECT COALESCE(SUM(value), 0)
		FROM iam_usage_records
		WHERE tenant_id   = $1
		  AND product_id  = $2
		  AND metric_name = $3
		  AND period_start >= $4
		  AND period_end   <= $5
	`

	var total int64
	err := r.db.QueryRow(ctx, query, tenantID, productID, metricName, from, to).Scan(&total)
	if err != nil {
		return 0, fmt.Errorf("UsageRecordRepository.Aggregate: %w", err)
	}
	return total, nil
}
