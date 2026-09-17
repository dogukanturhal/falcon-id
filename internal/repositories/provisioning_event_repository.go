// SPDX-License-Identifier: AGPL-3.0-or-later

package repositories

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

// ProvisioningEventRepository handles DB operations for provisioning events.
type ProvisioningEventRepository struct {
	db *pgxpool.Pool
}

// NewProvisioningEventRepository creates a new repository.
func NewProvisioningEventRepository(db *pgxpool.Pool) *ProvisioningEventRepository {
	return &ProvisioningEventRepository{db: db}
}

// Create inserts a new provisioning event.
func (r *ProvisioningEventRepository) Create(ctx context.Context, event *models.ProvisioningEvent) error {
	query := `
		INSERT INTO iam_provisioning_events (instance_id, tenant_id, product_id, event_type, payload)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING id, created_at`

	return r.db.QueryRow(ctx, query,
		event.InstanceID, event.TenantID, event.ProductID, event.EventType, event.Payload,
	).Scan(&event.ID, &event.CreatedAt)
}

// ListUndelivered returns events that haven't been delivered yet, ordered by creation time.
func (r *ProvisioningEventRepository) ListUndelivered(ctx context.Context, limit int) ([]models.ProvisioningEvent, error) {
	query := `
		SELECT id, instance_id, tenant_id, product_id, event_type, payload, delivered, created_at
		FROM iam_provisioning_events
		WHERE delivered = false
		ORDER BY created_at ASC
		LIMIT $1`

	rows, err := r.db.Query(ctx, query, limit)
	if err != nil {
		return nil, fmt.Errorf("ProvisioningEventRepository.ListUndelivered: %w", err)
	}
	defer rows.Close()

	var events []models.ProvisioningEvent
	for rows.Next() {
		var e models.ProvisioningEvent
		if err := rows.Scan(&e.ID, &e.InstanceID, &e.TenantID, &e.ProductID,
			&e.EventType, &e.Payload, &e.Delivered, &e.CreatedAt); err != nil {
			return nil, fmt.Errorf("ProvisioningEventRepository.ListUndelivered scan: %w", err)
		}
		events = append(events, e)
	}
	return events, rows.Err()
}

// MarkDelivered marks an event as delivered.
func (r *ProvisioningEventRepository) MarkDelivered(ctx context.Context, id uuid.UUID) error {
	_, err := r.db.Exec(ctx, `UPDATE iam_provisioning_events SET delivered = true WHERE id = $1`, id)
	return err
}

// ListByInstance returns all events for a given instance.
func (r *ProvisioningEventRepository) ListByInstance(ctx context.Context, instanceID uuid.UUID) ([]models.ProvisioningEvent, error) {
	query := `
		SELECT id, instance_id, tenant_id, product_id, event_type, payload, delivered, created_at
		FROM iam_provisioning_events
		WHERE instance_id = $1
		ORDER BY created_at ASC`

	rows, err := r.db.Query(ctx, query, instanceID)
	if err != nil {
		return nil, fmt.Errorf("ProvisioningEventRepository.ListByInstance: %w", err)
	}
	defer rows.Close()

	var events []models.ProvisioningEvent
	for rows.Next() {
		var e models.ProvisioningEvent
		if err := rows.Scan(&e.ID, &e.InstanceID, &e.TenantID, &e.ProductID,
			&e.EventType, &e.Payload, &e.Delivered, &e.CreatedAt); err != nil {
			return nil, fmt.Errorf("ProvisioningEventRepository.ListByInstance scan: %w", err)
		}
		events = append(events, e)
	}
	return events, rows.Err()
}
