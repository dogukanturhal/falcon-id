// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/pkg/logger"
)

// notifierEventRepo defines the repository interface for provisioning events.
type notifierEventRepo interface {
	Create(ctx context.Context, event *models.ProvisioningEvent) error
	ListUndelivered(ctx context.Context, limit int) ([]models.ProvisioningEvent, error)
	MarkDelivered(ctx context.Context, id uuid.UUID) error
	ListByInstance(ctx context.Context, instanceID uuid.UUID) ([]models.ProvisioningEvent, error)
}

// ProvisioningNotifier records provisioning lifecycle events into the
// iam_provisioning_events table (outbox pattern). A separate delivery
// worker or webhook consumer reads undelivered events and forwards
// them to subscription-management.
type ProvisioningNotifier struct {
	eventRepo notifierEventRepo
}

// NewProvisioningNotifier creates a new notifier.
func NewProvisioningNotifier(eventRepo notifierEventRepo) *ProvisioningNotifier {
	return &ProvisioningNotifier{eventRepo: eventRepo}
}

// NotifyActivated records a provisioning.activated event.
func (n *ProvisioningNotifier) NotifyActivated(ctx context.Context, instanceID, tenantID, productID uuid.UUID) error {
	payload := models.SubscriptionActivatedEvent{
		InstanceID: instanceID,
		TenantID:   tenantID,
		ProductID:  productID,
		Status:     provisioningStateActive,
	}
	return n.recordEvent(ctx, instanceID, tenantID, productID, models.ProvisioningEventActivated, payload)
}

// NotifyFailed records a provisioning.failed event.
func (n *ProvisioningNotifier) NotifyFailed(ctx context.Context, instanceID, tenantID, productID uuid.UUID, reason string) error {
	payload := models.SubscriptionActivatedEvent{
		InstanceID: instanceID,
		TenantID:   tenantID,
		ProductID:  productID,
		Status:     awxJobStatusFailed,
		Reason:     reason,
	}
	return n.recordEvent(ctx, instanceID, tenantID, productID, models.ProvisioningEventFailed, payload)
}

// NotifyDeleted records a provisioning.deleted event.
func (n *ProvisioningNotifier) NotifyDeleted(ctx context.Context, instanceID, tenantID, productID uuid.UUID) error {
	payload := models.SubscriptionActivatedEvent{
		InstanceID: instanceID,
		TenantID:   tenantID,
		ProductID:  productID,
		Status:     "deleted",
	}
	return n.recordEvent(ctx, instanceID, tenantID, productID, models.ProvisioningEventDeleted, payload)
}

func (n *ProvisioningNotifier) recordEvent(
	ctx context.Context,
	instanceID, tenantID, productID uuid.UUID,
	eventType models.ProvisioningEventType,
	payload interface{},
) error {
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("provisioning notifier: marshal payload: %w", err)
	}

	event := &models.ProvisioningEvent{
		InstanceID: instanceID,
		TenantID:   tenantID,
		ProductID:  productID,
		EventType:  eventType,
		Payload:    string(payloadJSON),
	}

	if err := n.eventRepo.Create(ctx, event); err != nil {
		return fmt.Errorf("provisioning notifier: create event: %w", err)
	}

	logger.Info("Provisioning event recorded",
		zap.String("event_type", string(eventType)),
		zap.String("instance_id", instanceID.String()),
		zap.String("tenant_id", tenantID.String()),
	)

	return nil
}
