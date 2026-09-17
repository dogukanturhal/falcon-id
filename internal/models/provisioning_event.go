// SPDX-License-Identifier: AGPL-3.0-or-later

package models

import (
	"time"

	"github.com/google/uuid"
)

// ProvisioningEventType represents the type of provisioning lifecycle event.
type ProvisioningEventType string

const (
	// ProvisioningEventActivated is an exported identifier.
	ProvisioningEventActivated ProvisioningEventType = "provisioning.activated"
	// ProvisioningEventFailed is an exported identifier.
	ProvisioningEventFailed ProvisioningEventType = "provisioning.failed"
	// ProvisioningEventDeleted is an exported identifier.
	ProvisioningEventDeleted ProvisioningEventType = "provisioning.deleted"
	// ProvisioningEventRetrying is an exported identifier.
	ProvisioningEventRetrying ProvisioningEventType = "provisioning.retrying"
)

// ProvisioningEvent records a provisioning lifecycle event for auditing
// and for notifying external services (e.g. subscription-management).
type ProvisioningEvent struct {
	ID         uuid.UUID             `json:"id" db:"id"`
	InstanceID uuid.UUID             `json:"instance_id" db:"instance_id"`
	TenantID   uuid.UUID             `json:"tenant_id" db:"tenant_id"`
	ProductID  uuid.UUID             `json:"product_id" db:"product_id"`
	EventType  ProvisioningEventType `json:"event_type" db:"event_type"`
	Payload    string                `json:"payload,omitempty" db:"payload"`
	Delivered  bool                  `json:"delivered" db:"delivered"`
	CreatedAt  time.Time             `json:"created_at" db:"created_at"`
}

// SubscriptionActivatedEvent is the payload sent to subscription-management
// when provisioning completes successfully.
type SubscriptionActivatedEvent struct {
	InstanceID uuid.UUID `json:"instance_id"`
	TenantID   uuid.UUID `json:"tenant_id"`
	ProductID  uuid.UUID `json:"product_id"`
	Status     string    `json:"status"` // "active" or "failed"
	Reason     string    `json:"reason,omitempty"`
}
