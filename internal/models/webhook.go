// SPDX-License-Identifier: AGPL-3.0-or-later

package models

import (
	"time"

	"github.com/google/uuid"
)

// WebhookEventType represents the types of events that can trigger webhooks
type WebhookEventType string

const (
	// WebhookEventUserCreated is an exported identifier.
	WebhookEventUserCreated WebhookEventType = "user.created"
	// WebhookEventUserUpdated is an exported identifier.
	WebhookEventUserUpdated WebhookEventType = "user.updated"
	// WebhookEventUserDeleted is an exported identifier.
	WebhookEventUserDeleted WebhookEventType = "user.deleted"
	// WebhookEventUserLocked is an exported identifier.
	WebhookEventUserLocked WebhookEventType = "user.locked"
	// WebhookEventUserUnlocked is an exported identifier.
	WebhookEventUserUnlocked WebhookEventType = "user.unlocked"

	// WebhookEventRoleCreated is an exported identifier.
	WebhookEventRoleCreated WebhookEventType = "role.created"
	// WebhookEventRoleUpdated is an exported identifier.
	WebhookEventRoleUpdated WebhookEventType = "role.updated"
	// WebhookEventRoleDeleted is an exported identifier.
	WebhookEventRoleDeleted WebhookEventType = "role.deleted"
	// WebhookEventRoleAssigned is an exported identifier.
	WebhookEventRoleAssigned WebhookEventType = "role.assigned"
	// WebhookEventRoleRevoked is an exported identifier.
	WebhookEventRoleRevoked WebhookEventType = "role.revoked"

	// WebhookEventSessionCreated is an exported identifier.
	WebhookEventSessionCreated WebhookEventType = "session.created"
	// WebhookEventSessionRevoked is an exported identifier.
	WebhookEventSessionRevoked WebhookEventType = "session.revoked"
	// WebhookEventSessionExpired is an exported identifier.
	WebhookEventSessionExpired WebhookEventType = "session.expired"

	// WebhookEventLoginSuccess is an exported identifier.
	WebhookEventLoginSuccess WebhookEventType = "login.success"
	// WebhookEventLoginFailed is an exported identifier.
	WebhookEventLoginFailed WebhookEventType = "login.failed"
	// WebhookEventLogout is an exported identifier.
	WebhookEventLogout WebhookEventType = "logout"

	// WebhookEventMFAEnabled is an exported identifier.
	WebhookEventMFAEnabled WebhookEventType = "mfa.enabled"
	// WebhookEventMFADisabled is an exported identifier.
	WebhookEventMFADisabled WebhookEventType = "mfa.disabled"
	// WebhookEventMFAChallenge is an exported identifier.
	WebhookEventMFAChallenge WebhookEventType = "mfa.challenge"

	// WebhookEventImpersonationStarted is an exported identifier.
	WebhookEventImpersonationStarted WebhookEventType = "impersonation.started"
	// WebhookEventImpersonationEnded is an exported identifier.
	WebhookEventImpersonationEnded WebhookEventType = "impersonation.ended"

	// WebhookEventPasswordChanged is an exported identifier.
	WebhookEventPasswordChanged WebhookEventType = "password.changed"
	// WebhookEventPasswordReset is an exported identifier.
	WebhookEventPasswordReset WebhookEventType = "password.reset"

	// WebhookEventApplicationCreated is an exported identifier.
	WebhookEventApplicationCreated WebhookEventType = "application.created"
	// WebhookEventApplicationUpdated is an exported identifier.
	WebhookEventApplicationUpdated WebhookEventType = "application.updated"
	// WebhookEventApplicationDeleted is an exported identifier.
	WebhookEventApplicationDeleted WebhookEventType = "application.deleted"

	// WebhookEventSPProvisioned is an exported identifier.
	WebhookEventSPProvisioned WebhookEventType = "sp.provisioned"
	// WebhookEventSPEnabled is an exported identifier.
	WebhookEventSPEnabled WebhookEventType = "sp.enabled"
	// WebhookEventSPDisabled is an exported identifier.
	WebhookEventSPDisabled WebhookEventType = "sp.disabled"
	// WebhookEventSPDeleted is an exported identifier.
	WebhookEventSPDeleted WebhookEventType = "sp.deleted"
	// WebhookEventSPCredentialsRotated is an exported identifier.
	WebhookEventSPCredentialsRotated WebhookEventType = "sp.credentials.rotated"
	// WebhookEventSPCredentialsExpiring is an exported identifier.
	WebhookEventSPCredentialsExpiring WebhookEventType = "sp.credentials.expiring"

	// WebhookEventConsentGranted is an exported identifier.
	WebhookEventConsentGranted WebhookEventType = "consent.granted"
	// WebhookEventConsentRevoked is an exported identifier.
	WebhookEventConsentRevoked WebhookEventType = "consent.revoked"
)

// AllWebhookEventTypes returns all available webhook event types
func AllWebhookEventTypes() []WebhookEventType {
	return []WebhookEventType{
		WebhookEventUserCreated,
		WebhookEventUserUpdated,
		WebhookEventUserDeleted,
		WebhookEventUserLocked,
		WebhookEventUserUnlocked,
		WebhookEventRoleCreated,
		WebhookEventRoleUpdated,
		WebhookEventRoleDeleted,
		WebhookEventRoleAssigned,
		WebhookEventRoleRevoked,
		WebhookEventSessionCreated,
		WebhookEventSessionRevoked,
		WebhookEventSessionExpired,
		WebhookEventLoginSuccess,
		WebhookEventLoginFailed,
		WebhookEventLogout,
		WebhookEventMFAEnabled,
		WebhookEventMFADisabled,
		WebhookEventMFAChallenge,
		WebhookEventImpersonationStarted,
		WebhookEventImpersonationEnded,
		WebhookEventPasswordChanged,
		WebhookEventPasswordReset,
		WebhookEventApplicationCreated,
		WebhookEventApplicationUpdated,
		WebhookEventApplicationDeleted,
		WebhookEventSPProvisioned,
		WebhookEventSPEnabled,
		WebhookEventSPDisabled,
		WebhookEventSPDeleted,
		WebhookEventSPCredentialsRotated,
		WebhookEventSPCredentialsExpiring,
		WebhookEventConsentGranted,
		WebhookEventConsentRevoked,
	}
	// WebhookDeliveryStatusSuccess is an exported identifier.
}

// WebhookDeliveryStatus represents the status of a webhook delivery
type WebhookDeliveryStatus string

const (
	// WebhookDeliveryStatusPending is an exported identifier.
	WebhookDeliveryStatusPending WebhookDeliveryStatus = "pending"
	// WebhookDeliveryStatusProcessing is an exported identifier.
	WebhookDeliveryStatusProcessing WebhookDeliveryStatus = "processing"
	// WebhookDeliveryStatusSuccess is an exported identifier.
	WebhookDeliveryStatusSuccess WebhookDeliveryStatus = "success"
	// WebhookDeliveryStatusFailed is an exported identifier.
	WebhookDeliveryStatusFailed WebhookDeliveryStatus = "failed"
	// WebhookDeliveryStatusCancelled is an exported identifier.
	WebhookDeliveryStatusCancelled WebhookDeliveryStatus = "cancelled"
)

// Webhook represents a webhook configuration
type Webhook struct {
	ID             uuid.UUID         `json:"id"`
	TenantID       uuid.UUID         `json:"tenant_id"`
	Name           string            `json:"name"`
	Description    *string           `json:"description,omitempty"`
	URL            string            `json:"url"`
	SecretHash     string            `json:"-"` // Never expose hash
	Events         []string          `json:"events"`
	Headers        map[string]string `json:"headers,omitempty"`
	IsActive       bool              `json:"is_active"`
	RetryCount     int               `json:"retry_count"`
	TimeoutSeconds int               `json:"timeout_seconds"`
	CreatedAt      time.Time         `json:"created_at"`
	UpdatedAt      time.Time         `json:"updated_at"`
	CreatedBy      *uuid.UUID        `json:"created_by,omitempty"`
}

// WebhookDelivery represents a webhook delivery attempt
type WebhookDelivery struct {
	ID              uuid.UUID              `json:"id"`
	WebhookID       uuid.UUID              `json:"webhook_id"`
	EventType       string                 `json:"event_type"`
	EventID         *string                `json:"event_id,omitempty"`
	Payload         map[string]interface{} `json:"payload"`
	Status          WebhookDeliveryStatus  `json:"status"`
	Attempts        int                    `json:"attempts"`
	MaxAttempts     int                    `json:"max_attempts"`
	NextRetryAt     *time.Time             `json:"next_retry_at,omitempty"`
	LastAttemptAt   *time.Time             `json:"last_attempt_at,omitempty"`
	ResponseStatus  *int                   `json:"response_status,omitempty"`
	ResponseBody    *string                `json:"response_body,omitempty"`
	ResponseHeaders map[string]string      `json:"response_headers,omitempty"`
	DurationMs      *int                   `json:"duration_ms,omitempty"`
	ErrorMessage    *string                `json:"error_message,omitempty"`
	CreatedAt       time.Time              `json:"created_at"`
	CompletedAt     *time.Time             `json:"completed_at,omitempty"`
	// Joined fields
	Webhook *Webhook `json:"webhook,omitempty"`
}

// WebhookEvent represents an event to be sent via webhook
type WebhookEvent struct {
	ID        string                 `json:"id"`
	Type      WebhookEventType       `json:"type"`
	Timestamp time.Time              `json:"timestamp"`
	TenantID  uuid.UUID              `json:"tenant_id"`
	Actor     *WebhookEventActor     `json:"actor,omitempty"`
	Data      map[string]interface{} `json:"data"`
}

// WebhookEventActor represents the actor who triggered the event
type WebhookEventActor struct {
	ID       string  `json:"id"`
	Type     string  `json:"type"` // user, system, service_account
	Username *string `json:"username,omitempty"`
	Email    *string `json:"email,omitempty"`
}

// Request/Response types

// CreateWebhookRequest represents the request to create a webhook
type CreateWebhookRequest struct {
	Name           string            `json:"name" binding:"required,min=1,max=100"`
	Description    *string           `json:"description,omitempty"`
	URL            string            `json:"url" binding:"required,url"`
	Secret         string            `json:"secret" binding:"required,min=16"`
	Events         []string          `json:"events" binding:"required,min=1"`
	Headers        map[string]string `json:"headers,omitempty"`
	IsActive       *bool             `json:"is_active,omitempty"`
	RetryCount     *int              `json:"retry_count,omitempty"`
	TimeoutSeconds *int              `json:"timeout_seconds,omitempty"`
}

// UpdateWebhookRequest represents the request to update a webhook
type UpdateWebhookRequest struct {
	Name           *string           `json:"name,omitempty"`
	Description    *string           `json:"description,omitempty"`
	URL            *string           `json:"url,omitempty"`
	Secret         *string           `json:"secret,omitempty"`
	Events         []string          `json:"events,omitempty"`
	Headers        map[string]string `json:"headers,omitempty"`
	IsActive       *bool             `json:"is_active,omitempty"`
	RetryCount     *int              `json:"retry_count,omitempty"`
	TimeoutSeconds *int              `json:"timeout_seconds,omitempty"`
}

// WebhookResponse represents the webhook in API responses (with secret hint)
type WebhookResponse struct {
	ID             uuid.UUID         `json:"id"`
	TenantID       uuid.UUID         `json:"tenant_id"`
	Name           string            `json:"name"`
	Description    *string           `json:"description,omitempty"`
	URL            string            `json:"url"`
	SecretHint     string            `json:"secret_hint"` // e.g., "****last4chars"
	Events         []string          `json:"events"`
	Headers        map[string]string `json:"headers,omitempty"`
	IsActive       bool              `json:"is_active"`
	RetryCount     int               `json:"retry_count"`
	TimeoutSeconds int               `json:"timeout_seconds"`
	CreatedAt      time.Time         `json:"created_at"`
	UpdatedAt      time.Time         `json:"updated_at"`
	CreatedBy      *uuid.UUID        `json:"created_by,omitempty"`
}

// WebhookCreatedResponse includes the secret (only shown once)
type WebhookCreatedResponse struct {
	WebhookResponse
	Secret string `json:"secret"` // Only returned on creation
}

// WebhookListResponse represents the paginated list of webhooks
type WebhookListResponse struct {
	Webhooks   []*WebhookResponse `json:"webhooks"`
	Total      int                `json:"total"`
	Page       int                `json:"page"`
	PageSize   int                `json:"page_size"`
	TotalPages int                `json:"total_pages"`
}

// WebhookDeliveryListResponse represents the paginated list of webhook deliveries
type WebhookDeliveryListResponse struct {
	Deliveries []*WebhookDelivery `json:"deliveries"`
	Total      int                `json:"total"`
	Page       int                `json:"page"`
	PageSize   int                `json:"page_size"`
	TotalPages int                `json:"total_pages"`
}

// WebhookTestRequest represents a request to test a webhook
type WebhookTestRequest struct {
	EventType string `json:"event_type" binding:"required"`
}

// WebhookTestResponse represents the response from testing a webhook
type WebhookTestResponse struct {
	Success      bool    `json:"success"`
	StatusCode   int     `json:"status_code,omitempty"`
	ResponseBody string  `json:"response_body,omitempty"`
	DurationMs   int     `json:"duration_ms,omitempty"`
	ErrorMessage *string `json:"error_message,omitempty"`
}

// ToResponse converts a Webhook to WebhookResponse
func (w *Webhook) ToResponse() *WebhookResponse {
	secretHint := "********"
	// We don't have the original secret, so just show a placeholder

	return &WebhookResponse{
		ID:             w.ID,
		TenantID:       w.TenantID,
		Name:           w.Name,
		Description:    w.Description,
		URL:            w.URL,
		SecretHint:     secretHint,
		Events:         w.Events,
		Headers:        w.Headers,
		IsActive:       w.IsActive,
		RetryCount:     w.RetryCount,
		TimeoutSeconds: w.TimeoutSeconds,
		CreatedAt:      w.CreatedAt,
		UpdatedAt:      w.UpdatedAt,
		CreatedBy:      w.CreatedBy,
	}
}
