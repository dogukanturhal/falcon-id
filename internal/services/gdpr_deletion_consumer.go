// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/pkg/logger"
)

// gdprUserDeleter is the minimum interface needed to hard-delete a user's identity data.
type gdprUserDeleter interface {
	DeleteUser(ctx context.Context, userID uuid.UUID) error
}

// gdprAuditLogger records GDPR deletion events in the immutable audit trail.
type gdprAuditLogger interface {
	LogGDPRDeletion(ctx context.Context, userID uuid.UUID) error
}

// GDPRDeletionConsumer polls the integration-bus for user.data_deletion_requested
// events and hard-deletes the user's IAM data (identity record, sessions, credentials).
//
// Polling interval defaults to 30 seconds.
type GDPRDeletionConsumer struct {
	userService  gdprUserDeleter
	auditService gdprAuditLogger
	pollURL      string
	httpClient   *http.Client
}

// NewGDPRDeletionConsumer creates a new consumer.
// integrationBusURL is the base URL of the integration-bus service.
func NewGDPRDeletionConsumer(userService gdprUserDeleter, auditService gdprAuditLogger, integrationBusURL string) *GDPRDeletionConsumer {
	return &GDPRDeletionConsumer{
		userService:  userService,
		auditService: auditService,
		pollURL:      fmt.Sprintf("%s/api/v1/events?event_type=user.data_deletion_requested&limit=10", integrationBusURL),
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// gdprDeletionEvent represents the shape of a user.data_deletion_requested event.
type gdprDeletionEvent struct {
	ID        string    `json:"id"`
	EventType string    `json:"event_type"`
	UserID    string    `json:"user_id"`
	TenantID  string    `json:"tenant_id"`
	Timestamp time.Time `json:"timestamp"`
}

// gdprEventsResponse is the response envelope from the integration-bus poll endpoint.
type gdprEventsResponse struct {
	Items []gdprDeletionEvent `json:"items"`
}

// Start begins the polling loop. Blocks until ctx is cancelled. Must be called in a goroutine.
func (c *GDPRDeletionConsumer) Start(ctx context.Context) {
	logger.Info("GDPRDeletionConsumer: starting poll loop",
		zap.String("poll_url", c.pollURL),
	)

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	// Run once immediately before waiting for the first tick.
	c.poll(ctx)

	for {
		select {
		case <-ctx.Done():
			logger.Info("GDPRDeletionConsumer: context cancelled, stopping")
			return
		case <-ticker.C:
			c.poll(ctx)
		}
	}
}

// poll fetches and processes pending deletion events from the integration-bus.
func (c *GDPRDeletionConsumer) poll(ctx context.Context) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.pollURL, nil)
	if err != nil {
		logger.Warn("GDPRDeletionConsumer: failed to build poll request",
			zap.Error(err),
		)
		return
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		logger.Warn("GDPRDeletionConsumer: poll request failed",
			zap.Error(err),
		)
		return
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode == http.StatusNoContent || resp.StatusCode == http.StatusNotFound {
		// No events — normal, nothing to do.
		return
	}

	if resp.StatusCode != http.StatusOK {
		logger.Warn("GDPRDeletionConsumer: unexpected status from integration-bus",
			zap.Int("status", resp.StatusCode),
		)
		return
	}

	var payload gdprEventsResponse
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		logger.Warn("GDPRDeletionConsumer: failed to decode response",
			zap.Error(err),
		)
		return
	}

	for _, event := range payload.Items {
		c.processEvent(ctx, event)
	}
}

// processEvent handles a single deletion event.
func (c *GDPRDeletionConsumer) processEvent(ctx context.Context, event gdprDeletionEvent) {
	userID, err := uuid.Parse(event.UserID)
	if err != nil {
		logger.Warn("GDPRDeletionConsumer: invalid user_id in event, skipping",
			zap.String("event_id", event.ID),
			zap.String("raw_user_id", event.UserID),
			zap.Error(err),
		)
		return
	}

	logger.Info("GDPRDeletionConsumer: processing deletion event",
		zap.String("event_id", event.ID),
		zap.String("user_id", userID.String()),
	)

	// 1. Hard-delete the user's IAM record (sessions, credentials, tokens, etc.).
	if c.userService != nil {
		if err := c.userService.DeleteUser(ctx, userID); err != nil {
			logger.Error("GDPRDeletionConsumer: failed to delete user IAM data",
				zap.String("event_id", event.ID),
				zap.String("user_id", userID.String()),
				zap.Error(err),
			)
			// Do not return — still attempt to audit log.
		}
	}

	// 2. Append to immutable audit trail.
	if c.auditService != nil {
		if err := c.auditService.LogGDPRDeletion(ctx, userID); err != nil {
			logger.Error("GDPRDeletionConsumer: failed to log GDPR deletion",
				zap.String("event_id", event.ID),
				zap.String("user_id", userID.String()),
				zap.Error(err),
			)
		}
	}
}
