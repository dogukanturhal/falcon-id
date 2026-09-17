// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/pkg/logger"
)

// SignupEventPublisher publishes a tenant.signup_completed event to the integration-bus,
// replacing the in-process PostSignupProvisioner for default app access and subdomain provisioning.
//
// Best-effort: errors are logged but never returned to the caller.
type SignupEventPublisher struct {
	integrationBusURL string
	httpClient        *http.Client
}

// NewSignupEventPublisher creates a new event publisher.
func NewSignupEventPublisher(integrationBusURL string) *SignupEventPublisher {
	return &SignupEventPublisher{
		integrationBusURL: integrationBusURL,
		httpClient: &http.Client{
			Timeout: 5 * time.Second,
		},
	}
}

// signupCompletedEvent is the payload published on tenant.signup_completed.
type signupCompletedEvent struct {
	EventType   string    `json:"event_type"`
	TenantID    string    `json:"tenant_id"`
	UserID      string    `json:"user_id"`
	AccountType string    `json:"account_type"`
	Timestamp   time.Time `json:"timestamp"`
}

// OnSignupComplete implements PostSignupHook by publishing a tenant.signup_completed
// event to the integration-bus. All errors are logged but never propagated.
func (p *SignupEventPublisher) OnSignupComplete(ctx context.Context, tenantID, userID uuid.UUID, accountType string) error {
	event := signupCompletedEvent{
		EventType:   "tenant.signup_completed",
		TenantID:    tenantID.String(),
		UserID:      userID.String(),
		AccountType: accountType,
		Timestamp:   time.Now().UTC(),
	}

	body, err := json.Marshal(event)
	if err != nil {
		logger.Warn("SignupEventPublisher: failed to marshal event (non-fatal)",
			zap.String("tenant_id", tenantID.String()),
			zap.String("user_id", userID.String()),
			zap.Error(err),
		)
		return nil
	}

	url := fmt.Sprintf("%s/api/v1/events", p.integrationBusURL)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		logger.Warn("SignupEventPublisher: failed to build request (non-fatal)",
			zap.String("tenant_id", tenantID.String()),
			zap.Error(err),
		)
		return nil
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := p.httpClient.Do(req)
	if err != nil {
		logger.Warn("SignupEventPublisher: HTTP call failed (non-fatal)",
			zap.String("tenant_id", tenantID.String()),
			zap.String("user_id", userID.String()),
			zap.Error(err),
		)
		return nil
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode >= 300 {
		logger.Warn("SignupEventPublisher: integration-bus returned non-2xx (non-fatal)",
			zap.String("tenant_id", tenantID.String()),
			zap.String("user_id", userID.String()),
			zap.Int("status", resp.StatusCode),
		)
		return nil
	}

	logger.Info("SignupEventPublisher: tenant.signup_completed event published",
		zap.String("tenant_id", tenantID.String()),
		zap.String("user_id", userID.String()),
		zap.String("account_type", accountType),
	)
	return nil
}
