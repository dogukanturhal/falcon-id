// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"go.uber.org/zap"
)

// IntegrationBusPublisher publishes lifecycle events to the integration bus service
// via its HTTP API. All publish calls are intended to be fire-and-forget; callers
// must invoke them in a goroutine so the user-facing operation is never blocked or
// failed by event delivery issues.
type IntegrationBusPublisher struct {
	baseURL string
	client  *http.Client
	logger  *zap.Logger
}

// NewIntegrationBusPublisher creates a publisher that sends events to the
// integration bus at baseURL. A 10-second HTTP timeout is applied per request.
func NewIntegrationBusPublisher(baseURL string, logger *zap.Logger) *IntegrationBusPublisher {
	return &IntegrationBusPublisher{
		baseURL: baseURL,
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
		logger: logger,
	}
}

// integrationBusRequest mirrors the PublishEventRequest expected by the integration
// bus POST /api/v1/integration/events endpoint.
type integrationBusRequest struct {
	EventType string      `json:"event_type"`
	Payload   interface{} `json:"payload"`
	TenantID  string      `json:"tenant_id"`
}

// PublishEvent sends a single event to the integration bus.
// tenantID is sent both as the X-Tenant-ID header and inside the JSON body so
// the bus can enforce tenant-consistency checks (see event_handler.go).
func (p *IntegrationBusPublisher) PublishEvent(ctx context.Context, tenantID, eventType string, payload interface{}) error {
	req := integrationBusRequest{
		EventType: eventType,
		Payload:   payload,
		TenantID:  tenantID,
	}

	body, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("integration_bus_publisher: marshal payload: %w", err)
	}

	url := p.baseURL + "/api/v1/integration/events"
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("integration_bus_publisher: build request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("X-Tenant-ID", tenantID)

	resp, err := p.client.Do(httpReq)
	if err != nil {
		return fmt.Errorf("integration_bus_publisher: http send: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("integration_bus_publisher: unexpected status %d publishing %s", resp.StatusCode, eventType)
	}

	p.logger.Debug("Published event to integration bus",
		zap.String("event_type", eventType),
		zap.String("tenant_id", tenantID),
		zap.Int("status", resp.StatusCode),
	)

	return nil
}
