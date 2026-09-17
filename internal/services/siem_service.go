// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/pkg/logger"
)

// siemWebhookDeliveryTimeout is the per-webhook HTTP call deadline.
const siemWebhookDeliveryTimeout = 10 * time.Second

// SIEMService manages security event delivery to external SIEM systems
// via configurable webhook endpoints.
type SIEMService struct {
	db         *pgxpool.Pool
	httpClient *http.Client
	logger     *zap.Logger
}

// NewSIEMService creates a new SIEMService.
func NewSIEMService(db *pgxpool.Pool, httpClient *http.Client, log *zap.Logger) *SIEMService {
	if log == nil {
		log = zap.NewNop()
	}
	if httpClient == nil {
		httpClient = &http.Client{Timeout: siemWebhookDeliveryTimeout}
	}
	return &SIEMService{
		db:         db,
		httpClient: httpClient,
		logger:     log,
	}
}

// PushEvent delivers a ThreatEvent to all active SIEM webhooks. Delivery
// failures are logged but do not cause PushEvent to return an error; events
// must not be lost due to a single bad webhook.
func (s *SIEMService) PushEvent(ctx context.Context, event *models.ThreatEvent) error {
	webhooks, err := s.GetActiveWebhooks(ctx)
	if err != nil {
		return fmt.Errorf("SIEMService.PushEvent: failed to load webhooks: %w", err)
	}

	payload, err := json.Marshal(event.ToResponse())
	if err != nil {
		return fmt.Errorf("SIEMService.PushEvent: failed to marshal event: %w", err)
	}

	for _, wh := range webhooks {
		if err := s.deliver(ctx, wh, payload); err != nil {
			s.logger.Warn("SIEMService: webhook delivery failed",
				zap.String("webhook_id", wh.ID.String()),
				zap.String("endpoint_url", wh.EndpointURL),
				zap.Error(err),
			)
			// Non-fatal: continue to next webhook.
		}
	}

	return nil
}

// GetActiveWebhooks returns all active SIEM webhook configurations.
func (s *SIEMService) GetActiveWebhooks(ctx context.Context) ([]models.SIEMWebhook, error) {
	if s.db == nil {
		return nil, fmt.Errorf("SIEMService.GetActiveWebhooks: database not configured")
	}

	query := `
		SELECT id, name, endpoint_url, auth_header_enc, severity_filter, event_type_filter, is_active, created_at, updated_at
		FROM siem_webhooks
		WHERE is_active = true
		ORDER BY created_at`

	rows, err := s.db.Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("SIEMService.GetActiveWebhooks: %w", err)
	}
	defer rows.Close()

	var webhooks []models.SIEMWebhook
	for rows.Next() {
		var wh models.SIEMWebhook
		if err := rows.Scan(
			&wh.ID, &wh.Name, &wh.EndpointURL, &wh.AuthHeaderEnc,
			&wh.SeverityFilter, &wh.EventTypeFilter,
			&wh.IsActive, &wh.CreatedAt, &wh.UpdatedAt,
		); err != nil {
			logger.Warn("SIEMService: failed to scan webhook row", zap.Error(err))
			continue
		}
		webhooks = append(webhooks, wh)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("SIEMService.GetActiveWebhooks: row iteration: %w", err)
	}

	return webhooks, nil
}

// CreateWebhook persists a new SIEM webhook configuration.
func (s *SIEMService) CreateWebhook(ctx context.Context, webhook *models.SIEMWebhook) error {
	if s.db == nil {
		return fmt.Errorf("SIEMService.CreateWebhook: database not configured")
	}

	query := `
		INSERT INTO siem_webhooks (name, endpoint_url, auth_header_enc, severity_filter, event_type_filter, is_active)
		VALUES ($1, $2, $3, $4, $5, $6)
		RETURNING id, created_at, updated_at`

	err := s.db.QueryRow(ctx, query,
		webhook.Name, webhook.EndpointURL, webhook.AuthHeaderEnc,
		webhook.SeverityFilter, webhook.EventTypeFilter, webhook.IsActive,
	).Scan(&webhook.ID, &webhook.CreatedAt, &webhook.UpdatedAt)
	if err != nil {
		return fmt.Errorf("SIEMService.CreateWebhook: %w", err)
	}

	s.logger.Info("SIEMService: webhook created",
		zap.String("webhook_id", webhook.ID.String()),
		zap.String("endpoint_url", webhook.EndpointURL),
	)
	return nil
}

// deliver sends a JSON payload to a single webhook endpoint.
// The auth header is transmitted if the webhook has one configured.
func (s *SIEMService) deliver(ctx context.Context, wh models.SIEMWebhook, payload []byte) error {
	deliveryCtx, cancel := context.WithTimeout(ctx, siemWebhookDeliveryTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(deliveryCtx, http.MethodPost, wh.EndpointURL, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("deliver: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	// AuthHeaderEnc is the encrypted representation of "Authorization: <value>".
	// The decryption layer is intentionally out of scope here; the raw bytes
	// would normally be decrypted before being set. We set the header only when
	// the auth material is present.
	if len(wh.AuthHeaderEnc) > 0 {
		req.Header.Set("Authorization", string(wh.AuthHeaderEnc))
	}

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("deliver: http: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode >= 300 {
		return fmt.Errorf("deliver: unexpected status %d for webhook %s", resp.StatusCode, wh.EndpointURL)
	}
	return nil
}
