// SPDX-License-Identifier: AGPL-3.0-or-later

package provisioners

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"go.uber.org/zap"
)

// RouteResourceProvisioner provisions APISIX consumers with per-tenant rate
// limiting.  An APISIX consumer represents a tenant identity in the gateway
// layer and allows per-tenant plugin configuration (rate limits, auth, etc.).
//
// # How it works
//
//  1. Provision creates (or updates) an APISIX consumer whose username is
//     derived from the tenant slug and resource name.
//  2. A limit-count plugin is attached to the consumer with the configured
//     rate limit value.
//  3. Deprovision deletes the APISIX consumer.
//
// # Dev-mode
//
// When the APISIX Admin API is unreachable or not configured, Provision logs
// what would be created and returns a simulated result.  This keeps local
// development usable without a running APISIX instance.
type RouteResourceProvisioner struct {
	apisixAdminURL string
	apisixAPIKey   string
	httpClient     *http.Client
	log            *zap.SugaredLogger
}

// NewRouteResourceProvisioner creates a RouteResourceProvisioner.
//
// adminURL is the base URL of the APISIX Admin API, e.g. "http://apisix:9180".
// apiKey is the X-API-KEY header value required by the APISIX Admin API.
func NewRouteResourceProvisioner(adminURL, apiKey string, log *zap.SugaredLogger) *RouteResourceProvisioner {
	return &RouteResourceProvisioner{
		apisixAdminURL: strings.TrimRight(adminURL, "/"),
		apisixAPIKey:   apiKey,
		httpClient: &http.Client{
			Timeout: 15 * time.Second,
		},
		log: log,
	}
}

// ResourceType satisfies ResourceProvisioner.
func (p *RouteResourceProvisioner) ResourceType() string { return "apisix_route" }

// Provision creates an APISIX consumer for the tenant.
//
// Config keys read from req.Config:
//   - "rate_limit" int – requests per second (default: 100)
func (p *RouteResourceProvisioner) Provision(ctx context.Context, req ResourceProvisionRequest) (*ResourceProvisionResult, error) {
	rateLimit := intFromConfig(req.Config, "rate_limit", 100)
	consumerID := buildConsumerID(req.TenantSlug, req.ResourceName)

	if p.apisixAdminURL == "" || p.apisixAPIKey == "" {
		p.log.Warnw("RouteResourceProvisioner: APISIX not configured, using simulated result",
			"consumer_id", consumerID,
			"rate_limit", rateLimit,
		)
		return devModeResult(p.ResourceType(), req.ResourceName, map[string]interface{}{
			"consumer_id": consumerID,
			"rate_limit":  rateLimit,
		}), nil
	}

	consumer := map[string]interface{}{
		"username": consumerID,
		"plugins": map[string]interface{}{
			"limit-count": map[string]interface{}{
				"count":                   rateLimit,
				"time_window":             1,
				"rejected_code":           429,
				"key_type":                "var",
				"key":                     "consumer_name",
				"show_limit_quota_header": true,
			},
		},
		"labels": map[string]string{
			"tenant":     req.TenantSlug,
			"managed_by": "falcon-id",
			"instance":   req.InstanceID,
		},
	}

	if err := p.upsertConsumer(ctx, consumerID, consumer); err != nil {
		p.log.Warnw("RouteResourceProvisioner: failed to upsert APISIX consumer, using simulated result",
			"consumer_id", consumerID,
			"error", err,
		)
		return devModeResult(p.ResourceType(), req.ResourceName, map[string]interface{}{
			"consumer_id": consumerID,
			"rate_limit":  rateLimit,
		}), nil
	}

	p.log.Infow("RouteResourceProvisioner: APISIX consumer provisioned",
		"consumer_id", consumerID,
		"rate_limit", rateLimit,
		"tenant_slug", req.TenantSlug,
	)

	return &ResourceProvisionResult{
		Status: "active",
		ProvisionedConfig: map[string]interface{}{
			"consumer_id": consumerID,
			"rate_limit":  rateLimit,
		},
	}, nil
}

// Deprovision deletes the APISIX consumer for the tenant.
func (p *RouteResourceProvisioner) Deprovision(ctx context.Context, req ResourceDeprovisionRequest) error {
	consumerID := stringFromConfig(req.ProvisionedConfig, "consumer_id", "")
	if consumerID == "" {
		// Fall back to reconstructing the ID from slug + resource name.
		consumerID = buildConsumerID(req.TenantSlug, req.ResourceName)
	}

	if p.apisixAdminURL == "" || p.apisixAPIKey == "" {
		p.log.Warnw("RouteResourceProvisioner.Deprovision: APISIX not configured, skipping",
			"consumer_id", consumerID,
		)
		return nil
	}

	if err := p.deleteConsumer(ctx, consumerID); err != nil {
		p.log.Warnw("RouteResourceProvisioner.Deprovision: failed to delete APISIX consumer (non-fatal)",
			"consumer_id", consumerID,
			"error", err,
		)
		// Non-fatal: do not block instance deletion.
		return nil
	}

	p.log.Infow("RouteResourceProvisioner.Deprovision: APISIX consumer deleted",
		"consumer_id", consumerID,
	)
	return nil
}

// HealthCheck verifies that the APISIX consumer exists.
func (p *RouteResourceProvisioner) HealthCheck(ctx context.Context, req ResourceHealthCheckRequest) (*ResourceHealthResult, error) {
	consumerID := stringFromConfig(req.ProvisionedConfig, "consumer_id", "")
	if consumerID == "" {
		return &ResourceHealthResult{Healthy: false, Message: "no consumer_id in provisioned config"}, nil
	}

	if p.apisixAdminURL == "" {
		return &ResourceHealthResult{Healthy: false, Message: "APISIX admin URL not configured"}, nil
	}

	url := fmt.Sprintf("%s/apisix/admin/consumers/%s", p.apisixAdminURL, consumerID)
	reqHTTP, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return &ResourceHealthResult{Healthy: false, Message: fmt.Sprintf("build request: %v", err)}, nil
	}
	p.setHeaders(reqHTTP)

	resp, err := p.httpClient.Do(reqHTTP)
	if err != nil {
		return &ResourceHealthResult{
			Healthy: false,
			Message: fmt.Sprintf("APISIX Admin API unreachable: %v", err),
		}, nil
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusNotFound {
		return &ResourceHealthResult{
			Healthy: false,
			Message: fmt.Sprintf("consumer %q not found in APISIX", consumerID),
		}, nil
	}
	if resp.StatusCode != http.StatusOK {
		return &ResourceHealthResult{
			Healthy: false,
			Message: fmt.Sprintf("APISIX returned unexpected status %d", resp.StatusCode),
		}, nil
	}

	return &ResourceHealthResult{
		Healthy: true,
		Message: fmt.Sprintf("APISIX consumer %q exists", consumerID),
	}, nil
}

// ---------------------------------------------------------------------------
// internal helpers
// ---------------------------------------------------------------------------

// buildConsumerID returns the APISIX consumer username for a tenant resource.
// Format: "tenant-{tenant_slug}-{resource_name}"
func buildConsumerID(tenantSlug, resourceName string) string {
	slug := sanitiseAPISIXName(tenantSlug)
	res := sanitiseAPISIXName(resourceName)
	return fmt.Sprintf("tenant-%s-%s", slug, res)
}

// upsertConsumer creates or replaces the APISIX consumer via a PUT request.
func (p *RouteResourceProvisioner) upsertConsumer(ctx context.Context, consumerID string, consumer map[string]interface{}) error {
	body, err := json.Marshal(consumer)
	if err != nil {
		return fmt.Errorf("marshal consumer: %w", err)
	}

	url := fmt.Sprintf("%s/apisix/admin/consumers/%s", p.apisixAdminURL, consumerID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build PUT request: %w", err)
	}
	p.setHeaders(req)
	req.Header.Set("Content-Type", "application/json")

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("PUT consumer: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("APISIX returned %d: %s", resp.StatusCode, string(raw))
	}
	return nil
}

// deleteConsumer removes an APISIX consumer by username.
func (p *RouteResourceProvisioner) deleteConsumer(ctx context.Context, consumerID string) error {
	url := fmt.Sprintf("%s/apisix/admin/consumers/%s", p.apisixAdminURL, consumerID)
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, url, nil)
	if err != nil {
		return fmt.Errorf("build DELETE request: %w", err)
	}
	p.setHeaders(req)

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("DELETE consumer: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusNotFound {
		// Already gone.
		return nil
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("APISIX returned %d: %s", resp.StatusCode, string(raw))
	}
	return nil
}

// setHeaders attaches the API key header required by APISIX.
func (p *RouteResourceProvisioner) setHeaders(req *http.Request) {
	req.Header.Set("X-API-KEY", p.apisixAPIKey)
}

// sanitiseAPISIXName converts an arbitrary string to a form safe for APISIX
// consumer usernames: lowercase alphanumeric and hyphens.
func sanitiseAPISIXName(s string) string {
	s = strings.ToLower(s)
	var b strings.Builder
	b.Grow(len(s))
	prevHyphen := false
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
			prevHyphen = false
		} else if !prevHyphen {
			b.WriteByte('-')
			prevHyphen = true
		}
	}
	return strings.Trim(b.String(), "-")
}
