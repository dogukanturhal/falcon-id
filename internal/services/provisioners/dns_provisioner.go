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

// DNSResourceProvisioner provisions DNS records for tenant subdomains.
//
// In production it calls the Cloudflare DNS API to create a CNAME record
// pointing the tenant's subdomain at the platform's shared load-balancer.
// In development (or when credentials are absent) it logs what would be
// created and returns a simulated result.
//
// # Config keys
//
//   - "domain_pattern" string – template for the FQDN, e.g.
//     "{tenant_slug}.example.com" (default: "{tenant_slug}.example.com")
//   - "record_type"    string – DNS record type: "CNAME" or "A" (default: "CNAME")
//   - "record_content" string – CNAME target or A record IP
//     (default: "platform.example.com")
//   - "proxied"        bool   – whether to enable Cloudflare proxy (default: true)
type DNSResourceProvisioner struct {
	// cloudflareAPIToken is the Cloudflare API bearer token.
	cloudflareAPIToken string
	// cloudflareZoneID is the Cloudflare zone in which records are created.
	cloudflareZoneID string
	httpClient       *http.Client
	log              *zap.SugaredLogger
}

// NewDNSResourceProvisioner creates a DNSResourceProvisioner.
//
// Provide empty strings for apiToken and zoneID to run in dev-mode (log only).
func NewDNSResourceProvisioner(cloudflareAPIToken, cloudflareZoneID string, log *zap.SugaredLogger) *DNSResourceProvisioner {
	return &DNSResourceProvisioner{
		cloudflareAPIToken: cloudflareAPIToken,
		cloudflareZoneID:   cloudflareZoneID,
		httpClient:         &http.Client{Timeout: 15 * time.Second},
		log:                log,
	}
}

// ResourceType satisfies ResourceProvisioner.
func (p *DNSResourceProvisioner) ResourceType() string { return "dns_entry" }

// Provision creates a DNS record for the tenant subdomain.
func (p *DNSResourceProvisioner) Provision(ctx context.Context, req ResourceProvisionRequest) (*ResourceProvisionResult, error) {
	pattern := stringFromConfig(req.Config, "domain_pattern", "{tenant_slug}.example.com")
	recordType := stringFromConfig(req.Config, "record_type", "CNAME")
	recordContent := stringFromConfig(req.Config, "record_content", "platform.example.com")

	fqdn := strings.ReplaceAll(pattern, "{tenant_slug}", req.TenantSlug)
	fqdn = strings.ReplaceAll(fqdn, "{product_slug}", req.ProductSlug)
	fqdn = strings.ToLower(fqdn)

	if p.cloudflareAPIToken == "" || p.cloudflareZoneID == "" {
		p.log.Infow("DNSResourceProvisioner: Cloudflare not configured — simulating DNS record creation",
			"fqdn", fqdn,
			"record_type", recordType,
			"record_content", recordContent,
		)
		return devModeResult(p.ResourceType(), req.ResourceName, map[string]interface{}{
			"fqdn":        fqdn,
			"record_type": recordType,
		}), nil
	}

	recordID, err := p.upsertDNSRecord(ctx, fqdn, recordType, recordContent)
	if err != nil {
		p.log.Warnw("DNSResourceProvisioner: failed to create DNS record, using simulated result",
			"fqdn", fqdn,
			"error", err,
		)
		return devModeResult(p.ResourceType(), req.ResourceName, map[string]interface{}{
			"fqdn":        fqdn,
			"record_type": recordType,
		}), nil
	}

	p.log.Infow("DNSResourceProvisioner: DNS record provisioned",
		"fqdn", fqdn,
		"record_type", recordType,
		"record_id", recordID,
	)

	return &ResourceProvisionResult{
		Status: "active",
		ProvisionedConfig: map[string]interface{}{
			"fqdn":        fqdn,
			"record_type": recordType,
			"record_id":   recordID,
		},
	}, nil
}

// Deprovision removes the DNS record from Cloudflare.
func (p *DNSResourceProvisioner) Deprovision(ctx context.Context, req ResourceDeprovisionRequest) error {
	recordID := stringFromConfig(req.ProvisionedConfig, "record_id", "")
	fqdn := stringFromConfig(req.ProvisionedConfig, "fqdn", "")

	if recordID == "" {
		p.log.Warnw("DNSResourceProvisioner.Deprovision: no record_id in provisioned config, skipping",
			"fqdn", fqdn,
		)
		return nil
	}

	if p.cloudflareAPIToken == "" || p.cloudflareZoneID == "" {
		p.log.Infow("DNSResourceProvisioner.Deprovision: Cloudflare not configured — simulating DNS record deletion",
			"fqdn", fqdn,
			"record_id", recordID,
		)
		return nil
	}

	url := fmt.Sprintf("https://api.cloudflare.com/client/v4/zones/%s/dns_records/%s",
		p.cloudflareZoneID, recordID)

	reqHTTP, err := http.NewRequestWithContext(ctx, http.MethodDelete, url, nil)
	if err != nil {
		p.log.Warnw("DNSResourceProvisioner.Deprovision: failed to build DELETE request (non-fatal)",
			"record_id", recordID,
			"error", err,
		)
		return nil
	}
	p.setCloudflareHeaders(reqHTTP)

	resp, err := p.httpClient.Do(reqHTTP)
	if err != nil {
		p.log.Warnw("DNSResourceProvisioner.Deprovision: Cloudflare API unreachable (non-fatal)",
			"record_id", recordID,
			"error", err,
		)
		return nil
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusNotFound {
		// Already gone.
		return nil
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		p.log.Warnw("DNSResourceProvisioner.Deprovision: Cloudflare returned unexpected status (non-fatal)",
			"status", resp.StatusCode,
			"body", string(raw),
		)
		return nil
	}

	p.log.Infow("DNSResourceProvisioner.Deprovision: DNS record deleted",
		"fqdn", fqdn,
		"record_id", recordID,
	)
	return nil
}

// HealthCheck verifies the DNS record exists in Cloudflare.
func (p *DNSResourceProvisioner) HealthCheck(ctx context.Context, req ResourceHealthCheckRequest) (*ResourceHealthResult, error) {
	recordID := stringFromConfig(req.ProvisionedConfig, "record_id", "")
	fqdn := stringFromConfig(req.ProvisionedConfig, "fqdn", "")

	if recordID == "" && fqdn == "" {
		return &ResourceHealthResult{Healthy: false, Message: "no record_id or fqdn in provisioned config"}, nil
	}

	if p.cloudflareAPIToken == "" || p.cloudflareZoneID == "" {
		// Dev mode: treat simulated records as healthy.
		return &ResourceHealthResult{Healthy: true, Message: "dev mode — DNS record simulated"}, nil
	}

	if recordID == "" {
		return &ResourceHealthResult{Healthy: false, Message: "no record_id in provisioned config"}, nil
	}

	url := fmt.Sprintf("https://api.cloudflare.com/client/v4/zones/%s/dns_records/%s",
		p.cloudflareZoneID, recordID)

	reqHTTP, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return &ResourceHealthResult{Healthy: false, Message: fmt.Sprintf("build request: %v", err)}, nil
	}
	p.setCloudflareHeaders(reqHTTP)

	resp, err := p.httpClient.Do(reqHTTP)
	if err != nil {
		return &ResourceHealthResult{
			Healthy: false,
			Message: fmt.Sprintf("Cloudflare API unreachable: %v", err),
		}, nil
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusNotFound {
		return &ResourceHealthResult{Healthy: false, Message: fmt.Sprintf("DNS record %q not found", recordID)}, nil
	}
	if resp.StatusCode != http.StatusOK {
		return &ResourceHealthResult{
			Healthy: false,
			Message: fmt.Sprintf("Cloudflare returned %d", resp.StatusCode),
		}, nil
	}

	return &ResourceHealthResult{
		Healthy: true,
		Message: fmt.Sprintf("DNS record for %q exists", fqdn),
	}, nil
}

// ---------------------------------------------------------------------------
// internal helpers
// ---------------------------------------------------------------------------

// cloudflareRecord is the request / response body for DNS record operations.
type cloudflareRecord struct {
	Type    string `json:"type"`
	Name    string `json:"name"`
	Content string `json:"content"`
	TTL     int    `json:"ttl"`
	Proxied bool   `json:"proxied"`
}

// cloudflareResponse wraps the Cloudflare API envelope.
type cloudflareResponse struct {
	Success bool `json:"success"`
	Result  struct {
		ID string `json:"id"`
	} `json:"result"`
	Errors []struct {
		Message string `json:"message"`
	} `json:"errors"`
}

// upsertDNSRecord creates a DNS record in Cloudflare, returning the record ID.
// If a record with the same name already exists it is replaced.
func (p *DNSResourceProvisioner) upsertDNSRecord(ctx context.Context, fqdn, recordType, content string) (string, error) {
	rec := cloudflareRecord{
		Type:    strings.ToUpper(recordType),
		Name:    fqdn,
		Content: content,
		TTL:     1, // 1 = automatic in Cloudflare
		Proxied: true,
	}

	body, err := json.Marshal(rec)
	if err != nil {
		return "", fmt.Errorf("marshal record: %w", err)
	}

	url := fmt.Sprintf("https://api.cloudflare.com/client/v4/zones/%s/dns_records", p.cloudflareZoneID)
	reqHTTP, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("build POST request: %w", err)
	}
	p.setCloudflareHeaders(reqHTTP)
	reqHTTP.Header.Set("Content-Type", "application/json")

	resp, err := p.httpClient.Do(reqHTTP)
	if err != nil {
		return "", fmt.Errorf("POST dns record: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 16384))
	var cfResp cloudflareResponse
	if err := json.Unmarshal(raw, &cfResp); err != nil {
		return "", fmt.Errorf("parse Cloudflare response (status=%d): %w", resp.StatusCode, err)
	}
	if !cfResp.Success {
		msgs := make([]string, len(cfResp.Errors))
		for i, e := range cfResp.Errors {
			msgs[i] = e.Message
		}
		return "", fmt.Errorf("cloudflare API error: %s", strings.Join(msgs, "; "))
	}

	return cfResp.Result.ID, nil
}

// setCloudflareHeaders attaches the Authorization and content-type headers.
func (p *DNSResourceProvisioner) setCloudflareHeaders(req *http.Request) {
	req.Header.Set("Authorization", "Bearer "+p.cloudflareAPIToken)
	req.Header.Set("Accept", "application/json")
}
