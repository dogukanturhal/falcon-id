// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

// httpTenantManagementSlugChecker implements
// services.TenantSlugAvailabilityChecker by calling tenant-management's
// S2S-scope-gated GET /api/v1/internal/tenants/slug-available/{slug}
// endpoint (platform:tenants:read — see
// buildTenantManagementSlugCheckerHTTPClient) with an OAuth-authenticated
// client_credentials client. Used by SignupService's up-front "claim your
// subdomain" signup step and by the live check-slug endpoint, both of
// which need a real synchronous answer — unlike the public
// /tenants/register call the ORIGINAL signup flow uses, this cannot
// piggyback on a create-and-see-if-it-fails retry loop, since the slug
// must be validated BEFORE the tenant even exists.
type httpTenantManagementSlugChecker struct {
	baseURL string
	client  *http.Client
}

func newHTTPTenantManagementSlugChecker(baseURL string, httpClient *http.Client) *httpTenantManagementSlugChecker {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 10 * time.Second}
	}
	return &httpTenantManagementSlugChecker{baseURL: baseURL, client: httpClient}
}

type slugAvailableWireResponse struct {
	Available bool `json:"available"`
}

// IsSlugAvailable implements services.TenantSlugAvailabilityChecker.
func (r *httpTenantManagementSlugChecker) IsSlugAvailable(ctx context.Context, slug string) (bool, error) {
	if r.baseURL == "" {
		return false, fmt.Errorf("tenant-management slug checker: TENANT_MANAGEMENT_INTERNAL_URL is not configured")
	}

	reqURL := fmt.Sprintf("%s/api/v1/internal/tenants/slug-available/%s", r.baseURL, url.PathEscape(slug))
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return false, fmt.Errorf("build slug availability request: %w", err)
	}
	httpReq.Header.Set("Accept", "application/json")

	resp, err := r.client.Do(httpReq)
	if err != nil {
		return false, fmt.Errorf("call tenant-management slug availability: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return false, fmt.Errorf("read slug availability response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("tenant-management slug availability check failed (%d)", resp.StatusCode)
	}

	var wireResp slugAvailableWireResponse
	if err := json.Unmarshal(respBody, &wireResp); err != nil {
		return false, fmt.Errorf("decode slug availability response: %w", err)
	}

	return wireResp.Available, nil
}
