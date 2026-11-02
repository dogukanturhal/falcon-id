// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/dogukanturhal/falcon-id/internal/services"
)

// Compile-time assertion that httpTenantManagementAppHostReader satisfies
// services.TenantAppHostResolver.
var _ services.TenantAppHostResolver = (*httpTenantManagementAppHostReader)(nil)

// httpTenantManagementAppHostReader implements services.TenantAppHostResolver
// by calling tenant-management's GET /api/v1/internal/tenants/{id}/app-host
// endpoint (platform-core !80, not merged as of this writing) with an
// OAuth-authenticated client_credentials client scoped to
// platform:tenants:app-host:read — a scope deliberately separate from the
// blanket platform:tenants:read svc-falcon-id already holds, so this reader
// needs its own ServiceClientClaim grant (see
// buildTenantManagementAppHostHTTPClient in cmd/services.go).
//
// UNVERIFIED: platform-core !80 is not merged and its response body shape
// was not available to read directly. The wire struct below assumes a
// `{"app_host": "<host>"}` JSON body mirroring the column name given in the
// dependency contract; this must be confirmed against the real MR before
// this endpoint is exercised end-to-end.
type httpTenantManagementAppHostReader struct {
	baseURL string
	client  *http.Client
}

// newHTTPTenantManagementAppHostReader builds the reader. httpClient is
// expected to already be OAuth-authenticated with the
// platform:tenants:app-host:read scope (see
// buildTenantManagementAppHostHTTPClient in cmd/services.go).
func newHTTPTenantManagementAppHostReader(baseURL string, httpClient *http.Client) *httpTenantManagementAppHostReader {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 10 * time.Second}
	}
	return &httpTenantManagementAppHostReader{
		baseURL: baseURL,
		client:  httpClient,
	}
}

// getAppHostWireResponse decodes tenant-management's app-host response.
// See the UNVERIFIED note on httpTenantManagementAppHostReader above.
type getAppHostWireResponse struct {
	AppHost string `json:"app_host"`
}

type getAppHostErrorResponse struct {
	Error string `json:"error"`
}

// ResolveAppHost implements services.TenantAppHostResolver.
func (r *httpTenantManagementAppHostReader) ResolveAppHost(ctx context.Context, tenantID uuid.UUID) (string, error) {
	if r.baseURL == "" {
		return "", fmt.Errorf("tenant-management app-host reader: TENANT_MANAGEMENT_INTERNAL_URL is not configured")
	}

	url := fmt.Sprintf("%s/api/v1/internal/tenants/%s/app-host", r.baseURL, tenantID.String())
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", fmt.Errorf("build app-host request: %w", err)
	}
	httpReq.Header.Set("Accept", "application/json")

	// As with httpTenantManagementStatusReader, r.client's own timeout is
	// the only bound enforced here — serviceauth.NewIAMHTTPClient's
	// internal transport timeout is not vendored locally to confirm.
	resp, err := r.client.Do(httpReq)
	if err != nil {
		return "", fmt.Errorf("call tenant-management app-host read: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", fmt.Errorf("read app-host response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		var errResp getAppHostErrorResponse
		_ = json.Unmarshal(respBody, &errResp)
		if errResp.Error != "" {
			return "", fmt.Errorf("tenant-management app-host read failed (%d): %s", resp.StatusCode, errResp.Error)
		}
		return "", fmt.Errorf("tenant-management app-host read failed (%d)", resp.StatusCode)
	}

	var wireResp getAppHostWireResponse
	if err := json.Unmarshal(respBody, &wireResp); err != nil {
		return "", fmt.Errorf("decode app-host response: %w", err)
	}
	if wireResp.AppHost == "" {
		return "", fmt.Errorf("tenant-management app-host read: empty app_host in response")
	}

	return wireResp.AppHost, nil
}
