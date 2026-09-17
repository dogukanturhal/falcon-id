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

// httpTenantManagementStatusReader implements
// services.TenantManagementStatusReader by calling tenant-management's
// existing S2S-scope-gated GET /api/v1/internal/tenants/{id} endpoint
// (services/tenant-management/cmd/init.go::registerInternalReadRoutes,
// gated on platform:tenants:read) with an OAuth-authenticated
// client_credentials client. No new tenant-management endpoint was added
// for this — TenantHandler.Get already returns the full Tenant JSON,
// slug_confirmed_at included; this reader just decodes the one field the
// onboarding-status handler needs.
type httpTenantManagementStatusReader struct {
	baseURL string
	client  *http.Client
}

// newHTTPTenantManagementStatusReader builds the reader. httpClient is
// expected to already be OAuth-authenticated (see
// buildTenantManagementStatusReaderHTTPClient in cmd/services.go),
// carrying the platform:tenants:read scope svc-falcon-id's
// ServiceClientClaim already grants (reused as-is — see
// cmd/background.go's identical scope on its own read call — no new S2S
// grant required).
func newHTTPTenantManagementStatusReader(baseURL string, httpClient *http.Client) *httpTenantManagementStatusReader {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 10 * time.Second}
	}
	return &httpTenantManagementStatusReader{
		baseURL: baseURL,
		client:  httpClient,
	}
}

// getTenantStatusWireResponse decodes only the field this caller needs
// from tenant-management's models.Tenant JSON response. NOTE: unlike
// updateTenantSlugWireResponse (cmd/tenant_management_slug_updater.go),
// widening THAT struct to also decode slug_confirmed_at was considered
// and explicitly rejected as a substitute for this reader — it is a
// separate, independently-justified change (it would only cover the
// slug-CONFIRM path, not the read-at-wizard-entry path this endpoint
// serves) and is out of scope here.
type getTenantStatusWireResponse struct {
	ID              uuid.UUID  `json:"id"`
	SlugConfirmedAt *time.Time `json:"slug_confirmed_at"`
}

type getTenantStatusErrorResponse struct {
	Error string `json:"error"`
}

func (r *httpTenantManagementStatusReader) GetTenantOnboardingStatus(
	ctx context.Context,
	tenantID uuid.UUID,
) (*services.TenantOnboardingStatus, error) {
	if r.baseURL == "" {
		return nil, fmt.Errorf("tenant-management status reader: TENANT_MANAGEMENT_INTERNAL_URL is not configured")
	}

	url := fmt.Sprintf("%s/api/v1/internal/tenants/%s", r.baseURL, tenantID.String())
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("build tenant status request: %w", err)
	}
	httpReq.Header.Set("Accept", "application/json")

	// NOTE: the tenant-management HTTP timeout enforced here is only the
	// r.client's own — this reader does not itself impose a shorter
	// deadline. r.client is built via serviceauth.NewIAMHTTPClient
	// (cmd/services.go::buildTenantManagementStatusReaderHTTPClient); the
	// serviceauth package is not vendored locally so its internal
	// transport timeout could not be directly confirmed from this repo.
	// It is ASSUMED bounded (mirroring newHTTPTenantManagementStatusReader's
	// own 10s fallback default above, used only when httpClient is nil)
	// but this is unverified — worth confirming separately, since an
	// unbounded timeout on this wizard-entry-time call could hang the
	// onboarding flow.
	resp, err := r.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("call tenant-management status read: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("read tenant status response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		var errResp getTenantStatusErrorResponse
		_ = json.Unmarshal(respBody, &errResp)
		if errResp.Error != "" {
			return nil, fmt.Errorf("tenant-management status read failed (%d): %s", resp.StatusCode, errResp.Error)
		}
		return nil, fmt.Errorf("tenant-management status read failed (%d)", resp.StatusCode)
	}

	var wireResp getTenantStatusWireResponse
	if err := json.Unmarshal(respBody, &wireResp); err != nil {
		return nil, fmt.Errorf("decode tenant status response: %w", err)
	}

	return &services.TenantOnboardingStatus{
		SlugConfirmed: wireResp.SlugConfirmedAt != nil,
	}, nil
}
