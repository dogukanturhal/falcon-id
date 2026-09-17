// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/dogukanturhal/falcon-id/internal/services"
)

// httpTenantManagementSlugUpdater implements services.TenantManagementSlugUpdater
// by calling tenant-management's S2S-scope-gated
// PUT /api/v1/internal/tenants/{id} endpoint with an OAuth-authenticated
// client_credentials client — unlike httpTenantManagementRegistrar's
// Register call, this mutates an EXISTING tenant (a rename, not a
// brand-new signup) so it MUST go through the authenticated
// /api/v1/internal/tenants* surface, not the bare, unauthenticated
// /api/v1/tenants/register route.
type httpTenantManagementSlugUpdater struct {
	baseURL string
	client  *http.Client
}

// newHTTPTenantManagementSlugUpdater builds the updater. httpClient is
// expected to already be OAuth-authenticated (see
// buildTenantManagementSlugUpdaterHTTPClient in cmd/services.go), carrying
// the platform:tenants:write scope svc-falcon-id's ServiceClientClaim
// grants.
func newHTTPTenantManagementSlugUpdater(baseURL string, httpClient *http.Client) *httpTenantManagementSlugUpdater {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 10 * time.Second}
	}
	return &httpTenantManagementSlugUpdater{
		baseURL: baseURL,
		client:  httpClient,
	}
}

// updateTenantSlugWireRequest mirrors tenant-management's
// models.UpdateTenantRequest, sending only the Slug field.
type updateTenantSlugWireRequest struct {
	Slug string `json:"slug"`
}

// updateTenantSlugWireResponse decodes only the fields this caller needs
// from tenant-management's models.Tenant JSON response.
type updateTenantSlugWireResponse struct {
	ID   uuid.UUID `json:"id"`
	Slug string    `json:"slug"`
}

type updateTenantSlugErrorResponse struct {
	Error string `json:"error"`
}

func (r *httpTenantManagementSlugUpdater) UpdateSlug(
	ctx context.Context,
	tenantID uuid.UUID,
	slug string,
) (*services.TenantManagementSlugUpdateResult, error) {
	if r.baseURL == "" {
		return nil, fmt.Errorf("tenant-management slug updater: TENANT_MANAGEMENT_INTERNAL_URL is not configured")
	}

	body, err := json.Marshal(updateTenantSlugWireRequest{Slug: slug})
	if err != nil {
		return nil, fmt.Errorf("marshal tenant slug update request: %w", err)
	}

	url := fmt.Sprintf("%s/api/v1/internal/tenants/%s", r.baseURL, tenantID.String())
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPut, url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("build tenant slug update request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "application/json")

	resp, err := r.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("call tenant-management slug update: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("read tenant slug update response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		var errResp updateTenantSlugErrorResponse
		_ = json.Unmarshal(respBody, &errResp)
		if errResp.Error != "" {
			return nil, fmt.Errorf("tenant-management slug update failed (%d): %s", resp.StatusCode, errResp.Error)
		}
		return nil, fmt.Errorf("tenant-management slug update failed (%d)", resp.StatusCode)
	}

	var wireResp updateTenantSlugWireResponse
	if err := json.Unmarshal(respBody, &wireResp); err != nil {
		return nil, fmt.Errorf("decode tenant slug update response: %w", err)
	}

	return &services.TenantManagementSlugUpdateResult{ID: wireResp.ID, Slug: wireResp.Slug}, nil
}
