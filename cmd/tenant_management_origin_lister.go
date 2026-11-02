// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/middleware"
)

// Compile-time assertion that httpTenantManagementOriginLister satisfies
// middleware.TenantOriginLister.
var _ middleware.TenantOriginLister = (*httpTenantManagementOriginLister)(nil)

// tenantListWireItem is the subset of tenant-management's
// GET /api/v1/internal/tenants response items this lister needs.
// is_active is the ONLY "verified/active" signal the dependency contract
// (platform-core !80's app-host addition, plus the pre-existing
// GET /tenants list) exposes for a tenant — there is no separate
// DNS/ownership-verification flag for app_host the way falcon-id's own
// iam_tenant_hosts custom-domain feature has (TXT-record verification).
//
// DECISION (documented here since it determines what Stage 3 is allowed to
// admit into CORS/CSRF): app_host is tenant-management ADMIN/PLATFORM
// data — set by tenant-management itself (server-side "<slug>.<apex>" for
// NULL, or an ops-configured custom value for the rest) — not a
// self-service claim a tenant admin types in unverified, the way a custom
// domain in falcon-id's own iam_tenant_hosts registry is. That is exactly
// why iam_tenant_hosts needs DNS TXT verification and tenant-management's
// app_host does not: the trust boundary is "tenant-management, as source
// of truth (ADR-0029), asserts this host belongs to this tenant", not
// "an end user asserts they own this domain". Given that, IsActive is
// used as the sole "may this tenant's host enter the allowlist" gate: an
// inactive/suspended/cancelled tenant's host is refused even if
// tenant-management would still resolve an app_host for it, because a
// deactivated tenant's app deployment (or a reused slug) is no longer a
// trustworthy origin to grant CORS/CSRF trust to.
type tenantListWireItem struct {
	ID       string `json:"id"`
	IsActive bool   `json:"is_active"`
}

type tenantListWireResponse struct {
	Data       []tenantListWireItem `json:"data"`
	Total      int                  `json:"total"`
	Page       int                  `json:"page"`
	PageSize   int                  `json:"page_size"`
	TotalPages int                  `json:"total_pages"`
}

// httpTenantManagementOriginLister implements middleware.TenantOriginLister
// by paginating tenant-management's GET /api/v1/internal/tenants (scope
// platform:tenants:read — svc-falcon-id already holds this grant, see
// buildTenantManagementStatusReaderHTTPClient), filtering to IsActive
// tenants, then resolving each active tenant's app_host via appHostReader
// (scope platform:tenants:app-host:read — the NEW grant this Stage
// requires; see buildTenantManagementAppHostHTTPClient's doc comment).
//
// KNOWN LIMITATION: this is an N+1 access pattern (one list page fetch,
// plus one app-host fetch per active tenant) run on DynamicOriginRegistry's
// TTL cadence (minutes, not per-request) rather than a bulk endpoint,
// because the dependency contract only specifies a per-tenant app-host
// read, not a bulk field on the list response. Acceptable for a
// background refresh; would need a bulk endpoint if the active-tenant
// count grows large enough to make a full pass at the configured TTL
// impractical.
type httpTenantManagementOriginLister struct {
	baseURL       string
	listClient    *http.Client
	appHostReader *httpTenantManagementAppHostReader
	logger        *zap.Logger
	pageSize      int
}

func newHTTPTenantManagementOriginLister(
	baseURL string,
	listClient *http.Client,
	appHostReader *httpTenantManagementAppHostReader,
	logger *zap.Logger,
) *httpTenantManagementOriginLister {
	if logger == nil {
		logger = zap.NewNop()
	}
	return &httpTenantManagementOriginLister{
		baseURL:       baseURL,
		listClient:    listClient,
		appHostReader: appHostReader,
		logger:        logger,
		pageSize:      100,
	}
}

// ListActiveOrigins implements middleware.TenantOriginLister.
func (l *httpTenantManagementOriginLister) ListActiveOrigins(ctx context.Context) ([]string, error) {
	if l.baseURL == "" {
		return nil, fmt.Errorf("origin lister: TENANT_MANAGEMENT_INTERNAL_URL is not configured")
	}
	if l.listClient == nil {
		return nil, fmt.Errorf("origin lister: tenant list HTTP client not configured")
	}
	if l.appHostReader == nil {
		return nil, fmt.Errorf("origin lister: app-host reader not configured")
	}

	var origins []string
	page := 1
	for {
		items, totalPages, err := l.fetchPage(ctx, page)
		if err != nil {
			return nil, err
		}

		for _, item := range items {
			if !item.IsActive {
				continue // SECURITY: inactive tenant — see tenantListWireItem's doc comment
			}
			tenantID, parseErr := uuid.Parse(item.ID)
			if parseErr != nil {
				l.logger.Warn("origin lister: skipping tenant with unparseable id", zap.String("id", item.ID))
				continue
			}
			host, resolveErr := l.appHostReader.ResolveAppHost(ctx, tenantID)
			if resolveErr != nil {
				// Not fatal to the whole refresh: one tenant's app-host
				// call failing (e.g. transient error) should not zero out
				// every other active tenant's origin. The registry-level
				// fail-closed behaviour is about the OVERALL refresh
				// failing, which still happens below if fetchPage itself
				// errors.
				l.logger.Warn("origin lister: app-host resolution failed for active tenant, skipping",
					zap.String("tenant_id", item.ID), zap.Error(resolveErr))
				continue
			}
			origins = append(origins, originFromAppHost(host))
		}

		if totalPages == 0 || page >= totalPages {
			break
		}
		page++
	}

	return origins, nil
}

type tenantListErrorResponse struct {
	Error string `json:"error"`
}

func (l *httpTenantManagementOriginLister) fetchPage(ctx context.Context, page int) ([]tenantListWireItem, int, error) {
	url := fmt.Sprintf("%s/api/v1/internal/tenants?page=%d&page_size=%d", l.baseURL, page, l.pageSize)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, 0, fmt.Errorf("build tenant list request: %w", err)
	}
	httpReq.Header.Set("Accept", "application/json")

	resp, err := l.listClient.Do(httpReq)
	if err != nil {
		return nil, 0, fmt.Errorf("call tenant-management tenant list: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, 0, fmt.Errorf("read tenant list response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		var errResp tenantListErrorResponse
		_ = json.Unmarshal(respBody, &errResp)
		if errResp.Error != "" {
			return nil, 0, fmt.Errorf("tenant-management tenant list failed (%d): %s", resp.StatusCode, errResp.Error)
		}
		return nil, 0, fmt.Errorf("tenant-management tenant list failed (%d)", resp.StatusCode)
	}

	var wireResp tenantListWireResponse
	if err := json.Unmarshal(respBody, &wireResp); err != nil {
		return nil, 0, fmt.Errorf("decode tenant list response: %w", err)
	}

	return wireResp.Data, wireResp.TotalPages, nil
}

// originFromAppHost mirrors internal/services' unexported
// appHostToFrontendURL: prepend https:// unless the host already carries a
// scheme. Duplicated here (rather than exported cross-package) to keep
// cmd's tenant-management HTTP glue self-contained, matching this file's
// sibling cmd/tenant_management_app_host_reader.go.
func originFromAppHost(host string) string {
	if strings.HasPrefix(host, "http://") || strings.HasPrefix(host, "https://") {
		return host
	}
	return "https://" + host
}
