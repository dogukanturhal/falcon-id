// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	serviceauth "github.com/dogukanturhal/platform-shared/service-auth"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/repositories"
	"github.com/dogukanturhal/falcon-id/internal/services"
	"github.com/dogukanturhal/falcon-id/pkg/config"
)

// businessWorkspaceNameScope is what the business default-legal-entity read
// needs: tenant:act-as (the tenant comes from X-Tenant-ID) plus the
// endpoint-specific legalentity:default:read.
const businessWorkspaceNameScope = "tenant:act-as legalentity:default:read"

// httpTenantManagementNameClient reads (platform:tenants:read) and renames
// (platform:tenants:write) tenants.name through tenant-management's S2S
// /api/v1/internal/tenants/{id}. Names are never logged or echoed in errors.
type httpTenantManagementNameClient struct {
	baseURL string
	reader  *http.Client
	writer  *http.Client
}

func (c *httpTenantManagementNameClient) GetName(ctx context.Context, tenantID uuid.UUID) (string, error) {
	url := fmt.Sprintf("%s/api/v1/internal/tenants/%s", c.baseURL, tenantID)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", fmt.Errorf("build tenant-management name read: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	resp, err := c.reader.Do(req)
	if err != nil {
		return "", fmt.Errorf("call tenant-management name read: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", fmt.Errorf("read tenant-management name response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("tenant-management name read failed (%d)", resp.StatusCode)
	}
	var wire struct {
		Name string `json:"name"`
	}
	if err := json.Unmarshal(body, &wire); err != nil {
		return "", fmt.Errorf("decode tenant-management name response: %w", err)
	}
	return wire.Name, nil
}

func (c *httpTenantManagementNameClient) UpdateName(ctx context.Context, tenantID uuid.UUID, name string) error {
	payload, err := json.Marshal(struct {
		Name string `json:"name"`
	}{Name: name})
	if err != nil {
		return fmt.Errorf("marshal tenant-management name update: %w", err)
	}
	url := fmt.Sprintf("%s/api/v1/internal/tenants/%s", c.baseURL, tenantID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, url, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("build tenant-management name update: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := c.writer.Do(req)
	if err != nil {
		return fmt.Errorf("call tenant-management name update: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("tenant-management name update failed (%d)", resp.StatusCode)
	}
	return nil
}

// httpBusinessDefaultCompanyReader reads a tenant's default legal entity title
// from business: GET /internal/v1/tenants/{id}/default-legal-entity (404 = none).
type httpBusinessDefaultCompanyReader struct {
	baseURL string
	client  *http.Client
}

func (r *httpBusinessDefaultCompanyReader) DefaultCompanyName(ctx context.Context, tenantID uuid.UUID) (string, bool, error) {
	url := fmt.Sprintf("%s/internal/v1/tenants/%s/default-legal-entity", r.baseURL, tenantID)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", false, fmt.Errorf("build business default-legal-entity read: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("X-Tenant-ID", tenantID.String())
	resp, err := r.client.Do(req)
	if err != nil {
		return "", false, fmt.Errorf("call business default-legal-entity: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", false, fmt.Errorf("read business default-legal-entity response: %w", err)
	}
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotFound:
		return "", false, nil
	default:
		return "", false, fmt.Errorf("business default-legal-entity failed (%d)", resp.StatusCode)
	}
	var wire struct {
		LegalName string `json:"legalName"`
	}
	if err := json.Unmarshal(body, &wire); err != nil {
		return "", false, fmt.Errorf("decode business default-legal-entity response: %w", err)
	}
	return wire.LegalName, strings.TrimSpace(wire.LegalName) != "", nil
}

// buildTenantWorkspaceNameService wires the placeholder-name service. The
// tenant-management mirror and the business reader are each optional: missing
// creds or URLs degrade that half (rename stays local / backfill refuses) rather
// than disabling the service.
func buildTenantWorkspaceNameService(cfg *config.Config, tenantRepo *repositories.TenantRepository, log *zap.Logger) *services.TenantWorkspaceNameService {
	var tm services.TenantManagementNameClient
	writer := buildTenantManagementSlugUpdaterHTTPClient(cfg, log)
	reader := buildTenantManagementStatusReaderHTTPClient(cfg, log)
	if writer != nil && reader != nil {
		tm = &httpTenantManagementNameClient{baseURL: strings.TrimRight(cfg.TenantManagementInternalURL, "/"), reader: reader, writer: writer}
	}

	var company services.DefaultCompanyNameReader
	if cfg.BusinessInternalURL != "" && cfg.ServiceClientID != "" && cfg.ServiceClientSecret != "" && cfg.IAMServiceURL != "" {
		client, err := serviceauth.NewIAMHTTPClient(serviceauth.IAMHTTPClientConfig{
			IAMURL:       cfg.IAMServiceURL,
			ClientID:     cfg.ServiceClientID,
			ClientSecret: cfg.ServiceClientSecret,
			Scope:        businessWorkspaceNameScope,
		})
		if err != nil {
			log.Error("workspace name backfill disabled: NewIAMHTTPClient failed", zap.Error(err))
		} else {
			if client.Timeout == 0 {
				client.Timeout = 10 * time.Second
			}
			company = &httpBusinessDefaultCompanyReader{baseURL: strings.TrimRight(cfg.BusinessInternalURL, "/"), client: client}
		}
	} else {
		log.Warn("workspace name backfill disabled: business URL or S2S credentials missing")
	}
	return services.NewTenantWorkspaceNameService(tenantRepo, tm, company, log)
}
