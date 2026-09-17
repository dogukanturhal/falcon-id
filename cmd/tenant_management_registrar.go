// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/dogukanturhal/falcon-id/internal/services"
)

// httpTenantManagementRegistrar implements services.TenantManagementRegistrar
// by calling tenant-management's public, unauthenticated
// POST /api/v1/tenants/register endpoint directly.
//
// Plain http.Client on purpose, no OAuth2 client-credentials wiring: unlike
// the S2S-scope-gated /api/v1/internal/tenants* surface (reserved for
// projection consumers — quota-service, falcon-id's own tenantprojection
// bootstrap — via ServiceClientClaim scope grants that live in
// the GitOps repository), /tenants/register is mounted directly on tenant-
// management's bare v1 router group before any auth middleware (confirmed
// by reading services/tenant-management/cmd/init.go's registerRoutes). It
// is the correct, already-public integration point for a brand-new
// tenant that by definition has no credentials yet.
type httpTenantManagementRegistrar struct {
	baseURL string
	client  *http.Client
}

func newHTTPTenantManagementRegistrar(baseURL string) *httpTenantManagementRegistrar {
	return &httpTenantManagementRegistrar{
		baseURL: baseURL,
		client:  &http.Client{Timeout: 10 * time.Second},
	}
}

// registerTenantWireRequest mirrors tenant-management's
// models.RegisterTenantRequest exactly (tenant_name, tenant_slug, email,
// first_name, last_name, password all required by its binding tags).
type registerTenantWireRequest struct {
	TenantName string `json:"tenant_name"`
	TenantSlug string `json:"tenant_slug"`
	Email      string `json:"email"`
	FirstName  string `json:"first_name"`
	LastName   string `json:"last_name"`
	Password   string `json:"password"`
}

// registerTenantWireResponse decodes only the fields this caller needs from
// tenant-management's models.Tenant JSON response.
type registerTenantWireResponse struct {
	ID uuid.UUID `json:"id"`
}

type registerTenantErrorResponse struct {
	Error string `json:"error"`
}

func (r *httpTenantManagementRegistrar) Register(
	ctx context.Context,
	req *services.TenantManagementRegisterRequest,
) (*services.TenantManagementRegisterResult, error) {
	if r.baseURL == "" {
		return nil, fmt.Errorf("tenant-management registrar: TENANT_MANAGEMENT_INTERNAL_URL is not configured")
	}

	// Throwaway password satisfying RegisterTenantRequest.Password's
	// `required,min=8` validator. Never the user's real password (that is
	// set separately, in falcon-id's own DB, by provisionUser) and never
	// logged — see TenantManagementRegisterRequest's doc comment for why
	// this is safe: tenant-management's Register handler validates but
	// never persists this field.
	throwawayPassword, err := randomHex(24)
	if err != nil {
		return nil, fmt.Errorf("generate throwaway registration secret: %w", err)
	}

	wireReq := registerTenantWireRequest{
		TenantName: req.TenantName,
		TenantSlug: req.TenantSlug,
		Email:      req.Email,
		FirstName:  req.FirstName,
		LastName:   req.LastName,
		Password:   throwawayPassword,
	}

	body, err := json.Marshal(wireReq)
	if err != nil {
		return nil, fmt.Errorf("marshal tenant register request: %w", err)
	}

	url := r.baseURL + "/api/v1/tenants/register"
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("build tenant register request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "application/json")

	resp, err := r.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("call tenant-management register: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("read tenant register response: %w", err)
	}

	if resp.StatusCode != http.StatusCreated {
		var errResp registerTenantErrorResponse
		_ = json.Unmarshal(respBody, &errResp)
		if errResp.Error != "" {
			return nil, fmt.Errorf("tenant-management register failed (%d): %s", resp.StatusCode, errResp.Error)
		}
		return nil, fmt.Errorf("tenant-management register failed (%d)", resp.StatusCode)
	}

	var wireResp registerTenantWireResponse
	if err := json.Unmarshal(respBody, &wireResp); err != nil {
		return nil, fmt.Errorf("decode tenant register response: %w", err)
	}
	if wireResp.ID == uuid.Nil {
		return nil, fmt.Errorf("tenant-management register response missing tenant id")
	}

	return &services.TenantManagementRegisterResult{ID: wireResp.ID}, nil
}

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
