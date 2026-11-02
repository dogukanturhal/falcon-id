// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
)

// BusinessAPIKeyScope is the space-separated S2S scope set the business
// internal endpoint requires: tenant:act-as (the tenant comes from X-Tenant-ID)
// plus iam:api-keys:sync.
const BusinessAPIKeyScope = "tenant:act-as iam:api-keys:sync"

// businessAPIKeyCompaniesPath is the business endpoint that owns the
// company edges of an API key principal. keyId is the iam_api_keys row id.
const businessAPIKeyCompaniesPath = "/api/v1/core/internal/api-key-principals/%s/companies"

// BusinessAPIKeyClient implements TenantAPIKeyCompanyClient over HTTP.
//
// Contract (built separately in business):
//
//	POST   {base}/api/v1/core/internal/api-key-principals/{keyId}/companies
//	DELETE {base}/api/v1/core/internal/api-key-principals/{keyId}/companies
//	header X-Tenant-ID: <tenant uuid>
//	body   {"companyIds": ["<uuid>", ...]}   (1-200 ids)
//
// POST idempotently grants the key access to the listed companies, DELETE
// idempotently removes it (an unknown principal on DELETE counts as done).
// Auth: client_credentials bearer with scopes tenant:act-as and
// iam:api-keys:sync. A 400 (invalid_company_ids) or 422 (company_not_in_tenant)
// reply is a *BusinessCompanyEdgeError with Terminal() true: retrying cannot
// succeed. 5xx and network errors are plain errors and keep retrying.
type BusinessAPIKeyClient struct {
	baseURL string
	client  *http.Client
}

// NewBusinessAPIKeyClient builds the client. httpClient is expected to be the
// OAuth-authenticated S2S client.
func NewBusinessAPIKeyClient(baseURL string, httpClient *http.Client) *BusinessAPIKeyClient {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 10 * time.Second}
	}
	return &BusinessAPIKeyClient{baseURL: strings.TrimRight(baseURL, "/"), client: httpClient}
}

type businessAPIKeyCompaniesBody struct {
	CompanyIDs []uuid.UUID `json:"companyIds"`
}

// businessAPIKeyProblem is the part of business's problem+json reply we use.
type businessAPIKeyProblem struct {
	Code       string      `json:"code"`
	CompanyIDs []uuid.UUID `json:"companyIds"`
}

// BusinessCompanyEdgeError is a non-2xx reply from the business endpoint.
type BusinessCompanyEdgeError struct {
	Method     string
	StatusCode int
	Code       string      // business error code, e.g. company_not_in_tenant
	CompanyIDs []uuid.UUID // offending ids on 422
}

func (e *BusinessCompanyEdgeError) Error() string {
	if e.Code != "" {
		return fmt.Sprintf("business company edge %s: status %d (%s)", e.Method, e.StatusCode, e.Code)
	}
	return fmt.Sprintf("business company edge %s: unexpected status %d", e.Method, e.StatusCode)
}

// Terminal reports whether retrying the same call can never succeed (400
// invalid_company_ids, 422 company_not_in_tenant).
func (e *BusinessCompanyEdgeError) Terminal() bool {
	return e.StatusCode == http.StatusBadRequest || e.StatusCode == http.StatusUnprocessableEntity
}

// companySyncTerminal extracts a terminal business error from err, if any.
func companySyncTerminal(err error) (*BusinessCompanyEdgeError, bool) {
	var be *BusinessCompanyEdgeError
	if errors.As(err, &be) && be.Terminal() {
		return be, true
	}
	return nil, false
}

// AddCompanies grants the key access to companyIDs.
func (c *BusinessAPIKeyClient) AddCompanies(ctx context.Context, tenantID, keyID uuid.UUID, companyIDs []uuid.UUID) error {
	return c.do(ctx, http.MethodPost, tenantID, keyID, companyIDs, false)
}

// RemoveCompanies removes the key's access to companyIDs.
func (c *BusinessAPIKeyClient) RemoveCompanies(ctx context.Context, tenantID, keyID uuid.UUID, companyIDs []uuid.UUID) error {
	return c.do(ctx, http.MethodDelete, tenantID, keyID, companyIDs, true)
}

func (c *BusinessAPIKeyClient) do(ctx context.Context, method string, tenantID, keyID uuid.UUID, companyIDs []uuid.UUID, notFoundOK bool) error {
	if c.baseURL == "" {
		return fmt.Errorf("business api-key client: BUSINESS_INTERNAL_URL is not configured")
	}
	payload, err := json.Marshal(businessAPIKeyCompaniesBody{CompanyIDs: nonNilIDs(companyIDs)})
	if err != nil {
		return fmt.Errorf("marshal company edge body: %w", err)
	}
	url := c.baseURL + fmt.Sprintf(businessAPIKeyCompaniesPath, keyID.String())
	req, err := http.NewRequestWithContext(ctx, method, url, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("build company edge request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("X-Tenant-ID", tenantID.String())
	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("business company edge %s: %w", method, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}
	if notFoundOK && resp.StatusCode == http.StatusNotFound {
		return nil
	}
	be := &BusinessCompanyEdgeError{Method: method, StatusCode: resp.StatusCode}
	var problem businessAPIKeyProblem
	if json.Unmarshal(raw, &problem) == nil {
		be.Code, be.CompanyIDs = problem.Code, problem.CompanyIDs
	}
	return be
}
