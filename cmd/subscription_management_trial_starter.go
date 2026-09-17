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
)

// httpSubscriptionManagementTrialStarter implements
// services.TrialStarter by calling subscription-management's
// S2S scope-gated POST /api/v1/internal/tenants/{id}/trial endpoint
// with an OAuth-authenticated client_credentials client.
//
// Deliberately sends an empty body: the internal endpoint's PackageID
// field is optional and, when omitted, subscription-management falls
// back to its own operator-configured default package
// (subscription_packages.is_default) rather than falcon-id supplying
// one. Falcon-id has no pricing/plan concept of its own to supply here.
type httpSubscriptionManagementTrialStarter struct {
	baseURL string
	client  *http.Client
}

// newHTTPSubscriptionManagementTrialStarter builds the trial starter.
// httpClient is expected to already be OAuth-authenticated (see
// buildSubscriptionManagementTrialStarterHTTPClient in cmd/services.go),
// carrying the subscription-management:trials:start scope svc-falcon-id's
// ServiceClientClaim grants.
func newHTTPSubscriptionManagementTrialStarter(baseURL string, httpClient *http.Client) *httpSubscriptionManagementTrialStarter {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 10 * time.Second}
	}
	return &httpSubscriptionManagementTrialStarter{
		baseURL: baseURL,
		client:  httpClient,
	}
}

type startTrialErrorResponse struct {
	Error string `json:"error"`
}

// StartTrial implements services.TrialStarter. packageCode, when non-empty,
// is sent as InternalStartTrialRequest.PackageCode so subscription-management
// resolves the specific subscription_packages row the user picked at
// signup (see PackageRepository.FindByCode); when empty the body is `{}`
// and subscription-management falls back to its own operator-configured
// default package (subscription_packages.is_default) rather than falcon-id
// guessing one.
func (r *httpSubscriptionManagementTrialStarter) StartTrial(ctx context.Context, tenantID uuid.UUID, packageCode string) error {
	if r.baseURL == "" {
		return fmt.Errorf("subscription-management trial starter: SUBSCRIPTION_MANAGEMENT_INTERNAL_URL is not configured")
	}

	bodyBytes := []byte("{}")
	if packageCode != "" {
		encoded, err := json.Marshal(struct {
			PackageCode string `json:"package_code"`
		}{PackageCode: packageCode})
		if err != nil {
			return fmt.Errorf("encode trial start request: %w", err)
		}
		bodyBytes = encoded
	}

	url := fmt.Sprintf("%s/api/v1/internal/tenants/%s/trial", r.baseURL, tenantID.String())
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(bodyBytes))
	if err != nil {
		return fmt.Errorf("build trial start request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "application/json")

	resp, err := r.client.Do(httpReq)
	if err != nil {
		return fmt.Errorf("call subscription-management trial start: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return fmt.Errorf("read trial start response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		var errResp startTrialErrorResponse
		_ = json.Unmarshal(respBody, &errResp)
		if errResp.Error != "" {
			return fmt.Errorf("subscription-management trial start failed (%d): %s", resp.StatusCode, errResp.Error)
		}
		return fmt.Errorf("subscription-management trial start failed (%d)", resp.StatusCode)
	}

	return nil
}
