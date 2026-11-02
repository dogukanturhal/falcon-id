// SPDX-License-Identifier: AGPL-3.0-or-later

package tenantpurge

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
)

// TMScope is the scope tenant-management requires on its tenant purge API.
const TMScope = "platform:tenants:admin"

// PlanRun is tenant-management's answer to a started purge run.
type PlanRun struct {
	RunID string `json:"run_id"`
	State string `json:"state"`
}

// TMError is a non-2xx answer from tenant-management.
type TMError struct {
	Status  int
	Message string
}

func (e *TMError) Error() string {
	return fmt.Sprintf("tenant-management purge API: %d %s", e.Status, e.Message)
}

// HTTPStatus lets callers map the failure without importing this package.
func (e *TMError) HTTPStatus() int { return e.Status }

// TMClient calls tenant-management's tenant purge API. falcon-id only ever starts
// a run in plan mode: applying it needs the reviewed plan digest and a backup
// reference, which stay with the operator on tenant-management's own API.
type TMClient struct {
	baseURL string
	http    *http.Client
}

// NewTMClient builds a client; httpClient must already carry TMScope.
func NewTMClient(baseURL string, httpClient *http.Client) *TMClient {
	if httpClient == nil {
		httpClient = &http.Client{}
	}
	if httpClient.Timeout == 0 {
		httpClient.Timeout = 15 * time.Second
	}
	return &TMClient{baseURL: strings.TrimRight(baseURL, "/"), http: httpClient}
}

// StartPlan asks tenant-management to plan the purge of a tenant.
func (c *TMClient) StartPlan(ctx context.Context, tenantID uuid.UUID, reason, actor string, actorID *uuid.UUID) (PlanRun, error) {
	var run PlanRun
	body := map[string]any{
		"tenant_id":   tenantID,
		"kind":        "tenant",
		"reason":      reason,
		"reason_code": "admin_requested",
		"actor":       actor,
	}
	if actorID != nil {
		body["actor_id"] = *actorID
	}
	raw, err := json.Marshal(body)
	if err != nil {
		return run, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/api/v1/internal/admin/tenant-purges", bytes.NewReader(raw))
	if err != nil {
		return run, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return run, fmt.Errorf("call tenant-management purge API: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return run, fmt.Errorf("read tenant-management purge response: %w", err)
	}
	if resp.StatusCode != http.StatusAccepted && resp.StatusCode != http.StatusOK {
		var e struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(data, &e)
		return run, &TMError{Status: resp.StatusCode, Message: e.Error}
	}
	if err := json.Unmarshal(data, &run); err != nil {
		return run, fmt.Errorf("decode tenant-management purge response: %w", err)
	}
	return run, nil
}
