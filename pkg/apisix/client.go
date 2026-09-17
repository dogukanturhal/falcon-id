// SPDX-License-Identifier: AGPL-3.0-or-later

// Package apisix provides an HTTP client for the APISIX Admin API.
// It supports idempotent route and upstream management for dynamic product
// instance registration in the HexxLock platform.
package apisix

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Route represents an APISIX route resource.
// Fields map to the APISIX Admin API route object schema.
type Route struct {
	ID       string            `json:"id,omitempty"`
	URI      string            `json:"uri,omitempty"`
	URIs     []string          `json:"uris,omitempty"`
	Name     string            `json:"name,omitempty"`
	Methods  []string          `json:"methods,omitempty"`
	Upstream *Upstream         `json:"upstream,omitempty"`
	Plugins  map[string]any    `json:"plugins,omitempty"`
	Status   int               `json:"status,omitempty"`
	Labels   map[string]string `json:"labels,omitempty"`
}

// Upstream represents an APISIX upstream resource.
// Nodes maps "host:port" strings to integer weights (e.g., {"svc:8080": 1}).
type Upstream struct {
	ID    string         `json:"id,omitempty"`
	Type  string         `json:"type,omitempty"`
	Nodes map[string]int `json:"nodes,omitempty"`
	Name  string         `json:"name,omitempty"`
}

// adminResponse is the envelope returned by the APISIX Admin API for write
// operations (PUT). The created or updated resource lives under the "value" key.
type adminResponse struct {
	Key   string          `json:"key"`
	Value json.RawMessage `json:"value"`
}

// Client is an HTTP client for the APISIX Admin API.
// It is safe for concurrent use.
type Client struct {
	baseURL    string
	apiKey     string
	httpClient *http.Client
}

// ClientOption is a functional option for configuring a Client.
type ClientOption func(*Client)

// WithHTTPClient replaces the default HTTP client used by the APISIX client.
// Use this in tests to inject a custom transport (e.g., an httptest server).
func WithHTTPClient(c *http.Client) ClientOption {
	return func(cl *Client) {
		cl.httpClient = c
	}
}

// NewClient creates an APISIX Admin API client.
//
// baseURL is the root URL of the APISIX instance, e.g. "http://apisix:9180".
// apiKey is the value sent in the X-API-KEY header for every request.
func NewClient(baseURL, apiKey string, opts ...ClientOption) *Client {
	c := &Client{
		baseURL: baseURL,
		apiKey:  apiKey,
		httpClient: &http.Client{
			Timeout: 15 * time.Second,
		},
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// CreateRoute creates or replaces an APISIX route via PUT.
// When route.ID is non-empty the resource is upserted at that fixed ID,
// ensuring idempotency across retries. Returns the route ID assigned by APISIX.
func (c *Client) CreateRoute(ctx context.Context, route *Route) (string, error) {
	if route == nil {
		return "", fmt.Errorf("apisix.Client.CreateRoute: route must not be nil")
	}

	path := "/apisix/admin/routes"
	if route.ID != "" {
		path = fmt.Sprintf("/apisix/admin/routes/%s", route.ID)
	}

	id, err := c.put(ctx, path, route)
	if err != nil {
		return "", fmt.Errorf("apisix.Client.CreateRoute: %w", err)
	}
	return id, nil
}

// DeleteRoute removes an APISIX route by its ID.
// A 404 response is treated as success (already deleted — idempotent).
func (c *Client) DeleteRoute(ctx context.Context, routeID string) error {
	if routeID == "" {
		return fmt.Errorf("apisix.Client.DeleteRoute: routeID must not be empty")
	}
	path := fmt.Sprintf("/apisix/admin/routes/%s", routeID)
	if err := c.delete(ctx, path); err != nil {
		return fmt.Errorf("apisix.Client.DeleteRoute: %w", err)
	}
	return nil
}

// CreateUpstream creates or replaces an APISIX upstream via PUT.
// Returns the upstream ID assigned by APISIX.
func (c *Client) CreateUpstream(ctx context.Context, upstream *Upstream) (string, error) {
	if upstream == nil {
		return "", fmt.Errorf("apisix.Client.CreateUpstream: upstream must not be nil")
	}

	path := "/apisix/admin/upstreams"
	if upstream.ID != "" {
		path = fmt.Sprintf("/apisix/admin/upstreams/%s", upstream.ID)
	}

	id, err := c.put(ctx, path, upstream)
	if err != nil {
		return "", fmt.Errorf("apisix.Client.CreateUpstream: %w", err)
	}
	return id, nil
}

// DeleteUpstream removes an APISIX upstream by its ID.
// A 404 response is treated as success (already deleted — idempotent).
func (c *Client) DeleteUpstream(ctx context.Context, upstreamID string) error {
	if upstreamID == "" {
		return fmt.Errorf("apisix.Client.DeleteUpstream: upstreamID must not be empty")
	}
	path := fmt.Sprintf("/apisix/admin/upstreams/%s", upstreamID)
	if err := c.delete(ctx, path); err != nil {
		return fmt.Errorf("apisix.Client.DeleteUpstream: %w", err)
	}
	return nil
}

// GetRoute fetches a single APISIX route by its ID.
// Returns nil and a descriptive error when the route is not found.
func (c *Client) GetRoute(ctx context.Context, routeID string) (*Route, error) {
	if routeID == "" {
		return nil, fmt.Errorf("apisix.Client.GetRoute: routeID must not be empty")
	}

	path := fmt.Sprintf("/apisix/admin/routes/%s", routeID)
	body, err := c.get(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("apisix.Client.GetRoute: %w", err)
	}

	// The Admin API returns {"key": "...", "value": {...route...}}.
	var resp adminResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("apisix.Client.GetRoute: decode response: %w", err)
	}

	var route Route
	if err := json.Unmarshal(resp.Value, &route); err != nil {
		return nil, fmt.Errorf("apisix.Client.GetRoute: decode route value: %w", err)
	}
	return &route, nil
}

// put executes a PUT request against the APISIX Admin API.
// It serialises body as JSON and returns the resource ID extracted from the
// response envelope. APISIX encodes the resource ID in the "key" field as
// "/apisix/admin/<resource>/<id>", so we parse the trailing segment.
func (c *Client) put(ctx context.Context, path string, body any) (string, error) {
	data, err := json.Marshal(body)
	if err != nil {
		return "", fmt.Errorf("marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPut, c.baseURL+path, bytes.NewReader(data))
	if err != nil {
		return "", fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-KEY", c.apiKey)

	respBody, statusCode, err := c.do(req)
	if err != nil {
		return "", err
	}

	// APISIX returns 200 for updates and 201 for creates.
	if statusCode != http.StatusOK && statusCode != http.StatusCreated {
		return "", fmt.Errorf("unexpected status %d: %s", statusCode, truncate(respBody, 256))
	}

	var resp adminResponse
	if err := json.Unmarshal(respBody, &resp); err != nil {
		return "", fmt.Errorf("decode response: %w", err)
	}

	// Extract the ID from the key path, e.g. "/apisix/admin/routes/abc123" → "abc123".
	return extractIDFromKey(resp.Key), nil
}

// delete executes a DELETE request against the APISIX Admin API.
// A 404 status is silently ignored (resource already absent — idempotent).
func (c *Client) delete(ctx context.Context, path string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, c.baseURL+path, nil)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("X-API-KEY", c.apiKey)

	respBody, statusCode, err := c.do(req)
	if err != nil {
		return err
	}

	if statusCode == http.StatusNotFound {
		// Already deleted — treat as success.
		return nil
	}

	if statusCode != http.StatusOK && statusCode != http.StatusNoContent {
		return fmt.Errorf("unexpected status %d: %s", statusCode, truncate(respBody, 256))
	}
	return nil
}

// get executes a GET request against the APISIX Admin API and returns the raw
// response body. Returns an error on non-2xx status.
func (c *Client) get(ctx context.Context, path string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+path, nil)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("X-API-KEY", c.apiKey)

	respBody, statusCode, err := c.do(req)
	if err != nil {
		return nil, err
	}

	if statusCode == http.StatusNotFound {
		return nil, fmt.Errorf("resource not found")
	}
	if statusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %d: %s", statusCode, truncate(respBody, 256))
	}
	return respBody, nil
}

// do executes an HTTP request and returns the response body, status code, and
// any transport-level error. It always drains and closes the response body.
func (c *Client) do(req *http.Request) ([]byte, int, error) {
	resp, err := c.httpClient.Do(req) //nolint:gosec // URL is validated before use
	if err != nil {
		return nil, 0, fmt.Errorf("http request: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, resp.StatusCode, fmt.Errorf("read response body: %w", err)
	}
	return body, resp.StatusCode, nil
}

// extractIDFromKey parses the APISIX Admin API key path and returns the final
// segment, which is the resource ID.
// Example: "/apisix/admin/routes/abc123" → "abc123"
func extractIDFromKey(key string) string {
	for i := len(key) - 1; i >= 0; i-- {
		if key[i] == '/' {
			return key[i+1:]
		}
	}
	return key
}

// truncate returns at most maxLen bytes of b as a string. It is used to
// cap error messages that include raw HTTP response bodies.
func truncate(b []byte, maxLen int) string {
	if len(b) <= maxLen {
		return string(b)
	}
	return string(b[:maxLen]) + "…"
}
