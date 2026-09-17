// SPDX-License-Identifier: AGPL-3.0-or-later

package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
)

// FalconClient is the interface for interacting with the Falcon ID API.
type FalconClient interface {
	Login(ctx context.Context, req *LoginRequest) (*LoginResponse, error)
	Logout(ctx context.Context) error
	Whoami(ctx context.Context) (*WhoamiResponse, error)
	ListUsers(ctx context.Context, opts *ListOptions) (*UserListResponse, error)
	GetUser(ctx context.Context, id string) (*UserResponse, error)
	CreateUser(ctx context.Context, req *CreateUserRequest) (*UserResponse, error)
	DeleteUser(ctx context.Context, id string) error
	ListRoles(ctx context.Context, opts *ListOptions) (*RoleListResponse, error)
	GetRole(ctx context.Context, id string) (*RoleResponse, error)
	ListPermissions(ctx context.Context, opts *ListOptions) (*PermissionListResponse, error)
	ListTenants(ctx context.Context, opts *ListOptions) (*TenantListResponse, error)
	ListRealms(ctx context.Context, opts *ListOptions) (*RealmListResponse, error)
	GenerateToken(ctx context.Context, req *GenerateTokenRequest) (*TokenResponse, error)
	Health(ctx context.Context) (*HealthResponse, error)
}

// HTTPClient implements FalconClient using HTTP calls.
type HTTPClient struct {
	baseURL    string
	token      string
	tenantSlug string
	httpClient *http.Client
}

// NewHTTPClient creates a new HTTP-backed Falcon client.
func NewHTTPClient(baseURL, token, tenantSlug string) *HTTPClient {
	return &HTTPClient{
		baseURL:    baseURL,
		token:      token,
		tenantSlug: tenantSlug,
		httpClient: &http.Client{},
	}
}

// SetToken updates the auth token.
func (c *HTTPClient) SetToken(token string) {
	c.token = token
}

// SetTenantSlug updates the tenant slug.
func (c *HTTPClient) SetTenantSlug(slug string) {
	c.tenantSlug = slug
}

func (c *HTTPClient) doRequest(ctx context.Context, method, path string, body interface{}) (*http.Response, error) {
	var bodyReader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("marshaling request body: %w", err)
		}
		bodyReader = bytes.NewReader(data)
	}

	reqURL := c.baseURL + path
	req, err := http.NewRequestWithContext(ctx, method, reqURL, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	if c.tenantSlug != "" {
		req.Header.Set("X-Tenant-Slug", c.tenantSlug)
	}

	return c.httpClient.Do(req)
}

func (c *HTTPClient) doJSON(ctx context.Context, method, path string, body interface{}, target interface{}) error {
	resp, err := c.doRequest(ctx, method, path, body)
	if err != nil {
		return err
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode >= 400 {
		return parseAPIError(resp)
	}

	if target == nil || resp.StatusCode == http.StatusNoContent {
		return nil
	}

	return json.NewDecoder(resp.Body).Decode(target)
}

func parseAPIError(resp *http.Response) error {
	apiErr := &APIError{StatusCode: resp.StatusCode}
	body, err := io.ReadAll(resp.Body)
	if err == nil && len(body) > 0 {
		_ = json.Unmarshal(body, apiErr)
	}
	if apiErr.Message == "" {
		apiErr.Message = http.StatusText(resp.StatusCode)
	}
	return apiErr
}

func addListParams(path string, opts *ListOptions) string {
	if opts == nil {
		return path
	}
	params := url.Values{}
	if opts.Page > 0 {
		params.Set("page", strconv.Itoa(opts.Page))
	}
	if opts.PageSize > 0 {
		params.Set("page_size", strconv.Itoa(opts.PageSize))
	}
	if opts.Search != "" {
		params.Set("search", opts.Search)
	}
	if len(params) == 0 {
		return path
	}
	return path + "?" + params.Encode()
}
