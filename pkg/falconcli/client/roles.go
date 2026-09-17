// SPDX-License-Identifier: AGPL-3.0-or-later

package client

import (
	"context"
	"net/url"
)

// ListRoles returns a paginated list of roles.
func (c *HTTPClient) ListRoles(ctx context.Context, opts *ListOptions) (*RoleListResponse, error) {
	var resp RoleListResponse
	path := addListParams("/api/v1/roles", opts)
	if err := c.doJSON(ctx, "GET", path, nil, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// GetRole retrieves a single role by ID.
func (c *HTTPClient) GetRole(ctx context.Context, id string) (*RoleResponse, error) {
	var resp RoleResponse
	if err := c.doJSON(ctx, "GET", "/api/v1/roles/"+url.PathEscape(id), nil, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}
