// SPDX-License-Identifier: AGPL-3.0-or-later

package client

import (
	"context"
	"net/url"
)

// ListUsers returns a paginated list of users.
func (c *HTTPClient) ListUsers(ctx context.Context, opts *ListOptions) (*UserListResponse, error) {
	var resp UserListResponse
	path := addListParams("/api/v1/users", opts)
	if err := c.doJSON(ctx, "GET", path, nil, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// GetUser retrieves a single user by ID.
func (c *HTTPClient) GetUser(ctx context.Context, id string) (*UserResponse, error) {
	var resp UserResponse
	if err := c.doJSON(ctx, "GET", "/api/v1/users/"+url.PathEscape(id), nil, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// CreateUser creates a new user.
func (c *HTTPClient) CreateUser(ctx context.Context, req *CreateUserRequest) (*UserResponse, error) {
	var resp UserResponse
	if err := c.doJSON(ctx, "POST", "/api/v1/users", req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// DeleteUser removes a user by ID.
func (c *HTTPClient) DeleteUser(ctx context.Context, id string) error {
	return c.doJSON(ctx, "DELETE", "/api/v1/users/"+url.PathEscape(id), nil, nil)
}
