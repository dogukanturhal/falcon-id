// SPDX-License-Identifier: AGPL-3.0-or-later

// Package client implements the Falcon-ID API client.
package client

import "context"

// Login authenticates with the Falcon ID API and returns tokens.
func (c *HTTPClient) Login(ctx context.Context, req *LoginRequest) (*LoginResponse, error) {
	var resp LoginResponse
	if err := c.doJSON(ctx, "POST", "/api/v1/auth/login", req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// Logout invalidates the current session on the server.
func (c *HTTPClient) Logout(ctx context.Context) error {
	return c.doJSON(ctx, "POST", "/api/v1/auth/logout", nil, nil)
}

// Whoami returns the current authenticated user's profile.
func (c *HTTPClient) Whoami(ctx context.Context) (*WhoamiResponse, error) {
	var resp WhoamiResponse
	if err := c.doJSON(ctx, "GET", "/api/v1/auth/me", nil, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}
