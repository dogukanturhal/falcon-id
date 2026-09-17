// SPDX-License-Identifier: AGPL-3.0-or-later

package client

import "context"

// GenerateToken creates a new API key/token.
func (c *HTTPClient) GenerateToken(ctx context.Context, req *GenerateTokenRequest) (*TokenResponse, error) {
	var resp TokenResponse
	if err := c.doJSON(ctx, "POST", "/api/v1/auth/api-keys", req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}
