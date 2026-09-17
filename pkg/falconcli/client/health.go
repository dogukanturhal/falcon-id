// SPDX-License-Identifier: AGPL-3.0-or-later

package client

import "context"

// Health retrieves the service health status.
func (c *HTTPClient) Health(ctx context.Context) (*HealthResponse, error) {
	var resp HealthResponse
	if err := c.doJSON(ctx, "GET", "/health", nil, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}
