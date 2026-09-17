// SPDX-License-Identifier: AGPL-3.0-or-later

package client

import "context"

// ListTenants returns a paginated list of platform tenants.
func (c *HTTPClient) ListTenants(ctx context.Context, opts *ListOptions) (*TenantListResponse, error) {
	var resp TenantListResponse
	path := addListParams("/api/v1/platform/tenants", opts)
	if err := c.doJSON(ctx, "GET", path, nil, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}
