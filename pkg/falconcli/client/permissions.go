// SPDX-License-Identifier: AGPL-3.0-or-later

package client

import "context"

// ListPermissions returns a paginated list of permissions.
func (c *HTTPClient) ListPermissions(ctx context.Context, opts *ListOptions) (*PermissionListResponse, error) {
	var resp PermissionListResponse
	path := addListParams("/api/v1/permissions", opts)
	if err := c.doJSON(ctx, "GET", path, nil, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}
