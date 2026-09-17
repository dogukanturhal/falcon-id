// SPDX-License-Identifier: AGPL-3.0-or-later

package client

import "context"

// ListRealms returns a paginated list of authentication realms.
func (c *HTTPClient) ListRealms(ctx context.Context, opts *ListOptions) (*RealmListResponse, error) {
	var resp RealmListResponse
	path := addListParams("/api/v1/platform/realms", opts)
	if err := c.doJSON(ctx, "GET", path, nil, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}
