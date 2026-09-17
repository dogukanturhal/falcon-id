// SPDX-License-Identifier: AGPL-3.0-or-later

package metrics

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
)

// minioBucketInfo is a single bucket entry returned by the MinIO console API.
type minioBucketInfo struct {
	Name    string `json:"name"`
	Details struct {
		Usage int64 `json:"usage"`
	} `json:"details"`
}

// minioBucketListResponse is the top-level structure returned by the MinIO
// console bucket list endpoint at GET /api/v1/buckets.
type minioBucketListResponse struct {
	Buckets []minioBucketInfo `json:"buckets"`
}

// MinIOScraper queries the MinIO Admin/Console API to obtain storage usage for
// tenant-prefixed buckets.
//
// Bucket naming convention: tenant-{tenantID[:8]}-{suffix}
// The scraper lists all buckets and sums the usage of those whose name starts
// with the tenant prefix.
type MinIOScraper struct {
	consoleURL string
	accessKey  string
	secretKey  string
	httpClient *http.Client
}

// NewMinIOScraper creates a MinIOScraper targeting the MinIO Console API at
// consoleURL (e.g. "http://minio:9001").  accessKey and secretKey are used
// for basic authentication.
//
// In deployments where MinIO is behind an internal service mesh without auth,
// pass empty strings for the credentials.
func NewMinIOScraper(consoleURL, accessKey, secretKey string) *MinIOScraper {
	return &MinIOScraper{
		consoleURL: consoleURL,
		accessKey:  accessKey,
		secretKey:  secretKey,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// GetTenantStorageBytes returns the total bytes stored across all buckets that
// belong to the given tenant.  Buckets are matched by the prefix pattern
// "tenant-{tenantID[:8]}-".
//
// Returns 0 when no matching buckets exist.  Returns an error when the MinIO
// Console API call fails.
func (s *MinIOScraper) GetTenantStorageBytes(ctx context.Context, tenantID uuid.UUID) (int64, error) {
	prefix := tenantPrefix(tenantID)
	buckets, err := s.listBuckets(ctx)
	if err != nil {
		return 0, fmt.Errorf("MinIOScraper.GetTenantStorageBytes: list buckets: %w", err)
	}

	var total int64
	for _, b := range buckets {
		if strings.HasPrefix(b.Name, prefix) {
			total += b.Details.Usage
		}
	}
	return total, nil
}

// tenantPrefix returns the bucket name prefix for a tenant.
// The first 8 characters of the UUID are used to keep bucket names short.
func tenantPrefix(tenantID uuid.UUID) string {
	id := tenantID.String()
	short := id
	if len(id) >= 8 {
		short = id[:8]
	}
	return fmt.Sprintf("tenant-%s-", short)
}

// listBuckets calls the MinIO Console API and returns all known buckets.
func (s *MinIOScraper) listBuckets(ctx context.Context) ([]minioBucketInfo, error) {
	endpoint := fmt.Sprintf("%s/api/v1/buckets", s.consoleURL)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("MinIOScraper.listBuckets: build request: %w", err)
	}

	if s.accessKey != "" {
		req.SetBasicAuth(s.accessKey, s.secretKey)
	}

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("MinIOScraper.listBuckets: HTTP request: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("MinIOScraper.listBuckets: read body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("MinIOScraper.listBuckets: unexpected status %d: %s",
			resp.StatusCode, string(body))
	}

	var result minioBucketListResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("MinIOScraper.listBuckets: parse response: %w", err)
	}

	return result.Buckets, nil
}
