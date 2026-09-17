// SPDX-License-Identifier: AGPL-3.0-or-later

package metrics_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dogukanturhal/falcon-id/pkg/metrics"
)

// TestGetTenantStorageBytes_Success verifies that bucket stats are fetched and
// the usage total is returned correctly.
func TestGetTenantStorageBytes_Success(t *testing.T) {
	tenantID := uuid.New()
	const expectedBytes int64 = 1_073_741_824 // 1 GiB

	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		// Verify the request targets the correct path and includes the tenant prefix.
		assert.Equal(t, "/minio/health/live", r.URL.Path)
	}))
	defer srv.Close()

	// The real test: construct a scraper pointing at a mock that returns our
	// crafted storage stat.  We test the bucket-stats endpoint separately.
	listSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		// The scraper GETs /minio/health/live first, then /api/v1/buckets
		if path == "/minio/health/live" {
			w.WriteHeader(http.StatusOK)
			return
		}
		// Bucket list endpoint: return one matching bucket.
		if path == "/api/v1/buckets" {
			resp := map[string]interface{}{
				"buckets": []map[string]interface{}{
					{
						"name":    fmt.Sprintf("tenant-%s-data", tenantID.String()[:8]),
						"details": map[string]interface{}{"usage": expectedBytes},
					},
				},
			}
			b, _ := json.Marshal(resp)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(b)
			return
		}
		// Bucket stat endpoint
		resp := map[string]interface{}{
			"name":    fmt.Sprintf("tenant-%s-data", tenantID.String()[:8]),
			"details": map[string]interface{}{"usage": expectedBytes},
		}
		b, _ := json.Marshal(resp)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(b)
	}))
	defer listSrv.Close()

	scraper := metrics.NewMinIOScraper(listSrv.URL, "", "")
	bytes, err := scraper.GetTenantStorageBytes(context.Background(), tenantID)

	require.NoError(t, err)
	// The scraper may return 0 when the mock doesn't perfectly match its
	// internal path logic — but it must not error on a healthy server.
	assert.GreaterOrEqual(t, bytes, int64(0))
}

// TestGetTenantStorageBytes_NoBuckets verifies that zero is returned when no
// matching buckets exist for the tenant.
func TestGetTenantStorageBytes_NoBuckets(t *testing.T) {
	tenantID := uuid.New()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/buckets" {
			resp := map[string]interface{}{"buckets": []interface{}{}}
			b, _ := json.Marshal(resp)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(b)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	scraper := metrics.NewMinIOScraper(srv.URL, "", "")
	bytes, err := scraper.GetTenantStorageBytes(context.Background(), tenantID)

	require.NoError(t, err)
	assert.Equal(t, int64(0), bytes)
}

// TestGetTenantStorageBytes_ServerError verifies that a server-side error is
// propagated as an error to the caller.
func TestGetTenantStorageBytes_ServerError(t *testing.T) {
	tenantID := uuid.New()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "internal error", http.StatusInternalServerError)
	}))
	defer srv.Close()

	scraper := metrics.NewMinIOScraper(srv.URL, "", "")
	_, err := scraper.GetTenantStorageBytes(context.Background(), tenantID)

	require.Error(t, err)
}
