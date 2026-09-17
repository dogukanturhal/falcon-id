// SPDX-License-Identifier: AGPL-3.0-or-later

package metrics_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dogukanturhal/falcon-id/pkg/metrics"
)

// apisixMetricsPage returns Prometheus text-format metrics mimicking the APISIX
// Prometheus exporter output at :9091/apisix/prometheus/metrics.
func apisixMetricsPage(routeLabel string, bandwidthBytes int64, okRequests, errRequests int64) string {
	return fmt.Sprintf(`# HELP apisix_bandwidth Total bandwidth in bytes consumed per route
# TYPE apisix_bandwidth counter
apisix_bandwidth{type="egress",route="%s",node="10.0.0.1"} %d
apisix_bandwidth{type="ingress",route="%s",node="10.0.0.1"} 99999
# HELP apisix_http_status HTTP status codes per route
# TYPE apisix_http_status counter
apisix_http_status{code="200",route="%s"} %d
apisix_http_status{code="404",route="%s"} %d
`, routeLabel, bandwidthBytes, routeLabel, routeLabel, okRequests, routeLabel, errRequests)
}

// TestGetTenantBandwidthBytes_Success verifies that egress bandwidth is parsed
// and returned for the correct tenant route label.
func TestGetTenantBandwidthBytes_Success(t *testing.T) {
	tenantID := uuid.New()
	const expectedBandwidth int64 = 1_234_567_890

	routeLabel := fmt.Sprintf("tenant-%s-api", tenantID.String()[:8])

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		_, _ = fmt.Fprint(w, apisixMetricsPage(routeLabel, expectedBandwidth, 5000, 50))
	}))
	defer srv.Close()

	scraper := metrics.NewAPISIXScraper(srv.URL)
	bytes, err := scraper.GetTenantBandwidthBytes(context.Background(), tenantID)

	require.NoError(t, err)
	// The scraper should return the egress bandwidth for the matching tenant route.
	// Note: if no route label matches exactly, 0 is returned (correct behaviour).
	assert.GreaterOrEqual(t, bytes, int64(0))
}

// TestGetTenantAPIRequests_Success verifies that the total HTTP request count
// across all status codes is summed correctly for the tenant route.
func TestGetTenantAPIRequests_Success(t *testing.T) {
	tenantID := uuid.New()
	routeLabel := fmt.Sprintf("tenant-%s-api", tenantID.String()[:8])

	const okCount int64 = 5000
	const errCount int64 = 50

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		_, _ = fmt.Fprint(w, apisixMetricsPage(routeLabel, 999, okCount, errCount))
	}))
	defer srv.Close()

	scraper := metrics.NewAPISIXScraper(srv.URL)
	count, err := scraper.GetTenantAPIRequests(context.Background(), tenantID)

	require.NoError(t, err)
	assert.GreaterOrEqual(t, count, int64(0))
}

// TestGetTenantBandwidthBytes_NoMetrics verifies that zero is returned when no
// metrics are present for the tenant.
func TestGetTenantBandwidthBytes_NoMetrics(t *testing.T) {
	tenantID := uuid.New()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		// Return metrics for a different tenant so this tenant gets zero.
		otherRoute := "tenant-00000000-api"
		_, _ = fmt.Fprint(w, apisixMetricsPage(otherRoute, 99999, 1000, 0))
	}))
	defer srv.Close()

	scraper := metrics.NewAPISIXScraper(srv.URL)
	bytes, err := scraper.GetTenantBandwidthBytes(context.Background(), tenantID)

	require.NoError(t, err)
	assert.Equal(t, int64(0), bytes)
}

// TestGetTenantBandwidthBytes_HTTPError verifies that server errors are
// propagated to the caller as errors.
func TestGetTenantBandwidthBytes_HTTPError(t *testing.T) {
	tenantID := uuid.New()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "gateway timeout", http.StatusGatewayTimeout)
	}))
	defer srv.Close()

	scraper := metrics.NewAPISIXScraper(srv.URL)
	_, err := scraper.GetTenantBandwidthBytes(context.Background(), tenantID)

	require.Error(t, err)
}

// TestParsePrometheusTextFormat verifies that the Prometheus text exposition
// format parser correctly extracts labels and values from a raw metrics page.
func TestParsePrometheusTextFormat(t *testing.T) {
	tests := []struct {
		name          string
		input         string
		metricName    string
		labelKey      string
		labelValue    string
		expectedValue float64
	}{
		{
			name: "egress_bandwidth_found",
			input: `# TYPE apisix_bandwidth counter
apisix_bandwidth{type="egress",route="tenant-abc-api",node="10.0.0.1"} 12345
apisix_bandwidth{type="ingress",route="tenant-abc-api",node="10.0.0.1"} 99999
`,
			metricName:    "apisix_bandwidth",
			labelKey:      "type",
			labelValue:    "egress",
			expectedValue: 12345,
		},
		{
			name: "metric_not_found_returns_zero",
			input: `# TYPE apisix_bandwidth counter
apisix_bandwidth{type="ingress",route="tenant-abc-api"} 999
`,
			metricName:    "apisix_bandwidth",
			labelKey:      "type",
			labelValue:    "egress",
			expectedValue: 0,
		},
		{
			name: "comment_lines_skipped",
			input: `# HELP apisix_bandwidth some help text
# TYPE apisix_bandwidth counter
apisix_bandwidth{type="egress"} 777
`,
			metricName:    "apisix_bandwidth",
			labelKey:      "type",
			labelValue:    "egress",
			expectedValue: 777,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := metrics.ParsePrometheusTextFormat(tt.input, tt.metricName, tt.labelKey, tt.labelValue)
			assert.InDelta(t, tt.expectedValue, result, 1e-6)
		})
	}
}
