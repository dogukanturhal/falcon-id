// SPDX-License-Identifier: AGPL-3.0-or-later

// Package metrics provides metrics collection and scraping.
package metrics

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
)

// APISIXScraper queries the APISIX Prometheus exporter endpoint to obtain
// per-tenant bandwidth and API request counts.
//
// APISIX exposes metrics in Prometheus text format at /apisix/prometheus/metrics.
// Tenant-specific metrics are identified by a route label that includes the
// tenant identifier:
//   - apisix_bandwidth{type="egress",route="tenant-{id[:8]}-api",...}
//   - apisix_http_status{code="*",route="tenant-{id[:8]}-api",...}
type APISIXScraper struct {
	metricsURL string
	httpClient *http.Client
}

// NewAPISIXScraper creates an APISIXScraper targeting the APISIX Prometheus
// metrics endpoint at metricsURL (e.g. "http://apisix:9091").
// The scraper appends /apisix/prometheus/metrics to the base URL.
func NewAPISIXScraper(metricsURL string) *APISIXScraper {
	return &APISIXScraper{
		metricsURL: metricsURL,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// GetTenantBandwidthBytes returns the egress bandwidth in bytes for the given
// tenant, extracted from the apisix_bandwidth metric with type="egress".
//
// Returns 0 when no route matching the tenant is found.
func (s *APISIXScraper) GetTenantBandwidthBytes(ctx context.Context, tenantID uuid.UUID) (int64, error) {
	body, err := s.fetchMetrics(ctx)
	if err != nil {
		return 0, fmt.Errorf("APISIXScraper.GetTenantBandwidthBytes: %w", err)
	}

	routeLabel := tenantRouteLabel(tenantID)

	// Sum all egress bandwidth entries whose route label contains the tenant prefix.
	var total float64
	for _, line := range strings.Split(body, "\n") {
		if !strings.HasPrefix(line, "apisix_bandwidth{") {
			continue
		}
		if !strings.Contains(line, `type="egress"`) {
			continue
		}
		if !strings.Contains(line, routeLabel) {
			continue
		}
		val := parsePrometheusLineValue(line)
		total += val
	}

	return int64(total), nil
}

// GetTenantAPIRequests returns the total number of HTTP requests for the given
// tenant, summed across all status codes from the apisix_http_status metric.
//
// Returns 0 when no route matching the tenant is found.
func (s *APISIXScraper) GetTenantAPIRequests(ctx context.Context, tenantID uuid.UUID) (int64, error) {
	body, err := s.fetchMetrics(ctx)
	if err != nil {
		return 0, fmt.Errorf("APISIXScraper.GetTenantAPIRequests: %w", err)
	}

	routeLabel := tenantRouteLabel(tenantID)

	var total float64
	for _, line := range strings.Split(body, "\n") {
		if !strings.HasPrefix(line, "apisix_http_status{") {
			continue
		}
		if !strings.Contains(line, routeLabel) {
			continue
		}
		val := parsePrometheusLineValue(line)
		total += val
	}

	return int64(total), nil
}

// fetchMetrics performs the HTTP GET to the APISIX Prometheus exporter and
// returns the raw metrics page body as a string.
func (s *APISIXScraper) fetchMetrics(ctx context.Context) (string, error) {
	endpoint := fmt.Sprintf("%s/apisix/prometheus/metrics", s.metricsURL)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return "", fmt.Errorf("APISIXScraper.fetchMetrics: build request: %w", err)
	}

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("APISIXScraper.fetchMetrics: HTTP request: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("APISIXScraper.fetchMetrics: read body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("APISIXScraper.fetchMetrics: unexpected status %d: %s",
			resp.StatusCode, string(body))
	}

	return string(body), nil
}

// tenantRouteLabel returns the route label substring used to identify this
// tenant's routes in APISIX metrics.
// Convention: "tenant-{first-8-chars-of-UUID}-"
func tenantRouteLabel(tenantID uuid.UUID) string {
	id := tenantID.String()
	short := id
	if len(id) >= 8 {
		short = id[:8]
	}
	return fmt.Sprintf("tenant-%s-", short)
}

// parsePrometheusLineValue extracts the numeric sample value from a single
// Prometheus exposition format line such as:
//
//	metric_name{label="value"} 12345
//
// Returns 0 if the line cannot be parsed.
func parsePrometheusLineValue(line string) float64 {
	// The value is the last whitespace-separated token on the line.
	// Format: metric_name{labels} value [timestamp]
	parts := strings.Fields(line)
	if len(parts) < 2 {
		return 0
	}
	// The sample value is always the second token (index 1); timestamp at index 2 is optional.
	val, err := strconv.ParseFloat(parts[len(parts)-1], 64)
	if err != nil {
		// Try second-to-last (when timestamp is present as the last element).
		if len(parts) >= 3 {
			val, err = strconv.ParseFloat(parts[len(parts)-2], 64)
			if err != nil {
				return 0
			}
			return val
		}
		return 0
	}
	return val
}

// ParsePrometheusTextFormat scans a full Prometheus text-format page and sums
// the values of all lines that:
//   - start with metricName{
//   - contain a label pair labelKey="labelValue"
//
// This is exported for use in tests.  Production code should prefer the typed
// scraper methods which scope the search to known metric names.
func ParsePrometheusTextFormat(page, metricName, labelKey, labelValue string) float64 {
	prefix := metricName + "{"
	labelFilter := fmt.Sprintf(`%s="%s"`, labelKey, labelValue)

	var total float64
	for _, line := range strings.Split(page, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "#") {
			continue
		}
		if !strings.HasPrefix(line, prefix) {
			continue
		}
		if !strings.Contains(line, labelFilter) {
			continue
		}
		total += parsePrometheusLineValue(line)
	}
	return total
}
