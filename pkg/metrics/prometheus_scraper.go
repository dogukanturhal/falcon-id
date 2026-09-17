// SPDX-License-Identifier: AGPL-3.0-or-later

package metrics

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

// DataPoint is a single (timestamp, value) pair from a Prometheus range query.
type DataPoint struct {
	Timestamp time.Time
	Value     float64
}

// prometheusInstantResult is the parsed structure of a Prometheus instant-query
// HTTP response (GET /api/v1/query).
type prometheusInstantResult struct {
	Status    string `json:"status"`
	ErrorType string `json:"errorType"`
	Error     string `json:"error"`
	Data      struct {
		ResultType string `json:"resultType"`
		Result     []struct {
			Metric map[string]string `json:"metric"`
			// Value is a two-element JSON array: [unix_timestamp, "string_value"]
			Value []json.RawMessage `json:"value"`
		} `json:"result"`
	} `json:"data"`
}

// PrometheusScraper queries the Prometheus HTTP API for instant and range
// metric values.
type PrometheusScraper struct {
	baseURL    string
	httpClient *http.Client
}

// NewPrometheusScraper creates a PrometheusScraper that talks to the Prometheus
// server at baseURL (e.g. "http://prometheus:9090").  A 10-second timeout is
// applied to every request; the caller's context is always respected first.
func NewPrometheusScraper(baseURL string) *PrometheusScraper {
	return &PrometheusScraper{
		baseURL: baseURL,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// QueryInstant executes an instant PromQL query at the given time and returns
// the value of the first result vector element.  When the result set is empty
// (metric absent) zero is returned without error.
//
// The caller must pass a context with an appropriate deadline; the HTTP client
// timeout acts as an upper bound but the context wins.
func (s *PrometheusScraper) QueryInstant(ctx context.Context, query string, ts time.Time) (float64, error) {
	endpoint := fmt.Sprintf("%s/api/v1/query", s.baseURL)

	params := url.Values{}
	params.Set("query", query)
	params.Set("time", strconv.FormatInt(ts.Unix(), 10))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint+"?"+params.Encode(), nil)
	if err != nil {
		return 0, fmt.Errorf("PrometheusScraper.QueryInstant: build request: %w", err)
	}

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return 0, fmt.Errorf("PrometheusScraper.QueryInstant: HTTP request: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, fmt.Errorf("PrometheusScraper.QueryInstant: read body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("PrometheusScraper.QueryInstant: unexpected status %d: %s",
			resp.StatusCode, string(body))
	}

	var parsed prometheusInstantResult
	if err := json.Unmarshal(body, &parsed); err != nil {
		return 0, fmt.Errorf("PrometheusScraper.QueryInstant: parse response: %w", err)
	}

	if parsed.Status != "success" {
		return 0, fmt.Errorf("PrometheusScraper.QueryInstant: Prometheus error (%s): %s",
			parsed.ErrorType, parsed.Error)
	}

	if len(parsed.Data.Result) == 0 {
		return 0, nil
	}

	first := parsed.Data.Result[0]
	if len(first.Value) < 2 {
		return 0, fmt.Errorf("PrometheusScraper.QueryInstant: malformed value array in result")
	}

	// The second element is the string-encoded numeric value.
	var rawStr string
	if err := json.Unmarshal(first.Value[1], &rawStr); err != nil {
		return 0, fmt.Errorf("PrometheusScraper.QueryInstant: parse value string: %w", err)
	}

	val, err := strconv.ParseFloat(rawStr, 64)
	if err != nil {
		return 0, fmt.Errorf("PrometheusScraper.QueryInstant: parse float %q: %w", rawStr, err)
	}

	return val, nil
}
