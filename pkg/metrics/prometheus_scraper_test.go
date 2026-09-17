// SPDX-License-Identifier: AGPL-3.0-or-later

package metrics_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dogukanturhal/falcon-id/pkg/metrics"
)

// promInstantResponse builds a minimal Prometheus instant-query JSON response.
func promInstantResponse(namespace, value string) []byte {
	resp := map[string]interface{}{
		"status": "success",
		"data": map[string]interface{}{
			"resultType": "vector",
			"result": []interface{}{
				map[string]interface{}{
					"metric": map[string]string{"namespace": namespace},
					"value":  []interface{}{1709312400, value},
				},
			},
		},
	}
	b, _ := json.Marshal(resp)
	return b
}

// promEmptyResponse returns a Prometheus response with an empty result set.
func promEmptyResponse() []byte {
	resp := map[string]interface{}{
		"status": "success",
		"data": map[string]interface{}{
			"resultType": "vector",
			"result":     []interface{}{},
		},
	}
	b, _ := json.Marshal(resp)
	return b
}

// TestQueryInstant_Success verifies that a well-formed Prometheus response is
// parsed and the first result value is returned as a float64.
func TestQueryInstant_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/v1/query", r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(promInstantResponse("tenant-abc123", "0.5432"))
	}))
	defer srv.Close()

	scraper := metrics.NewPrometheusScraper(srv.URL)
	val, err := scraper.QueryInstant(context.Background(), `sum(rate(container_cpu_usage_seconds_total[5m]))`, time.Now())

	require.NoError(t, err)
	assert.InDelta(t, 0.5432, val, 1e-6)
}

// TestQueryInstant_EmptyResult verifies that an empty Prometheus result set
// returns zero without an error — this is the normal "no activity" path.
func TestQueryInstant_EmptyResult(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(promEmptyResponse())
	}))
	defer srv.Close()

	scraper := metrics.NewPrometheusScraper(srv.URL)
	val, err := scraper.QueryInstant(context.Background(), `some_metric`, time.Now())

	require.NoError(t, err)
	assert.Equal(t, float64(0), val)
}

// TestQueryInstant_HTTPError verifies that a non-2xx HTTP response is surfaced
// as an error so the caller can handle it appropriately.
func TestQueryInstant_HTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "internal server error", http.StatusInternalServerError)
	}))
	defer srv.Close()

	scraper := metrics.NewPrometheusScraper(srv.URL)
	_, err := scraper.QueryInstant(context.Background(), `some_metric`, time.Now())

	require.Error(t, err)
	assert.Contains(t, err.Error(), "500")
}

// TestQueryInstant_InvalidJSON verifies that a malformed JSON body returns an
// error rather than silently producing a zero value.
func TestQueryInstant_InvalidJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{ not valid json`))
	}))
	defer srv.Close()

	scraper := metrics.NewPrometheusScraper(srv.URL)
	_, err := scraper.QueryInstant(context.Background(), `some_metric`, time.Now())

	require.Error(t, err)
}

// TestQueryInstant_Timeout verifies that a slow server causes a context
// deadline exceeded error to propagate correctly.
func TestQueryInstant_Timeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Block until the request context is cancelled.
		<-r.Context().Done()
		http.Error(w, "cancelled", http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	scraper := metrics.NewPrometheusScraper(srv.URL)

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	_, err := scraper.QueryInstant(ctx, `some_metric`, time.Now())

	require.Error(t, err)
}

// TestQueryInstant_StatusError verifies that a Prometheus "error" status is
// returned as an error even when HTTP status is 200.
func TestQueryInstant_StatusError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		resp := map[string]interface{}{
			"status":    "error",
			"errorType": "bad_data",
			"error":     "parse error at char 1",
		}
		b, _ := json.Marshal(resp)
		_, _ = w.Write(b)
	}))
	defer srv.Close()

	scraper := metrics.NewPrometheusScraper(srv.URL)
	_, err := scraper.QueryInstant(context.Background(), `bad query`, time.Now())

	require.Error(t, err)
	assert.Contains(t, err.Error(), "parse error")
}
