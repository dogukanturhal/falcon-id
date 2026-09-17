// SPDX-License-Identifier: AGPL-3.0-or-later

package client

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHealth_Success(t *testing.T) {
	healthResp := HealthResponse{
		Status:  "ok",
		Version: "1.2.3",
		Services: map[string]string{
			"database": "up",
			"redis":    "up",
			"spicedb":  "up",
		},
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		assert.Equal(t, "/health", r.URL.Path)
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(healthResp)
	}))
	defer srv.Close()

	c := NewHTTPClient(srv.URL, "", "")
	resp, err := c.Health(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "ok", resp.Status)
	assert.Equal(t, "1.2.3", resp.Version)
	assert.Equal(t, "up", resp.Services["database"])
	assert.Equal(t, "up", resp.Services["redis"])
}

func TestHealth_Degraded(t *testing.T) {
	healthResp := HealthResponse{
		Status: "degraded",
		Services: map[string]string{
			"database": "up",
			"redis":    "down",
		},
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// Degraded can still return 200 with a degraded status body
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(healthResp)
	}))
	defer srv.Close()

	c := NewHTTPClient(srv.URL, "", "")
	resp, err := c.Health(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "degraded", resp.Status)
	assert.Equal(t, "down", resp.Services["redis"])
}

func TestHealth_ServiceUnavailable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"status":  "down",
			"message": "service unavailable",
		})
	}))
	defer srv.Close()

	c := NewHTTPClient(srv.URL, "", "")
	resp, err := c.Health(context.Background())
	require.Error(t, err)
	assert.Nil(t, resp)

	var apiErr *APIError
	require.ErrorAs(t, err, &apiErr)
	assert.Equal(t, http.StatusServiceUnavailable, apiErr.StatusCode)
}

func TestHealth_MinimalResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(HealthResponse{Status: "ok"})
	}))
	defer srv.Close()

	c := NewHTTPClient(srv.URL, "", "")
	resp, err := c.Health(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "ok", resp.Status)
	assert.Empty(t, resp.Version)
	assert.Empty(t, resp.Services)
}
