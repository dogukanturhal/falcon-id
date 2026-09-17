// SPDX-License-Identifier: AGPL-3.0-or-later

package client

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewHTTPClient(t *testing.T) {
	c := NewHTTPClient("http://localhost:8005", "tok123", "test-tenant")
	assert.Equal(t, "http://localhost:8005", c.baseURL)
	assert.Equal(t, "tok123", c.token)
	assert.Equal(t, "test-tenant", c.tenantSlug)
	assert.NotNil(t, c.httpClient)
}

func TestSetToken(t *testing.T) {
	c := NewHTTPClient("http://localhost:8005", "initial", "tenant")
	c.SetToken("updated-token")
	assert.Equal(t, "updated-token", c.token)
}

func TestSetTenantSlug(t *testing.T) {
	c := NewHTTPClient("http://localhost:8005", "tok", "initial-tenant")
	c.SetTenantSlug("new-tenant")
	assert.Equal(t, "new-tenant", c.tenantSlug)
}

func TestDoRequest_SetsHeaders(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "Bearer mytoken", r.Header.Get("Authorization"))
		assert.Equal(t, "my-tenant", r.Header.Get("X-Tenant-Slug"))
		assert.Equal(t, "application/json", r.Header.Get("Accept"))
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	}))
	defer srv.Close()

	c := NewHTTPClient(srv.URL, "mytoken", "my-tenant")
	resp, err := c.doRequest(context.Background(), "GET", "/health", nil)
	require.NoError(t, err)
	resp.Body.Close() //nolint:errcheck,gosec
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestDoRequest_SetsContentTypeForBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]string{})
	}))
	defer srv.Close()

	c := NewHTTPClient(srv.URL, "tok", "tenant")
	body := map[string]string{"key": "value"}
	resp, err := c.doRequest(context.Background(), "POST", "/api/v1/test", body)
	require.NoError(t, err)
	resp.Body.Close() //nolint:errcheck,gosec
}

func TestDoRequest_NoContentTypeWithoutBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Empty(t, r.Header.Get("Content-Type"))
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]string{})
	}))
	defer srv.Close()

	c := NewHTTPClient(srv.URL, "tok", "tenant")
	resp, err := c.doRequest(context.Background(), "GET", "/api/v1/test", nil)
	require.NoError(t, err)
	resp.Body.Close() //nolint:errcheck,gosec
}

func TestDoRequest_NoAuthHeaderWhenTokenEmpty(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Empty(t, r.Header.Get("Authorization"))
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]string{})
	}))
	defer srv.Close()

	c := NewHTTPClient(srv.URL, "", "")
	resp, err := c.doRequest(context.Background(), "GET", "/health", nil)
	require.NoError(t, err)
	resp.Body.Close() //nolint:errcheck,gosec
}

func TestDoJSON_ParsesSuccessResponse(t *testing.T) {
	expected := map[string]string{"message": "hello"}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(expected)
	}))
	defer srv.Close()

	c := NewHTTPClient(srv.URL, "tok", "tenant")
	var result map[string]string
	err := c.doJSON(context.Background(), "GET", "/test", nil, &result)
	require.NoError(t, err)
	assert.Equal(t, "hello", result["message"])
}

func TestDoJSON_HandlesNoContent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	c := NewHTTPClient(srv.URL, "tok", "tenant")
	err := c.doJSON(context.Background(), "DELETE", "/test/123", nil, nil)
	require.NoError(t, err)
}

func TestParseAPIError_400(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"code":    "VALIDATION_ERROR",
			"message": "invalid input",
		})
	}))
	defer srv.Close()

	c := NewHTTPClient(srv.URL, "tok", "tenant")
	err := c.doJSON(context.Background(), "POST", "/test", map[string]string{}, nil)
	require.Error(t, err)

	var apiErr *APIError
	require.ErrorAs(t, err, &apiErr)
	assert.Equal(t, http.StatusBadRequest, apiErr.StatusCode)
	assert.Equal(t, "invalid input", apiErr.Message)
	assert.Equal(t, "VALIDATION_ERROR", apiErr.Code)
}

func TestParseAPIError_401(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"code":    "UNAUTHORIZED",
			"message": "invalid token",
		})
	}))
	defer srv.Close()

	c := NewHTTPClient(srv.URL, "bad-token", "tenant")
	err := c.doJSON(context.Background(), "GET", "/test", nil, nil)
	require.Error(t, err)

	var apiErr *APIError
	require.ErrorAs(t, err, &apiErr)
	assert.Equal(t, http.StatusUnauthorized, apiErr.StatusCode)
}

func TestParseAPIError_404(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"message": "not found",
		})
	}))
	defer srv.Close()

	c := NewHTTPClient(srv.URL, "tok", "tenant")
	err := c.doJSON(context.Background(), "GET", "/test/missing", nil, nil)
	require.Error(t, err)

	var apiErr *APIError
	require.ErrorAs(t, err, &apiErr)
	assert.Equal(t, http.StatusNotFound, apiErr.StatusCode)
	assert.Equal(t, "not found", apiErr.Message)
}

func TestParseAPIError_500_UsesHTTPStatusText(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		// Return non-JSON body to test fallback
		_, _ = w.Write([]byte("internal server error"))
	}))
	defer srv.Close()

	c := NewHTTPClient(srv.URL, "tok", "tenant")
	err := c.doJSON(context.Background(), "GET", "/test", nil, nil)
	require.Error(t, err)

	var apiErr *APIError
	require.ErrorAs(t, err, &apiErr)
	assert.Equal(t, http.StatusInternalServerError, apiErr.StatusCode)
	assert.NotEmpty(t, apiErr.Message)
}

func TestAPIError_Error(t *testing.T) {
	tests := []struct {
		name     string
		apiErr   *APIError
		expected string
	}{
		{
			name:     "returns message when set",
			apiErr:   &APIError{StatusCode: 400, Code: "ERR", Message: "bad request"},
			expected: "bad request",
		},
		{
			name:     "returns code when message empty",
			apiErr:   &APIError{StatusCode: 400, Code: "VALIDATION_ERROR", Message: ""},
			expected: "VALIDATION_ERROR",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.apiErr.Error())
		})
	}
}

func TestAddListParams(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		opts     *ListOptions
		contains []string
	}{
		{
			name: "nil opts returns path unchanged",
			path: "/api/v1/users",
			opts: nil,
		},
		{
			name: "empty opts returns path unchanged",
			path: "/api/v1/users",
			opts: &ListOptions{},
		},
		{
			name:     "page parameter",
			path:     "/api/v1/users",
			opts:     &ListOptions{Page: 2},
			contains: []string{"page=2"},
		},
		{
			name:     "page_size parameter",
			path:     "/api/v1/users",
			opts:     &ListOptions{PageSize: 50},
			contains: []string{"page_size=50"},
		},
		{
			name:     "search parameter",
			path:     "/api/v1/users",
			opts:     &ListOptions{Search: "john"},
			contains: []string{"search=john"},
		},
		{
			name:     "all parameters",
			path:     "/api/v1/users",
			opts:     &ListOptions{Page: 1, PageSize: 20, Search: "admin"},
			contains: []string{"page=1", "page_size=20", "search=admin"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := addListParams(tt.path, tt.opts)
			if len(tt.contains) == 0 {
				assert.Equal(t, tt.path, result)
			} else {
				assert.True(t, strings.HasPrefix(result, tt.path+"?"))
				for _, c := range tt.contains {
					assert.Contains(t, result, c)
				}
			}
		})
	}
}

func TestDoRequest_ContextCancellation(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	c := NewHTTPClient(srv.URL, "tok", "tenant")
	resp, err := c.doRequest(ctx, "GET", "/health", nil)
	if resp != nil {
		resp.Body.Close() //nolint:errcheck,gosec
	}
	require.Error(t, err)
}
