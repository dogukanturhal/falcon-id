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

func TestGenerateToken_Success(t *testing.T) {
	tokenResp := TokenResponse{
		ID:        "tok-id-123",
		Name:      "my-api-key",
		Key:       "sk_live_abcdefghijklmnop", // gitleaks:allow — test fixture, not a real credential
		ExpiresAt: "2027-01-01T00:00:00Z",
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "/api/v1/auth/api-keys", r.URL.Path)

		var req GenerateTokenRequest
		require.NoError(t, json.NewDecoder(r.Body).Decode(&req))
		assert.Equal(t, "my-api-key", req.Name)
		assert.Equal(t, "30d", req.ExpiresIn)
		assert.Equal(t, []string{"users:read", "roles:read"}, req.Scopes)

		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(tokenResp)
	}))
	defer srv.Close()

	c := NewHTTPClient(srv.URL, "tok", "tenant")
	resp, err := c.GenerateToken(context.Background(), &GenerateTokenRequest{
		Name:      "my-api-key",
		ExpiresIn: "30d",
		Scopes:    []string{"users:read", "roles:read"},
	})
	require.NoError(t, err)
	assert.Equal(t, "tok-id-123", resp.ID)
	assert.Equal(t, "my-api-key", resp.Name)
	assert.Equal(t, "sk_live_abcdefghijklmnop", resp.Key) // gitleaks:allow — test fixture, not a real credential
	assert.Equal(t, "2027-01-01T00:00:00Z", resp.ExpiresAt)
}

func TestGenerateToken_MinimalRequest(t *testing.T) {
	tokenResp := TokenResponse{
		ID:   "tok-minimal",
		Name: "minimal-key",
		Key:  "sk_test_xyz",
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req GenerateTokenRequest
		require.NoError(t, json.NewDecoder(r.Body).Decode(&req))
		assert.Equal(t, "minimal-key", req.Name)
		assert.Empty(t, req.ExpiresIn)
		assert.Empty(t, req.Scopes)

		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(tokenResp)
	}))
	defer srv.Close()

	c := NewHTTPClient(srv.URL, "tok", "tenant")
	resp, err := c.GenerateToken(context.Background(), &GenerateTokenRequest{
		Name: "minimal-key",
	})
	require.NoError(t, err)
	assert.Equal(t, "minimal-key", resp.Name)
}

func TestGenerateToken_Unauthorized(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(map[string]string{"message": "unauthorized"})
	}))
	defer srv.Close()

	c := NewHTTPClient(srv.URL, "", "tenant")
	resp, err := c.GenerateToken(context.Background(), &GenerateTokenRequest{Name: "key"})
	require.Error(t, err)
	assert.Nil(t, resp)
}
