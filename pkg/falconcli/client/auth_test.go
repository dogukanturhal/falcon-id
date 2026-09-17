// SPDX-License-Identifier: AGPL-3.0-or-later

package client

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLogin_Success(t *testing.T) {
	loginResp := LoginResponse{
		AccessToken:  "access-token-xyz",
		RefreshToken: "refresh-token-abc",
		ExpiresIn:    3600,
		TokenType:    "Bearer",
		User: &User{
			ID:       "user-1",
			Email:    "admin@test.com",
			Username: "admin",
		},
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "/api/v1/auth/login", r.URL.Path)
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))

		var req LoginRequest
		require.NoError(t, json.NewDecoder(r.Body).Decode(&req))
		assert.Equal(t, "admin", req.Username)
		assert.Equal(t, "secret", req.Password)
		assert.Equal(t, "my-tenant", req.TenantSlug)

		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(loginResp) //nolint:gosec // test struct with token field, not real credentials
	}))
	defer srv.Close()

	c := NewHTTPClient(srv.URL, "", "")
	resp, err := c.Login(context.Background(), &LoginRequest{
		Username:   "admin",
		Password:   "secret",
		TenantSlug: "my-tenant",
	})
	require.NoError(t, err)
	assert.Equal(t, "access-token-xyz", resp.AccessToken)
	assert.Equal(t, "refresh-token-abc", resp.RefreshToken)
	assert.Equal(t, 3600, resp.ExpiresIn)
	assert.Equal(t, "Bearer", resp.TokenType)
	require.NotNil(t, resp.User)
	assert.Equal(t, "admin", resp.User.Username)
}

func TestLogin_Unauthorized(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"code":    "INVALID_CREDENTIALS",
			"message": "invalid username or password",
		})
	}))
	defer srv.Close()

	c := NewHTTPClient(srv.URL, "", "")
	resp, err := c.Login(context.Background(), &LoginRequest{
		Username:   "admin",
		Password:   "wrong",
		TenantSlug: "tenant",
	})
	require.Error(t, err)
	assert.Nil(t, resp)

	var apiErr *APIError
	require.ErrorAs(t, err, &apiErr)
	assert.Equal(t, http.StatusUnauthorized, apiErr.StatusCode)
}

func TestLogout_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "/api/v1/auth/logout", r.URL.Path)
		assert.Equal(t, "Bearer tok123", r.Header.Get("Authorization"))
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	c := NewHTTPClient(srv.URL, "tok123", "tenant")
	err := c.Logout(context.Background())
	require.NoError(t, err)
}

func TestLogout_Error(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]string{"message": "server error"})
	}))
	defer srv.Close()

	c := NewHTTPClient(srv.URL, "tok", "tenant")
	err := c.Logout(context.Background())
	require.Error(t, err)
}

func TestWhoami_Success(t *testing.T) {
	whoamiResp := WhoamiResponse{
		ID:         "user-123",
		Email:      "admin@example.com",
		Username:   "admin",
		TenantID:   "tenant-456",
		TenantSlug: "exampletenant",
		Roles:      []string{"admin", "user"},
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		assert.Equal(t, "/api/v1/auth/me", r.URL.Path)
		assert.Equal(t, "Bearer mytoken", r.Header.Get("Authorization"))
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(whoamiResp)
	}))
	defer srv.Close()

	c := NewHTTPClient(srv.URL, "mytoken", "exampletenant")
	resp, err := c.Whoami(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "user-123", resp.ID)
	assert.Equal(t, "admin@example.com", resp.Email)
	assert.Equal(t, "admin", resp.Username)
	assert.Equal(t, "exampletenant", resp.TenantSlug)
	assert.Equal(t, []string{"admin", "user"}, resp.Roles)
}

func TestWhoami_Unauthorized(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(map[string]string{"message": "token expired"})
	}))
	defer srv.Close()

	c := NewHTTPClient(srv.URL, "expired-token", "tenant")
	resp, err := c.Whoami(context.Background())
	require.Error(t, err)
	assert.Nil(t, resp)
}

func TestLoginResponse_UserFields(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	loginResp := LoginResponse{
		AccessToken: "tok",
		User: &User{
			ID:        "u1",
			Email:     "user@test.com",
			Username:  "testuser",
			FirstName: "Test",
			LastName:  "User",
			Status:    "active",
			CreatedAt: now,
		},
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(loginResp) //nolint:gosec // test struct with token field, not real credentials
	}))
	defer srv.Close()

	c := NewHTTPClient(srv.URL, "", "")
	resp, err := c.Login(context.Background(), &LoginRequest{
		Username:   "testuser",
		Password:   "pass",
		TenantSlug: "tenant",
	})
	require.NoError(t, err)
	require.NotNil(t, resp.User)
	assert.Equal(t, "testuser", resp.User.Username)
	assert.Equal(t, "active", resp.User.Status)
}
