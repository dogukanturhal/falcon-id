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

func TestListPermissions_Success(t *testing.T) {
	permissions := []Permission{
		{ID: "p1", Name: "users:read", Description: "Read users", Resource: "users", Action: "read"},
		{ID: "p2", Name: "users:write", Description: "Write users", Resource: "users", Action: "write"},
		{ID: "p3", Name: "roles:read", Description: "Read roles", Resource: "roles", Action: "read"},
	}
	listResp := PermissionListResponse{
		Permissions: permissions,
		Total:       3,
		Page:        1,
		PageSize:    20,
		TotalPages:  1,
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		assert.Equal(t, "/api/v1/permissions", r.URL.Path)
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(listResp)
	}))
	defer srv.Close()

	c := NewHTTPClient(srv.URL, "tok", "tenant")
	resp, err := c.ListPermissions(context.Background(), nil)
	require.NoError(t, err)
	assert.Len(t, resp.Permissions, 3)
	assert.Equal(t, 3, resp.Total)
	assert.Equal(t, "users:read", resp.Permissions[0].Name)
	assert.Equal(t, "users", resp.Permissions[0].Resource)
	assert.Equal(t, "read", resp.Permissions[0].Action)
}

func TestListPermissions_WithSearch(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "users", r.URL.Query().Get("search"))
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(PermissionListResponse{})
	}))
	defer srv.Close()

	c := NewHTTPClient(srv.URL, "tok", "tenant")
	_, err := c.ListPermissions(context.Background(), &ListOptions{Search: "users"})
	require.NoError(t, err)
}

func TestListPermissions_Error(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]string{"message": "server error"})
	}))
	defer srv.Close()

	c := NewHTTPClient(srv.URL, "tok", "tenant")
	resp, err := c.ListPermissions(context.Background(), nil)
	require.Error(t, err)
	assert.Nil(t, resp)
}

func TestListPermissions_Empty(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(PermissionListResponse{
			Permissions: []Permission{},
			Total:       0,
			TotalPages:  0,
		})
	}))
	defer srv.Close()

	c := NewHTTPClient(srv.URL, "tok", "tenant")
	resp, err := c.ListPermissions(context.Background(), nil)
	require.NoError(t, err)
	assert.Empty(t, resp.Permissions)
	assert.Equal(t, 0, resp.Total)
}
