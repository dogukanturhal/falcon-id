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

func makeRole(id, name string, isSystem bool) Role {
	return Role{
		ID:          id,
		Name:        name,
		Description: "Role: " + name,
		IsSystem:    isSystem,
		CreatedAt:   time.Now(),
	}
}

func TestListRoles_Success(t *testing.T) {
	roles := []Role{
		makeRole("r1", "admin", true),
		makeRole("r2", "viewer", false),
	}
	listResp := RoleListResponse{
		Roles:      roles,
		Total:      2,
		Page:       1,
		PageSize:   20,
		TotalPages: 1,
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		assert.Equal(t, "/api/v1/roles", r.URL.Path)
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(listResp)
	}))
	defer srv.Close()

	c := NewHTTPClient(srv.URL, "tok", "tenant")
	resp, err := c.ListRoles(context.Background(), nil)
	require.NoError(t, err)
	assert.Len(t, resp.Roles, 2)
	assert.Equal(t, "admin", resp.Roles[0].Name)
	assert.True(t, resp.Roles[0].IsSystem)
	assert.False(t, resp.Roles[1].IsSystem)
}

func TestListRoles_WithOptions(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "1", r.URL.Query().Get("page"))
		assert.Equal(t, "5", r.URL.Query().Get("page_size"))
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(RoleListResponse{})
	}))
	defer srv.Close()

	c := NewHTTPClient(srv.URL, "tok", "tenant")
	_, err := c.ListRoles(context.Background(), &ListOptions{Page: 1, PageSize: 5})
	require.NoError(t, err)
}

func TestListRoles_Error(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(map[string]string{"message": "unauthorized"})
	}))
	defer srv.Close()

	c := NewHTTPClient(srv.URL, "", "tenant")
	resp, err := c.ListRoles(context.Background(), nil)
	require.Error(t, err)
	assert.Nil(t, resp)
}

func TestGetRole_Success(t *testing.T) {
	role := makeRole("r-xyz", "superadmin", true)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		assert.Equal(t, "/api/v1/roles/r-xyz", r.URL.Path)
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(RoleResponse{Role: role})
	}))
	defer srv.Close()

	c := NewHTTPClient(srv.URL, "tok", "tenant")
	resp, err := c.GetRole(context.Background(), "r-xyz")
	require.NoError(t, err)
	assert.Equal(t, "r-xyz", resp.ID)
	assert.Equal(t, "superadmin", resp.Name)
	assert.True(t, resp.IsSystem)
}

func TestGetRole_NotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(map[string]string{"message": "role not found"})
	}))
	defer srv.Close()

	c := NewHTTPClient(srv.URL, "tok", "tenant")
	resp, err := c.GetRole(context.Background(), "nonexistent")
	require.Error(t, err)
	assert.Nil(t, resp)

	var apiErr *APIError
	require.ErrorAs(t, err, &apiErr)
	assert.Equal(t, http.StatusNotFound, apiErr.StatusCode)
}
