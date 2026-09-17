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

func TestListTenants_Success(t *testing.T) {
	tenants := []Tenant{
		{ID: "t1", Name: "Acme Corp", Slug: "acme", Status: "active"},
		{ID: "t2", Name: "Beta Inc", Slug: "beta", Status: "suspended"},
	}
	listResp := TenantListResponse{
		Tenants:    tenants,
		Total:      2,
		Page:       1,
		PageSize:   20,
		TotalPages: 1,
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		assert.Equal(t, "/api/v1/platform/tenants", r.URL.Path)
		assert.Equal(t, "Bearer platform-admin-token", r.Header.Get("Authorization"))
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(listResp)
	}))
	defer srv.Close()

	c := NewHTTPClient(srv.URL, "platform-admin-token", "")
	resp, err := c.ListTenants(context.Background(), nil)
	require.NoError(t, err)
	assert.Len(t, resp.Tenants, 2)
	assert.Equal(t, "Acme Corp", resp.Tenants[0].Name)
	assert.Equal(t, "acme", resp.Tenants[0].Slug)
	assert.Equal(t, "suspended", resp.Tenants[1].Status)
}

func TestListTenants_WithPagination(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "3", r.URL.Query().Get("page"))
		assert.Equal(t, "5", r.URL.Query().Get("page_size"))
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(TenantListResponse{})
	}))
	defer srv.Close()

	c := NewHTTPClient(srv.URL, "tok", "")
	_, err := c.ListTenants(context.Background(), &ListOptions{Page: 3, PageSize: 5})
	require.NoError(t, err)
}

func TestListTenants_Unauthorized(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(map[string]string{"message": "unauthorized"})
	}))
	defer srv.Close()

	c := NewHTTPClient(srv.URL, "", "")
	resp, err := c.ListTenants(context.Background(), nil)
	require.Error(t, err)
	assert.Nil(t, resp)
}

func TestListTenants_Empty(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(TenantListResponse{
			Tenants:    []Tenant{},
			Total:      0,
			TotalPages: 0,
		})
	}))
	defer srv.Close()

	c := NewHTTPClient(srv.URL, "tok", "")
	resp, err := c.ListTenants(context.Background(), nil)
	require.NoError(t, err)
	assert.Empty(t, resp.Tenants)
}
