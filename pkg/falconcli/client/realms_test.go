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

func TestListRealms_Success(t *testing.T) {
	realms := []Realm{
		{ID: "realm-1", Name: "Default Realm", TenantID: "t1", Status: "active"},
		{ID: "realm-2", Name: "Dev Realm", TenantID: "t1", Status: "active"},
	}
	listResp := RealmListResponse{
		Realms:     realms,
		Total:      2,
		Page:       1,
		PageSize:   20,
		TotalPages: 1,
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		assert.Equal(t, "/api/v1/platform/realms", r.URL.Path)
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(listResp)
	}))
	defer srv.Close()

	c := NewHTTPClient(srv.URL, "tok", "tenant")
	resp, err := c.ListRealms(context.Background(), nil)
	require.NoError(t, err)
	assert.Len(t, resp.Realms, 2)
	assert.Equal(t, "realm-1", resp.Realms[0].ID)
	assert.Equal(t, "Default Realm", resp.Realms[0].Name)
	assert.Equal(t, "t1", resp.Realms[0].TenantID)
}

func TestListRealms_WithPagination(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "2", r.URL.Query().Get("page"))
		assert.Equal(t, "10", r.URL.Query().Get("page_size"))
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(RealmListResponse{})
	}))
	defer srv.Close()

	c := NewHTTPClient(srv.URL, "tok", "tenant")
	_, err := c.ListRealms(context.Background(), &ListOptions{Page: 2, PageSize: 10})
	require.NoError(t, err)
}

func TestListRealms_Forbidden(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(map[string]string{"message": "access denied"})
	}))
	defer srv.Close()

	c := NewHTTPClient(srv.URL, "tok", "tenant")
	resp, err := c.ListRealms(context.Background(), nil)
	require.Error(t, err)
	assert.Nil(t, resp)

	var apiErr *APIError
	require.ErrorAs(t, err, &apiErr)
	assert.Equal(t, http.StatusForbidden, apiErr.StatusCode)
}
