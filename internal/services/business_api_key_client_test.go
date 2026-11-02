// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBusinessAPIKeyScopeRequestsBothScopes(t *testing.T) {
	assert.Equal(t, "tenant:act-as iam:api-keys:sync", BusinessAPIKeyScope)
}

func TestBusinessAPIKeyClient_RequestShape(t *testing.T) {
	tenantID, keyID, companyID := uuid.New(), uuid.New(), uuid.New()
	for _, method := range []string{http.MethodPost, http.MethodDelete} {
		var gotPath, gotTenant string
		var gotBody map[string]interface{}
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, method, r.Method)
			gotPath, gotTenant = r.URL.Path, r.Header.Get("X-Tenant-ID")
			raw, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(raw, &gotBody)
			w.WriteHeader(http.StatusOK)
		}))
		c := NewBusinessAPIKeyClient(srv.URL, srv.Client())
		var err error
		if method == http.MethodPost {
			err = c.AddCompanies(t.Context(), tenantID, keyID, []uuid.UUID{companyID})
		} else {
			err = c.RemoveCompanies(t.Context(), tenantID, keyID, []uuid.UUID{companyID})
		}
		srv.Close()
		require.NoError(t, err)
		assert.Equal(t, "/api/v1/core/internal/api-key-principals/"+keyID.String()+"/companies", gotPath)
		assert.Equal(t, tenantID.String(), gotTenant)
		assert.Equal(t, map[string]interface{}{"companyIds": []interface{}{companyID.String()}}, gotBody)
	}
}

func TestBusinessAPIKeyClient_StatusClassification(t *testing.T) {
	bad := uuid.New()
	cases := []struct {
		name     string
		status   int
		body     string
		terminal bool
	}{
		{"422 company_not_in_tenant", 422, `{"code":"company_not_in_tenant","companyIds":["` + bad.String() + `"]}`, true},
		{"400 invalid_company_ids", 400, `{"code":"invalid_company_ids"}`, true},
		{"500 retries", 500, ``, false},
		{"503 retries", 503, ``, false},
		{"403 retries", 403, ``, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer srv.Close()
			c := NewBusinessAPIKeyClient(srv.URL, srv.Client())
			err := c.AddCompanies(t.Context(), uuid.New(), uuid.New(), []uuid.UUID{bad})
			require.Error(t, err)
			be, terminal := companySyncTerminal(err)
			assert.Equal(t, tc.terminal, terminal)
			if tc.terminal {
				assert.Equal(t, tc.status, be.StatusCode)
			}
			if tc.status == 422 {
				assert.Equal(t, "company_not_in_tenant", be.Code)
				assert.Equal(t, []uuid.UUID{bad}, be.CompanyIDs)
			}
		})
	}
}

func TestBusinessAPIKeyClient_NetworkErrorIsNotTerminal(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	url := srv.URL
	srv.Close()
	err := NewBusinessAPIKeyClient(url, nil).AddCompanies(t.Context(), uuid.New(), uuid.New(), []uuid.UUID{uuid.New()})
	require.Error(t, err)
	_, terminal := companySyncTerminal(err)
	assert.False(t, terminal)
}

func TestBusinessAPIKeyClient_DeleteNotFoundIsDone(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	defer srv.Close()
	require.NoError(t, NewBusinessAPIKeyClient(srv.URL, srv.Client()).RemoveCompanies(t.Context(), uuid.New(), uuid.New(), []uuid.UUID{uuid.New()}))
}
