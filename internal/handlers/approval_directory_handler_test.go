// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"bytes"
	"context"
	"errors"
	"net/http/httptest"
	"os"
	"testing"

	v1 "github.com/authzed/authzed-go/proto/authzed/api/v1"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/dogukanturhal/falcon-id/internal/middleware"
	"github.com/stretchr/testify/require"
)

var approvalTenant = uuid.MustParse("11111111-1111-1111-1111-111111111111")
var approvalUser = uuid.MustParse("22222222-2222-2222-2222-222222222222")

type approvalDirectoryFake struct {
	members []uuid.UUID
	ids     []string
	err     error
	allowed []bool
}

func (f *approvalDirectoryFake) ListApprovalMembers(context.Context, uuid.UUID) ([]uuid.UUID, error) {
	return f.members, f.err
}
func (f *approvalDirectoryFake) LookupApprovalSubjects(_ context.Context, typ, id, perm string) ([]string, error) {
	if typ != "access_grant" || id != approvalTenant.String()+"/mm__purchase_orders__approve" || perm != "check" {
		return nil, errors.New("wrong ID contract")
	}
	return f.ids, f.err
}
func (f *approvalDirectoryFake) CheckApprovalPermissions(_ context.Context, tenant, user string, checks []*v1.CheckBulkPermissionsRequestItem) ([]bool, error) {
	if tenant != approvalTenant.String() || user != approvalUser.String() || checks[0].Resource.ObjectType != "access_grant" || checks[0].Resource.ObjectId != tenant+"/mm__purchase_orders__approve" || checks[0].Permission != "check" {
		return nil, errors.New("wrong batch contract")
	}
	return f.allowed, f.err
}

func approvalFixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile("testdata/approvals/" + name + ".json")
	require.NoError(t, err)
	return data
}
func approvalRequest(h *ApprovalDirectoryHandler, method, path string, body []byte, tenant, scopes, auth string) *httptest.ResponseRecorder {
	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set(middleware.CtxKeyAuthMethod, auth)
		c.Set(middleware.CtxKeyServiceTenantID, tenant)
		c.Set(middleware.CtxKeyServiceScopes, scopes)
	})
	r.GET("/tenants/:id/summary", middleware.RequireScope("iam:members:read"), h.MembershipSummary)
	r.GET("/tenants/:id/members/:user_id", middleware.RequireScope("iam:members:read"), h.ApprovalMember)
	r.POST("/lookup", middleware.RequireScope("authz:lookup"), h.LookupSubjects)
	r.POST("/batch", middleware.RequireScope("authz:check"), h.BatchCheck)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(method, path, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(rec, req)
	return rec
}

func TestApprovalDirectoryGoldenContracts(t *testing.T) {
	f := &approvalDirectoryFake{members: []uuid.UUID{approvalUser}, ids: []string{approvalTenant.String() + "/" + approvalUser.String()}}
	h := NewApprovalDirectoryHandler(f, f)
	for _, name := range []string{"single", "multiple"} {
		if name == "multiple" {
			f.members = append(f.members, uuid.New())
		}
		rec := approvalRequest(h, "GET", "/tenants/"+approvalTenant.String()+"/summary", nil, approvalTenant.String(), "iam:members:read", "service_jwt")
		require.Equal(t, 200, rec.Code)
		require.JSONEq(t, string(approvalFixture(t, "membership-summary."+name)), rec.Body.String())
	}
	rec := approvalRequest(h, "POST", "/lookup", approvalFixture(t, "falcon-lookup.request"), approvalTenant.String(), "authz:lookup", "service_jwt")
	require.Equal(t, 200, rec.Code)
	require.JSONEq(t, string(approvalFixture(t, "falcon-lookup.response")), rec.Body.String())
}

func TestApprovalDirectoryTenantAndFailureControls(t *testing.T) {
	for _, tc := range []struct {
		name, tenant, scopes, auth string
		want                       int
	}{
		{"missing scope", approvalTenant.String(), "", "service_jwt", 403},
		{"different tenant", uuid.NewString(), "authz:lookup", "service_jwt", 403},
		{"unbound service", "", "authz:lookup", "service_jwt", 403},
		{"act as", "", "authz:lookup tenant:act-as", "service_jwt", 200},
		{"legacy key", approvalTenant.String(), "authz:lookup", "internal_key", 401},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := &approvalDirectoryFake{}
			rec := approvalRequest(NewApprovalDirectoryHandler(f, f), "POST", "/lookup", approvalFixture(t, "falcon-lookup.request"), tc.tenant, tc.scopes, tc.auth)
			require.Equal(t, tc.want, rec.Code)
		})
	}
	f := &approvalDirectoryFake{err: errors.New("down")}
	rec := approvalRequest(NewApprovalDirectoryHandler(f, f), "POST", "/lookup", approvalFixture(t, "falcon-lookup.request"), approvalTenant.String(), "authz:lookup", "service_jwt")
	require.Equal(t, 503, rec.Code)
	for _, id := range []string{uuid.NewString() + "/" + approvalUser.String(), approvalTenant.String() + "/not-uuid", "*"} {
		f.err = nil
		f.ids = []string{id}
		rec = approvalRequest(NewApprovalDirectoryHandler(f, f), "POST", "/lookup", approvalFixture(t, "falcon-lookup.request"), approvalTenant.String(), "authz:lookup", "service_jwt")
		require.Equal(t, 503, rec.Code)
	}
}

func TestApprovalDirectoryFiltersAndBatch(t *testing.T) {
	f := &approvalDirectoryFake{members: []uuid.UUID{approvalUser}, ids: []string{approvalTenant.String() + "/" + approvalUser.String(), approvalTenant.String() + "/" + uuid.NewString(), approvalTenant.String() + "/" + approvalUser.String()}, allowed: []bool{true}}
	h := NewApprovalDirectoryHandler(f, f)
	rec := approvalRequest(h, "POST", "/lookup", approvalFixture(t, "falcon-lookup.request"), approvalTenant.String(), "authz:lookup", "service_jwt")
	require.Equal(t, 200, rec.Code)
	require.JSONEq(t, string(approvalFixture(t, "falcon-lookup.response")), rec.Body.String())
	body := []byte(`{"tenant_id":"` + approvalTenant.String() + `","user_id":"` + approvalUser.String() + `","checks":[{"resource_type":"access_grant","resource_id":"` + approvalTenant.String() + `/mm__purchase_orders__approve","permission":"check"}]}`)
	rec = approvalRequest(h, "POST", "/batch", body, approvalTenant.String(), "authz:check", "service_jwt")
	require.Equal(t, 200, rec.Code)
	require.Contains(t, rec.Body.String(), `"allowed":[true]`)
	f.members = nil
	rec = approvalRequest(h, "POST", "/batch", body, approvalTenant.String(), "authz:check", "service_jwt")
	require.Equal(t, 200, rec.Code)
	require.Contains(t, rec.Body.String(), `"allowed":[false]`)
	bad := bytes.ReplaceAll(approvalFixture(t, "falcon-lookup.request"), []byte(approvalTenant.String()+"/mm"), []byte(approvalTenant.String()+"_mm"))
	rec = approvalRequest(h, "POST", "/lookup", bad, approvalTenant.String(), "authz:lookup", "service_jwt")
	require.Equal(t, 400, rec.Code)
}

func TestApprovalDirectoryApprovalMember(t *testing.T) {
	other := uuid.New()
	f := &approvalDirectoryFake{members: []uuid.UUID{approvalUser}}
	h := NewApprovalDirectoryHandler(f, f)
	path := func(user string) string { return "/tenants/" + approvalTenant.String() + "/members/" + user }

	rec := approvalRequest(h, "GET", path(approvalUser.String()), nil, approvalTenant.String(), "iam:members:read", "service_jwt")
	require.Equal(t, 200, rec.Code)
	require.JSONEq(t, `{"tenant_id":"`+approvalTenant.String()+`","user_id":"`+approvalUser.String()+`","active_non_guest":true}`, rec.Body.String())

	rec = approvalRequest(h, "GET", path(other.String()), nil, approvalTenant.String(), "iam:members:read", "service_jwt")
	require.Equal(t, 200, rec.Code)
	require.JSONEq(t, `{"tenant_id":"`+approvalTenant.String()+`","user_id":"`+other.String()+`","active_non_guest":false}`, rec.Body.String())

	for _, tc := range []struct {
		name, user, tenant, scopes, auth string
		want                             int
	}{
		{"bad user", "not-uuid", approvalTenant.String(), "iam:members:read", "service_jwt", 400},
		{"nil user", uuid.Nil.String(), approvalTenant.String(), "iam:members:read", "service_jwt", 400},
		{"missing scope", approvalUser.String(), approvalTenant.String(), "", "service_jwt", 403},
		{"different tenant", approvalUser.String(), uuid.NewString(), "iam:members:read", "service_jwt", 403},
		{"legacy key", approvalUser.String(), approvalTenant.String(), "iam:members:read", "internal_key", 401},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := approvalRequest(h, "GET", path(tc.user), nil, tc.tenant, tc.scopes, tc.auth)
			require.Equal(t, tc.want, rec.Code)
		})
	}

	down := &approvalDirectoryFake{err: errors.New("down")}
	rec = approvalRequest(NewApprovalDirectoryHandler(down, down), "GET", path(approvalUser.String()), nil, approvalTenant.String(), "iam:members:read", "service_jwt")
	require.Equal(t, 503, rec.Code)
}
