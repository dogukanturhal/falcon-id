// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/dogukanturhal/falcon-id/internal/middleware"
	"github.com/dogukanturhal/falcon-id/internal/repositories"
	"github.com/dogukanturhal/falcon-id/internal/services"
	"github.com/stretchr/testify/require"
)

type notifRecipientsFake struct {
	rows     []repositories.NotificationRecipientRow
	err      error
	gotUsers []uuid.UUID
	gotRoles []string
	calls    int
}

func (f *notifRecipientsFake) ListNotificationRecipients(_ context.Context, _ uuid.UUID, ids []uuid.UUID, roles []string) ([]repositories.NotificationRecipientRow, error) {
	f.calls++
	f.gotUsers, f.gotRoles = ids, roles
	return f.rows, f.err
}

type notifPermFake struct {
	allow map[uuid.UUID]map[string]bool
	err   error
}

func (f *notifPermFake) CheckPermission(_ context.Context, req services.PermissionRequest) (*services.PermissionResult, error) {
	if f.err != nil {
		return nil, f.err
	}
	return &services.PermissionResult{Allowed: f.allow[req.UserID][req.Permission]}, nil
}

func notifRecipientsDo(h *NotificationRecipientsHandler, tenantPath, body, serviceTenant, scopes, auth string) *httptest.ResponseRecorder {
	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set(middleware.CtxKeyAuthMethod, auth)
		c.Set(middleware.CtxKeyServiceTenantID, serviceTenant)
		c.Set(middleware.CtxKeyServiceScopes, scopes)
	})
	r.POST("/tenants/:id/notification-recipients", middleware.RequireScope("iam:members:read"), h.Resolve)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/tenants/"+tenantPath+"/notification-recipients", bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(rec, req)
	return rec
}

func TestNotificationRecipientsScopeAndActAs(t *testing.T) {
	gin.SetMode(gin.TestMode)
	f := &notifRecipientsFake{}
	h := NewNotificationRecipientsHandler(f, &notifPermFake{})
	body := `{"permissions":["preaccounting:edoc-credits:read"]}`
	tenant := approvalTenant.String()

	require.Equal(t, 403, notifRecipientsDo(h, tenant, body, tenant, "authz:lookup", "service_jwt").Code)
	require.Equal(t, 401, notifRecipientsDo(h, tenant, body, tenant, "iam:members:read", "jwt").Code)
	// Bound to another tenant without tenant:act-as.
	rec := notifRecipientsDo(h, tenant, body, uuid.NewString(), "iam:members:read", "service_jwt")
	require.Equal(t, 403, rec.Code)
	require.Contains(t, rec.Body.String(), "tenant_act_as_required")
	require.Equal(t, 0, f.calls)
	// Act-as unbound platform service is allowed.
	require.Equal(t, 200, notifRecipientsDo(h, tenant, body, "", "iam:members:read tenant:act-as", "service_jwt").Code)
	require.Equal(t, 400, notifRecipientsDo(h, "not-a-uuid", body, tenant, "iam:members:read", "service_jwt").Code)
}

func TestNotificationRecipientsValidation(t *testing.T) {
	gin.SetMode(gin.TestMode)
	tenant := approvalTenant.String()
	ids := func(n int) string {
		s := make([]string, n)
		for i := range s {
			s[i] = uuid.NewString()
		}
		b, _ := json.Marshal(s)
		return string(b)
	}
	perm := `["preaccounting:edoc-credits:read"]`
	cases := map[string]string{
		"no permissions":      `{"permissions":[]}`,
		"missing permissions": `{"user_ids":[]}`,
		"too many perms":      `{"permissions":["a:b:c","a:b:d","a:b:e","a:b:f","a:b:g","a:b:h"]}`,
		"too many roles":      `{"system_roles":["a","b","c","d","e","f"],"permissions":` + perm + `}`,
		"too many users":      `{"user_ids":` + ids(501) + `,"permissions":` + perm + `}`,
		"nil user":            `{"user_ids":["00000000-0000-0000-0000-000000000000"],"permissions":` + perm + `}`,
		"bad user":            `{"user_ids":["x"],"permissions":` + perm + `}`,
		"bad role":            `{"system_roles":["Owner;"],"permissions":` + perm + `}`,
		"bad permission":      `{"permissions":["not a permission"]}`,
		"bad json":            `{`,
	}
	for name, body := range cases {
		f := &notifRecipientsFake{}
		h := NewNotificationRecipientsHandler(f, &notifPermFake{})
		rec := notifRecipientsDo(h, tenant, body, tenant, "iam:members:read", "service_jwt")
		require.Equal(t, 400, rec.Code, name)
		require.Equal(t, 0, f.calls, name)
	}
	// Upper bounds are accepted.
	f := &notifRecipientsFake{}
	h := NewNotificationRecipientsHandler(f, &notifPermFake{})
	rec := notifRecipientsDo(h, tenant, `{"user_ids":`+ids(500)+`,"system_roles":["owner","admin","billing","a","b"],"permissions":["a:b:c","a:b:d","a:b:e","a:b:f","a:b:g"]}`, tenant, "iam:members:read", "service_jwt")
	require.Equal(t, 200, rec.Code)
	require.Len(t, f.gotUsers, 500)
}

func TestNotificationRecipientsInactiveAndDecisions(t *testing.T) {
	gin.SetMode(gin.TestMode)
	tenant := approvalTenant.String()
	active, inactive, missing := uuid.New(), uuid.New(), uuid.New()
	const read, manage = "preaccounting:edoc-credits:read", "preaccounting:edoc-credits:manage"
	f := &notifRecipientsFake{rows: []repositories.NotificationRecipientRow{
		{UserID: active, Email: "a@example.com", Active: true, MembershipKind: "internal", SystemRoles: []string{"admin"}},
		{UserID: inactive, Active: false, MembershipKind: "internal"},
		{UserID: missing, Active: false},
	}}
	// Inactive users are granted by the engine here; the handler must still report false.
	p := &notifPermFake{allow: map[uuid.UUID]map[string]bool{
		active:   {read: true},
		inactive: {read: true, manage: true},
	}}
	h := NewNotificationRecipientsHandler(f, p)
	rec := notifRecipientsDo(h, tenant, `{"user_ids":["`+active.String()+`","`+inactive.String()+`","`+missing.String()+`"],"system_roles":["admin"],"permissions":["`+manage+`","`+read+`"]}`, tenant, "iam:members:read", "service_jwt")
	require.Equal(t, 200, rec.Code)
	require.Equal(t, "no-store", rec.Header().Get("Cache-Control"))
	var out struct {
		TenantID uuid.UUID                     `json:"tenant_id"`
		Complete bool                          `json:"complete"`
		Members  []notificationRecipientMember `json:"members"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &out))
	require.True(t, out.Complete)
	require.Equal(t, approvalTenant, out.TenantID)
	require.Len(t, out.Members, 3)
	require.True(t, out.Members[0].Active)
	require.Equal(t, map[string]bool{read: true, manage: false}, out.Members[0].Decisions)
	require.Equal(t, []string{"admin"}, out.Members[0].SystemRoles)
	require.Empty(t, out.Members[0].ExternalScopes)
	for _, m := range out.Members[1:] {
		require.False(t, m.Active)
		require.Equal(t, map[string]bool{read: false, manage: false}, m.Decisions)
		require.NotNil(t, m.SystemRoles)
		require.Empty(t, m.Email)
	}
	require.Contains(t, rec.Body.String(), `"external_scopes":[]`)
}

func TestNotificationRecipientsBillingEnumerationAndExternalKind(t *testing.T) {
	gin.SetMode(gin.TestMode)
	tenant := approvalTenant.String()
	billing, ext := uuid.New(), uuid.New()
	f := &notifRecipientsFake{rows: []repositories.NotificationRecipientRow{
		{UserID: billing, Email: "b@example.com", Active: true, MembershipKind: "internal", SystemRoles: []string{"billing"}},
		{UserID: ext, Email: "e@example.com", Active: true, MembershipKind: "external", SystemRoles: []string{}},
	}}
	h := NewNotificationRecipientsHandler(f, &notifPermFake{})
	rec := notifRecipientsDo(h, tenant, `{"system_roles":["owner","admin","billing","billing"],"permissions":["preaccounting:edoc-credits:read"]}`, tenant, "iam:members:read", "service_jwt")
	require.Equal(t, 200, rec.Code)
	// No user_ids requested: members come from role enumeration; roles are deduped and sorted.
	require.Empty(t, f.gotUsers)
	require.Equal(t, []string{"admin", "billing", "owner"}, f.gotRoles)
	var out struct {
		Members []notificationRecipientMember `json:"members"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &out))
	require.Equal(t, "internal", out.Members[0].MembershipKind)
	require.Equal(t, []string{"billing"}, out.Members[0].SystemRoles)
	require.Equal(t, "external", out.Members[1].MembershipKind)
	require.Empty(t, out.Members[1].ExternalScopes)
}

func TestNotificationRecipientsFailClosed(t *testing.T) {
	gin.SetMode(gin.TestMode)
	tenant := approvalTenant.String()
	u := uuid.New()
	body := `{"user_ids":["` + u.String() + `"],"permissions":["preaccounting:edoc-credits:read"]}`

	h := NewNotificationRecipientsHandler(&notifRecipientsFake{err: errors.New("db")}, &notifPermFake{})
	rec := notifRecipientsDo(h, tenant, body, tenant, "iam:members:read", "service_jwt")
	require.Equal(t, 503, rec.Code)
	require.Equal(t, "no-store", rec.Header().Get("Cache-Control"))

	h = NewNotificationRecipientsHandler(&notifRecipientsFake{rows: []repositories.NotificationRecipientRow{{UserID: u, Active: true}}}, &notifPermFake{err: errors.New("spicedb")})
	rec = notifRecipientsDo(h, tenant, body, tenant, "iam:members:read", "service_jwt")
	require.Equal(t, 503, rec.Code)
	require.NotContains(t, rec.Body.String(), `"complete":true`)
}
