// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"bytes"
	"context"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

type teamSvcFake struct {
	orgs     map[uuid.UUID]*models.Organization
	members  map[uuid.UUID][]*models.OrgMember
	created  *models.CreateOrganizationRequest
	addedRol string
	deleted  bool
}

func (f *teamSvcFake) CreateOrganization(_ context.Context, tenantID uuid.UUID, req *models.CreateOrganizationRequest, _ *uuid.UUID) (*models.Organization, error) {
	f.created = req
	o := &models.Organization{ID: uuid.New(), TenantID: tenantID, Name: req.Name, OrgType: req.OrgType, CreatedAt: time.Now()}
	f.orgs[o.ID] = o
	return o, nil
}
func (f *teamSvcFake) GetOrganization(_ context.Context, id uuid.UUID) (*models.Organization, error) {
	if o, ok := f.orgs[id]; ok {
		return o, nil
	}
	return nil, context.Canceled
}
func (f *teamSvcFake) ListOrganizations(context.Context, uuid.UUID, int, int, string, string) (*models.OrganizationListResponse, error) {
	return &models.OrganizationListResponse{}, nil
}
func (f *teamSvcFake) UpdateOrganization(_ context.Context, id uuid.UUID, _ *models.UpdateOrganizationRequest) (*models.Organization, error) {
	return f.orgs[id], nil
}
func (f *teamSvcFake) DeleteOrganization(_ context.Context, id uuid.UUID) error {
	f.deleted = true
	delete(f.orgs, id)
	return nil
}
func (f *teamSvcFake) AddMember(_ context.Context, _ uuid.UUID, req *models.AddOrgMemberRequest, _ *uuid.UUID) error {
	f.addedRol = req.Role
	return nil
}
func (f *teamSvcFake) RemoveMembers(_ context.Context, id uuid.UUID, _ []uuid.UUID) error {
	f.members[id] = nil
	return nil
}
func (f *teamSvcFake) UpdateMember(context.Context, uuid.UUID, uuid.UUID, *models.UpdateOrgMemberRequest) error {
	return nil
}
func (f *teamSvcFake) GetMembers(_ context.Context, id uuid.UUID, _, _ int) (*models.OrgMembersResponse, error) {
	return &models.OrgMembersResponse{Members: f.members[id]}, nil
}

func teamCall(h *TenantTeamHandler, tenant uuid.UUID, method, path, body string) *httptest.ResponseRecorder {
	r := gin.New()
	r.Use(func(c *gin.Context) { c.Set("tenant_id", tenant) })
	r.POST("/teams", h.Create)
	r.DELETE("/teams/:id", h.Delete)
	r.POST("/teams/:id/members", h.AddMember)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(method, path, bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(rec, req)
	return rec
}

func TestTenantTeamHandler(t *testing.T) {
	tenant := uuid.New()
	team := &models.Organization{ID: uuid.New(), TenantID: tenant, OrgType: models.OrgTypeTeam}
	dept := &models.Organization{ID: uuid.New(), TenantID: tenant, OrgType: models.OrgTypeDepartment}
	foreign := &models.Organization{ID: uuid.New(), TenantID: uuid.New(), OrgType: models.OrgTypeTeam}
	f := &teamSvcFake{
		orgs:    map[uuid.UUID]*models.Organization{team.ID: team, dept.ID: dept, foreign.ID: foreign},
		members: map[uuid.UUID][]*models.OrgMember{team.ID: {{UserID: uuid.New()}}},
	}
	h := NewTenantTeamHandler(f)

	rec := teamCall(h, tenant, "POST", "/teams", `{"name":"Sales","org_type":"company"}`)
	require.Equal(t, 201, rec.Code)
	require.Equal(t, models.OrgTypeTeam, f.created.OrgType, "org_type is forced to team")

	require.Equal(t, 404, teamCall(h, tenant, "DELETE", "/teams/"+dept.ID.String(), "").Code, "non-team org")
	require.Equal(t, 404, teamCall(h, tenant, "DELETE", "/teams/"+foreign.ID.String(), "").Code, "other tenant")

	require.Equal(t, 400, teamCall(h, tenant, "POST", "/teams/"+team.ID.String()+"/members", `{"user_id":"`+uuid.NewString()+`","role":"owner"}`).Code)
	require.Equal(t, 201, teamCall(h, tenant, "POST", "/teams/"+team.ID.String()+"/members", `{"user_id":"`+uuid.NewString()+`","role":"manager"}`).Code)
	require.Equal(t, "manager", f.addedRol)

	require.Equal(t, 204, teamCall(h, tenant, "DELETE", "/teams/"+team.ID.String(), "").Code)
	require.True(t, f.deleted)
}
