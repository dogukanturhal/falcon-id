// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"context"
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

// tenantTeamService is the slice of OrganizationService the tenant teams API uses.
type tenantTeamService interface {
	CreateOrganization(ctx context.Context, tenantID uuid.UUID, req *models.CreateOrganizationRequest, createdBy *uuid.UUID) (*models.Organization, error)
	GetOrganization(ctx context.Context, orgID uuid.UUID) (*models.Organization, error)
	ListOrganizations(ctx context.Context, tenantID uuid.UUID, page, pageSize int, search, orgType string) (*models.OrganizationListResponse, error)
	UpdateOrganization(ctx context.Context, orgID uuid.UUID, req *models.UpdateOrganizationRequest) (*models.Organization, error)
	DeleteOrganization(ctx context.Context, orgID uuid.UUID) error
	AddMember(ctx context.Context, orgID uuid.UUID, req *models.AddOrgMemberRequest, addedBy *uuid.UUID) error
	RemoveMembers(ctx context.Context, orgID uuid.UUID, userIDs []uuid.UUID) error
	UpdateMember(ctx context.Context, orgID, userID uuid.UUID, req *models.UpdateOrgMemberRequest) error
	GetMembers(ctx context.Context, orgID uuid.UUID, page, pageSize int) (*models.OrgMembersResponse, error)
}

// TenantTeamHandler serves /api/v1/tenants/me/teams: tenant-admin CRUD over
// organizations whose org_type is forced to "team".
type TenantTeamHandler struct {
	svc tenantTeamService
}

func NewTenantTeamHandler(svc tenantTeamService) *TenantTeamHandler {
	return &TenantTeamHandler{svc: svc}
}

type teamDTO struct {
	ID          uuid.UUID `json:"id"`
	Name        string    `json:"name"`
	Description *string   `json:"description,omitempty"`
	MemberCount int       `json:"member_count"`
	CreatedAt   string    `json:"created_at"`
}

type teamMemberDTO struct {
	UserID      uuid.UUID `json:"user_id"`
	Role        string    `json:"role"`
	Email       string    `json:"email,omitempty"`
	DisplayName *string   `json:"display_name,omitempty"`
}

type createTeamRequest struct {
	Name        string  `json:"name" binding:"required,min=1,max=100"`
	Description *string `json:"description,omitempty"`
}

type updateTeamRequest struct {
	Name        *string `json:"name,omitempty" binding:"omitempty,min=1,max=100"`
	Description *string `json:"description,omitempty"`
}

type teamMemberRequest struct {
	UserID uuid.UUID `json:"user_id" binding:"required"`
	Role   string    `json:"role,omitempty"`
}

type updateTeamMemberRequest struct {
	Role string `json:"role" binding:"required"`
}

func toTeamDTO(o *models.Organization) teamDTO {
	return teamDTO{ID: o.ID, Name: o.Name, Description: o.Description, MemberCount: o.MemberCount, CreatedAt: o.CreatedAt.UTC().Format("2006-01-02T15:04:05Z")}
}

func teamRoleValid(role string) bool {
	return role == models.OrgRoleMember || role == models.OrgRoleManager
}

func (h *TenantTeamHandler) tenantID(c *gin.Context) (uuid.UUID, bool) {
	v, ok := c.Get("tenant_id")
	id, isUUID := v.(uuid.UUID)
	if !ok || !isUUID || id == uuid.Nil {
		c.JSON(http.StatusBadRequest, gin.H{"code": "tenant_required"})
		return uuid.Nil, false
	}
	return id, true
}

func actorID(c *gin.Context) *uuid.UUID {
	if v, ok := c.Get("user_id"); ok {
		if id, isUUID := v.(uuid.UUID); isUUID {
			return &id
		}
	}
	return nil
}

// loadTeam resolves :id to a team of the caller's tenant; anything else is 404.
func (h *TenantTeamHandler) loadTeam(c *gin.Context) (*models.Organization, bool) {
	tenantID, ok := h.tenantID(c)
	if !ok {
		return nil, false
	}
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"code": "invalid_team"})
		return nil, false
	}
	org, err := h.svc.GetOrganization(c.Request.Context(), id)
	if err != nil || org == nil || org.TenantID != tenantID || org.OrgType != models.OrgTypeTeam {
		c.JSON(http.StatusNotFound, gin.H{"code": "team_not_found"})
		return nil, false
	}
	return org, true
}

func teamWriteError(c *gin.Context, err error) {
	if strings.Contains(err.Error(), "already exists") {
		c.JSON(http.StatusConflict, gin.H{"code": "team_name_taken"})
		return
	}
	c.JSON(http.StatusBadRequest, gin.H{"code": "invalid_team", "message": err.Error()})
}

func (h *TenantTeamHandler) List(c *gin.Context) {
	tenantID, ok := h.tenantID(c)
	if !ok {
		return
	}
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "50"))
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 100 {
		pageSize = 50
	}
	res, err := h.svc.ListOrganizations(c.Request.Context(), tenantID, page, pageSize, c.Query("search"), models.OrgTypeTeam)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"code": "internal_error"})
		return
	}
	teams := make([]teamDTO, 0, len(res.Organizations))
	for _, o := range res.Organizations {
		teams = append(teams, toTeamDTO(o))
	}
	c.JSON(http.StatusOK, gin.H{"teams": teams, "total": res.Total, "page": res.Page, "page_size": res.PageSize})
}

func (h *TenantTeamHandler) Create(c *gin.Context) {
	tenantID, ok := h.tenantID(c)
	if !ok {
		return
	}
	var req createTeamRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"code": "invalid_request"})
		return
	}
	org, err := h.svc.CreateOrganization(c.Request.Context(), tenantID, &models.CreateOrganizationRequest{
		Name: strings.TrimSpace(req.Name), Description: req.Description, OrgType: models.OrgTypeTeam,
	}, actorID(c))
	if err != nil {
		teamWriteError(c, err)
		return
	}
	c.JSON(http.StatusCreated, toTeamDTO(org))
}

func (h *TenantTeamHandler) Get(c *gin.Context) {
	org, ok := h.loadTeam(c)
	if !ok {
		return
	}
	c.JSON(http.StatusOK, toTeamDTO(org))
}

func (h *TenantTeamHandler) Update(c *gin.Context) {
	org, ok := h.loadTeam(c)
	if !ok {
		return
	}
	var req updateTeamRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"code": "invalid_request"})
		return
	}
	upd := &models.UpdateOrganizationRequest{Description: req.Description}
	if req.Name != nil {
		name := strings.TrimSpace(*req.Name)
		upd.Name = &name
	}
	updated, err := h.svc.UpdateOrganization(c.Request.Context(), org.ID, upd)
	if err != nil {
		teamWriteError(c, err)
		return
	}
	c.JSON(http.StatusOK, toTeamDTO(updated))
}

// Delete removes the team together with its memberships.
func (h *TenantTeamHandler) Delete(c *gin.Context) {
	org, ok := h.loadTeam(c)
	if !ok {
		return
	}
	ctx := c.Request.Context()
	for {
		res, err := h.svc.GetMembers(ctx, org.ID, 1, 100)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"code": "internal_error"})
			return
		}
		if len(res.Members) == 0 {
			break
		}
		ids := make([]uuid.UUID, 0, len(res.Members))
		for _, m := range res.Members {
			ids = append(ids, m.UserID)
		}
		if err := h.svc.RemoveMembers(ctx, org.ID, ids); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"code": "internal_error"})
			return
		}
	}
	if err := h.svc.DeleteOrganization(ctx, org.ID); err != nil {
		c.JSON(http.StatusConflict, gin.H{"code": "team_delete_failed"})
		return
	}
	c.Status(http.StatusNoContent)
}

func (h *TenantTeamHandler) ListMembers(c *gin.Context) {
	org, ok := h.loadTeam(c)
	if !ok {
		return
	}
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "50"))
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 100 {
		pageSize = 50
	}
	res, err := h.svc.GetMembers(c.Request.Context(), org.ID, page, pageSize)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"code": "internal_error"})
		return
	}
	members := make([]teamMemberDTO, 0, len(res.Members))
	for _, m := range res.Members {
		d := teamMemberDTO{UserID: m.UserID, Role: m.Role}
		if m.User != nil {
			d.Email = m.User.Email
			d.DisplayName = m.User.DisplayName
		}
		members = append(members, d)
	}
	c.JSON(http.StatusOK, gin.H{"members": members, "total": res.Total, "page": res.Page, "page_size": res.PageSize})
}

func (h *TenantTeamHandler) AddMember(c *gin.Context) {
	org, ok := h.loadTeam(c)
	if !ok {
		return
	}
	var req teamMemberRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"code": "invalid_request"})
		return
	}
	if req.Role == "" {
		req.Role = models.OrgRoleMember
	}
	if !teamRoleValid(req.Role) {
		c.JSON(http.StatusBadRequest, gin.H{"code": "invalid_role"})
		return
	}
	if err := h.svc.AddMember(c.Request.Context(), org.ID, &models.AddOrgMemberRequest{UserID: req.UserID, Role: req.Role}, actorID(c)); err != nil {
		teamWriteError(c, err)
		return
	}
	c.JSON(http.StatusCreated, teamMemberDTO{UserID: req.UserID, Role: req.Role})
}

func (h *TenantTeamHandler) UpdateMember(c *gin.Context) {
	org, ok := h.loadTeam(c)
	if !ok {
		return
	}
	userID, err := uuid.Parse(c.Param("user_id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"code": "invalid_user"})
		return
	}
	var req updateTeamMemberRequest
	if err := c.ShouldBindJSON(&req); err != nil || !teamRoleValid(req.Role) {
		c.JSON(http.StatusBadRequest, gin.H{"code": "invalid_role"})
		return
	}
	if err := h.svc.UpdateMember(c.Request.Context(), org.ID, userID, &models.UpdateOrgMemberRequest{Role: &req.Role}); err != nil {
		teamWriteError(c, err)
		return
	}
	c.JSON(http.StatusOK, teamMemberDTO{UserID: userID, Role: req.Role})
}

func (h *TenantTeamHandler) RemoveMember(c *gin.Context) {
	org, ok := h.loadTeam(c)
	if !ok {
		return
	}
	userID, err := uuid.Parse(c.Param("user_id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"code": "invalid_user"})
		return
	}
	if err := h.svc.RemoveMembers(c.Request.Context(), org.ID, []uuid.UUID{userID}); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"code": "internal_error"})
		return
	}
	c.Status(http.StatusNoContent)
}
