// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"context"
	"net/http"
	"regexp"
	"sort"
	"strings"

	v1 "github.com/authzed/authzed-go/proto/authzed/api/v1"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/dogukanturhal/falcon-id/internal/middleware"
)

type ApprovalMembershipReader interface {
	ListApprovalMembers(context.Context, uuid.UUID) ([]uuid.UUID, error)
}

type ApprovalPermissionReader interface {
	LookupApprovalSubjects(context.Context, string, string, string) ([]string, error)
	CheckApprovalPermissions(context.Context, string, string, []*v1.CheckBulkPermissionsRequestItem) ([]bool, error)
}

type ApprovalDirectoryHandler struct {
	members     ApprovalMembershipReader
	permissions ApprovalPermissionReader
}

func NewApprovalDirectoryHandler(members ApprovalMembershipReader, permissions ApprovalPermissionReader) *ApprovalDirectoryHandler {
	return &ApprovalDirectoryHandler{members: members, permissions: permissions}
}

// authorizeDirectoryTenant requires a scoped service JWT, never user headers
// or the transitional internal key. Unbound platform services also need act-as.
func authorizeDirectoryTenant(c *gin.Context, tenantID uuid.UUID) bool {
	if tenantID == uuid.Nil {
		c.AbortWithStatusJSON(400, gin.H{"code": "invalid_tenant"})
		return false
	}
	if c.GetString(middleware.CtxKeyAuthMethod) != "service_jwt" {
		c.AbortWithStatusJSON(401, gin.H{"code": "service_authentication_required"})
		return false
	}
	if middleware.GetServiceTenantID(c) != tenantID {
		if _, ok := middleware.GetServiceScopes(c)["tenant:act-as"]; !ok {
			c.AbortWithStatusJSON(403, gin.H{"code": "tenant_act_as_required"})
			return false
		}
	}
	return true
}

func directoryUnavailable(c *gin.Context) {
	c.JSON(http.StatusServiceUnavailable, gin.H{"code": "approver_directory_unavailable"})
}

func (h *ApprovalDirectoryHandler) MembershipSummary(c *gin.Context) {
	tenantID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(400, gin.H{"code": "invalid_tenant"})
		return
	}
	if !authorizeDirectoryTenant(c, tenantID) {
		return
	}
	if h.members == nil {
		directoryUnavailable(c)
		return
	}
	members, err := h.members.ListApprovalMembers(c.Request.Context(), tenantID)
	if err != nil {
		directoryUnavailable(c)
		return
	}
	var sole *uuid.UUID
	if len(members) == 1 {
		sole = &members[0]
	}
	c.JSON(200, gin.H{"tenant_id": tenantID, "active_non_guest_user_count": len(members), "sole_user_id": sole})
}

// ApprovalMember answers whether one user is an active, non-guest member of the
// tenant, with the same membership set as MembershipSummary. workflow-engine
// calls it to validate a delegation target before reassigning a task.
func (h *ApprovalDirectoryHandler) ApprovalMember(c *gin.Context) {
	tenantID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(400, gin.H{"code": "invalid_tenant"})
		return
	}
	userID, err := uuid.Parse(c.Param("user_id"))
	if err != nil || userID == uuid.Nil {
		c.JSON(400, gin.H{"code": "invalid_user"})
		return
	}
	if !authorizeDirectoryTenant(c, tenantID) {
		return
	}
	if h.members == nil {
		directoryUnavailable(c)
		return
	}
	members, err := h.members.ListApprovalMembers(c.Request.Context(), tenantID)
	if err != nil {
		directoryUnavailable(c)
		return
	}
	active := false
	for _, id := range members {
		if id == userID {
			active = true
			break
		}
	}
	c.JSON(200, gin.H{"tenant_id": tenantID, "user_id": userID, "active_non_guest": active})
}

type directoryResource struct {
	ResourceType string `json:"resource_type" binding:"required"`
	ResourceID   string `json:"resource_id" binding:"required"`
	Permission   string `json:"permission" binding:"required"`
}

var directoryName = regexp.MustCompile(`^[a-z][a-z0-9_]{0,127}$`)

func validDirectoryResource(tenantID uuid.UUID, r directoryResource) bool {
	prefix := tenantID.String() + "/"
	return directoryName.MatchString(r.ResourceType) && directoryName.MatchString(r.Permission) &&
		strings.HasPrefix(r.ResourceID, prefix) && len(r.ResourceID) > len(prefix) && len(r.ResourceID) <= 512 &&
		!strings.ContainsAny(strings.TrimPrefix(r.ResourceID, prefix), "/ \t\r\n")
}

func (h *ApprovalDirectoryHandler) LookupSubjects(c *gin.Context) {
	var req struct {
		TenantID uuid.UUID `json:"tenant_id" binding:"required"`
		directoryResource
		SubjectType        string `json:"subject_type" binding:"required"`
		ActiveNonGuestOnly bool   `json:"active_non_guest_only"`
	}
	if err := c.ShouldBindJSON(&req); err != nil || req.SubjectType != "user" || !validDirectoryResource(req.TenantID, req.directoryResource) {
		c.JSON(400, gin.H{"code": "invalid_lookup_request"})
		return
	}
	if !authorizeDirectoryTenant(c, req.TenantID) {
		return
	}
	if h.permissions == nil || h.members == nil {
		directoryUnavailable(c)
		return
	}
	ids, err := h.permissions.LookupApprovalSubjects(c.Request.Context(), req.ResourceType, req.ResourceID, req.Permission)
	if err != nil {
		directoryUnavailable(c)
		return
	}
	active := map[uuid.UUID]bool{}
	if req.ActiveNonGuestOnly {
		members, err := h.members.ListApprovalMembers(c.Request.Context(), req.TenantID)
		if err != nil {
			directoryUnavailable(c)
			return
		}
		for _, id := range members {
			active[id] = true
		}
	}
	result := make([]string, 0)
	seen := map[string]bool{}
	for _, id := range ids {
		parts := strings.Split(id, "/")
		if len(parts) != 2 || parts[0] != req.TenantID.String() {
			directoryUnavailable(c)
			return
		}
		userID, err := uuid.Parse(parts[1])
		if err != nil || userID == uuid.Nil || parts[1] != userID.String() {
			directoryUnavailable(c)
			return
		}
		if (!req.ActiveNonGuestOnly || active[userID]) && !seen[id] {
			result = append(result, id)
			seen[id] = true
		}
	}
	sort.Strings(result)
	c.JSON(200, gin.H{"tenant_id": req.TenantID, "subject_ids": result, "complete": true, "active_non_guest_only": req.ActiveNonGuestOnly})
}

// BatchCheck uses the same scoped IDs as lookup-subjects; results preserve input
// order. It is suitable for the unified inbox's distinct module permissions.
func (h *ApprovalDirectoryHandler) BatchCheck(c *gin.Context) {
	var req struct {
		TenantID uuid.UUID           `json:"tenant_id" binding:"required"`
		UserID   uuid.UUID           `json:"user_id" binding:"required"`
		Checks   []directoryResource `json:"checks" binding:"required,min=1,max=100,dive"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"code": "invalid_batch_request"})
		return
	}
	if !authorizeDirectoryTenant(c, req.TenantID) {
		return
	}
	checks := make([]*v1.CheckBulkPermissionsRequestItem, len(req.Checks))
	for i, check := range req.Checks {
		if !validDirectoryResource(req.TenantID, check) {
			c.JSON(400, gin.H{"code": "invalid_batch_request"})
			return
		}
		checks[i] = &v1.CheckBulkPermissionsRequestItem{Resource: &v1.ObjectReference{ObjectType: check.ResourceType, ObjectId: check.ResourceID}, Permission: check.Permission}
	}
	if h.permissions == nil || h.members == nil {
		directoryUnavailable(c)
		return
	}
	members, err := h.members.ListApprovalMembers(c.Request.Context(), req.TenantID)
	if err != nil {
		directoryUnavailable(c)
		return
	}
	active := false
	for _, id := range members {
		active = active || id == req.UserID
	}
	allowed := make([]bool, len(checks))
	if active {
		allowed, err = h.permissions.CheckApprovalPermissions(c.Request.Context(), req.TenantID.String(), req.UserID.String(), checks)
		if err != nil || len(allowed) != len(checks) {
			directoryUnavailable(c)
			return
		}
	}
	c.JSON(200, gin.H{"tenant_id": req.TenantID, "user_id": req.UserID, "allowed": allowed, "complete": true})
}
