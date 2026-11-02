// SPDX-License-Identifier: AGPL-3.0-or-later

package opsconsole

import (
	"net/http"
	"sort"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/dogukanturhal/platform-shared/operatorauth"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

const staffElevationScan = 500

// ListStaff: GET /ops/staff. Standing roles plus active elevations per user.
func (cs *Console) ListStaff(c *gin.Context) {
	ctx := c.Request.Context()
	actor := actorOf(c)

	type entry struct {
		standing []string
		elevs    []gin.H
	}
	byUser := map[uuid.UUID]*entry{}
	get := func(id uuid.UUID) *entry {
		e := byUser[id]
		if e == nil {
			e = &entry{standing: []string{}, elevs: []gin.H{}}
			byUser[id] = e
		}
		return e
	}

	roles, err := cs.JITRepo.ListPlatformRoles(ctx)
	if err != nil {
		cs.internalErr(c, "list platform roles", err)
		return
	}
	for _, r := range roles {
		e := get(r.UserID)
		e.standing = append(e.standing, string(r.RoleKey))
	}
	active := models.PlatformElevationActive
	page, err := cs.JITRepo.ListElevations(ctx, models.ElevationListFilter{Status: &active}, staffElevationScan, 0)
	if err != nil {
		cs.internalErr(c, "list active elevations", err)
		return
	}
	for _, el := range page.Items {
		e := get(el.RequesterID)
		e.elevs = append(e.elevs, gin.H{"id": el.ID, "role_key": el.RoleKey, "expires_at": el.ExpiresAt, "is_break_glass": el.IsBreakGlass})
	}

	items := make([]gin.H, 0, len(byUser))
	for id, e := range byUser {
		item := gin.H{
			"user_id": id, "standing_roles": e.standing, "active_elevations": e.elevs,
			"is_self": id == actor.UserID, "email_masked": "", "display_name_masked": "", "last_login_at": nil,
		}
		if u, uErr := cs.Users.GetByID(ctx, id); uErr == nil && u != nil {
			item["email_masked"] = MaskEmail(u.Email)
			item["display_name_masked"] = MaskName(displayName(u))
			item["last_login_at"] = u.LastLoginAt
		}
		items = append(items, item)
	}
	sort.Slice(items, func(i, j int) bool {
		return items[i]["user_id"].(uuid.UUID).String() < items[j]["user_id"].(uuid.UUID).String()
	})
	c.JSON(http.StatusOK, gin.H{"items": items})
}

// RevokeStandingRole: POST /ops/platform-roles/:user_id/revoke (viewer only).
func (cs *Console) RevokeStandingRole(c *gin.Context) {
	ctx := c.Request.Context()
	uid, err := uuid.Parse(c.Param("user_id"))
	if err != nil {
		fail(c, http.StatusBadRequest, "invalid_user_id")
		return
	}
	if uid == actorOf(c).UserID {
		fail(c, http.StatusBadRequest, "cannot_revoke_self")
		return
	}
	if err := cs.dropStandingRole(c, uid, models.PlatformRoleViewer); err != nil {
		cs.internalErr(c, "revoke standing role", err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "revoked", "user_id": uid, "role_key": models.PlatformRoleViewer})
	_ = ctx
}

// dropStandingRole removes the relation first (fail closed), then the row.
func (cs *Console) dropStandingRole(c *gin.Context, uid uuid.UUID, role models.PlatformRoleKey) error {
	ctx := c.Request.Context()
	if _, err := cs.Spice.DeletePlatformElevation(ctx, uid, string(role)); err != nil {
		return err
	}
	SetAudit(c, "user:"+uid.String(), "")
	cs.live.forget(uid)
	return cs.JITRepo.DeletePlatformRole(ctx, uid, role)
}

// OffboardStaff: POST /ops/staff/:user_id/offboard. T3: step-up (chain) plus a
// consumed four-eyes approval.
func (cs *Console) OffboardStaff(c *gin.Context) {
	ctx := c.Request.Context()
	actor := actorOf(c)
	uid, err := uuid.Parse(c.Param("user_id"))
	if err != nil {
		fail(c, http.StatusBadRequest, "invalid_user_id")
		return
	}
	if uid == actor.UserID {
		fail(c, http.StatusBadRequest, "cannot_offboard_self")
		return
	}
	// The standing platform_admin offboards directly (no second approver);
	// everyone else needs a consumed four-eyes approval.
	standing := operatorauth.IsStandingPlatformAdmin(c)
	var aid uuid.UUID
	if !standing {
		var req struct {
			ApprovalID string `json:"approval_id"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			fail(c, http.StatusBadRequest, "invalid_body")
			return
		}
		aid, err = uuid.Parse(req.ApprovalID)
		if err != nil {
			fail(c, http.StatusForbidden, "approval_required")
			return
		}
	}
	u, err := cs.Users.GetByID(ctx, uid)
	if err != nil {
		cs.internalErr(c, "offboard lookup", err)
		return
	}
	if u == nil || u.TenantID.String() != models.HexxlockInternalTenantID {
		fail(c, http.StatusNotFound, "not_found")
		return
	}
	if cs.Authority != nil && cs.Authority.IsBreakGlassAccount(u.Email) {
		fail(c, http.StatusConflict, "break_glass_account")
		return
	}
	SetAudit(c, "user:"+uid.String(), u.TenantID.String())
	defer cs.live.forget(uid)

	resource := "user:" + uid.String()
	approvalMode := operatorauth.ApprovalModePlatformAdminBypass
	if !standing {
		if _, err := cs.ConsumeLocal(ctx, actor.UserID, aid, "staff.offboard", resource, PayloadHash("staff.offboard:"+uid.String())); err != nil {
			fail(c, http.StatusForbidden, "approval_required")
			return
		}
		c.Set(ctxAuditApproval, aid.String())
		approvalMode = operatorauth.ApprovalModeFourEyes
	}

	rolesRevoked, elevsRevoked := 0, 0
	// 1. Elevations: active ones through the service (SpiceDB + status +
	//    projection), pending/approved ones are denied.
	open, err := cs.JITRepo.ListOpenForRequester(ctx, uid)
	if err != nil {
		cs.internalErr(c, "offboard list elevations", err)
		return
	}
	for _, el := range open {
		switch el.Status {
		case models.PlatformElevationActive:
			if rErr := cs.JIT.RevokeElevation(ctx, el.ID, actor.UserID); rErr != nil {
				cs.internalErr(c, "offboard revoke elevation", rErr)
				return
			}
			elevsRevoked++
		default:
			if uErr := cs.JITRepo.UpdateElevationStatus(ctx, el.ID, el.Status, models.PlatformElevationDenied, ""); uErr != nil {
				cs.Log.Warn("offboard: deny open elevation failed", zap.String("elevation_id", el.ID.String()), zap.Error(uErr))
			} else {
				elevsRevoked++
			}
		}
	}
	// 2. Every remaining iam_platform_roles row (standing viewer, or an
	//    elevated projection the revoke above did not clear).
	all, err := cs.JITRepo.ListPlatformRoles(ctx)
	if err != nil {
		cs.internalErr(c, "offboard list roles", err)
		return
	}
	for _, r := range all {
		if r.UserID != uid {
			continue
		}
		if dErr := cs.dropStandingRole(c, uid, r.RoleKey); dErr != nil {
			cs.internalErr(c, "offboard drop role", dErr)
			return
		}
		rolesRevoked++
	}
	// 3. Sessions and tokens.
	if cs.KillSessions != nil {
		if kErr := cs.KillSessions(ctx, uid, "staff offboarded"); kErr != nil {
			cs.internalErr(c, "offboard kill sessions", kErr)
			return
		}
	}
	SetAudit(c, resource, u.TenantID.String())
	c.Set(ctxAuditDetails, map[string]interface{}{"roles_revoked": rolesRevoked, "elevations_revoked": elevsRevoked, "approval_mode": approvalMode, "at": time.Now().UTC()})
	c.JSON(http.StatusOK, gin.H{"user_id": uid, "roles_revoked": rolesRevoked, "elevations_revoked": elevsRevoked, "sessions_revoked": true})
}
