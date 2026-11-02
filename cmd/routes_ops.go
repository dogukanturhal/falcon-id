// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"github.com/gin-gonic/gin"

	"github.com/dogukanturhal/falcon-id/internal/opsconsole"
)

// ServiceClient scopes of the console BFF (svc-hexxlock-control) per area.
const (
	scopeOpsUsers     = "platform:ops-users"
	scopeOpsStaff     = "platform:ops-staff"
	scopeOpsAudit     = "platform:ops-audit"
	scopeOpsApprovals = "platform:ops-approvals"
	// scopeOpsApprovalsConsume lets a target service spend an approval.
	scopeOpsApprovalsConsume = "platform:ops-approvals-consume"
)

// registerOpsConsoleRoutes mounts the staff-console "people" surface on the
// OPERATOR chain: ServiceAuth + RequireScope + operatorauth.RequireOperator
// (+ RequireStepUp for T2/T3). The legacy /internal/v1/{jit-elevations,
// break-glass,platform-roles} routes (RequireActorAuth with the operator's
// legacy access token) are untouched; the /ops twins below take the operator
// assertion instead. Absent when the operator exchange is not configured.
func registerOpsConsoleRoutes(internalV1 *gin.RouterGroup, handlers *Handlers, serviceAuth gin.HandlerFunc) {
	cs := handlers.Ops
	if cs == nil {
		return
	}
	cs.ServiceAuth = serviceAuth

	read := func(scope, perm string, h ...gin.HandlerFunc) []gin.HandlerFunc {
		return cs.Chain(opsconsole.Spec{Scope: scope, Perm: perm}, h...)
	}
	// write: T1 (reason + audit, no step-up); t2: adds step-up.
	write := func(sp opsconsole.Spec, h ...gin.HandlerFunc) []gin.HandlerFunc {
		return cs.Chain(sp, h...)
	}
	t2 := func(scope, perm, action string, res func(*gin.Context) (string, string)) opsconsole.Spec {
		return opsconsole.Spec{Scope: scope, Perm: perm, StepUp: true, Action: action, Resource: res}
	}
	userRes := opsconsole.ParamResource("user", "id")

	ops := internalV1.Group("/ops")

	// ---- users (platform:ops-users) -----------------------------------
	ops.GET("/users", read(scopeOpsUsers, "ops:users:read", cs.SearchUsers)...)
	ops.GET("/users/:id", read(scopeOpsUsers, "ops:users:read", cs.GetUser)...)
	ops.GET("/users/:id/sessions", read(scopeOpsUsers, "ops:users:read", opsconsole.SessionsList(handlers.Admin.ListAllSessions))...)
	ops.POST("/users/:id/sessions/:session_id/revoke", write(t2(scopeOpsUsers, "ops:users:write", "user.session.revoke", userRes),
		cs.ScopeUserTenant, cs.RevokeSession(handlers.Admin.RevokeSession))...)
	ops.POST("/users/:id/sessions/revoke-all", write(t2(scopeOpsUsers, "ops:users:write", "user.sessions.revoke_all", userRes),
		cs.ScopeUserTenant, handlers.Admin.RevokeUserSessions)...)
	ops.GET("/users/:id/mfa", read(scopeOpsUsers, "ops:users:read", handlers.Admin.GetUserMFAStatus)...)
	ops.POST("/users/:id/mfa/reset", write(t2(scopeOpsUsers, "ops:users:write", "user.mfa.reset", userRes),
		cs.ScopeUserTenant, opsconsole.MFAReset(handlers.Admin.SetUserMFA))...)
	ops.GET("/users/:id/devices", read(scopeOpsUsers, "ops:users:read", handlers.Admin.GetUserDevices)...)
	ops.POST("/users/:id/devices/:device_id/untrust", write(t2(scopeOpsUsers, "ops:users:write", "user.device.untrust", userRes),
		cs.ScopeUserTenant, handlers.Admin.AdminUntrustUserDevice)...)
	ops.POST("/users/:id/devices/:device_id/delete", write(t2(scopeOpsUsers, "ops:users:write", "user.device.delete", userRes),
		cs.ScopeUserTenant, handlers.Admin.AdminDeleteUserDevice)...)
	ops.POST("/users/:id/unlock", write(t2(scopeOpsUsers, "ops:users:write", "user.unlock", userRes),
		cs.Unlock(handlers.PlatformManagement.UnlockUser))...)
	ops.POST("/users/:id/impersonations", write(t2(scopeOpsUsers, "ops:users:write", "user.impersonation.start", userRes),
		cs.ScopeUserTenant, handlers.Impersonation.StartImpersonation)...)
	ops.GET("/impersonations", read(scopeOpsUsers, "ops:users:read", opsconsole.ImpersonationList(handlers.Impersonation.ListImpersonationSessions))...)
	ops.POST("/impersonations/:id/end", write(t2(scopeOpsUsers, "ops:users:write", "user.impersonation.end", opsconsole.ParamResource("impersonation", "id")),
		opsconsole.ImpersonationEnd(handlers.Impersonation.EndImpersonationByAdmin, handlers.Impersonation.SessionTenantID))...)
	ops.GET("/users/:id/elevations", read(scopeOpsUsers, "ops:users:read", cs.UserElevations)...)
	ops.POST("/pii-reveals", write(t2(scopeOpsUsers, "ops:pii:reveal", "pii.reveal", nil), cs.RevealPII)...)

	// ---- staff, JIT, platform roles (platform:ops-staff) --------------
	ops.GET("/staff", read(scopeOpsStaff, "ops:users:read", cs.ListStaff)...)
	ops.POST("/staff/:user_id/offboard", write(opsconsole.Spec{Scope: scopeOpsStaff, Perm: "ops:staff:manage", StepUp: true, Action: "staff.offboard",
		Resource: opsconsole.ParamResource("user", "user_id")}, cs.OffboardStaff)...)

	jit := handlers.PlatformJIT
	ops.GET("/platform-roles", read(scopeOpsStaff, "ops:users:read", jit.ListStandingRoles)...)
	ops.POST("/platform-roles", write(t2(scopeOpsStaff, "ops:staff:manage", "platform_role.grant", nil), jit.GrantStandingRole)...)
	ops.POST("/platform-roles/:user_id/revoke", write(t2(scopeOpsStaff, "ops:staff:manage", "platform_role.revoke", opsconsole.ParamResource("user", "user_id")), cs.RevokeStandingRole)...)

	elev := opsconsole.ParamResource("jit_elevation", "id")
	ops.GET("/jit-elevations", read(scopeOpsStaff, "ops:users:read", jit.ListElevations)...)
	ops.POST("/jit-elevations", write(opsconsole.Spec{Scope: scopeOpsStaff, Perm: "ops:users:read", Action: "jit.request"}, jit.RequestElevation)...)
	ops.GET("/jit-elevations/:id/transitions", read(scopeOpsStaff, "ops:users:read", jit.ListTransitions)...)
	ops.POST("/jit-elevations/:id/activate", write(opsconsole.Spec{Scope: scopeOpsStaff, Perm: "ops:users:read", Action: "jit.activate", Resource: elev}, jit.ActivateElevation)...)
	ops.POST("/jit-elevations/:id/approve", write(t2(scopeOpsStaff, "ops:staff:manage", "jit.approve", elev), jit.ApproveElevation)...)
	ops.POST("/jit-elevations/:id/revoke", write(t2(scopeOpsStaff, "ops:staff:manage", "jit.revoke", elev), jit.RevokeElevation)...)
	ops.GET("/break-glass", read(scopeOpsStaff, "ops:users:read", jit.ListBreakGlass)...)
	ops.POST("/break-glass", write(t2(scopeOpsStaff, "ops:users:read", "jit.break_glass.request", nil), jit.RequestBreakGlass)...)
	ops.POST("/break-glass/:id/retroactive-approve", write(t2(scopeOpsStaff, "ops:staff:manage", "jit.break_glass.retroactive_approve", elev), jit.RetroactivelyApprove)...)

	// ---- audit (platform:ops-audit) -----------------------------------
	ops.GET("/audit", read(scopeOpsAudit, "ops:audit:read", cs.ListAudit)...)
	ops.GET("/audit/integrity", read(scopeOpsAudit, "ops:audit:read", cs.AuditIntegrity)...)
	ops.POST("/audit/exports", write(opsconsole.Spec{Scope: scopeOpsAudit, Perm: "ops:audit:export", StepUp: true, Action: "audit.export"}, cs.CreateExport)...)
	ops.GET("/audit/exports/:id", read(scopeOpsAudit, "ops:audit:export", cs.GetExport)...)
	ops.GET("/audit/exports/:id/download", write(opsconsole.Spec{Scope: scopeOpsAudit, Perm: "ops:audit:export", Action: "audit.export.download", NoReason: true}, cs.DownloadExport)...)

	// ---- four-eyes approvals (platform:ops-approvals) -----------------
	appr := internalV1.Group("/ops-approvals")
	apprRes := opsconsole.ParamResource("approval", "id")
	appr.POST("", write(opsconsole.Spec{Scope: scopeOpsApprovals, Perm: "ops:users:read", StepUp: true, Action: "approval.create"}, cs.CreateApproval)...)
	appr.GET("", read(scopeOpsApprovals, "ops:users:read", cs.ListApprovals)...)
	appr.GET("/:id", read(scopeOpsApprovals, "ops:users:read", cs.GetApproval)...)
	appr.POST("/:id/approve", write(opsconsole.Spec{Scope: scopeOpsApprovals, Perm: "ops:users:read", StepUp: true, Action: "approval.approve", NoReason: true, Resource: apprRes}, cs.DecideApproval(true))...)
	appr.POST("/:id/reject", write(opsconsole.Spec{Scope: scopeOpsApprovals, Perm: "ops:users:read", StepUp: true, Action: "approval.reject", NoReason: true, Resource: apprRes}, cs.DecideApproval(false))...)
	appr.POST("/:id/cancel", write(opsconsole.Spec{Scope: scopeOpsApprovals, Perm: "ops:users:read", Action: "approval.cancel", NoReason: true, Resource: apprRes}, cs.CancelApproval)...)
	appr.POST("/:id/consume", cs.ServiceChain(scopeOpsApprovalsConsume, cs.ConsumeApproval)...)
}
