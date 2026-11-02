// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/middleware"
	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/internal/services"
)

// PlatformJITHandler exposes /internal/v1/jit-elevations and
// /internal/v1/break-glass. Every handler here derives requester/approver
// identity EXCLUSIVELY from middleware.GetActorUserID(c) - the human
// operator's own validated JWT, set by middleware.RequireActorAuth() -
// never from a request-body field. This is deliberate per this rollout's
// "tenant/user from the validated JWT only" rule: these routes sit behind
// ServiceAuth()+RequireScope() (the acmeweb BFF's own S2S credential) AND
// RequireActorAuth()+RequirePlatformInternalActor() (the operator's own
// session token, forwarded in X-Actor-Assertion) - see
// internal/middleware/actor_auth.go's doc comment for the full rationale.
type PlatformJITHandler struct {
	svc    *services.PlatformJITService
	logger *zap.Logger
}

// NewPlatformJITHandler creates a new PlatformJITHandler.
func NewPlatformJITHandler(svc *services.PlatformJITService, logger *zap.Logger) *PlatformJITHandler {
	return &PlatformJITHandler{svc: svc, logger: logger}
}

func platformJITErrorStatus(err error) (int, string) {
	switch {
	case errors.Is(err, services.ErrPlatformRoleNotStandingAssignable):
		return http.StatusForbidden, "platform_role_not_standing_assignable"
	case errors.Is(err, services.ErrNotPlatformInternalUser):
		return http.StatusForbidden, "platform_role_requires_internal_tenant"
	case errors.Is(err, services.ErrSelfApprovalNotAllowed):
		return http.StatusForbidden, "self_approval_not_allowed"
	case errors.Is(err, services.ErrElevationNotPending):
		return http.StatusConflict, "elevation_not_in_expected_state"
	case errors.Is(err, services.ErrInvalidRoleKey):
		return http.StatusBadRequest, "invalid_role_key"
	case errors.Is(err, services.ErrDurationExceedsCap):
		return http.StatusBadRequest, "duration_exceeds_cap"
	default:
		return http.StatusInternalServerError, "internal_error"
	}
}

// RequestElevation handles POST /internal/v1/jit-elevations.
func (h *PlatformJITHandler) RequestElevation(c *gin.Context) {
	actorID := middleware.GetActorUserID(c)
	if actorID == uuid.Nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "actor_identity_required"})
		return
	}

	var req models.RequestPlatformElevationRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	e, err := h.svc.RequestElevation(c.Request.Context(), actorID, req.RoleKey, req.TenantScope, req.Reason, time.Duration(req.DurationSeconds)*time.Second)
	if err != nil {
		status, code := platformJITErrorStatus(err)
		if status == http.StatusInternalServerError {
			h.logger.Error("PlatformJITHandler.RequestElevation failed", zap.Error(err), zap.String("actor_id", actorID.String()))
		}
		c.JSON(status, gin.H{"error": code})
		return
	}
	c.JSON(http.StatusCreated, e)
}

// ApproveElevation handles POST /internal/v1/jit-elevations/:id/approve.
func (h *PlatformJITHandler) ApproveElevation(c *gin.Context) {
	actorID := middleware.GetActorUserID(c)
	if actorID == uuid.Nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "actor_identity_required"})
		return
	}
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid elevation id"})
		return
	}

	e, err := h.svc.ApproveElevation(c.Request.Context(), id, actorID)
	if err != nil {
		status, code := platformJITErrorStatus(err)
		if status == http.StatusInternalServerError {
			h.logger.Error("PlatformJITHandler.ApproveElevation failed", zap.Error(err))
		}
		c.JSON(status, gin.H{"error": code})
		return
	}
	c.JSON(http.StatusOK, e)
}

// ActivateElevation handles POST /internal/v1/jit-elevations/:id/activate.
func (h *PlatformJITHandler) ActivateElevation(c *gin.Context) {
	if middleware.GetActorUserID(c) == uuid.Nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "actor_identity_required"})
		return
	}
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid elevation id"})
		return
	}

	e, err := h.svc.ActivateElevation(c.Request.Context(), id)
	if err != nil {
		status, code := platformJITErrorStatus(err)
		if status == http.StatusInternalServerError {
			h.logger.Error("PlatformJITHandler.ActivateElevation failed", zap.Error(err))
		}
		c.JSON(status, gin.H{"error": code})
		return
	}
	c.JSON(http.StatusOK, e)
}

// RevokeElevation handles POST /internal/v1/jit-elevations/:id/revoke.
func (h *PlatformJITHandler) RevokeElevation(c *gin.Context) {
	actorID := middleware.GetActorUserID(c)
	if actorID == uuid.Nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "actor_identity_required"})
		return
	}
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid elevation id"})
		return
	}

	if err := h.svc.RevokeElevation(c.Request.Context(), id, actorID); err != nil {
		status, code := platformJITErrorStatus(err)
		if status == http.StatusInternalServerError {
			h.logger.Error("PlatformJITHandler.RevokeElevation failed", zap.Error(err))
		}
		c.JSON(status, gin.H{"error": code})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "revoked"})
}

// RequestBreakGlass handles POST /internal/v1/break-glass.
func (h *PlatformJITHandler) RequestBreakGlass(c *gin.Context) {
	actorID := middleware.GetActorUserID(c)
	if actorID == uuid.Nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "actor_identity_required"})
		return
	}

	var req models.RequestBreakGlassRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	e, err := h.svc.RequestBreakGlass(c.Request.Context(), actorID, req.RoleKey, req.TenantScope, req.Reason, time.Duration(req.DurationSeconds)*time.Second)
	if err != nil {
		status, code := platformJITErrorStatus(err)
		if status == http.StatusInternalServerError {
			h.logger.Error("PlatformJITHandler.RequestBreakGlass failed", zap.Error(err), zap.String("actor_id", actorID.String()))
		}
		c.JSON(status, gin.H{"error": code})
		return
	}
	c.JSON(http.StatusCreated, e)
}

// RetroactivelyApprove handles
// POST /internal/v1/break-glass/:id/retroactive-approve.
func (h *PlatformJITHandler) RetroactivelyApprove(c *gin.Context) {
	actorID := middleware.GetActorUserID(c)
	if actorID == uuid.Nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "actor_identity_required"})
		return
	}
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid elevation id"})
		return
	}

	e, err := h.svc.RetroactivelyApprove(c.Request.Context(), id, actorID)
	if err != nil {
		status, code := platformJITErrorStatus(err)
		if status == http.StatusInternalServerError {
			h.logger.Error("PlatformJITHandler.RetroactivelyApprove failed", zap.Error(err))
		}
		c.JSON(status, gin.H{"error": code})
		return
	}
	c.JSON(http.StatusOK, e)
}

// GrantStandingRole handles POST /internal/v1/platform-roles. Only
// platform_viewer is standing-assignable directly - see
// services.PlatformJITService.GrantStandingRole's doc comment.
func (h *PlatformJITHandler) GrantStandingRole(c *gin.Context) {
	actorID := middleware.GetActorUserID(c)
	if actorID == uuid.Nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "actor_identity_required"})
		return
	}

	var req struct {
		UserID  uuid.UUID `json:"user_id" binding:"required"`
		RoleKey string    `json:"role_key" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	role, err := h.svc.GrantStandingRole(c.Request.Context(), actorID, req.UserID, req.RoleKey)
	if err != nil {
		status, code := platformJITErrorStatus(err)
		if status == http.StatusInternalServerError {
			h.logger.Error("PlatformJITHandler.GrantStandingRole failed", zap.Error(err))
		}
		c.JSON(status, gin.H{"error": code})
		return
	}
	c.JSON(http.StatusCreated, role)
}

// ListStandingRoles handles GET /internal/v1/platform-roles.
func (h *PlatformJITHandler) ListStandingRoles(c *gin.Context) {
	if middleware.GetActorUserID(c) == uuid.Nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "actor_identity_required"})
		return
	}
	roles, err := h.svc.ListStandingRoles(c.Request.Context())
	if err != nil {
		h.logger.Error("PlatformJITHandler.ListStandingRoles failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal_error"})
		return
	}
	c.JSON(http.StatusOK, roles)
}

// parseElevationListQuery reads the shared status/requester_id/page/
// page_size query params used by ListElevations and ListBreakGlass.
// Returns (filter, page, pageSize, ok) — ok is false and the response
// has already been written when a param fails to parse.
func parseElevationListQuery(c *gin.Context) (models.ElevationListFilter, int, int, bool) {
	var filter models.ElevationListFilter
	if status := c.Query("status"); status != "" {
		s := models.PlatformElevationStatus(status)
		filter.Status = &s
	}
	if requester := c.Query("requester_id"); requester != "" {
		id, err := uuid.Parse(requester)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid requester_id"})
			return filter, 0, 0, false
		}
		filter.RequesterID = &id
	}
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "20"))
	return filter, page, pageSize, true
}

// ListElevations handles GET /internal/v1/jit-elevations. Optional
// filters: status, requester_id. Paginated via page/page_size (see
// services.DefaultElevationPageSize/MaxElevationPageSize). Never
// returns break-glass rows — see GetBreakGlass for those.
func (h *PlatformJITHandler) ListElevations(c *gin.Context) {
	if middleware.GetActorUserID(c) == uuid.Nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "actor_identity_required"})
		return
	}
	filter, page, pageSize, ok := parseElevationListQuery(c)
	if !ok {
		return
	}
	resp, err := h.svc.ListElevations(c.Request.Context(), filter, page, pageSize)
	if err != nil {
		h.logger.Error("PlatformJITHandler.ListElevations failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal_error"})
		return
	}
	c.JSON(http.StatusOK, resp)
}

// ListBreakGlass handles GET /internal/v1/break-glass. Same filters and
// pagination as ListElevations, restricted to is_break_glass = true rows.
func (h *PlatformJITHandler) ListBreakGlass(c *gin.Context) {
	if middleware.GetActorUserID(c) == uuid.Nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "actor_identity_required"})
		return
	}
	filter, page, pageSize, ok := parseElevationListQuery(c)
	if !ok {
		return
	}
	resp, err := h.svc.ListBreakGlass(c.Request.Context(), filter, page, pageSize)
	if err != nil {
		h.logger.Error("PlatformJITHandler.ListBreakGlass failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal_error"})
		return
	}
	c.JSON(http.StatusOK, resp)
}

// ListTransitions handles GET /internal/v1/jit-elevations/:id/transitions
// — a read-only view over the append-only hash-chain audit log for one
// elevation (see migration 0016's iam_jit_elevation_transitions). Never
// writes; the only writer remains
// PlatformJITService.appendTransition/AppendTransition.
func (h *PlatformJITHandler) ListTransitions(c *gin.Context) {
	if middleware.GetActorUserID(c) == uuid.Nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "actor_identity_required"})
		return
	}
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid elevation id"})
		return
	}
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "20"))
	resp, err := h.svc.ListTransitions(c.Request.Context(), id, page, pageSize)
	if err != nil {
		h.logger.Error("PlatformJITHandler.ListTransitions failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal_error"})
		return
	}
	c.JSON(http.StatusOK, resp)
}
