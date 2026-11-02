// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"errors"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/internal/services"
)

// kioskTemplateKey is the role template every kiosk-class (shop-floor Operatör) account receives, and ONLY that one.
const kioskTemplateKey = "ppscm:operator"

type provisionKioskUserRequest struct {
	Email     string `json:"email" binding:"required,email"`
	FirstName string `json:"firstName"`
	LastName  string `json:"lastName"`
}

type kioskUserResponse struct {
	UserID    uuid.UUID `json:"userId"`
	SeatClass string    `json:"seatClass"`
}

// ProvisionKioskUser creates a kiosk-class user for the caller's tenant (R6 WP-23 / D16). POST /api/v1/tenants/me/kiosk-users.
// The account never consumes a paid seat and holds only the ppscm:operator template role; it is counted against the
// quota-service kiosk_users quota (full quota answers 403). It shares the employee-account collaborators.
func (h *TeamInvitationHandler) ProvisionKioskUser(c *gin.Context) {
	deps := h.employeeAccounts
	if deps == nil || h.userMemberships == nil || h.tenantBootstrap == nil || h.userRepo == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "kiosk users unavailable", "code": "kiosk_users_unavailable"})
		return
	}
	currentUser := requireTeamPermission(c, "iam:users:create")
	if currentUser == nil {
		return
	}
	var req provisionKioskUserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}
	ctx := c.Request.Context()
	tenantID := currentUser.TenantID
	email := models.CanonicalInvitationEmail(req.Email)

	existing, err := h.userRepo.GetByEmail(ctx, tenantID, email)
	if err != nil {
		h.logger.Error("kiosk user: lookup failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "lookup failed"})
		return
	}
	if existing != nil {
		c.JSON(http.StatusConflict, gin.H{"error": "a user with this email already exists", "code": "user_exists"})
		return
	}

	if err := deps.users.CheckKioskQuota(ctx, tenantID); err != nil {
		var exceeded *services.KioskQuotaExceededError
		if errors.As(err, &exceeded) {
			c.JSON(http.StatusForbidden, gin.H{
				"error":         "Quota exceeded",
				"code":          "quota_exceeded",
				"resource_type": string(services.ResourceTypeKioskUsers),
				"current_usage": exceeded.CurrentUsage,
				"limit":         exceeded.Limit,
				"message":       exceeded.Message,
			})
			return
		}
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "quota check unavailable", "code": "quota_check_failed"})
		return
	}

	// Role first: a missing template then leaves nothing behind.
	role, err := deps.provisioner.InstantiateForTenant(ctx, tenantID, kioskTemplateKey, "", &currentUser.ID)
	if err != nil || role == nil {
		h.logger.Error("kiosk user: ppscm:operator template unavailable", zap.Error(err))
		c.JSON(http.StatusConflict, gin.H{"error": "operator role template unavailable", "code": "ppscm_template_missing"})
		return
	}

	first, last := strings.TrimSpace(req.FirstName), strings.TrimSpace(req.LastName)
	createReq := &models.CreateUserRequest{TenantID: tenantID, Username: email, Email: email}
	if first != "" {
		createReq.FirstName = &first
	}
	if last != "" {
		createReq.LastName = &last
	}
	user, err := deps.users.CreateSeatFree(ctx, createReq, &currentUser.ID)
	if err != nil || user == nil {
		h.logger.Error("kiosk user: user create failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "user create failed"})
		return
	}

	resourceType := "user"
	audit := &models.AuditLog{
		TenantID: tenantID, UserID: &currentUser.ID, TargetUserID: &user.ID, Action: "kiosk_user_provisioned", ResourceType: &resourceType, ResourceID: &user.ID,
		Details: map[string]interface{}{"result": "success", "seat_class": string(models.SeatClassKiosk), "role_template": kioskTemplateKey}, Success: true,
	}
	if err := h.userMemberships.ProvisionKioskTx(ctx, tenantID, user.ID, role.ID, audit); err != nil {
		h.logger.Error("kiosk user: membership/role tx failed; removing user", zap.Error(err))
		if delErr := h.userRepo.Delete(ctx, user.ID); delErr != nil {
			h.logger.Error("kiosk user: compensation delete failed", zap.Error(delErr))
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "provisioning failed"})
		return
	}
	if err := h.tenantBootstrap.SyncUserAccess(ctx, tenantID, user.ID, true, false, []uuid.UUID{role.ID}); err != nil {
		h.logger.Error("kiosk user: authorization sync failed", zap.Error(err))
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "authorization sync failed", "code": "authz_sync_failed"})
		return
	}
	deps.users.RecordKioskUsage(ctx, tenantID, 1)
	h.sendEmployeeSetupInvitation(ctx, deps, tenantID, user.ID, user.Email)
	c.JSON(http.StatusCreated, kioskUserResponse{UserID: user.ID, SeatClass: string(models.SeatClassKiosk)})
}

// RevokeKioskUser switches a kiosk user off and frees its kiosk_users quota slot. DELETE /api/v1/tenants/me/kiosk-users/:id.
// Only active kiosk-class accounts qualify; a seat-holding member answers 404 and is never touched.
func (h *TeamInvitationHandler) RevokeKioskUser(c *gin.Context) {
	deps := h.employeeAccounts
	if deps == nil || h.userMemberships == nil || h.tenantBootstrap == nil || h.userRepo == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "kiosk users unavailable", "code": "kiosk_users_unavailable"})
		return
	}
	currentUser := requireTeamPermission(c, "iam:users:delete")
	if currentUser == nil {
		return
	}
	userID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid user id"})
		return
	}
	ctx := c.Request.Context()
	tenantID := currentUser.TenantID

	m, err := h.userMemberships.GetByTenantAndUser(ctx, tenantID, userID)
	if err != nil {
		h.logger.Error("kiosk user: membership lookup failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "lookup failed"})
		return
	}
	if m == nil || m.SeatClass != models.SeatClassKiosk || m.Status != models.UserMembershipStatusActive {
		c.JSON(http.StatusNotFound, gin.H{"error": "kiosk user not found"})
		return
	}

	resourceType := "user"
	audit := &models.AuditLog{
		TenantID: tenantID, UserID: &currentUser.ID, TargetUserID: &userID, Action: "kiosk_user_revoked", ResourceType: &resourceType, ResourceID: &userID,
		Details: map[string]interface{}{"result": "success", "seat_class": string(models.SeatClassKiosk)}, Success: true,
	}
	if err := h.userRepo.DeactivateEmployeeUser(ctx, tenantID, userID, audit); err != nil {
		h.logger.Error("kiosk user: deactivate failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "revoke failed"})
		return
	}
	if err := h.userRepo.RevokeTenantRoles(ctx, userID, tenantID); err != nil {
		h.logger.Error("kiosk user: role revoke failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "revoke failed"})
		return
	}
	if err := h.tenantBootstrap.SyncUserAccess(ctx, tenantID, userID, false, false, nil); err != nil {
		h.logger.Error("kiosk user: authorization revocation failed", zap.Error(err))
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "authorization sync failed", "code": "authz_sync_failed"})
		return
	}
	changed, err := h.userMemberships.DeactivateKiosk(ctx, tenantID, userID)
	if err != nil {
		h.logger.Error("kiosk user: membership close failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "revoke failed"})
		return
	}
	if changed {
		deps.users.RecordKioskUsage(ctx, tenantID, -1)
	}
	c.Status(http.StatusNoContent)
}
