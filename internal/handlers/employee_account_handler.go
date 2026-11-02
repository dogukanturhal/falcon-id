// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/internal/services"
)

// employeeTemplateKey is the role template every employee-class (ESS) account receives, and ONLY that one.
const employeeTemplateKey = "hr:employee"

// employeeAccountDeps are the collaborators of the employee-account S2S endpoints (R-HR WP-21). They are injected with
// SetEmployeeAccountServices so the established handler constructor stays unchanged.
type employeeAccountDeps struct {
	users       *services.UserService
	provisioner *services.TemplateRoleProvisioner
	invitations *services.InvitationService
	access      *services.EmployeeAccessService
}

// SetEmployeeAccountServices wires ProvisionEmployeeAccount and SetEmployeeAccessExpiry; without it they answer 503.
func (h *TeamInvitationHandler) SetEmployeeAccountServices(users *services.UserService, provisioner *services.TemplateRoleProvisioner, invitations *services.InvitationService, access *services.EmployeeAccessService) {
	h.employeeAccounts = &employeeAccountDeps{users: users, provisioner: provisioner, invitations: invitations, access: access}
}

type provisionEmployeeAccountRequest struct {
	Email     string `json:"email" binding:"required,email"`
	FirstName string `json:"firstName"`
	LastName  string `json:"lastName"`
}

type employeeAccountResponse struct {
	UserID    uuid.UUID `json:"userId"`
	SeatClass string    `json:"seatClass"`
	Created   bool      `json:"created"`
}

// ProvisionEmployeeAccount creates (or finds) the employee-class account of a business employee. POST
// /internal/v1/tenants/:id/employee-accounts, scope iam:employee-accounts:write. The account never consumes a seat, holds
// only the hr:employee template role and gets a password-setup invitation. An existing user is returned unchanged.
func (h *TeamInvitationHandler) ProvisionEmployeeAccount(c *gin.Context) {
	deps := h.employeeAccounts
	if deps == nil || h.userMemberships == nil || h.tenantBootstrap == nil || h.userRepo == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "employee accounts unavailable", "code": "employee_accounts_unavailable"})
		return
	}
	tenantID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid tenant id"})
		return
	}
	var req provisionEmployeeAccountRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}
	ctx := c.Request.Context()
	email := models.CanonicalInvitationEmail(req.Email)

	existing, err := h.userRepo.GetByEmail(ctx, tenantID, email)
	if err != nil {
		h.logger.Error("employee account: lookup failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "lookup failed"})
		return
	}
	if existing != nil {
		seatClass := string(models.SeatClassMember)
		if m, err := h.userMemberships.GetByTenantAndUser(ctx, tenantID, existing.ID); err == nil && m != nil {
			seatClass = string(m.SeatClass)
		}
		c.JSON(http.StatusOK, employeeAccountResponse{UserID: existing.ID, SeatClass: seatClass, Created: false})
		return
	}

	// Role first: a missing template then leaves nothing behind.
	role, err := deps.provisioner.InstantiateForTenant(ctx, tenantID, employeeTemplateKey, "", nil)
	if err != nil || role == nil {
		h.logger.Error("employee account: hr:employee template unavailable", zap.Error(err))
		c.JSON(http.StatusConflict, gin.H{"error": "employee role template unavailable", "code": "hr_template_missing"})
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
	user, err := deps.users.CreateSeatFree(ctx, createReq, nil)
	if err != nil || user == nil {
		h.logger.Error("employee account: user create failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "user create failed"})
		return
	}

	resourceType := "user"
	audit := &models.AuditLog{
		TenantID: tenantID, TargetUserID: &user.ID, Action: "employee_account_provisioned", ResourceType: &resourceType, ResourceID: &user.ID,
		Details: map[string]interface{}{"result": "success", "seat_class": string(models.SeatClassEmployee), "role_template": employeeTemplateKey}, Success: true,
	}
	if err := h.userMemberships.ProvisionEmployeeTx(ctx, tenantID, user.ID, role.ID, audit); err != nil {
		h.logger.Error("employee account: membership/role tx failed; removing user", zap.Error(err))
		if delErr := h.userRepo.Delete(ctx, user.ID); delErr != nil {
			h.logger.Error("employee account: compensation delete failed", zap.Error(delErr))
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "provisioning failed"})
		return
	}
	if err := h.tenantBootstrap.SyncUserAccess(ctx, tenantID, user.ID, true, false, []uuid.UUID{role.ID}); err != nil {
		h.logger.Error("employee account: authorization sync failed", zap.Error(err))
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "authorization sync failed", "code": "authz_sync_failed"})
		return
	}
	h.sendEmployeeSetupInvitation(ctx, deps, tenantID, user.ID, user.Email)

	c.JSON(http.StatusCreated, employeeAccountResponse{UserID: user.ID, SeatClass: string(models.SeatClassEmployee), Created: true})
}

// sendEmployeeSetupInvitation issues the password-setup email; a failure is logged only (the account exists and the
// business side can retry through the password-reset flow).
func (h *TeamInvitationHandler) sendEmployeeSetupInvitation(ctx context.Context, deps *employeeAccountDeps, tenantID, userID uuid.UUID, email string) {
	if deps.invitations == nil {
		return
	}
	_, _, err := deps.invitations.CreateInvitation(ctx, &models.CreateInvitationRequest{
		UserID: userID, TenantID: tenantID, InvitationType: models.InvitationTypePasswordSetup, Email: email, SendEmail: true,
	})
	if err != nil {
		h.logger.Warn("employee account: setup invitation failed", zap.Error(err))
	}
}

type employeeAccessExpiryRequest struct {
	ExpiresAt *time.Time `json:"expiresAt"`
}

// SetEmployeeAccessExpiry sets or clears the access expiry of an employee-class seat. PUT
// /internal/v1/tenants/:id/employee-accounts/:userId/access-expiry. An expiry at or before now switches the account off now.
func (h *TeamInvitationHandler) SetEmployeeAccessExpiry(c *gin.Context) {
	deps := h.employeeAccounts
	if deps == nil || deps.access == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "employee accounts unavailable", "code": "employee_accounts_unavailable"})
		return
	}
	tenantID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid tenant id"})
		return
	}
	userID, err := uuid.Parse(c.Param("userId"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid user id"})
		return
	}
	var req employeeAccessExpiryRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}
	switch err := deps.access.SetExpiry(c.Request.Context(), tenantID, userID, req.ExpiresAt); {
	case err == nil:
		c.Status(http.StatusNoContent)
	case errors.Is(err, services.ErrEmployeeMembershipNotFound):
		c.JSON(http.StatusNotFound, gin.H{"error": "employee account not found"})
	case errors.Is(err, services.ErrNotEmployeeSeat):
		c.JSON(http.StatusConflict, gin.H{"error": "membership is not an employee seat", "code": "not_employee_seat"})
	default:
		h.logger.Error("employee account: set expiry failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "set expiry failed"})
	}
}
