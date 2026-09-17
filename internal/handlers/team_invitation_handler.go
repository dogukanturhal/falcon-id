// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gin-gonic/gin/binding"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/authorization"
	"github.com/dogukanturhal/falcon-id/internal/middleware"
	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/internal/repositories"
	"github.com/dogukanturhal/falcon-id/internal/services"
)

const (
	teamInvitationDefaultExpiry = 7 * 24 * time.Hour
	teamInvitationTokenBytes    = 32
)

// errRoleNotInTenant is returned (never with the offending role ID attached)
// whenever a caller supplies a role_id that does not belong to the tenant in
// scope. Deliberately generic: distinguishing "unknown role" from "role
// belongs to another tenant" in the response would itself be a cross-tenant
// enumeration oracle.
var errRoleNotInTenant = fmt.Errorf("one or more role IDs are invalid for this tenant")

// Reasons surfaced on a non-editable models.RoleRef. Exact strings the
// frontend role picker should render for a locked grant.
const (
	// reasonDifferentTenant: the role belongs to a different tenant_id than
	// the one the caller is currently managing. Kept as defence in depth —
	// no such grant is known to exist today (every role a hexxlock user
	// holds is tenant_id = hexxlock), but a role picker scoped to the
	// caller's tenant could never offer it either way.
	reasonDifferentTenant = "granted under a different tenant"
	// reasonModuleNotEntitled: the role is in the caller's own tenant, but
	// GET /api/v1/roles (RoleService.ListSelfService) excludes it because
	// none of its permissions fall in a module the tenant is entitled to
	// (see RoleService.getEntitledModules / RoleRepository.ListForModules).
	// This is the actual cause of the reported data-loss bug.
	reasonModuleNotEntitled = "not offered by the role picker: this tenant isn't entitled to this role's product module"
	reasonSystemRole        = "system roles are locked"
	reasonPriority          = "not manageable by this actor"
	permInvitationCreate    = "iam:invitations:create"
	permInvitationRead      = "iam:invitations:read"
	permInvitationDelete    = "iam:invitations:delete"
	permUsersRead           = "iam:users:read"
	permUsersUpdate         = "iam:users:update"
	permUsersDelete         = "iam:users:delete"
	teamMaxPage             = 10000
	teamMaxPageSize         = 100
)

func requireTeamPermission(c *gin.Context, permission string) *models.CurrentUser {
	currentUser := middleware.GetCurrentUser(c)
	if currentUser == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return nil
	}
	if !currentUser.HasPermission(permission) {
		c.JSON(http.StatusForbidden, gin.H{"error": "forbidden"})
		return nil
	}
	return currentUser
}

func (h *TeamInvitationHandler) validateManageableRoleIDs(ctx context.Context, tenantID, actorID uuid.UUID, roleIDs []uuid.UUID) error {
	if h.roleService == nil {
		return fmt.Errorf("role catalogue service is unavailable")
	}
	visible, err := h.roleService.ManageableSelfServiceRoleIDs(ctx, tenantID, actorID)
	if err != nil {
		return fmt.Errorf("validate manageable roles: %w", err)
	}
	for _, roleID := range roleIDs {
		if !visible[roleID] {
			return errRoleNotInTenant
		}
	}
	return nil
}

// TeamInvitationHandler handles the Team page invite/RSVP + tenant user CRUD
// endpoints for Phase 2 of the Mearax settings pages.
type TeamInvitationHandler struct {
	tenantRepo        *repositories.TenantRepository
	userRepo          *repositories.UserRepository
	roleRepo          *repositories.RoleRepository
	roleService       *services.RoleService
	invitationRepo    *repositories.TeamInvitationRepository
	serviceAccounts   *repositories.ServiceAccountRepository
	servicePrincipals *repositories.ServicePrincipalRepository
	emailService      *services.EmailService
	tenantBootstrap   *services.TenantBootstrapService
	logger            *zap.Logger
}

// SetMachineRepositories wires the native machine inventory without changing
// the established constructor used by existing callers and tests.
func (h *TeamInvitationHandler) SetMachineRepositories(accounts *repositories.ServiceAccountRepository, principals *repositories.ServicePrincipalRepository) {
	h.serviceAccounts = accounts
	h.servicePrincipals = principals
}

// SetEmailService wires the transactional invitation delivery path.
func (h *TeamInvitationHandler) SetEmailService(email *services.EmailService) { h.emailService = email }

// SetTenantBootstrap wires synchronous PostgreSQL-to-SpiceDB role repair for
// invitation acceptance and Team role replacement.
func (h *TeamInvitationHandler) SetTenantBootstrap(bootstrap *services.TenantBootstrapService) {
	h.tenantBootstrap = bootstrap
}

// NewTeamInvitationHandler creates a TeamInvitationHandler.
func NewTeamInvitationHandler(
	tenantRepo *repositories.TenantRepository,
	userRepo *repositories.UserRepository,
	roleRepo *repositories.RoleRepository,
	roleService *services.RoleService,
	invitationRepo *repositories.TeamInvitationRepository,
	logger *zap.Logger,
) *TeamInvitationHandler {
	return &TeamInvitationHandler{
		tenantRepo:     tenantRepo,
		userRepo:       userRepo,
		roleRepo:       roleRepo,
		roleService:    roleService,
		invitationRepo: invitationRepo,
		logger:         logger,
	}
}

// generateToken returns a cryptographically random 32-byte hex string.
func generateToken() (string, error) {
	b := make([]byte, teamInvitationTokenBytes)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generateToken: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// verifyRolesBelongToTenant re-checks every role ID against iam_roles.tenant_id
// (the platform's sole role/product-scoping mechanism, per RoleRepository.
// GetByIDAndTenant — the same check RoleHandler.GetByID/Update/Delete already
// apply) before it is persisted anywhere a role assignment can take effect.
//
// The Team page's role picker (GET /api/v1/roles) is scoped by this same
// tenant_id, but that only controls what the UI *offers*. Without this check,
// CreateInvitation / AcceptInvitation / SetUserRoles would happily persist any
// role_id a caller supplies — including a cross-tenant or cross-product role
// (e.g. "Platform Admin", "Payment Provider Sync Admin") — regardless of
// whether the UI ever displayed it. That is a privilege-escalation gap, not
// just a display bug: the dialog's own copy calls this "destructive" for a
// reason. Returns a generic error (never echoes back *which* role failed) so
// this can't be used to enumerate cross-tenant role existence.
func (h *TeamInvitationHandler) verifyRolesBelongToTenant(ctx context.Context, tenantID uuid.UUID, roleIDs []uuid.UUID) error {
	for _, roleID := range roleIDs {
		role, err := h.roleRepo.GetByIDAndTenant(ctx, roleID, tenantID)
		if err != nil {
			return fmt.Errorf("verifyRolesBelongToTenant: %w", err)
		}
		if role == nil {
			return errRoleNotInTenant
		}
	}
	return nil
}

// CreateInvitation handles POST /api/v1/invitations.
//
// Creates a new team invitation and publishes an iam.invitation.created event
// to the integration-bus via the outbox so the notification-service can send
// the invite email asynchronously.
//
// @Summary Create team invitation
// @Tags Team
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param request body models.CreateTeamInvitationRequest true "Email + role IDs"
// @Success 201 {object} models.TeamInvitationResponse
// @Failure 400 {object} map[string]string
// @Failure 409 {object} map[string]string "Duplicate pending invitation"
// @Router /api/v1/invitations [post]
func (h *TeamInvitationHandler) CreateInvitation(c *gin.Context) {
	if rejectIfImpersonated(c) {
		return
	}
	currentUser := requireTeamPermission(c, permInvitationCreate)
	if currentUser == nil {
		return
	}

	// Bind before validation so canonicalization is applied exactly once before
	// the established email validator, persistence, and downstream delivery.
	var input struct {
		Email   string      `json:"email"`
		RoleIDs []uuid.UUID `json:"roleIds"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	req := models.CreateTeamInvitationRequest{Email: models.CanonicalInvitationEmail(input.Email), RoleIDs: input.RoleIDs}
	if err := binding.Validator.ValidateStruct(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Tenant boundary: only invite within current tenant.
	tenantID := currentUser.TenantID

	// Tenant boundary on the ROLES too: reject any role_id that isn't one of
	// this tenant's own iam_roles rows before the invitation is ever
	// persisted. See verifyRolesBelongToTenant.
	if len(req.RoleIDs) > 0 {
		if err := h.verifyRolesBelongToTenant(c.Request.Context(), tenantID, req.RoleIDs); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": errRoleNotInTenant.Error()})
			return
		}
		if err := h.validateManageableRoleIDs(c.Request.Context(), tenantID, currentUser.ID, req.RoleIDs); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": errRoleNotInTenant.Error()})
			return
		}
	}

	token, err := generateToken()
	if err != nil {
		h.logger.Error("CreateInvitation: token generation failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate invitation token"})
		return
	}

	inv := &models.TeamInvitation{
		TenantID:  tenantID,
		Email:     req.Email,
		RoleIDs:   req.RoleIDs,
		InvitedBy: currentUser.ID,
		Token:     models.TeamInvitationTokenDigest(token),
		Status:    models.TeamInvitationStatusPending,
		ExpiresAt: time.Now().Add(teamInvitationDefaultExpiry),
	}

	resourceType := "team_invitation"
	audit := &models.AuditLog{TenantID: tenantID, UserID: &currentUser.ID, Action: "team_invitation_create", ResourceType: &resourceType, ResourceID: &inv.ID, Details: map[string]interface{}{"result": "success", "correlation_id": middleware.GetCorrelationID(c)}, Success: true}
	if h.emailService == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "invitation delivery is unavailable"})
		return
	}
	if err := h.invitationRepo.InTransaction(c.Request.Context(), func(tx pgx.Tx) error {
		repo := h.invitationRepo.WithDB(tx)
		if err := repo.ExpirePendingForEmail(c.Request.Context(), tenantID, req.Email); err != nil {
			return err
		}
		if err := repo.Create(c.Request.Context(), inv); err != nil {
			return err
		}
		return repositories.CreateAuditLogTx(c.Request.Context(), tx, audit)
	}); err != nil {
		if errors.Is(err, repositories.ErrDuplicatePendingInvitation) {
			c.JSON(http.StatusConflict, gin.H{"error": "a pending invitation already exists for this email"})
			return
		}
		h.logger.Error("CreateInvitation: failed to persist", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create invitation"})
		return
	}
	if err := h.emailService.SendTeamInvitation(c.Request.Context(), tenantID, req.Email, token); err != nil {
		cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(c.Request.Context()), 5*time.Second)
		defer cancel()
		revoked, revokeErr := h.invitationRepo.TransitionPending(cleanupCtx, inv.ID, models.TeamInvitationStatusRevoked)
		h.logger.Error("CreateInvitation: delivery failed after persistence",
			zap.Error(err), zap.Bool("invitation_revoked", revoked), zap.Error(revokeErr))
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "invitation delivery failed; retry to issue a new invitation"})
		return
	}

	c.JSON(http.StatusCreated, toInvitationResponse(inv))
}

// ListInvitations handles GET /api/v1/invitations?status=pending.
//
// @Summary List team invitations
// @Tags Team
// @Security BearerAuth
// @Produce json
// @Param status query string false "Filter by status (pending, accepted, expired, revoked)"
// @Param page query int false "Page number" default(1)
// @Param page_size query int false "Page size" default(20)
// @Header 200 {integer} X-Total-Count "Total matching invitations"
// @Header 200 {integer} X-Page "Current page"
// @Header 200 {integer} X-Page-Size "Current page size"
// @Success 200 {array} models.TeamInvitationResponse
// @Router /api/v1/invitations [get]
func (h *TeamInvitationHandler) ListInvitations(c *gin.Context) {
	currentUser := requireTeamPermission(c, permInvitationRead)
	if currentUser == nil {
		return
	}

	status := c.Query("status")
	if status != "" && status != string(models.TeamInvitationStatusPending) && status != string(models.TeamInvitationStatusAccepted) && status != string(models.TeamInvitationStatusExpired) && status != string(models.TeamInvitationStatusRevoked) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid invitation status"})
		return
	}
	page, pageSize, ok := teamPagination(c)
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid pagination"})
		return
	}
	invitations, total, err := h.invitationRepo.ListByTenantPage(c.Request.Context(), currentUser.TenantID, status, page, pageSize)
	if err != nil {
		h.logger.Error("ListInvitations: failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list invitations"})
		return
	}

	resp := make([]models.TeamInvitationResponse, 0, len(invitations))
	for _, inv := range invitations {
		resp = append(resp, toInvitationResponse(inv))
	}
	c.Header("X-Total-Count", strconv.FormatInt(total, 10))
	c.Header("X-Page", strconv.Itoa(page))
	c.Header("X-Page-Size", strconv.Itoa(pageSize))
	// Preserve the shipped array response while exposing pagination metadata in
	// headers so existing clients do not break.
	c.JSON(http.StatusOK, resp)
}

// RevokeInvitation handles DELETE /api/v1/invitations/:id.
//
// @Summary Revoke a team invitation
// @Tags Team
// @Security BearerAuth
// @Param id path string true "Invitation ID"
// @Success 204
// @Failure 403 {object} map[string]string "Cross-tenant access"
// @Failure 404 {object} map[string]string
// @Router /api/v1/invitations/{id} [delete]
func (h *TeamInvitationHandler) RevokeInvitation(c *gin.Context) {
	if rejectIfImpersonated(c) {
		return
	}
	currentUser := requireTeamPermission(c, permInvitationDelete)
	if currentUser == nil {
		return
	}

	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid invitation id"})
		return
	}

	var result string
	err = h.invitationRepo.InTransaction(c.Request.Context(), func(tx pgx.Tx) error {
		inv, err := h.invitationRepo.WithDB(tx).GetByIDForUpdate(c.Request.Context(), id)
		if err != nil {
			return err
		}
		if inv == nil {
			result = "not_found"
			return nil
		}
		if inv.TenantID != currentUser.TenantID {
			result = "forbidden"
			return nil
		}
		if inv.Status != models.TeamInvitationStatusPending {
			result = "not_pending"
			return nil
		}
		ok, err := h.invitationRepo.WithDB(tx).TransitionPending(c.Request.Context(), id, models.TeamInvitationStatusRevoked)
		if err != nil || !ok {
			return fmt.Errorf("revoke invitation transition: %w", err)
		}
		resourceType := "team_invitation"
		return repositories.CreateAuditLogTx(c.Request.Context(), tx, &models.AuditLog{TenantID: currentUser.TenantID, UserID: &currentUser.ID, Action: "team_invitation_revoke", ResourceType: &resourceType, ResourceID: &id, Details: map[string]interface{}{"result": "success", "correlation_id": middleware.GetCorrelationID(c)}, Success: true})
	})
	if err != nil {
		h.logger.Error("RevokeInvitation: transaction failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to revoke invitation"})
		return
	}
	if result == "not_found" {
		c.JSON(http.StatusNotFound, gin.H{"error": "invitation not found"})
		return
	}
	if result == "forbidden" {
		c.JSON(http.StatusForbidden, gin.H{"error": "access denied"})
		return
	}
	if result == "not_pending" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invitation is no longer pending"})
		return
	}

	c.Status(http.StatusNoContent)
}

// AcceptInvitation handles POST /api/v1/invitations/accept.
//
// Validates the token, enforces tenant boundary, applies role_ids to the
// authenticated user, and marks the invitation as accepted.
//
// @Summary Accept a team invitation
// @Tags Team
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param request body models.AcceptTeamInvitationRequest true "Invitation token"
// @Success 200 {object} map[string]string
// @Failure 400 {object} map[string]string
// @Failure 403 {object} map[string]string
// @Router /api/v1/invitations/accept [post]
func (h *TeamInvitationHandler) AcceptInvitation(c *gin.Context) {
	if rejectIfImpersonated(c) {
		return
	}
	currentUser := middleware.GetCurrentUser(c)
	if currentUser == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	var req models.AcceptTeamInvitationRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var result string
	if h.roleService == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "role catalogue service is unavailable"})
		return
	}
	if h.tenantBootstrap == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "role authorization is unavailable"})
		return
	}
	modules, err := h.roleService.EntitledModules(c.Request.Context(), currentUser.TenantID)
	if err != nil {
		h.logger.Error("AcceptInvitation: entitlement lookup failed", zap.Error(err))
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "role catalogue is unavailable"})
		return
	}
	err = h.invitationRepo.InTransaction(c.Request.Context(), func(tx pgx.Tx) error {
		inv, err := h.invitationRepo.WithDB(tx).GetByTokenForUpdate(c.Request.Context(), req.Token)
		if err != nil {
			return err
		}
		if inv == nil || !inv.IsValid() {
			result = "invalid"
			return nil
		}
		if currentUser.TenantID != inv.TenantID {
			result = "tenant"
			return nil
		}
		if !teamInvitationMatchesUser(currentUser, inv) {
			result = "identity"
			return nil
		}
		roleRepo := h.roleRepo.WithDB(tx)
		for _, roleID := range inv.RoleIDs {
			role, err := roleRepo.GetByIDAndTenantForShare(c.Request.Context(), roleID, inv.TenantID)
			if err != nil {
				return err
			}
			if role == nil {
				result = "roles"
				return nil
			}
		}
		if err := roleRepo.LockPermissionCatalogue(c.Request.Context()); err != nil {
			return err
		}
		for _, roleID := range inv.RoleIDs {
			allowed, err := roleRepo.HasOnlyPermissionsInModules(c.Request.Context(), roleID, modules)
			if err != nil {
				return err
			}
			if !allowed {
				result = "roles"
				return nil
			}
		}
		if err := h.userRepo.WithDB(tx).GrantRoles(c.Request.Context(), currentUser.ID, inv.RoleIDs, nil); err != nil {
			return err
		}
		ok, err := h.invitationRepo.WithDB(tx).TransitionPending(c.Request.Context(), inv.ID, models.TeamInvitationStatusAccepted)
		if err != nil || !ok {
			return fmt.Errorf("accept invitation transition: %w", err)
		}
		resourceType := "team_invitation"
		return repositories.CreateAuditLogTx(c.Request.Context(), tx, &models.AuditLog{TenantID: inv.TenantID, UserID: &currentUser.ID, TargetUserID: &currentUser.ID, Action: "team_invitation_accept", ResourceType: &resourceType, ResourceID: &inv.ID, Details: map[string]interface{}{"result": "success", "correlation_id": middleware.GetCorrelationID(c)}, Success: true})
	})
	if err != nil {
		h.logger.Error("AcceptInvitation: transaction failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to accept invitation"})
		return
	}
	if result == "invalid" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid or expired token"})
		return
	}
	if result == "tenant" {
		c.JSON(http.StatusForbidden, gin.H{"error": "this invitation belongs to a different tenant"})
		return
	}
	if result == "identity" {
		c.JSON(http.StatusForbidden, gin.H{"error": "this invitation belongs to a different account"})
		return
	}
	if result == "roles" {
		c.JSON(http.StatusBadRequest, gin.H{"error": errRoleNotInTenant.Error()})
		return
	}

	roleErr := h.syncUserRolesFromDatabase(c.Request.Context(), currentUser.TenantID, currentUser.ID)
	if roleErr != nil {
		h.logger.Error("AcceptInvitation: SpiceDB role synchronization failed", zap.Error(roleErr))
		c.JSON(http.StatusAccepted, gin.H{"message": "invitation accepted; role authorization is synchronizing"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "invitation accepted"})
}

func teamInvitationMatchesUser(user *models.CurrentUser, invitation *models.TeamInvitation) bool {
	return user != nil && invitation != nil &&
		user.TenantID == invitation.TenantID &&
		models.CanonicalInvitationEmail(user.Email) == models.CanonicalInvitationEmail(invitation.Email)
}

func tenantRoleIDs(roles []models.Role, tenantID uuid.UUID) []uuid.UUID {
	ids := make([]uuid.UUID, 0, len(roles))
	for _, role := range roles {
		if role.TenantID == tenantID {
			ids = append(ids, role.ID)
		}
	}
	return ids
}

func (h *TeamInvitationHandler) syncUserRolesFromDatabase(ctx context.Context, tenantID, userID uuid.UUID) error {
	for attempt := 0; attempt < 3; attempt++ {
		roles, err := h.userRepo.GetUserRoles(ctx, userID)
		if err != nil {
			return err
		}
		desired := tenantRoleIDs(roles, tenantID)
		if err := h.tenantBootstrap.SyncUserRoles(ctx, tenantID, userID, desired); err != nil {
			return err
		}
		current, err := h.userRepo.GetUserRoles(ctx, userID)
		if err != nil {
			return err
		}
		if sameRoleIDs(desired, tenantRoleIDs(current, tenantID)) {
			return nil
		}
	}
	return errors.New("role assignments changed during authorization synchronization")
}

func sameRoleIDs(left, right []uuid.UUID) bool {
	if len(left) != len(right) {
		return false
	}
	set := make(map[uuid.UUID]struct{}, len(left))
	for _, id := range left {
		set[id] = struct{}{}
	}
	for _, id := range right {
		if _, ok := set[id]; !ok {
			return false
		}
	}
	return true
}

// ListTenantUsers handles GET /api/v1/tenants/me/users.
//
// Returns paginated tenant users with their role assignments.
//
// @Summary List tenant users
// @Tags Team
// @Security BearerAuth
// @Produce json
// @Param page      query int false "Page number (default 1)"
// @Param page_size query int false "Items per page (default 25)"
// @Param search    query string false "Search by username"
// @Success 200 {object} map[string]interface{}
// @Router /api/v1/tenants/me/users [get]
func (h *TeamInvitationHandler) ListTenantUsers(c *gin.Context) {
	currentUser := requireTeamPermission(c, permUsersRead)
	if currentUser == nil {
		return
	}

	page, pageSize, ok := teamPagination(c)
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid pagination"})
		return
	}
	search := c.Query("search")

	users, total, err := h.userRepo.List(c.Request.Context(), currentUser.TenantID, page, pageSize, search)
	if err != nil {
		h.logger.Error("ListTenantUsers: failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list users"})
		return
	}

	// The exact set of role IDs the current actor's self-service picker (GET /api/v1/roles)
	// would offer for this tenant. A role NOT in this set — whether because
	// it belongs to another tenant, or because it's in this tenant but the
	// tenant isn't entitled to its product module — can never be selected
	// or resubmitted by the picker, so it must render as locked, not just
	// omitted. Computed once per page, not per user.
	var catalogueVisible map[uuid.UUID]bool
	var selfServiceVisible map[uuid.UUID]bool
	if h.roleService != nil {
		catalogueVisible, err = h.roleService.SelfServiceVisibleRoleIDs(c.Request.Context(), currentUser.TenantID)
		if err != nil {
			h.logger.Warn("ListTenantUsers: ManageableSelfServiceRoleIDs failed, treating all roles as locked",
				zap.Error(err))
		}
		selfServiceVisible, err = h.roleService.ManageableSelfServiceRoleIDs(c.Request.Context(), currentUser.TenantID, currentUser.ID)
		if err != nil {
			h.logger.Warn("ListTenantUsers: SelfServiceVisibleRoleIDs failed, treating all roles as locked",
				zap.Error(err))
		}
	}

	items := make([]models.TenantUserWithRoles, 0, len(users))
	for _, u := range users {
		// Fetch roles for each user. The call volume is bounded by page_size
		// (max 100 per page) and roles per user is typically small (< 5).
		// A single JOIN query with array_agg is the ideal long-term
		// optimisation; for Phase 2 this N+1 is acceptable.
		roles, err := h.userRepo.GetUserRoles(c.Request.Context(), u.ID)
		if err != nil {
			h.logger.Warn("ListTenantUsers: GetRolesForUser failed, returning empty roles",
				zap.String("user_id", u.ID.String()), zap.Error(err))
		}

		roleRefs := make([]models.RoleRef, 0, len(roles))
		for _, r := range roles {
			switch {
			case r.TenantID != currentUser.TenantID:
				roleRefs = append(roleRefs, models.RoleRef{ID: r.ID, Name: r.Name, Editable: false, Reason: reasonDifferentTenant, Source: models.RoleSourceExternal})
			case r.IsSystem:
				roleRefs = append(roleRefs, models.RoleRef{ID: r.ID, Name: r.Name, Editable: false, Reason: reasonSystemRole, Source: models.RoleSourceSystem})
			case !catalogueVisible[r.ID]:
				roleRefs = append(roleRefs, models.RoleRef{ID: r.ID, Name: r.Name, Editable: false, Reason: reasonModuleNotEntitled, Source: models.RoleSourceTenantCatalogue})
			case !selfServiceVisible[r.ID]:
				roleRefs = append(roleRefs, models.RoleRef{ID: r.ID, Name: r.Name, Editable: false, Reason: reasonPriority, Source: models.RoleSourceTenantCatalogue})
			default:
				roleRefs = append(roleRefs, models.RoleRef{ID: r.ID, Name: r.Name, Editable: true, Source: models.RoleSourceTenantCatalogue})
			}
		}

		displayName := ""
		if u.DisplayName != nil {
			displayName = *u.DisplayName
		}
		items = append(items, models.TenantUserWithRoles{
			ID:              u.ID,
			Email:           u.Email,
			DisplayName:     displayName,
			IsActive:        u.IsActive,
			Roles:           roleRefs,
			CreatedAt:       u.CreatedAt,
			PrincipalType:   "human",
			PrincipalSource: "iam_users",
		})
	}

	c.JSON(http.StatusOK, gin.H{
		"items":    items,
		"total":    total,
		"page":     page,
		"pageSize": pageSize,
	})
}

// ListTenantServiceAccounts returns signed-tenant service-account inventory.
// @Summary List tenant service accounts
// @Tags Team
// @Security BearerAuth
// @Router /api/v1/tenants/me/service-accounts [get]
func (h *TeamInvitationHandler) ListTenantServiceAccounts(c *gin.Context) {
	currentUser := requireTeamPermission(c, "iam:service_accounts:read")
	if currentUser == nil {
		return
	}
	if h.serviceAccounts == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "machine inventory is unavailable"})
		return
	}
	page, pageSize, ok := teamPagination(c)
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid pagination"})
		return
	}
	items, total, err := h.serviceAccounts.ListTenantInventory(c.Request.Context(), currentUser.TenantID, page, pageSize)
	if err != nil {
		h.logger.Error("ListTenantServiceAccounts", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list service accounts"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"items": items, "total": total, "page": page, "pageSize": pageSize})
}

// ListTenantServicePrincipals returns signed-tenant service-principal inventory.
// @Summary List tenant service principals
// @Tags Team
// @Security BearerAuth
// @Router /api/v1/tenants/me/service-principals [get]
func (h *TeamInvitationHandler) ListTenantServicePrincipals(c *gin.Context) {
	currentUser := requireTeamPermission(c, "iam:service_principals:read")
	if currentUser == nil {
		return
	}
	if h.servicePrincipals == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "machine inventory is unavailable"})
		return
	}
	page, pageSize, ok := teamPagination(c)
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid pagination"})
		return
	}
	items, total, err := h.servicePrincipals.ListTenantInventory(c.Request.Context(), currentUser.TenantID, page, pageSize)
	if err != nil {
		h.logger.Error("ListTenantServicePrincipals", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list service principals"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"items": items, "total": total, "page": page, "pageSize": pageSize})
}

func teamPagination(c *gin.Context) (int, int, bool) {
	parse := func(name string, fallback, maximum int) (int, bool) {
		raw := c.Query(name)
		if raw == "" {
			return fallback, true
		}
		value, err := strconv.ParseInt(raw, 10, 0)
		if err != nil || value < 1 || value > int64(maximum) {
			return 0, false
		}
		return int(value), true
	}
	page, ok := parse("page", 1, teamMaxPage)
	if !ok {
		return 0, 0, false
	}
	pageSize, ok := parse("page_size", 25, teamMaxPageSize)
	if !ok {
		return 0, 0, false
	}
	return page, pageSize, true
}

// SetUserRoles handles POST /api/v1/users/:id/roles.
//
// Replaces the target user's role assignments. Enforces tenant boundary.
//
// @Summary Replace user role assignments
// @Tags Team
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param id      path string true "User ID"
// @Param request body models.TeamSetUserRolesRequest true "New role IDs"
// @Success 200 {object} map[string]string
// @Failure 403 {object} map[string]string
// @Router /api/v1/team/users/{id}/roles [post]
func (h *TeamInvitationHandler) SetUserRoles(c *gin.Context) {
	if rejectIfImpersonated(c) {
		return
	}
	currentUser := requireTeamPermission(c, permUsersUpdate)
	if currentUser == nil {
		return
	}

	targetID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid user id"})
		return
	}

	var req models.TeamSetUserRolesRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Tenant boundary: load target user and verify tenant membership.
	target, err := h.userRepo.GetByID(c.Request.Context(), targetID)
	if err != nil {
		h.logger.Error("SetUserRoles: GetByID failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to load user"})
		return
	}
	if target == nil || target.TenantID != currentUser.TenantID {
		c.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
		return
	}

	// Tenant boundary on the ROLES: this dialog "replaces the user's current
	// role assignments" (destructive), so a role_id from another tenant/
	// product must never be assignable here, regardless of what the picker
	// UI displayed. See verifyRolesBelongToTenant.
	if err := h.verifyRolesBelongToTenant(c.Request.Context(), currentUser.TenantID, req.RoleIDs); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": errRoleNotInTenant.Error()})
		return
	}

	if h.roleService == nil {
		h.logger.Error("SetUserRoles: roleService not configured")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to assign roles"})
		return
	}
	if h.tenantBootstrap == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "role authorization is unavailable"})
		return
	}

	// The invariant this endpoint must uphold: it can never delete a grant
	// the self-service picker (GET /api/v1/roles) could not have shown in
	// the first place — whether that's because the role belongs to another
	// tenant (verifyRolesBelongToTenant above) or because it's in THIS
	// tenant but not in an entitled module or outside this actor's priority
	// ceiling (RoleService.ListManageableSelfService). Deriving the deletable set
	// from the exact same source the picker uses keeps the two from
	// drifting apart again. AssignRolesInTenant further intersects this
	// with tenant_id = currentUser.TenantID as defence in depth.
	visible, err := h.roleService.ManageableSelfServiceRoleIDs(c.Request.Context(), currentUser.TenantID, currentUser.ID)
	if err != nil {
		h.logger.Error("SetUserRoles: ManageableSelfServiceRoleIDs failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to assign roles"})
		return
	}
	assignableRoleIDs := make([]uuid.UUID, 0, len(visible))
	for id := range visible {
		assignableRoleIDs = append(assignableRoleIDs, id)
	}

	resourceType := "user"
	audit := &models.AuditLog{
		TenantID: currentUser.TenantID, UserID: &currentUser.ID, TargetUserID: &targetID,
		Action: "team_roles_replace", ResourceType: &resourceType, ResourceID: &targetID,
		Details: map[string]interface{}{"result": "success", "requested_role_count": len(req.RoleIDs)}, Success: true,
	}
	modules, err := h.roleService.EntitledModules(c.Request.Context(), currentUser.TenantID)
	if err != nil {
		h.logger.Error("SetUserRoles: entitlement lookup failed", zap.Error(err))
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "role catalogue is unavailable"})
		return
	}
	if err := h.userRepo.ReplaceTeamRoles(c.Request.Context(), currentUser.TenantID, currentUser.ID, targetID, assignableRoleIDs, req.RoleIDs, audit, modules); err != nil {
		if errors.Is(err, repositories.ErrTeamTargetNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
			return
		}
		if errors.Is(err, repositories.ErrTeamTargetPriority) || errors.Is(err, repositories.ErrTeamLastAdministrator) {
			c.JSON(http.StatusForbidden, gin.H{"error": "cannot replace this member's roles"})
			return
		}
		h.logger.Error("SetUserRoles: ReplaceTeamRoles failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to assign roles"})
		return
	}
	syncErr := h.syncUserRolesFromDatabase(c.Request.Context(), currentUser.TenantID, targetID)
	if syncErr != nil {
		h.logger.Error("SetUserRoles: SpiceDB role synchronization failed", zap.Error(syncErr))
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "roles were updated but authorization synchronization failed; retry the request"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "roles updated"})
}

// DeactivateUser handles DELETE /api/v1/users/:id (Team page soft-delete).
//
// Sets is_active = false. Cross-tenant access is denied (404). Does not hard-delete
// because audit retention policy requires the row.
//
// @Summary Deactivate a user (soft delete)
// @Tags Team
// @Security BearerAuth
// @Param id path string true "User ID"
// @Success 204
// @Failure 403 {object} map[string]string
// @Failure 404 {object} map[string]string
// @Router /api/v1/team/users/{id} [delete]
func (h *TeamInvitationHandler) DeactivateUser(c *gin.Context) {
	if rejectIfImpersonated(c) {
		return
	}
	currentUser := requireTeamPermission(c, permUsersDelete)
	if currentUser == nil {
		return
	}

	targetID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid user id"})
		return
	}

	// Prevent self-deactivation.
	if targetID == currentUser.ID {
		c.JSON(http.StatusBadRequest, gin.H{"error": "cannot deactivate your own account via this endpoint"})
		return
	}

	resourceType := "user"
	audit := &models.AuditLog{TenantID: currentUser.TenantID, UserID: &currentUser.ID, TargetUserID: &targetID, Action: "team_member_deactivate", ResourceType: &resourceType, ResourceID: &targetID, Details: map[string]interface{}{"result": "success", "correlation_id": middleware.GetCorrelationID(c)}, Success: true}
	if err := h.userRepo.SetTeamMemberActive(c.Request.Context(), currentUser.TenantID, currentUser.ID, targetID, false, audit); err != nil {
		if errors.Is(err, repositories.ErrTeamTargetNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
			return
		}
		if errors.Is(err, repositories.ErrTeamTargetPriority) || errors.Is(err, repositories.ErrTeamLastAdministrator) {
			c.JSON(http.StatusForbidden, gin.H{"error": "cannot deactivate this member"})
			return
		}
		h.logger.Error("DeactivateUser: failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to deactivate user"})
		return
	}
	if err := h.tenantBootstrap.SyncUserAccess(c.Request.Context(), currentUser.TenantID, targetID, false, false, nil); err != nil {
		h.logger.Error("DeactivateUser: SpiceDB revocation failed", zap.Error(err))
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "user was deactivated but authorization revocation is synchronizing"})
		return
	}

	c.Status(http.StatusNoContent)
}

// ReactivateUser restores an existing member in the signed tenant context.
// @Summary Reactivate a tenant member
// @Tags Team
// @Security BearerAuth
// @Param id path string true "User ID"
// @Success 204
// @Failure 403 {object} map[string]string
// @Failure 404 {object} map[string]string
// @Router /api/v1/team/users/{id}/reactivate [post]
func (h *TeamInvitationHandler) ReactivateUser(c *gin.Context) {
	if rejectIfImpersonated(c) {
		return
	}
	currentUser := requireTeamPermission(c, permUsersDelete)
	if currentUser == nil {
		return
	}
	targetID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid user id"})
		return
	}
	resourceType := "user"
	audit := &models.AuditLog{TenantID: currentUser.TenantID, UserID: &currentUser.ID, TargetUserID: &targetID, Action: "team_member_reactivate", ResourceType: &resourceType, ResourceID: &targetID, Details: map[string]interface{}{"result": "success", "correlation_id": middleware.GetCorrelationID(c)}, Success: true}
	if err := h.userRepo.SetTeamMemberActive(c.Request.Context(), currentUser.TenantID, currentUser.ID, targetID, true, audit); err != nil {
		if errors.Is(err, repositories.ErrTeamTargetNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
			return
		}
		if errors.Is(err, repositories.ErrTeamTargetPriority) {
			c.JSON(http.StatusForbidden, gin.H{"error": "cannot reactivate this member"})
			return
		}
		h.logger.Error("ReactivateUser: failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to reactivate user"})
		return
	}
	roles, err := h.userRepo.GetUserRoles(c.Request.Context(), targetID)
	if err != nil {
		h.logger.Error("ReactivateUser: role lookup failed", zap.Error(err))
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "user was reactivated but authorization synchronization failed"})
		return
	}
	tenantRoles := tenantRoleIDs(roles, currentUser.TenantID)
	if err := h.tenantBootstrap.SyncUserAccess(
		c.Request.Context(), currentUser.TenantID, targetID, true, hasAdministratorRole(roles, currentUser.TenantID), tenantRoles,
	); err != nil {
		h.logger.Error("ReactivateUser: SpiceDB synchronization failed", zap.Error(err))
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "user was reactivated but authorization synchronization failed"})
		return
	}
	c.Status(http.StatusNoContent)
}

func hasAdministratorRole(roles []models.Role, tenantID uuid.UUID) bool {
	for _, role := range roles {
		if role.TenantID == tenantID && authorization.IsTenantAdministratorRole(role.Name) {
			return true
		}
	}
	return false
}

// queryParamInt parses an integer query parameter with a fallback default.
func toInvitationResponse(inv *models.TeamInvitation) models.TeamInvitationResponse {
	return models.TeamInvitationResponse{
		ID:        inv.ID,
		Email:     inv.Email,
		RoleIDs:   inv.RoleIDs,
		Status:    inv.Status,
		ExpiresAt: inv.ExpiresAt,
		CreatedAt: inv.CreatedAt,
	}
}
