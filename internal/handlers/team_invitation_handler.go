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
	// teamInvitationDefaultExpiry is 7 days (team1 operator decision 2026-10-13; was 14 days per the product roadmap §4.1 /
	// the product specification §13.2 (was 7 days before the
	// seat-model work landed).
	teamInvitationDefaultExpiry = 7 * 24 * time.Hour
	teamInvitationTokenBytes    = 32
	// errCodeSeatLimitReached is the 409 problem code returned by
	// CreateInvitation when the tenant's seat_limit would be exceeded.
	errCodeSeatLimitReached = "seat_limit_reached"
	// errCodeAlreadyMember / errCodeInvitationPending are the 409 problem
	// codes CreateInvitation returns for an invitee who already belongs to the
	// tenant and for a duplicate pending invitation.
	errCodeAlreadyMember     = "already_member"
	errCodeInvitationPending = "invitation_pending"
	// errCodeInvitationNotPending: the invitation was already accepted,
	// declined, revoked or has expired (signed-in accept/decline by id).
	errCodeInvitationNotPending = "invitation_not_pending"
	// errCodeMFAEnrollmentRequired: accepting a role that requires MFA before
	// the person has enrolled a second factor.
	errCodeMFAEnrollmentRequired = "mfa_enrollment_required"
	// errCodeExternalRoleNotReadOnly is the 400 problem code returned when an
	// external (seat-free) invitation carries a role that can write.
	errCodeExternalRoleNotReadOnly = "external_role_not_read_only"
)

// errExternalRoleNotReadOnly: a seat_class=external invitation may only carry
// roles whose every permission is a read action (spec 17 §3.2: external
// seats are free because they are read-only accountant access).
var errExternalRoleNotReadOnly = errors.New("external invitations may only grant read-only roles")

// errRoleNotInTenant is returned (never with the offending role ID attached)
// whenever a caller supplies a role_id that does not belong to the tenant in
// scope. Deliberately generic: distinguishing "unknown role" from "role
// belongs to another tenant" in the response would itself be a cross-tenant
// enumeration oracle.
// errInviteeAlreadyMember: the invitee already holds an active membership (or
// has their home) in the inviting tenant.
var errInviteeAlreadyMember = errors.New("invitee is already a member of this tenant")

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
	reasonExternalMember    = "external member: revoke access and send a new invitation to change roles"
	permInvitationCreate    = "iam:invitations:create"
	permInvitationRead      = "iam:invitations:read"
	permInvitationDelete    = "iam:invitations:delete"
	permUsersRead           = "iam:users:read"
	permUsersUpdate         = "iam:users:update"
	permUsersDelete         = "iam:users:delete"
	teamMaxPage             = 10000
	teamMaxPageSize         = 100
)

// requireTeamPermission fetches the authenticated CurrentUser from the Gin
// context. Every caller of this function sits behind a route registered
// with authMiddleware.RequirePermission(<same permission>) in cmd/routes.go
// (see the table maintained there), so the SpiceDB-backed middleware check
// is the sole and authoritative enforcement point for `permission` — this
// helper does not, and must not, re-check it locally.
//
// SECURITY HISTORY: this used to also call currentUser.HasPermission(permission)
// and return 403 "forbidden" when it failed. CurrentUser.Permissions is
// intentionally left nil for v2 (SpiceDB) tokens — see
// token_service.go/GenerateAccessTokenV2 and
// token_service_validation.go/extractSpiceDBClaims, both commented
// "Permissions: nil, // Resolved via SpiceDB" — so that stale local check
// denied EVERY v2-token caller unconditionally, including platform admins
// whom the middleware's SpiceDB bypass had already authorized. It was dead
// weight even for legacy/minimal tokens (which do populate Permissions):
// the middleware in front of every one of these routes had already made
// the real, authoritative decision via SpiceDB before this handler ran.
// Removed 2026-09-18; do not reintroduce a permission re-check here without
// wiring it through the authorization engine instead of the static claim.
func requireTeamPermission(c *gin.Context, permission string) *models.CurrentUser {
	_ = permission // retained for call-site documentation of which permission the route middleware enforces
	currentUser := middleware.GetCurrentUser(c)
	if currentUser == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
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
// endpoints for Phase 2 of the AcmeWeb settings pages.
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
	userMemberships   *repositories.UserMembershipRepository
	employeeAccounts  *employeeAccountDeps
	seatCounters      *repositories.SeatCounterRepository
	invitedUsers      invitedMemberPreparer
	invitedSessions   invitedSessionIssuer
	invitedAccounts   invitedAccountStore
	inviteeIdentities inviteeIdentityStore
	emailProof        firstPartyEmailProof
	contextCache      func(ctx context.Context, userID uuid.UUID)
	logger            *zap.Logger
}

// SetContextCacheInvalidator wires the callback that drops a user's cached
// tenant switcher list (GET /api/v1/auth/available-contexts) after an
// external membership is granted or revoked, so the switcher reflects the
// change at once instead of after the cache TTL.
func (h *TeamInvitationHandler) SetContextCacheInvalidator(fn func(ctx context.Context, userID uuid.UUID)) {
	h.contextCache = fn
}

func (h *TeamInvitationHandler) invalidateContexts(ctx context.Context, userID uuid.UUID) {
	if h.contextCache != nil {
		h.contextCache(ctx, userID)
	}
}

// SetMachineRepositories wires the native machine inventory without changing
// the established constructor used by existing callers and tests.
func (h *TeamInvitationHandler) SetMachineRepositories(accounts *repositories.ServiceAccountRepository, principals *repositories.ServicePrincipalRepository) {
	h.serviceAccounts = accounts
	h.servicePrincipals = principals
}

// SetEmailService wires the transactional invitation delivery path.
func (h *TeamInvitationHandler) SetEmailService(email *services.EmailService) { h.emailService = email }

// SetSeatRepositories wires the seat model (the product roadmap §2.1/§4.9,
// the product specification §13.2/§13.7) without changing the
// established constructor. Both must be set together for CreateInvitation's
// seat reservation, RevokeInvitation/DeclineInvitation's release, and
// AcceptInvitation's membership+seat confirmation to take effect; if either
// is nil, those handlers skip seat bookkeeping entirely (fail-open, matching
// tenant_seat_counters.seat_limit's own NULL-means-unenforced convention) so
// this can be wired in incrementally without breaking existing deployments
// mid-rollout.
func (h *TeamInvitationHandler) SetSeatRepositories(memberships *repositories.UserMembershipRepository, seats *repositories.SeatCounterRepository) {
	h.userMemberships = memberships
	h.seatCounters = seats
}

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
		Email     string           `json:"email"`
		RoleIDs   []uuid.UUID      `json:"roleIds"`
		SeatClass models.SeatClass `json:"seatClass"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	req := models.CreateTeamInvitationRequest{Email: models.CanonicalInvitationEmail(input.Email), RoleIDs: input.RoleIDs, SeatClass: input.SeatClass}
	if err := binding.Validator.ValidateStruct(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	seatClass := req.SeatClass
	if seatClass == "" {
		seatClass = models.SeatClassMember
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
	if seatClass == models.SeatClassExternal {
		if err := verifyRolesReadOnly(c.Request.Context(), h.roleRepo, req.RoleIDs); err != nil {
			if errors.Is(err, errExternalRoleNotReadOnly) {
				c.JSON(http.StatusBadRequest, gin.H{"error": err.Error(), "code": errCodeExternalRoleNotReadOnly})
				return
			}
			h.logger.Error("CreateInvitation: read-only role check failed", zap.Error(err))
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create invitation"})
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
		SeatClass: seatClass,
	}

	resourceType := "team_invitation"
	audit := &models.AuditLog{TenantID: tenantID, UserID: &currentUser.ID, Action: "team_invitation_create", ResourceType: &resourceType, ResourceID: &inv.ID, Details: map[string]interface{}{"result": "success", "seat_class": string(seatClass), "correlation_id": middleware.GetCorrelationID(c)}, Success: true}
	if h.emailService == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "invitation delivery is unavailable"})
		return
	}

	// seatCounters/userMemberships may be nil during an incremental rollout
	// (see SetSeatRepositories doc comment) — in that case seat enforcement
	// is skipped entirely, matching seat_limit's own NULL-means-unenforced
	// fail-open convention.
	consumesSeat := inv.ConsumesSeat() && h.seatCounters != nil

	var seatCountersAtLimit *models.SeatCounters
	// existingAccount only steers the wording of the email; it is never part
	// of the response (that would be an account-existence oracle).
	var existingAccount bool
	if err := h.invitationRepo.InTransaction(c.Request.Context(), func(tx pgx.Tx) error {
		var err error
		existingAccount, seatCountersAtLimit, err = h.persistInvitationTx(c.Request.Context(), tx, inv, audit, consumesSeat)
		return err
	}); err != nil {
		if errors.Is(err, repositories.ErrSeatLimitReached) {
			body := models.SeatLimitReachedError{Code: errCodeSeatLimitReached, Requested: 1}
			if seatCountersAtLimit != nil {
				body.SeatsUsed = seatCountersAtLimit.SeatsUsed
				if seatCountersAtLimit.SeatLimit != nil {
					body.SeatLimit = *seatCountersAtLimit.SeatLimit
					body.Shortfall = (seatCountersAtLimit.SeatsUsed + seatCountersAtLimit.SeatsPending + 1) - body.SeatLimit
				}
			}
			c.JSON(http.StatusConflict, body)
			return
		}
		if errors.Is(err, errInviteeAlreadyMember) {
			// The admin can already see this person on the team list, so this
			// reveals nothing new. No seat was reserved: the transaction rolled back.
			c.JSON(http.StatusConflict, gin.H{"error": "this person is already a member of this company", "code": errCodeAlreadyMember})
			return
		}
		if errors.Is(err, repositories.ErrDuplicatePendingInvitation) {
			c.JSON(http.StatusConflict, gin.H{"error": "a pending invitation already exists for this email", "code": errCodeInvitationPending})
			return
		}
		h.logger.Error("CreateInvitation: failed to persist", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create invitation"})
		return
	}
	if err := h.emailService.SendTeamInvitation(c.Request.Context(), tenantID, req.Email, token, existingAccount); err != nil {
		cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(c.Request.Context()), 5*time.Second)
		defer cancel()
		revoked, revokeErr := h.invitationRepo.TransitionPending(cleanupCtx, inv.ID, models.TeamInvitationStatusRevoked)
		if revoked && consumesSeat {
			if releaseErr := h.seatCounters.ReleaseReservation(cleanupCtx, tenantID); releaseErr != nil {
				h.logger.Error("CreateInvitation: failed to release seat reservation after delivery failure", zap.Error(releaseErr))
			}
		}
		h.logger.Error("CreateInvitation: delivery failed after persistence",
			zap.Error(err), zap.Bool("invitation_revoked", revoked), zap.Error(revokeErr))
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "invitation delivery failed; retry to issue a new invitation"})
		return
	}

	c.JSON(http.StatusCreated, toInvitationResponse(inv))
}

// persistInvitationTx is the transactional core of CreateInvitation: it refuses
// an invitee who is already an active member, expires a lapsed pending row for
// the same email (releasing the seat that row held), reserves a seat, and
// inserts the invitation plus its audit row. The invitee's account is looked up
// by canonical email across all tenants (one global account, many companies), so
// a person who already has an account elsewhere is invited exactly like a new
// one; only an existing membership in THIS tenant is refused.
//
// existingAccount reports whether a global account owns the email; seatsAtLimit
// is set when ErrSeatLimitReached is returned.
func (h *TeamInvitationHandler) persistInvitationTx(ctx context.Context, tx pgx.Tx, inv *models.TeamInvitation, audit *models.AuditLog, consumesSeat bool) (existingAccount bool, seatsAtLimit *models.SeatCounters, err error) {
	invitee, err := h.accountStore().FindByEmail(ctx, tx, inv.Email)
	if err != nil {
		return false, nil, fmt.Errorf("look up invitee account: %w", err)
	}
	if invitee != nil {
		existingAccount = true
		if invitee.TenantID == inv.TenantID {
			return existingAccount, nil, errInviteeAlreadyMember
		}
		if h.userMemberships != nil {
			m, mErr := h.userMemberships.WithDB(tx).GetByTenantAndUser(ctx, inv.TenantID, invitee.ID)
			if mErr != nil {
				return existingAccount, nil, fmt.Errorf("look up invitee membership: %w", mErr)
			}
			if m != nil && m.IsActiveMember() {
				return existingAccount, nil, errInviteeAlreadyMember
			}
		}
	}

	repo := h.invitationRepo.WithDB(tx)
	expiredReserved, err := repo.ExpirePendingForEmail(ctx, inv.TenantID, inv.Email)
	if err != nil {
		return existingAccount, nil, err
	}
	if h.seatCounters != nil {
		seats := h.seatCounters.WithDB(tx)
		// A lapsed row flipped to 'expired' here is invisible to the background
		// sweeper, so its reservation is released in this same transaction.
		for i := 0; i < expiredReserved; i++ {
			if err := seats.ReleaseReservation(ctx, inv.TenantID); err != nil {
				return existingAccount, nil, err
			}
		}
		if consumesSeat {
			if err := seats.EnsureRow(ctx, inv.TenantID); err != nil {
				return existingAccount, nil, err
			}
			if _, err := seats.ReserveSeat(ctx, inv.TenantID); err != nil {
				if errors.Is(err, repositories.ErrSeatLimitReached) {
					if current, getErr := seats.Get(ctx, inv.TenantID); getErr == nil {
						seatsAtLimit = current
					}
				}
				return existingAccount, seatsAtLimit, err
			}
		}
	}
	if err := repo.Create(ctx, inv); err != nil {
		return existingAccount, nil, err
	}
	return existingAccount, nil, repositories.CreateAuditLogTx(ctx, tx, audit)
}

// inviteeHasAccount is the best-effort existing-account flag used only to pick
// the wording of a (re)sent invitation email; a lookup failure reads as false.
func (h *TeamInvitationHandler) inviteeHasAccount(ctx context.Context, email string) bool {
	u, err := h.accountStore().FindByEmail(ctx, nil, email)
	if err != nil {
		h.logger.Warn("invitation email: account lookup failed", zap.Error(err))
		return false
	}
	return u != nil
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

// ResendInvitation handles POST /api/v1/invitations/{id}/actions/resend.
// Resets a still-pending invitation's expires_at to now()+7 days and
// re-sends the delivery email, rate-limited to at most one resend per
// invitation per 5 minutes (429 beyond that) per
// the product specification §13.17.
//
// @Summary Resend a team invitation
// @Tags Team
// @Security BearerAuth
// @Param id path string true "Invitation ID"
// @Success 200 {object} models.TeamInvitationResponse
// @Failure 403 {object} map[string]string "Cross-tenant access"
// @Failure 404 {object} map[string]string
// @Failure 409 {object} map[string]string "Not pending"
// @Failure 429 {object} map[string]string "Resent too recently"
// @Router /api/v1/invitations/{id}/actions/resend [post]
func (h *TeamInvitationHandler) ResendInvitation(c *gin.Context) {
	if rejectIfImpersonated(c) {
		return
	}
	currentUser := requireTeamPermission(c, permInvitationCreate)
	if currentUser == nil {
		return
	}
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid invitation id"})
		return
	}
	if h.emailService == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "invitation delivery is unavailable"})
		return
	}

	inv, err := h.invitationRepo.GetByID(c.Request.Context(), id)
	if err != nil {
		h.logger.Error("ResendInvitation: lookup failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to resend invitation"})
		return
	}
	if inv == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "invitation not found"})
		return
	}
	// Tenant boundary: an admin can only resend within their own tenant —
	// same cross-tenant defence as RevokeInvitation.
	if inv.TenantID != currentUser.TenantID {
		c.JSON(http.StatusForbidden, gin.H{"error": "cannot resend invitations for another tenant"})
		return
	}
	if inv.Status != models.TeamInvitationStatusPending {
		c.JSON(http.StatusConflict, gin.H{"error": "invitation is not pending"})
		return
	}

	// Delivery uses a fresh token: the stored digest cannot be reversed into
	// the original bearer token, so a resend must mint and persist a new one
	// (invalidating the previous email's link) rather than resend the old
	// plaintext, which this handler never has access to.
	token, err := generateToken()
	if err != nil {
		h.logger.Error("ResendInvitation: token generation failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate invitation token"})
		return
	}
	newExpiry := time.Now().Add(teamInvitationDefaultExpiry)
	resourceType := "team_invitation"
	var rateLimited bool
	if err := h.invitationRepo.InTransaction(c.Request.Context(), func(tx pgx.Tx) error {
		ok, err := h.invitationRepo.WithDB(tx).Resend(c.Request.Context(), id, newExpiry, models.TeamInvitationTokenDigest(token))
		if err != nil {
			return err
		}
		if !ok {
			// The CAS lost either to a concurrent state change (now handled
			// by the pending re-check above being stale) or, far more
			// likely, the 5-minute resend rate limit.
			rateLimited = true
			return nil
		}
		return repositories.CreateAuditLogTx(c.Request.Context(), tx, &models.AuditLog{TenantID: inv.TenantID, UserID: &currentUser.ID, Action: "team_invitation_resend", ResourceType: &resourceType, ResourceID: &inv.ID, Details: map[string]interface{}{"result": "success", "correlation_id": middleware.GetCorrelationID(c)}, Success: true})
	}); err != nil {
		h.logger.Error("ResendInvitation: failed to persist", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to resend invitation"})
		return
	}
	if rateLimited {
		c.JSON(http.StatusTooManyRequests, gin.H{"error": "invitation was resent too recently; try again later"})
		return
	}
	inv.ExpiresAt = newExpiry

	if err := h.emailService.SendTeamInvitation(c.Request.Context(), inv.TenantID, inv.Email, token, h.inviteeHasAccount(c.Request.Context(), inv.Email)); err != nil {
		h.logger.Error("ResendInvitation: delivery failed after persistence", zap.Error(err))
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "invitation delivery failed; the invitation was reset and can be resent again"})
		return
	}

	c.JSON(http.StatusOK, toInvitationResponse(inv))
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
		if inv.ConsumesSeat() && h.seatCounters != nil {
			if err := h.seatCounters.WithDB(tx).ReleaseReservation(c.Request.Context(), inv.TenantID); err != nil {
				return err
			}
		}
		resourceType := "team_invitation"
		return repositories.CreateAuditLogTx(c.Request.Context(), tx, &models.AuditLog{TenantID: currentUser.TenantID, UserID: &currentUser.ID, Action: "team_invitation_revoke", ResourceType: &resourceType, ResourceID: &id, Details: map[string]interface{}{"result": "success", "seat_class": string(inv.SeatClass), "correlation_id": middleware.GetCorrelationID(c)}, Success: true})
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

	if !h.acceptDependenciesReady(c) {
		return
	}
	// Entitlement belongs to the INVITING tenant, not the caller's token
	// tenant: an external (seat-free) accountant accepts while signed in to
	// their own partner tenant. This unlocked read only picks that tenant; the
	// transaction re-reads the row under lock and refuses if it moved.
	peek, err := h.invitationRepo.GetByToken(c.Request.Context(), req.Token)
	if err != nil {
		h.logger.Error("AcceptInvitation: invitation lookup failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to accept invitation"})
		return
	}
	if peek == nil || !peek.IsValid() {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid or expired token"})
		return
	}
	h.acceptInvitation(c, currentUser, peek, func(ctx context.Context, repo *repositories.TeamInvitationRepository) (*models.TeamInvitation, error) {
		return repo.GetByTokenForUpdate(ctx, req.Token)
	}, false)
}

// invitationLocker re-reads the invitation under a row lock inside the
// accept/decline transaction (by token for the emailed link, by id for the
// signed-in "my invitations" flow).
type invitationLocker func(ctx context.Context, repo *repositories.TeamInvitationRepository) (*models.TeamInvitation, error)

// acceptDependenciesReady answers 503 and returns false when the role
// catalogue or the SpiceDB bootstrap needed by acceptance is not wired.
func (h *TeamInvitationHandler) acceptDependenciesReady(c *gin.Context) bool {
	if h.roleService == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "role catalogue service is unavailable"})
		return false
	}
	if h.tenantBootstrap == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "role authorization is unavailable"})
		return false
	}
	return true
}

// acceptInvitation runs the shared accept flow for an already identified,
// still-valid invitation (peek): MFA gate, entitlement lookup, the locked
// transaction (acceptInvitationTx), SpiceDB synchronisation and the response.
// byID selects the error vocabulary of the signed-in flow (409/404 instead of
// the token flow's 400/403).
func (h *TeamInvitationHandler) acceptInvitation(c *gin.Context, currentUser *models.CurrentUser, peek *models.TeamInvitation, lock invitationLocker, byID bool) {
	ctx := c.Request.Context()
	inviteTenantID := peek.TenantID
	if peek.SeatClass == models.SeatClassExternal && h.userMemberships == nil {
		// The membership row is what lists the client tenant in the switcher
		// and what revocation removes; without it an external grant would be
		// unrevocable from the Team page.
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "membership ledger is unavailable"})
		return
	}
	// Owner/admin roles in the new company require a second factor. Login only
	// enforces that for the tenant being signed in to, so acceptance (which
	// creates the membership) is where it is gated for a joined company.
	mfaRequired, _, err := h.invitationRequiresMFA(ctx, peek)
	if err != nil {
		h.logger.Error("AcceptInvitation: role lookup failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to accept invitation"})
		return
	}
	if mfaRequired {
		hasFactor, fErr := h.inviteeIdentity().HasAnyMFAFactor(ctx, currentUser.ID)
		if fErr != nil {
			h.logger.Error("AcceptInvitation: MFA factor lookup failed", zap.Error(fErr))
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to accept invitation"})
			return
		}
		if !hasFactor {
			h.auditAcceptRefused(c, currentUser, peek, errCodeMFAEnrollmentRequired)
			c.JSON(http.StatusForbidden, gin.H{"error": "this invitation grants an owner or admin role; enrol a second factor first", "code": errCodeMFAEnrollmentRequired})
			return
		}
	}
	modules, err := h.roleService.EntitledModules(ctx, inviteTenantID)
	if err != nil {
		h.logger.Error("AcceptInvitation: entitlement lookup failed", zap.Error(err))
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "role catalogue is unavailable"})
		return
	}
	var (
		result            string
		accepted          *models.TeamInvitation
		joinedOtherTenant bool
	)
	err = h.invitationRepo.InTransaction(ctx, func(tx pgx.Tx) error {
		inv, err := lock(ctx, h.invitationRepo.WithDB(tx))
		if err != nil {
			return err
		}
		if inv == nil || !inv.IsValid() || inv.TenantID != inviteTenantID {
			result = "invalid"
			return nil
		}
		result, joinedOtherTenant, err = h.acceptInvitationTx(ctx, tx, inv, currentUser, modules, middleware.GetCorrelationID(c))
		if err == nil && result == "" {
			accepted = inv
		}
		return err
	})
	if err != nil {
		h.logger.Error("AcceptInvitation: transaction failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to accept invitation"})
		return
	}
	switch result {
	case "invalid":
		if byID {
			c.JSON(http.StatusConflict, gin.H{"error": "this invitation is no longer pending", "code": errCodeInvitationNotPending})
			return
		}
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid or expired token"})
		return
	case "tenant":
		c.JSON(http.StatusForbidden, gin.H{"error": "this invitation belongs to a different tenant"})
		return
	case "identity":
		if byID {
			c.JSON(http.StatusNotFound, gin.H{"error": "invitation not found"})
			return
		}
		c.JSON(http.StatusForbidden, gin.H{"error": "this invitation belongs to a different account"})
		return
	case "already_member":
		c.JSON(http.StatusConflict, gin.H{"error": "you are already a member of this tenant", "code": errCodeAlreadyMember})
		return
	case "unavailable":
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "membership ledger is unavailable"})
		return
	case "roles":
		c.JSON(http.StatusBadRequest, gin.H{"error": errRoleNotInTenant.Error()})
		return
	}

	var roleErr error
	if joinedOtherTenant {
		roleErr = h.syncJoinedMemberAccess(ctx, accepted.TenantID, currentUser.ID)
		h.invalidateContexts(ctx, currentUser.ID)
	} else if accepted.SeatClass == models.SeatClassExternal {
		roleErr = h.syncExternalAccessFromDatabase(ctx, accepted.TenantID, currentUser.ID)
		h.invalidateContexts(ctx, currentUser.ID)
	} else {
		roleErr = h.syncUserRolesFromDatabase(ctx, accepted.TenantID, currentUser.ID)
	}
	if roleErr != nil {
		h.logger.Error("AcceptInvitation: SpiceDB role synchronization failed", zap.Error(roleErr))
		c.JSON(http.StatusAccepted, gin.H{"message": "invitation accepted; role authorization is synchronizing", "tenantId": accepted.TenantID, "seatClass": accepted.SeatClass})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "invitation accepted", "tenantId": accepted.TenantID, "seatClass": accepted.SeatClass})
}

// auditAcceptRefused records a refused acceptance (best effort: a failing audit
// write must not change the answer the caller gets).
func (h *TeamInvitationHandler) auditAcceptRefused(c *gin.Context, user *models.CurrentUser, inv *models.TeamInvitation, reason string) {
	ctx := context.WithoutCancel(c.Request.Context())
	resourceType := "team_invitation"
	err := h.invitationRepo.InTransaction(ctx, func(tx pgx.Tx) error {
		return repositories.CreateAuditLogTx(ctx, tx, &models.AuditLog{
			TenantID: inv.TenantID, UserID: &user.ID, TargetUserID: &user.ID,
			Action: "team_invitation_accept", ResourceType: &resourceType, ResourceID: &inv.ID,
			Details: map[string]interface{}{"result": "refused", "reason": reason, "seat_class": string(inv.SeatClass), "correlation_id": middleware.GetCorrelationID(c)},
			Success: false,
		})
	})
	if err != nil {
		h.logger.Error("AcceptInvitation: failed to audit refusal", zap.String("reason", reason), zap.Error(err))
	}
}

// acceptInvitationTx is the transactional core of acceptance, shared by the
// token and the signed-in flows. inv is already locked and valid. It returns a
// non-empty result ("identity", "already_member", "roles", "unavailable") for a
// refusal that leaves the invitation pending; "" means the invitation was
// accepted: roles granted, membership upserted, seat confirmed, audit written.
func (h *TeamInvitationHandler) acceptInvitationTx(ctx context.Context, tx pgx.Tx, inv *models.TeamInvitation, currentUser *models.CurrentUser, modules []string, correlationID string) (result string, joinedOtherTenant bool, err error) {
	external := inv.SeatClass == models.SeatClassExternal
	if external {
		// Cross-tenant by design: the invitee's home tenant is their
		// partner firm. Identity is the verified email alone, and a home
		// member of the inviting tenant can never be re-classed as a
		// free external seat.
		if !teamInvitationEmailMatches(currentUser, inv) {
			result = "identity"
			return result, joinedOtherTenant, nil
		}
		homeTenantID, exists, err := h.userRepo.WithDB(tx).GetHomeTenantID(ctx, currentUser.ID)
		if err != nil {
			return "", false, err
		}
		if !exists {
			result = "identity"
			return result, joinedOtherTenant, nil
		}
		if homeTenantID == inv.TenantID {
			result = "already_member"
			return result, joinedOtherTenant, nil
		}
	} else {
		// One global account, many companies (D1): the invitation binds to
		// the verified email of the signed-in person, not to their home
		// tenant. A person whose token is for another company joins this
		// one as an additional membership.
		if !teamInvitationEmailMatches(currentUser, inv) {
			result = "identity"
			return result, joinedOtherTenant, nil
		}
		if currentUser.TenantID != inv.TenantID {
			if h.userMemberships == nil {
				result = "unavailable"
				return result, joinedOtherTenant, nil
			}
			existing, err := h.userMemberships.WithDB(tx).GetByTenantAndUser(ctx, inv.TenantID, currentUser.ID)
			if err != nil {
				return "", false, err
			}
			if existing != nil && existing.IsActiveMember() {
				result = "already_member"
				return result, joinedOtherTenant, nil
			}
			joinedOtherTenant = true
		}
	}
	roleRepo := h.roleRepo.WithDB(tx)
	for _, roleID := range inv.RoleIDs {
		role, err := roleRepo.GetByIDAndTenantForShare(ctx, roleID, inv.TenantID)
		if err != nil {
			return "", false, err
		}
		if role == nil {
			result = "roles"
			return result, joinedOtherTenant, nil
		}
	}
	if err := roleRepo.LockPermissionCatalogue(ctx); err != nil {
		return "", false, err
	}
	for _, roleID := range inv.RoleIDs {
		allowed, err := roleRepo.HasOnlyPermissionsInModules(ctx, roleID, modules)
		if err != nil {
			return "", false, err
		}
		if !allowed {
			result = "roles"
			return result, joinedOtherTenant, nil
		}
	}
	if external {
		// Re-checked under the catalogue lock: a role edited to gain a
		// write permission after the invite was sent must not ride in.
		if err := verifyRolesReadOnly(ctx, roleRepo, inv.RoleIDs); err != nil {
			if errors.Is(err, errExternalRoleNotReadOnly) {
				result = "roles"
				return result, joinedOtherTenant, nil
			}
			return "", false, err
		}
	}
	if err := h.userRepo.WithDB(tx).GrantRoles(ctx, currentUser.ID, inv.RoleIDs, nil); err != nil {
		return "", false, err
	}
	ok, err := h.invitationRepo.WithDB(tx).TransitionPending(ctx, inv.ID, models.TeamInvitationStatusAccepted)
	if err != nil || !ok {
		return "", false, fmt.Errorf("accept invitation transition: %w", err)
	}
	// Membership + seat conversion: create/reactivate the tenant<->user
	// membership row and, if this invitation reserved a seat, convert
	// that reservation into used capacity. Both happen in this same
	// transaction as the role grant and status transition above, so
	// acceptance is all-or-nothing (the product roadmap §4.1/§4.9;
	// the product specification §13.2).
	if h.userMemberships != nil {
		invID := inv.ID
		if _, err := h.userMemberships.WithDB(tx).Upsert(ctx, &models.UserMembership{
			TenantID:     inv.TenantID,
			UserID:       currentUser.ID,
			SeatClass:    inv.SeatClass,
			InvitationID: &invID,
		}); err != nil {
			return "", false, fmt.Errorf("accept invitation: upsert membership: %w", err)
		}
	}
	if inv.ConsumesSeat() && h.seatCounters != nil {
		if err := h.seatCounters.WithDB(tx).ConfirmSeat(ctx, inv.TenantID); err != nil {
			return "", false, fmt.Errorf("accept invitation: confirm seat: %w", err)
		}
	}
	resourceType := "team_invitation"
	if err := repositories.CreateAuditLogTx(ctx, tx, &models.AuditLog{TenantID: inv.TenantID, UserID: &currentUser.ID, TargetUserID: &currentUser.ID, Action: "team_invitation_accept", ResourceType: &resourceType, ResourceID: &inv.ID, Details: map[string]interface{}{"result": "success", "seat_class": string(inv.SeatClass), "correlation_id": correlationID}, Success: true}); err != nil {
		return "", false, err
	}
	return "", joinedOtherTenant, nil

}

// verifyRolesReadOnly returns errExternalRoleNotReadOnly unless every role
// grants only read permissions (see RoleRepository.HasOnlyReadPermissions).
func verifyRolesReadOnly(ctx context.Context, roleRepo *repositories.RoleRepository, roleIDs []uuid.UUID) error {
	for _, roleID := range roleIDs {
		readOnly, err := roleRepo.HasOnlyReadPermissions(ctx, roleID)
		if err != nil {
			return err
		}
		if !readOnly {
			return errExternalRoleNotReadOnly
		}
	}
	return nil
}

// syncExternalAccessFromDatabase mirrors syncUserRolesFromDatabase for an
// external member: the tenant-scoped roles plus the tenant#guest marker,
// never tenant#member (see TenantBootstrapService.SyncExternalAccess).
func (h *TeamInvitationHandler) syncExternalAccessFromDatabase(ctx context.Context, tenantID, userID uuid.UUID) error {
	roles, err := h.userRepo.GetUserRoles(ctx, userID)
	if err != nil {
		return err
	}
	return h.tenantBootstrap.SyncExternalAccess(ctx, tenantID, userID, true, tenantRoleIDs(roles, tenantID))
}

// DeclineInvitation handles POST /api/v1/invitations/decline.
//
// Validates the token the same way AcceptInvitation does (tenant boundary +
// identity match against the authenticated caller), but grants no roles: it
// only transitions the invitation to "declined". Unlike RevokeInvitation
// (an admin action, gated on permIAMInvitationsDelete), this is the
// INVITEE'S OWN action on their own invitation — same authorization shape
// as AcceptInvitation, not RevokeInvitation, which is why this sits in the
// same auth-only (no permission gate) route group as accept.
//
// @Summary Decline a team invitation
// @Tags Team
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param request body models.AcceptTeamInvitationRequest true "Invitation token"
// @Success 200 {object} map[string]string
// @Failure 400 {object} map[string]string
// @Failure 403 {object} map[string]string
// @Router /api/v1/invitations/decline [post]
func (h *TeamInvitationHandler) DeclineInvitation(c *gin.Context) {
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

	h.declineInvitation(c, currentUser, func(ctx context.Context, repo *repositories.TeamInvitationRepository) (*models.TeamInvitation, error) {
		return repo.GetByTokenForUpdate(ctx, req.Token)
	}, false)
}

// declineInvitation is the shared decline flow (by token or by id): under the
// row lock it checks the caller's email, transitions the invitation to
// declined and releases its seat reservation, all in one transaction.
func (h *TeamInvitationHandler) declineInvitation(c *gin.Context, currentUser *models.CurrentUser, lock invitationLocker, byID bool) {
	ctx := c.Request.Context()
	var result string
	err := h.invitationRepo.InTransaction(ctx, func(tx pgx.Tx) error {
		inv, err := lock(ctx, h.invitationRepo.WithDB(tx))
		if err != nil {
			return err
		}
		if inv == nil || !inv.IsValid() {
			result = "invalid"
			return nil
		}
		// Invitees decline from whichever company they are signed in to, so
		// only the verified email binds them (same rule as accept).
		if !teamInvitationEmailMatches(currentUser, inv) {
			result = "identity"
			return nil
		}
		ok, err := h.invitationRepo.WithDB(tx).TransitionPending(ctx, inv.ID, models.TeamInvitationStatusDeclined)
		if err != nil || !ok {
			return fmt.Errorf("decline invitation transition: %w", err)
		}
		if inv.ConsumesSeat() && h.seatCounters != nil {
			if err := h.seatCounters.WithDB(tx).ReleaseReservation(ctx, inv.TenantID); err != nil {
				return fmt.Errorf("decline invitation: release seat reservation: %w", err)
			}
		}
		resourceType := "team_invitation"
		return repositories.CreateAuditLogTx(ctx, tx, &models.AuditLog{TenantID: inv.TenantID, UserID: &currentUser.ID, TargetUserID: &currentUser.ID, Action: "team_invitation_decline", ResourceType: &resourceType, ResourceID: &inv.ID, Details: map[string]interface{}{"result": "success", "correlation_id": middleware.GetCorrelationID(c)}, Success: true})
	})
	if err != nil {
		h.logger.Error("DeclineInvitation: transaction failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to decline invitation"})
		return
	}
	switch result {
	case "invalid":
		if byID {
			c.JSON(http.StatusConflict, gin.H{"error": "this invitation is no longer pending", "code": errCodeInvitationNotPending})
			return
		}
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid or expired token"})
		return
	case "identity":
		if byID {
			c.JSON(http.StatusNotFound, gin.H{"error": "invitation not found"})
			return
		}
		c.JSON(http.StatusForbidden, gin.H{"error": "this invitation belongs to a different account"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "invitation declined"})
}

func teamInvitationMatchesUser(user *models.CurrentUser, invitation *models.TeamInvitation) bool {
	return user != nil && invitation != nil &&
		user.TenantID == invitation.TenantID &&
		models.CanonicalInvitationEmail(user.Email) == models.CanonicalInvitationEmail(invitation.Email)
}

// teamInvitationEmailMatches is the identity rule for external invitations,
// which are accepted across tenants: the caller's verified email must equal
// the invited email. An empty caller email never matches.
func teamInvitationEmailMatches(user *models.CurrentUser, invitation *models.TeamInvitation) bool {
	if user == nil || invitation == nil {
		return false
	}
	email := models.CanonicalInvitationEmail(user.Email)
	return email != "" && email == models.CanonicalInvitationEmail(invitation.Email)
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
// @Param status    query string false "Member status: all (default), active, inactive; service identities are always excluded"
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
	status := c.DefaultQuery("status", "all")
	if status != "all" && status != "active" && status != "inactive" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid member status"})
		return
	}

	users, total, err := h.userRepo.ListTenantHumans(c.Request.Context(), currentUser.TenantID, page, pageSize, search, status)
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
		if errors.Is(err, repositories.ErrSeatLimitReached) {
			body := models.SeatLimitReachedError{Code: errCodeSeatLimitReached, Requested: 1}
			if current, getErr := h.seatCounters.Get(c.Request.Context(), currentUser.TenantID); getErr == nil && current != nil {
				body.SeatsUsed = current.SeatsUsed
				if current.SeatLimit != nil {
					body.SeatLimit = *current.SeatLimit
					body.Shortfall = (current.SeatsUsed + current.SeatsPending + 1) - body.SeatLimit
				}
			}
			c.JSON(http.StatusConflict, body)
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
		SeatClass: inv.SeatClass,
		ExpiresAt: inv.ExpiresAt,
		CreatedAt: inv.CreatedAt,
	}
}

// ListExternalMembers handles GET /api/v1/tenants/me/external-members.
//
// Lists the tenant's active external (seat_class=external, seat-free)
// members: accountants who live in their own partner tenant and were invited
// into this one. They are absent from GET /tenants/me/users, which lists
// only users whose home tenant is this one.
//
// @Summary List external (seat-free) members
// @Tags Team
// @Security BearerAuth
// @Produce json
// @Success 200 {object} map[string]interface{}
// @Router /api/v1/tenants/me/external-members [get]
func (h *TeamInvitationHandler) ListExternalMembers(c *gin.Context) {
	currentUser := requireTeamPermission(c, permUsersRead)
	if currentUser == nil {
		return
	}
	if h.userMemberships == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "membership ledger is unavailable"})
		return
	}
	rows, err := h.userMemberships.ListActiveExternal(c.Request.Context(), currentUser.TenantID)
	if err != nil {
		h.logger.Error("ListExternalMembers: failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list external members"})
		return
	}
	items := make([]models.ExternalMember, 0, len(rows))
	for _, row := range rows {
		roles, err := h.userRepo.GetUserRoles(c.Request.Context(), row.UserID)
		if err != nil {
			h.logger.Warn("ListExternalMembers: role lookup failed, returning empty roles",
				zap.String("user_id", row.UserID.String()), zap.Error(err))
		}
		refs := make([]models.RoleRef, 0, len(roles))
		for _, r := range roles {
			// Only this tenant's grants: the member's partner-tenant roles
			// are none of this tenant's business.
			if r.TenantID != currentUser.TenantID {
				continue
			}
			refs = append(refs, models.RoleRef{ID: r.ID, Name: r.Name, Editable: false, Reason: reasonExternalMember, Source: models.RoleSourceTenantCatalogue})
		}
		displayName := ""
		if row.DisplayName != nil {
			displayName = *row.DisplayName
		}
		items = append(items, models.ExternalMember{
			ID:          row.UserID,
			Email:       row.Email,
			DisplayName: displayName,
			SeatClass:   models.SeatClassExternal,
			Roles:       refs,
			JoinedAt:    row.CreatedAt,
		})
	}
	c.JSON(http.StatusOK, gin.H{"items": items, "total": len(items)})
}

// RevokeExternalMember handles DELETE /api/v1/team/external-members/:id.
//
// Ends an external member's access to the caller's tenant: the membership is
// deactivated and every role grant in THIS tenant is removed in one
// transaction (the member's partner-tenant roles are untouched), then the
// SpiceDB role memberships and the tenant#guest edge are deleted so access
// stops on the next permission check. Never touches a seat-holding member:
// only rows with seat_class='external' qualify.
//
// @Summary Revoke an external member's access
// @Tags Team
// @Security BearerAuth
// @Param id path string true "User ID"
// @Success 204
// @Failure 404 {object} map[string]string
// @Router /api/v1/team/external-members/{id} [delete]
func (h *TeamInvitationHandler) RevokeExternalMember(c *gin.Context) {
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
	if h.userMemberships == nil || h.tenantBootstrap == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "membership ledger is unavailable"})
		return
	}
	tenantID := currentUser.TenantID
	found := false
	if err := h.invitationRepo.InTransaction(c.Request.Context(), func(tx pgx.Tx) error {
		ok, err := h.userMemberships.WithDB(tx).DeactivateExternal(c.Request.Context(), tenantID, targetID)
		if err != nil {
			return err
		}
		if !ok {
			return nil
		}
		found = true
		if err := h.userRepo.WithDB(tx).RevokeTenantRoles(c.Request.Context(), targetID, tenantID); err != nil {
			return err
		}
		resourceType := "user"
		return repositories.CreateAuditLogTx(c.Request.Context(), tx, &models.AuditLog{TenantID: tenantID, UserID: &currentUser.ID, TargetUserID: &targetID, Action: "team_external_member_revoke", ResourceType: &resourceType, ResourceID: &targetID, Details: map[string]interface{}{"result": "success", "seat_class": string(models.SeatClassExternal), "correlation_id": middleware.GetCorrelationID(c)}, Success: true})
	}); err != nil {
		h.logger.Error("RevokeExternalMember: transaction failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to revoke access"})
		return
	}
	if !found {
		c.JSON(http.StatusNotFound, gin.H{"error": "external member not found"})
		return
	}
	h.invalidateContexts(c.Request.Context(), targetID)
	if err := h.tenantBootstrap.SyncExternalAccess(c.Request.Context(), tenantID, targetID, false, nil); err != nil {
		// PostgreSQL already holds the revocation; the SpiceDB reconciler
		// converges the stale edges if this synchronous delete failed.
		h.logger.Error("RevokeExternalMember: SpiceDB revocation failed", zap.Error(err))
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "access was revoked but authorization revocation is synchronizing"})
		return
	}
	c.Status(http.StatusNoContent)
}
