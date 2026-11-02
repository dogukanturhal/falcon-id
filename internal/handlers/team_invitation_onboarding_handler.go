// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/middleware"
	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/internal/repositories"
	"github.com/dogukanturhal/falcon-id/internal/services"
)

// Token-scoped onboarding of invited people (team1 D1/D2).
//
// A team invitation link is a single-use bearer token that proves possession of
// the invited mailbox. Two public, token-scoped endpoints let the accept page
// serve a person who has no falcon-id account yet:
//
//	GET  /api/v1/invitations/preview?token=…        what am I being invited to
//	POST /api/v1/auth/invitations/register          create the global account
//
// Registering creates the one global account (home tenant = the inviting
// company, email already verified), grants the invited roles, writes the
// membership, converts the reserved seat and consumes the invitation in ONE
// transaction. A person who already has an account never registers: they sign
// in and call POST /api/v1/invitations/accept, which now also adds a membership
// in a company that is not their home tenant.

var errInvitationAccountExists = errors.New("an account already exists for this email")

func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}

// syncJoinedMemberAccess writes the SpiceDB edges of a person who just joined a
// company that is not their pre-existing home tenant (or has no account yet):
// tenant#member plus exactly the tenant's role memberships.
func (h *TeamInvitationHandler) syncJoinedMemberAccess(ctx context.Context, tenantID, userID uuid.UUID) error {
	roles, err := h.userRepo.GetUserRoles(ctx, userID)
	if err != nil {
		return err
	}
	return h.tenantBootstrap.SyncUserAccess(ctx, tenantID, userID, true, false, tenantRoleIDs(roles, tenantID))
}

// invitedMemberPreparer builds the unsaved global account of an invited person
// (services.UserService satisfies it).
type invitedMemberPreparer interface {
	PrepareInvitedMemberUser(ctx context.Context, tenantID uuid.UUID, email, fullName, password string) (*models.User, error)
}

// invitedAccountStore is the persistence the onboarding transaction needs from
// the user table. The production implementation wraps UserRepository; the
// interface exists so the transaction (roles, membership, seat, invitation) can
// be exercised against a minimal schema.
type invitedAccountStore interface {
	// EmailTaken reports whether any account (in any tenant) owns the email.
	EmailTaken(ctx context.Context, email string) (bool, error)
	// FindByEmail returns the global account owning the email, or nil. A nil
	// tx reads through the pool.
	FindByEmail(ctx context.Context, tx pgx.Tx, email string) (*models.User, error)
	// CreateVerified inserts the account inside tx with its email verified.
	// It returns errInvitationAccountExists on a uniqueness violation.
	CreateVerified(ctx context.Context, tx pgx.Tx, user *models.User) error
}

// inviteeIdentityStore is what the signed-in "my invitations" flow needs to
// trust the caller: their verified mailbox and whether they hold an MFA factor
// (services-level repositories.UserRepository satisfies it; tests inject a stub).
type inviteeIdentityStore interface {
	// VerifiedEmail returns the account email and whether its mailbox is verified.
	VerifiedEmail(ctx context.Context, userID uuid.UUID) (email string, verified bool, err error)
	HasAnyMFAFactor(ctx context.Context, userID uuid.UUID) (bool, error)
}

// firstPartyEmailProof is the evidence that this deployment itself verified an
// account's mailbox (as opposed to an administrator, LDAP, SAML or a social
// provider asserting it).
type firstPartyEmailProof interface {
	// HasCompletedSignupForUser: the user was created by a verified, completed
	// self-service signup for exactly this canonical email.
	HasCompletedSignupForUser(ctx context.Context, userID uuid.UUID, canonicalEmail string) (bool, error)
}

// emailOwnerCounter reports how many accounts (any tenant) share an email.
type emailOwnerCounter interface {
	CountAccountsByEmail(ctx context.Context, email string) (int, error)
}

// inviteeAccountReader reads the signed-in account (repositories.UserRepository).
type inviteeAccountReader interface {
	GetByID(ctx context.Context, id uuid.UUID) (*models.User, error)
}

type repositoryInviteeIdentity struct {
	repo  inviteeAccountReader
	proof firstPartyEmailProof
	owner emailOwnerCounter
	mfa   interface {
		HasAnyMFAFactor(ctx context.Context, userID uuid.UUID) (bool, error)
	}
}

// VerifiedEmail returns the account email and whether the mailbox is verified
// by first-party proof. is_email_verified alone is NOT trusted: tenant admins
// can force it, LDAP/SAML/social sign-in set it from an external assertion, and
// emails are only unique per tenant. Verified here means all of: the flag is
// set, the account is not federated, no other account shares the address, and a
// completed self-service signup for this address created the account.
func (s repositoryInviteeIdentity) VerifiedEmail(ctx context.Context, userID uuid.UUID) (string, bool, error) {
	u, err := s.repo.GetByID(ctx, userID)
	if err != nil || u == nil {
		return "", false, err
	}
	if !u.IsEmailVerified || (u.FederationType != nil && *u.FederationType != "") || s.proof == nil || s.owner == nil {
		return u.Email, false, nil
	}
	n, err := s.owner.CountAccountsByEmail(ctx, u.Email)
	if err != nil {
		return "", false, err
	}
	if n != 1 {
		return u.Email, false, nil
	}
	ok, err := s.proof.HasCompletedSignupForUser(ctx, u.ID, models.CanonicalInvitationEmail(u.Email))
	if err != nil {
		return "", false, err
	}
	return u.Email, ok, nil
}

func (s repositoryInviteeIdentity) HasAnyMFAFactor(ctx context.Context, userID uuid.UUID) (bool, error) {
	return s.mfa.HasAnyMFAFactor(ctx, userID)
}

// SetInviteeIdentityStore overrides the caller-identity lookups (tests).
func (h *TeamInvitationHandler) SetInviteeIdentityStore(store inviteeIdentityStore) {
	h.inviteeIdentities = store
}

// SetFirstPartyEmailProof wires the signup-proof lookup behind the signed-in
// "my invitations" flow. Without it nobody counts as verified (fail closed).
func (h *TeamInvitationHandler) SetFirstPartyEmailProof(proof firstPartyEmailProof) {
	h.emailProof = proof
}

func (h *TeamInvitationHandler) inviteeIdentity() inviteeIdentityStore {
	if h.inviteeIdentities != nil {
		return h.inviteeIdentities
	}
	return repositoryInviteeIdentity{repo: h.userRepo, proof: h.emailProof, owner: h.userRepo, mfa: h.userRepo}
}

type repositoryInvitedAccountStore struct{ repo *repositories.UserRepository }

func (s repositoryInvitedAccountStore) EmailTaken(ctx context.Context, email string) (bool, error) {
	u, err := s.repo.GetByEmailGlobal(ctx, email)
	return u != nil, err
}

func (s repositoryInvitedAccountStore) FindByEmail(ctx context.Context, tx pgx.Tx, email string) (*models.User, error) {
	repo := s.repo
	if tx != nil {
		repo = repo.WithDB(tx)
	}
	return repo.GetByEmailGlobal(ctx, email)
}

func (s repositoryInvitedAccountStore) CreateVerified(ctx context.Context, tx pgx.Tx, user *models.User) error {
	repo := s.repo.WithDB(tx)
	if err := repo.Create(ctx, user); err != nil {
		if isUniqueViolation(err) {
			return errInvitationAccountExists
		}
		return fmt.Errorf("create user: %w", err)
	}
	return repo.MarkEmailVerified(ctx, user.ID)
}

// SetInvitedAccountStore overrides the user-table persistence (tests).
func (h *TeamInvitationHandler) SetInvitedAccountStore(store invitedAccountStore) {
	h.invitedAccounts = store
}

func (h *TeamInvitationHandler) accountStore() invitedAccountStore {
	if h.invitedAccounts != nil {
		return h.invitedAccounts
	}
	return repositoryInvitedAccountStore{repo: h.userRepo}
}

// invitedSessionIssuer mints the first session of a freshly created account
// (services.AuthService satisfies it).
type invitedSessionIssuer interface {
	IssueSessionForNewUser(ctx context.Context, tenantID uuid.UUID, user *models.User, ipAddress, userAgent string) (*models.LoginResponse, error)
}

// SetOnboardingServices wires the account creation and session issuance used
// by RegisterFromInvitation. Without them the endpoint answers 503.
func (h *TeamInvitationHandler) SetOnboardingServices(users invitedMemberPreparer, sessions invitedSessionIssuer) {
	h.invitedUsers = users
	h.invitedSessions = sessions
}

// mfaRequiredRoleNames are the role names whose holders must enrol a second
// factor before they work in the company (operator decision 2026-10-13: owner
// and admin required, everyone else optional).
var mfaRequiredRoleNames = map[string]bool{"owner": true, "admin": true}

// invitationRequiresMFA reports whether any invited role is an owner/admin role.
func (h *TeamInvitationHandler) invitationRequiresMFA(ctx context.Context, inv *models.TeamInvitation) (bool, []string, error) {
	names := make([]string, 0, len(inv.RoleIDs))
	required := false
	for _, roleID := range inv.RoleIDs {
		role, err := h.roleRepo.GetByIDAndTenant(ctx, roleID, inv.TenantID)
		if err != nil {
			return false, nil, err
		}
		if role == nil {
			continue
		}
		label := role.DisplayName
		if label == "" {
			label = role.Name
		}
		names = append(names, label)
		if mfaRequiredRoleNames[strings.ToLower(role.Name)] {
			required = true
		}
	}
	return required, names, nil
}

// maskInvitationEmail keeps the first character and the domain: a***@example.com.
func maskInvitationEmail(email string) string {
	local, domain, ok := strings.Cut(email, "@")
	if !ok || local == "" {
		return ""
	}
	return local[:1] + "***@" + domain
}

type invitationPreviewResponse struct {
	Valid                bool     `json:"valid"`
	Reason               string   `json:"reason,omitempty"` // expired | used | revoked | not_found
	CompanyName          string   `json:"companyName,omitempty"`
	InviterName          string   `json:"inviterName,omitempty"`
	Roles                []string `json:"roles,omitempty"`
	SeatClass            string   `json:"seatClass,omitempty"`
	ExpiresAt            string   `json:"expiresAt,omitempty"`
	MaskedEmail          string   `json:"maskedEmail,omitempty"`
	AccountExists        bool     `json:"accountExists"`
	RequiresMFAEnrolment bool     `json:"requiresMfaEnrollment"`
}

// PreviewInvitation handles GET /api/v1/invitations/preview?token=…
//
// Public and token-scoped. It returns only what the invitee needs to decide
// (company, inviter, roles, expiry, masked email). accountExists is returned on
// purpose so the page can offer "Sign in" instead of "Create your account": it
// is only reachable with the invitation token, i.e. by the mailbox owner (the
// invite response itself is identical whether or not the account exists), and
// RegisterFromInvitation still answers an existing account with a generic
// conflict.
func (h *TeamInvitationHandler) PreviewInvitation(c *gin.Context) {
	token := strings.TrimSpace(c.Query("token"))
	if token == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "token is required"})
		return
	}
	inv, err := h.invitationRepo.GetByToken(c.Request.Context(), token)
	if err != nil {
		h.logger.Error("PreviewInvitation: lookup failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to read invitation"})
		return
	}
	if inv == nil {
		c.JSON(http.StatusNotFound, invitationPreviewResponse{Reason: "not_found"})
		return
	}
	if !inv.IsValid() {
		reason := "expired"
		switch inv.Status {
		case models.TeamInvitationStatusAccepted:
			reason = "used"
		case models.TeamInvitationStatusRevoked, models.TeamInvitationStatusDeclined:
			reason = "revoked"
		}
		c.JSON(http.StatusGone, invitationPreviewResponse{Reason: reason})
		return
	}

	out := invitationPreviewResponse{
		Valid:       true,
		SeatClass:   string(inv.SeatClass),
		ExpiresAt:   inv.ExpiresAt.UTC().Format("2006-01-02T15:04:05Z"),
		MaskedEmail: maskInvitationEmail(inv.Email),
	}
	if taken, eErr := h.accountStore().EmailTaken(c.Request.Context(), inv.Email); eErr != nil {
		h.logger.Warn("PreviewInvitation: account lookup failed", zap.Error(eErr))
	} else {
		out.AccountExists = taken
	}
	if h.tenantRepo != nil {
		if tenant, tErr := h.tenantRepo.GetByID(c.Request.Context(), inv.TenantID); tErr == nil && tenant != nil {
			out.CompanyName = tenant.DisplayName
			if out.CompanyName == "" {
				out.CompanyName = tenant.Name
			}
		}
	}
	if inviter, uErr := h.userRepo.GetByID(c.Request.Context(), inv.InvitedBy); uErr == nil && inviter != nil {
		out.InviterName = userDisplayLabel(inviter)
	}
	required, names, rErr := h.invitationRequiresMFA(c.Request.Context(), inv)
	if rErr != nil {
		h.logger.Warn("PreviewInvitation: role lookup failed", zap.Error(rErr))
	}
	out.Roles = names
	out.RequiresMFAEnrolment = required
	c.JSON(http.StatusOK, out)
}

func userDisplayLabel(u *models.User) string {
	if u.DisplayName != nil && strings.TrimSpace(*u.DisplayName) != "" {
		return strings.TrimSpace(*u.DisplayName)
	}
	var parts []string
	if u.FirstName != nil && *u.FirstName != "" {
		parts = append(parts, *u.FirstName)
	}
	if u.LastName != nil && *u.LastName != "" {
		parts = append(parts, *u.LastName)
	}
	return strings.Join(parts, " ")
}

type registerFromInvitationRequest struct {
	Token    string `json:"token" binding:"required"`
	Name     string `json:"name" binding:"required,min=1,max=200"`
	Password string `json:"password" binding:"required"`
}

// RegisterFromInvitation handles POST /api/v1/auth/invitations/register.
//
// Creates the invited person's global account and joins them to the inviting
// company, atomically. The invitation token is the proof of email ownership;
// the email address always comes from the invitation, never from the request.
//
// Outcomes: 201 created (session tokens unless the invited role requires MFA
// enrolment, in which case the client continues through the hosted sign-in
// with mfa_enrollment_required); 400 invalid/expired/used token; 409
// account_exists (sign in and accept instead) or external seat (needs an
// account); 422 password policy; 503 not wired.
func (h *TeamInvitationHandler) RegisterFromInvitation(c *gin.Context) {
	if h.invitedUsers == nil || h.userMemberships == nil || h.tenantBootstrap == nil || h.roleService == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "invitation onboarding is unavailable"})
		return
	}
	var req registerFromInvitationRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	ctx := c.Request.Context()

	peek, err := h.invitationRepo.GetByToken(ctx, req.Token)
	if err != nil {
		h.logger.Error("RegisterFromInvitation: lookup failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to read invitation"})
		return
	}
	if peek == nil || !peek.IsValid() {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid or expired token"})
		return
	}
	if peek.SeatClass != models.SeatClassMember {
		// External (partner) access belongs to an account that already has its
		// own company; there is no company to hang a brand-new account on.
		c.JSON(http.StatusConflict, gin.H{"code": "account_required", "error": "this invitation needs an existing account"})
		return
	}
	if taken, gErr := h.accountStore().EmailTaken(ctx, peek.Email); gErr != nil {
		h.logger.Error("RegisterFromInvitation: account lookup failed", zap.Error(gErr))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create account"})
		return
	} else if taken {
		c.JSON(http.StatusConflict, gin.H{"code": "account_exists", "error": "an account already exists for this invitation; sign in to accept it"})
		return
	}

	modules, err := h.roleService.EntitledModules(ctx, peek.TenantID)
	if err != nil {
		h.logger.Error("RegisterFromInvitation: entitlement lookup failed", zap.Error(err))
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "role catalogue is unavailable"})
		return
	}
	mfaRequired, _, err := h.invitationRequiresMFA(ctx, peek)
	if err != nil {
		h.logger.Error("RegisterFromInvitation: role lookup failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create account"})
		return
	}

	// Password policy and breach check run before anything is written, so a
	// weak password leaves the invitation untouched and retryable.
	user, err := h.invitedUsers.PrepareInvitedMemberUser(ctx, peek.TenantID, peek.Email, req.Name, req.Password)
	if err != nil {
		var policyErr *services.SignupPasswordError
		if errors.As(err, &policyErr) {
			c.JSON(http.StatusUnprocessableEntity, gin.H{"code": "password_policy_violation", "violations": policyErr.Violations, "policy": policyErr.Policy})
			return
		}
		h.logger.Error("RegisterFromInvitation: prepare account failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create account"})
		return
	}

	result := ""
	var accepted *models.TeamInvitation
	err = h.invitationRepo.InTransaction(ctx, func(tx pgx.Tx) error {
		inv, err := h.invitationRepo.WithDB(tx).GetByTokenForUpdate(ctx, req.Token)
		if err != nil {
			return err
		}
		if inv == nil || !inv.IsValid() || inv.TenantID != peek.TenantID || inv.SeatClass != models.SeatClassMember ||
			models.CanonicalInvitationEmail(inv.Email) != models.CanonicalInvitationEmail(peek.Email) {
			result = "invalid"
			return nil
		}
		roleRepo := h.roleRepo.WithDB(tx)
		for _, roleID := range inv.RoleIDs {
			role, err := roleRepo.GetByIDAndTenantForShare(ctx, roleID, inv.TenantID)
			if err != nil {
				return err
			}
			if role == nil {
				result = "roles"
				return nil
			}
		}
		if err := roleRepo.LockPermissionCatalogue(ctx); err != nil {
			return err
		}
		for _, roleID := range inv.RoleIDs {
			allowed, err := roleRepo.HasOnlyPermissionsInModules(ctx, roleID, modules)
			if err != nil {
				return err
			}
			if !allowed {
				result = "roles"
				return nil
			}
		}
		if err := h.accountStore().CreateVerified(ctx, tx, user); err != nil {
			return err
		}
		if err := h.userRepo.WithDB(tx).GrantRoles(ctx, user.ID, inv.RoleIDs, &inv.InvitedBy); err != nil {
			return err
		}
		ok, err := h.invitationRepo.WithDB(tx).TransitionPending(ctx, inv.ID, models.TeamInvitationStatusAccepted)
		if err != nil || !ok {
			return fmt.Errorf("register invitation: transition: %w", err)
		}
		invID := inv.ID
		if _, err := h.userMemberships.WithDB(tx).Upsert(ctx, &models.UserMembership{
			TenantID: inv.TenantID, UserID: user.ID, SeatClass: inv.SeatClass, InvitationID: &invID,
		}); err != nil {
			return fmt.Errorf("register invitation: upsert membership: %w", err)
		}
		if inv.ConsumesSeat() && h.seatCounters != nil {
			if err := h.seatCounters.WithDB(tx).ConfirmSeat(ctx, inv.TenantID); err != nil {
				return fmt.Errorf("register invitation: confirm seat: %w", err)
			}
		}
		accepted = inv
		resourceType := "team_invitation"
		return repositories.CreateAuditLogTx(ctx, tx, &models.AuditLog{
			TenantID: inv.TenantID, UserID: &user.ID, TargetUserID: &user.ID, Action: "team_invitation_register",
			ResourceType: &resourceType, ResourceID: &inv.ID,
			Details: map[string]interface{}{"result": "success", "seat_class": string(inv.SeatClass), "mfa_enrollment_required": mfaRequired, "correlation_id": middleware.GetCorrelationID(c)},
			Success: true,
		})
	})
	if errors.Is(err, errInvitationAccountExists) {
		c.JSON(http.StatusConflict, gin.H{"code": "account_exists", "error": "an account already exists for this invitation; sign in to accept it"})
		return
	}
	if err != nil {
		h.logger.Error("RegisterFromInvitation: transaction failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create account"})
		return
	}
	switch result {
	case "invalid":
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid or expired token"})
		return
	case "roles":
		c.JSON(http.StatusBadRequest, gin.H{"error": errRoleNotInTenant.Error()})
		return
	}

	h.invalidateContexts(ctx, user.ID)
	tenantSlug := ""
	if h.tenantRepo != nil {
		if tenant, tErr := h.tenantRepo.GetByID(ctx, accepted.TenantID); tErr == nil && tenant != nil {
			tenantSlug = tenant.Slug
		}
	}
	resp := gin.H{
		"message":                 "Account created successfully.",
		"user_id":                 user.ID,
		"email":                   user.Email,
		"tenant_id":               accepted.TenantID,
		"tenant_slug":             tenantSlug,
		"mfa_enrollment_required": mfaRequired,
	}
	if err := h.syncJoinedMemberAccess(ctx, accepted.TenantID, user.ID); err != nil {
		// The account and membership are committed; authorization catches up on
		// the reconciler; the session below is still issued.
		h.logger.Error("RegisterFromInvitation: SpiceDB role synchronization failed", zap.Error(err))
	}
	if mfaRequired || h.invitedSessions == nil {
		// Owner/admin: no unchallenged session. The client signs in through the
		// hosted flow, which forces second-factor enrolment before the session.
		c.JSON(http.StatusCreated, resp)
		return
	}
	session, sErr := h.invitedSessions.IssueSessionForNewUser(ctx, accepted.TenantID, user, GetClientIP(c), c.GetHeader("User-Agent"))
	if sErr != nil || session == nil || session.AccessToken == "" {
		if sErr != nil {
			h.logger.Warn("RegisterFromInvitation: session issuance failed; client falls back to sign-in", zap.Error(sErr))
		}
		c.JSON(http.StatusCreated, resp)
		return
	}
	resp["access_token"] = session.AccessToken
	resp["token_type"] = session.TokenType
	resp["expires_in"] = session.ExpiresIn
	c.JSON(http.StatusCreated, resp)
}
