// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"context"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/middleware"
	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/internal/repositories"
)

// The signed-in "my invitations" flow. A person whose mailbox is verified can
// see, accept and decline the pending invitations addressed to their email
// without the emailed token: the verified mailbox is what the token would have
// proved. This is what makes an invitation usable when the emailed link's
// return path is lost (the invitee signs in somewhere else and lands in their
// own company).
//
// Only the account's own verified email is trusted. An unverified account sees
// nothing, and an invitation addressed to another email answers 404 exactly
// like an unknown id. The token is never returned.

// myInvitationResponse is one pending invitation as the invitee sees it.
type myInvitationResponse struct {
	ID                   uuid.UUID `json:"id"`
	TenantID             uuid.UUID `json:"tenantId"`
	CompanyName          string    `json:"companyName,omitempty"`
	InviterName          string    `json:"inviterName,omitempty"`
	Roles                []string  `json:"roles"`
	SeatClass            string    `json:"seatClass"`
	ExpiresAt            string    `json:"expiresAt"`
	RequiresMFAEnrolment bool      `json:"requiresMfaEnrollment"`
}

// verifiedInvitee resolves the caller and their verified canonical email. The
// email is "" for an account whose mailbox is not verified. ok=false means the
// response (401/500) was already written.
func (h *TeamInvitationHandler) verifiedInvitee(c *gin.Context) (user *models.CurrentUser, email string, ok bool) {
	currentUser := middleware.GetCurrentUser(c)
	if currentUser == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return nil, "", false
	}
	dbEmail, verified, err := h.inviteeIdentity().VerifiedEmail(c.Request.Context(), currentUser.ID)
	if err != nil {
		h.logger.Error("my invitations: identity lookup failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to read invitations"})
		return nil, "", false
	}
	if !verified {
		return currentUser, "", true
	}
	return currentUser, models.CanonicalInvitationEmail(dbEmail), true
}

// ListMyInvitations handles GET /api/v1/invitations/mine.
//
// @Summary List pending invitations addressed to the signed-in user
// @Tags Team
// @Security BearerAuth
// @Produce json
// @Success 200 {array} myInvitationResponse
// @Router /api/v1/invitations/mine [get]
func (h *TeamInvitationHandler) ListMyInvitations(c *gin.Context) {
	if rejectIfImpersonated(c) {
		return
	}
	_, email, ok := h.verifiedInvitee(c)
	if !ok {
		return
	}
	out := make([]myInvitationResponse, 0)
	if email == "" {
		c.JSON(http.StatusOK, out)
		return
	}
	ctx := c.Request.Context()
	invs, err := h.invitationRepo.ListPendingByEmail(ctx, email)
	if err != nil {
		h.logger.Error("ListMyInvitations: lookup failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to read invitations"})
		return
	}
	for _, inv := range invs {
		out = append(out, h.describeMyInvitation(ctx, inv))
	}
	c.JSON(http.StatusOK, out)
}

func (h *TeamInvitationHandler) describeMyInvitation(ctx context.Context, inv *models.TeamInvitation) myInvitationResponse {
	resp := myInvitationResponse{
		ID:        inv.ID,
		TenantID:  inv.TenantID,
		Roles:     []string{},
		SeatClass: string(inv.SeatClass),
		ExpiresAt: inv.ExpiresAt.UTC().Format(time.RFC3339),
	}
	if h.tenantRepo != nil {
		if tenant, err := h.tenantRepo.GetByID(ctx, inv.TenantID); err == nil && tenant != nil {
			resp.CompanyName = tenant.DisplayName
			if resp.CompanyName == "" {
				resp.CompanyName = tenant.Name
			}
		}
	}
	if inviter, err := h.userRepo.GetByID(ctx, inv.InvitedBy); err == nil && inviter != nil {
		resp.InviterName = userDisplayLabel(inviter)
	}
	required, names, err := h.invitationRequiresMFA(ctx, inv)
	if err != nil {
		h.logger.Warn("my invitations: role lookup failed", zap.Error(err))
	}
	if names != nil {
		resp.Roles = names
	}
	resp.RequiresMFAEnrolment = required
	return resp
}

// AcceptMyInvitation handles POST /api/v1/invitations/mine/:id/accept.
//
// @Summary Accept a pending invitation addressed to the signed-in user
// @Tags Team
// @Security BearerAuth
// @Produce json
// @Param id path string true "Invitation ID"
// @Success 200 {object} map[string]string
// @Failure 403 {object} map[string]string "mfa_enrollment_required"
// @Failure 404 {object} map[string]string
// @Failure 409 {object} map[string]string "already_member | invitation_not_pending"
// @Router /api/v1/invitations/mine/{id}/accept [post]
func (h *TeamInvitationHandler) AcceptMyInvitation(c *gin.Context) {
	if rejectIfImpersonated(c) {
		return
	}
	if !h.acceptDependenciesReady(c) {
		return
	}
	user, inv, ok := h.loadMyInvitation(c)
	if !ok {
		return
	}
	h.acceptInvitation(c, user, inv, myInvitationLocker(inv.ID), true)
}

// DeclineMyInvitation handles POST /api/v1/invitations/mine/:id/decline.
//
// @Summary Decline a pending invitation addressed to the signed-in user
// @Tags Team
// @Security BearerAuth
// @Produce json
// @Param id path string true "Invitation ID"
// @Success 200 {object} map[string]string
// @Failure 404 {object} map[string]string
// @Failure 409 {object} map[string]string "invitation_not_pending"
// @Router /api/v1/invitations/mine/{id}/decline [post]
func (h *TeamInvitationHandler) DeclineMyInvitation(c *gin.Context) {
	if rejectIfImpersonated(c) {
		return
	}
	user, inv, ok := h.loadMyInvitation(c)
	if !ok {
		return
	}
	h.declineInvitation(c, user, myInvitationLocker(inv.ID), true)
}

func myInvitationLocker(id uuid.UUID) invitationLocker {
	return func(ctx context.Context, repo *repositories.TeamInvitationRepository) (*models.TeamInvitation, error) {
		return repo.GetByIDForUpdate(ctx, id)
	}
}

// loadMyInvitation resolves :id to an invitation addressed to the caller's
// verified email. Anything else (bad id, unknown id, someone else's invitation,
// unverified mailbox) is the same 404. It returns a copy of the caller whose
// Email is the verified account email, which is what the shared accept/decline
// identity check compares. A found but no-longer-pending invitation is 409
// (410 when it merely expired).
func (h *TeamInvitationHandler) loadMyInvitation(c *gin.Context) (*models.CurrentUser, *models.TeamInvitation, bool) {
	notFound := func() {
		c.JSON(http.StatusNotFound, gin.H{"error": "invitation not found"})
	}
	user, email, ok := h.verifiedInvitee(c)
	if !ok {
		return nil, nil, false
	}
	id, err := uuid.Parse(c.Param("id"))
	if err != nil || email == "" {
		notFound()
		return nil, nil, false
	}
	inv, err := h.invitationRepo.GetByID(c.Request.Context(), id)
	if err != nil {
		h.logger.Error("my invitations: lookup failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to read invitation"})
		return nil, nil, false
	}
	if inv == nil || models.CanonicalInvitationEmail(inv.Email) != email {
		notFound()
		return nil, nil, false
	}
	if !inv.IsValid() {
		if inv.Status == models.TeamInvitationStatusPending {
			c.JSON(http.StatusGone, gin.H{"error": "this invitation has expired", "code": "invitation_expired"})
		} else {
			c.JSON(http.StatusConflict, gin.H{"error": "this invitation is no longer pending", "code": errCodeInvitationNotPending})
		}
		return nil, nil, false
	}
	verifiedUser := *user
	verifiedUser.Email = email
	return &verifiedUser, inv, true
}
