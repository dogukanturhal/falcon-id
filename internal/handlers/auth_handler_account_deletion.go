// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/middleware"
	"github.com/dogukanturhal/falcon-id/internal/services"
	"github.com/dogukanturhal/falcon-id/pkg/logger"
)

// deleteAccountRequest is the JSON shape accepted by
// POST /api/v1/users/me/delete-account.
//
// `confirmation_text` must equal `expectedDeletionConfirmation` so that a
// user-initiated deletion can't accidentally fire (e.g. via a misclicked
// form). The frontend renders the literal string they must type.
type deleteAccountRequest struct {
	Password          string `json:"password" binding:"required"`
	ConfirmationText  string `json:"confirmation_text" binding:"required"`
	Reason            string `json:"reason"`
}

// expectedDeletionConfirmation is the typed-confirmation phrase the user
// must enter — copy-paste blocked unless they read the warning copy.
const expectedDeletionConfirmation = "DELETE MY ACCOUNT"

// DeleteMyAccount handles POST /api/v1/users/me/delete-account.
// Schedules the row for deletion subject to a grace period; the row is
// not purged immediately so the user can change their mind.
func (h *AuthHandler) DeleteMyAccount(c *gin.Context) {
	user := middleware.GetCurrentUser(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": msgNotAuthenticatedProfile})
		return
	}

	var req deleteAccountRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if req.ConfirmationText != expectedDeletionConfirmation {
		c.JSON(http.StatusUnprocessableEntity, gin.H{
			"error": "Confirmation text must exactly match the phrase shown in the form.",
			"code":  "invalid_confirmation",
		})
		return
	}

	ipAddress := middleware.RealClientIP(c)

	updated, err := h.authService.ScheduleAccountDeletion(c.Request.Context(), user.ID, req.Password, req.Reason)
	if err != nil {
		switch {
		case errors.Is(err, services.ErrPasswordIncorrect):
			// Security audit — wrong-password attempt on a sensitive
			// destructive endpoint; SIEM rules should flag clustered
			// attempts as account-takeover preparation.
			logger.SecurityAudit.Warn("Security audit: delete-account password incorrect",
				zap.String("event", "user.account.delete_password_failed"),
				zap.String("user_id", user.ID.String()),
				zap.String("ip", ipAddress),
			)
			c.JSON(http.StatusForbidden, gin.H{
				"error": "Password is incorrect.",
				"code":  "password_incorrect",
			})
		case errors.Is(err, services.ErrDeletionAlreadyScheduled):
			c.JSON(http.StatusConflict, gin.H{
				"error": "Account deletion is already scheduled. Use cancel-deletion to abort.",
				"code":  "deletion_already_scheduled",
			})
		case errors.Is(err, services.ErrFederatedAccountCannotDelete):
			c.JSON(http.StatusForbidden, gin.H{
				"error": "Federated accounts must be deprovisioned through your identity provider.",
				"code":  "federated_account_cannot_delete",
			})
		default:
			logger.Error("DeleteMyAccount failed",
				zap.String("user_id", user.ID.String()),
				zap.Error(err))
			c.JSON(http.StatusInternalServerError, gin.H{"error": msgInternalErrorProfile})
		}
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success":               true,
		"scheduled_at":          updated.DeletionScheduledAt,
		"grace_period_ends_at":  updated.DeletionGracePeriodEndsAt,
		"grace_period_days":     int(services.DefaultDeletionGracePeriod.Hours() / 24),
		"activation_status":     updated.ActivationStatus,
		"message":               "Account scheduled for deletion. Cancel within the grace period to restore.",
	})
}

// CancelMyDeletion handles POST /api/v1/users/me/cancel-deletion.
// Aborts a pending deletion as long as the grace period hasn't elapsed.
func (h *AuthHandler) CancelMyDeletion(c *gin.Context) {
	user := middleware.GetCurrentUser(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": msgNotAuthenticatedProfile})
		return
	}

	updated, err := h.authService.CancelAccountDeletion(c.Request.Context(), user.ID)
	if err != nil {
		switch {
		case errors.Is(err, services.ErrDeletionNotScheduled):
			c.JSON(http.StatusConflict, gin.H{
				"error": "No deletion is currently scheduled.",
				"code":  "deletion_not_scheduled",
			})
		default:
			logger.Error("CancelMyDeletion failed",
				zap.String("user_id", user.ID.String()),
				zap.Error(err))
			c.JSON(http.StatusInternalServerError, gin.H{"error": msgInternalErrorProfile})
		}
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success":           true,
		"activation_status": updated.ActivationStatus,
		"message":           "Account deletion cancelled.",
	})
}
